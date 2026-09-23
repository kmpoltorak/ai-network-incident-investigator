package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

const validJSON = `{"summary":"s","root_cause":"r","confidence":0.7,"severity":"high",
"evidence":[{"source":"ping","description":"d"}],"possible_causes":["c"],"recommended_actions":["a"]}`

func TestDecodeAnalysis(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"plain", validJSON, false},
		{"fenced", "```json\n" + validJSON + "\n```", false},
		{"bare fence", "```\n" + validJSON + "\n```", false},
		{"unknown field", `{"summary":"s","hacked":true}`, true},
		{"trailing object", validJSON + `{"x":1}`, true},
		{"prose", "The root cause is DNS.", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := decodeAnalysis(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidOutput) {
					t.Fatalf("want ErrInvalidOutput, got %v", err)
				}
				return
			}
			if err != nil || a.RootCause != "r" || a.Confidence != 0.7 {
				t.Fatalf("a=%+v err=%v", a, err)
			}
		})
	}
}

func sampleInput() AnalysisInput {
	return AnalysisInput{
		Incident: domain.Incident{ID: "secret-db-id", Title: "Link flapping", TargetHost: "gw.example.net", TargetPort: 443},
		Evidence: []domain.Evidence{{ID: "ev-id", Source: "ping", Health: domain.Degraded, Summary: "18% loss",
			Data: json.RawMessage(`{"packet_loss_percent":18}`)}},
	}
}

func TestUserPromptContainsEvidenceOnly(t *testing.T) {
	p, err := userPrompt(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Link flapping", "gw.example.net", `"packet_loss_percent": 18`, `"health": "degraded"`} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "secret-db-id") || strings.Contains(p, "ev-id") {
		t.Error("prompt leaks internal IDs")
	}
}

func TestOpenAIProvider(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" || r.Header.Get("Authorization") != "Bearer sk-test" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		content, _ := json.Marshal(validJSON)
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"content":` + string(content) + `}}]}`))
	}))
	defer srv.Close()

	p := NewOpenAIProvider(srv.URL, "sk-test", "gpt-test", 5*time.Second)
	a, err := p.AnalyzeIncident(context.Background(), sampleInput())
	if err != nil || a.RootCause != "r" {
		t.Fatalf("a=%+v err=%v", a, err)
	}
	rf := got["response_format"].(map[string]any)
	js := rf["json_schema"].(map[string]any)
	if rf["type"] != "json_schema" || js["strict"] != true || got["model"] != "gpt-test" {
		t.Fatalf("request not using strict schema: %v", got)
	}
	if p.Name() != "openai/gpt-test" {
		t.Fatalf("name = %s", p.Name())
	}
}

func TestOpenAIProviderErrors(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantInvalid bool
	}{
		{"server error", 500, `{"error":{"message":"boom"}}`, false},
		{"unauthorized", 401, `{"error":{"message":"bad key"}}`, false},
		{"no choices", 200, `{"choices":[]}`, true},
		{"refusal", 200, `{"choices":[{"message":{"refusal":"I can't"}}]}`, true},
		{"truncated", 200, `{"choices":[{"finish_reason":"length","message":{"content":"{"}}]}`, true},
		{"prose content", 200, `{"choices":[{"message":{"content":"It is DNS."}}]}`, true},
		{"broken envelope", 200, `not json`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			_, err := NewOpenAIProvider(srv.URL, "k", "m", time.Second).AnalyzeIncident(context.Background(), sampleInput())
			if err == nil {
				t.Fatal("expected error")
			}
			if errors.Is(err, ErrInvalidOutput) != tt.wantInvalid {
				t.Fatalf("ErrInvalidOutput=%t, want %t: %v", errors.Is(err, ErrInvalidOutput), tt.wantInvalid, err)
			}
		})
	}
}

func TestProviderTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	start := time.Now()
	_, err := NewOllamaProvider(srv.URL, "m", 100*time.Millisecond).AnalyzeIncident(context.Background(), sampleInput())
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("timeout not enforced: err=%v elapsed=%s", err, time.Since(start))
	}
}

func TestOllamaProvider(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		content, _ := json.Marshal("```json\n" + validJSON + "\n```")
		_, _ = w.Write([]byte(`{"message":{"role":"assistant","content":` + string(content) + `},"done":true}`))
	}))
	defer srv.Close()

	a, err := NewOllamaProvider(srv.URL, "llama3.1", time.Second).AnalyzeIncident(context.Background(), sampleInput())
	if err != nil || a.Severity != domain.SeverityHigh {
		t.Fatalf("a=%+v err=%v", a, err)
	}
	if got["stream"] != false || got["format"] == nil {
		t.Fatalf("request missing stream=false or format schema: %v", got)
	}
	msgs := got["messages"].([]any)
	if len(msgs) != 2 || !strings.Contains(msgs[0].(map[string]any)["content"].(string), "network incident analyst") {
		t.Fatalf("system prompt not sent: %v", msgs)
	}
}

func ev(source string, h domain.Health, data string) domain.Evidence {
	if data == "" {
		data = "{}"
	}
	return domain.Evidence{Source: source, Health: h, Summary: source + " " + string(h), Data: json.RawMessage(data)}
}

func TestRulesProvider(t *testing.T) {
	tests := []struct {
		name      string
		evidence  []domain.Evidence
		rootCause string
		severity  domain.Severity
	}{
		{"dns down wins", []domain.Evidence{ev("dns", domain.Down, ""), ev("ping", domain.Down, ""), ev("tcp", domain.Down, "")},
			"DNS resolution failure", domain.SeverityHigh},
		{"host unreachable", []domain.Evidence{ev("ping", domain.Down, `{"packet_loss_percent":100}`), ev("tcp", domain.Down, "")},
			"Host unreachable", domain.SeverityCritical},
		{"port closed", []domain.Evidence{ev("ping", domain.Healthy, ""), ev("tcp", domain.Down, "")},
			"TCP connectivity failure: service port unreachable", domain.SeverityHigh},
		{"icmp filtered", []domain.Evidence{ev("ping", domain.Down, `{"packet_loss_percent":100}`), ev("tcp", domain.Healthy, "")},
			"ICMP filtered; no connectivity fault detected", domain.SeverityLow},
		{"packet loss", []domain.Evidence{ev("ping", domain.Degraded, `{"packet_loss_percent":18}`), ev("tcp", domain.Healthy, "")},
			"Packet loss on the network path", domain.SeverityHigh},
		{"minor loss", []domain.Evidence{ev("ping", domain.Degraded, `{"packet_loss_percent":2}`)},
			"Packet loss on the network path", domain.SeverityMedium},
		{"latency", []domain.Evidence{ev("ping", domain.Degraded, `{"packet_loss_percent":0}`)},
			"High network latency", domain.SeverityMedium},
		{"healthy", []domain.Evidence{ev("dns", domain.Healthy, ""), ev("ping", domain.Healthy, "")},
			"No network-layer fault detected", domain.SeverityLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := AnalysisInput{Incident: domain.Incident{TargetHost: "h", TargetPort: 5432}, Evidence: tt.evidence}
			a, err := RulesProvider{}.AnalyzeIncident(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if a.RootCause != tt.rootCause || a.Severity != tt.severity {
				t.Fatalf("got %q/%s, want %q/%s", a.RootCause, a.Severity, tt.rootCause, tt.severity)
			}
			var sources []string
			for _, e := range tt.evidence {
				sources = append(sources, e.Source)
			}
			if err := a.Validate(sources); err != nil {
				t.Fatalf("rules output fails validation: %v", err)
			}
		})
	}
	if _, err := (RulesProvider{}).AnalyzeIncident(context.Background(), AnalysisInput{}); err == nil {
		t.Fatal("no-evidence input accepted")
	}
}
