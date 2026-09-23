//go:build integration

package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/diagnostics"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/incidents"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/investigation"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/llm"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/storage"
)

// newIntegrationServer wires the real stack: PostgreSQL store, simulated
// tools, and the given provider.
func newIntegrationServer(t *testing.T, provider llm.Provider) *httptest.Server {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	store, err := storage.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.MigrateUp(ctx); err != nil {
		t.Fatal(err)
	}
	toolbox, err := diagnostics.NewToolbox(true, "healthy")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := investigation.NewEngine(store, toolbox, provider, log, investigation.Config{Timeout: 10 * time.Second, MaxConcurrent: 4})
	srv := httptest.NewServer(New(incidents.NewService(store), engine, store.Ping, log))
	t.Cleanup(srv.Close)
	return srv
}

func TestIntegrationSampleIncidents(t *testing.T) {
	srv := newIntegrationServer(t, llm.RulesProvider{})
	samples := []struct {
		file, scenario, keyword string
	}{
		{"packet_loss.json", "packet_loss", "packet loss"},
		{"dns_failure.json", "dns_failure", "dns"},
		{"tcp_failure.json", "tcp_failure", "tcp"},
	}
	for _, s := range samples {
		t.Run(s.scenario, func(t *testing.T) {
			body, err := os.ReadFile("../../docs/examples/" + s.file)
			if err != nil {
				t.Fatal(err)
			}
			resp, out := do(t, "POST", srv.URL+"/api/v1/incidents", string(body))
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("create: %d %v", resp.StatusCode, out)
			}
			id := out["id"].(string)

			resp, out = do(t, "POST", srv.URL+"/api/v1/incidents/"+id+"/investigate", `{"scenario":"`+s.scenario+`"}`)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("investigate: %d %v", resp.StatusCode, out)
			}

			// The report must be readable back from PostgreSQL.
			resp, out = do(t, "GET", srv.URL+"/api/v1/incidents/"+id+"/report", "")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("report: %d %v", resp.StatusCode, out)
			}
			rootCause := out["report"].(map[string]any)["analysis"].(map[string]any)["root_cause"].(string)
			if !strings.Contains(strings.ToLower(rootCause), s.keyword) {
				t.Fatalf("root cause %q does not mention %q", rootCause, s.keyword)
			}
			if n := len(out["evidence"].([]any)); n != 3 {
				t.Fatalf("stored evidence = %d, want 3", n)
			}
			if _, inc := do(t, "GET", srv.URL+"/api/v1/incidents/"+id, ""); inc["status"] != "analyzed" {
				t.Fatalf("incident status = %v", inc["status"])
			}
		})
	}
}

func TestIntegrationFailedAnalysisIsStoredWithoutReport(t *testing.T) {
	srv := newIntegrationServer(t, brokenProvider{})
	resp, out := do(t, "POST", srv.URL+"/api/v1/incidents", `{"title":"t","target_host":"10.0.0.5","target_port":22}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	id := out["id"].(string)

	resp, out = do(t, "POST", srv.URL+"/api/v1/incidents/"+id+"/investigate", "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("investigate: %d %v", resp.StatusCode, out)
	}
	if resp, _ := do(t, "GET", srv.URL+"/api/v1/incidents/"+id+"/report", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("report after failed analysis: %d", resp.StatusCode)
	}
	if _, inc := do(t, "GET", srv.URL+"/api/v1/incidents/"+id, ""); inc["status"] != "open" {
		t.Fatalf("incident status = %v, want open", inc["status"])
	}
}

func TestIntegrationReadiness(t *testing.T) {
	srv := newIntegrationServer(t, llm.RulesProvider{})
	resp, out := do(t, "GET", srv.URL+"/ready", "")
	if resp.StatusCode != http.StatusOK || out["database"] != "ok" {
		t.Fatalf("ready: %d %v", resp.StatusCode, out)
	}
}
