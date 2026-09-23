//go:build eval

package investigation

import (
	"context"
	"os"
	"testing"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/config"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/llm"
)

// TestEvaluationLiveProvider runs the evaluation cases against the provider
// configured by LLM_PROVIDER / LLM_MODEL / OPENAI_API_KEY / OLLAMA_BASE_URL.
// Results depend on the model, so it is opt-in:
//
//	LLM_PROVIDER=ollama LLM_MODEL=llama3.2 go test -tags eval -v ./internal/investigation/
func TestEvaluationLiveProvider(t *testing.T) {
	cfg, err := config.Load(func(k string) string {
		if k == "DATABASE_URL" {
			return "unused"
		}
		return os.Getenv(k)
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := llm.FromConfig(cfg)
	passed := 0
	for _, tc := range evalCases {
		t.Run(tc.Scenario, func(t *testing.T) {
			e := newEngine(newMemStore(tc.Incident), simToolbox(t), provider)
			e.cfg.Timeout = cfg.LLMTimeout + cfg.LLMTimeout/2
			rec, err := e.Investigate(context.Background(), tc.Incident.ID, Options{Scenario: tc.Scenario})
			if err != nil {
				t.Fatalf("investigation failed: %v", err)
			}
			a := rec.Report.Analysis
			t.Logf("root_cause=%q confidence=%.2f severity=%s", a.RootCause, a.Confidence, a.Severity)
			if !matchesKeywords(a.RootCause+" "+a.Summary, tc.Keywords) {
				t.Fatalf("root cause %q does not match any of %v", a.RootCause, tc.Keywords)
			}
			passed++
		})
	}
	t.Logf("%s: %d/%d cases passed", provider.Name(), passed, len(evalCases))
}
