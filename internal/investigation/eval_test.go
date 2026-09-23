package investigation

import (
	"context"
	"strings"
	"testing"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/llm"
)

// EvalCases pairs each simulation scenario with a realistic incident and the
// root-cause category a correct analysis must name. tests/eval_test.go runs
// the same cases against a live LLM.
var EvalCases = []struct {
	Scenario string
	Incident domain.Incident
	Keywords []string // root cause must contain at least one (case-insensitive)
}{
	{"packet_loss", domain.Incident{ID: "e1", Title: "Warehouse WAW-01 has intermittent connectivity", TargetHost: "gw.waw01.example.net", TargetPort: 443},
		[]string{"packet loss", "wan"}},
	{"dns_failure", domain.Incident{ID: "e2", Title: "Users cannot resolve internal application hostnames", TargetHost: "app.corp.example.com", TargetPort: 443},
		[]string{"dns", "resolution"}},
	{"tcp_failure", domain.Incident{ID: "e3", Title: "Application cannot connect to the database service", TargetHost: "db.corp.example.com", TargetPort: 5432},
		[]string{"tcp", "port", "connect", "reachab"}},
	{"high_latency", domain.Incident{ID: "e4", Title: "ERP is very slow from the Krakow office", TargetHost: "erp.corp.example.com", TargetPort: 443},
		[]string{"latency", "slow", "delay"}},
	{"healthy", domain.Incident{ID: "e5", Title: "User reports the portal is down", TargetHost: "portal.corp.example.com", TargetPort: 443},
		[]string{"no network", "not network", "no fault", "application"}},
}

func MatchesKeywords(rootCause string, keywords []string) bool {
	rc := strings.ToLower(rootCause)
	for _, k := range keywords {
		if strings.Contains(rc, k) {
			return true
		}
	}
	return false
}

// TestEvaluationRulesProvider is the deterministic AI evaluation: every
// scenario must produce a valid report naming the expected root cause.
func TestEvaluationRulesProvider(t *testing.T) {
	for _, tc := range EvalCases {
		t.Run(tc.Scenario, func(t *testing.T) {
			e := newEngine(newMemStore(tc.Incident), simToolbox(t), llm.RulesProvider{})
			rec, err := e.Investigate(context.Background(), tc.Incident.ID, Options{Scenario: tc.Scenario})
			if err != nil {
				t.Fatal(err)
			}
			if !MatchesKeywords(rec.Report.Analysis.RootCause, tc.Keywords) {
				t.Fatalf("root cause %q does not match any of %v", rec.Report.Analysis.RootCause, tc.Keywords)
			}
		})
	}
}
