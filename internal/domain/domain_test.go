package domain

import (
	"strings"
	"testing"
)

func validAnalysis() Analysis {
	return Analysis{
		Summary:            "WAN degradation",
		RootCause:          "Packet loss on WAN link",
		Confidence:         0.8,
		Severity:           SeverityHigh,
		Evidence:           []EvidenceReference{{Source: "ping", Description: "18% loss"}},
		RecommendedActions: []string{"check interface counters"},
	}
}

func TestAnalysisValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Analysis)
		wantErr string
	}{
		{"valid", func(*Analysis) {}, ""},
		{"empty summary", func(a *Analysis) { a.Summary = " " }, "summary is empty"},
		{"empty root cause", func(a *Analysis) { a.RootCause = "" }, "root_cause is empty"},
		{"confidence above one", func(a *Analysis) { a.Confidence = 1.2 }, "confidence"},
		{"negative confidence", func(a *Analysis) { a.Confidence = -0.1 }, "confidence"},
		{"bad severity", func(a *Analysis) { a.Severity = "urgent" }, "severity"},
		{"no evidence", func(a *Analysis) { a.Evidence = nil }, "evidence is empty"},
		{"uncollected source", func(a *Analysis) { a.Evidence[0].Source = "bgp" }, `"bgp" was not collected`},
		{"blank evidence description", func(a *Analysis) { a.Evidence[0].Description = "" }, "empty description"},
		{"no actions", func(a *Analysis) { a.RecommendedActions = []string{""} }, "recommended_actions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := validAnalysis()
			tt.mutate(&a)
			err := a.Validate([]string{"ping", "dns"})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateHost(t *testing.T) {
	valid := []string{"example.com", "gw.waw01.example.net", "localhost", "10.0.0.1", "::1", "db-1.internal.", "a"}
	invalid := []string{"", "-c1", "exa mple.com", "host;rm -rf /", "$(id)", "foo..bar", "-.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com"}
	for _, h := range valid {
		if err := ValidateHost(h); err != nil {
			t.Errorf("ValidateHost(%q) = %v, want nil", h, err)
		}
	}
	for _, h := range invalid {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) = nil, want error", h)
		}
	}
}
