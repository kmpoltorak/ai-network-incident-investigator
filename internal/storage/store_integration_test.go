//go:build integration

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.MigrateUp(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMigrateDownAndUp(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.MigrateDown(ctx); err != nil {
		t.Fatalf("down: %v", err)
	}
	if n, err := s.MigrateUp(ctx); err != nil || n != 1 {
		t.Fatalf("up: applied=%d err=%v", n, err)
	}
	if n, err := s.MigrateUp(ctx); err != nil || n != 0 {
		t.Fatalf("second up should be a no-op: applied=%d err=%v", n, err)
	}
}

func TestIncidentRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	in := domain.Incident{Title: "DB unreachable", Description: "d", TargetHost: "db.internal", TargetPort: 5432}
	if err := s.CreateIncident(ctx, &in); err != nil {
		t.Fatal(err)
	}
	if in.ID == "" || in.Status != domain.IncidentOpen || in.CreatedAt.IsZero() {
		t.Fatalf("defaults not returned: %+v", in)
	}

	got, err := s.GetIncident(ctx, in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TargetPort != 5432 || got.Title != in.Title {
		t.Fatalf("got %+v", got)
	}

	list, err := s.ListIncidents(ctx, 100, 0)
	if err != nil || len(list) == 0 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}

	for _, id := range []string{domain.NewID(), "not-a-uuid"} {
		if _, err := s.GetIncident(ctx, id); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("GetIncident(%q) err = %v, want ErrNotFound", id, err)
		}
	}
}

func TestFinishInvestigationAndLatestReport(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	inc := domain.Incident{Title: "t", TargetHost: "example.com"}
	if err := s.CreateIncident(ctx, &inc); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LatestReport(ctx, inc.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("want ErrNotFound before any investigation, got %v", err)
	}

	inv := domain.Investigation{IncidentID: inc.ID, Status: domain.InvestigationRunning, Scenario: "packet_loss"}
	if err := s.CreateInvestigation(ctx, &inv); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	te := domain.ToolExecution{ID: domain.NewID(), ToolName: "ping", Status: domain.ToolSucceeded,
		Input: json.RawMessage(`{"host":"example.com"}`), Output: json.RawMessage(`{"packet_loss_percent":18}`), StartedAt: now}
	failed := domain.ToolExecution{ID: domain.NewID(), ToolName: "tcp", Status: domain.ToolFailed,
		Input: json.RawMessage(`{}`), Error: "boom", StartedAt: now.Add(time.Millisecond)}
	ev := domain.Evidence{ID: domain.NewID(), ToolExecutionID: te.ID, Source: "ping", Health: domain.Degraded,
		Summary: "18% loss", Data: te.Output}
	analysis := domain.Analysis{Summary: "s", RootCause: "loss", Confidence: 0.87, Severity: domain.SeverityHigh,
		Evidence: []domain.EvidenceReference{{Source: "ping", Description: "18%"}}, RecommendedActions: []string{"a"}}

	inv.Status = domain.InvestigationCompleted
	inv.CompletedAt = &now
	rec := domain.InvestigationRecord{
		Investigation:  inv,
		ToolExecutions: []domain.ToolExecution{te, failed},
		Evidence:       []domain.Evidence{ev},
		Report:         &domain.Report{ID: domain.NewID(), Provider: "rules/rules-v1", Analysis: analysis, CreatedAt: now},
	}
	if err := s.FinishInvestigation(ctx, rec); err != nil {
		t.Fatal(err)
	}

	got, err := s.LatestReport(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Investigation.Status != domain.InvestigationCompleted || got.Investigation.Scenario != "packet_loss" ||
		len(got.ToolExecutions) != 2 || len(got.Evidence) != 1 || got.Report == nil ||
		got.Report.Analysis.Confidence != 0.87 || got.Report.Analysis.RootCause != "loss" {
		t.Fatalf("unexpected record: %+v", got)
	}

	updated, _ := s.GetIncident(ctx, inc.ID)
	if updated.Status != domain.IncidentAnalyzed {
		t.Fatalf("incident status = %s, want analyzed", updated.Status)
	}
}
