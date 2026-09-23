package investigation

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/diagnostics"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/llm"
)

type memStore struct {
	mu        sync.Mutex
	incidents map[string]domain.Incident
	finished  []domain.InvestigationRecord
	finishErr error // context error observed at save time
}

func newMemStore(incs ...domain.Incident) *memStore {
	s := &memStore{incidents: map[string]domain.Incident{}}
	for _, i := range incs {
		s.incidents[i.ID] = i
	}
	return s
}

func (s *memStore) GetIncident(_ context.Context, id string) (domain.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i, ok := s.incidents[id]; ok {
		return i, nil
	}
	return domain.Incident{}, domain.ErrNotFound
}

func (s *memStore) CreateInvestigation(_ context.Context, inv *domain.Investigation) error {
	inv.ID = domain.NewID()
	inv.StartedAt = time.Now()
	return nil
}

func (s *memStore) FinishInvestigation(ctx context.Context, rec domain.InvestigationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = append(s.finished, rec)
	s.finishErr = ctx.Err()
	return nil
}

type fakeProvider struct {
	analysis domain.Analysis
	err      error
	block    chan struct{}
	calls    int
}

func (f *fakeProvider) Name() string { return "fake/test" }

func (f *fakeProvider) AnalyzeIncident(ctx context.Context, _ llm.AnalysisInput) (domain.Analysis, error) {
	f.calls++
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return domain.Analysis{}, ctx.Err()
		}
	}
	return f.analysis, f.err
}

type failingTool struct{ name string }

func (f failingTool) Name() string { return f.name }
func (f failingTool) Run(context.Context, diagnostics.Target) (diagnostics.Result, error) {
	return diagnostics.Result{}, errors.New("ping: executable file not found")
}

type staticToolbox map[string]diagnostics.Tool

func (s staticToolbox) Tools(string) (map[string]diagnostics.Tool, string, error) { return s, "", nil }

var incident = domain.Incident{ID: "inc-1", Title: "Warehouse WAW-01 has intermittent connectivity",
	TargetHost: "gw.waw01.example.net", TargetPort: 443}

func simToolbox(t *testing.T) diagnostics.Toolbox {
	t.Helper()
	b, err := diagnostics.NewToolbox(true, "healthy")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newEngine(store Store, tb Toolbox, p llm.Provider) *Engine {
	return NewEngine(store, tb, p, slog.New(slog.NewTextHandler(io.Discard, nil)),
		Config{Timeout: 5 * time.Second, ToolTimeout: time.Second, MaxConcurrent: 1})
}

func TestInvestigateSuccess(t *testing.T) {
	store := newMemStore(incident)
	rec, err := newEngine(store, simToolbox(t), llm.RulesProvider{}).
		Investigate(context.Background(), incident.ID, Options{Scenario: "packet_loss"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Investigation.Status != domain.InvestigationCompleted || rec.Investigation.Scenario != "packet_loss" ||
		rec.Investigation.CompletedAt == nil {
		t.Fatalf("investigation = %+v", rec.Investigation)
	}
	if len(rec.ToolExecutions) != 3 || len(rec.Evidence) != 3 || rec.Report == nil {
		t.Fatalf("executions=%d evidence=%d report=%v", len(rec.ToolExecutions), len(rec.Evidence), rec.Report)
	}
	for i, want := range []string{"dns", "ping", "tcp"} {
		if rec.ToolExecutions[i].ToolName != want || rec.Evidence[i].ToolExecutionID != rec.ToolExecutions[i].ID {
			t.Fatalf("execution %d = %+v", i, rec.ToolExecutions[i])
		}
	}
	if len(store.finished) != 1 || store.finished[0].Report == nil {
		t.Fatal("record not persisted with report")
	}
}

func TestPlan(t *testing.T) {
	tests := []struct {
		inc  domain.Incident
		want []string
	}{
		{domain.Incident{TargetHost: "db.internal", TargetPort: 5432}, []string{"dns", "ping", "tcp"}},
		{domain.Incident{TargetHost: "10.0.0.1", TargetPort: 5432}, []string{"ping", "tcp"}},
		{domain.Incident{TargetHost: "db.internal"}, []string{"dns", "ping"}},
	}
	for _, tt := range tests {
		got := plan(tt.inc)
		if len(got) != len(tt.want) {
			t.Fatalf("plan(%+v) = %v, want %v", tt.inc, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("plan(%+v) = %v, want %v", tt.inc, got, tt.want)
			}
		}
	}
}

func TestInvalidAnalysisIsNotPersistedAsReport(t *testing.T) {
	store := newMemStore(incident)
	hallucinated := domain.Analysis{Summary: "s", RootCause: "BGP session down", Confidence: 0.9, Severity: domain.SeverityHigh,
		Evidence: []domain.EvidenceReference{{Source: "bgp", Description: "neighbor down"}}, RecommendedActions: []string{"x"}}
	rec, err := newEngine(store, simToolbox(t), &fakeProvider{analysis: hallucinated}).
		Investigate(context.Background(), incident.ID, Options{})
	if !errors.Is(err, ErrAnalysisFailed) {
		t.Fatalf("err = %v, want ErrAnalysisFailed", err)
	}
	if rec.Report != nil || rec.Investigation.Status != domain.InvestigationFailed || rec.Investigation.Error == "" {
		t.Fatalf("rec = %+v", rec.Investigation)
	}
	saved := store.finished[0]
	if saved.Report != nil || saved.Investigation.Status != domain.InvestigationFailed || len(saved.Evidence) != 3 {
		t.Fatal("failed investigation must keep evidence but have no report")
	}
}

func TestProviderErrorFailsInvestigation(t *testing.T) {
	store := newMemStore(incident)
	_, err := newEngine(store, simToolbox(t), &fakeProvider{err: errors.New("connection refused")}).
		Investigate(context.Background(), incident.ID, Options{})
	if !errors.Is(err, ErrAnalysisFailed) || store.finished[0].Investigation.Status != domain.InvestigationFailed {
		t.Fatalf("err = %v", err)
	}
}

func TestToolFailureIsRecordedAndInvestigationContinues(t *testing.T) {
	sim, _, _ := simToolbox(t).Tools("healthy")
	tb := staticToolbox{"dns": sim["dns"], "ping": failingTool{"ping"}, "tcp": sim["tcp"]}
	rec, err := newEngine(newMemStore(incident), tb, llm.RulesProvider{}).Investigate(context.Background(), incident.ID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ToolExecutions[1].Status != domain.ToolFailed || rec.ToolExecutions[1].Error == "" || len(rec.Evidence) != 2 {
		t.Fatalf("executions = %+v", rec.ToolExecutions)
	}
}

func TestAllToolsFailSkipsLLM(t *testing.T) {
	tb := staticToolbox{"dns": failingTool{"dns"}, "ping": failingTool{"ping"}, "tcp": failingTool{"tcp"}}
	p := &fakeProvider{}
	_, err := newEngine(newMemStore(incident), tb, p).Investigate(context.Background(), incident.ID, Options{})
	if !errors.Is(err, ErrAnalysisFailed) || p.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, p.calls)
	}
}

func TestInvestigateRejections(t *testing.T) {
	e := newEngine(newMemStore(incident), simToolbox(t), llm.RulesProvider{})
	if _, err := e.Investigate(context.Background(), "missing", Options{}); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("missing incident: %v", err)
	}
	if _, err := e.Investigate(context.Background(), incident.ID, Options{Scenario: "alien_invasion"}); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("bad scenario: %v", err)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	p := &fakeProvider{block: make(chan struct{}), analysis: domain.Analysis{}}
	e := newEngine(newMemStore(incident), simToolbox(t), p)
	done := make(chan struct{})
	go func() {
		_, _ = e.Investigate(context.Background(), incident.ID, Options{})
		close(done)
	}()
	for len(e.slots) == 0 {
		time.Sleep(time.Millisecond)
	}
	if _, err := e.Investigate(context.Background(), incident.ID, Options{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	close(p.block)
	<-done
}

func TestCanceledRequestStillPersistsFinalStatus(t *testing.T) {
	store := newMemStore(incident)
	p := &fakeProvider{block: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := newEngine(store, simToolbox(t), p).Investigate(ctx, incident.ID, Options{})
	if !errors.Is(err, ErrAnalysisFailed) {
		t.Fatalf("err = %v", err)
	}
	if store.finished[0].Investigation.Status != domain.InvestigationFailed || store.finishErr != nil {
		t.Fatal("final status must be persisted with a live context")
	}
}
