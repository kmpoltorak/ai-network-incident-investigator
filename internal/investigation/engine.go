// Package investigation owns the investigation workflow. The workflow is
// deterministic: the application decides which diagnostics run; the LLM only
// analyzes the evidence they produce.
package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/diagnostics"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/llm"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/observability"
)

var (
	// ErrBusy means all investigation slots are in use; retry later.
	ErrBusy = errors.New("too many concurrent investigations")
	// ErrInvalidOptions wraps problems with the caller's options.
	ErrInvalidOptions = errors.New("invalid investigation options")
	// ErrAnalysisFailed wraps failures after the investigation started. The
	// returned record still contains the stored executions and evidence.
	ErrAnalysisFailed = errors.New("investigation failed")
)

type Store interface {
	GetIncident(ctx context.Context, id string) (domain.Incident, error)
	CreateInvestigation(ctx context.Context, inv *domain.Investigation) error
	FinishInvestigation(ctx context.Context, rec domain.InvestigationRecord) error
}

// Toolbox supplies the allowlisted tools; implemented by diagnostics.Toolbox.
type Toolbox interface {
	Tools(scenario string) (map[string]diagnostics.Tool, string, error)
}

type Config struct {
	Timeout       time.Duration // whole investigation
	ToolTimeout   time.Duration // each diagnostic
	MaxConcurrent int
}

type Engine struct {
	store    Store
	toolbox  Toolbox
	provider llm.Provider
	log      *slog.Logger
	cfg      Config
	slots    chan struct{}
}

func NewEngine(store Store, toolbox Toolbox, provider llm.Provider, log *slog.Logger, cfg Config) *Engine {
	if cfg.ToolTimeout <= 0 {
		cfg.ToolTimeout = 10 * time.Second
	}
	return &Engine{store: store, toolbox: toolbox, provider: provider, log: log, cfg: cfg,
		slots: make(chan struct{}, max(cfg.MaxConcurrent, 1))}
}

type Options struct {
	// Scenario selects a simulation scenario; empty uses the default.
	Scenario string `json:"scenario"`
}

// Investigate runs the full workflow for one incident and returns everything
// it produced. On ErrAnalysisFailed the record is still returned.
func (e *Engine) Investigate(ctx context.Context, incidentID string, opts Options) (domain.InvestigationRecord, error) {
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return domain.InvestigationRecord{}, ErrBusy
	}

	tools, scenario, err := e.toolbox.Tools(opts.Scenario)
	if err != nil {
		return domain.InvestigationRecord{}, fmt.Errorf("%w: %v", ErrInvalidOptions, err)
	}
	inc, err := e.store.GetIncident(ctx, incidentID)
	if err != nil {
		return domain.InvestigationRecord{}, fmt.Errorf("load incident: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	start := time.Now()

	rec := domain.InvestigationRecord{
		Investigation: domain.Investigation{IncidentID: inc.ID, Status: domain.InvestigationRunning, Scenario: scenario},
	}
	if err := e.store.CreateInvestigation(ctx, &rec.Investigation); err != nil {
		return domain.InvestigationRecord{}, fmt.Errorf("create investigation: %w", err)
	}
	log := e.log.With("incident_id", inc.ID, "investigation_id", rec.Investigation.ID)
	log.InfoContext(ctx, "investigation started", "scenario", scenario)

	target := diagnostics.Target{Host: inc.TargetHost, Port: inc.TargetPort}
	for _, name := range plan(inc) {
		te, ev := e.runTool(ctx, log, tools[name], target)
		rec.ToolExecutions = append(rec.ToolExecutions, te)
		if ev != nil {
			rec.Evidence = append(rec.Evidence, *ev)
		}
	}

	analysisErr := e.analyze(ctx, log, inc, &rec)

	now := time.Now().UTC()
	rec.Investigation.CompletedAt = &now
	rec.Investigation.Status = domain.InvestigationCompleted
	if analysisErr != nil {
		rec.Investigation.Status = domain.InvestigationFailed
		rec.Investigation.Error = analysisErr.Error()
	}

	// Persist even if the caller went away or the deadline passed, so an
	// investigation never stays "running".
	saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer saveCancel()
	if err := e.store.FinishInvestigation(saveCtx, rec); err != nil {
		log.ErrorContext(ctx, "persist investigation", "error", err)
		return rec, fmt.Errorf("persist investigation: %w", err)
	}

	duration := time.Since(start)
	observability.InvestigationsTotal.WithLabelValues(string(rec.Investigation.Status)).Inc()
	observability.InvestigationDuration.Observe(duration.Seconds())
	log.InfoContext(ctx, "investigation finished", "status", rec.Investigation.Status, "duration_ms", duration.Milliseconds())

	if analysisErr != nil {
		return rec, fmt.Errorf("%w: %v", ErrAnalysisFailed, analysisErr)
	}
	return rec, nil
}

// plan is the deterministic diagnostic plan for an incident.
func plan(inc domain.Incident) []string {
	var steps []string
	if !domain.IsIP(inc.TargetHost) {
		steps = append(steps, diagnostics.DNS)
	}
	steps = append(steps, diagnostics.Ping)
	if inc.TargetPort > 0 {
		steps = append(steps, diagnostics.TCP)
	}
	return steps
}

func (e *Engine) runTool(ctx context.Context, log *slog.Logger, tool diagnostics.Tool, target diagnostics.Target) (domain.ToolExecution, *domain.Evidence) {
	name := tool.Name()
	input, _ := json.Marshal(target) // Target always marshals
	te := domain.ToolExecution{ID: domain.NewID(), ToolName: name, Input: input, StartedAt: time.Now().UTC()}

	toolCtx, cancel := context.WithTimeout(ctx, e.cfg.ToolTimeout)
	res, err := tool.Run(toolCtx, target)
	cancel()
	te.DurationMs = time.Since(te.StartedAt).Milliseconds()

	var output []byte
	if err == nil {
		output, err = json.Marshal(res.Data)
	}
	if err != nil {
		te.Status, te.Error = domain.ToolFailed, err.Error()
		observability.ToolFailuresTotal.WithLabelValues(name).Inc()
		log.WarnContext(ctx, "diagnostic failed", "tool_name", name, "duration_ms", te.DurationMs, "status", te.Status, "error", err)
		return te, nil
	}
	te.Status, te.Output = domain.ToolSucceeded, output
	observability.ToolExecutionsTotal.WithLabelValues(name, string(res.Health)).Inc()
	log.InfoContext(ctx, "diagnostic completed", "tool_name", name, "duration_ms", te.DurationMs, "status", te.Status, "health", res.Health)
	return te, &domain.Evidence{
		ID: domain.NewID(), ToolExecutionID: te.ID, Source: name, Health: res.Health, Summary: res.Summary, Data: output,
	}
}

// analyze calls the provider and validates its output. Only a valid analysis
// becomes a report.
func (e *Engine) analyze(ctx context.Context, log *slog.Logger, inc domain.Incident, rec *domain.InvestigationRecord) error {
	if len(rec.Evidence) == 0 {
		return errors.New("no diagnostic evidence collected; every tool failed")
	}
	provider := e.provider.Name()
	start := time.Now()
	analysis, err := e.provider.AnalyzeIncident(ctx, llm.AnalysisInput{Incident: inc, Evidence: rec.Evidence})
	observability.LLMRequestDuration.WithLabelValues(provider).Observe(time.Since(start).Seconds())
	if err == nil {
		sources := make([]string, len(rec.Evidence))
		for i, ev := range rec.Evidence {
			sources[i] = ev.Source
		}
		if verr := analysis.Validate(sources); verr != nil {
			err = fmt.Errorf("%w: %v", llm.ErrInvalidOutput, verr)
		}
	}
	if err != nil {
		reason := "request"
		if errors.Is(err, llm.ErrInvalidOutput) {
			reason = "invalid_output"
		}
		observability.LLMRequestsTotal.WithLabelValues(provider, "error").Inc()
		observability.LLMFailuresTotal.WithLabelValues(provider, reason).Inc()
		// The error never contains the raw model response, only a summary.
		log.ErrorContext(ctx, "analysis failed", "provider", provider, "reason", reason, "error", err)
		return fmt.Errorf("analysis by %s failed: %w", provider, err)
	}
	observability.LLMRequestsTotal.WithLabelValues(provider, "ok").Inc()
	rec.Report = &domain.Report{ID: domain.NewID(), Provider: provider, Analysis: analysis, CreatedAt: time.Now().UTC()}
	return nil
}
