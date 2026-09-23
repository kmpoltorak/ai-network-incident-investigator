// Package storage implements persistence on PostgreSQL using plain SQL.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

type Store struct {
	pool *pgxpool.Pool
}

// Connect opens a connection pool and verifies connectivity. Every
// connection gets a server-side statement timeout so a stuck query cannot
// hold a request forever.
func Connect(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.MaxConns = 10
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "10000"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return s, nil
}

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
func (s *Store) Close()                         { s.pool.Close() }

func (s *Store) CreateIncident(ctx context.Context, in *domain.Incident) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO incidents (title, description, target_host, target_port)
		VALUES ($1, $2, $3, $4)
		RETURNING id, status, created_at, updated_at`,
		in.Title, in.Description, in.TargetHost, nullablePort(in.TargetPort),
	).Scan(&in.ID, &in.Status, &in.CreatedAt, &in.UpdatedAt)
}

const incidentColumns = `id, title, description, target_host, COALESCE(target_port, 0), status, created_at, updated_at`

func (s *Store) GetIncident(ctx context.Context, id string) (domain.Incident, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id = $1`, id)
	inc, err := scanIncident(row)
	return inc, notFound(err)
}

func (s *Store) ListIncidents(ctx context.Context, limit, offset int) ([]domain.Incident, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+incidentColumns+` FROM incidents ORDER BY created_at DESC, id LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (domain.Incident, error) { return scanIncident(r) })
}

func scanIncident(row pgx.Row) (domain.Incident, error) {
	var i domain.Incident
	err := row.Scan(&i.ID, &i.Title, &i.Description, &i.TargetHost, &i.TargetPort, &i.Status, &i.CreatedAt, &i.UpdatedAt)
	return i, err
}

func (s *Store) CreateInvestigation(ctx context.Context, inv *domain.Investigation) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO investigations (incident_id, status, scenario)
		VALUES ($1, $2, $3)
		RETURNING id, started_at`,
		inv.IncidentID, inv.Status, inv.Scenario,
	).Scan(&inv.ID, &inv.StartedAt)
}

// FinishInvestigation atomically stores everything an investigation produced
// and records its final status. The incident becomes "analyzed" only when a
// report is stored.
func (s *Store) FinishInvestigation(ctx context.Context, rec domain.InvestigationRecord) error {
	inv := rec.Investigation
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, te := range rec.ToolExecutions {
			if _, err := tx.Exec(ctx, `
				INSERT INTO tool_executions (id, investigation_id, tool_name, status, input, output, error, duration_ms, started_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
				te.ID, inv.ID, te.ToolName, te.Status, te.Input, nullableJSON(te.Output), te.Error, te.DurationMs, te.StartedAt,
			); err != nil {
				return fmt.Errorf("insert tool execution: %w", err)
			}
		}
		for _, ev := range rec.Evidence {
			if _, err := tx.Exec(ctx, `
				INSERT INTO evidence (id, investigation_id, tool_execution_id, source, health, summary, data)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				ev.ID, inv.ID, ev.ToolExecutionID, ev.Source, ev.Health, ev.Summary, ev.Data,
			); err != nil {
				return fmt.Errorf("insert evidence: %w", err)
			}
		}
		if r := rec.Report; r != nil {
			analysis, err := json.Marshal(r.Analysis)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO reports (id, investigation_id, summary, root_cause, confidence, severity, analysis, provider, created_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
				r.ID, inv.ID, r.Analysis.Summary, r.Analysis.RootCause, r.Analysis.Confidence, r.Analysis.Severity,
				analysis, r.Provider, r.CreatedAt,
			); err != nil {
				return fmt.Errorf("insert report: %w", err)
			}
			if _, err := tx.Exec(ctx,
				`UPDATE incidents SET status = 'analyzed', updated_at = now() WHERE id = $1`, inv.IncidentID); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx,
			`UPDATE investigations SET status = $2, error = $3, completed_at = $4 WHERE id = $1`,
			inv.ID, inv.Status, inv.Error, inv.CompletedAt)
		return err
	})
}

// LatestReport returns the most recent completed investigation of an
// incident with its executions, evidence and report.
func (s *Store) LatestReport(ctx context.Context, incidentID string) (domain.InvestigationRecord, error) {
	var rec domain.InvestigationRecord
	inv := &rec.Investigation
	err := s.pool.QueryRow(ctx, `
		SELECT id, incident_id, status, scenario, error, started_at, completed_at
		FROM investigations
		WHERE incident_id = $1 AND status = 'completed'
		ORDER BY started_at DESC LIMIT 1`, incidentID,
	).Scan(&inv.ID, &inv.IncidentID, &inv.Status, &inv.Scenario, &inv.Error, &inv.StartedAt, &inv.CompletedAt)
	if err != nil {
		return rec, notFound(err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, tool_name, status, input, COALESCE(output, 'null'::jsonb), error, duration_ms, started_at
		FROM tool_executions WHERE investigation_id = $1 ORDER BY started_at, id`, inv.ID)
	if err != nil {
		return rec, err
	}
	rec.ToolExecutions, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (domain.ToolExecution, error) {
		var te domain.ToolExecution
		err := r.Scan(&te.ID, &te.ToolName, &te.Status, &te.Input, &te.Output, &te.Error, &te.DurationMs, &te.StartedAt)
		return te, err
	})
	if err != nil {
		return rec, err
	}

	rows, err = s.pool.Query(ctx, `
		SELECT e.id, e.tool_execution_id, e.source, e.health, e.summary, e.data
		FROM evidence e JOIN tool_executions t ON t.id = e.tool_execution_id
		WHERE e.investigation_id = $1 ORDER BY t.started_at, e.id`, inv.ID)
	if err != nil {
		return rec, err
	}
	rec.Evidence, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (domain.Evidence, error) {
		var ev domain.Evidence
		err := r.Scan(&ev.ID, &ev.ToolExecutionID, &ev.Source, &ev.Health, &ev.Summary, &ev.Data)
		return ev, err
	})
	if err != nil {
		return rec, err
	}

	var r domain.Report
	var analysis []byte
	err = s.pool.QueryRow(ctx,
		`SELECT id, provider, analysis, created_at FROM reports WHERE investigation_id = $1`, inv.ID,
	).Scan(&r.ID, &r.Provider, &analysis, &r.CreatedAt)
	if err != nil {
		return rec, fmt.Errorf("load report: %w", err)
	}
	if err := json.Unmarshal(analysis, &r.Analysis); err != nil {
		return rec, fmt.Errorf("decode report analysis: %w", err)
	}
	rec.Report = &r
	return rec, nil
}

// notFound maps "no rows" and malformed UUIDs to domain.ErrNotFound.
func notFound(err error) error {
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == "22P02") {
		return domain.ErrNotFound
	}
	return err
}

func nullablePort(p int) *int {
	if p == 0 {
		return nil
	}
	return &p
}

func nullableJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
