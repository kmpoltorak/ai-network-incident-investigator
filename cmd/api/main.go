// Command api runs the AI Network Incident Investigator HTTP server.
//
// Usage:
//
//	api                 start the server (applies pending migrations first)
//	api migrate up      apply pending migrations
//	api migrate down    roll back the latest migration
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/api"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/config"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/diagnostics"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/incidents"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/investigation"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/llm"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/observability"
	"github.com/kmpoltorak/ai-network-incident-investigator/internal/storage"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	log := observability.NewLogger(os.Stdout, cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	store, err := storage.Connect(connectCtx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()

	if len(args) > 0 {
		return migrateCommand(ctx, store, args, log)
	}
	n, err := store.MigrateUp(ctx)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Info("database ready", "migrations_applied", n)

	toolbox, err := diagnostics.NewToolbox(cfg.SimulationEnabled, cfg.SimulationScenario)
	if err != nil {
		return fmt.Errorf("SIMULATION_SCENARIO: %w", err)
	}
	provider := llm.FromConfig(cfg)
	engine := investigation.NewEngine(store, toolbox, provider, log, investigation.Config{
		Timeout:       cfg.InvestigationTimeout,
		MaxConcurrent: cfg.MaxConcurrentInvestigations,
	})

	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.HTTPPort),
		Handler:           api.New(incidents.NewService(store), engine, store.Ping, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Investigations run synchronously, so writes may take up to the
		// investigation timeout.
		WriteTimeout:   cfg.InvestigationTimeout + 15*time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server starting", "addr", srv.Addr, "config", cfg.String())
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("server stopped")
	return nil
}

func migrateCommand(ctx context.Context, store *storage.Store, args []string, log *slog.Logger) error {
	if len(args) != 2 || args[0] != "migrate" {
		return errors.New("usage: api [migrate up|down]")
	}
	switch args[1] {
	case "up":
		n, err := store.MigrateUp(ctx)
		if err == nil {
			log.Info("migrations applied", "count", n)
		}
		return err
	case "down":
		err := store.MigrateDown(ctx)
		if err == nil {
			log.Info("rolled back latest migration")
		}
		return err
	}
	return errors.New("usage: api [migrate up|down]")
}
