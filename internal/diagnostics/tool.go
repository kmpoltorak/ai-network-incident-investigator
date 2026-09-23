// Package diagnostics contains the allowlisted network diagnostic tools and
// their simulated counterparts. Tools take a validated Target and return a
// structured Result; they never accept free-form commands.
package diagnostics

import (
	"context"
	"fmt"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

// Tool names form the complete allowlist.
const (
	DNS  = "dns"
	Ping = "ping"
	TCP  = "tcp"
)

type Target struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
}

// Validate is the last line of defense before a target reaches a tool.
func (t Target) Validate() error {
	if err := domain.ValidateHost(t.Host); err != nil {
		return fmt.Errorf("host %w", err)
	}
	if t.Port < 0 || t.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

// Result is a completed observation. A Down health is a valid result: the
// tool worked and observed a failure. Tools return an error only when they
// could not observe anything.
type Result struct {
	Health  domain.Health
	Summary string
	Data    any
}

type Tool interface {
	Name() string
	Run(ctx context.Context, t Target) (Result, error)
}

// Latency above this threshold is reported as degraded.
const highLatencyMs = 150

func healthForLatency(ms float64) domain.Health {
	if ms > highLatencyMs {
		return domain.Degraded
	}
	return domain.Healthy
}
