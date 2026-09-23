package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

type TCPResult struct {
	Host      string  `json:"host"`
	Port      int     `json:"port"`
	Reachable bool    `json:"reachable"`
	LatencyMs float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}

func (r TCPResult) result() Result {
	if !r.Reachable {
		return Result{
			Health:  domain.Down,
			Summary: fmt.Sprintf("TCP %s:%d unreachable: %s", r.Host, r.Port, r.Error),
			Data:    r,
		}
	}
	return Result{
		Health:  healthForLatency(r.LatencyMs),
		Summary: fmt.Sprintf("TCP %s:%d reachable, handshake %.1f ms", r.Host, r.Port, r.LatencyMs),
		Data:    r,
	}
}

// TCPTool measures whether a TCP handshake to host:port completes. It sends
// no payload.
type TCPTool struct {
	Timeout time.Duration
}

func (TCPTool) Name() string { return TCP }

func (c TCPTool) Run(ctx context.Context, t Target) (Result, error) {
	if err := t.Validate(); err != nil {
		return Result{}, err
	}
	if t.Port == 0 {
		return Result{}, errors.New("tcp check requires a port")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)))
	r := TCPResult{Host: t.Host, Port: t.Port, LatencyMs: msSince(start)}
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, fmt.Errorf("tcp check: %w", ctx.Err())
		}
		r.Error = err.Error()
		return r.result(), nil
	}
	_ = conn.Close()
	r.Reachable = true
	return r.result(), nil
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000
}
