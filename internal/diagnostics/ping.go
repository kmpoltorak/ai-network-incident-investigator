package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

type PingResult struct {
	Target            string        `json:"target"`
	PacketsSent       int           `json:"packets_sent"`
	PacketsReceived   int           `json:"packets_received"`
	PacketLossPercent float64       `json:"packet_loss_percent"`
	LatencyAvgMs      float64       `json:"latency_avg_ms"`
	Status            domain.Health `json:"status"`
}

func (r PingResult) result() Result {
	return Result{
		Health:  r.Status,
		Summary: fmt.Sprintf("%.0f%% packet loss, avg latency %.1f ms", r.PacketLossPercent, r.LatencyAvgMs),
		Data:    r,
	}
}

// PingTool runs the system ping binary. ICMP needs raw or ping sockets, which
// the OS binary already knows how to obtain; arguments are fixed and the host
// is validated, and no shell is involved.
type PingTool struct {
	Count int
}

func (PingTool) Name() string { return Ping }

func (p PingTool) Run(ctx context.Context, t Target) (Result, error) {
	if err := t.Validate(); err != nil {
		return Result{}, err
	}
	count := max(p.Count, 1)
	out, err := exec.CommandContext(ctx, "ping", "-n", "-c", strconv.Itoa(count), "--", t.Host).CombinedOutput()
	// ping exits non-zero on packet loss; the output is still meaningful.
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return Result{}, fmt.Errorf("run ping: %w", err)
	}
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("ping: %w", ctx.Err())
	}
	r, perr := parsePing(string(out))
	if perr != nil {
		return Result{}, fmt.Errorf("ping %s: %w: %s", t.Host, perr, truncate(string(out), 200))
	}
	r.Target = t.Host
	return r.result(), nil
}

var (
	// Linux: "4 packets transmitted, 4 received, 0% packet loss"
	// macOS/BusyBox: "4 packets transmitted, 4 packets received, 0.0% packet loss"
	pingSummary = regexp.MustCompile(`(\d+) packets transmitted, (\d+) (?:packets )?received.*?([\d.]+)% packet loss`)
	// "rtt min/avg/max/mdev = 0.1/0.2/0.3/0.0 ms" or "round-trip min/avg/max = ..."
	pingRTT = regexp.MustCompile(`= [\d.]+/([\d.]+)/`)
)

// parsePing extracts statistics from ping output across Linux (iputils),
// BusyBox and macOS formats.
func parsePing(out string) (PingResult, error) {
	m := pingSummary.FindStringSubmatch(out)
	if m == nil {
		return PingResult{}, errors.New("unrecognized ping output")
	}
	var r PingResult
	r.PacketsSent, _ = strconv.Atoi(m[1])
	r.PacketsReceived, _ = strconv.Atoi(m[2])
	r.PacketLossPercent, _ = strconv.ParseFloat(m[3], 64)
	if rtt := pingRTT.FindStringSubmatch(out); rtt != nil {
		r.LatencyAvgMs, _ = strconv.ParseFloat(rtt[1], 64)
	}
	switch {
	case r.PacketsReceived == 0:
		r.Status = domain.Down
	case r.PacketLossPercent > 0:
		r.Status = domain.Degraded
	default:
		r.Status = healthForLatency(r.LatencyAvgMs)
	}
	return r, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
