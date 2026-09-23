package diagnostics

import (
	"context"
	"fmt"
	"slices"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

// Scenarios supported by simulation mode.
var Scenarios = []string{"healthy", "packet_loss", "dns_failure", "tcp_failure", "high_latency"}

// simulatedTool returns fixed, realistic results for a scenario. It uses the
// same result types as the real tools, so consumers cannot tell them apart.
type simulatedTool struct {
	name     string
	scenario string
}

func (s simulatedTool) Name() string { return s.name }

func (s simulatedTool) Run(ctx context.Context, t Target) (Result, error) {
	if err := t.Validate(); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	switch s.name {
	case DNS:
		return simulateDNS(s.scenario, t), nil
	case Ping:
		return simulatePing(s.scenario, t), nil
	case TCP:
		return simulateTCP(s.scenario, t), nil
	}
	return Result{}, fmt.Errorf("no simulation for tool %q", s.name)
}

func simulateDNS(scenario string, t Target) Result {
	if scenario == "dns_failure" {
		return DNSResult{Hostname: t.Host, Addresses: []string{}, ResponseStatus: "nxdomain", Error: "no such host"}.result()
	}
	return DNSResult{Hostname: t.Host, Addresses: []string{"10.20.30.40"}, ResponseStatus: "resolved"}.result()
}

func simulatePing(scenario string, t Target) Result {
	r := PingResult{Target: t.Host, PacketsSent: 50, PacketsReceived: 50, LatencyAvgMs: 12.4, Status: domain.Healthy}
	switch scenario {
	case "packet_loss":
		r.PacketsReceived, r.PacketLossPercent, r.LatencyAvgMs, r.Status = 41, 18, 47.2, domain.Degraded
	case "high_latency":
		r.LatencyAvgMs, r.Status = 381.6, domain.Degraded
	}
	return r.result()
}

func simulateTCP(scenario string, t Target) Result {
	r := TCPResult{Host: t.Host, Port: t.Port, Reachable: true, LatencyMs: 14.1}
	switch scenario {
	case "packet_loss":
		r.LatencyMs = 51.3 // retransmitted SYNs inflate handshake time
	case "high_latency":
		r.LatencyMs = 395.2
	case "tcp_failure":
		r.Reachable, r.LatencyMs = false, 0.8
		r.Error = fmt.Sprintf("dial tcp %s:%d: connect: connection refused", t.Host, t.Port)
	}
	return r.result()
}

// Toolbox hands out the allowlisted tools, either real or simulated.
type Toolbox struct {
	simulated       bool
	defaultScenario string
}

func NewToolbox(simulated bool, defaultScenario string) (Toolbox, error) {
	if simulated && !slices.Contains(Scenarios, defaultScenario) {
		return Toolbox{}, fmt.Errorf("unknown simulation scenario %q (valid: %v)", defaultScenario, Scenarios)
	}
	return Toolbox{simulated: simulated, defaultScenario: defaultScenario}, nil
}

// Tools returns the tool set keyed by name and the effective scenario ("" in
// real mode). Requesting a scenario outside simulation mode is an error.
func (b Toolbox) Tools(scenario string) (map[string]Tool, string, error) {
	if !b.simulated {
		if scenario != "" {
			return nil, "", fmt.Errorf("scenario %q requires simulation mode", scenario)
		}
		return map[string]Tool{DNS: DNSTool{}, Ping: PingTool{Count: 4}, TCP: TCPTool{}}, "", nil
	}
	if scenario == "" {
		scenario = b.defaultScenario
	}
	if !slices.Contains(Scenarios, scenario) {
		return nil, "", fmt.Errorf("unknown simulation scenario %q (valid: %v)", scenario, Scenarios)
	}
	tools := map[string]Tool{}
	for _, name := range []string{DNS, Ping, TCP} {
		tools[name] = simulatedTool{name: name, scenario: scenario}
	}
	return tools, scenario, nil
}
