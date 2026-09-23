package diagnostics

import (
	"context"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

func TestParsePing(t *testing.T) {
	tests := []struct {
		name     string
		out      string
		loss     float64
		avg      float64
		received int
		health   domain.Health
	}{
		{"linux iputils healthy", `PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
--- 10.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 0.041/0.052/0.063/0.008 ms`, 0, 0.052, 4, domain.Healthy},
		{"linux iputils loss", `--- gw ping statistics ---
10 packets transmitted, 8 received, 20% packet loss, time 9012ms
rtt min/avg/max/mdev = 40.1/47.5/60.2/5.1 ms`, 20, 47.5, 8, domain.Degraded},
		{"macos", `--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.090/0.094/0.098/0.004 ms`, 0, 0.094, 2, domain.Healthy},
		{"busybox high latency", `--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max = 300.1/350.2/401.3 ms`, 0, 350.2, 4, domain.Degraded},
		{"total loss", `--- 10.9.9.9 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3060ms`, 100, 0, 0, domain.Down},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parsePing(tt.out)
			if err != nil {
				t.Fatal(err)
			}
			if r.PacketLossPercent != tt.loss || r.LatencyAvgMs != tt.avg || r.PacketsReceived != tt.received || r.Status != tt.health {
				t.Fatalf("got %+v", r)
			}
		})
	}
	if _, err := parsePing("ping: unknown host nope"); err == nil {
		t.Fatal("expected error for unrecognized output")
	}
}

func TestPingToolLoopback(t *testing.T) {
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("ping binary not available")
	}
	res, err := PingTool{Count: 1}.Run(context.Background(), Target{Host: "127.0.0.1"})
	if err != nil {
		t.Skipf("ping not permitted in this environment: %v", err)
	}
	if res.Health != domain.Healthy || res.Data.(PingResult).PacketsReceived != 1 {
		t.Fatalf("got %+v", res)
	}
}

func TestToolsRejectInvalidTargets(t *testing.T) {
	for _, tool := range []Tool{PingTool{}, DNSTool{}, TCPTool{}, simulatedTool{name: Ping, scenario: "healthy"}} {
		if _, err := tool.Run(context.Background(), Target{Host: "-c 1000 x", Port: 80}); err == nil {
			t.Errorf("%s accepted an invalid host", tool.Name())
		}
	}
}

func TestDNSTool(t *testing.T) {
	ctx := context.Background()
	res, err := DNSTool{}.Run(ctx, Target{Host: "localhost"})
	if err != nil || res.Health != domain.Healthy || len(res.Data.(DNSResult).Addresses) == 0 {
		t.Fatalf("localhost: res=%+v err=%v", res, err)
	}
	// .invalid is reserved and never resolves (RFC 6761).
	res, err = DNSTool{}.Run(ctx, Target{Host: "does-not-exist.invalid"})
	if err != nil || res.Health != domain.Down || res.Data.(DNSResult).ResponseStatus == "resolved" {
		t.Fatalf(".invalid: res=%+v err=%v", res, err)
	}
}

func TestTCPTool(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	openPort := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()

	tool := TCPTool{Timeout: time.Second}
	res, err := tool.Run(context.Background(), Target{Host: "127.0.0.1", Port: openPort})
	if err != nil || res.Health != domain.Healthy || !res.Data.(TCPResult).Reachable {
		t.Fatalf("open port: res=%+v err=%v", res, err)
	}
	res, err = tool.Run(context.Background(), Target{Host: "127.0.0.1", Port: closedPort})
	if err != nil || res.Health != domain.Down || res.Data.(TCPResult).Error == "" {
		t.Fatalf("closed port: res=%+v err=%v", res, err)
	}
	if _, err := tool.Run(context.Background(), Target{Host: "127.0.0.1"}); err == nil {
		t.Fatal("missing port accepted")
	}
}

func TestSimulationScenarios(t *testing.T) {
	want := map[string][3]domain.Health{ // dns, ping, tcp
		"healthy":      {domain.Healthy, domain.Healthy, domain.Healthy},
		"packet_loss":  {domain.Healthy, domain.Degraded, domain.Healthy},
		"dns_failure":  {domain.Down, domain.Healthy, domain.Healthy},
		"tcp_failure":  {domain.Healthy, domain.Healthy, domain.Down},
		"high_latency": {domain.Healthy, domain.Degraded, domain.Degraded},
	}
	box, err := NewToolbox(true, "healthy")
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Host: "app.example.com", Port: 443}
	for _, scenario := range Scenarios {
		t.Run(scenario, func(t *testing.T) {
			tools, effective, err := box.Tools(scenario)
			if err != nil || effective != scenario {
				t.Fatalf("Tools(%q): %v", scenario, err)
			}
			for i, name := range []string{DNS, Ping, TCP} {
				first, err := tools[name].Run(context.Background(), target)
				if err != nil {
					t.Fatal(err)
				}
				if first.Health != want[scenario][i] {
					t.Errorf("%s health = %s, want %s", name, first.Health, want[scenario][i])
				}
				again, _ := tools[name].Run(context.Background(), target)
				if again.Summary != first.Summary {
					t.Errorf("%s is not deterministic", name)
				}
			}
		})
	}
	if tr := mustRun(t, box, "packet_loss", Ping, target).Data.(PingResult); tr.PacketLossPercent != 18 {
		t.Errorf("packet_loss scenario loss = %v, want 18", tr.PacketLossPercent)
	}
}

func mustRun(t *testing.T, box Toolbox, scenario, tool string, target Target) Result {
	t.Helper()
	tools, _, err := box.Tools(scenario)
	if err != nil {
		t.Fatal(err)
	}
	r, err := tools[tool].Run(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestToolbox(t *testing.T) {
	if _, err := NewToolbox(true, "meteor_strike"); err == nil {
		t.Fatal("unknown default scenario accepted")
	}
	sim, _ := NewToolbox(true, "dns_failure")
	if _, s, _ := sim.Tools(""); s != "dns_failure" {
		t.Fatalf("default scenario not applied: %q", s)
	}
	if _, _, err := sim.Tools("nope"); err == nil {
		t.Fatal("unknown scenario accepted")
	}

	live, _ := NewToolbox(false, "")
	tools, s, err := live.Tools("")
	if err != nil || s != "" || len(tools) != 3 {
		t.Fatalf("real toolbox: %v %q %d", err, s, len(tools))
	}
	if _, ok := tools[Ping].(PingTool); !ok {
		t.Fatal("real toolbox returned a simulated ping")
	}
	if _, _, err := live.Tools("packet_loss"); err == nil {
		t.Fatal("scenario accepted outside simulation mode")
	}
}
