package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

// RulesProvider is a deterministic analyzer that needs no external model.
// It makes the platform usable offline and is the baseline for evaluation
// tests. It encodes the same triage order an engineer would follow:
// name resolution, then reachability, then service, then path quality.
type RulesProvider struct{}

func (RulesProvider) Name() string { return "rules/rules-v1" }

func (RulesProvider) AnalyzeIncident(_ context.Context, in AnalysisInput) (domain.Analysis, error) {
	if len(in.Evidence) == 0 {
		return domain.Analysis{}, fmt.Errorf("rules: no evidence to analyze")
	}
	bySource := map[string]domain.Evidence{}
	var refs []domain.EvidenceReference
	for _, e := range in.Evidence {
		bySource[e.Source] = e
		refs = append(refs, domain.EvidenceReference{Source: e.Source, Description: e.Summary})
	}
	health := func(src string) domain.Health { return bySource[src].Health }

	a := domain.Analysis{Evidence: refs}
	switch {
	case health("dns") == domain.Down:
		a.Summary = fmt.Sprintf("%s cannot be resolved; clients cannot locate the service.", in.Incident.TargetHost)
		a.RootCause = "DNS resolution failure"
		a.Confidence, a.Severity = 0.9, domain.SeverityHigh
		a.PossibleCauses = []string{"missing or deleted DNS record", "misconfigured or unreachable DNS resolver", "split-horizon zone not served to this network"}
		a.RecommendedActions = []string{"query the record against each configured resolver (dig @resolver name)", "verify the record exists in the authoritative zone", "check recent DNS or DHCP resolver configuration changes"}

	case health("ping") == domain.Down && health("tcp") != domain.Healthy:
		a.Summary = fmt.Sprintf("%s does not answer ICMP or TCP; the host or the path to it is down.", in.Incident.TargetHost)
		a.RootCause = "Host unreachable"
		a.Confidence, a.Severity = 0.8, domain.SeverityCritical
		a.PossibleCauses = []string{"host powered off or crashed", "routing failure on the path", "firewall dropping all traffic"}
		a.RecommendedActions = []string{"check host power and console", "run traceroute to locate where the path stops", "review recent firewall and routing changes"}

	case health("tcp") == domain.Down:
		a.Summary = fmt.Sprintf("%s is reachable, but TCP port %d is not accepting connections.", in.Incident.TargetHost, in.Incident.TargetPort)
		a.RootCause = "TCP connectivity failure: service port unreachable"
		a.Confidence, a.Severity = 0.85, domain.SeverityHigh
		a.PossibleCauses = []string{"service process stopped or not listening", "host or network firewall blocking the port", "service bound to a different interface or port"}
		a.RecommendedActions = []string{"check the service status and listening sockets on the host (ss -ltnp)", "review firewall rules and security groups for the port", "inspect service logs for crashes or restarts"}

	case health("ping") == domain.Down:
		a.Summary = fmt.Sprintf("%s does not answer ping but accepts TCP connections; ICMP is likely filtered.", in.Incident.TargetHost)
		a.RootCause = "ICMP filtered; no connectivity fault detected"
		a.Confidence, a.Severity = 0.6, domain.SeverityLow
		a.PossibleCauses = []string{"firewall policy dropping ICMP echo", "ICMP rate limiting on an intermediate device"}
		a.RecommendedActions = []string{"confirm whether ICMP is intentionally blocked by policy", "use TCP-based checks for monitoring this host"}

	case packetLoss(bySource["ping"]) > 0:
		loss := packetLoss(bySource["ping"])
		a.Summary = fmt.Sprintf("%.0f%% packet loss towards %s indicates WAN or link degradation.", loss, in.Incident.TargetHost)
		a.RootCause = "Packet loss on the network path"
		a.Confidence, a.Severity = 0.8, domain.SeverityHigh
		if loss < 5 {
			a.Confidence, a.Severity = 0.6, domain.SeverityMedium
		}
		a.PossibleCauses = []string{"physical link degradation (optics, cabling)", "congested WAN or ISP circuit", "duplex mismatch or interface errors"}
		a.RecommendedActions = []string{"check interface error and discard counters along the path", "verify ISP circuit health with the provider", "run an extended ping or MTR to locate the lossy hop"}

	case health("ping") == domain.Degraded || health("tcp") == domain.Degraded:
		a.Summary = fmt.Sprintf("Latency towards %s is elevated without packet loss.", in.Incident.TargetHost)
		a.RootCause = "High network latency"
		a.Confidence, a.Severity = 0.75, domain.SeverityMedium
		a.PossibleCauses = []string{"congested link or bufferbloat", "suboptimal routing path", "overloaded intermediate device"}
		a.RecommendedActions = []string{"compare latency against the historical baseline", "run MTR to find the hop where latency increases", "check link utilization on the WAN edge"}

	default:
		a.Summary = "All diagnostics are healthy; the evidence does not show a network-layer fault. The problem may be in the application layer."
		a.RootCause = "No network-layer fault detected"
		a.Confidence, a.Severity = 0.5, domain.SeverityLow
		a.PossibleCauses = []string{"application-level error", "intermittent issue not present during the checks"}
		a.RecommendedActions = []string{"check application logs and error rates", "re-run the investigation while the problem is occurring"}
	}
	return a, nil
}

func packetLoss(e domain.Evidence) float64 {
	var d struct {
		PacketLossPercent float64 `json:"packet_loss_percent"`
	}
	_ = json.Unmarshal(e.Data, &d) // missing or foreign data means no known loss
	return d.PacketLossPercent
}
