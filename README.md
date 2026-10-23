# AI Network Incident Investigator

[![CI](https://github.com/kmpoltorak/ai-network-incident-investigator/actions/workflows/ci.yml/badge.svg)](https://github.com/kmpoltorak/ai-network-incident-investigator/actions/workflows/ci.yml)

A Go service for first-line triage of network incidents. You report an
incident such as "Warehouse WAW-01 has intermittent connectivity"; it runs a
fixed set of diagnostics (DNS, ping, TCP) against the target, stores every
result as evidence, and has an LLM or a built-in rules engine turn that evidence
into a validated report: root cause, confidence, severity, possible causes and
actions. It runs fully offline with simulated diagnostics and the rules engine.

```text
$ ID=$(curl -s -X POST localhost:8080/api/v1/incidents -H 'Content-Type: application/json' \
    -d @docs/examples/packet_loss.json | jq -r .id)
$ curl -s -X POST localhost:8080/api/v1/incidents/$ID/investigate -H 'Content-Type: application/json' \
    -d '{"scenario":"packet_loss"}' | jq '{status: .investigation.status, evidence: [.evidence[] | "\(.source) \(.health): \(.summary)"], root_cause: .report.analysis.root_cause, confidence: .report.analysis.confidence, severity: .report.analysis.severity}'
{
  "status": "completed",
  "evidence": [
    "dns healthy: gw.waw01.example.net resolved to 10.20.30.40",
    "ping degraded: 18% packet loss, avg latency 47.2 ms",
    "tcp healthy: TCP gw.waw01.example.net:443 reachable, handshake 51.3 ms"
  ],
  "root_cause": "Packet loss on the network path",
  "confidence": 0.8,
  "severity": "high"
}
```

- The application picks the diagnostics, their arguments and order from a hard-coded allowlist (`dns`, `ping`, `tcp`); the LLM only analyzes and cannot run anything. `ping` runs with fixed argv, no shell.
- LLM output is decoded strictly and validated; an analysis that cites a diagnostic that was not collected is rejected and never stored.
- A diagnostic that fails to run is recorded and passed to the analyzer as missing, never read as healthy.
- Executions, evidence and the report are stored in one transaction. On `SIGTERM` running investigations are saved as `failed` with the evidence so far; investigations orphaned by a crash are marked `failed` at startup.
- When the analysis fails, the API answers `502` and still returns the stored executions and evidence.

## Install

Requires Docker with Compose v2.

```bash
git clone https://github.com/kmpoltorak/ai-network-incident-investigator.git
cd ai-network-incident-investigator
cp .env.example .env
```

## Quick start

```bash
docker compose up --build
```

Open http://localhost:8080, pick a sample (packet loss, DNS or TCP), create the
incident and click **Run investigation**. Optional profiles:

```bash
LLM_PROVIDER=ollama docker compose --profile ollama up --build   # Ollama, pulls llama3.2 (~2 GB)
docker compose --profile monitoring up --build                   # Prometheus :9090, Grafana :3000
```

Without Docker (Go 1.27 and PostgreSQL): set `DATABASE_URL` in `.env`, then
`make web` (optional, embeds the UI) and `make run`.

## Configuration

Environment variables. Invalid values stop startup with a message naming every
bad variable.

| Variable | Default | Meaning |
|---|---|---|
| `APP_ENV` | `development` | `development` or `production` |
| `HTTP_PORT` | `8080` | listen port |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `DATABASE_URL` | required | PostgreSQL connection string |
| `LLM_PROVIDER` | `rules` | `rules`, `openai`, `ollama` |
| `LLM_MODEL` | per provider | `gpt-4o-mini` (openai), `llama3.2` (ollama) |
| `LLM_TIMEOUT` | `60s` | per LLM request |
| `OPENAI_API_KEY` | | required for `openai` |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | any OpenAI-compatible endpoint |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server |
| `SIMULATION_ENABLED` | `true` | simulated diagnostics |
| `SIMULATION_SCENARIO` | `healthy` | default scenario |
| `INVESTIGATION_TIMEOUT` | `90s` | whole investigation |
| `MAX_CONCURRENT_INVESTIGATIONS` | `4` | more get `429` with `Retry-After` |

**Simulation.** Scenarios return fixed values in the same types as the real tools:

| Scenario | dns | ping | tcp |
|---|---|---|---|
| `healthy` | resolves | 0% loss, 12.4 ms | reachable, 14.1 ms |
| `packet_loss` | resolves | 18% loss, 47.2 ms | reachable, 51.3 ms |
| `dns_failure` | NXDOMAIN | healthy | healthy |
| `tcp_failure` | resolves | healthy | connection refused |
| `high_latency` | resolves | 0% loss, 381.6 ms | reachable, 395.2 ms |

Pick one per investigation with `{"scenario": "..."}`; outside simulation mode
that returns `400`. With `SIMULATION_ENABLED=false` the tools probe the real
target: the OS `ping`, the Go resolver and a TCP handshake with no payload.

**Providers.** `rules` (default, no network) triages in order: resolution,
reachability, ICMP filtering, service port, packet loss, latency, and concludes
only from checks that ran. `openai` uses Chat Completions with a strict JSON
schema; `ollama` uses `/api/chat` with the schema in `format`. Both run at
temperature 0 with the prompt in
[internal/llm/system_prompt.txt](internal/llm/system_prompt.txt).

## API

| Method | Path | Success | Errors |
|---|---|---|---|
| POST | `/api/v1/incidents` | 201 + `Location` | 400, 413 |
| GET | `/api/v1/incidents?limit=&offset=` (limit ≤ 100, newest first) | 200 | 400 |
| GET | `/api/v1/incidents/{id}` | 200 | 400, 404 |
| POST | `/api/v1/incidents/{id}/investigate` (body optional) | 201 | 400, 404, 429, 502 |
| GET | `/api/v1/incidents/{id}/report` (latest completed) | 200 | 404 |
| GET | `/health`, `/ready` (database ping), `/metrics` | 200 | 503 (`/ready`) |

Errors look like `{"error": {"code": "...", "message": "..."}, "request_id": "..."}`.
Requests are strict JSON (unknown fields rejected, 1 MiB limit) and the target
must be an RFC 1123 hostname or an IP. `X-Request-ID` and `traceparent` are
validated and echoed or generated. Logs are JSON with request, trace,
incident and investigation IDs; secrets are redacted. The `monitoring` profile
provisions a Grafana dashboard from [deployments/grafana/](deployments/grafana/).

**Kubernetes.** [deployments/kubernetes/](deployments/kubernetes/) (kustomize)
has the Namespace, ConfigMap, Deployment (2 replicas), Service and Ingress;
PostgreSQL is external. Create the secret first (shape in
`secret.example.yaml`, which is not in the kustomization):

```bash
kubectl create namespace incident-investigator
kubectl -n incident-investigator create secret generic incident-investigator \
  --from-literal=DATABASE_URL='postgres://user:pass@host:5432/investigator?sslmode=require' \
  --from-literal=OPENAI_API_KEY=
kubectl apply -k deployments/kubernetes
```

The container runs as UID 10001 with a read-only root filesystem, no
capabilities and `no-new-privileges` (plus `RuntimeDefault` seccomp in
Kubernetes); ICMP works through unprivileged ping sockets.

## Limitations

- The service probes whatever host a user gives it, and there is no authentication or target allowlist. Deploy it where that is acceptable.
- Per-client rate limiting is left to the ingress.
- Investigations are synchronous and the tools run one after another.
- Diagnostics are DNS, ping and TCP only: no traceroute, MTR, interface counters, BGP or syslog.
- The live AI evaluation has been run with `llama3.2` on CPU only (5/5 scenarios, about 45 s each). The OpenAI client is tested against a fake server.
- The Kubernetes manifests were checked on minikube v1.34 only.

## Development

```bash
make test               # unit tests with the race detector
make test-integration   # starts a disposable PostgreSQL container, runs integration tests
make lint               # gofmt, go vet, golangci-lint
LLM_PROVIDER=ollama LLM_TIMEOUT=150s go test -tags eval -v ./internal/investigation/   # live AI evaluation
```

Unit tests cover config, host validation, ping output parsing (Linux, BusyBox,
macOS), each tool, the simulation, analysis validation and strict decoding, the
OpenAI and Ollama clients against `httptest` servers, the engine with an
in-memory store (tool failures, invalid output, cancellation, shutdown,
concurrency limit) and the HTTP handlers. Integration tests (`-tags integration`)
run migrations up and down and the full API against real PostgreSQL. A
deterministic evaluation runs every scenario through the rules provider and
checks the root-cause category. CI also runs `govulncheck`, `npm audit` and a
Docker build.

Built with an AI coding assistant. I wrote the spec and reviewed every change.

## License

MIT, see [LICENSE](LICENSE).
