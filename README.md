# AI Network Incident Investigator

[![CI](https://github.com/kmpoltorak/ai-network-incident-investigator/actions/workflows/ci.yml/badge.svg)](https://github.com/kmpoltorak/ai-network-incident-investigator/actions/workflows/ci.yml)

An AI-assisted network incident investigation service written in Go. You report an incident such as "Warehouse WAW-01 has intermittent connectivity". The service then runs a fixed, safe set of diagnostics (DNS, ping, TCP) against the affected target, stores every result as evidence, and asks an LLM to correlate that evidence into a **validated, structured report**: root cause, confidence, severity, cited evidence, possible causes and recommended actions.

![Web UI](docs/images/web-ui.png)

## Overview

First-line triage of network incidents is repetitive: ping the gateway, resolve the name, test the port, then reason about the combination. This project automates that loop and keeps a strict boundary around the AI:

- **The application owns the workflow.** It decides which diagnostics run, with which arguments, in which order.
- **The LLM only analyzes.** It receives structured evidence and returns JSON that must pass schema and evidence validation before it is stored. It cannot run tools, commands, or anything else.
- **Everything is auditable.** Every tool execution, piece of evidence and report is persisted in PostgreSQL.

It runs fully offline: **simulation mode** produces realistic, deterministic diagnostics, and a **rules provider** analyzes them without any external model. Switch to OpenAI or a local Ollama model with one environment variable.

## Features

- REST API for incidents, investigations and reports, plus a **React web UI** served by the same binary
- Diagnostics: **ping** (ICMP, unprivileged), **DNS** lookup, **TCP** connect check, with a hard-coded tool allowlist
- **Simulation mode** with five deterministic scenarios: `healthy`, `packet_loss`, `dns_failure`, `tcp_failure`, `high_latency`
- LLM providers: **OpenAI** (strict JSON schema), **Ollama** (schema-constrained output), deterministic **rules**
- Structured output validation: required fields, confidence range, severity enum, and **every cited evidence source must have actually been collected**
- PostgreSQL persistence with embedded, advisory-locked migrations
- Observability: JSON logs with request and trace IDs, Prometheus metrics, and a provisioned **Grafana dashboard**
- Production-style packaging: 35 MB non-root image, Docker Compose with optional profiles, hardened Kubernetes manifests, GitHub Actions CI

## Architecture

```mermaid
flowchart LR
    User([User / Web UI]) -->|HTTP JSON| API[REST API<br/>internal/api]
    API --> IS[Incident Service<br/>internal/incidents]
    API --> IE[Investigation Engine<br/>internal/investigation]
    IE --> TB[Toolbox<br/>internal/diagnostics]
    TB --> Real[Real tools<br/>ping · dns · tcp]
    TB --> Sim[Simulated tools<br/>5 scenarios]
    IE -->|structured evidence| LLM[LLM Analyzer<br/>internal/llm]
    LLM --> OpenAI
    LLM --> Ollama
    LLM --> Rules[Rules provider]
    IE -->|validated report| DB[(PostgreSQL<br/>internal/storage)]
    IS --> DB
    API -.->|/metrics| Prom[Prometheus] -.-> Graf[Grafana]
```

Investigation workflow:

1. Take a concurrency slot (HTTP 429 if all are busy).
2. Load the incident and create an investigation record (`running`).
3. Build a deterministic plan: `dns` (hostnames only), then `ping`, then `tcp` (only when a port is set).
4. Run each tool with its own timeout. A tool that cannot run is recorded as a failed execution and the investigation continues.
5. Normalize results into evidence (`healthy`, `degraded`, `down`) and send them to the provider.
6. Validate the analysis. Invalid or hallucinated output is rejected and never stored as a report.
7. Persist executions, evidence and the report in **one transaction**, with a context detached from the request so an investigation can never be left `running`.

The engine does not know whether the tools it receives are real or simulated.

## Technology Stack

| Area | Choice |
|------|--------|
| Language | Go 1.27 (standard library HTTP router, `log/slog`) |
| Database | PostgreSQL 17 via `pgx/v5`, plain SQL |
| Metrics | Prometheus `client_golang`, Grafana dashboard |
| LLM | OpenAI Chat Completions and Ollama over plain HTTP (no vendor SDKs) |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS, embedded with `go:embed` |
| Packaging | Multi-stage Docker (Node, Go, Alpine), Docker Compose, Kubernetes (kustomize) |
| CI | GitHub Actions: gofmt, go vet, golangci-lint, race tests, integration tests, govulncheck, npm audit, Docker build |

Direct Go dependencies: `pgx` and `prometheus/client_golang`, nothing else.

## Quick Start

Requirements: Docker with Compose v2.

```bash
cp .env.example .env
docker compose up --build
```

Then open **http://localhost:8080**, pick a sample (Packet loss, DNS or TCP), create the incident and click **Run investigation**.

Optional profiles:

```bash
# Local LLM: starts Ollama and pulls llama3.2 (about 2 GB) on first run
LLM_PROVIDER=ollama docker compose --profile ollama up --build

# Monitoring: Prometheus on :9090, Grafana on :3000 (dashboard is provisioned)
docker compose --profile monitoring up --build
```

Running locally without Docker (needs Go 1.27 and a PostgreSQL instance):

```bash
cp .env.example .env      # adjust DATABASE_URL
make web                  # optional: build the UI into the binary
make run
```

## Example Incident

Sample payloads live in [`docs/examples/`](docs/examples/).

```bash
curl -s -X POST localhost:8080/api/v1/incidents \
  -H 'Content-Type: application/json' \
  -d @docs/examples/packet_loss.json
```

```json
{
  "id": "6ab33712-7aec-47ce-9762-d5b92be60af2",
  "title": "Warehouse WAW-01 has intermittent connectivity",
  "description": "Handheld scanners in warehouse WAW-01 lose connection to the WMS every few minutes since 08:00. Wired terminals are also affected.",
  "target_host": "gw.waw01.example.net",
  "target_port": 443,
  "status": "open",
  "created_at": "2026-09-23T19:23:34.49Z",
  "updated_at": "2026-09-23T19:23:34.49Z"
}
```

## Example Investigation

```bash
curl -s -X POST localhost:8080/api/v1/incidents/6ab33712-7aec-47ce-9762-d5b92be60af2/investigate \
  -H 'Content-Type: application/json' -d '{"scenario":"packet_loss"}'
```

Response (abridged):

```json
{
  "investigation": { "id": "fedee72a-…", "status": "completed", "scenario": "packet_loss" },
  "tool_executions": [
    { "tool_name": "dns",  "status": "succeeded", "duration_ms": 0 },
    { "tool_name": "ping", "status": "succeeded", "duration_ms": 0 },
    { "tool_name": "tcp",  "status": "succeeded", "duration_ms": 0 }
  ],
  "evidence": [
    { "source": "dns",  "health": "healthy",  "summary": "gw.waw01.example.net resolved to 10.20.30.40" },
    { "source": "ping", "health": "degraded", "summary": "18% packet loss, avg latency 47.2 ms" },
    { "source": "tcp",  "health": "healthy",  "summary": "TCP gw.waw01.example.net:443 reachable, handshake 51.3 ms" }
  ],
  "report": {
    "provider": "rules/rules-v1",
    "analysis": {
      "summary": "18% packet loss towards gw.waw01.example.net indicates WAN or link degradation.",
      "root_cause": "Packet loss on the network path",
      "confidence": 0.8,
      "severity": "high",
      "evidence": [{ "source": "ping", "description": "18% packet loss, avg latency 47.2 ms" }],
      "possible_causes": ["physical link degradation (optics, cabling)", "congested WAN or ISP circuit", "duplex mismatch or interface errors"],
      "recommended_actions": ["check interface error and discard counters along the path", "verify ISP circuit health with the provider", "run an extended ping or MTR to locate the lossy hop"]
    }
  }
}
```

Results for the three reference incidents:

| Incident | Scenario | Root cause (rules) | Root cause (llama3.2) |
|----------|----------|--------------------|-----------------------|
| Warehouse WAW-01 has intermittent connectivity | `packet_loss` | Packet loss on the network path | Network congestion or packet loss |
| Users cannot resolve internal application hostnames | `dns_failure` | DNS resolution failure | DNS resolution failure for app.corp.example.com |
| Application cannot connect to the database service | `tcp_failure` | TCP connectivity failure: service port unreachable | connection refused due to unreachable host |

## API Usage

| Method | Path | Description | Success | Errors |
|--------|------|-------------|---------|--------|
| POST | `/api/v1/incidents` | Create an incident | 201 + `Location` | 400, 413 |
| GET | `/api/v1/incidents?limit=&offset=` | List, newest first (limit ≤ 100) | 200 | 400 |
| GET | `/api/v1/incidents/{id}` | Get one incident | 200 | 400, 404 |
| POST | `/api/v1/incidents/{id}/investigate` | Run an investigation (body optional: `{"scenario": "..."}`) | 201 | 400, 404, 429, 502 |
| GET | `/api/v1/incidents/{id}/report` | Latest completed investigation | 200 | 404 |
| GET | `/health` | Liveness | 200 | |
| GET | `/ready` | Readiness (database ping) | 200 | 503 |
| GET | `/metrics` | Prometheus metrics | 200 | |

All errors share one shape:

```json
{ "error": { "code": "validation_failed", "message": "target_host: must be a valid hostname or IP address" }, "request_id": "4f0c…" }
```

When the analysis fails (for example, the model returns invalid JSON), the API responds **502** with `error.code = "analysis_failed"` and a `result` field containing the stored executions and evidence, so the diagnostics are never lost.

Send `X-Request-ID` and W3C `traceparent` headers to correlate logs. Both are validated and echoed back or generated.

## Configuration

All settings come from environment variables. Invalid values stop startup with a message naming every bad variable.

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | `development` or `production` |
| `HTTP_PORT` | `8080` | Listen port |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `DATABASE_URL` | required | PostgreSQL connection string |
| `LLM_PROVIDER` | `rules` | `rules`, `openai`, `ollama` |
| `LLM_MODEL` | per provider | `gpt-4o-mini` (openai), `llama3.2` (ollama) |
| `LLM_TIMEOUT` | `60s` | Timeout per LLM request |
| `OPENAI_API_KEY` | | Required when `LLM_PROVIDER=openai` |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | Any OpenAI-compatible endpoint |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server |
| `SIMULATION_ENABLED` | `true` | Use simulated diagnostics |
| `SIMULATION_SCENARIO` | `healthy` | Default scenario |
| `INVESTIGATION_TIMEOUT` | `90s` | Whole-investigation deadline |
| `MAX_CONCURRENT_INVESTIGATIONS` | `4` | Further requests get 429 |

## Simulation Mode

With `SIMULATION_ENABLED=true`, the diagnostics are replaced by simulated tools that return the **same result types** as the real ones, with fixed values per scenario:

| Scenario | dns | ping | tcp |
|----------|-----|------|-----|
| `healthy` | resolves | 0% loss, 12.4 ms | reachable, 14.1 ms |
| `packet_loss` | resolves | **18% loss**, 47.2 ms | reachable, 51.3 ms |
| `dns_failure` | **NXDOMAIN** | healthy | healthy |
| `tcp_failure` | resolves | healthy | **connection refused** |
| `high_latency` | resolves | 0% loss, **381.6 ms** | reachable, **395.2 ms** |

Choose the scenario per investigation with `{"scenario": "dns_failure"}` or set a default with `SIMULATION_SCENARIO`. Outside simulation mode, a scenario in the request returns 400.

With `SIMULATION_ENABLED=false`, the tools probe the real target: the OS `ping` binary (fixed arguments, no shell), the Go DNS resolver, and a TCP handshake with no payload.

## LLM Providers

| Provider | How it works |
|----------|--------------|
| `rules` | Deterministic analyzer that triages in the order an engineer would: resolution, then reachability, then ICMP filtering, then service port, then packet loss, then latency. No network access; the default. |
| `openai` | Chat Completions with `response_format: json_schema` (strict) and temperature 0 |
| `ollama` | `/api/chat` with the same JSON schema in `format`, `stream: false` and temperature 0 |

The system prompt ([`internal/llm/system_prompt.txt`](internal/llm/system_prompt.txt)) requires the model to use only the supplied evidence, separate observations (`evidence`) from hypotheses (`possible_causes`), lower its confidence and admit uncertainty when evidence is weak, and return a single JSON object.

Every response is decoded strictly (unknown fields and trailing data are rejected) and validated. An analysis citing a source that was not collected (for example `bgp`) is rejected, so hallucinated diagnostics never reach the database.

## Testing

```bash
make test               # unit tests with the race detector
make test-integration   # starts a disposable PostgreSQL container, runs integration tests
make lint               # gofmt, go vet, golangci-lint
```

- **Unit tests** cover config parsing, host validation, ping output parsing (Linux, BusyBox, macOS), DNS and TCP tools, simulation scenarios, analysis validation, strict decoding, the OpenAI and Ollama clients against `httptest` servers, the rules provider, the engine with an in-memory store (tool failures, invalid output, cancellation, concurrency limit) and the HTTP handlers.
- **Integration tests** (`-tags integration`) cover migrations up and down, repository round-trips and the full API over real PostgreSQL using the sample incidents.
- **Deterministic AI evaluation** runs every scenario through the engine with the rules provider and requires the expected root-cause category.
- **Live AI evaluation** (`-tags eval`, opt-in) runs the same cases against a real model:

  ```bash
  LLM_PROVIDER=ollama LLM_TIMEOUT=150s go test -tags eval -v ./internal/investigation/
  ```

  With `llama3.2` on CPU in Docker, it passed **5/5** scenarios in about 45 s each.

## Observability

- **Logs:** JSON (`log/slog`) with `request_id`, `trace_id`, `incident_id`, `investigation_id`, `tool_name`, `duration_ms` and `status`. Secrets are never logged, and the config is printed redacted.
- **Metrics:** `http_requests_total`, `http_request_duration_seconds` (labeled by route pattern, never the raw path), `incidents_total`, `investigations_total`, `investigation_duration_seconds`, `diagnostic_tool_executions_total` (by tool and observed health), `diagnostic_tool_failures_total`, `llm_requests_total`, `llm_request_duration_seconds` and `llm_failures_total` (by reason: `request` or `invalid_output`).
- **Dashboard:** [`deployments/grafana/`](deployments/grafana/) is provisioned automatically by the `monitoring` Compose profile.

![Grafana dashboard](docs/images/grafana-dashboard.png)

## Docker

- Multi-stage build: `node:22-alpine` builds the UI, `golang:1.27-alpine` builds a static binary, and `alpine:3.22` is the runtime with `iputils-ping` and CA certificates.
- About **35 MB**, runs as **UID 10001**, has a `HEALTHCHECK` on `/health`, and the binary is PID 1 and handles `SIGTERM` for graceful shutdown.
- In Compose, the app container is `read_only`, with `cap_drop: [ALL]` and `no-new-privileges`. ICMP works without root through unprivileged ping sockets.

| Profile | Services |
|---------|----------|
| default | `app`, `postgres` |
| `ollama` | `ollama` plus a one-shot `ollama-pull` job for the model |
| `monitoring` | `prometheus` (:9090), `grafana` (:3000) |

## Kubernetes

Manifests in [`deployments/kubernetes/`](deployments/kubernetes/) (kustomize): Namespace, ConfigMap, Deployment (2 replicas), Service and Ingress. PostgreSQL is expected to be provided externally.

```bash
kubectl create namespace incident-investigator
kubectl -n incident-investigator create secret generic incident-investigator \
  --from-literal=DATABASE_URL='postgres://user:pass@host:5432/investigator?sslmode=require' \
  --from-literal=OPENAI_API_KEY=
kubectl apply -k deployments/kubernetes
```

- Probes: readiness on `/ready`, liveness on `/health`. Resource requests and limits are set.
- `securityContext`: non-root, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, and no service account token.
- Unprivileged ICMP through the namespaced safe sysctl `net.ipv4.ping_group_range`.
- `secret.example.yaml` documents the secret shape and is **deliberately not** part of the kustomization.
- Ingress annotations (ingress-nginx) handle per-client rate limiting and timeouts sized for synchronous investigations.

These manifests were checked on a local minikube cluster (v1.34).

## Security

- **No arbitrary execution:** the LLM never selects tools or arguments. The tool allowlist is hard-coded (`dns`, `ping`, `tcp`).
- **Input validation at every boundary:** strict JSON (unknown fields rejected, 1 MiB limit), RFC 1123 hostname or IP validation applied by the API and again by every tool, UUID path IDs, and length limits.
- **No shell:** `ping` runs through `exec.CommandContext` with fixed argv and `--` before the host.
- **Output validation:** schema-constrained generation, strict decoding, domain validation and an evidence-source cross-check. Invalid output is never persisted.
- **Timeouts everywhere:** per tool, per LLM request, per investigation, database statement timeout, and HTTP read/write/idle timeouts.
- **Resource limits:** bounded concurrent investigations (429 with `Retry-After`) and pagination caps. Per-client rate limiting belongs at the ingress.
- **Secrets:** read only from the environment and redacted in logs. `.env` is git-ignored, and CI runs `govulncheck` and `npm audit`.
- **Browser:** strict CSP (`default-src 'self'`), `nosniff`, `no-referrer`. The UI renders all data as text, never as HTML.
- **Containers:** non-root, read-only filesystem, no capabilities.

**By design, the service probes the hosts users give it.** Deploy it where that is acceptable, or put it behind authentication (see the roadmap).

## Project Structure

```text
cmd/api/                 entrypoint: server, `migrate up|down`
internal/
  api/                   HTTP handlers, middleware, embedded UI (ui/dist)
  config/                environment configuration and validation
  domain/                entities, analysis validation, host validation
  incidents/             incident service
  investigation/         investigation engine and AI evaluation tests
  diagnostics/           ping, dns, tcp, simulation, toolbox
  llm/                   provider interface, OpenAI, Ollama, rules, prompt
  observability/         logging and Prometheus metrics
  storage/               PostgreSQL store and migrator
migrations/              embedded SQL migrations
web/                     React + TypeScript + Vite + Tailwind UI
deployments/
  kubernetes/            kustomize manifests
  prometheus/            scrape config
  grafana/               dashboard and provisioning
docs/                    sample incidents and screenshots
```

## Roadmap

- Traceroute and MTR diagnostics, and interface counters through device adapters (SNMP, gNMI)
- BGP session diagnostics and syslog correlation
- Alertmanager webhook intake, so alerts open incidents automatically
- Authentication and role-based access control
- Asynchronous investigations with progress streaming, and parallel tool execution
- Per-deployment target allowlists (CIDR or domain)
- Richer LLM evaluation: golden datasets, confidence calibration, per-model scoring
- Helm chart and ArgoCD application

## License

[MIT](LICENSE)
