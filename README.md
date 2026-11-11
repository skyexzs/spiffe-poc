# SPIFFE + OAuth 2.0 (RFC 8693) + MCP Security Sandbox

A local multi-container security sandbox demonstrating how an AI Agent authenticates and authorizes tool calls against an **MCP Server** on behalf of concurrent human users using **SPIFFE/SPIRE** workload identity and **OAuth 2.0 Token Exchange (RFC 8693)**.

For a full component specification and vector workflow diagrams, see [docs/SPIFFE_OAUTH_MCP_Architecture.pdf](docs/SPIFFE_OAUTH_MCP_Architecture.pdf) and [ANTIGRAVITY_SPEC.md](ANTIGRAVITY_SPEC.md).

---

## Architecture Overview

| Service | Container User (UID) | SPIFFE ID (`example.org`) | Port / Socket | Role |
| :--- | :--- | :--- | :--- | :--- |
| `spire-server` | `root` | Control Plane Root CA | TCP `:8081` | Trust domain root CA, SQLite entry store, node join-token & SVID issuer |
| `spire-agent` | `root` (`pid: "host"`) | `spiffe://example.org/host` | `/spire-socket/api.sock` | Node attestation, Unix UID workload attestation, local SPIFFE Workload API |
| `auth-server` | `authuser` (`1001`) | `spiffe://example.org/ns/security/auth-server` | HTTP `:8001` | RFC 8693 STS exchanging human tokens + agent JWT-SVIDs into OBO Combo Pass JWTs |
| `mcp-server` | `mcpuser` (`1002`) | `spiffe://example.org/ns/mcp/billing-server` | HTTP `:8002` | Resource server enforcing 4-gate Double-Lock & intersection authorization |
| `ai-agent` | `agentuser` (`1003`) | `spiffe://example.org/ns/ai/finops-bot` | Client | Runs coroutine-isolated user sessions (`ContextVar`) and the tool-call harness |
| `rogue-agent` | `rogueuser` (`1004`) | `spiffe://example.org/ns/ai/rogue-bot` | Client | Simulates a rogue container replaying a stolen OBO JWT against `mcp-server` |

### Key Security Properties Demonstrated
- **Zero LLM Credential Access:** Human login tokens are isolated per `asyncio` task using `contextvars.ContextVar` (`current_user_token`) inside `app/agent.py`, never passed to the LLM tool-selection layer.
- **Kernel UID Attestation:** `spire-agent` runs with `pid: "host"` and the `unix` WorkloadAttestor, mapping Linux UIDs (`1001`–`1004`) to SPIFFE IDs without static workload secrets.
- **Double-Lock Verification:** `app/mcp_server.py` checks that the caller's live `X-SPIFFE-SVID` JWT-SVID matches the `act.sub` claim inside the `Authorization: Bearer <OBO_JWT>` token.
- **Intersection Authorization:** Both the bot identity (`BOT_PERMISSIONS`) and the human user's role (`HUMAN_PERMISSIONS`) must permit `get_q3_invoices`.

---

## Prerequisites

- **Docker Engine & Docker Compose v2** (`docker compose`)
  - On **macOS / Windows**, ensure **Docker Desktop** is started and running before executing the bootstrap script.
  - On **Linux**, ensure the Docker daemon is active and your user can run `docker` commands.
- **Network access** on first run to pull:
  - `ghcr.io/spiffe/spire-server:1.10.3`
  - `ghcr.io/spiffe/spire-agent:1.10.3`
  - `python:3.12-slim`

---

## Quick Start: Deploy & Run the Simulation

Make `bootstrap.sh` executable (if needed) and run it from the repository root:

```bash
chmod +x bootstrap.sh
./bootstrap.sh
```

### What `bootstrap.sh` Does
1. **Clean State (`[1/6]`):** Tears down any leftover containers, networks, and the `spire-socket` volume (`docker compose down -v --remove-orphans`).
2. **Build & Boot SPIRE Server (`[2/6]`):** Starts `spire-server` (`spire/server/server.conf`).
3. **Mint Node Join Token (`[3/6]`):** Generates an ephemeral join token for `spiffe://example.org/host` via `spire-server token generate`.
4. **Launch SPIRE Agent & Workloads (`[4/6]`):** Starts `spire-agent`, `auth-server`, `mcp-server`, `ai-agent`, and `rogue-agent`, then runs `docker compose exec -T -u 0 ai-agent chmod -R 777 /spire-socket` so non-root UIDs `1001`–`1004` can access the socket (the upstream `spire-agent` image is distroless and does not include `chmod`).
5. **Register SPIFFE Workload Entries (`[5/6]`):** Maps `unix:uid:1001` through `unix:uid:1004` to their respective SPIFFE IDs under `spiffe://example.org/host`, then waits 6 seconds for `spire-agent` workload synchronization.
6. **Run Both Verification Suites (`[6/6]`):**
   - Executes `agent.py` inside `ai-agent` (concurrent Alice + Bob sessions).
   - Mints an Alice OBO Combo Pass JWT and passes it to `attack_test.py` inside `rogue-agent`.

### Expected Output

```text
==> [6/6] Running Verification Suite...

--- Session: Alice (finops_admin) ---
  [SPIFFE] Attested workload as: spiffe://example.org/ns/ai/finops-bot

--- Session: Bob (engineering_intern) ---
  [SPIFFE] Attested workload as: spiffe://example.org/ns/ai/finops-bot
  [Response] HTTP 403: {'detail': "Human user 'bob@example.org' (role: engineering_intern) is not authorized for 'get_q3_invoices'"}
  [Response] HTTP 200: {'status': 'success', 'executed_by_bot': 'spiffe://example.org/ns/ai/finops-bot', 'on_behalf_of_user': 'alice@example.org', 'data': ['Invoice #901: $4,200 (AWS)', 'Invoice #902: $1,150 (GCP)']}

[PASS] Concurrent session isolation and intersection AuthZ verified.
==> Running Stolen Token Replay Test...

--- Security Test: Stolen OBO Token Replay from Rogue Workload ---
  [Attacker Workload] Attested as: spiffe://example.org/ns/ai/rogue-bot
  [MCP Server Response] HTTP 403: {'detail': "Actor mismatch! Live caller is 'spiffe://example.org/ns/ai/rogue-bot', but token is bound to 'spiffe://example.org/ns/ai/finops-bot'"}
[PASS] Stolen Combo Pass replay blocked by SPIFFE Double-Lock check.
```

---

## Re-Running Tests & Inspecting the Running Stack

After `./bootstrap.sh` finishes, the six containers remain running so you can re-run tests or inspect SPIRE state:

> **Note:** Prefix `docker compose` commands with `SPIRE_JOIN_TOKEN="dummy"` when running outside `bootstrap.sh` to avoid Compose warnings about `${SPIRE_JOIN_TOKEN}` in `docker-compose.yml`.

```bash
# Check container status
SPIRE_JOIN_TOKEN="dummy" docker compose ps

# Re-run the concurrent Alice/Bob session test
SPIRE_JOIN_TOKEN="dummy" docker compose exec -T ai-agent python agent.py

# Re-run the stolen-token replay attack test
ALICE_COMBO_TOKEN=$(SPIRE_JOIN_TOKEN="dummy" docker compose exec -T ai-agent python -c '
import asyncio
from agent import simulate_user_request
res = asyncio.run(simulate_user_request("Minting Alice Token", "token-alice-123"))
print("TOKEN_OUT:" + res["combo_pass_jwt"])
' | grep "TOKEN_OUT:" | cut -d':' -f2 | tr -d '\r')
SPIRE_JOIN_TOKEN="dummy" docker compose exec -T rogue-agent python attack_test.py "$ALICE_COMBO_TOKEN"

# Inspect registered SPIFFE entries
SPIRE_JOIN_TOKEN="dummy" docker compose exec -T spire-server /opt/spire/bin/spire-server entry show
```

---

## Stopping & Cleaning Up

To stop all containers and remove the `spire-socket` volume and Compose network:

```bash
SPIRE_JOIN_TOKEN="dummy" docker compose down -v --remove-orphans
```

---

## Troubleshooting

- **Docker daemon connection error (macOS):**
  If `docker compose` fails with `failed to connect to the docker API at unix:///...docker.sock`, start Docker Desktop (`open -a Docker`), wait for it to finish booting, and re-run `./bootstrap.sh`.
- **Workloads cannot access `/spire-socket/api.sock`:**
  Inspect `spire-agent` logs and confirm the socket exists and has permissions applied:
  ```bash
  SPIRE_JOIN_TOKEN="dummy" docker compose logs spire-agent
  SPIRE_JOIN_TOKEN="dummy" docker compose exec -T -u 0 ai-agent ls -la /spire-socket
  ```
- **SVID fetch fails immediately after startup:**
  `spire-agent` polls `spire-server` periodically for updated workload entries. Wait a few seconds after entry registration or re-run `docker compose exec -T ai-agent python agent.py`.

---

## Repository Structure

```text
.
├── ANTIGRAVITY_SPEC.md                     # Architecture & sandbox execution specification
├── README.md                               # Deployment and simulation runbook
├── bootstrap.sh                            # End-to-end deploy, SPIRE registration, and test script
├── docker-compose.yml                      # 6-service multi-container topology & spire-socket volume
├── docs/
│   └── SPIFFE_OAUTH_MCP_Architecture.pdf   # Component documentation & workflow diagrams
├── spire/
│   ├── server/server.conf                  # SPIRE Server config (example.org, SQLite, join_token)
│   └── agent/agent.conf                    # SPIRE Agent config (unix WorkloadAttestor)
└── app/
    ├── Dockerfile                          # python:3.12-slim image creating UIDs 1001-1004
    ├── requirements.txt                    # Pinned FastAPI, Uvicorn, HTTPX, PyJWT, spiffe deps
    ├── auth_server.py                      # RFC 8693 Token Exchange STS (:8001)
    ├── mcp_server.py                       # MCP Billing Server enforcing 4-gate Double-Lock (:8002)
    ├── agent.py                            # Coroutine-isolated AI Agent + Tool-Call Harness
    └── attack_test.py                      # Rogue workload stolen-token replay test
```

> **Lab Disclaimer:** This repository is a local educational sandbox. It intentionally uses `insecure_bootstrap = true` on `spire-agent`, in-memory SPIRE keys (`KeyManager "memory"`), symmetric `HS256` with a hardcoded lab secret (`OAUTH_SIGNING_SECRET`), and mock `USER_TOKENS` for self-contained execution. Production deployments should use attested node bootstrapping, asymmetric RS256/ES256 JWKS verification, an external IdP, and X.509-SVID mTLS.

