# Antigravity IDE Execution Spec: SPIFFE + OAuth 2.0 (RFC 8693) + MCP Security Lab

## 1. Objective & Architectural Guardrails
Build and verify a local multi-container security sandbox demonstrating how an AI Agent authenticates and authorizes tool calls against an MCP Server on behalf of concurrent human users using **SPIFFE/SPIRE** and **OAuth 2.0 Token Exchange (RFC 8693)**.

### Strict Implementation Rules (Do Not Violate)
1. **Zero LLM Credential Access:** The simulated LLM function must NEVER accept `user_id`, `subject_token`, or SPIFFE credentials as parameters. User session tokens must be isolated per coroutine using Python's `contextvars.ContextVar`.
2. **Environment-Driven SPIFFE Socket:** Always configure `SPIFFE_ENDPOINT_SOCKET=unix:///spire-socket/api.sock` via container environment variables and instantiate `WorkloadApiClient()` without hardcoded path overrides.
3. **Host PID & UID Attestation:** Use Linux UID selectors (`unix:uid:1001`, `unix:uid:1002`, `unix:uid:1003`) with `pid: "host"` on `spire-agent` so workload attestation succeeds across Linux, macOS Docker Desktop, and WSL2.
4. **Double-Lock Verification at MCP Server:** The MCP Server must verify:
   - The caller's live `X-SPIFFE-SVID` JWT-SVID against the SPIRE Workload API.
   - The `Authorization: Bearer <OBO_JWT>` signature and audience (`https://mcp-billing.internal`).
   - That the live SPIFFE ID matches the `act.sub` claim inside the OBO JWT.
   - Intersection authorization: Both the bot (`act.sub`) AND the human role (`user_role`) must be permitted to invoke the requested tool.

---

## 2. Target Workspace File Tree
Create the following exact directory structure:

```text
.
├── docker-compose.yml
├── bootstrap.sh
├── spire/
│   ├── server/
│   │   └── server.conf
│   └── agent/
│       └── agent.conf
└── app/
    ├── Dockerfile
    ├── requirements.txt
    ├── auth_server.py
    ├── mcp_server.py
    ├── agent.py
    └── attack_test.py
```

---

## 3. File Specifications

### 3.1 `spire/server/server.conf`
```hcl
server {
    bind_address = "0.0.0.0"
    bind_port = "8081"
    trust_domain = "example.org"
    data_dir = "/opt/spire/data/server"
    log_level = "INFO"
    default_x509_svid_ttl = "1h"
    default_jwt_svid_ttl = "5m"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/opt/spire/data/server/datastore.sqlite3"
        }
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
    KeyManager "memory" {
        plugin_data {}
    }
}
```

### 3.2 `spire/agent/agent.conf`
```hcl
agent {
    data_dir = "/opt/spire/data/agent"
    log_level = "INFO"
    server_address = "spire-server"
    server_port = "8081"
    socket_path = "/spire-socket/api.sock"
    trust_domain = "example.org"
    insecure_bootstrap = true
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }
    KeyManager "memory" {
        plugin_data {}
    }
    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
```

### 3.3 `app/requirements.txt`
```text
fastapi==0.115.0
uvicorn==0.30.6
httpx==0.27.2
PyJWT==2.9.0
spiffe==0.2.3
python-multipart==0.0.9
```

### 3.4 `app/Dockerfile`
```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Dedicated Linux UIDs for SPIRE unix workload attestation
RUN useradd -u 1001 -m authuser && \
    useradd -u 1002 -m mcpuser && \
    useradd -u 1003 -m agentuser && \
    useradd -u 1004 -m rogueuser

COPY . /app
```

### 3.5 `app/auth_server.py`
```python
import time
import jwt
from fastapi import FastAPI, Form, HTTPException
from spiffe import WorkloadApiClient

app = FastAPI()

OAUTH_SIGNING_SECRET = "local-lab-oauth-signing-secret-key-2026"

USER_TOKENS = {
    "token-alice-123": {"sub": "alice@example.org", "role": "finops_admin"},
    "token-bob-456":   {"sub": "bob@example.org",   "role": "engineering_intern"},
}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/oauth/token")
def token_exchange(
    grant_type: str = Form(...),
    subject_token: str = Form(...),
    actor_token: str = Form(...),
    resource: str = Form(...),
    scope: str = Form(...),
):
    if grant_type != "urn:ietf:params:oauth:grant-type:token-exchange":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

    user_info = USER_TOKENS.get(subject_token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid human subject_token")

    try:
        with WorkloadApiClient() as spiffe_client:
            validated_svid = spiffe_client.validate_jwt_svid(
                token=actor_token,
                audience="[https://auth-server.internal](https://auth-server.internal)"
            )
            agent_spiffe_id = str(validated_svid.spiffe_id)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"SPIFFE verification failed: {e}")

    now = int(time.time())
    combo_claims = {
        "iss": "[https://auth-server.internal](https://auth-server.internal)",
        "sub": user_info["sub"],
        "user_role": user_info["role"],
        "aud": resource,
        "scope": scope,
        "iat": now,
        "exp": now + 300,
        "act": {
            "sub": agent_spiffe_id
        }
    }

    obo_jwt = jwt.encode(combo_claims, OAUTH_SIGNING_SECRET, algorithm="HS256")
    return {"access_token": obo_jwt, "token_type": "Bearer", "expires_in": 300}
```

### 3.6 `app/mcp_server.py`
```python
import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from spiffe import WorkloadApiClient

app = FastAPI()

OAUTH_SIGNING_SECRET = "local-lab-oauth-signing-secret-key-2026"
MCP_AUDIENCE = "[https://mcp-billing.internal](https://mcp-billing.internal)"

BOT_PERMISSIONS = {
    "spiffe://example.org/ns/ai/finops-bot": ["get_q3_invoices"],
}

HUMAN_PERMISSIONS = {
    "finops_admin": ["get_q3_invoices"],
    "engineering_intern": [],
}

INVOICE_DB = {
    "alice@example.org": ["Invoice #901: $4,200 (AWS)", "Invoice #902: $1,150 (GCP)"],
    "bob@example.org": ["Invoice #903: $50 (Sandbox)"],
}

class MCPToolRequest(BaseModel):
    method: str
    tool_name: str

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/mcp/tools/call")
def call_tool(
    req: MCPToolRequest,
    authorization: str = Header(...),
    x_spiffe_svid: str = Header(...),
):
    # 1. Verify caller's live SPIFFE JWT-SVID
    try:
        with WorkloadApiClient() as spiffe_client:
            caller_svid = spiffe_client.validate_jwt_svid(
                token=x_spiffe_svid,
                audience=MCP_AUDIENCE
            )
            live_caller_spiffe_id = str(caller_svid.spiffe_id)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Caller SPIFFE badge invalid: {e}")

    # 2. Verify OAuth Combo Pass (OBO JWT)
    try:
        token_str = authorization.replace("Bearer ", "")
        claims = jwt.decode(
            token_str,
            OAUTH_SIGNING_SECRET,
            algorithms=["HS256"],
            audience=MCP_AUDIENCE,
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid OBO Combo Pass: {e}")

    # 3. Double-Lock Check: Live SPIFFE caller must match token's 'act.sub'
    token_actor_id = claims.get("act", {}).get("sub")
    if live_caller_spiffe_id != token_actor_id:
        raise HTTPException(
            status_code=403,
            detail=f"Actor mismatch! Live caller is '{live_caller_spiffe_id}', but token is bound to '{token_actor_id}'"
        )

    # 4. Intersection Authorization (Bot + Human)
    if req.tool_name not in BOT_PERMISSIONS.get(live_caller_spiffe_id, []):
        raise HTTPException(
            status_code=403,
            detail=f"Bot '{live_caller_spiffe_id}' is not permitted to invoke '{req.tool_name}'"
        )

    user_sub = claims["sub"]
    user_role = claims["user_role"]
    if req.tool_name not in HUMAN_PERMISSIONS.get(user_role, []):
        raise HTTPException(
            status_code=403,
            detail=f"Human user '{user_sub}' (role: {user_role}) is not authorized for '{req.tool_name}'"
        )

    return {
        "status": "success",
        "executed_by_bot": live_caller_spiffe_id,
        "on_behalf_of_user": user_sub,
        "data": INVOICE_DB.get(user_sub, []),
    }
```

### 3.7 `app/agent.py`
```python
import asyncio
import contextvars
import sys
import httpx
from spiffe import WorkloadApiClient

AUTH_SERVER_URL = "http://auth-server:8001/oauth/token"
MCP_SERVER_URL = "http://mcp-server:8002/mcp/tools/call"

# Strict per-request context isolation so the LLM never touches user tokens
current_user_token: contextvars.ContextVar[str] = contextvars.ContextVar("current_user_token")

async def call_mcp_tool_harness(tool_name: str) -> dict:
    human_token = current_user_token.get()

    with WorkloadApiClient() as spiffe_client:
        auth_svid = spiffe_client.fetch_jwt_svid(audience={"[https://auth-server.internal](https://auth-server.internal)"})
        mcp_svid = spiffe_client.fetch_jwt_svid(audience={"[https://mcp-billing.internal](https://mcp-billing.internal)"})
        print(f"  [SPIFFE] Attested workload as: {auth_svid.spiffe_id}")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            AUTH_SERVER_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": human_token,
                "actor_token": auth_svid.token,
                "resource": "[https://mcp-billing.internal](https://mcp-billing.internal)",
                "scope": "read_billing",
            },
        )
        token_resp.raise_for_status()
        combo_pass_jwt = token_resp.json()["access_token"]

        mcp_resp = await client.post(
            MCP_SERVER_URL,
            json={"method": "tools/call", "tool_name": tool_name},
            headers={
                "Authorization": f"Bearer {combo_pass_jwt}",
                "X-SPIFFE-SVID": mcp_svid.token,
            },
        )
        return {
            "http_status": mcp_resp.status_code,
            "body": mcp_resp.json(),
            "combo_pass_jwt": combo_pass_jwt,
        }

async def simulate_user_request(label: str, login_token: str) -> dict:
    token_ref = current_user_token.set(login_token)
    try:
        print(f"\n--- Session: {label} ---")
        res = await call_mcp_tool_harness(tool_name="get_q3_invoices")
        print(f"  [Response] HTTP {res['http_status']}: {res['body']}")
        return res
    finally:
        current_user_token.reset(token_ref)

async def main():
    alice_res, bob_res = await asyncio.gather(
        simulate_user_request("Alice (finops_admin)", "token-alice-123"),
        simulate_user_request("Bob (engineering_intern)", "token-bob-456"),
    )

    assert alice_res["http_status"] == 200, f"Expected 200 for Alice, got {alice_res['http_status']}"
    assert bob_res["http_status"] == 403, f"Expected 403 for Bob, got {bob_res['http_status']}"
    print("\n[PASS] Concurrent session isolation and intersection AuthZ verified.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except AssertionError as err:
        print(f"\n[FAIL] {err}")
        sys.exit(1)
```

### 3.8 `app/attack_test.py` (Stolen Combo Pass Replay Simulation)
```python
import asyncio
import sys
import httpx
from spiffe import WorkloadApiClient

AUTH_SERVER_URL = "http://auth-server:8001/oauth/token"
MCP_SERVER_URL = "http://mcp-server:8002/mcp/tools/call"

async def main():
    print("\n--- Security Test: Stolen OBO Token Replay from Rogue Workload ---")
    # Simulate a rogue container (UID 1004 -> spiffe://example.org/ns/ai/rogue-bot)
    # trying to use a valid Combo Pass minted for finops-bot
    with WorkloadApiClient() as spiffe_client:
        rogue_mcp_svid = spiffe_client.fetch_jwt_svid(audience={"[https://mcp-billing.internal](https://mcp-billing.internal)"})
        print(f"  [Attacker Workload] Attested as: {rogue_mcp_svid.spiffe_id}")

    stolen_combo_pass = sys.argv[1]

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            MCP_SERVER_URL,
            json={"method": "tools/call", "tool_name": "get_q3_invoices"},
            headers={
                "Authorization": f"Bearer {stolen_combo_pass}",
                "X-SPIFFE-SVID": rogue_mcp_svid.token,
            },
        )
        print(f"  [MCP Server Response] HTTP {resp.status_code}: {resp.json()}")
        assert resp.status_code == 403, "Expected 403 Actor Mismatch!"
        assert "Actor mismatch" in resp.json().get("detail", ""), "Expected Actor mismatch error detail!"
        print("[PASS] Stolen Combo Pass replay blocked by SPIFFE Double-Lock check.")

if __name__ == "__main__":
    asyncio.run(main())
```

### 3.9 `docker-compose.yml`
```yaml
services:
  spire-server:
    image: ghcr.io/spiffe/spire-server:1.10.3
    hostname: spire-server
    command: ["-config", "/opt/spire/conf/server/server.conf"]
    volumes:
      - ./spire/server:/opt/spire/conf/server

  spire-agent:
    image: ghcr.io/spiffe/spire-agent:1.10.3
    hostname: spire-agent
    pid: "host"
    depends_on:
      - spire-server
    command: ["-config", "/opt/spire/conf/agent/agent.conf", "-joinToken", "${SPIRE_JOIN_TOKEN}"]
    volumes:
      - ./spire/agent:/opt/spire/conf/agent
      - spire-socket:/spire-socket

  auth-server:
    build: ./app
    user: "1001"
    environment:
      - SPIFFE_ENDPOINT_SOCKET=unix:///spire-socket/api.sock
    command: ["uvicorn", "auth_server:app", "--host", "0.0.0.0", "--port", "8001"]
    volumes:
      - spire-socket:/spire-socket

  mcp-server:
    build: ./app
    user: "1002"
    environment:
      - SPIFFE_ENDPOINT_SOCKET=unix:///spire-socket/api.sock
    command: ["uvicorn", "mcp_server:app", "--host", "0.0.0.0", "--port", "8002"]
    volumes:
      - spire-socket:/spire-socket

  ai-agent:
    build: ./app
    user: "1003"
    environment:
      - SPIFFE_ENDPOINT_SOCKET=unix:///spire-socket/api.sock
    command: ["sleep", "infinity"]
    volumes:
      - spire-socket:/spire-socket

  rogue-agent:
    build: ./app
    user: "1004"
    environment:
      - SPIFFE_ENDPOINT_SOCKET=unix:///spire-socket/api.sock
    command: ["sleep", "infinity"]
    volumes:
      - spire-socket:/spire-socket

volumes:
  spire-socket:
```

### 3.10 `bootstrap.sh`
```bash
#!/usr/bin/env bash
set -euo pipefail

echo "==> [1/6] Cleaning previous containers and volumes..."
SPIRE_JOIN_TOKEN="dummy" docker compose down -v --remove-orphans

echo "==> [2/6] Building application images and starting spire-server..."
SPIRE_JOIN_TOKEN="dummy" docker compose up -d --build spire-server
sleep 3

echo "==> [3/6] Generating SPIRE Node Join Token..."
JOIN_TOKEN=$(SPIRE_JOIN_TOKEN="dummy" docker compose exec -T spire-server \
  /opt/spire/bin/spire-server token generate -spiffeID spiffe://example.org/host | awk '{print $2}' | tr -d '\r')
echo "Join Token: $JOIN_TOKEN"

echo "==> [4/6] Starting spire-agent and workload containers..."
export SPIRE_JOIN_TOKEN="$JOIN_TOKEN"
docker compose up -d spire-agent auth-server mcp-server ai-agent rogue-agent
sleep 4

# Ensure non-root UIDs (1001-1004) have read/write access to the SPIRE socket directory
docker compose exec -T spire-agent chmod -R 777 /spire-socket

echo "==> [5/6] Registering SPIFFE Workload Entries..."
docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \
  -parentID spiffe://example.org/host \
  -spiffeID spiffe://example.org/ns/security/auth-server \
  -selector unix:uid:1001

docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \
  -parentID spiffe://example.org/host \
  -spiffeID spiffe://example.org/ns/mcp/billing-server \
  -selector unix:uid:1002

docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \
  -parentID spiffe://example.org/host \
  -spiffeID spiffe://example.org/ns/ai/finops-bot \
  -selector unix:uid:1003

docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \
  -parentID spiffe://example.org/host \
  -spiffeID spiffe://example.org/ns/ai/rogue-bot \
  -selector unix:uid:1004

echo "Waiting 6 seconds for SPIRE Agent workload sync..."
sleep 6

echo "==> [6/6] Running Verification Suite..."
docker compose exec -T ai-agent python agent.py

echo "==> Running Stolen Token Replay Test..."
ALICE_COMBO_TOKEN=$(docker compose exec -T ai-agent python -c '
import asyncio
from agent import simulate_user_request
res = asyncio.run(simulate_user_request("Minting Alice Token", "token-alice-123"))
print("TOKEN_OUT:" + res["combo_pass_jwt"])
' | grep "TOKEN_OUT:" | cut -d':' -f2 | tr -d '\r')

docker compose exec -T rogue-agent python attack_test.py "$ALICE_COMBO_TOKEN"
```

---

## 4. Antigravity Agent Execution Checklist
Execute these terminal actions sequentially and verify the outputs:
1. Create all files in Section 3 and run `chmod +x bootstrap.sh`.
2. Execute `./bootstrap.sh` in the integrated terminal.
3. Verify the terminal prints both:
   - `[PASS] Concurrent session isolation and intersection AuthZ verified.`
   - `[PASS] Stolen Combo Pass replay blocked by SPIFFE Double-Lock check.`
4. If any container fails to reach `/spire-socket/api.sock`, inspect `docker compose logs spire-agent` and ensure `chmod -R 777 /spire-socket` succeeded after the socket file was created.