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
        auth_svid = spiffe_client.fetch_jwt_svid(audience={"https://auth-server.internal"})
        mcp_svid = spiffe_client.fetch_jwt_svid(audience={"https://mcp-billing.internal"})
        print(f"  [SPIFFE] Attested workload as: {auth_svid.spiffe_id}")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            AUTH_SERVER_URL,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": human_token,
                "actor_token": auth_svid.token,
                "resource": "https://mcp-billing.internal",
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

