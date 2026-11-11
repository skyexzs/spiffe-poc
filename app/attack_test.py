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
        rogue_mcp_svid = spiffe_client.fetch_jwt_svid(audience={"https://mcp-billing.internal"})
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

