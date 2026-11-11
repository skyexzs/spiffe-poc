import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from spiffe import WorkloadApiClient

app = FastAPI()

OAUTH_SIGNING_SECRET = "local-lab-oauth-signing-secret-key-2026"
MCP_AUDIENCE = "https://mcp-billing.internal"

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

