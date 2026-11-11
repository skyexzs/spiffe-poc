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
                audience="https://auth-server.internal"
            )
            agent_spiffe_id = str(validated_svid.spiffe_id)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"SPIFFE verification failed: {e}")

    now = int(time.time())
    combo_claims = {
        "iss": "https://auth-server.internal",
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

