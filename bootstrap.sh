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
# (spire-agent image is distroless without chmod, so apply permissions via a workload container sharing the volume)
docker compose exec -T -u 0 ai-agent chmod -R 777 /spire-socket

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

