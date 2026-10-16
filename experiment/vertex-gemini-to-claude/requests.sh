#!/usr/bin/env bash
# Sends a Gemini on Vertex AI request through the gateway, unary and then streamed, and prints the
# AI Protocol Manager's counters.
set -euo pipefail
gateway="${GATEWAY:-http://127.0.0.1:10080}"
model="/v1/projects/acme/locations/us-east5/publishers/google/models/gemini-2.5-flash"
body='{
  "systemInstruction": {"parts": [{"text": "You are an expert in Envoy and distributed systems."}]},
  "contents": [{"role": "user", "parts": [{"text": "Explain how Envoy routes an HTTP request."}]}],
  "generationConfig": {"maxOutputTokens": 1024}
}'

echo "== POST $model:generateContent"
curl -sS "$gateway$model:generateContent" -H "content-type: application/json" -d "$body"
echo
echo "== POST $model:streamGenerateContent?alt=sse"
curl -sSN "$gateway$model:streamGenerateContent?alt=sse" -H "content-type: application/json" \
  -d "$body"
echo "== counters"
curl -sS "http://127.0.0.1:9980/stats?filter=ai_protocol_manager\.(transcoder\.|route_binding)"
