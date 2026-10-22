#!/usr/bin/env bash
# Sends OpenAI Chat Completions requests for coding_model. team-a's first request spends its Claude
# budget, so its second goes to Gemini; team-b still gets Claude.
set -euo pipefail
gateway="${GATEWAY:-http://127.0.0.1:10081}"

ask() {
  local tenant=$1 stream=$2
  echo "== $tenant, stream=$stream"
  curl -sSN "$gateway/v1/chat/completions" -H "content-type: application/json" \
    -H "x-tenant: $tenant" -d '{
    "model": "coding_model",
    "stream": '"$stream"',
    "stream_options": {"include_usage": true},
    "max_tokens": 1024,
    "messages": [
      {"role": "system", "content": "You are an expert in Envoy and distributed systems."},
      {"role": "user", "content": "Explain how Envoy routes an HTTP request."}
    ]
  }'
  echo
}

ask team-a false
ask team-a true
ask team-b true
echo "== counters"
curl -sS "http://127.0.0.1:9981/stats?filter=ai_protocol_manager\.(transcoder\.|token_usage_|usage_trailers)"
