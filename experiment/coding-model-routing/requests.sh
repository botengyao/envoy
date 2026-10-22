#!/usr/bin/env bash
# Sends OpenAI Chat Completions requests for coding_model. team-a's first request spends its Claude
# budget, so its second goes to Gemini; team-b still gets Claude. Then sends a request that is not
# LLM traffic, which passes through to the host it names.
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
echo "== not LLM traffic: a plain-text body to another service"
curl -sS "$gateway/echo" -H "host: us-east5-aiplatform.googleapis.com:8444" \
  -H "content-type: text/plain" -d 'not JSON, and not for the AI Protocol Manager'
echo
echo "== counters"
curl -sS "http://127.0.0.1:9981/stats?filter=ai_protocol_manager\.(request_parsed|transcoder\.(transcoded|failed|unresolved)|token_usage_found|usage_trailers)"
