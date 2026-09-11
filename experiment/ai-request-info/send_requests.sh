#!/usr/bin/env bash
# Sends one request per scenario through the gateway, then prints the filter's counters.
set -euo pipefail

GATEWAY=${GATEWAY:-http://127.0.0.1:10000}
ADMIN=${ADMIN:-http://127.0.0.1:9901}

send() {
  local label=$1 path=$2 body=$3
  shift 3
  printf '%-34s POST %-58s -> ' "$label" "$path"
  curl -sS -o /dev/null -w '%{http_code}\n' \
    -H 'content-type: application/json' "$@" --data-binary "$body" "${GATEWAY}${path}"
}

send "1 openai chat completions" /v1/chat/completions \
  '{"model":"gpt-4o-mini","max_completion_tokens":256,"messages":[{"role":"system","content":"You are terse."},{"role":"user","content":"What is Envoy?"}],"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}]}'

send "2 openai chat completions (sse)" /v1/chat/completions \
  '{"model":"gpt-4o-mini","stream":true,"stream_options":{"include_usage":true},"max_tokens":64,"messages":[{"role":"user","content":"Say hi"}]}' \
  -H 'x-mock-stream: true'

send "3 openai responses" /v1/responses \
  '{"model":"gpt-4.1","input":"What is the capital of France?","max_output_tokens":512,"tools":[{"type":"web_search"},{"type":"function","name":"lookup","parameters":{}}]}'

send "4 anthropic messages" /v1/messages \
  '{"model":"claude-sonnet-5","max_tokens":1024,"messages":[{"role":"user","content":"Hello"},{"role":"assistant","content":"Hi! How can I help?"},{"role":"user","content":"Tell me a joke"}],"tools":[{"name":"get_time","description":"Current time","input_schema":{"type":"object"}}]}'

send "5 gemini generateContent" /v1beta/models/gemini-2.5-flash:generateContent \
  '{"contents":[{"role":"user","parts":[{"text":"Write a haiku about proxies"}]}],"generationConfig":{"maxOutputTokens":200}}'

send "6 gemini streamGenerateContent" '/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse' \
  '{"contents":[{"role":"user","parts":[{"text":"Hello"}]}],"generation_config":{"max_output_tokens":32}}'

send "7 anthropic, unusable values" /v1/messages \
  '{"model":"claude-sonnet-5","max_tokens":"lots","messages":[{"role":"user","content":"hi"}],"tools":{"name":"not-an-array"}}'

send "8 undeclared route" /v1/embeddings \
  '{"model":"text-embedding-3-small","input":"hello"}'

send "9 malformed json" /v1/chat/completions \
  '{"model":"gpt-4o-mini","messages":['

printf '\n# counters\n'
curl -sS "${ADMIN}/stats?filter=ai_protocol_manager" | grep -v ': 0$' || true
