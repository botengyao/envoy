#!/usr/bin/env bash
# Starts the mock backends, the routing PDP and Envoy, runs the e2e cases, and stops everything.
#   ./run.sh               prototype behavior
#   ./run.sh --no-restore  with request header restore turned off through runtime
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(git rev-parse --show-toplevel)"
ENVOY="${ENVOY:-$ROOT/bazel-bin/source/exe/envoy-static}"
RUN=run
mkdir -p "$RUN"
rm -f "$RUN"/*.log "$RUN"/*.jsonl

if [[ ! -f "$RUN/cert.pem" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$RUN/key.pem" -out "$RUN/cert.pem" \
    -days 30 -subj "/CN=mock-llm" \
    -addext "subjectAltName=DNS:generativelanguage.googleapis.com,DNS:us-central1-aiplatform.googleapis.com" \
    2>/dev/null
fi

RESTORE=true
if [[ "${1:-}" == "--no-restore" ]]; then
  RESTORE=false
fi

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

python3 mock_llm.py --name gemini --port 18443 --cert "$RUN/cert.pem" --key "$RUN/key.pem" \
  --log "$RUN/gemini.jsonl" > "$RUN/mock_gemini.log" 2>&1 & pids+=($!)
python3 mock_llm.py --name vertex --port 18444 --cert "$RUN/cert.pem" --key "$RUN/key.pem" \
  --log "$RUN/vertex.jsonl" > "$RUN/mock_vertex.log" 2>&1 & pids+=($!)
(cd pdp && go build -o "../$RUN/pdp" .)
"$RUN/pdp" -addr 127.0.0.1:18080 > "$RUN/pdp.log" 2>&1 & pids+=($!)

"$ENVOY" -c envoy.yaml --concurrency 1 --file-flush-interval-msec 100 \
  --component-log-level router:debug,ai_protocol_manager:debug,ext_proc:debug,filter:debug \
  --log-path "$RUN/envoy.log" & pids+=($!)

for _ in $(seq 1 100); do
  if curl -sf http://127.0.0.1:19901/ready > /dev/null 2>&1 && nc -z 127.0.0.1 18080 2>/dev/null; then
    break
  fi
  sleep 0.2
done

if [[ "$RESTORE" == false ]]; then
  curl -sf -X POST \
    "http://127.0.0.1:19901/runtime_modify?envoy.reloadable_features.restore_request_headers_on_cross_cluster_retry=false" \
    > /dev/null
fi

python3 e2e.py --restore "$RESTORE" | tee "$RUN/e2e.log"
curl -s "http://127.0.0.1:19901/stats?filter=(retry_body|retry_or_shadow_abandoned|upstream_rq_retry|ai_protocol_manager)" \
  > "$RUN/stats.log"
