#!/usr/bin/env bash
# Starts the OpenAI -> Vertex AI Gemini gateway on 127.0.0.1:10000.
#
#   GCP_PROJECT=my-project VERTEX_API_KEY_FILE=~/vertex.key ./run.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
RUN_DIR=${RUN_DIR:-$HERE/run}
ENVOY=${ENVOY:-$ROOT/bazel-bin/source/exe/envoy-static}
GCP_LOCATION=${GCP_LOCATION:-global}
: "${GCP_PROJECT:?set GCP_PROJECT}"
: "${VERTEX_API_KEY_FILE:?set VERTEX_API_KEY_FILE to a file holding the Vertex AI API key}"

"$HERE/stop.sh" >/dev/null 2>&1 || true
mkdir -p "$RUN_DIR/secrets"
chmod 700 "$RUN_DIR/secrets"
rm -f "$RUN_DIR"/*.log

# The key only lands in this SDS file, never in envoy.yaml or a log.
(umask 077 && python3 - "$VERTEX_API_KEY_FILE" "$RUN_DIR/secrets/vertex_api_key.json" <<'EOF'
import json, sys
key = open(sys.argv[1]).read().strip()
with open(sys.argv[2], "w") as f:
    json.dump({"resources": [{
        "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
        "name": "vertex_api_key", "generic_secret": {"secret": {"inline_string": key}}}]}, f)
EOF
)

sed -e "s|__GCP_PROJECT__|$GCP_PROJECT|g" -e "s|__GCP_LOCATION__|$GCP_LOCATION|g" \
  -e "s|__RUN_DIR__|$RUN_DIR|g" "$HERE/envoy.yaml.tmpl" >"$RUN_DIR/envoy.yaml"

"$ENVOY" -c "$RUN_DIR/envoy.yaml" --log-level info \
  --component-log-level ai_protocol_manager:debug \
  --file-flush-interval-msec 1000 --log-path "$RUN_DIR/envoy.log" \
  </dev/null >"$RUN_DIR/envoy.stdout.log" 2>&1 &
echo $! >"$RUN_DIR/envoy.pid"

for _ in $(seq 1 100); do
  if curl -fsS 127.0.0.1:9901/ready >/dev/null 2>&1; then
    echo "gateway ready on 127.0.0.1:10000 (Vertex AI project $GCP_PROJECT, $GCP_LOCATION)"
    exit 0
  fi
  sleep 0.2
done
echo "envoy did not become ready; see $RUN_DIR/envoy.log" >&2
exit 1
