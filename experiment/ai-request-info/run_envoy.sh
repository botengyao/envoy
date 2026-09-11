#!/usr/bin/env bash
# Runs Envoy in the foreground with the demo config. Ctrl-C to stop.
set -euo pipefail
cd "$(dirname "$0")"

ENVOY=${ENVOY:-bin/envoy}
mkdir -p logs

exec "$ENVOY" -c envoy.yaml \
  --concurrency 2 \
  --disable-hot-restart \
  --log-level info \
  --component-log-level ai_protocol_manager:trace,filter:debug \
  --log-path logs/envoy.log \
  --file-flush-interval-msec 1000
