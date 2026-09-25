#!/usr/bin/env bash
# Stops what run.sh started.
HERE=$(cd "$(dirname "$0")" && pwd)
RUN_DIR=${RUN_DIR:-$HERE/run}
if [[ -f "$RUN_DIR/envoy.pid" ]]; then
  kill "$(cat "$RUN_DIR/envoy.pid")" 2>/dev/null || true
  rm -f "$RUN_DIR/envoy.pid"
fi
