#!/usr/bin/env bash
# Orchestrates the demo: Token Director + both Envoy hops, then the SDK client.
#
#   ./run.sh up          start the Director and both proxies
#   ./run.sh demo [args] run the client against the DFP hop (args go to client.py)
#   ./run.sh tunnel      run the client against the tunnel hop
#   ./run.sh ledger      show what the Director recorded
#   ./run.sh down        stop everything
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUN=/tmp/token-director
ENVOY_BIN="${ENVOY_BIN:-$REPO/bazel-bin/source/exe/envoy-static}"
VENV="${VENV:-$HERE/.venv}"
PY="$VENV/bin/python"

mkdir -p "$RUN"

need() { [ -x "$1" ] || { echo "missing: $1" >&2; exit 1; }; }

start_one() {
  local name=$1; shift
  if [ -f "$RUN/$name.pid" ] && kill -0 "$(cat "$RUN/$name.pid")" 2>/dev/null; then
    echo "$name already running (pid $(cat "$RUN/$name.pid"))"
    return
  fi
  "$@" >"$RUN/$name.log" 2>&1 &
  echo $! > "$RUN/$name.pid"
  echo "started $name (pid $!) -> $RUN/$name.log"
}

wait_for_port() {
  for _ in $(seq 1 50); do
    if nc -z 127.0.0.1 "$1" 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  echo "port $1 never came up" >&2
  return 1
}

case "${1:-up}" in
up)
  need "$ENVOY_BIN"; need "$PY"
  [ -d "$HERE/pb" ] || { echo "run gen_protos.sh first" >&2; exit 1; }
  : > "$RUN/ledger.jsonl"
  start_one director "$PY" "$HERE/token_director.py" --port 9000 \
    --budget "${BUDGET:-100000}" --ledger "$RUN/ledger.jsonl"
  wait_for_port 9000
  # Envoy logs to stderr, which start_one captures; passing --log-path too
  # would have both writers racing for the same file.
  start_one envoy-dfp "$ENVOY_BIN" -c "$HERE/envoy-dfp.yaml" \
    --log-level "${ENVOY_LOG_LEVEL:-info}"
  wait_for_port 10000
  start_one envoy-tunnel "$ENVOY_BIN" -c "$HERE/envoy-tunnel.yaml" \
    --log-level "${ENVOY_LOG_LEVEL:-info}"
  wait_for_port 10010
  echo "ready: dfp :10000  tunnel :10010  director :9000  admin :9901/:9902"
  ;;
demo)
  shift || true
  "$PY" "$HERE/client.py" --hop dfp "$@"
  ;;
tunnel)
  shift || true
  "$PY" "$HERE/client.py" --hop tunnel "$@"
  ;;
ledger)
  echo "--- director ---"; cat "$RUN/director.log" 2>/dev/null || true
  echo "--- ledger ---"
  "$PY" "$HERE/show_ledger.py" "$RUN/ledger.jsonl"
  ;;
down)
  for name in envoy-tunnel envoy-dfp director; do
    if [ -f "$RUN/$name.pid" ]; then
      kill "$(cat "$RUN/$name.pid")" 2>/dev/null && echo "stopped $name" || true
      rm -f "$RUN/$name.pid"
    fi
  done
  ;;
*)
  echo "usage: $0 {up|demo|tunnel|ledger|down}" >&2
  exit 2
  ;;
esac
