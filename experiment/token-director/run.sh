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
  # Truncate every per-run artifact, so a report reflects this run rather than
  # everything the directory has ever accumulated.
  : > "$RUN/ledger.jsonl"
  : > "$RUN/dfp-access.log"
  : > "$RUN/tunnel-access.log"
  start_one director "$PY" "$HERE/token_director.py" --port 9000 \
    --budget "${BUDGET:-100000}" --ledger "$RUN/ledger.jsonl"
  wait_for_port 9000
  # Envoy logs to stderr, which start_one captures; passing --log-path too
  # would have both writers racing for the same file.
  # Envoy buffers file access logs for 10s by default, which makes a short
  # demo look like it logged nothing. Flush promptly instead.
  start_one envoy-dfp "$ENVOY_BIN" -c "$HERE/envoy-dfp.yaml" \
    --file-flush-interval-msec 250 \
    --log-level "${ENVOY_LOG_LEVEL:-info}"
  wait_for_port 10000
  start_one envoy-tunnel "$ENVOY_BIN" -c "$HERE/envoy-tunnel.yaml" \
    --file-flush-interval-msec 250 \
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
  "$PY" "$HERE/report.py" --ledger
  ;;
access)
  shift || true
  "$PY" "$HERE/report.py" --access "$@"
  ;;
stats)
  "$PY" "$HERE/report.py" --stats
  ;;
report)
  "$PY" "$HERE/report.py"
  ;;
director)
  tail -n "${2:-40}" "$RUN/director.log" 2>/dev/null || echo "(no director log)"
  ;;
logs)
  for name in director envoy-dfp envoy-tunnel; do
    echo "--- $name ---"
    tail -n "${2:-20}" "$RUN/$name.log" 2>/dev/null || true
  done
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
  cat >&2 <<'USAGE'
usage: run.sh <command>

  up                 start the Director and both proxies
  demo [args...]     drive the SDK client through the DFP hop
  tunnel [args...]   drive the SDK client through the tunnel hop
  report             everything below, in one pass
  ledger             per-request token accounting, per-model totals, estimate accuracy
  access [--tail N]  Envoy access logs, and what they structurally cannot show
  stats              filter and ext_proc counters from both admin endpoints
  director [n]       tail the Director's admit/settle log
  logs [n]           tail every process log
  down               stop everything
USAGE
  exit 2
  ;;
esac
