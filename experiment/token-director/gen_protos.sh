#!/usr/bin/env bash
# Generate Python stubs for the ext_proc service and the AI metadata records,
# straight from this checkout's api/ tree, so the Token Director unpacks the
# exact protos this Envoy build publishes.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VENV="${VENV:-$HERE/.venv}"
OUT="$HERE/pb"

# Proto dependencies live in the bazel external tree; resolve it from the
# workspace's own output base rather than hardcoding a hash.
EXT="${EXT:-$(cd "$REPO" && bazel info output_base 2>/dev/null)/external}"
ROOTS="$REPO/api:$EXT/xds:$EXT/com_envoyproxy_protoc_gen_validate:$EXT/com_google_googleapis"

TARGETS=(
  envoy/service/ext_proc/v3/external_processor.proto
  envoy/data/ai/v3/token_usage.proto
  envoy/data/ai/v3/request_info.proto
)

rm -rf "$OUT" && mkdir -p "$OUT"
LIST=$("$VENV/bin/python" "$HERE/closure.py" "$ROOTS" "${TARGETS[@]}")

INCS=()
for r in ${ROOTS//:/ }; do INCS+=("-I$r"); done
# shellcheck disable=SC2086
"$VENV/bin/python" -m grpc_tools.protoc "${INCS[@]}" \
  --python_out="$OUT" --grpc_python_out="$OUT" $LIST

# Generated modules import each other by absolute package path; make the tree a
# package root on sys.path rather than rewriting imports.
find "$OUT" -type d -exec touch {}/__init__.py \;
echo "generated $(find "$OUT" -name '*_pb2.py' | wc -l | tr -d ' ') modules into $OUT"
