#!/usr/bin/env bash
# Runs envoy.yaml on envoy-static against mock_vertex.py and sends requests.sh through it. What each
# side saw lands in captured/.
set -euo pipefail
cd "$(dirname "$0")"
envoy="${ENVOY:-../../bazel-bin/source/exe/envoy-static}"
[[ -f certs/ca.pem ]] || ./gen_certs.sh
mkdir -p captured

python3 mock_vertex.py > captured/mock.log 2>&1 &
mock=$!
"$envoy" -c envoy.yaml --log-level warn --component-log-level ai_protocol_manager:debug \
  > captured/access.log 2> captured/envoy.log &
gateway=$!
trap 'kill "$gateway" "$mock" 2> /dev/null || true' EXIT

until curl -sf http://127.0.0.1:9980/ready > /dev/null; do
  for pid in "$gateway" "$mock"; do
    kill -0 "$pid" 2> /dev/null || { tail -5 captured/envoy.log captured/mock.log; exit 1; }
  done
  sleep 0.2
done
./requests.sh | tee captured/requests.log
