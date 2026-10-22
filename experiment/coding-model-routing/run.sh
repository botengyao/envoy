#!/usr/bin/env bash
# Runs envoy.yaml on envoy-static with the ext_proc server and mock_vertex.py, and sends
# requests.sh through it. What each side saw lands in captured/.
set -euo pipefail
cd "$(dirname "$0")"
envoy="${ENVOY:-../../bazel-bin/source/exe/envoy-static}"
[[ -f certs/ca.pem ]] || ./gen_certs.sh
mkdir -p captured bin
(cd ext_proc && go build -o ../bin/ext_proc .)

python3 mock_vertex.py > captured/mock.log 2>&1 &
mock=$!
# Local run: the mock listens on 8444.
bin/ext_proc -vertex-host us-east5-aiplatform.googleapis.com:8444 > captured/ext_proc.log 2>&1 &
processor=$!
"$envoy" -c envoy.yaml --log-level warn --component-log-level ai_protocol_manager:debug \
  --file-flush-interval-msec 100 \
  > captured/access.log 2> captured/envoy.log &
gateway=$!
trap 'kill "$gateway" "$processor" "$mock" 2> /dev/null || true' EXIT

# Ready once Envoy, ext_proc and the mock all listen.
until curl -sf http://127.0.0.1:9981/ready > /dev/null && nc -z 127.0.0.1 50061 &&
  nc -z 127.0.0.1 8444; do
  for pid in "$gateway" "$processor" "$mock"; do
    kill -0 "$pid" 2> /dev/null || { tail -5 captured/*.log; exit 1; }
  done
  sleep 0.2
done
./requests.sh | tee captured/requests.log
# Lets the access log flush before the trap stops Envoy.
sleep 1
