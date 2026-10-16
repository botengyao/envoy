#!/usr/bin/env bash
# Makes a throwaway CA, and a certificate for *.googleapis.com it signs, for mock_vertex.py.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj "/CN=Vertex AI mock CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
  -keyout certs/ca.key -out certs/ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=*.googleapis.com" \
  -keyout certs/server.key -out certs/server.csr 2>/dev/null
openssl x509 -req -in certs/server.csr -CA certs/ca.pem -CAkey certs/ca.key -CAcreateserial \
  -days 7 -extfile <(printf 'subjectAltName=DNS:*.googleapis.com\nextendedKeyUsage=serverAuth\n') \
  -out certs/server.pem 2>/dev/null
rm -f certs/server.csr certs/ca.srl
