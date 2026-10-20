#!/usr/bin/env python3
"""Mock Gemini API / Vertex AI backend for the retry-buffer failover prototype.

Serves HTTPS with HTTP/1.1, records the SNI the client sent, and checks what each real backend
would check: the path form, a single credential of the right kind, and a JSON body. Every request
is appended to a JSONL log with a SHA-256 of the body, so a test can prove that the bytes an
attempt received are the bytes the client sent.

The x-test-behavior request header scripts a response per backend, for example
"gemini=429;vertex=200". Values: an HTTP status code, "reset" (close without a response),
"reset-early" (close before reading the body), or "delay:<ms>" (then 200).
"""

import argparse
import hashlib
import http.server
import json
import re
import ssl
import threading
import time
import weakref

PATHS = {
    "gemini": re.compile(r"^/v1beta/models/(?P<model>[A-Za-z0-9._-]+):generateContent$"),
    "vertex": re.compile(
        r"^/v1/projects/[^/]+/locations/[^/]+/publishers/google/models/"
        r"(?P<model>[A-Za-z0-9._-]+):generateContent$"),
}

_sni = weakref.WeakKeyDictionary()
_log_lock = threading.Lock()


def google_error(code, status, message):
    return {"error": {"code": code, "message": message, "status": status}}


def behavior_for(name, header):
    for part in (header or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value.strip()
    return "200"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-llm"

    def log_message(self, fmt, *args):
        pass

    def read_body(self):
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return b"".join(chunks)
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
        return self.rfile.read(int(self.headers.get("content-length", "0")))

    def reply(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        name = self.server.backend_name
        if behavior_for(name, self.headers.get("x-test-behavior")) == "reset-early":
            # Reset before reading the body, while the proxy is still sending it.
            with _log_lock, open(self.server.log_path, "a") as f:
                f.write(json.dumps({"ts": time.time(), "test": self.headers.get("x-test-name"),
                                    "backend": name, "status": None, "early_reset": True}) + "\n")
            self.close_connection = True
            self.connection.shutdown(2)
            return
        body = self.read_body()
        record = {
            "ts": time.time(),
            "test": self.headers.get("x-test-name"),
            "backend": name,
            "sni": _sni.get(self.connection),
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("host"),
            "x-goog-api-key": self.headers.get("x-goog-api-key"),
            "authorization": self.headers.get("authorization"),
            "content-length": self.headers.get("content-length"),
            "transfer-encoding": self.headers.get("transfer-encoding"),
            "x-envoy-attempt-count": self.headers.get("x-envoy-attempt-count"),
            "x-pdp-decision": self.headers.get("x-pdp-decision"),
            "body_len": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        behavior = behavior_for(name, self.headers.get("x-test-behavior"))
        status, payload = self.decide(name, body, behavior)
        record["status"] = status
        with _log_lock, open(self.server.log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
        if status is None:
            self.close_connection = True
            self.connection.shutdown(2)
            return
        self.reply(status, payload)

    def decide(self, name, body, behavior):
        if behavior == "reset":
            return None, None
        if behavior.startswith("delay:"):
            time.sleep(int(behavior.split(":", 1)[1]) / 1000.0)
            behavior = "200"
        match = PATHS[name].match(self.path)
        if match is None:
            return 404, google_error(404, "NOT_FOUND", f"{name}: no such path {self.path}")
        api_key = self.headers.get("x-goog-api-key")
        bearer = self.headers.get("authorization")
        if api_key and bearer:
            return 400, google_error(400, "INVALID_ARGUMENT",
                                     "Multiple authentication credentials received. "
                                     "Please only provide one.")
        if name == "gemini" and not api_key:
            return 401, google_error(401, "UNAUTHENTICATED", "API key required")
        if name == "vertex" and not (bearer or "").startswith("Bearer "):
            return 401, google_error(401, "UNAUTHENTICATED", "OAuth token required")
        try:
            json.loads(body)
        except ValueError:
            return 400, google_error(400, "INVALID_ARGUMENT", "Invalid JSON payload received.")
        status = int(behavior)
        if status != 200:
            return status, google_error(status, "RESOURCE_EXHAUSTED" if status == 429 else
                                        "UNAVAILABLE", f"{name}: scripted {status}")
        return 200, {
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": f"served by {name}"}]},
                "finishReason": "STOP",
            }],
            "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 3,
                              "totalTokenCount": 10},
            "modelVersion": match.group("model"),
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", choices=sorted(PATHS), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)

    def on_sni(sock, server_name, _ctx):
        _sni[sock] = server_name

    context.sni_callback = on_sni
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.backend_name = args.name
    server.log_path = args.log
    print(f"mock {args.name} on https://127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
