#!/usr/bin/env python3
"""A mock of Vertex AI for envoy.yaml.

It answers DNS for *-aiplatform.googleapis.com with 127.0.0.1, and serves Claude on Vertex AI's
rawPredict and streamRawPredict and Gemini's generateContent and streamGenerateContent over TLS,
refusing a request the way Vertex AI would: the method must match the endpoint's region, carry a
bearer token and name the model in the path alone; Claude also needs the Vertex AI API version in
the body.
"""

import argparse
import json
import re
import socket
import socketserver
import ssl
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERTEX_HOST = re.compile(r"^(?P<location>[a-z0-9-]+)-aiplatform\.googleapis\.com(:\d+)?$")
CLAUDE_METHOD = re.compile(
    r"^/v1/projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)"
    r"/publishers/anthropic/models/(?P<model>[^/:]+):(?P<method>rawPredict|streamRawPredict)$")
GEMINI_METHOD = re.compile(
    r"^/v1/projects/(?P<project>[^/]+)/locations/(?P<location>[^/]+)"
    r"/publishers/google/models/(?P<model>[^/:]+)"
    r":(?P<method>generateContent|streamGenerateContent\?alt=sse)$")
ANSWER = [
    "Envoy matches the request to a route, ",
    "runs that route's HTTP filters, ",
    "and forwards it to a host the route's cluster picks.",
]


def log(line):
    print(line, flush=True)


class DnsHandler(socketserver.BaseRequestHandler):
    """Answers A queries for *-aiplatform.googleapis.com with 127.0.0.1."""

    def handle(self):
        query, sock = self.request
        end, labels = 12, []
        while query[end]:
            labels.append(query[end + 1:end + 1 + query[end]].decode())
            end += 1 + query[end]
        qtype = struct.unpack("!H", query[end + 1:end + 3])[0]
        name = ".".join(labels).lower()
        known = name.endswith("-aiplatform.googleapis.com")
        answer = b""
        if known and qtype == 1:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("127.0.0.1")
        # A recursive answer; NXDOMAIN for any other name.
        flags = 0x8180 if known else 0x8183
        header = query[:2] + struct.pack("!HHHHH", flags, 1, 1 if answer else 0, 0, 0)
        sock.sendto(header + query[12:end + 5] + answer, self.client_address)
        log(f"dns    {name} -> {'127.0.0.1' if answer else 'no address'}")


class VertexError(Exception):

    def __init__(self, code, status, message):
        super().__init__(message)
        self.code = code
        self.status = status


class VertexHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        if self.path == "/echo":
            # Any other service the forward proxy reaches.
            log(f"echo   POST https://{self.headers.get('host')}{self.path} {body!r}")
            self.send_response(200)
            self.send_header("content-type", self.headers.get("content-type", "text/plain"))
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        log(f"vertex POST https://{self.headers.get('host')}{self.path}")
        log(f"       authorization: {self.headers.get('authorization')}")
        log(f"       body: {body.decode(errors='replace')}")
        try:
            method, request = self.check(body)
        except VertexError as error:
            log(f"       -> {error.code} {error}")
            self.send_json(error.code,
                           {"error": {"code": error.code, "message": str(error), "status": error.status}})
            return
        if method["method"] == "streamRawPredict":
            self.stream(method["model"])
        elif method["method"] == "rawPredict":
            self.send_json(200, self.message(method["model"]))
        elif method["method"] == "generateContent":
            self.send_json(200, self.gemini_chunk(method["model"], "".join(ANSWER), final=True))
        else:
            self.stream_gemini(method["model"])
        log(f"       -> 200 {method['method']}")

    def check(self, body):
        method = CLAUDE_METHOD.match(self.path) or GEMINI_METHOD.match(self.path)
        host = VERTEX_HOST.match(self.headers.get("host", ""))
        if method is None or host is None:
            raise VertexError(404, "NOT_FOUND", f"no such method: {self.path}")
        if host["location"] != method["location"]:
            raise VertexError(400, "FAILED_PRECONDITION",
                              "the endpoint's region is not the location the path names")
        if not self.headers.get("authorization", "").startswith("Bearer "):
            raise VertexError(401, "UNAUTHENTICATED",
                              "Request is missing required authentication credential.")
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            raise VertexError(400, "INVALID_ARGUMENT", "the body is not JSON")
        if method.re is GEMINI_METHOD:
            for extra in ("model", "stream"):
                if extra in request:
                    raise VertexError(400, "INVALID_ARGUMENT",
                                      f'Invalid JSON payload received. Unknown name "{extra}"')
            if not request.get("contents"):
                raise VertexError(400, "INVALID_ARGUMENT", "contents is required")
            return method, request
        if request.get("anthropic_version") != "vertex-2023-10-16":
            raise VertexError(400, "INVALID_ARGUMENT",
                              "anthropic_version: Input should be 'vertex-2023-10-16'")
        if "model" in request:
            raise VertexError(400, "INVALID_ARGUMENT", "model: Extra inputs are not permitted")
        if not isinstance(request.get("max_tokens"), int) or not request.get("messages"):
            raise VertexError(400, "INVALID_ARGUMENT", "max_tokens and messages are required")
        if request.get("stream", False) != (method["method"] == "streamRawPredict"):
            raise VertexError(400, "INVALID_ARGUMENT", "stream does not match the method")
        return method, request

    @staticmethod
    def message(model):
        return {
            "id": "msg_vrtx_01",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": "".join(ANSWER)}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 27, "output_tokens": 24},
        }

    def stream(self, model):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()
        start = self.message(model) | {"content": [], "stop_reason": None,
                                        "usage": {"input_tokens": 27, "output_tokens": 1}}
        events = [
            ("message_start", {"type": "message_start", "message": start}),
            ("content_block_start",
             {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ("ping", {"type": "ping"}),
        ]
        events += [("content_block_delta", {"type": "content_block_delta", "index": 0,
                                            "delta": {"type": "text_delta", "text": text}})
                   for text in ANSWER]
        events += [
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta",
                               "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                               "usage": {"output_tokens": 24}}),
            ("message_stop", {"type": "message_stop"}),
        ]
        for name, data in events:
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.05)
        self.close_connection = True

    @staticmethod
    def gemini_chunk(model, text, final):
        chunk = {
            "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}}],
            "usageMetadata": {"trafficType": "ON_DEMAND"},
            "modelVersion": model,
            "responseId": "vertex-response-1",
        }
        if final:
            chunk["candidates"][0]["finishReason"] = "STOP"
            chunk["usageMetadata"] |= {"promptTokenCount": 25, "candidatesTokenCount": 22,
                                       "totalTokenCount": 47}
        return chunk

    def stream_gemini(self, model):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()
        # Gemini on Vertex AI ends each event with CRLFs and the stream without `[DONE]`.
        for i, text in enumerate(ANSWER):
            chunk = self.gemini_chunk(model, text, final=i + 1 == len(ANSWER))
            self.wfile.write(f"data: {json.dumps(chunk)}\r\n\r\n".encode())
            self.wfile.flush()
            time.sleep(0.05)
        self.close_connection = True

    def send_json(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json; charset=UTF-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dns-port", type=int, default=15354)
    parser.add_argument("--https-port", type=int, default=8444)
    parser.add_argument("--cert", default="certs/server.pem")
    parser.add_argument("--key", default="certs/server.key")
    args = parser.parse_args()

    dns = socketserver.ThreadingUDPServer(("127.0.0.1", args.dns_port), DnsHandler)
    threading.Thread(target=dns.serve_forever, daemon=True).start()

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(args.cert, args.key)
    tls.set_alpn_protocols(["http/1.1"])
    https = ThreadingHTTPServer(("127.0.0.1", args.https_port), VertexHandler)
    https.socket = tls.wrap_socket(https.socket, server_side=True)
    log(f"mock Vertex AI: DNS on 127.0.0.1:{args.dns_port}, HTTPS on 127.0.0.1:{args.https_port}")
    https.serve_forever()


if __name__ == "__main__":
    main()
