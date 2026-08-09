#!/usr/bin/env python3
"""Mock LLM provider for ai_protocol_manager edge-case simulation.

Serves dialect-faithful response shapes on 127.0.0.1:8600; reached through
Envoy with Host: mock.local. Each path simulates one scenario the real
providers cannot produce on demand.
"""

import gzip
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GEMINI_FINAL = {
    "candidates": [{"content": {"parts": [{"text": "hello"}], "role": "model"},
                    "finishReason": "STOP"}],
    "usageMetadata": {"promptTokenCount": 6, "toolUsePromptTokenCount": 5,
                      "candidatesTokenCount": 149, "thoughtsTokenCount": 12,
                      "cachedContentTokenCount": 2, "totalTokenCount": 172},
    "modelVersion": "gemini-2.5-flash-mock",
}
GEMINI_EARLY = {
    "candidates": [{"content": {"parts": [{"text": "hel"}], "role": "model"}}],
    "usageMetadata": {"promptTokenCount": 6, "candidatesTokenCount": 16,
                      "totalTokenCount": 22},
}


def sse(*events):
    return "".join(f"data: {json.dumps(e)}\n\n" for e in events).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        route = getattr(self, "route_" + self.path.strip("/").replace("/", "_"),
                        None)
        if route is None:
            self.reply(404, b'{"error":"unknown scenario"}')
            return
        route()

    def reply(self, status, body, ctype="application/json", extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    # Gemini generateContent: single JSON document.
    def route_gemini_json(self):
        self.reply(200, json.dumps(GEMINI_FINAL).encode())

    # Gemini streamGenerateContent?alt=sse: cumulative snapshots, last wins.
    def route_gemini_sse(self):
        self.reply(200, sse(GEMINI_EARLY, GEMINI_FINAL), "text/event-stream")

    # Gemini default (non-SSE) streaming: root-level JSON array of chunks.
    def route_gemini_array(self):
        self.reply(200, json.dumps([GEMINI_EARLY, GEMINI_FINAL]).encode())

    # Anthropic response with cache buckets: the wire input_tokens EXCLUDES
    # the cache counts; the published canonical input must be their sum.
    def route_anthropic_cached(self):
        self.reply(200, json.dumps({
            "type": "message", "model": "claude-mock",
            "usage": {"input_tokens": 100, "cache_read_input_tokens": 30,
                      "cache_creation_input_tokens": 20, "output_tokens": 10},
        }).encode())

    # Provider-reported total disagrees with input + output.
    def route_mismatch_total(self):
        self.reply(200, json.dumps({
            "object": "chat.completion", "model": "openai-mock",
            "usage": {"prompt_tokens": 3, "completion_tokens": 4,
                      "total_tokens": 100},
        }).encode())

    # Early usage snapshot, then a >1MiB event: published counts are the stale
    # snapshot, flagged extraction_status=partial.
    def route_oversized_event(self):
        big = dict(GEMINI_FINAL)
        big["padding"] = "x" * (2 * 1024 * 1024)
        self.reply(200, sse(GEMINI_EARLY, big), "text/event-stream")

    # Compressed body: content-encoding != identity must skip extraction.
    def route_gzip(self):
        body = gzip.compress(json.dumps(GEMINI_FINAL).encode())
        self.reply(200, body, extra=[("Content-Encoding", "gzip")])

    # Error status carrying usage-shaped JSON: never extracted.
    def route_error_with_usage(self):
        self.reply(500, json.dumps({
            "object": "chat.completion",
            "usage": {"prompt_tokens": 9, "completion_tokens": 9,
                      "total_tokens": 18},
        }).encode())

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    print("mock provider on 127.0.0.1:8600")
    ThreadingHTTPServer(("127.0.0.1", 8600), Handler).serve_forever()
