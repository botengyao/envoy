#!/usr/bin/env python3
"""End-to-end client for the ai_protocol_manager DFP experiment.

Sends real provider requests THROUGH Envoy (127.0.0.1:10000): the Host header
names the provider, the DFP cluster resolves and dials it over TLS, and the
upstream ai_protocol_manager auto-detects the dialect and publishes token
usage to dynamic metadata (see /tmp/aipm_access.log).

API keys are read from the environment and never printed:
  OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY (or GOOGLE_API_KEY).
Providers without a key are skipped.
"""

import http.client
import json
import os
import sys

ENVOY = ("127.0.0.1", 10000)


def call(host, path, headers, body, stream=False):
    conn = http.client.HTTPConnection(*ENVOY, timeout=120)
    payload = json.dumps(body).encode()
    conn.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host)
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(payload)))
    # Ask for identity so the filter can inspect the body (see the docs on
    # content-encoding; providers honor this).
    conn.putheader("Accept-Encoding", "identity")
    for k, v in headers.items():
        conn.putheader(k, v)
    conn.endheaders()
    conn.send(payload)
    resp = conn.getresponse()
    total = 0
    events = 0
    while True:
        chunk = resp.read(16384)
        if not chunk:
            break
        total += len(chunk)
        if stream:
            events += chunk.count(b"data:")
    conn.close()
    kind = f"SSE ({events} data lines)" if stream else "JSON"
    print(f"  -> {resp.status} {kind}, {total} body bytes")
    return resp.status


def openai(key):
    print("[openai] chat completion (JSON)")
    call("api.openai.com", "/v1/chat/completions",
         {"Authorization": f"Bearer {key}"},
         {"model": "gpt-4o-mini", "max_tokens": 24,
          "messages": [{"role": "user", "content": "Say hi in five words."}]})
    print("[openai] chat completion (streaming SSE, include_usage)")
    call("api.openai.com", "/v1/chat/completions",
         {"Authorization": f"Bearer {key}"},
         {"model": "gpt-4o-mini", "max_tokens": 24, "stream": True,
          "stream_options": {"include_usage": True},
          "messages": [{"role": "user", "content": "Say hi in five words."}]},
         stream=True)


def anthropic(key):
    print("[anthropic] messages (JSON)")
    call("api.anthropic.com", "/v1/messages",
         {"x-api-key": key, "anthropic-version": "2023-06-01"},
         {"model": "claude-haiku-4-5", "max_tokens": 24,
          "messages": [{"role": "user", "content": "Say hi in five words."}]})
    print("[anthropic] messages (streaming SSE)")
    call("api.anthropic.com", "/v1/messages",
         {"x-api-key": key, "anthropic-version": "2023-06-01"},
         {"model": "claude-haiku-4-5", "max_tokens": 24, "stream": True,
          "messages": [{"role": "user", "content": "Say hi in five words."}]},
         stream=True)


def gemini(key):
    print("[gemini] generateContent (JSON)")
    call("generativelanguage.googleapis.com",
         "/v1beta/models/gemini-flash-latest:generateContent",
         {"x-goog-api-key": key},
         {"contents": [{"parts": [{"text": "Say hi in five words."}]}]})
    print("[gemini] streamGenerateContent (SSE)")
    call("generativelanguage.googleapis.com",
         "/v1beta/models/gemini-flash-latest:streamGenerateContent?alt=sse",
         {"x-goog-api-key": key},
         {"contents": [{"parts": [{"text": "Say hi in five words."}]}]},
         stream=True)


def main():
    ran = False
    if os.environ.get("OPENAI_API_KEY"):
        openai(os.environ["OPENAI_API_KEY"])
        ran = True
    else:
        print("[openai] skipped: OPENAI_API_KEY not set")
    if os.environ.get("ANTHROPIC_API_KEY"):
        anthropic(os.environ["ANTHROPIC_API_KEY"])
        ran = True
    else:
        print("[anthropic] skipped: ANTHROPIC_API_KEY not set")
    gem = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if gem:
        gemini(gem)
        ran = True
    else:
        print("[gemini] skipped: GEMINI_API_KEY/GOOGLE_API_KEY not set")
    if not ran:
        sys.exit("no provider keys set; nothing to do")
    print("\nToken usage extracted by Envoy (per request):")
    print("  tail /tmp/aipm_access.log | python3 -m json.tool")


if __name__ == "__main__":
    main()
