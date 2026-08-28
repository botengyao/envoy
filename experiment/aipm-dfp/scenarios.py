#!/usr/bin/env python3
"""Extended use-case scenarios for the ai_protocol_manager experiment.

Real-provider track (keys from env, never printed):
  - OpenAI Responses API streaming (usage on the terminal lifecycle event).
  - OpenAI prompt caching: a >1024-token prompt sent twice; the second call
    reports prompt_tokens_details.cached_tokens.
  - Anthropic prompt caching via cache_control: first call writes the cache
    (cache_creation_input_tokens), second reads it (cache_read_input_tokens);
    the published canonical input must include both buckets, which the wire
    input_tokens excludes.

Mock track (Host: mock.local -> local mock provider):
  Gemini JSON / SSE / root-array framing, cache-bucket summation,
  provider-total mismatch, oversized SSE event, gzip skip, error status.
"""

import http.client
import json
import os

ENVOY = ("127.0.0.1", 10000)


def call(host, path, headers, body, label):
    conn = http.client.HTTPConnection(*ENVOY, timeout=120)
    payload = json.dumps(body).encode()
    conn.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host)
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(payload)))
    conn.putheader("Accept-Encoding", "identity")
    for k, v in headers.items():
        conn.putheader(k, v)
    conn.endheaders()
    conn.send(payload)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    print(f"[{label}] -> {resp.status}, {len(data)} bytes")
    return resp.status, data


def mock_scenarios():
    for scenario in ["gemini/json", "gemini/sse", "gemini/array",
                     "anthropic/cached", "mismatch/total", "oversized/event",
                     "gzip", "error/with/usage"]:
        call("mock.local", "/" + scenario, {}, {}, f"mock {scenario}")


def openai_responses_api(key):
    call("api.openai.com", "/v1/responses",
         {"Authorization": f"Bearer {key}"},
         {"model": "gpt-4o-mini", "input": "Say hi in five words.",
          "max_output_tokens": 32, "stream": True},
         "openai responses-api SSE")


def openai_prompt_caching(key):
    # >1024 prompt tokens so the second identical call hits the prompt cache.
    long_prefix = "You are a precise assistant. " + \
        " ".join(f"Fact {i}: the number {i} is {'even' if i % 2 == 0 else 'odd'}."
                 for i in range(260))
    body = {"model": "gpt-4o-mini", "max_tokens": 8,
            "messages": [{"role": "system", "content": long_prefix},
                         {"role": "user", "content": "Say ok."}]}
    call("api.openai.com", "/v1/chat/completions",
         {"Authorization": f"Bearer {key}"}, body, "openai cache warm")
    call("api.openai.com", "/v1/chat/completions",
         {"Authorization": f"Bearer {key}"}, body, "openai cache hit")


def anthropic_prompt_caching(key):
    # >2048 cacheable tokens for haiku; cache_control marks the block.
    long_doc = " ".join(f"Clause {i}: the number {i} is "
                        f"{'even' if i % 2 == 0 else 'odd'}."
                        for i in range(520))
    body = {"model": "claude-haiku-4-5", "max_tokens": 8,
            "system": [{"type": "text", "text": long_doc,
                        "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": "Say ok."}]}
    hdrs = {"x-api-key": key, "anthropic-version": "2023-06-01"}
    status, data = call("api.anthropic.com", "/v1/messages", hdrs, body,
                        "anthropic cache write")
    if status == 200:
        print("   wire usage:", json.dumps(json.loads(data).get("usage", {})))
    status, data = call("api.anthropic.com", "/v1/messages", hdrs, body,
                        "anthropic cache read")
    if status == 200:
        print("   wire usage:", json.dumps(json.loads(data).get("usage", {})))


def main():
    mock_scenarios()
    if os.environ.get("OPENAI_API_KEY"):
        openai_responses_api(os.environ["OPENAI_API_KEY"])
        openai_prompt_caching(os.environ["OPENAI_API_KEY"])
    if os.environ.get("ANTHROPIC_API_KEY"):
        anthropic_prompt_caching(os.environ["ANTHROPIC_API_KEY"])
    print("\nPublished metadata: tail -n 20 /tmp/aipm_access.log")


if __name__ == "__main__":
    main()
