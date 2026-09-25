#!/usr/bin/env python3
"""Drives OpenAI Chat Completions requests through the gateway started by run.sh.

Each case is checked for OpenAI response shape and saved under captured/. Standard library only.

    ./e2e.py                 # all cases
    ./e2e.py stream long     # cases whose name contains any argument
    MODEL=gemini-2.5-flash-lite ./e2e.py
"""

import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

GATEWAY = os.environ.get("GATEWAY", "http://127.0.0.1:10000")
ADMIN = os.environ.get("ADMIN", "http://127.0.0.1:9901")
MODEL = os.environ.get("MODEL", "gemini-2.5-flash")
HERE = pathlib.Path(__file__).resolve().parent
# Captures are meant to be shared, so the project id is replaced when GCP_PROJECT is set.
PROJECT = os.environ.get("GCP_PROJECT")
CAPTURED = HERE / "captured"
RUN_DIR = pathlib.Path(os.environ.get("RUN_DIR", HERE / "run"))


def redact(text):
    return text.replace(PROJECT, "my-project") if PROJECT else text


def post(body):
    request = urllib.request.Request(
        f"{GATEWAY}/v1/chat/completions",
        data=json.dumps(body).encode(),
        # A client's own key is stripped by the route; Vertex AI never sees it.
        headers={"content-type": "application/json", "authorization": "Bearer sk-client"},
        method="POST")
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return response.status, dict(response.headers), response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode()


def sse_payloads(raw):
    return [line[len("data:"):].strip() for line in raw.splitlines() if line.startswith("data:")]


# Gemini 2.5 models think; OpenAI counts reasoning inside completion_tokens.
def check_usage(usage):
    assert usage["total_tokens"] > 0, usage
    assert usage["prompt_tokens"] + usage["completion_tokens"] == usage["total_tokens"], usage


def check_unary(status, headers, raw):
    assert status == 200, f"status {status}: {raw[:300]}"
    body = json.loads(raw)
    assert body["object"] == "chat.completion", body
    choice = body["choices"][0]
    assert choice["message"]["role"] == "assistant", choice
    assert choice["message"]["content"], f"empty content: {choice}"
    assert choice["finish_reason"] in ("stop", "length", "content_filter"), choice
    check_usage(body["usage"])
    return choice["message"]["content"]


def check_stream(status, headers, raw):
    assert status == 200, f"status {status}: {raw[:300]}"
    assert headers.get("content-type", "").startswith("text/event-stream"), headers
    payloads = sse_payloads(raw)
    assert payloads and payloads[-1] == "[DONE]", f"stream must end with [DONE]: {payloads[-1:]}"
    chunks = [json.loads(p) for p in payloads[:-1]]
    assert all(c["object"] == "chat.completion.chunk" for c in chunks), chunks
    text = "".join(c["choices"][0]["delta"].get("content", "") for c in chunks if c["choices"])
    finish = [c["choices"][0]["finish_reason"] for c in chunks if c["choices"]]
    assert text, "empty streamed content"
    assert finish[-1] in ("stop", "length"), finish
    usages = [c["usage"] for c in chunks if "usage" in c]
    assert usages, "no usage on any chunk"
    check_usage(usages[-1])
    return text


def check_status(expected):
    def check(status, headers, raw):
        assert status == expected, f"status {status}, want {expected}: {raw[:300]}"
        return raw.strip()[:200]
    return check


def messages(*turns):
    return [{"role": role, "content": content} for role, content in turns]


CASES = [
    ("unary", check_unary, {
        "model": MODEL,
        "messages": messages(("user", "Reply with one word: the capital of France.")),
    }),
    ("unary_system_params", check_unary, {
        "model": MODEL,
        "messages": messages(("system", "You answer in upper case only."),
                             ("user", "Name three primary colors, comma separated.")),
        "temperature": 0,
        "top_p": 0.9,
        "max_tokens": 512,
        "stop": ["END"],
        "stream": False,
    }),
    ("unary_multi_turn", check_unary, {
        "model": MODEL,
        "messages": messages(("user", "My name is Ada. Remember it."),
                             ("assistant", "Got it, Ada."),
                             ("user", "What is my name? One word.")),
    }),
    ("stream", check_stream, {
        "model": MODEL,
        "messages": messages(("user", "Count from 1 to 20, comma separated.")),
        "stream": True,
    }),
    ("stream_include_usage", check_stream, {
        "model": MODEL,
        "messages": messages(("user", "Write a haiku about proxies.")),
        "stream": True,
        "stream_options": {"include_usage": True},
    }),
    # Gemini sends multi-KiB chunks for long answers.
    ("stream_long", check_stream, {
        "model": MODEL,
        "messages": messages(("user", "Write 25 numbered sentences, each about 30 words, "
                                      "describing what an HTTP proxy does.")),
        "stream": True,
    }),
    ("unary_long", check_unary, {
        "model": MODEL,
        "messages": messages(("user", "Write 25 numbered sentences, each about 30 words, "
                                      "describing what an HTTP proxy does.")),
    }),
    # A prompt past the 1KiB inline threshold is parsed as a reference into the request body, and
    # must survive the move from `messages[].content` to `contents[].parts[].text`.
    ("unary_long_prompt", check_unary, {
        "model": MODEL,
        "messages": messages(("user", "How many lines are in this log? Answer with a number.\n"
                              + "".join(f"line {i}: \"GET /api/v1/items/{i}\" 200 ✓\n"
                                        for i in range(1, 81)))),
    }),
    # The model becomes a path segment, so the transcoder refuses anything that could escape it.
    ("reject_unsafe_model", check_status(400), {
        "model": "../../evil:generateContent?key=x",
        "messages": messages(("user", "hi")),
    }),
    # Vertex AI's own error passes through untranscoded.
    ("unknown_model", check_status(404), {
        "model": "gemini-does-not-exist",
        "messages": messages(("user", "hi")),
    }),
]


def main(filters):
    CAPTURED.mkdir(exist_ok=True)
    failures = 0
    for index, (name, check, body) in enumerate(CASES, start=1):
        if filters and not any(f in name for f in filters):
            continue
        status, headers, raw = post(body)
        try:
            summary = check(status, {k.lower(): v for k, v in headers.items()}, raw)
            verdict = "PASS"
        except (AssertionError, KeyError, IndexError, ValueError) as error:
            summary, verdict = f"{type(error).__name__}: {error}", "FAIL"
            failures += 1
        capture = f"== request\nPOST /v1/chat/completions\n{json.dumps(body, indent=2)}\n\n"
        capture += f"== response {status}\n"
        for key in ("content-type", "content-length", "transfer-encoding"):
            if key in {k.lower() for k in headers}:
                capture += f"{key}: {next(v for k, v in headers.items() if k.lower() == key)}\n"
        capture += f"\n{raw}\n\n== {verdict}\n{summary}\n"
        (CAPTURED / f"{index:02d}_{name}.txt").write_text(redact(capture))
        print(f"{verdict} {name}: {redact(' '.join(str(summary).split()))[:150]}")

    with urllib.request.urlopen(f"{ADMIN}/stats?filter=ai_protocol_manager") as response:
        (CAPTURED / "stats.txt").write_text(response.read().decode())
    # Envoy flushes the access log every second (run.sh's --file-flush-interval-msec).
    time.sleep(1.5)
    if (RUN_DIR / "access.log").exists():
        (CAPTURED / "access.log").write_text(redact((RUN_DIR / "access.log").read_text()))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
