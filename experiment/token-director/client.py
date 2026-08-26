#!/usr/bin/env python3
"""Drive the demo with the real provider SDKs, pointed at an Envoy hop.

Nothing here knows about Envoy beyond the base_url: the SDKs speak their own
native wire protocol, send their own credentials, and the proxy is transparent.
That is the point -- the token accounting happens without the client
participating in it.
"""
import argparse
import os
import sys
import time
import warnings

# The SDK stack is noisy on this interpreter (google-auth EOL notice,
# urllib3/LibreSSL); none of it is about the proxy under test.
warnings.filterwarnings("ignore")

PORTS = {"dfp": 10000, "tunnel": 10010}


def banner(title):
    print(f"\n\033[1m=== {title} ===\033[0m", flush=True)


def show(text, elapsed, framing):
    one_line = " ".join(text.split())
    if len(one_line) > 160:
        one_line = one_line[:157] + "..."
    print(f"  [{framing}] {elapsed*1000:.0f}ms  {one_line}", flush=True)


def openai_chat(base, model, prompt, stream, max_tokens):
    from openai import OpenAI
    client = OpenAI(base_url=f"{base}/openai/v1", api_key=os.environ["OPENAI_API_KEY"])
    start = time.time()
    if stream:
        chunks = client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens, stream=True,
            # Without this, an OpenAI stream carries no usage at all and there
            # is nothing for the filter to extract.
            stream_options={"include_usage": True})
        text = "".join(c.choices[0].delta.content or "" for c in chunks if c.choices)
        show(text, time.time() - start, "sse")
    else:
        resp = client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}], max_tokens=max_tokens)
        show(resp.choices[0].message.content, time.time() - start, "json")


def openai_responses(base, model, prompt, stream, max_tokens):
    from openai import OpenAI
    client = OpenAI(base_url=f"{base}/openai/v1", api_key=os.environ["OPENAI_API_KEY"])
    start = time.time()
    if stream:
        events = client.responses.create(model=model, input=prompt,
                                         max_output_tokens=max_tokens, stream=True)
        text = "".join(e.delta for e in events if e.type == "response.output_text.delta")
        show(text, time.time() - start, "sse")
    else:
        resp = client.responses.create(model=model, input=prompt, max_output_tokens=max_tokens)
        show(resp.output_text, time.time() - start, "json")


def anthropic_messages(base, model, prompt, stream, max_tokens):
    from anthropic import Anthropic
    client = Anthropic(base_url=f"{base}/anthropic", api_key=os.environ["ANTHROPIC_API_KEY"])
    start = time.time()
    if stream:
        with client.messages.stream(model=model, max_tokens=max_tokens,
                                    messages=[{"role": "user", "content": prompt}]) as s:
            text = "".join(s.text_stream)
        show(text, time.time() - start, "sse")
    else:
        resp = client.messages.create(model=model, max_tokens=max_tokens,
                                      messages=[{"role": "user", "content": prompt}])
        show(resp.content[0].text, time.time() - start, "json")


def gemini_generate(base, model, prompt, stream, max_tokens):
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"],
                          http_options=types.HttpOptions(base_url=f"{base}/gemini"))
    config = types.GenerateContentConfig(max_output_tokens=max_tokens)
    start = time.time()
    if stream:
        text = "".join(c.text or "" for c in
                       client.models.generate_content_stream(model=model, contents=prompt,
                                                             config=config))
        show(text, time.time() - start, "sse")
    else:
        resp = client.models.generate_content(model=model, contents=prompt, config=config)
        show(resp.text or "", time.time() - start, "json")


SCENARIOS = {
    "openai": (openai_chat, "gpt-4o-mini"),
    "openai-responses": (openai_responses, "gpt-4o-mini"),
    "anthropic": (anthropic_messages, "claude-haiku-4-5"),
    "gemini": (gemini_generate, "gemini-3.6-flash"),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hop", choices=sorted(PORTS), default="dfp",
                        help="dfp = straight to the DFP proxy; tunnel = via the extra hop")
    parser.add_argument("--provider", default="all",
                        choices=["all"] + sorted(SCENARIOS))
    parser.add_argument("--prompt", default="Name three primary colors. Answer in one line.")
    parser.add_argument("--max-tokens", type=int, default=64)
    parser.add_argument("--framing", default="both", choices=["both", "json", "sse"])
    parser.add_argument("--model", default=None, help="override the scenario's model")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()

    base = f"http://127.0.0.1:{PORTS[args.hop]}"
    names = sorted(SCENARIOS) if args.provider == "all" else [args.provider]
    framings = [False, True] if args.framing == "both" else [args.framing == "sse"]

    failures = 0
    for _ in range(args.repeat):
        for name in names:
            fn, default_model = SCENARIOS[name]
            model = args.model or default_model
            banner(f"{name} / {model} via {args.hop} ({base})")
            for stream in framings:
                try:
                    fn(base, model, args.prompt, stream, args.max_tokens)
                except Exception as exc:  # noqa: BLE001 - demo surface
                    failures += 1
                    print(f"  [{'sse' if stream else 'json'}] \033[31mFAILED\033[0m "
                          f"{type(exc).__name__}: {exc}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
