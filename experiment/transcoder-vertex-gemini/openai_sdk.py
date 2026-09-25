# /// script
# dependencies = ["openai>=1.40"]
# ///
"""The official OpenAI Python SDK, pointed at the gateway: `uv run openai_sdk.py`."""

import os

from openai import OpenAI

client = OpenAI(base_url=os.environ.get("GATEWAY", "http://127.0.0.1:10000") + "/v1",
                api_key="sk-client")
model = os.environ.get("MODEL", "gemini-2.5-flash")

completion = client.chat.completions.create(
    model=model,
    messages=[{"role": "system", "content": "Be brief."},
              {"role": "user", "content": "What does Envoy proxy do? One sentence."}],
)
print("== unary")
print(completion.model_dump_json(indent=2))

print("\n== stream")
stream = client.chat.completions.create(
    model=model,
    messages=[{"role": "user", "content": "Count from 1 to 10, comma separated."}],
    stream=True,
    stream_options={"include_usage": True},
)
for chunk in stream:
    if chunk.choices:
        print(repr(chunk.choices[0].delta.content), chunk.choices[0].finish_reason)
    if chunk.usage:
        print("usage:", chunk.usage.model_dump_json())
