# OpenAI clients on Vertex AI Gemini, through two transcoder AI filters

An end-to-end run of the transcoder AI filter from
[envoyproxy/envoy#47682](https://github.com/envoyproxy/envoy/pull/47682): clients speak OpenAI
Chat Completions to Envoy, and Envoy calls Gemini on Vertex AI.

```
client (OpenAI SDK, curl)
  POST /v1/chat/completions
    |
  ai_protocol_manager   route: request OPENAI_CHAT_COMPLETIONS, response GEMINI_GENERATE_CONTENT
    |  request  (top down)                       response (bottom up)
    |  transcoder  TO_IR     OpenAI -> IR        FROM_IR  IR -> OpenAI
    |  request_info          sees the IR
    |  transcoder  FROM_IR   IR -> Gemini body,  TO_IR    Gemini JSON/SSE -> IR, adds [DONE]
    |                        :path /v1beta/models/{model}:generateContent
    |                              /v1beta/models/{model}:streamGenerateContent?alt=sse
  credential_injector   x-goog-api-key, read from an SDS file
  router                regex_rewrite /v1beta/models/ -> /v1/projects/P/locations/L/publishers/google/models/
    |                   removes the client's authorization and accept-encoding
Vertex AI  aiplatform.googleapis.com (HTTP/2, TLS)
```

The IR is OpenAI Chat Completions, so for an OpenAI client both legs of the client-edge
transcoder are identities, and the backend-edge transcoder does the Gemini work in both
directions. Token usage is extracted from the raw Gemini response, before it is transcoded.

## Run

```bash
bazel build -c dbg //source/exe:envoy-static
GCP_PROJECT=my-project VERTEX_API_KEY_FILE=~/vertex.key ./run.sh
GCP_PROJECT=my-project ./e2e.py     # shape-checked cases, written to captured/
uv run openai_sdk.py                # the official OpenAI Python SDK against the gateway
./stop.sh
```

`GCP_LOCATION` defaults to `global` and `MODEL` to `gemini-2.5-flash`. The key is written only to
`run/secrets/vertex_api_key.json` (git-ignored, mode 600), which `credential_injector` reads over
SDS. `run/access.log` shows each request's transcoded and upstream path, `request_info`, and token
usage; `e2e.py` copies it into `captured/` with the project id replaced.

## Results

All ten `e2e.py` cases pass against `gemini-2.5-flash`, and the OpenAI Python SDK parses both the
unary and the streamed responses (`captured/openai_sdk.txt`):

| case | checks |
|---|---|
| `unary`, `unary_system_params`, `unary_multi_turn` | `chat.completion` shape; system prompt, `temperature`, `top_p`, `max_tokens`, `stop`, multi-turn history |
| `stream`, `stream_include_usage`, `stream_long` | `chat.completion.chunk` frames ending in `[DONE]`, `finish_reason` on the last chunk |
| `unary_long` | the long answer of `stream_long`, unary |
| `unary_long_prompt` | a 3KiB prompt, held by reference past the 1KiB inline threshold, reaches Gemini intact |
| every 200 | `prompt_tokens + completion_tokens == total_tokens`; `reasoning_tokens` carries Gemini's thoughts |
| `reject_unsafe_model` | a model that is not a path segment is refused with a 400 before any upstream call |
| `unknown_model` | Vertex AI's 404 passes through untouched |

## What the run found in #47682

Fixed forward on this branch, one commit each, with unit tests that fail on the PR's code:

1. **The Gemini call never reached a Gemini URL, and Vertex AI rejected the body.** The `FROM_IR`
   leg left `model`, `stream` and `stream_options` in the body and the path at
   `/v1/chat/completions`. Vertex AI answers `400 Unknown name "stream"` even for
   `"stream": false`, and a static route cannot put a per-request model or streaming mode into the
   path. The leg now moves `model` and `stream` into `:path` and drops `stream_options`; the model
   must be a plain path segment. The `TO_IR` leg lifts `stream` from a Gemini path, next to
   `model`, so Gemini clients keep their method. This needs `AiFilterContext::request_headers` to
   be mutable, which is safe because the manager holds the headers until the chain finishes.
2. **Streamed text past 1KiB was dropped.** The SSE decoder holds such a string as a reference
   into the frame, and Gemini-to-IR copied only inline strings, so the chunk went out with an empty
   `delta.content`. A lone text part is now moved, reference and all.
3. **`completion_tokens` left out Gemini's thought tokens**, so it disagreed with `total_tokens`
   and with the manager's own token-usage record. Usage is now inclusive, as the manager
   canonicalizes it, with `reasoning_tokens` and `cached_tokens` details.

Still open, not needed for this path:

* `created` is never set on transcoded responses; the OpenAI SDK reads it as `null`.
* OpenAI fields with no mapping ride through and Vertex AI rejects them: `tools`, `n`, `seed`,
  `presence_penalty`, `frequency_penalty`, `response_format`, `logprobs`, `user`, and
  content-part arrays (`[{"type": "text", ...}]`).
* Upstream error bodies are not transcoded, so an OpenAI client gets Vertex AI's error shape.
* A compressed response skips response transcoding; the route removes `accept-encoding` for that.
* The other SSE conversions (Anthropic to IR, IR to Gemini or Anthropic clients) have the same
  inline-string-only copy as item 2.
