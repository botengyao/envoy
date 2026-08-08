# AI Protocol Manager: response handling and token-usage propagation

Status: draft for iteration. Covers the response (encode-path) handlers, dual
downstream/upstream deployment, provider auto-detection, and the dynamic-metadata
contract used to propagate token usage to ext_proc, access logs, and other consumers.

Out of scope here (future designs): request/response transcoding between AI dialects,
storage-backed external buffer, request-payload anti-smuggling validation.

## 1. Goals

- Extract **LLM token usage** from upstream responses — streaming SSE and
  non-streaming JSON — for **OpenAI** (Chat Completions + Responses API),
  **Anthropic** (Messages API), and **Gemini** (generateContent /
  streamGenerateContent), normalize it, and publish it as dynamic metadata.
- Work as a **downstream HTTP filter, an upstream HTTP filter, or both at once**.
  The upstream-filter role is required for Ambient DFP-style egress, where the
  provider is chosen per request and the filter must live on the (dynamic forward
  proxy) cluster's upstream filter chain.
- **Auto-detect** the provider/API dialect; no static provider config required
  (explicit config remains possible).
- Integrate with **ext_proc** purely through metadata: an external server receives
  request classification (model, provider) and response token usage without either
  component knowing about the other.
- Never alter, delay, or fail the response. Response handling is observe-only.

## 2. Mental model

Three planes connected by one bus:

| Plane | Component | Job |
|---|---|---|
| Protocol plane | `ai_protocol_manager` (dual-role) | Understands AI wire dialects. Parses, classifies, (later) transcodes. Produces *facts*: model, provider, API, token usage. No policy. |
| Policy / reporting plane | `ext_proc` <-> external server | Consumes facts, makes decisions (auth, quota, model routing), reports usage. Never parses AI protocols. |
| Transport plane | router / DFP cluster | Picks the upstream. In Ambient DFP the provider is only known per request, hence auto-detection. |

The bus is **dynamic metadata on the downstream StreamInfo** under the
`envoy.aigw.*` namespaces. Upstream HTTP filters read and write the *downstream*
StreamInfo (`UpstreamFilterManager::streamInfo()` returns
`parent_.callbacks()->streamInfo()`, see `source/common/router/upstream_request.cc`),
so a fact written by any instance on any path is immediately visible to every later
filter on that frame's path, to access loggers, and to ext_proc's
`metadata_context`. Metadata writes are the events; filter ordering is the causality
guarantee. No new channel is required.

When both instances are deployed, each faces one dialect:

- **Downstream instance** speaks the client's dialect: request classification
  (model id, provider, streaming), later response transcoding back to the client.
- **Upstream instance** speaks the provider's dialect: request pass-through or
  transcoding, and **response token extraction — always here**, because it must see
  provider-native bytes (pre-transcode), and in upstream-only deployments it is the
  only instance.

## 3. Topology and data flow

```
            request path (decode) ──────────────────────────────►
 client ──► [DS] ai_protocol_manager ──► [DS] ext_proc ──► router ──► [US] ai_protocol_manager ──► provider
             │ detect provider/API        │ metadata_context          │ per-cluster (DFP), per-attempt
             │ extract model from body    │ → authz / quota / creds   │ passthrough (now) / transcode (later)
             └─ write envoy.aigw.request  └─ can deny / mutate        │
                                                                      │
            ◄────────────────────────── response path (encode)        │
 client ◄── [DS] ext_proc ◄──────────────────────────────────────── [US] ai_protocol_manager
             │ final body/trailers message carries                    │ tee SSE/JSON, accumulate usage
             │ metadata_context.envoy.aigw.token_usage                └─ write envoy.aigw.token_usage
             └─ external server debits budget       access logs / OTel read the same namespaces at stream end
```

Ordering guarantees (pure filter-order, no coordination):

- Request: downstream `ai_protocol_manager` runs before `ext_proc`, so
  `envoy.aigw.request` is present in ext_proc's request-phase `metadata_context`.
  Both run before the upstream instance, which inherits the detection result.
- Response: for every frame, upstream filters run before downstream filters, so
  usage written by the upstream instance on the final data frame is visible when
  downstream ext_proc forwards that same end-of-stream frame.

Supported deployments, same binary behavior:

1. **Upstream-only (Ambient DFP):** one instance on the DFP cluster's upstream
   filter chain performs detection and response usage extraction. Usage still lands
   in downstream metadata, so access logging needs zero downstream config.
2. **Downstream-only:** everything in the listener chain.
3. **Full gateway:** the diagram above.

## 4. The `envoy.aigw.*` metadata contract

Stable, versioned contract between the protocol plane and every consumer.
Two namespaces, single writer each. Namespace strings are configurable with these
defaults.

`envoy.aigw.request` — written once by the instance that classifies the request
(downstream if present, else upstream):

```yaml
provider: "openai" | "anthropic" | "gemini"
api:      "chat_completions" | "responses" | "messages" | "generate_content"
model:    "gpt-5" | "claude-opus-5" | ...     # from the request body
streaming: true                               # stream:true / alt=sse / :streamGenerateContent
```

`envoy.aigw.token_usage` — written by the instance that owns response handling
(upstream wins; a downstream instance skips when the namespace is already
populated):

```yaml
provider: "anthropic"
model: "claude-opus-5"            # response-reported model (may differ from request)
input_tokens: 1200
output_tokens: 350
total_tokens: 1550
cached_input_tokens: 800          # when present
cache_creation_input_tokens: 0    # anthropic, when present
reasoning_tokens: 120             # when present
complete: true                    # false = partial (stream ended abnormally)
```

Contract rules:

- **Ownership:** one writer per namespace per stream. Response extraction binds to
  the provider-facing instance; `envoy.aigw.request` binds to the client-facing
  instance.
- **Detection propagates on the bus:** the response handler first reads
  `envoy.aigw.request.provider` as its provider hint; only if absent does it fall
  back to response-shape sniffing. Detection happens once per stream, wherever it
  happens first.
- **Retries:** upstream filter instances are per-attempt; last-write-wins means the
  winning attempt's usage is final.

### Write policy (event semantics)

- **FINALIZE (default):** write once at the last response data frame / trailers.
  Guaranteed to precede ext_proc's end-of-stream message and the access-log flush.
- **PROGRESSIVE (opt-in, later phase):** rewrite the namespace whenever accumulated
  usage changes (Anthropic `message_delta`, Gemini cumulative snapshots). Enables
  mid-stream consumers — e.g. an ext_proc server in STREAMED mode watching output
  tokens grow and cutting off a stream that exceeds a budget. `setDynamicMetadata`
  merges per namespace, so this is cheap and idempotent.
- **Abnormal end:** on stream reset mid-SSE (tokens were still generated and billed
  by the provider), flush partial usage with `complete: false` from `onDestroy`.
  Access logs always fire at stream end, so access log / ALS / OTel is the
  guaranteed export channel; ext_proc reporting is the interactive channel (its
  stream may die with the client). Consumers that must never lose usage should use
  both.

### ext_proc integration (config only, no code coupling)

```yaml
ext_proc:
  metadata_options:
    forwarding_namespaces:
      untyped: ["envoy.aigw.request", "envoy.aigw.token_usage"]
```

Request phase: the server sees model/provider for authz, quota pre-checks,
credential injection, or model-based routing via header mutation. Response phase:
the final `response_body` / `response_trailers` ProcessingRequest carries the
completed `token_usage` for budget debiting. For pure reporting, run ext_proc in
`observability_mode` (fire-and-forget, off the latency path).

## 5. Filter architecture

```
AiProtocolManagerFilter (one class, dual-registered via DualFactoryBase:
                         envoy.filters.http + envoy.filters.http.upstream)
├── decode path (existing): external-buffer offload/replay
│     └── RequestClassifier (phase 2): host/path detection + model extraction
│           → writes envoy.aigw.request
├── encode path (new): observe-only tee; never holds or mutates the response
│     ├── SseResponseHandler  — shared SseParser + per-event Json::Factory
│     ├── JsonResponseHandler — capped side buffer, parse at end_stream
│     └── TokenUsageExtractor per provider + field-wise merge
│           → writes envoy.aigw.token_usage
└── (future) Transcoder: request rewrite via BufferManager offload/replay,
      streaming response rewrite via EncoderFilterChainBridge. Token extraction
      taps provider-native bytes regardless.
```

- **No role knob.** The proto has independent `request_handling` /
  `response_handling` sections; an instance does whatever its config enables,
  wherever it is installed. Typical: downstream enables request handling, upstream
  enables response handling; upstream-only enables both.
- **Observe-only tee:** every `encodeData` frame is copied into the handler and the
  original bytes continue unmodified (`FilterDataStatus::Continue` always; headers
  never held). SSE must stream (time-to-first-token); JSON extraction is
  observability and does not justify a buffering hop. The
  `EncoderFilterChainBridge` + encode-side `BufferManager` remain reserved for
  future response validation/rewrite.
- **Parsers:** the shared `source/common/http/sse` `SseParser`
  (`findEventEnd`/`parseEvent`) with a side buffer and `max_event_size` discard
  guard (same shape as `sse_to_metadata`); per-event data payloads and JSON bodies
  parsed with Envoy `Json::Factory` (nlohmann). **The wuffs streaming cursor is
  deliberately not used**: it caps nesting depth (Gemini tool-call `args` nest
  arbitrarily) and rejects duplicate keys — right for request validation, wrong for
  observe-only extraction.
- **Upstream-filter constraints are compatible:** the observe-only encode path uses
  no downstream-only APIs (no route mutation, no local replies on the response
  path).

### Handler selection (`encodeHeaders`)

- No `response_handling` config, or non-2xx status: inert pass-through.
- `content-type: text/event-stream` (case-insensitive, parameters cropped): SSE
  handler.
- `content-type: application/json` (parameter-tolerant prefix match — deliberately
  avoiding json_to_metadata's exact-match pitfall with `; charset=utf-8`): JSON
  handler. A root-level JSON **array** is handled per element with last-wins merge,
  which covers Gemini's default (non-SSE) streaming for free.
- Anything else: inert. `end_stream` at headers: nothing to do.

### Provider detection ladder

First hit wins; the result is cached in `envoy.aigw.request` and reused:

1. Request `:authority` + `:path` — `api.openai.com` + `/v1/chat/completions` or
   `/v1/responses`; `api.anthropic.com` + `/v1/messages`;
   `generativelanguage.googleapis.com` / `*-aiplatform.googleapis.com` +
   `:generateContent` / `:streamGenerateContent`. The primary signal in DFP, where
   host is the routing key anyway.
2. Request body shape — `model` + `messages[]` vs `contents[]`, etc. (phase 2).
3. Response shape — `usageMetadata`/`candidates`/`modelVersion` => Gemini; root
   `type` in `{message, message_start, message_delta, ...}` => Anthropic; `object`
   in `{chat.completion, chat.completion.chunk, response}` or `type` starting with
   `response.` => OpenAI. Undetermined events are skipped; once detected, the
   provider is pinned for the stream.

## 6. Token-usage mapping and merge semantics

Normalized struct (all fields optional): `input_tokens`, `output_tokens`,
`total_tokens`, `cached_input_tokens`, `cache_creation_input_tokens`,
`reasoning_tokens`, `model`, `provider`.

| | OpenAI (Chat Completions / Responses) | Anthropic (Messages) | Gemini (generateContent) |
|---|---|---|---|
| Non-streaming JSON | `usage.prompt_tokens` / `completion_tokens` / `total_tokens`; Responses: `usage.input_tokens` / `output_tokens` / `total_tokens` | `usage.input_tokens`, `usage.output_tokens` (no total — computed) | `usageMetadata.promptTokenCount` / `candidatesTokenCount` / `totalTokenCount` |
| Streaming (SSE) | chunks carry `usage: null`; final pre-`[DONE]` chunk has `usage` only when the client sent `stream_options.include_usage` (absent => `token_usage_missing`). Responses API: `event: response.completed` → `response.usage` | `event: message_start` → `message.usage.input_tokens` + cache fields; `event: message_delta` → cumulative `usage.output_tokens` (last wins); `message_stop` = parsing complete | each chunk may carry cumulative `usageMetadata`; last wins; no terminator (finalize at end_stream) |
| Cache / extras | `prompt_tokens_details.cached_tokens`, `completion_tokens_details.reasoning_tokens` (Responses: `input_tokens_details.cached_tokens`, `output_tokens_details.reasoning_tokens`) | `cache_read_input_tokens` → cached_input; `cache_creation_input_tokens` | `cachedContentTokenCount` → cached_input; `thoughtsTokenCount` → reasoning |
| Model | root `model` | `message.model` / root `model` | `modelVersion` |

**One merge rule for all providers:** every event/body yields a partial usage; the
accumulator merges field-wise with later-non-null-wins. Correct simultaneously for
OpenAI (single terminal usage), Anthropic (input from `message_start`, cumulative
output from the last `message_delta`), and Gemini (cumulative snapshots). At
finalize: `total_tokens = provider total, else input + output`.

`data: [DONE]` is recognized as the OpenAI terminator (marks parsing complete), not
a parse error.

## 7. Config sketch

```proto
message AiProtocolManager {
  RequestHandling request_handling = 1;    // phase 2
  ResponseHandling response_handling = 2;
}

message ResponseHandling {
  enum ApiProvider { AUTO_DETECT = 0; OPENAI = 1; ANTHROPIC = 2; GEMINI = 3; }
  ApiProvider provider = 1;

  // Namespace for emitted dynamic metadata. Default: envoy.aigw.token_usage
  string metadata_namespace = 2;

  // SSE: max buffered bytes for one incomplete event before pending data is
  // discarded (stream keeps flowing). Default 16KiB, max 10MiB.
  google.protobuf.UInt32Value max_event_size = 3;

  // JSON: max response-body bytes to inspect; larger bodies skip extraction.
  // Default 4MiB, max 10MiB.
  google.protobuf.UInt32Value max_inspected_body_size = 4;
}
```

Listener/cluster-level only initially; per-route/per-cluster overrides are a
follow-up.

## 8. Stats

`ai_protocol_manager.` scope (the filter's first stats):

- `token_usage_found` / `token_usage_missing`
- `response_parse_error` (per occurrence; stream unaffected)
- `response_body_too_large` / `sse_event_too_large`

## 9. Failure policy

No path through response handling can alter, delay, or fail the response. Parse
errors skip the event/body with a stat; caps bound memory; unknown shapes end in
`token_usage_missing`; terminators only stop further parsing. Abnormal stream end
produces a best-effort partial write (phase 3).

## 10. Phasing

| Phase | Deliverable | Unblocks |
|---|---|---|
| 1 | Dual registration (DualFactoryBase, upstream extension metadata) + SSE/JSON response handlers + provider extractors + `envoy.aigw.token_usage` (FINALIZE) + stats | Ambient DFP upstream-only usage accounting via access logs |
| 2 | RequestClassifier: detection ladder + model extraction + `envoy.aigw.request`; ext_proc `forwarding_namespaces` example + integration test | Full gateway: request-side quota/authz, response-side debit |
| 3 | PROGRESSIVE updates + `complete:false` partial flush on destroy | Mid-stream budget enforcement; loss-free billing |
| 4 | Transcoding (separate design) | Client dialect <-> provider dialect |

## 11. Test plan (phase 1)

- `token_usage_extractor_test`: captured payload fixtures per provider —
  non-streaming, streaming sequences (Anthropic `message_start`/`message_delta`
  accumulation; OpenAI usage-null chunks + `include_usage` final chunk + missing
  usage; Gemini cumulative snapshots), cache/reasoning fields, auto-detection,
  merge semantics.
- `sse_response_handler_test`: events split at arbitrary byte boundaries (incl.
  split CRLF), `[DONE]`, comments/`ping` keep-alives, oversized event,
  multi-`data:`-line events.
- `json_response_handler_test`: multi-frame bodies, cap exceeded, invalid JSON,
  root array (Gemini non-SSE stream), non-object root.
- `filter_test`: dispatch matrix (status x content-type), pass-through invariants
  (bytes untouched, always Continue), metadata at end_stream vs trailers, decode
  path regression-free.
- Integration: chunked SSE and JSON responses from fake upstream, asserted via
  access-log format string, across protocol combos; one variant with the filter
  installed as an upstream filter.

## 12. Open questions

1. `envoy.aigw.request` as a second namespace vs folding request facts into one
   namespace. (Recommended: separate, keeps single-writer semantics clean.)
2. Should phase 1 include header-only (host/path) detection so upstream-only DFP
   deployments classify without body parsing, or stay strictly response-side?
3. Configurable namespace strings (recommended, with `envoy.aigw.*` defaults) vs
   hardcoded.
4. Whether partial-usage flush on destroy (phase 3) should also fire for failed
   retry attempts, or only for the winning attempt.
