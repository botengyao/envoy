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
model:    "gpt-5" | "claude-opus-5" | ...     # body `model` (OpenAI/Anthropic); URL path (Gemini)
streaming: true                               # body stream:true (OpenAI/Anthropic); URL :streamGenerateContent (Gemini)
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

### ext_proc reporting mechanics (config only, no code coupling)

The mechanic everything rides on: ext_proc attaches `metadata_context` to **every**
ProcessingRequest — headers, each body chunk, and trailers — snapshotted from the
downstream StreamInfo **when that message is built** (`buildHeaderRequest` /
`setupBodyChunk` / trailers each call `addDynamicMetadata`). It is not a one-time
handshake.

Request path sequencing: because `ai_protocol_manager` pins request headers until
the body is offloaded and classified, `envoy.aigw.request` (model, provider) is
already in dynamic metadata when ext_proc's `decodeHeaders` fires — **the server
receives body-derived facts in the `request_headers` message** and can
authorize/deny/inject on it alone. `request_body_mode: NONE` is therefore the
gateway default. (If body chunks are requested, they arrive with the replayed 64KiB
framing, not the client's original chunk boundaries.)

Response path (SSE): upstream filters run before downstream filters on every encode
frame, so usage written by the upstream instance on the final data frame is inside
the `metadata_context` of ext_proc's final `response_body` message
(`end_of_stream=true`). **The final response_body message is the usage event.**
Consequence: with `response_body_mode: NONE` the server's last message is
`response_headers`, which predates the usage — the reporting role **requires**
`response_body_mode: STREAMED`. Since non-observability STREAMED holds each chunk
for a server ack (adds RTT to the token stream), reporting runs with
`observability_mode: true` (fire-and-forget).

`observability_mode` is filter-level, so decision-making and reporting split into
two ext_proc instances:

```yaml
# 1. Policy (sync, request side only)
- name: envoy.filters.http.ext_proc          # "aigw-policy"
  processing_mode:
    request_header_mode: SEND                 # metadata_context carries envoy.aigw.request
    request_body_mode: NONE
    response_header_mode: SKIP
    response_body_mode: NONE
  metadata_options:
    forwarding_namespaces:
      untyped: [envoy.aigw.request]

# 2. Reporting (async, response side only)
- name: envoy.filters.http.ext_proc          # "aigw-usage-report"
  observability_mode: true                    # never blocks the token stream
  processing_mode:
    request_header_mode: SKIP
    response_header_mode: SEND                # optional: status / TTFT marker
    response_body_mode: STREAMED              # final chunk = the usage event
  metadata_options:
    forwarding_namespaces:
      untyped: [envoy.aigw.request, envoy.aigw.token_usage]
```

Caveats:

- STREAMED means one gRPC message per SSE frame (body bytes included). If the
  server needs only the final number, access logs (gRPC ALS / OTel) reading the
  same namespace at stream end are the cheaper channel; ext_proc earns its place
  when the server must also act.
- PROGRESSIVE + non-observability STREAMED is the mid-stream enforcement combo
  (server watches running `output_tokens` per chunk and can stop the stream), at
  the cost of per-chunk latency — a deliberate trade, not a default.
- On client disconnect mid-SSE the ext_proc stream dies with the client; the
  phase-3 `complete: false` partial flush + access log is the loss-proof billing
  path.

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

## 6. Wire-format extraction spec (verified against official docs, 2026-08-08)

Sources: OpenAI OpenAPI spec (github.com/openai/openai-openapi), Anthropic API
reference (platform.claude.com), Google discovery documents (generativelanguage +
aiplatform). Normalized struct (all fields optional): `input_tokens`,
`output_tokens`, `total_tokens`, `cached_input_tokens`,
`cache_creation_input_tokens`, `reasoning_tokens`, `model`, `provider`.

### Model id

| | Request | Streaming selector | Response-reported model |
|---|---|---|---|
| OpenAI Chat Completions | body root `model` (required) | body `stream: true`; usage needs `stream_options.include_usage` | root `model`, and on every chunk |
| OpenAI Responses | body root `model` (optional — stored prompts / `previous_response_id`) | body `stream: true` | `response.model` in every lifecycle event |
| Anthropic Messages | body root `model` (required) | body `stream: true` | root `model`; streaming: only `message_start.message.model` |
| Gemini | **URL path**: `/v1beta/models/{model}:generateContent` (split last segment on `:`); Vertex: `/v1/projects/.../models/{m}:...` | **URL verb** `:streamGenerateContent`; `?alt=sse` selects SSE framing | `modelVersion` (optional per chunk) |

Gemini corollaries: Vertex tuned-model endpoints
(`/v1/.../endpoints/{id}:generateContent`) carry no model in the path — fall back
to response `modelVersion`. `?key=` API keys ride the query string — scrub before
logging paths.

### Token usage

| | OpenAI Chat Completions | OpenAI Responses | Anthropic Messages | Gemini generateContent |
|---|---|---|---|---|
| input | `usage.prompt_tokens` | `usage.input_tokens` | `usage.input_tokens` | `usageMetadata.promptTokenCount` |
| output | `usage.completion_tokens` | `usage.output_tokens` | `usage.output_tokens` | `usageMetadata.candidatesTokenCount` |
| total | `usage.total_tokens` | `usage.total_tokens` | — (compute input+output) | `usageMetadata.totalTokenCount` |
| cache read | `usage.prompt_tokens_details.cached_tokens` | `usage.input_tokens_details.cached_tokens` | `usage.cache_read_input_tokens` | `usageMetadata.cachedContentTokenCount` (**subset of promptTokenCount — never add**) |
| cache write | `usage.prompt_tokens_details.cache_write_tokens` | `usage.input_tokens_details.cache_write_tokens` | `usage.cache_creation_input_tokens` (+ TTL split in `usage.cache_creation.*`) | — (billed via cachedContents API) |
| reasoning | `usage.completion_tokens_details.reasoning_tokens` | `usage.output_tokens_details.reasoning_tokens` | `usage.output_tokens_details.thinking_tokens` | `usageMetadata.thoughtsTokenCount` |

Every `usage` object and every details sub-object is optional in practice, even
where schemas mark them required.

### Streaming semantics (per dialect — do not share heuristics)

| | Framing | Usage-bearing event(s) | Semantics | Terminator |
|---|---|---|---|---|
| Chat Completions | data-only SSE | one chunk with `choices: []` right before `[DONE]` — **only if** client sent `stream_options.include_usage`; all other chunks `usage: null` | final-only | `data: [DONE]` |
| Responses | named-event SSE | terminal lifecycle event: `response.completed` **or** `response.failed` / `response.incomplete` — read usage from all three | final-only, unconditional | terminal lifecycle event; no `[DONE]` per official examples |
| Anthropic | named-event SSE | `message_start` → `message.usage` (input + cache, initial output≈1-3); `message_delta` → **cumulative** usage (simple: only `output_tokens`; newer: also input + cache) | cumulative; last `message_delta` wins; tolerate absent `usage` | `event: message_stop` |
| Gemini `?alt=sse` | data-only SSE | any chunk may carry `usageMetadata`; presence per chunk not guaranteed | cumulative snapshots; last-seen wins | none — `finishReason: "STOP"` + stream close |
| Gemini default | streamed JSON **array** (`[{...},{...}]`) | same as above, per array element | last element wins (JSON handler root-array path) | array close |

**One merge rule covers all five shapes:** every event/body/element yields a
partial usage; the accumulator merges field-wise with later-non-null-wins. At
finalize: `total_tokens = provider total, else input + output`. Terminators only
mark parsing complete; `data: [DONE]` is not a parse error.

### Detection and misclassification guards

- generativelanguage also hosts an **OpenAI-compat endpoint**
  (`/v1beta/openai/chat/completions`) — OpenAI extraction rules despite the Google
  host; and the newer **Interactions API** (`/v1beta/interactions`: model in body,
  named events, explicit `[DONE]`) is a different surface — detection keys on
  path, not host alone. Interactions support is future work.
- Absent usage is a normal outcome (`token_usage_missing`): Chat Completions
  streams without `include_usage`, client cancels before the usage chunk, optional
  `usage` in non-streaming schemas. A transcoding-phase option is to inject
  `stream_options.include_usage: true` on the request path to guarantee usage.
- Ignore unknown fields and unknown SSE event types everywhere (OpenAI
  `obfuscation` padding fields, Anthropic `ping`/in-stream `error` events, future
  event types).

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
