# AI transcoding filter

Status: design proposal, not implemented. Branch `ai-transcoder-filter`, based on upstream/main
`a712680a07`, stacked on the declarative transcoding engine in
[#47560](https://github.com/envoyproxy/envoy/pull/47560).

## 1. Summary

A client speaks one LLM protocol, and the upstream speaks another. The
`envoy.http.ai_filters.transcoder` AI filter bridges the two in two legs. The **client's bytes
stay the source of truth** until the one place the request leaves for a provider.

* **Downstream `internal` leg.** It derives an internal representation (IR) of the request as
  a *read-only view* and publishes it in filter state. Routing, policy, and observability read
  that view, whatever protocol the client spoke. The request body is not changed and not
  re-serialized: the client's bytes are forwarded as received.
* **Upstream `upstream` leg.** It runs per attempt, on the cluster the router picked. It parses
  the client's bytes and converts them to the provider's format, **from the client's format,
  not from the IR**. When both sides speak the same protocol, it passes the body through and
  changes only the envelope. It rewrites the URL and serializes once. On the way back, it
  converts the provider's response to the client's protocol.

The IR is OpenAI Chat Completions, matching `TranscodingEngine::kIrProtocol` in #47560. The
first targets are Vertex AI `generateContent` (Gemini) and `rawPredict` (Anthropic), with
OpenAI clients converted and Anthropic clients passed through to Claude.

## 2. Topology

```
 client: OpenAI (/v1/chat/completions) or Anthropic (/v1/messages)
     │
     ▼
┌─ HCM ──────────────────────────────────────────────────────────────────────┐
│ ai_protocol_manager (downstream): parse + validate as the route's protocol │
│   AI chain: transcoder{internal} ─► IR view ─► filter state                │
│             request_info                   envoy.ai.request_ir             │
│   body replayed as received: no re-serialization                           │
│ set_filter_state: IR model ─► envoy.ai.routing.model, clear_route_cache    │
│ router: routes on the model; owns retries and fallback                     │
└──────────────┬─────────────────────────────────────┬───────────────────────┘
               ▼ cluster vertex_anthropic            ▼ cluster vertex_gemini
┌─ upstream filters ─────────────────────┐ ┌─ upstream filters ─────────────────┐
│ ai_protocol_manager (upstream)         │ │ ai_protocol_manager (upstream)     │
│   parse the client's bytes             │ │   parse the client's bytes         │
│   transcoder{upstream: ANTHROPIC,      │ │   transcoder{upstream: GEMINI,     │
│     vertex_ai}                         │ │     vertex_ai}                     │
│   OpenAI → Anthropic, or pass through  │ │   OpenAI → Gemini                  │
│   :path → …/anthropic/models/{m}:…     │ │   :path → …/google/models/{m}:…    │
│ credential_injector, upstream_codec    │ │ credential_injector, upstream_codec│
└────────────────────────────────────────┘ └────────────────────────────────────┘
    responses: provider → client protocol, once, in the upstream leg
```

| Stage | Request | Response |
|---|---|---|
| Downstream APM, `internal` leg | derives the IR view into filter state; the body is forwarded as received | none |
| Router | routes on the IR's model; owns retries and fallback | forwards the winning attempt |
| Upstream APM, `upstream` leg | parses the client's bytes; converts client → provider, or passes the body through; applies the envelope and `:path` | converts provider → client, or passes it through |

## 3. Source of truth: the client's bytes

Decided 2026-09-23. The upstream converts **from the client's format**, and the IR is a
read-only view. Converting from the IR held in filter state was considered and rejected.

The reason is data loss. Loss happens at every conversion, and nothing after the IR can
restore a field the IR dropped. #47560's to-IR rules drop data today, even when the client and
the provider speak the same protocol:

* **Anthropic → IR → Anthropic.**
  * `tool_choice.disable_parallel_tool_use` is dropped going in.
  * The rules going out always delete a tool's `type`, so built-in server tools such as web
    search arrive as broken custom tools.
* **Gemini → IR → Gemini.**
  * `generationConfig` keeps four fields. `topK`, `seed`, `thinkingConfig`, and
    `responseSchema`/`responseMimeType` (structured output) are dropped.
  * `thoughtSignature` beside a text part is discarded.
  * Image, function-call, and function-response parts are rejected.

| | Upstream converts from the IR | Upstream converts from the client format |
|---|---|---|
| Same protocol on both ends | two lossy conversions | body passed through with only the envelope changed: lossless |
| Different protocols | whatever the IR dropped stays dropped | one conversion; direct pair rules can carry fields the IR lacks (§9) |
| OpenAI client | same request | same request |
| Downstream edits | carried in the IR | explicit channels (§4.1, §4.3) |
| Machinery | pointers into another buffer, plus a body hash to trust them | parse the bytes actually received |
| To remove the loss | make the IR lossless, with every rule invertible | nothing; the view may stay lossy |

Consequences:

* The IR never has to be lossless, because nothing is sent from it.
* Every attempt converts from the same client bytes to its own target, so retries and fallback
  never compound loss.
* A body-modifying filter between the two APMs is honored automatically.

## 4. Request path

### 4.1 Downstream: `internal` leg

1. **Parse.** The APM holds the headers, then parses and validates the body as the
   route-declared protocol P. This is today's behavior.
2. **Derive the view.**
   * The leg reads `model` and `stream` from where P keeps them. Gemini clients keep both in
     the path (phase 4).
   * It then **copies** the document and runs `engine.transcodeToIr(P, copy)`. The copy is
     cheap: offloaded strings are `ExternalRef` nodes, not bytes.
3. **Publish.** The leg writes `AiRequestIr` under `envoy.ai.request_ir`, once, with
   `LifeSpan::FilterChain`. An internal redirect rebuilds the chain, so a stale view never
   survives it. The object has two parts:
   * **Field support**, for formatters and matchers. It exposes `model`, `stream`, and
     `client_protocol`, so `%FILTER_STATE(envoy.ai.request_ir:FIELD:model)%` works in
     set_filter_state and access logs.
   * **`document()`**, the IR DOM for AI filters and C++ HTTP filters. Its `ExternalRef`s index
     the downstream body, so outside that buffer readers see sizes, not bytes.

   If the conversion fails, for content the engine cannot express, the record still carries
   the fields but has no `document()`. The request is not failed; the view is advisory. This is
   counted as `ir_incomplete`.
4. **Forward as received.** `json()` is untouched, since only the copy was converted. Nothing
   marked the document modified, so the sink replays the stored body with
   `BufferManager::replay(0, length)` instead of serializing it (C1). `content-length` is
   unchanged.
5. **Edits.** A filter that must change the request edits the client-format document through
   `mutableJson()`, using the dialect adapters to find fields. The sink then serializes it,
   still in P, so the upstream still receives P.
   * Put editing filters before `internal` so the view reflects their edits.
   * Model changes use the override (§4.3) instead.

### 4.2 Upstream: `upstream` leg

On each attempt:

1. **Engage and parse.** The upstream APM runs unchanged.
   * It engages when the route declares `request` under its filter name. Upstream filters
     resolve per-route config through the downstream `StreamInfo`'s route
     (`filter_manager.cc:322-348`).
   * Naming the upstream APM `envoy.filters.http.ai_protocol_manager` lets one route
     declaration serve both chains.
   * It parses and validates the received bytes as P.
2. **Resolve the model.** The `envoy.ai.upstream_model` filter state wins when present (§4.3);
   otherwise the model comes from the document.
3. **Convert.** The target protocol T comes from config.
   * T == P: no conversion.
   * T ≠ P:
     1. `engine.transcodeToIr(P)`.
     2. Target preparation (§9).
     3. `engine.transcodeFromIr(T)`, which applies the rules and then validates against T's
        `PayloadSchema`.
   * Where P is not the IR, direct pair rules carry fields that both P and T model but the IR
     does not (phase 4).
   * A pair whose response conversion is not implemented fails **before anything is sent**,
     with a 501, rather than returning a response the client cannot read.
4. **Apply the envelope** (§4.4). This runs after validation, because the envelope is not part
   of the dialect schema: Anthropic's schema requires `model` and rejects `anthropic_version`.
5. **Stage header edits** (§4.5).

The sink serializes only if something changed. For example, an OpenAI client sent to an
OpenAI-native endpoint on the same path is forwarded byte for byte.

### 4.3 Model override

`envoy.ai.upstream_model` is a string filter-state object, compatible with the `envoy.string`
factory, so set_filter_state, ext_proc, and Lua can write it.

* When present, it replaces the model in the URL or the body of the provider request. The
  client document itself is never rewritten.
* Routing writes it to resolve aliases. The model-fallback work writes it per attempt.
* Hedged attempts read one shared value. A per-attempt value under hedging belongs to the
  fallback design.

### 4.4 Endpoint bindings

The *protocol* fixes the body. The *endpoint* fixes the URL, plus any envelope quirks of the
place that serves it.

| Target | Path (`stream: false` / `true`) | Envelope |
|---|---|---|
| Gemini on Vertex AI | `/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent` / `…:streamGenerateContent?alt=sse` | Remove `model`, `stream`, and `stream_options`. `alt=sse` makes Vertex stream SSE rather than a JSON array. |
| Anthropic on Vertex AI | `…/publishers/anthropic/models/{model}:rawPredict` / `…:streamRawPredict` | Remove `model`, keep `stream`, set `anthropic_version: "vertex-2023-10-16"`. |
| *later:* OpenAI native | `/v1/chat/completions` | none |
| *later:* Anthropic native | `/v1/messages` | header `anthropic-version: 2023-06-01` |
| *later:* Gemini API | `/v1beta/models/{model}:generateContent` / `…:streamGenerateContent?alt=sse` | as Vertex |

* **Validation.** Model names reach the URL, so they must match `^[A-Za-z0-9._@-]{1,128}$`.
  That covers `claude-sonnet-4-5@20250929` and `gemini-2.5-flash`; anything else gets a 400. No
  body string is spliced into `:path` unchecked.
* **Out of scope.** Host selection belongs to the route or cluster: `:authority` and SNI come
  from `auto_host_rewrite` on a `LOGICAL_DNS` cluster. The credential comes from an upstream
  `credential_injector`.

### 4.5 Headers: ownership, retries, hedging

* **Owned headers.** The leg owns `:path`, `content-length`, and `accept-encoding`, plus the
  per-endpoint headers (`anthropic-version`). It sets or removes each one on every attempt.
  * Upstream filters share the router's header map across retries and hedges
    (`upstream_request.cc:487` passes `*parent_.downstreamHeaders()`). So an attempt must never
    inherit a header set by an earlier attempt that went to another provider.
  * `accept-encoding` is removed. Conversion needs an identity response, and the APM skips
    encoded bodies (`filter.cc:529`). The OpenAI Python SDK sends `gzip, deflate` by default.
* **Staged, not direct.** AI filters do not get a mutable header map. They record edits on the
  request (`AiRequest::headerEdits()`), and the manager applies them just before the first
  injection releases the held headers.
  * Hedged attempts share one map. Applying edits mid-chain would let attempt B rewrite `:path`
    after attempt A's transcoder ran but before A's codec encoded it.
  * The sink's `setContentLength` (`request_filter_manager.cc:170`) moves into the same staged
    edits.
* **Path rewrite versus routing.** An `upstream` leg placed in the downstream chain (§6) rewrites
  `:path` there, so a later `clearRouteCache()` would re-resolve on the provider path.
  Route-refreshing filters must run before it.

## 5. Response path

The `upstream` leg converts the provider's response into the client's protocol, once:

* T == P: the leg splices itself out and the response passes through untouched. Anthropic
  thinking blocks, signatures, and citations reach an Anthropic client intact.
* P is OpenAI (v1): provider → OpenAI codecs, described below.
* Any other P (phase 4): T → IR → P.

Downstream response consumers see the client's protocol, which is what the route declares, so
token-usage extraction in the downstream APM works unchanged. The `internal` leg does no
response work.

Response AI filters run in reverse order. The `upstream` leg is last on the request side, so it
is first on the response side.

### 5.1 Unary JSON

`encodeUnary` receives flattened leaf batches.

1. The leg accumulates them up to `max_response_bytes` (default 4 MiB).
2. It rebuilds the DOM with `unflatten()` and maps it to `chat.completion`.
3. It re-emits the result with `flatten()`, in the document order `FlatteningJsonSerializer`
   requires, then sends an empty batch to end the stream.

| OpenAI field | from Anthropic `message` | from Gemini `GenerateContentResponse` |
|---|---|---|
| `id` | `id` | `responseId` |
| `created` | `stream_info.startTime()`, deterministic for tests | same |
| `model` | `model` | `modelVersion`, else the request's model |
| `choices[0].message.content` | the `text` blocks, joined | the non-`thought` `parts[].text`, joined |
| `choices[0].message.tool_calls` | `tool_use` → `{id, type: function, function: {name, arguments: dump(input)}}` | `functionCall` → the same, with `id` = `call_<n>` when Gemini sends none |
| `finish_reason` | §5.3 | §5.3 |
| `usage` | §5.3 | §5.3 |

### 5.2 SSE

`encodeSSE` is one coroutine per response. Its locals hold the stream state: whether the role
was emitted, the tool index map, the model and id, and whether usage was requested.

**Anthropic → OpenAI chunks**

| Anthropic event | Emitted |
|---|---|
| `message_start` | `delta: {role: "assistant", content: ""}`; captures `id`, `model`, and input usage |
| `content_block_delta` / `text_delta` | `delta: {content}` |
| `content_block_start` / `tool_use` | `delta: {tool_calls: [{index: k, id, type: "function", function: {name, arguments: ""}}]}` |
| `content_block_delta` / `input_json_delta` | `delta: {tool_calls: [{index: k, function: {arguments: partial_json}}]}` |
| `thinking_delta`, `signature_delta`, `content_block_stop`, `ping` | dropped |
| `message_delta` | `delta: {}, finish_reason`; captures output usage |
| `message_stop` | the usage chunk (§5.3), then `data: [DONE]` |
| `error` | `data: {"error": {"message", "type"}}`, then the stream ends |

**Gemini (`alt=sse`) → OpenAI chunks.** Every Gemini event is a whole `GenerateContentResponse`.
The first one also emits the role chunk.

| Gemini event content | Emitted |
|---|---|
| `parts[].text`, non-thought parts only | `delta: {content}` |
| `parts[].functionCall` (arrives whole) | a `tool_calls` delta carrying the complete `arguments` |
| `finishReason` | `finish_reason` |
| `usageMetadata` | usage (§5.3) |
| end of stream | `data: [DONE]` |

Unrecognized frames are dropped and counted; they never fail the stream. A frame that is not
JSON is forwarded as an OpenAI error chunk, and the stream ends.

### 5.3 Finish reasons and usage

| OpenAI `finish_reason` | Anthropic `stop_reason` | Gemini `finishReason` |
|---|---|---|
| `stop` | `end_turn`, `stop_sequence`, `pause_turn` | `STOP`, `OTHER`, `FINISH_REASON_UNSPECIFIED`, `MALFORMED_FUNCTION_CALL` (counted) |
| `length` | `max_tokens`, `model_context_window_exceeded` | `MAX_TOKENS` |
| `tool_calls` | `tool_use` | `STOP` when a `functionCall` was emitted |
| `content_filter` | `refusal` | `SAFETY`, `RECITATION`, `BLOCKLIST`, `PROHIBITED_CONTENT`, `SPII`, `IMAGE_SAFETY` |

Usage follows the canonical inclusive contract in `token_usage.h`:

| OpenAI `usage` | from Anthropic | from Gemini |
|---|---|---|
| `prompt_tokens` | `input_tokens + cache_read_input_tokens + cache_creation_input_tokens` | `promptTokenCount + toolUsePromptTokenCount` |
| `completion_tokens` | `output_tokens` | `candidatesTokenCount + thoughtsTokenCount` |
| `total_tokens` | the sum | `totalTokenCount` |
| `prompt_tokens_details.cached_tokens` | `cache_read_input_tokens` | `cachedContentTokenCount` |
| `completion_tokens_details.reasoning_tokens` | none | `thoughtsTokenCount` |

**Usage on a converted stream.** Exactly one chunk carries `usage`:

* when the client set `stream_options.include_usage`, the OpenAI-standard trailing chunk with
  `choices: []`;
* otherwise the `finish_reason` chunk.

The OpenAI SDKs treat `usage` as optional on every chunk, so the extra field is harmless. The
OpenAI adapter's last-wins merge reads it from any chunk, so token accounting always gets a
count.

### 5.4 Errors

* The response chain runs only on 2xx `application/json` or `text/event-stream` bodies with
  identity encoding (`filter.cc:506-534`). A provider error therefore passes through in the
  provider's own shape.
* Vertex `{"error": {"code", "message", "status"}}` and Anthropic
  `{"type": "error", "error": {"type", "message"}}` both carry `error.message`, which the
  OpenAI SDKs surface.
* Proper mapping needs the chain to run on non-2xx JSON (C5, phase 5).
* In-stream errors are mapped as described in §5.2.

## 6. Placements

The same proto works in either chain. The `internal` leg is optional everywhere, because it only
feeds readers.

| Deployment | Downstream AI chain | Upstream AI chain | Notes |
|---|---|---|---|
| **Two-stage** (model routing, fallback) | `internal`, readers | `upstream` per cluster | each attempt converts from the same client bytes |
| **Downstream only** (one target per route) | readers, then `upstream` last | none | converts in the downstream chain; route-refreshing filters run before it (§4.5) |
| **Upstream only** | none | `upstream` | no IR view for routing |

An `internal` leg in an upstream chain has no reader. It is counted as `misplaced` and does
nothing else.

## 7. API

```proto
// [#extension: envoy.http.ai_filters.transcoder]
package envoy.extensions.http.ai_filters.transcoder.v3;

// Bridges LLM protocols. The request is converted from the client's format directly, never
// from the internal representation (IR), which is a read-only view.
message Transcoder {
  oneof leg {
    option (validate.required) = true;

    // Publishes the request's IR view, currently OpenAI Chat Completions, under the
    // ``envoy.ai.request_ir`` filter state key for routing and policy. The request is not
    // changed.
    Internal internal = 1;

    // Converts the request from the client's protocol to the one the upstream serves,
    // rewriting the URL, and converts the response back. A request whose protocol already
    // matches passes through with only the endpoint envelope changed.
    Upstream upstream = 2;
  }
}

message Internal {
}

message Upstream {
  // The protocol the upstream serves.
  type.ai.v3.LLMProtocol llm_protocol = 1
      [(validate.rules).enum = {defined_only: true not_in: 0}];

  // Where it is served, which determines the request path and envelope.
  oneof endpoint {
    option (validate.required) = true;

    VertexAi vertex_ai = 2;
  }

  // Sent to an upstream that requires an output cap (Anthropic Messages) when the request sets
  // none. Defaults to 4096.
  google.protobuf.UInt32Value default_max_output_tokens = 3 [(validate.rules).uint32 = {gt: 0}];

  // Largest unary response held for conversion; a larger one fails with a 502. Defaults to 4MiB.
  google.protobuf.UInt32Value max_response_bytes = 4 [(validate.rules).uint32 = {gt: 0}];
}

// Vertex AI publisher-model endpoints. The publisher follows from ``llm_protocol``: ``google``
// for Gemini, ``anthropic`` for Anthropic Messages.
message VertexAi {
  string project = 1 [(validate.rules).string = {min_len: 1}];

  // A region such as ``us-east5``, or ``global``.
  string location = 2 [(validate.rules).string = {min_len: 1}];
}
```

The code lives in `source/extensions/http/ai_filters/transcoder/`, following request_info. It
contains `config`, `filter`, `endpoint_binding`, and `response/{anthropic,gemini}_to_openai`.

## 8. Core changes (AI Protocol Manager)

Each change is small and testable with a fake AI filter.

| # | Change | Where |
|---|---|---|
| C1 | The sink replays the stored body when the document was not modified, and serializes it otherwise. `AiRequest::json()` becomes const-only, and `mutableJson()` marks the document modified. This covers penguingao's "condition the serialization" TODO at `request_filter_manager.cc:173`. | `ai_request.h`, `request_filter_manager.cc` |
| C2 | Staged header edits (`set`, `remove`, `:path`), applied by the bridge just before the first injection. The sink's `setContentLength` moves here. | `ai_request.h`, `filter_chain_bridge.cc`, `request_filter_manager.cc` |
| C3 | `flatten()` / `unflatten()` between `FlattenJsonField` batches and a DOM | `flattening_json_codec.h` |
| C4 | The `AiRequestIr` filter-state type: a shared contract, written by the transcoder and read by other extensions | new `ai_request_ir.h` beside `ai_filter.h` |
| C5 | *Phase 2:* `AiRequest::readExternal(node, max_bytes)`, a bounded async read of an offloaded string for mappings that need its bytes. The case is OpenAI `arguments`, a JSON *string*, which becomes an Anthropic `input` or Gemini `args` *object*; over 1 KiB it is an `ExternalRef` by default. | `ai_request.h`, `request_filter_manager.cc` |
| C6 | *Phase 5:* the response chain on non-2xx JSON, and a token-usage protocol for an upstream-placed extractor (it sees the provider's protocol, not the route's) | `filter.cc` |

The upstream APM's decode path needs no change. It parses what it receives, just as it does
today.

## 9. Engine gaps (#47560) and where they are filled

The engine converts request bodies only. It leaves the envelope to the calling filter: its
Gemini pack keeps `model` and `stream` in the body, with a TODO to move them into `:path`.
Because the upstream converts from the client's format, the to-IR losses in §3 now affect only
cross-protocol paths from non-OpenAI clients.

| Gap | Effect today | Fix | Phase |
|---|---|---|---|
| OpenAI-only fields: `stream_options`, `n`, `user`, `seed`, `logit_bias`, `logprobs`, `presence_penalty`, `frequency_penalty`, `response_format`, `parallel_tool_calls`, `service_tier` | The Anthropic root schema rejects them, so the gateway returns 400. Gemini's schema admits them, but **Vertex rejects** them. | Map where an equivalent exists: `user` → `metadata.user_id`; `seed`, penalties, and `n` → `generationConfig.*`; `response_format` → `responseMimeType`/`responseJsonSchema`; `parallel_tool_calls: false` → `disable_parallel_tool_use`. Then prune to the target schema's declared fields. `n > 1` to Anthropic → 400. | 1 |
| Text-part arrays (`content: [{type: "text", text}]`) to Gemini | `parts[].type` fails Gemini's Part schema | drop `type` on text parts | 1 |
| `max_tokens` default | compiled in at 4096 | the filter sets it from config before `transcodeFromIr` | 1 (filter) |
| `tools` → Gemini `tools[{functionDeclarations}]`, with `parameters` → `parametersJsonSchema` | missing; Vertex rejects the OpenAI shape | new rules | 2 |
| Assistant `tool_calls` → Anthropic `tool_use` / Gemini `functionCall`; `role: tool` → `tool_result` / `functionResponse` | `tool_call_id` rides through and is rejected; `arguments` stays a string | Needs an id → name lookup, since Gemini's `functionResponse.name` is not on OpenAI tool messages. Also needs C5. Parts are imperative: a `TranscodeRule::custom()` hook. | 2 |
| `image_url` → Anthropic `image` / Gemini `inlineData`/`fileData` | passes through and is rejected | data-URL split plus the URL forms | 2 |
| Direct pair rules for fields the IR lacks: Anthropic `thinking.budget_tokens` ↔ Gemini `thinkingConfig.thinkingBudget`, `top_k` ↔ `topK` | lost in P → IR → T | rules keyed by (P, T), applied beside the engine | 4 |
| Response conversion | none in the engine | codecs in the extension (§5), movable into the engine later | 1 |

## 10. Failure semantics, limits, security

* **Downstream view.** Failing to derive the IR view never fails a request (§4.1).
* **Request conversion.** An engine error, a target-schema violation, an unsafe model name,
  `n > 1` to Anthropic, or oversized arguments each end in a local reply `400` with details
  `ai_transcoder_request_invalid`.
  * An unsupported protocol pair ends in a `501`, sent before anything leaves.
  * In an upstream chain, a local reply goes through the router. It is terminal and not
    retried. Dropping a target before the attempt is model routing's job.
* **Response conversion.** An over-limit unary body, malformed JSON, or a missing required field
  produces a 502 through `onEncodeComplete()` when headers have not been sent. Mid-stream SSE
  failures emit an error chunk and end the stream; they never emit a partial chunk.
* **Limits.** `max_response_bytes` bounds unary accumulation. SSE frames are bounded by the
  existing decoder limits. `readExternal` takes an explicit cap.
* **Security.**
  * Model names are validated before they reach `:path`.
  * Credentials stay with `credential_injector`, which overwrites the client's `authorization`.
  * The owned-header list (§4.5) keeps one attempt's headers out of another provider's request.

## 11. Observability

* **Stats** go under `ai_protocol_manager.transcoder.`:
  * `ir_published`, `ir_incomplete`, `misplaced`;
  * `request_converted`, `request_passthrough` (same protocol), `request_rejected`,
    `unsupported_pair`;
  * `response_converted`, `response_passthrough`, `response_failed`, `sse_event_dropped`.
* **Formatters.**
  * `%FILTER_STATE(envoy.ai.request_ir:FIELD:model)%`, likewise `stream` and `client_protocol`.
  * `%REQ(:PATH)%` in the HCM access log shows the provider path after the upstream rewrite,
    because upstream filters edit the router's header map.
* **Logging.** Debug logs are under the `ai_protocol_manager` logger.

## 12. End-to-end integration

A demo branch, `ai-transcoder-vertex-demo`, holds `experiment/ai-transcoder-vertex/`: the Envoy
configs, run and request scripts, a mock server, a README, and `captured/`. Commits there use
the `experiment:` prefix. There are two modes:

* **`vertex`**: a real Vertex AI project. It needs `GCP_PROJECT` and an OAuth access token.
  `run.sh` refreshes the token every 30 minutes with `gcloud auth print-access-token`, writing
  it to an SDS file that Envoy watches through `watched_directory`.
* **`mock`**: the same Envoy config, with the clusters pointed at `mock_vertex.py` on
  `127.0.0.1:10001`. The mock serves canned `generateContent`, `streamGenerateContent`,
  `rawPredict`, and `streamRawPredict` JSON and SSE. It also records each request body so the
  passthrough case (E5) can be diffed.

### 12.1 `envoy.yaml` (vertex mode)

```yaml
admin:
  address: {socket_address: {address: 127.0.0.1, port_value: 9901}}

static_resources:
  listeners:
  - name: ai_gateway
    address: {socket_address: {address: 127.0.0.1, port_value: 10000}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ai_gateway
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
              log_format:
                json_format:
                  route: "%ROUTE_NAME%"
                  cluster: "%UPSTREAM_CLUSTER%"
                  upstream_path: "%REQ(:PATH)%"
                  status: "%RESPONSE_CODE%"
                  client_protocol: "%FILTER_STATE(envoy.ai.request_ir:FIELD:client_protocol)%"
                  model: "%FILTER_STATE(envoy.ai.request_ir:FIELD:model)%"
                  request_info: "%TYPED_CEL(metadata.typed_filter_metadata['envoy.ai.request_info'])%"
                  token_usage: "%TYPED_CEL(metadata.typed_filter_metadata['envoy.ai.token_usage'])%"
          route_config:
            name: ai_routes
            virtual_hosts:
            - name: ai
              domains: ["*"]
              routes:
              # OpenAI clients, converted to either provider.
              - name: gemini
                match:
                  path: /v1/chat/completions
                  filter_state:
                  - key: envoy.ai.routing.model
                    string_match: {prefix: gemini-}
                route: {cluster: vertex_gemini, auto_host_rewrite: true, timeout: 300s}
                typed_per_filter_config: &openai_endpoint
                  envoy.filters.http.ai_protocol_manager:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
                    request: {llm_protocol: OPENAI_CHAT_COMPLETIONS}
              - name: claude
                match:
                  path: /v1/chat/completions
                  filter_state:
                  - key: envoy.ai.routing.model
                    string_match: {prefix: claude-}
                route: {cluster: vertex_anthropic, auto_host_rewrite: true, timeout: 300s}
                typed_per_filter_config: *openai_endpoint
              # Matched before the model is known: the AI chain runs on this route, then
              # set_filter_state re-resolves. A model no route claims ends here.
              - name: unrouted_chat
                match: {path: /v1/chat/completions}
                direct_response:
                  status: 404
                  body: {inline_string: '{"error":{"message":"model not served","type":"invalid_request_error"}}'}
                typed_per_filter_config: *openai_endpoint
              # Anthropic clients: the same protocol as Claude on Vertex, so the body passes
              # through with only the Vertex envelope changed.
              - name: claude_messages
                match:
                  path: /v1/messages
                  filter_state:
                  - key: envoy.ai.routing.model
                    string_match: {prefix: claude-}
                route: {cluster: vertex_anthropic, auto_host_rewrite: true, timeout: 300s}
                typed_per_filter_config: &anthropic_endpoint
                  envoy.filters.http.ai_protocol_manager:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
                    request: {llm_protocol: ANTHROPIC_MESSAGES}
              - name: unrouted_messages
                match: {path: /v1/messages}
                direct_response:
                  status: 404
                  body: {inline_string: '{"type":"error","error":{"type":"not_found_error","message":"model not served"}}'}
                typed_per_filter_config: *anthropic_endpoint
          http_filters:
          - name: envoy.filters.http.ai_protocol_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
              request_handling: {}
              # The response arrives downstream in the client's protocol.
              response_handling: {token_usage: {}}
              filters:
              - name: envoy.http.ai_filters.transcoder
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
                  internal: {}
              - name: envoy.http.ai_filters.request_info
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.http.ai_filters.request_info.v3.RequestInfo
          # Runs once the APM releases the headers, after the IR view is published.
          - name: envoy.filters.http.set_filter_state
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
              on_request_headers:
              - object_key: envoy.ai.routing.model
                factory_key: envoy.string
                format_string:
                  text_format_source:
                    inline_string: "%FILTER_STATE(envoy.ai.request_ir:FIELD:model)%"
              clear_route_cache: true
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: vertex_gemini
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    connect_timeout: 5s
    load_assignment:
      cluster_name: vertex_gemini
      endpoints:
      - lb_endpoints:
        - endpoint: {address: {socket_address: {address: aiplatform.googleapis.com, port_value: 443}}}
    transport_socket: &vertex_tls
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: aiplatform.googleapis.com
        common_tls_context:
          alpn_protocols: [h2]
          validation_context:
            trusted_ca: {filename: /etc/ssl/cert.pem}
            match_typed_subject_alt_names:
            - san_type: DNS
              matcher: {exact: aiplatform.googleapis.com}
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config: {http2_protocol_options: {}}
        http_filters:
        - name: envoy.filters.http.ai_protocol_manager
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
            request_handling: {}
            filters:
            - name: envoy.http.ai_filters.transcoder
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
                upstream:
                  llm_protocol: GEMINI_GENERATE_CONTENT
                  vertex_ai: {project: GCP_PROJECT, location: global}
        - &vertex_credential
          name: envoy.filters.http.credential_injector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.credential_injector.v3.CredentialInjector
            overwrite: true
            credential:
              name: envoy.http.injected_credentials.generic
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.injected_credentials.generic.v3.Generic
                credential:
                  name: vertex_access_token
                  sds_config:
                    path_config_source:
                      path: RUN_DIR/vertex_token.yaml
                      watched_directory: {path: RUN_DIR}
                header_value_prefix: "Bearer "
        - &upstream_codec
          name: envoy.filters.http.upstream_codec
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec

  - name: vertex_anthropic
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    connect_timeout: 5s
    load_assignment:
      cluster_name: vertex_anthropic
      endpoints:
      - lb_endpoints:
        - endpoint: {address: {socket_address: {address: aiplatform.googleapis.com, port_value: 443}}}
    transport_socket: *vertex_tls
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config: {http2_protocol_options: {}}
        http_filters:
        - name: envoy.filters.http.ai_protocol_manager
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
            request_handling: {}
            filters:
            - name: envoy.http.ai_filters.transcoder
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
                upstream:
                  llm_protocol: ANTHROPIC_MESSAGES
                  vertex_ai: {project: GCP_PROJECT, location: global}
                  default_max_output_tokens: 4096
        - *vertex_credential
        - *upstream_codec
```

`run.sh` substitutes `GCP_PROJECT` and `RUN_DIR`. The token file is a standard SDS
`generic_secret`:

```yaml
resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: vertex_access_token
  generic_secret: {secret: {inline_string: "<gcloud auth print-access-token>"}}
```

Routing needs no new code:

1. The first route resolution happens before the model is known, so it lands on an `unrouted_*`
   route. That route declares the AI endpoint, so the APM engages there.
2. `set_filter_state` copies the IR view's `model` field and re-resolves the route.
3. The upstream APM finds the same route declaration under the same filter name. It sees
   OpenAI on `/v1/chat/completions` routes and Anthropic on `/v1/messages`.

### 12.2 Requests and what each proves

| # | Request | Expected |
|---|---|---|
| E1 | OpenAI, `gemini-2.5-flash`, system message plus `max_tokens`, `stream: false` | `upstream_path` is `…/publishers/google/models/gemini-2.5-flash:generateContent`; the body is a `chat.completion` with `finish_reason: "stop"` and usage; `token_usage` COMPLETE in the access log |
| E2 | E1 with `stream: true` and `stream_options.include_usage` | `…:streamGenerateContent?alt=sse`; `chat.completion.chunk` frames, a trailing `choices: []` usage chunk, then `[DONE]` |
| E3 | OpenAI, `claude-sonnet-4-5@20250929`, `stream: false` | `…/publishers/anthropic/models/claude-sonnet-4-5@20250929:rawPredict`; the upstream body has `anthropic_version` and no `model`; the response is a `chat.completion` |
| E4 | E3 with `stream: true`, without `include_usage` | `…:streamRawPredict`; usage on the `finish_reason` chunk; `token_usage` COMPLETE |
| E5 | Anthropic Messages to `/v1/messages`, with `thinking`, `top_k`, and `system` blocks carrying `cache_control` | `:rawPredict`; the upstream body is byte-identical except `model` removed and `anthropic_version` added (diffed in mock mode); the native Anthropic response, thinking blocks included, is untouched |
| E6 | `model: "gpt-4o"` | a 404 from `unrouted_chat`; no upstream request |
| E7 | a `claude-`-prefixed model containing `/` | a 400 from the model-name check; no upstream request |
| E8 | the OpenAI Python SDK (`base_url=http://127.0.0.1:10000/v1`) running E1–E4 | the SDK parses every response; its default `accept-encoding: gzip` does not break conversion |
| E9 | admin `/stats?filter=transcoder` | `ir_published` equals the routed-request count, `request_passthrough` equals E5's count, and `unsupported_pair` is 0 |

In-tree coverage:

* **Unit tests** for each rule and codec, including golden SSE transcripts captured from E2, E4,
  and E5.
* **`ai_transcoder_integration_test`**, a two-stage config against a fake upstream. It asserts
  the Vertex path and body per provider, then replays canned JSON and SSE and asserts the
  client-side output.
* **A retry test**, from a Gemini cluster to an Anthropic cluster on 503. The second attempt must
  carry the Anthropic path and headers, with no Gemini leftovers.

## 13. Delivery plan

* **PR 0 — #47560 (Gina).** The engine. This branch merges its head unchanged until it lands.
* **PR 1 — core.** C1–C4 with a fake AI filter: the forward-unless-modified sink, staged header
  edits, flatten helpers, and the `AiRequestIr` type. No user-visible API.
* **PR 2 — the transcoder filter.**
  * An `internal` leg for OpenAI and Anthropic clients.
  * An `upstream` leg with `vertex_ai` for Gemini and Anthropic: same-protocol passthrough,
    OpenAI → Gemini/Anthropic with the phase-1 engine rules, and response codecs to OpenAI.
  * The usage policy, the model override, and the integration test.
  * The e2e demo branch builds on this PR.
* **PR 3 — tool calling and multimodal.** Engine rules and C5.
* **PR 4 — non-OpenAI clients across protocols.** The Gemini client URL lift, IR → client
  response codecs, and direct pair rules.
* **PR 5.** Error-body conversion, upstream-placed token usage (C6), and native endpoints.
* **Deferred: reuse the downstream parse upstream.** The downstream would publish the client
  document's index plus a body hash, and the upstream would adopt it when its received bytes
  match. That saves CPU only; it cannot change fidelity, because the source is the same client
  document either way.

## 14. Open questions

1. **Tool calling.** Phase 2 as proposed, or pulled into v1 for agent traffic?
2. **Usage policy.** Should usage always ride the finish chunk when the client did not ask for
   it, or should that be a knob?
3. **Where `AiRequestIr` lives.** In the APM core lib beside `ai_filter.h`, as proposed, or in
   `source/extensions/common/ai/`?
4. **Gemini clients.** Should the `internal` leg accept Gemini clients in v1? The path lift is
   small. The alternative is phase 4, alongside their cross-protocol responses.
