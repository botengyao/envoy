# AI protocol transcoding

How the AI Protocol Manager decides which payload schema a stream follows, how a
preceding filter can decide it at runtime instead of the route, and how the
inbound and outbound halves of an AI gateway translate between wire APIs.

Status: design. Nothing here is implemented. Sections 1 and 6.1 describe code
that exists today; everything else is proposed.

---

## 1. Where the schema comes from today

### 1.1 Request path

One input, read once:

1. `decodeHeaders()` resolves `AiProtocolManagerPerRoute` off the route
   (`filter.cc:229`) and copies two scalars out of it: `has_request_`, which
   declares the route an AI endpoint, and `request_protocol_`, an
   `envoy.type.ai.v3.ApiProtocol`.
2. `AdapterRegistry::get(protocol).schema()` returns a process-wide
   `const PayloadSchema*`. `OPENAI_CHAT_COMPLETIONS`, `ANTHROPIC_MESSAGES` and
   `GEMINI_GENERATE_CONTENT` have one; `OPENAI_RESPONSES` and
   `API_PROTOCOL_UNSPECIFIED` return `nullptr`.
3. The schema is used twice: it may pin the inline-string threshold used to
   build the parser (`filter.cc:280`), and it validates the completed document
   at end of payload, rejecting with a 400 (`filter.cc:333`).

### 1.2 Response path

A precedence chain, resolved in `encodeHeaders()` (`filter.cc:488`):
per-route `response.api_protocol`, then per-route `request.api_protocol`, then
`TokenUsageExtraction.default_api_protocol`, then `AdapterRegistry::detect()`
on the response shape.

### 1.3 What this cannot express

The request-side resolution has three properties that block an AI gateway:

- **It is static per route.** A route names one wire API. A fleet where the
  client's API is a property of the *caller* — an agent registry keyed on an
  API key, an agent id, or an mTLS SAN — cannot express that as a route match
  without exploding the route table.
- **It has one dimension.** There is no "what the upstream speaks". The
  response path already admits that request and response APIs can differ
  ("protocol translation can make them differ"), but nothing produces that
  difference.
- **It is decided before routing.** That is correct for the *inbound* schema —
  the parser needs a threshold before the first body byte — and impossible for
  the *outbound* one, which depends on a model-routing decision that by
  construction happens after the payload is parsed.

---

## 2. Schema selection inputs

### 2.1 Two schemas, not one

A stream carrying protocol translation has two payload schemas, resolved at
different times by different filter instances:

| | inbound | outbound |
|---|---|---|
| what it describes | the API the client spoke | the API the selected provider speaks |
| resolved by | downstream `ai_protocol_manager` | upstream `ai_protocol_manager` |
| resolved at | `decodeHeaders()`, before the body | `decodeHeaders()` of the upstream chain, after host selection |
| natural source | route config, or a registry filter | a model-routing decision |
| used for | parse threshold, validation, AI filters | transcode target, response inverse mapping |

### 2.2 Well-known filter state objects

Two keys, each write-once, each with one obvious writer:

```
envoy.ai.llm_protocol.request     <- set by an admission/registry filter on headers
envoy.ai.llm_protocol.upstream    <- set by the model-routing decision, after parse
```

The `envoy.ai.llm_protocol.` prefix keeps the inbound and outbound halves of
one decision together and names what they carry: the LLM wire contract a
payload follows, not Envoy's own routing. The field inside each message stays
`api_protocol`, matching its `type.ai.v3.ApiProtocol` type and the existing
`RequestPerRoute.api_protocol`.

Backed by protos in `envoy/data/ai/v3/`, so they serialize into access logs and
read through CEL:

```proto
// envoy/data/ai/v3/llm_protocol.proto

// The wire API the client's request payload follows, named at runtime by a
// filter that knows the caller. Overrides the route declaration only where the
// route opted in.
message RequestLlmProtocol {
  type.ai.v3.ApiProtocol api_protocol = 1 [(validate.rules).enum = {defined_only: true}];
}

// The wire API the selected upstream speaks, and what the outbound payload must
// carry to address it. Written after the routing decision; read by the upstream
// filter chain.
message UpstreamLlmProtocol {
  type.ai.v3.ApiProtocol api_protocol = 1 [(validate.rules).enum = {defined_only: true}];

  // Model identifier to place in the outbound payload, replacing the requested
  // one. Empty leaves the client's value.
  string model = 2;

  // Path to address the upstream with. Gemini encodes both the model and the
  // streaming choice in the path, so a transcode to it cannot be body-only.
  string path = 3;
}
```

Each gets a `FilterState::ObjectFactory` registered under its key, so the
objects are settable from `set_filter_state`, Lua and ext_proc without C++, and
`hasFieldSupport()`/`getField("api_protocol")` so a CEL match or an access log
can read them without proto reflection. That is what makes them *well-known*
rather than one more private key: the contract is the key name and the proto,
not a particular C++ filter.

Filter state, not dynamic metadata, because the objects are read on the hot
path by another filter rather than exported, and because a typed object gives
the writers a validated enum instead of a stringly-typed `Struct` field. The
existing `envoy.ai.request_info` metadata record stays what it is — an
observability output, not a control input.

### 2.3 Resolution order

Inbound, in `decodeHeaders()` of the downstream instance:

1. `envoy.ai.llm_protocol.request` filter state — **only if the route opted in**.
2. Per-route `request.api_protocol`.
3. `API_PROTOCOL_UNSPECIFIED`: a declared endpoint with no schema; parsed, not
   validated.

The opt-in matters. A filter state object is only as trustworthy as whatever
set it, and "which schema validates this payload" is a security-relevant
decision — silently letting a Lua snippet relax validation on a route that
declared `ANTHROPIC_MESSAGES` is not a default anyone asked for. So:

```proto
message RequestPerRoute {
  type.ai.v3.ApiProtocol api_protocol = 1;

  // Let a preceding filter name the wire API at runtime through the
  // ``envoy.ai.llm_protocol.request`` filter state object, overriding
  // ``api_protocol``. Unset, ``api_protocol`` is the only source.
  bool api_protocol_from_filter_state = 2;
}
```

A route that expects the registry to decide sets
`api_protocol_from_filter_state: true` and leaves `api_protocol` unset or as the
fallback for a caller the registry did not recognize.

Outbound, in `decodeHeaders()` of the upstream instance:

1. `envoy.ai.llm_protocol.upstream` filter state.
2. `Transcoding.default_upstream_protocol` from the upstream filter's own
   config (a cluster fronting exactly one provider needs no runtime decision).
3. Unspecified — no transcoding; the payload passes through as it stands.

### 2.4 Timing: the inbound hint must arrive on headers

The downstream instance needs the inbound protocol in `decodeHeaders()`,
before any body byte, because the schema can pin the parser's
`inline_string_threshold_bytes` (`filter.cc:280`) and that threshold decides,
irreversibly, which strings land inline and which become external references.
Learning the protocol later would mean re-parsing.

So the registry filter must sit **before** `ai_protocol_manager` and must decide
from headers alone. That is not a restriction in practice — `:path`, an API key,
an agent id header, an mTLS SAN are all header-time — but it is a hard ordering
constraint and belongs in the docs.

A filter that can only decide after the body is out of scope: it would have to
run as an AI filter, and by then the parse is done.

### 2.5 Lifespan

`LifeSpan::FilterChain`, not `Request`, for both objects.

The upstream filter chain reads the **downstream** stream's filter state —
`UpstreamFilterManager::streamInfo()` returns
`upstream_request_.parent_.callbacks()->streamInfo()`
(`source/common/router/upstream_request.cc:56`) — so a `FilterChain`-lifespan
object written downstream is visible upstream without any marking. In
particular, `SharedWithUpstreamConnection` is the wrong tool: it shares with the
upstream *connection*, binds the object to connection lifetime, and constrains
pooling.

`FilterChain` is also the safer lifespan. On an internal redirect the HCM
replaces the `FilterChain`-level filter state and keeps only its parent
(`source/common/http/conn_manager_impl.cc:2671`), so the hint is re-derived by
whatever runs on the new chain. A `Request`-lifespan hint would survive the
redirect and win over the new route's declaration — a stale override that is
hard to debug.

Per-route config resolution works identically in the upstream chain: with no
downstream callbacks, `ActiveStreamFilterBase::getRouteSharedPtr()` falls back
to `parent_.streamInfo().routeSharedPtr()`
(`source/common/http/filter_manager.cc:331`), which is the same route.

---

## 3. The well-known schema

### 3.1 Why a pivot

Four dialects today, more later. Direct pairwise mappers are N·(N−1) = 12 and
grow quadratically; a pivot is 2N = 8 and grows linearly. The usual objection to
a pivot — two rewrites instead of one, and loss compounding twice — is weaker
here than usual:

- The canonical form is never serialized. Transcoding is a DOM rewrite over
  `nlohmann::json`; bytes are only produced once, by `Serializer::serialize()`
  at the sink. "Two rewrites" means two passes of node moves, not two
  serializations.
- Loss is made explicit and observable (§3.5, §3.6) rather than being a
  property of which pair you happened to pick.

The pivot is also the only shape in which a payload-shaped policy — token
budgeting, prompt inspection, content classification — can be written once
instead of once per dialect. That is the second reason to have it, and probably
the longer-lived one.

### 3.2 What the offload constrains

The parser leaves any string over the inline threshold in the external buffer
and puts an `ExternalRef{offset, length}` in the DOM. Three consequences the
canonical model has to be designed around:

- **Every field that can carry conversation content must be `.offloadable()`.**
  A canonical field that is not offloadable is a field a large prompt cannot
  survive; validation would reject the reference outright.
- **A transcode moves nodes; it never copies string content.** Relocating an
  `ExternalRef` node from `messages[i].content` to `contents[i].parts[0].text`
  is a move of a 16-byte binary node. Materializing it would reintroduce exactly
  the per-stream footprint the offload exists to avoid.
- **`JsonWithExtBuf` is move-only by design.** Any step that needs a second copy
  of the document — retrying with a different target (§4.6) — needs an explicit
  `clone()`, and cloning is only cheap because the large values are references.

One field breaks the move-only rule, and it is not an edge case. See §3.4.

### 3.3 Shape

`envoy.ai.canonical.v1`, written in the existing `Schema` DSL so it validates,
declares offloadability, and declares a `streamable_field_order` on the same
machinery as the dialect schemas:

```
{
  "model":             string,                        // required, never offloadable
  "stream":            boolean,
  "max_output_tokens": integer,
  "temperature":       number,
  "top_p":             number,
  "stop":              [string],

  "system": [ {"type": "text", "text": string(offloadable)} ],

  "messages": [{
    "role": "user" | "assistant" | "tool",
    "content": [                                      // always parts, never a bare string
      {"type": "text",        "text": string(offloadable)},
      {"type": "image",       "media_type": string, "data": string(offloadable),
                              "url": string(offloadable)},
      {"type": "reasoning",   "text": string(offloadable), "signature": string(offloadable)},
      {"type": "tool_call",   "id": string, "name": string,
                              "arguments": object | string(offloadable)},
      {"type": "tool_result", "tool_call_id": string, "is_error": boolean,
                              "content": string(offloadable) | [part] }
    ]
  }],

  "tools": [ {"name": string, "description": string(offloadable), "parameters": object} ],
  "tool_choice": "auto" | "none" | "required" | {"name": string},
  "response_format": {"type": "text"|"json_object"|"json_schema", "json_schema": object},

  "vendor": { "<dialect>": { ...unmapped source fields, verbatim... } }
}
```

Three shape decisions worth defending:

**Content is always an array of tagged parts.** All three dialects accept a bare
string as a shorthand; two of them (OpenAI, Anthropic) also accept parts. Gemini
uses `parts[]` whose members are *untagged* — discriminated by which key is
present (`text`, `inlineData`, `functionCall`). Normalizing to one tagged-part
form means every mapper has exactly one input shape to read and one to write,
and the Gemini mapper is the only one that has to synthesize or strip the tag.

**Tool calls are content parts, not a separate message field.** OpenAI splits
them: an assistant message carries `tool_calls[]`, and results come back as
separate `role: "tool"` messages joined by `tool_call_id`. Anthropic and Gemini
inline them as content blocks. The inline form is the superset — it can express
text interleaved with tool calls in a defined order, which OpenAI's split cannot
— so canonical uses it and the OpenAI mapper does the splitting and joining.

**The system prompt is hoisted to the top level.** OpenAI carries it in-band as
`messages[0]` with role `system` or `developer`; Anthropic has a top-level
`system`; Gemini has `systemInstruction`. Hoisting means a policy filter reading
canonical does not have to know that one dialect hides the system prompt inside
the message list.

### 3.4 Dialect mapping

| canonical | OpenAI Chat Completions | Anthropic Messages | Gemini generateContent |
|---|---|---|---|
| `model` | `model` | `model` | **path** `/v1beta/models/{model}:...` |
| `stream` | `stream` (+`stream_options.include_usage`) | `stream` | **path** `:streamGenerateContent`, `?alt=sse` |
| `max_output_tokens` | `max_completion_tokens` \| `max_tokens` | `max_tokens` (**required**) | `generationConfig.maxOutputTokens` |
| `temperature` / `top_p` | same | same (`temperature` capped at 1.0) | `generationConfig.temperature` / `.topP` |
| `stop` | `stop` | `stop_sequences` | `generationConfig.stopSequences` |
| `system` | `messages[role=system\|developer]` | `system` | `systemInstruction` |
| `messages[].role` | `user`/`assistant`/`tool` | `user`/`assistant` | `contents[].role` `user`/**`model`** |
| `content[text]` | `content` string \| `{type:text}` | `content` string \| `{type:text}` | `parts[].text` |
| `content[image]` | `{type:image_url,image_url:{url}}` | `{type:image,source:{...}}` | `parts[].inlineData` \| `.fileData` |
| `content[tool_call]` | `message.tool_calls[].function` | `{type:tool_use}` block | `parts[].functionCall` |
| `content[tool_result]` | separate `role:tool` message | `{type:tool_result}` block | `parts[].functionResponse` |
| `content[reasoning]` | — | `{type:thinking}` block | `parts[].thought` / `thoughtSignature` |
| `tools[]` | `tools[].function.{name,description,parameters}` | `tools[].{name,description,input_schema}` | `tools[].functionDeclarations[]` |
| `response_format` | `response_format` | — (tool-forcing idiom) | `generationConfig.responseMimeType`/`responseSchema` |

Four mappings are not node moves, and each needs a decision:

**Tool-call arguments change encoding.** OpenAI's `function.arguments` is a
**JSON-encoded string**; Anthropic's `input` and Gemini's `args` are
**objects**. OpenAI → Anthropic means parsing a string into a document;
Anthropic → OpenAI means serializing one into a string. This is the one field
that must be materialized, and it is a field that can be offloaded. Proposal:
canonical accepts `arguments` as either form, the conversion is bounded by
`max_materialized_bytes` (default 64KiB), and a payload over the bound is
rejected or dropped per `on_unmappable`. An offloaded `arguments` node must be
resolved from the external buffer before conversion; that resolution is the only
place the transcoder touches buffer bytes.

**Anthropic requires `max_tokens`.** OpenAI and Gemini do not. A transcode to
Anthropic from a payload without an output cap produces a request the provider
rejects with a 400 — so the failure surfaces as a confusing upstream error
rather than a config error. `Transcoding.default_max_output_tokens` supplies
one; leaving it unset on a route that can target Anthropic should be a config
warning.

**Gemini puts model and streaming in the path.** `model`, and the choice between
`:generateContent` and `:streamGenerateContent`, are URL components. A transcode
to Gemini must rewrite `:path`. This is safe only in the upstream chain, where
the route is already resolved and no route re-resolution follows — one more
reason transcoding belongs there (§4.1).

**Anthropic caps `temperature` at 1.0**; OpenAI allows 2.0. A value in (1, 2]
is `approximated` (clamped) or `unsupported`, per §3.6.

### 3.5 The `vendor` side-channel

A gateway whose inbound and outbound protocols are the same must not degrade
payloads just because it parsed them. And a dialect gains fields faster than
this table is updated.

So: on `toCanonical()`, every top-level field the mapper does not claim is
**moved** — not copied — under `vendor.<dialect>`. On `fromCanonical()` to the
same dialect, it is moved back. Round-tripping A → canonical → A is therefore
value-preserving for unknown fields, including offloaded ones, at the cost of
one map insert and one erase per field.

Transcoding to a *different* dialect drops `vendor.*`, counts
`transcode_vendor_dropped`, and logs the field names at debug. Dropping is
correct — an Anthropic-specific `thinking.budget_tokens` has no OpenAI meaning —
but it must be visible.

`vendor` is internal. It never reaches the wire: `fromCanonical()` either
restores it or drops it, and a canonical document with a surviving `vendor` key
at serialization time is an `ENVOY_BUG`.

### 3.6 Fidelity classes

Each mapper declares, per canonical field, one of:

- `exact` — a faithful move.
- `approximated` — representable with a documented distortion (temperature
  clamped, a `response_format` expressed as forced tool use, `system` folded
  into the first user message).
- `unsupported` — no representation.

`Transcoding.on_unmappable` decides what an `unsupported` field does:
`REJECT` (400, naming the field) or `DROP` (drop, count, debug log). Default
`REJECT`: a silently dropped `response_format` produces prose where the client
expected JSON, which is worse than a clear rejection. `approximated` never
rejects; it counts.

### 3.7 Should canonical be an `ApiProtocol` value?

No, not in v1. `ApiProtocol` documents itself as naming what is spoken *on the
wire*, and the canonical model is an in-memory pivot with no wire consumer yet.
Adding the enum value commits API surface — and a stability promise about the
canonical shape — before anything reads it.

The promotion path is additive and costs nothing to defer: when a consumer
appears (an ext_proc forwarding canonical bodies, a backend speaking it
natively), add `AI_CANONICAL_V1` to the enum and register an adapter whose
`toCanonical`/`fromCanonical` are the identity. Versioning lives in the name,
so `v2` is a second value rather than a breaking change to the first.

---

## 4. Transcoding mechanics

### 4.1 Where it runs

In the **upstream** filter chain, always. Three independent reasons:

1. **The target is not known downstream.** Model routing picks the provider
   after the payload is parsed, and on a cluster fronting several providers, not
   until host selection.
2. **It must be redone per attempt.** A retry or a model-fallback attempt
   (see the `ai_model_fallback` / `upstream_target_policy` work) can pick a
   different provider, which means a different target dialect. The upstream
   chain runs once per attempt; the downstream chain runs once per request.
   Transcoding downstream would freeze the first attempt's target into the body.
3. **The response inverse mapping needs the client's dialect intact.** The
   downstream half must keep holding the payload in the client's shape, because
   that is what the response has to be mapped back to.

The downstream instance's job is unchanged: parse, validate against the inbound
schema, run AI filters, replay. The upstream instance adds one step.

### 4.2 Adapter surface

Transcoding hangs off `ApiProtocolAdapter`, which already owns "how does this
dialect express X":

```cpp
class ApiProtocolAdapter {
  // ...

  // Rewrite a payload in this dialect into the canonical model, in place.
  // Nodes are moved, never copied: ExternalRef nodes keep their offsets, and
  // unclaimed fields move under vendor.<dialect>.
  virtual absl::Status toCanonical(nlohmann::json& doc, TranscodeContext& ctx) const {
    return absl::UnimplementedError("no canonical mapping for this API");
  }

  // The inverse. Restores vendor.<dialect> when it is present, drops it when
  // it belongs to another dialect.
  virtual absl::Status fromCanonical(nlohmann::json& doc, TranscodeContext& ctx) const {
    return absl::UnimplementedError("no canonical mapping for this API");
  }
};
```

Not pure, so the three dialects without a mapping keep compiling and a partial
rollout is possible. `TranscodeContext` carries the limits, the
`on_unmappable` policy, the stats, and an out-parameter for header and `:path`
rewrites the mapper wants (§3.4).

A transcode is then:

```cpp
if (source == target) { return absl::OkStatus(); }        // the common case
RETURN_IF_ERROR(AdapterRegistry::get(source).toCanonical(doc, ctx));
RETURN_IF_ERROR(AdapterRegistry::get(target).fromCanonical(doc, ctx));
```

Skipping identical protocols outright is not just an optimization: it is what
guarantees a non-translating gateway is byte-faithful regardless of how good the
mappers are.

### 4.3 Where it sits in the pipeline

`RequestFilterManager::runSink()` (`request_filter_manager.cc:149`) already does
the three things that must happen around a transcode, in this order:

1. `Serializer::calculateSerializedOffsets()` — dry-run the byte layout of the
   rewritten DOM and recompute every `ExternalRef` offset.
2. Publish `APMRequestPayloadIndex` to filter state.
3. `request_headers_->setContentLength(total_size)`.
4. `Serializer::serialize()` — replay JSON tokens and buffer slices into the
   `BufferManager`.

The transcode is a new step **0**: after the last AI filter propagates, before
`calculateSerializedOffsets`. Everything downstream of it — offset recomputation,
content-length fixup, flow-controlled replay — already handles an arbitrary
rewritten DOM with external references. No serializer change is needed, which is
the main reason this design is cheap to land.

It cannot run as an AI filter: AI filters operate on the inbound shape (the
`request_info` extractor keys off `context.request_protocol`), and a transcode
that ran mid-chain would silently invalidate every filter after it.

### 4.4 Headers

A transcode can require header changes: `:path` (§3.4), `content-type`,
provider-specific auth headers such as `anthropic-version`. Only `:path` and
`content-length` are the transcoder's business. Auth is credential injection and
belongs to the filter that owns credentials, not here — the transcoder must not
grow a provider-credentials surface.

`:path` rewriting is safe in the upstream chain: the route is resolved, no
re-resolution follows, and the rewritten path is per-attempt, which is what a
per-attempt target requires.

### 4.5 The double parse

The upstream instance re-parses the body the downstream instance just
serialized. That is the v1 cost, and it is real: two Wuffs passes and two
external buffers per request.

It is also the only correct thing available today. `APMRequestPayloadIndex` is
published with offsets into the *serialized output stream*, and
`JsonWithExtBuf` "nothing here holds a buffer" — the refs are offsets, not
handles, so the upstream instance has no way to read bytes belonging to the
downstream instance's `ExternalBuffer`.

The optimization, for later, is a handoff: publish the index together with a
shared, ref-counted handle to the external buffer, and have the upstream
instance adopt it instead of parsing. It needs three things that do not exist:
buffer ownership in `JsonWithExtBuf`, an explicit `clone()` (the DOM is
move-only, and each retry attempt needs its own copy to transcode), and a
lifetime argument for the buffer outliving the downstream filter across retries.
Worth doing; not worth blocking transcoding on.

Deployments that do not need per-attempt targets can avoid the second parse
entirely by configuring only the downstream instance and accepting a fixed
target — at the cost of correct model fallback.

---

## 5. Response path

### 5.1 The asymmetry

Request transcoding is a DOM rewrite over one complete document. Response
transcoding is not: an SSE response is an event stream, and the target dialect's
event vocabulary, framing and ordering differ from the source's. It is a state
machine, not a rewrite, and it is the larger half of this work.

- **OpenAI** streams unnamed `data:` frames, each a `chat.completion.chunk` with
  a `choices[].delta`, terminated by the non-JSON `data: [DONE]`.
- **Anthropic** streams *named* events — `message_start`, `content_block_start`,
  `content_block_delta`, `content_block_stop`, `message_delta`, `message_stop` —
  with an `index` per content block, and no `[DONE]`.
- **Gemini** streams `GenerateContentResponse` objects, as a JSON array or as SSE
  under `?alt=sse`, with cumulative `usageMetadata` and no terminator.

So transcoding to Anthropic means **synthesizing** events the source never sent
(`message_start` before the first delta, `content_block_start`/`_stop` around
each block, `message_stop` at the end) and allocating block indices. Transcoding
to OpenAI means **collapsing** Anthropic's block structure into flat deltas and
appending `[DONE]`.

The existing `sse/` codec and the `AiFilter::encodeSSE()` chain give the framing
and the per-frame coroutine; the transcoder is a stateful consumer on top of
them, with "frames in and frames out need not correspond" already part of that
contract.

### 5.2 What the state machine carries

Per stream: the source and target dialects, the message id and model echoed in
synthesized headers, the current content-block index and kind, whether
`message_start` has been emitted, and partial tool-call arguments — OpenAI
streams `function.arguments` as string fragments while Anthropic streams
`input_json_delta` fragments, and the two do not chunk at the same boundaries.
Everything is bounded by the existing `max_sse_event_size` and
`max_parsed_sse_events` limits; exhausting them must fail the stream, not
silently emit a truncated event sequence, because a malformed event stream is
worse for a client than a reset.

### 5.3 Usage and errors

Token usage already has a canonical pivot: `TokenUsage` plus the adapters'
`canonicalizeUsage()`. Response transcoding reuses it — extract in the source
dialect, canonicalize, re-emit in the target dialect's usage shape — rather than
mapping usage fields pairwise.

Errors need the same treatment and are easy to forget. A provider error body
(Anthropic's `{"type":"error","error":{...}}`, OpenAI's `{"error":{...}}`,
Gemini's `{"error":{"code","message","status"}}`) must be mapped into the
client's dialect, including the in-band `event: error` Anthropic can send after
a 200 has begun streaming — which the existing extractor already recognizes as a
`stream_error`.

### 5.4 Request transcoding without response transcoding is a broken gateway

If a client sends OpenAI, the gateway translates to Anthropic, and the response
comes back untranslated, the client gets a response it cannot parse. So:

- Response transcoding for a pair is a **precondition** for enabling request
  transcoding for that pair. Configuring the second without the first is a
  config error, not a runtime surprise.
- The single exception is an explicit `ResponseTranscoding.mode: PASSTHROUGH`,
  for deployments where the caller is itself protocol-aware — another Envoy, or
  an SDK that speaks both. It must be opt-in and named for what it is.

This is why phase 1 (§7) ships request transcoding **only for pairs whose
response mapping also ships**, rather than shipping the easy half first.

---

## 6. The chain, end to end

### 6.1 Placement

```
downstream HCM http_filters:
  agent_registry           identifies the caller from headers;
                           writes envoy.ai.llm_protocol.request
  ai_protocol_manager      request_handling: parse + validate against the
                           INBOUND schema; run AI filters (request_info, ...)
  model_routing_pdp        reads the parsed payload / request_info; selects
                           model + provider; writes envoy.ai.llm_protocol.upstream
  router

cluster upstream http_filters:
  ai_protocol_manager      transcoding: inbound -> envoy.ai.llm_protocol.upstream;
                           response: target -> inbound
  envoy.filters.http.upstream_codec
```

Two ordering constraints, both load-bearing:

- `agent_registry` **before** `ai_protocol_manager`, because the inbound schema
  must be known at `decodeHeaders()` (§2.4).
- `model_routing_pdp` **after** `ai_protocol_manager`, because it needs the
  parsed payload. This is exactly what the downstream instance's header-holding
  is for: it pins the request headers until the payload is offloaded, so routing
  and admission filters never act before the body they depend on exists.

### 6.2 PDP as an HTTP filter or as an AI filter

Both slots work; they are not equivalent.

As an **AI filter** inside `ai_protocol_manager`, the PDP receives `AiRequest`
directly — no re-serialization, no reading the payload index back out of filter
state — and can await (the chain is coroutine-based, so an async policy call
fits) and `reply_locally`. This is the cheaper slot, and the right one if the
PDP only *reads* the payload.

As an **HTTP filter** after `ai_protocol_manager`, it additionally gets the
HTTP-filter surface: mutable request headers, route cache clearing, cluster
selection, retry-aware local replies. `AiFilterContext` exposes none of those.

Recommendation: HTTP filter, because a model-routing decision that cannot change
the cluster or the headers is not much of a routing decision. Revisit if
`AiFilterContext` grows a routing surface.

### 6.3 One request

Client sends OpenAI Chat Completions; policy routes it to Anthropic.

1. `agent_registry` recognizes the API key, writes
   `envoy.ai.llm_protocol.request{OPENAI_CHAT_COMPLETIONS}` at `FilterChain`
   lifespan.
2. `ai_protocol_manager` (downstream) resolves the inbound schema from filter
   state (the route opted in), builds the parser with the OpenAI schema's
   threshold, holds the headers, offloads and parses the body, validates, runs
   `request_info`, serializes, publishes `APMRequestPayloadIndex`, fixes
   `content-length`, replays.
3. `model_routing_pdp` reads `envoy.ai.request_info`, picks
   `claude-sonnet-4-5` on the Anthropic cluster, writes
   `envoy.ai.llm_protocol.upstream{ANTHROPIC_MESSAGES, model: "claude-sonnet-4-5"}`,
   selects the cluster.
4. Router picks a host. The upstream chain runs.
5. `ai_protocol_manager` (upstream) resolves target `ANTHROPIC_MESSAGES` from
   filter state, parses the replayed body against the inbound OpenAI schema,
   runs `toCanonical` then `fromCanonical`: hoists the system message to
   `system`, splits `tool_calls`/`role:tool` into `tool_use`/`tool_result`
   blocks, parses each `function.arguments` string into `input`, renames
   `max_completion_tokens` to `max_tokens` (or supplies
   `default_max_output_tokens`), clamps `temperature` to 1.0 and counts an
   approximation, drops `vendor.openai`. Serializes, fixes `content-length`,
   forwards.
6. The Anthropic SSE response streams back through the upstream encode path. The
   response transcoder collapses `content_block_delta` events into
   `chat.completion.chunk` frames, maps the final usage through `TokenUsage`,
   and appends `[DONE]`.
7. The downstream instance sees an OpenAI-shaped response, as the route declared.

If step 5's host fails and the fallback policy picks an OpenAI host instead,
step 5 runs again on the new attempt with target `OPENAI_CHAT_COMPLETIONS` and
transcoding is skipped entirely — which is the whole reason it lives upstream.

---

## 7. Configuration

```proto
message AiProtocolManager {
  RequestHandling request_handling = 1;
  ResponseHandling response_handling = 2;
  repeated config.core.v3.TypedExtensionConfig filters = 3;

  // Protocol translation. Meaningful only in an upstream HTTP filter chain;
  // rejected at config load in a downstream chain.
  Transcoding transcoding = 4;
}

message Transcoding {
  enum OnUnmappable {
    // Reject the request with a 400 naming the field.
    REJECT = 0;
    // Drop the field, count it, log it at debug.
    DROP = 1;
  }

  // Wire API the upstream speaks, when it is a property of the cluster. A
  // ``envoy.ai.llm_protocol.upstream`` filter state object overrides it, which is
  // how a runtime model-routing decision names its target.
  type.ai.v3.ApiProtocol default_upstream_protocol = 1;

  OnUnmappable on_unmappable = 2;

  // Output cap for a target that requires one (Anthropic) when the source
  // payload carried none. Config load warns when a target that requires it is
  // reachable and this is unset.
  google.protobuf.UInt32Value default_max_output_tokens = 3;

  // Largest value that may be materialized out of the external buffer to change
  // its encoding -- tool-call arguments, which are a JSON string in one dialect
  // and an object in another. Above it, ``on_unmappable`` applies.
  // Defaults to 64KiB.
  google.protobuf.UInt32Value max_materialized_bytes = 4;

  ResponseTranscoding response = 5;
}

message ResponseTranscoding {
  enum Mode {
    // Map the response back to the request's wire API. Required whenever the
    // request was transcoded, unless PASSTHROUGH is set explicitly.
    TRANSLATE = 0;
    // Forward the upstream's response untouched. Only for callers that speak
    // the upstream's API themselves.
    PASSTHROUGH = 1;
  }
  Mode mode = 1;
}
```

---

## 8. Observability

Counters, alongside the existing `ALL_AI_PROTOCOL_MANAGER_STATS`:

```
transcode_request                 request transcoded
transcode_request_skipped         source == target
transcode_response                response transcoded
transcode_rejected                rejected under on_unmappable=REJECT
transcode_field_dropped           unsupported field dropped
transcode_field_approximated      field mapped with a documented distortion
transcode_vendor_dropped          vendor.* dropped on a cross-dialect transcode
transcode_materialized            a value read out of the external buffer
transcode_too_large               materialization over max_materialized_bytes
transcode_unsupported_pair        no mapping for source -> target
transcode_response_desync         response event stream could not be mapped
```

The source and target protocols belong on the existing `envoy.ai.request_info`
record so one access log line answers "what did the client send, what did we
send, and was it translated".

---

## 9. Failure modes

| | behavior |
|---|---|
| filter state names a protocol with no schema | treated as `UNSPECIFIED`: parsed, not validated |
| filter state set but route did not opt in | ignored; counted; debug log |
| filter state names a target with no mapper | `transcode_unsupported_pair`, 502 — the upstream cannot serve this request |
| `toCanonical` fails mid-rewrite | the DOM is partially moved and must not be forwarded: fail the attempt |
| `fromCanonical` drops a required target field | 400 under `REJECT`; under `DROP` the provider rejects it, which is worse — hence `REJECT` is the default |
| offloaded tool arguments over the cap | `transcode_too_large`, then `on_unmappable` |
| response transcoder loses stream sync | reset the stream; a truncated event sequence is worse than a reset |
| retry picks a different target | re-transcode from the inbound shape; never transcode a transcoded document |

That last row is why the upstream instance re-derives the inbound document each
attempt rather than mutating one shared copy, and why a buffer handoff (§4.5)
must hand off a *clonable* index rather than a moved one.

---

## 10. Phasing

1. **Schema selection.** `envoy.ai.llm_protocol.request` /
   `envoy.ai.llm_protocol.upstream`, their protos and object factories,
   `api_protocol_from_filter_state`, and resolution in both instances. No
   transcoding. Independently useful: it is what lets a registry filter, rather
   than the route table, decide the inbound schema.
2. **Canonical model.** `schema/canonical.cc`, the `toCanonical` /
   `fromCanonical` hooks, and the OpenAI ↔ canonical pair, with
   `transcode_request_skipped` proving the identity path is free. No response
   path, so no pair is enabled end to end yet.
3. **First pair, both directions.** Anthropic ↔ canonical plus the SSE response
   state machine for OpenAI ↔ Anthropic. This is the first phase that can be
   turned on in production.
4. **Gemini**, including the `:path` rewriting its model and streaming encoding
   forces.
5. **Parse-once handoff** (§4.5), if the double parse shows up in profiles.

Phases 1 and 2 are separable PRs with their own tests. Phase 3 is the large one
and should probably split again along request/response.

---

## 11. Open questions

- **Does the inbound schema need a per-*caller* threshold?** Filter state can
  name the protocol, and the protocol pins the threshold. A registry that wants
  a per-caller threshold has no way to express it. Probably fine to leave out.
- **`model` rewriting: transcoder or a dedicated filter?** `UpstreamLlmProtocol`
  carries it here because Gemini needs it in the path at the same moment the
  body is rewritten, but it is arguably a separate concern.
- **Canonical `tool_result` content.** Anthropic allows a nested block array;
  OpenAI allows only a string. Flattening is lossy in one direction and the
  right flattening (JSON-encode? concatenate text blocks?) is not obvious.
- **Where response transcoding runs when the response is unary.** The SSE chain
  is the interesting case, but a unary JSON response needs the same mapping
  through a different path, and it is not obvious it should share code with the
  request-side DOM rewrite.
- **`OPENAI_RESPONSES` has no request schema.** It is the dialect furthest from
  the others (`input` instead of `messages`, server-side conversation state), and
  canonical v1 as drafted cannot represent stored-conversation semantics at all.
