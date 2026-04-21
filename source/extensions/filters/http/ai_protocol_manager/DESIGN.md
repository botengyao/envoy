# AI Protocol Manager Filter — Design

Status: DRAFT — focused on naming and code structure. Wire-level
semantics and config proto are intentionally deferred.

## 1. Purpose

`ai_protocol_manager` is a **decoder-only, terminal** HTTP filter that:

1. Consumes the full HTTP request (headers, body, trailers).
2. Parses the body as JSON-RPC into a protocol-agnostic internal
   representation (`AiRequest`) that unifies the common fields of:
   - **Inference** APIs (OpenAI-style `chat.completions`, `responses`, …)
   - **Agent** protocols (A2A, MCP).
3. Dispatches the `AiRequest` through one of two **sub filter chains**
   exposed to operators:
   - **Inference filter chain** (`inference_chain`) — for model
     invocations.
   - **Agent filter chain** (`agent_chain`) — for agent protocol
     messages.
4. At the end of each sub-chain, a **terminal dispatch filter** re-encodes
   the `AiRequest` back into JSON-RPC and forwards it to one or more HTTP
   backends via `Http::AsyncClient`, then pumps the response(s) back to
   the downstream caller.

The filter replaces what would otherwise be two parallel stacks (one per
protocol family) and lets AI-aware logic — routing, budgeting, PII
scrubbing, prompt rewriting, caching, guardrails — be written **once**
against a neutral request type.

### Non-goals (for v0)

- Streaming response translation / SSE fan-in (handled by existing
  `mcp_router` patterns; can be adopted later).
- Tokenizer / cost accounting (separate filter, consumes `AiRequest`
  from filter state).
- gRPC / protobuf transports.
- Response-side rewriting beyond pass-through (filter is decoder-only).

## 2. High-level architecture

```
                            downstream HTTP request
                                     │
                                     ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │                  AiProtocolManagerFilter (terminal)                │
 │                                                                    │
 │   decodeHeaders / decodeData / decodeTrailers                      │
 │            │                                                       │
 │            ▼                                                       │
 │   ┌──────────────────┐        ┌──────────────────────────────┐     │
 │   │ JsonRpcDecoder   │───────▶│ AiRequest (internal repr.)   │     │
 │   │  (streaming)     │        │  + PayloadRefs → PayloadStore│     │
 │   └──────────────────┘        └──────────────┬───────────────┘     │
 │                                              │                     │
 │                              classify(protocol) picks ONE chain    │
 │                               ┌──────────────┴──────────────┐      │
 │                               ▼                             ▼      │
 │                      ┌──────────────────┐       ┌──────────────────┐
 │                      │ InferenceChain   │       │   AgentChain     │
 │                      │ (ordered         │       │  (ordered        │
 │                      │  AiFilters over  │       │   AiFilters over │
 │                      │  AiRequest)      │       │   AiRequest)     │
 │                      └────────┬─────────┘       └────────┬─────────┘
 │                               │ AiRequest                │ AiRequest│
 │                               ▼                          ▼          │
 │                      ┌──────────────────┐       ┌──────────────────┐
 │                      │ InferenceDispatch│       │  AgentDispatch   │
 │                      │   (terminal,     │       │    (terminal,    │
 │                      │  JsonRpcEncoder) │       │  JsonRpcEncoder) │
 │                      └────────┬─────────┘       └────────┬─────────┘
 │                               └──────────────┬───────────┘         │
 │                                              ▼                     │
 │                              Http::AsyncClient → upstream(s)       │
 └────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
                              downstream response
```

`AiRequest` is the **shared** neutral model: `JsonRpcDecoder` emits one,
`classify()` selects which sub-chain runs, and that same `AiRequest`
(possibly mutated by chain filters) is handed to the sub-chain's
terminal `*Dispatch` filter for re-encoding. The two sub-chains differ
only in which `AiFilter` factories they draw from and which `*Dispatch`
implementation sits at their tail — not in the type that flows through
them.

## 3. Directory & file layout

All files live under
`source/extensions/filters/http/ai_protocol_manager/`. Public protos live
under `api/envoy/extensions/filters/http/ai_protocol_manager/v3/`.

```
ai_protocol_manager/
├── BUILD
├── DESIGN.md
│
│   # Envoy filter plumbing
├── config.h / config.cc                 # NamedHttpFilterConfigFactory
├── filter.h / filter.cc                 # AiProtocolManagerFilter
├── filter_config.h / filter_config.cc   # AiProtocolManagerConfig, stats
│
│   # Protocol-neutral request model + JSON-RPC codec
├── codec/
│   ├── ai_request.h / ai_request.cc         # AiRequest, AiResponse, enums
│   ├── ai_payload.h / ai_payload.cc         # PayloadRef, PayloadStore iface
│   ├── json_rpc_decoder.h / .cc             # streaming decoder → AiRequest
│   ├── json_rpc_encoder.h / .cc             # AiRequest → JSON-RPC buffer
│   ├── inference_mapping.h / .cc            # OpenAI-style ↔ AiRequest
│   ├── agent_mapping.h / .cc                # A2A + MCP ↔ AiRequest
│   └── protocol_classifier.h / .cc          # headers+method → ProtocolKind
│
│   # Sub-chain machinery (the “ergonomic AI filter chain” surface)
├── chain/
│   ├── ai_filter.h                          # AiFilter interface (pure virtual)
│   ├── ai_filter_callbacks.h                # AiFilterCallbacks (chain API)
│   ├── ai_filter_chain.h / .cc              # ordered runner, shared by both kinds
│   ├── ai_filter_factory.h                  # registration for sub-chain filters
│   ├── inference_chain.h / .cc              # InferenceChain (typed façade)
│   └── agent_chain.h / .cc                  # AgentChain (typed façade)
│
│   # Terminal dispatch filters at the tail of each sub-chain
└── dispatch/
    ├── ai_dispatch_filter.h / .cc           # shared base (encode + async client)
    ├── inference_dispatch.h / .cc           # InferenceDispatchFilter
    └── agent_dispatch.h / .cc               # AgentDispatchFilter
```

### Namespace

```cpp
Envoy::Extensions::HttpFilters::AiProtocolManager
  ::Codec       // codec/
  ::Chain       // chain/
  ::Dispatch    // dispatch/
```

## 4. Core types

### 4.1 `AiRequest` — shared envelope + variant payload

`codec/ai_request.h`. The request is a shared envelope holding fields
that are genuinely protocol-neutral, plus a `std::variant` payload
carrying the protocol-specific body. Cross-cutting sub-chain filters
(PII scrub, rate limit, budget, logging) take `AiRequest&` and never
see the variant; specialized filters and the terminal `*Dispatch`
filters pull out the variant they expect.

#### Envelope

```cpp
// codec/ai_request.h

enum class ProtocolKind { Unknown, Inference, AgentA2a, AgentMcp };

// Per-filter scratch shared across sub-chain filters (not cross-request,
// not serialized back out).
using AiScratch = absl::flat_hash_map<std::string, std::any>;

class AiRequest {
public:
  // --- JSON-RPC identity ---
  std::string jsonrpc_id;       // empty ⇒ notification
  std::string method;           // raw "method" token

  // --- Protocol discriminator + variant payload ---
  ProtocolKind protocol{ProtocolKind::Unknown};
  std::variant<std::monostate, InferencePayload, AgentPayload> payload;

  // --- Protocol-neutral small scalars that arrived with the request
  //     (tenant, user id, request-id, routing hints). Cross-cutting
  //     filters read from here.
  absl::flat_hash_map<std::string, std::string> attributes;

  // --- Streaming intent (OpenAI stream:true, A2A/MCP SSE subscribe). ---
  bool streaming{false};

  // --- Payload offload: not owned; outer filter owns the store. ---
  PayloadStore* payload_store{nullptr};

  // --- Filter-to-filter scratch within this request. ---
  AiScratch scratch;

  // --- Typed accessors. Return nullptr on wrong variant. ---
  InferencePayload*       as_inference();
  const InferencePayload* as_inference() const;
  AgentPayload*           as_agent();
  const AgentPayload*     as_agent() const;
};
```

#### Inference variant — `codec/inference_payload.h`

```cpp
enum class InferenceInvocation {
  Unknown,
  ChatCompletion,   // POST /v1/chat/completions
  Completion,       // POST /v1/completions
  Responses,        // POST /v1/responses
  Embeddings,       // POST /v1/embeddings
  // (Audio, Moderations, Images — added as needed.)
};

struct ModelTarget {
  std::string name;            // "gpt-4o-mini", "claude-sonnet-4-6", …
  std::string provider_hint;   // optional: "openai", "anthropic", "vertex"
};

struct SamplingParams {
  absl::optional<double>   temperature;
  absl::optional<double>   top_p;
  absl::optional<int32_t>  max_tokens;
  absl::optional<int32_t>  n;
  std::vector<std::string> stop;
  absl::optional<int64_t>  seed;
  // Rarer knobs (presence_penalty, frequency_penalty, logprobs, …)
  // live in InferencePayload::extra_params rather than bloating this.
};

struct InferencePayload {
  InferenceInvocation invocation{InferenceInvocation::Unknown};
  ModelTarget         target;

  // Potentially large — always PayloadRef so the decoder can offload.
  std::vector<PayloadRef> messages;      // chat turns
  std::vector<PayloadRef> tools;         // tool / function definitions
  std::vector<PayloadRef> attachments;   // images, audio, files

  // tool_choice, response_format, service_tier, user, plus any params
  // the mapper didn't claim.
  absl::flat_hash_map<std::string, std::string> extra_params;

  SamplingParams sampling;

  // Everything the mapper didn't pull apart — keeps pass-through honest.
  PayloadRef residual_params;
};
```

#### Agent variant — `codec/agent_payload.h`

```cpp
enum class AgentDialect { Unknown, A2a, Mcp };

enum class AgentInvocation {
  Unknown,
  // MCP
  Initialize, Ping,
  ToolsList, ToolsCall,
  ResourcesList, ResourcesRead, ResourcesSubscribe, ResourcesUnsubscribe,
  PromptsList, PromptsGet,
  SamplingCreateMessage, CompletionComplete, LoggingSetLevel,
  // A2A
  MessageSend, MessageStream,
  TaskSubmit, TaskGet, TaskCancel,
  // Notifications folded in here (NotificationInitialized, …) when we
  // need to route them.
};

struct AgentTarget {
  std::string agent_id;     // logical agent / skill id for routing
  std::string session_id;   // MCP session / A2A context id (may be empty)
  std::string task_id;      // A2A task id (empty outside task ops)
};

struct AgentPayload {
  AgentDialect     dialect{AgentDialect::Unknown};
  AgentInvocation  invocation{AgentInvocation::Unknown};
  AgentTarget      target;

  // Selector fields — small, protocol-specific, filled based on
  // invocation. Only the ones relevant to `invocation` are populated.
  std::string tool_name;       // ToolsCall
  std::string resource_uri;    // Resources*
  std::string prompt_name;     // PromptsGet
  std::string completion_ref;  // CompletionComplete ("ref/prompt" | "ref/resource")

  // Potentially large — offloadable.
  std::vector<PayloadRef> parts;        // A2A Parts | MCP content[]
  PayloadRef              arguments;    // ToolsCall.arguments, PromptsGet.arguments
  PayloadRef              capabilities; // Initialize

  PayloadRef residual_params;
};
```

#### Design notes

1. **Variant inside `AiRequest`, not base class**: avoids heap
   allocation per request, keeps cross-cutting filters taking
   `AiRequest&` without virtual dispatch, and lets `std::visit` work
   for exhaustive handling in dispatch filters.
2. **`ModelTarget` vs `AgentTarget` don't unify**: an inference target
   names a *model*; an agent target names an *agent / session / task*.
   Hoisting a shared "target" into the envelope would paper over that.
3. **One invocation enum per variant**: keeps the inference mapper
   from ever considering MCP values and vice versa, and lets each
   sub-chain's `AiFilter` factories validate config against only its
   variant.
4. **Three field tiers, on purpose**:
   - `attributes` — protocol-neutral scalars that arrived with the
     request and cross-cutting filters care about (tenant, user id).
   - `InferencePayload::extra_params` / variant residuals —
     protocol-specific JSON fields the mapper didn't model.
   - `scratch` — runtime-only, filter-to-filter data, never
     serialized back out.
5. **`AiResponse`**: unified for v0 (status + headers + body). Apply
   the same envelope+variant pattern if response-side logic grows
   protocol-specific (OpenAI chunk framing vs A2A event types).
6. **Open**: should `AgentPayload` split into `A2aPayload` /
   `McpPayload`? Kept unified because fields overlap heavily and
   `dialect` is already a discriminator; revisit if MCP/A2A diverge
   more than expected.

### 4.2 `PayloadRef` + `PayloadStore` — offload boundary

`codec/ai_payload.h`. Keeps large blobs out of filter memory.

```cpp
class PayloadRef {
public:
  enum class Storage { Inline, Buffered, External };
  Storage storage() const;
  absl::string_view inline_view() const;           // Inline
  const Buffer::Instance& buffered() const;        // Buffered
  absl::string_view external_handle() const;       // External (opaque URI)
  size_t size() const;
};

class PayloadStore {
public:
  virtual ~PayloadStore() = default;
  // Stash raw bytes, return a ref the encoder can later resolve.
  virtual PayloadRef store(Buffer::Instance&& data, PayloadKind kind) = 0;
  // Materialize a ref back into a buffer (may be async for External).
  virtual void fetch(const PayloadRef&, FetchCallback cb) = 0;
};
```

Initial implementations:
- `InMemoryPayloadStore` (default, threshold-bounded).
- `FileApiPayloadStore` (offloads above threshold to the configured
  file API / object store).

The decoder owns a `PayloadStore*` and, when a field crosses a
configured byte threshold during streaming, emits an `External` ref
instead of an `Inline`/`Buffered` one. The encoder resolves refs back
into the outbound JSON-RPC buffer.

### 4.3 `JsonRpcDecoder` / `JsonRpcEncoder`

`codec/json_rpc_decoder.h` exposes a streaming interface modeled on the
existing `McpJsonParser` (see
`source/extensions/filters/http/mcp/mcp_json_parser.h`). Key properties:

```cpp
class JsonRpcDecoder : public Logger::Loggable<Logger::Id::filter> {
public:
  JsonRpcDecoder(const DecoderConfig&, PayloadStore&);
  absl::Status onData(absl::string_view chunk);  // incremental
  absl::Status onEndStream();
  absl::StatusOr<AiRequest> take();              // owns result
};
```

- Field-level callbacks into a protocol mapper
  (`InferenceMapping` or `AgentMapping`) which know how to translate
  OpenAI/A2A/MCP shapes into `AiRequest` fields.
- Streaming sink so large string fields (`messages[*].content`,
  `tool_call.function.arguments`, `attachments[*].data`) can be
  redirected to `PayloadStore` without ever being concatenated in
  memory.

`JsonRpcEncoder` is the dual: it writes an `AiRequest` back to a
`Buffer::Instance`, resolving `PayloadRef`s lazily (supports async
`fetch()` when a backend demands an inlined body).

### 4.4 Protocol classification

`codec/protocol_classifier.h`:

```cpp
ProtocolKind classify(const Http::RequestHeaderMap&,
                      absl::string_view jsonrpc_method);
```

Decides Inference vs Agent (and which agent dialect) from a combination
of path prefix, `content-type`, an explicit config override, and the
JSON-RPC `method` token. Output drives which sub-chain runs.

## 5. Filter chain surface (`chain/`)

Operators should be able to write an `AiFilter` in a few dozen lines
without touching HTTP plumbing. That is the whole point of this filter.

### 5.1 `AiFilter` interface

`chain/ai_filter.h`:

```cpp
class AiFilter {
public:
  virtual ~AiFilter() = default;

  // Called once per request, in order. Return Continue to advance,
  // StopIteration to pause (filter holds the token, resumes via cb).
  virtual AiFilterStatus onRequest(AiRequest&, AiFilterCallbacks&) = 0;

  // Response path (v0: pass-through; most filters won't override).
  virtual AiFilterStatus onResponse(AiResponse&, AiFilterCallbacks&) {
    return AiFilterStatus::Continue;
  }

  virtual void onDestroy() {}
};
```

### 5.2 `AiFilterCallbacks`

`chain/ai_filter_callbacks.h` — the only way an `AiFilter` interacts
with the world. Deliberately narrow:

```cpp
class AiFilterCallbacks {
public:
  virtual Event::Dispatcher& dispatcher() = 0;
  virtual StreamInfo::StreamInfo& streamInfo() = 0;
  virtual const AiProtocolManagerConfig& config() = 0;

  // Resume after StopIteration.
  virtual void continueRequest() = 0;
  virtual void continueResponse() = 0;

  // Short-circuit the chain and reply directly (e.g. guardrail denial).
  virtual void sendLocalReply(AiResponse&&) = 0;

  // Emit stats / access-log entries in the AI-manager namespace.
  virtual void recordEvent(AiEvent) = 0;
};
```

What is **intentionally not exposed**: `Http::RequestHeaderMap`,
`Buffer::Instance`, route config, cluster manager. If a sub-chain
filter needs them, it should instead promote the concern into the
`AiRequest` model — keeps the AI layer HTTP-agnostic.

### 5.3 `AiFilterChain`

`chain/ai_filter_chain.h` holds an ordered `std::vector<AiFilterPtr>`
and runs the sync state machine (Continue / StopIteration / Error).
Single implementation used by both sub-chains; the distinction is
purely configuration.

### 5.4 `InferenceChain` / `AgentChain`

`chain/inference_chain.h` and `chain/agent_chain.h` are thin typed
façades over `AiFilterChain`. They exist so:

- Registration factories live in separate namespaces
  (`InferenceFilterFactoryRegistry`, `AgentFilterFactoryRegistry`) and
  can be searched independently.
- Future protocol-specific helpers (e.g. `InferenceChain::modelTarget()`
  accessor, `AgentChain::sessionId()`) have a natural home without
  polluting the shared base.

### 5.5 Sub-chain configuration

Proto sketch (names only):

```
AiProtocolManager
├── inference_chain
│   ├── filters []       // repeated AiFilterConfig
│   └── dispatch         // InferenceDispatchConfig
├── agent_chain
│   ├── filters []
│   └── dispatch         // AgentDispatchConfig
├── codec
│   ├── max_inline_bytes
│   ├── payload_store    // InMemory | FileApi { uri, creds, … }
│   └── protocol_override
└── classifier           // path prefixes, method allowlist, …
```

Each `AiFilterConfig` is `{ name, typed_config }` matching existing
Envoy idioms; factories register against
`Envoy::Registry::FactoryRegistry<Chain::AiFilterFactory>`.

## 6. Terminal dispatch (`dispatch/`)

`AiDispatchFilter` is the tail of a sub-chain. It is **not** an
`AiFilter` — it owns the async client, so it sits outside the chain
abstraction the way `router` sits outside `http_filters`.

Responsibilities:

1. Invoke `JsonRpcEncoder` to serialize the (possibly rewritten)
   `AiRequest`.
2. Resolve per-backend routing: one or N backends (fanout), which
   cluster / path / auth header set.
3. Open streams via `Http::AsyncClient` (reuse the
   `MuxDemux`/`MultiStream` primitives already used by `mcp_router`, see
   `source/extensions/filters/http/mcp_router/backend_stream.h`).
4. Aggregate / stream responses back to the outer
   `AiProtocolManagerFilter`, which forwards to the downstream caller.

`InferenceDispatchFilter` and `AgentDispatchFilter` subclass
`AiDispatchFilter` and supply:

- Backend selection strategy (model-based vs capability-based).
- Response shape expectations (`chat.completions` chunk framing vs
  JSON-RPC result / SSE `message` events).
- Error taxonomy mapping back into `AiResponse`.

## 7. Request lifecycle

```
decodeHeaders
  → classify(protocol) → pick SubChain
  → install PayloadStore
  → StopIteration, wait for body

decodeData (streaming)
  → JsonRpcDecoder::onData
  → large fields flushed to PayloadStore as External refs

decodeTrailers / end_stream
  → JsonRpcDecoder::onEndStream → AiRequest
  → SubChain::run(AiRequest)
       ├ AiFilter #1 onRequest → Continue
       ├ AiFilter #2 onRequest → StopIteration … continueRequest()
       └ …
  → DispatchFilter
       ├ JsonRpcEncoder → Buffer
       ├ Http::AsyncClient → upstream(s)
       ├ aggregate responses → AiResponse
       └ SubChain::runResponse(AiResponse)  // v0: no-op
  → AiProtocolManagerFilter::sendDownstreamResponse
```

## 8. Stats & observability

`filter_config.h` defines the stat struct (pattern copied from
`McpRouterStats`):

```
AI_PROTOCOL_MANAGER_STATS(COUNTER)
  rq_total
  rq_inference
  rq_agent
  rq_classify_unknown
  rq_decode_error
  rq_encode_error
  rq_payload_offloaded
  rq_chain_stop
  rq_local_reply
  rq_dispatch_failure
```

Plus per-sub-chain histograms for decode/encode/dispatch latency.

## 9. Threading & lifetime

- Filter is per-stream, owned by the HTTP filter manager — same as
  `McpRouterFilter`.
- `PayloadStore` is per-filter by default; a pooled implementation
  (shared across streams on the same worker) is a later addition.
- `AiFilter` instances are per-stream and destroyed in `onDestroy()`
  along with the owning filter.
- No cross-worker state in v0.

## 10. Testing strategy (structural)

```
test/extensions/filters/http/ai_protocol_manager/
├── codec/
│   ├── json_rpc_decoder_test.cc
│   ├── json_rpc_encoder_test.cc
│   ├── inference_mapping_test.cc
│   ├── agent_mapping_test.cc
│   └── payload_store_test.cc
├── chain/
│   ├── ai_filter_chain_test.cc
│   └── fake_ai_filter.h          # test helper
├── dispatch/
│   ├── inference_dispatch_test.cc
│   └── agent_dispatch_test.cc
├── filter_test.cc                # unit, with mock decoder/chain
├── integration/
│   ├── inference_integration_test.cc
│   └── agent_integration_test.cc
└── BUILD
```

A `fake_ai_filter.h` that records `onRequest` invocations is the
canonical way to write sub-chain tests; keeps the AI layer verifiable
without any HTTP spinup.

## 11. Open questions (to iterate on)

1. **Chain composition**: do we allow a single request to traverse
   both chains (e.g. agent invoking inference), or is that modeled
   as two separate requests? Current draft assumes the latter.
2. **Backpressure to offload**: what is the exact threshold policy —
   per-field byte limit, cumulative budget, or adaptive based on
   cluster memory pressure?
3. **Response streaming**: v0 treats dispatch as request/response.
   SSE / chunked streaming (OpenAI stream, A2A events) needs a
   response-side equivalent of `PayloadRef` and is sketched but not
   specified.
4. **Auth / identity propagation**: do we reuse `mcp_router`'s
   `SubjectSource` abstraction verbatim, generalize it, or require
   upstream filters to populate `AiRequest::headers().attributes`?
5. **Per-route overrides**: probable, modeled after `McpOverrideConfig`;
   not yet specified which fields are overridable per route.
