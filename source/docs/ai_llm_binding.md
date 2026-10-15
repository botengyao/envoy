# LLM bindings

Status: proposal, 2026-10-15. The API is in this change; the behavior lands in the follow-ups in
[Plan](#plan).

## Problem

Claude on Vertex AI (`rawPredict`, `streamRawPredict`) serves the Anthropic Messages API in a
different envelope: the model goes in the path and must not be in the body, and the body needs
`anthropic_version: vertex-2023-10-16`. Today:

- An OpenAI or Gemini client cannot reach it: the transcoder leaves `model` in the body and never
  writes `anthropic_version`.
- A Vertex AI client cannot be transcoded to OpenAI or Gemini: `anthropic_version` leaks to the
  backend, schema validation rejects the body for lacking `model`, request_info records no model.
- Behind a dynamic forward proxy, with no per-route configuration, no AI filter runs at all.

Bedrock InvokeModel, Azure OpenAI and Gemini on Vertex AI differ from their APIs in the same ways.

## Design

1. `LLMProtocol` stays the API. A provider is not an API, so it gets no value of its own.
2. `LLMBinding` is how a provider carries an API on HTTP: a URI pattern and a list of edits to the
   body and headers.
3. The AI Protocol Manager core applies bindings at the edges of the AI filter chain. On the way
   in it undoes the client's binding, so every AI filter, the transcoder included, sees the API's
   own document. On the way out it applies the backend's.
4. Filter state alone can instruct a request: a filter ahead sets the APIs, the bindings and
   the model, with or without per-route configuration. The binding keys replace today's
   `envoy.ai.uri_pattern.*` keys.

## API

```proto
// envoy/type/ai/v3/llm_binding.proto
message LLMBinding {
  message Mutation {
    oneof target {
      string body_field = 1;              // a top-level body member
      string header = 2;
    }
    google.protobuf.Value value = 3;      // unset: remove the target
    bool keep_existing = 4;               // write only where the target is absent
  }
  string uri_pattern = 1;                 // {model} etc. from the body; {unary|stream} from stream
  repeated Mutation mutations = 2;        // applied in order
}
```

Also: `RequestPerRoute.binding` and `ResponsePerRoute.binding` (one each), and
`AiProtocolManager.bindings`, a `map<string, LLMBinding>` that filter state can name. All three are
hidden until implemented.

A binding has two parts. The URI pattern is a two-way map between the request's path and its
named values. The mutations edit the body and headers around the API's document. Coming in, the
client's binding is read and undone, so AI filters see the API's own document; going out, the
backend's binding is applied. Routing and the host stay with the route and the cluster. Either part
left empty is the API's own: Gemini's own mutations remove `model` and `stream`, which its path
carries.

The pattern's syntax is today's: a URI template in `path_match_policy` syntax, at most one
`{unary|stream}` choice, several layouts separated by spaces (matching tries each, rendering writes
the first), and a query on a spelling, which is rendered but never read.

### Read rules: coming in, the client's binding

1. **Match.** The client's path, without its query, is matched against the binding's layouts; with
   no binding given, against the API's own layouts and those Envoy knows for it. The first layout
   that fits the whole path is used. A given binding that does not match reads nothing, as today.
2. **Values.** Each named variable gives a value; unnamed wildcards and the query give none, and
   the query can carry credentials, such as the Gemini API's `key`. Every value must be a token of
   letters, digits and `-._@`, so none can escape its segment. A path whose values are not tokens
   does not match.
3. **Fields.** A value named after a top-level field of the API's request is that field; `model`
   and `stream` count for every API, and the choice is `stream` (its first spelling false, its
   second true). It is written into the body. For a field the binding removes, the path is its
   only home and the path's value wins; otherwise the body's value wins.
4. **Path variables.** Any other value, such as `{project}`, is recorded on the
   `envoy.ai.binding.request` object and never written into the body. Filters and access logs read
   it as `%FILTER_STATE(envoy.ai.binding.request:FIELD:project)%`.
5. **Undo.** Each body field a mutation writes is removed, and its value kept for rule 11. Header
   mutations are not undone.

### Mutation rules: going out, the backend's binding

6. **Model.** `envoy.ai.model.resolved`, when set, replaces the body's `model`.
7. **Validate.** The document is validated against the backend API's schema before any mutation,
   so a field the API requires and the provider moves into the path (`model` on Vertex AI) is still
   there.
8. **Render.** Each variable is filled from the first of: the body field of its name; the path
   variables given to the backend binding for this request; the path variables read in rule 4. A
   variable without a value fails the request with a 500 (`unresolved`), and every value must be a
   token. A variable filled from the client's path is the client's choice, so pin `{project}`
   unless the client may pick it.
9. **Mutate,** in order. Each mutation targets a top-level body field or a header:

   | Edit | Mutation |
   |---|---|
   | Remove a body field | `{ body_field: model }` |
   | Replace, or add, a body field | `{ body_field: max_tokens, value: 4096 }` |
   | Add a body field where absent | `{ body_field: anthropic_version, value: vertex-2023-10-16, keep_existing: true }` |
   | Set a header | `{ header: x-llm-model, value: "{model}" }` |
   | Add a header where absent | `{ header: anthropic-version, value: "2023-06-01", keep_existing: true }` |
   | Remove a header | `{ header: x-api-key }` |

10. **Placeholders.** `{name}` in a string value reads the same values as rule 8, for example a
    header `x-goog-user-project: {project}`. A header's value must be a string.
11. **Same binding.** A request leaving in the binding it arrived in is rendered from what rule 4
    read and gets back the body values rule 5 removed, so only a resolved model changes it.

Nothing in the rules names a provider or a field: `model` and `stream` appear only because every
API's request has them. A gateway's `/tenants/{tenant}/llm/{model}` reads `tenant` as a path
variable, and an OpenAI-shaped `/users/{user}/chat/completions` would read the body's `user`.

What the rules replace in today's engine (`transcoding_engine.cc`, `uri_pattern.cc`):

| Today | Rule |
|---|---|
| Only `model` and `stream` move between path and body (`kModelField`, `kStreamField`) | 3: any variable named after a request field |
| Fields leave the body only when the pack has an envelope (`erase_fields = envelope.has_value()`) | 9: removal mutations, per binding |
| Gemini's layouts compiled into its pack (`DialectTranscodePack::envelope`) | Gemini's own binding, as data |
| The body always wins over the path (`liftFromRequestPath`) | 3: the path wins for a field the binding removes |
| `UriPattern::match()` reads only `{model}`; `render()` refuses other variables | 2, 4 and 8: every named variable |
| The document is validated after `model` and `stream` are erased | 7: validate before mutating |
| No way to add a body field or a header | 9 |

### Example

A Vertex AI client of Claude, sent to Gemini in the same project and region:

```
client     POST /v1/projects/acme/locations/us-east5/publishers/anthropic/models/claude-sonnet-4-5@20250929:streamRawPredict
reads      fields: model = claude-sonnet-4-5@20250929, stream = true
           path variables: version = v1, project = acme, location = us-east5

backend    uri_pattern: "/{version}/projects/{project}/locations/{location}/publishers/google/models/{model}:{generateContent|streamGenerateContent?alt=sse}"
           envoy.ai.model.resolved = gemini-2.5-flash

upstream   POST /v1/projects/acme/locations/us-east5/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse
```

The backend binding sets no mutations, so Gemini's own apply and `model` and `stream` leave the
body. A `set_filter_state` placed after the AI Protocol Manager can send the request to the region
the client addressed:

```yaml
- object_key: envoy.upstream.dynamic_host
  format_string:
    text_format_source:
      inline_string: "%FILTER_STATE(envoy.ai.binding.request:FIELD:location)%-aiplatform.googleapis.com"
```

Layouts Envoy knows, for recognizing clients:

| API | Layouts |
|---|---|
| `ANTHROPIC_MESSAGES` | `/v1/messages`; `/{version}/projects/{project}/locations/{location}/publishers/anthropic/models/{model}:{rawPredict\|streamRawPredict}` |
| `GEMINI_GENERATE_CONTENT` | `/v1beta/models/{model}:{generateContent\|streamGenerateContent?alt=sse}`; the same under `/{version}/projects/{project}/locations/{location}/publishers/google/models/` |
| `OPENAI_CHAT_COMPLETIONS`, `OPENAI_RESPONSES` | `/v1/chat/completions`, `/v1/responses` |

Vertex AI's `count-tokens` model id is not a match: that endpoint keeps `model` in the body.

## Filter state

| Key | Value | Read | When unset |
|---|---|---|---|
| `envoy.ai.llm_protocol.request` | API name | `decodeHeaders`; marks an AI request | the route's; else not an AI request |
| `envoy.ai.binding.request` | binding | before the first AI filter | the route's; else recognized from the path; else the API's own |
| `envoy.ai.llm_protocol.response` | API name | backend-side transcoder leg | the route's; else the client's API, untranscoded |
| `envoy.ai.binding.response` | binding | at the sink | the route's; else the binding the request arrived in, when the API did not change; else the API's own |
| `envoy.ai.model.resolved` | model | at the sink | the client's model |

`envoy.ai.binding.*` replaces the `envoy.ai.uri_pattern.*` keys (#48082). A binding with only a
pattern is what the old key held, so an existing `set_filter_state` entry changes only its key.
A binding key holds a typed object, written as one of:

| Written as | Example | For |
|---|---|---|
| A name | `vertex_claude` | a binding in `AiProtocolManager.bindings`: a hash lookup, checked at config load. The fast path. |
| A name with path variables | `vertex_claude?project=acme&location=us-east5` | the same binding, with variables chosen per request |
| A pattern | `/gateway/anthropic/{model}/{messages\|messages-stream}` | a binding with only a path, as the old key |
| JSON | `{"uri_pattern":"...","mutations":[...]}` | any binding, spelled out per request |
| C++ | `LlmBindingObject` | a filter that sets the object, or updates it in place with `getDataMutable()`, copying on the first change |

The first character tells them apart: `/` is a pattern, `{` is JSON, anything else a name. A value
that does not resolve or parse fails the request with a 500 (`unresolved`) where it is read. Only
trusted filters write these keys: a binding edits the body and headers, and its variables choose
path segments.

### Objects

`envoy.ai.binding.request` and `envoy.ai.binding.response` hold one object per request. It points
at a shared, immutable binding, and carries what a writer gave and, on the request side, what the
core read from the client's path.

```cpp
// The runtime form of an LLMBinding: built once, from configuration or from one write, then shared
// between requests and never changed.
struct LlmBinding {
  struct Mutation {
    enum class Target { BodyField, Header };
    Target target;
    std::string name;                     // the body field, or the lower-cased header
    std::optional<nlohmann::json> value;  // nullopt: remove the target
    bool keep_existing{false};
  };
  std::optional<UriPattern> pattern;      // compiled once; nullopt: the API's own path
  std::vector<Mutation> mutations;        // empty: the API's own edits
};

class LlmBindingObject : public Router::StringAccessor {
public:
  // What the core read from the client's path; request side only.
  struct Read {
    std::string model;                                             // "" when the path names none
    std::optional<bool> stream;                                    // unset when the path does not say
    absl::flat_hash_map<std::string, std::string> path_variables;  // project, location, version
  };

  explicit LlmBindingObject(std::shared_ptr<const LlmBinding> binding);  // from C++
  // From the factory: "name", "name?k=v", "/pattern" or "{json}". Never null: a bad value keeps
  // its error, reported where the object is read.
  static std::shared_ptr<LlmBindingObject> fromBytes(absl::string_view value);

  absl::Status resolve(const BindingTable& named, LLMProtocol api);  // the core, at the read point
  const LlmBinding* binding() const;                                  // null until resolved
  const absl::flat_hash_map<std::string, std::string>& variables() const;
  void setVariable(absl::string_view name, absl::string_view value);  // C++ update
  LlmBinding& mutableBinding();           // C++ update: copies the shared binding first
  const std::optional<Read>& read() const;
  void setRead(Read read);                // the core, after matching the client's path

  absl::string_view asString() const override;                // the value as written
  bool hasFieldSupport() const override { return true; }
  FieldType getField(absl::string_view name) const override;  // model, stream, path variables

private:
  std::string source_;                    // as written
  std::string name_;                      // still to resolve; empty once resolved
  std::shared_ptr<const LlmBinding> binding_;
  absl::flat_hash_map<std::string, std::string> variables_;  // "?k=v", or set from C++
  std::optional<Read> read_;
  absl::Status status_;                   // a parse or resolve error
};
```

| Member | Set by | When |
|---|---|---|
| `source_`, `name_`, `variables_` | the writer: `set_filter_state`, Lua, a dynamic module, C++ | before the read point |
| `binding_` | a C++ writer, or `resolve()` for a name | when written, or at the read point |
| `read_` | the core, after matching the client's path | at ingress |
| `status_` | the factory, or `resolve()` | fails the request as `unresolved` at the read point |

The object is a `StringAccessor`, so string readers keep working. So do writers that can only store
a plain string: Golang's `SetFilterState` and the dynamic modules' bytes setter. Readers accept
either, and read a plain string as the factory would.

For a Vertex AI client that arrives with no key set, the core creates the object itself:

```
binding_  the built-in ANTHROPIC_MESSAGES Vertex AI layout; mutations: remove model, add anthropic_version
read_     model = claude-sonnet-4-5@20250929, stream = true,
          path_variables = { version: v1, project: acme, location: us-east5 }
```

`%FILTER_STATE(envoy.ai.binding.request:FIELD:location)%` then reads `us-east5`.

## Examples

Both examples send an OpenAI client to Claude on Vertex AI. The AI Protocol Manager runs the two
transcoder instances as in its docs. Credentials and clusters are as for any route.

### Static: per route

```yaml
routes:
- match: { prefix: /v1/chat/completions }
  route: { cluster: vertex_us_east5 }
  typed_per_filter_config:
    envoy.filters.http.ai_protocol_manager:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
      request: { llm_protocol: OPENAI_CHAT_COMPLETIONS }
      response:
        llm_protocol: ANTHROPIC_MESSAGES
        binding:
          uri_pattern: "/v1/projects/acme/locations/us-east5/publishers/anthropic/models/{model}:{rawPredict|streamRawPredict}"
          mutations:
          - { body_field: model }
          - { body_field: anthropic_version, value: vertex-2023-10-16, keep_existing: true }
```

### Filter state: no routes, behind a dynamic forward proxy

```yaml
http_filters:
- name: envoy.filters.http.set_filter_state
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
    on_request_headers:
    - object_key: envoy.ai.llm_protocol.request
      format_string: { text_format_source: { inline_string: OPENAI_CHAT_COMPLETIONS } }
    - object_key: envoy.ai.llm_protocol.response
      format_string: { text_format_source: { inline_string: ANTHROPIC_MESSAGES } }
    - object_key: envoy.ai.binding.response
      format_string: { text_format_source: { inline_string: "vertex_claude?project=acme&location=us-east5" } }
    - object_key: envoy.ai.model.resolved
      format_string: { text_format_source: { inline_string: claude-sonnet-4-5@20250929 } }
    - object_key: envoy.upstream.dynamic_host
      format_string: { text_format_source: { inline_string: us-east5-aiplatform.googleapis.com } }
- name: envoy.filters.http.ai_protocol_manager
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
    request_handling: {}
    filters: [ ... ]                           # the two transcoder instances
    bindings:
      vertex_claude:
        uri_pattern: "/v1/projects/{project}/locations/{location}/publishers/anthropic/models/{model}:{rawPredict|streamRawPredict}"
        mutations:
        - { body_field: model }
        - { body_field: anthropic_version, value: vertex-2023-10-16, keep_existing: true }
- name: envoy.filters.http.dynamic_forward_proxy
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
    dns_cache_config: { name: dfp }
    allow_dynamic_host_from_filter_state: true
- name: envoy.filters.http.router
```

The constants above are for the example. In practice a decision filter ahead (ext_proc, through
dynamic metadata and `%DYNAMIC_METADATA(...)%`) or a C++ filter writes them per request. The same
key takes any other form:

```
# the binding spelled out
envoy.ai.binding.response = {"uri_pattern":"/v1/projects/acme/locations/us-east5/publishers/anthropic/models/{model}:{rawPredict|streamRawPredict}","mutations":[{"body_field":"model"},{"body_field":"anthropic_version","value":"vertex-2023-10-16","keep_existing":true}]}

# a gateway with the Anthropic API's own body, as envoy.ai.uri_pattern.response did
envoy.ai.binding.response = /gateway/anthropic/{model}/{messages|messages-stream}
```

### On the wire

Both examples send the same request:

```
client    POST /v1/chat/completions
          {"model": "claude-sonnet-4-5@20250929", "stream": true, "max_completion_tokens": 512,
           "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Hi"}]}

upstream  POST /v1/projects/acme/locations/us-east5/publishers/anthropic/models/claude-sonnet-4-5@20250929:streamRawPredict
          {"anthropic_version": "vertex-2023-10-16", "stream": true, "max_tokens": 512,
           "system": "Be brief.", "messages": [{"role": "user", "content": "Hi"}]}
```

The reverse direction needs no binding. An `AnthropicVertex` client sent to OpenAI is recognized
by its path. AI filters see `model` in the body and no `anthropic_version`, and the request leaves
for `/v1/chat/completions`.

## Other providers

A new provider is configuration, not code:

| Provider | `uri_pattern` | `mutations` |
|---|---|---|
| Claude on Vertex AI | `.../publishers/anthropic/models/{model}:{rawPredict\|streamRawPredict}` | remove `model`; add `anthropic_version: vertex-2023-10-16` |
| Gemini on Vertex AI | `.../publishers/google/models/{model}:{generateContent\|streamGenerateContent?alt=sse}` | remove `model`, `stream` |
| Bedrock InvokeModel, Claude | `/model/{model}/{invoke\|invoke-with-response-stream}` | remove `model`, `stream`; add `anthropic_version: bedrock-2023-05-31` |
| Azure OpenAI deployment | `/openai/deployments/{model}/chat/completions?api-version=2024-10-21` | none: `model` stays in the body |
| Gateway that routes on a header | `/v1/chat/completions` | set header `x-llm-model: {model}` |
| Anthropic API, as a backend | `/v1/messages` | add header `anthropic-version: 2023-06-01` |

Later, when a provider needs them: a header copied into the body (InvokeModel's `anthropic_beta`),
response framing (Bedrock's event stream), and query parameters from the body.

## The transcoder contract

Today the transcoder owns the request path. The engine's `TranscodeContext` takes URI patterns in
and gives a rewritten path out, and the transcoder sets `:path`. With bindings, the transcoder only
converts between APIs, on each API's own document, and the core owns the path.

| | Today | With bindings |
|---|---|---|
| Reading the path (`TO_IR`) | the engine lifts `model` and `stream` from `request_path`, by `request_uri_pattern` or `DialectTranscodePack::envelope` | the core, at ingress, by the client's binding |
| Writing the path (`FROM_IR`) | the engine renders `rewritten_path`; the transcoder sets `:path` | the core, at the sink, by the backend's binding |
| Fields leaving the body | the engine erases `model` and `stream` when the pack has an envelope | the backend binding's mutations; Gemini's own remove `model` and `stream` |
| `envoy.ai.model.resolved` | the engine writes it into the body before the `FROM_IR` rules | the core, at the sink, before rendering |
| No backend API | `FROM_IR` fails the request with a 400 | the client's API; both legs pass the document through |
| A Gemini document | no `model` or `stream`: they live in the path | `model` and `stream` at the root, as in every API |

The engine keeps its rules and loses its path code:

```cpp
struct TranscodeContext {
  absl::string_view request_model{};           // response legs: the model the client asked for
  int64_t now_unix_seconds{0};
  TranscodeStreamState* stream_state{nullptr};
  std::string ir_model{};                      // set by request legs
  // Removed: request_path, request_uri_pattern, response_uri_pattern, resolved_model,
  // rewritten_path, request_path_matched.
};
// Removed: DialectTranscodePack::envelope, TranscodingEngine::modelFromRequestPath().
```

`FROM_IR` still validates against the target's schema. It now validates while `model` is still in
the body, which is the order a Vertex AI Claude binding needs, since Anthropic's schema requires
`model`. The transcoder filter takes its two APIs from `AiFilterContext`, which the core resolves.
It reads no filter state, never sets `:path`, and loses `Instructions` and `readInstructions()`.
The engine's URI pattern tests and the transcoder's instruction tests move to the core.

### OpenAI to Gemini on Vertex AI

Today this already works, with three keys:

```
envoy.ai.llm_protocol.response = GEMINI_GENERATE_CONTENT
envoy.ai.uri_pattern.response  = /v1/projects/acme/locations/us-central1/publishers/google/models/{model}:{generateContent|streamGenerateContent?alt=sse}
envoy.ai.model.resolved        = gemini-2.5-flash
```

Without the pattern, the engine renders the Gemini API's `/v1beta/models/...`, which Vertex AI does
not serve. With bindings, per route:

```yaml
response:
  llm_protocol: GEMINI_GENERATE_CONTENT
  binding:
    uri_pattern: "/v1/projects/acme/locations/us-central1/publishers/google/models/{model}:{generateContent|streamGenerateContent?alt=sse}"
```

The binding sets no mutations, so Gemini's own apply. Or per request, behind a dynamic forward
proxy, with `bindings: { vertex_gemini: { uri_pattern: "/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:{generateContent|streamGenerateContent?alt=sse}" } }`:

```
envoy.ai.llm_protocol.request  = OPENAI_CHAT_COMPLETIONS
envoy.ai.llm_protocol.response = GEMINI_GENERATE_CONTENT
envoy.ai.binding.response      = vertex_gemini?project=acme&location=us-central1
envoy.ai.model.resolved        = gemini-2.5-flash
envoy.upstream.dynamic_host    = us-central1-aiplatform.googleapis.com
```

Today's three keys migrate by renaming one of them: `envoy.ai.binding.response` takes the old
pattern as it is.

```
client      POST /v1/chat/completions
            {"model": "gpt-4o", "stream": true, "max_completion_tokens": 512,
             "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Hi"}]}

ingress     OpenAI's own binding: nothing to read

transcoder  TO_IR is the identity, since OpenAI Chat is the IR. FROM_IR converts IR to Gemini and
            validates, with model and stream still at the root:
            {"model": "gpt-4o", "stream": true,
             "systemInstruction": {"parts": [{"text": "Be brief."}]},
             "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
             "generationConfig": {"maxOutputTokens": 512}}

sink        model becomes gemini-2.5-flash; the pattern is rendered; model and stream are removed

upstream    POST /v1/projects/acme/locations/us-central1/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse
            {"systemInstruction": {"parts": [{"text": "Be brief."}]},
             "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
             "generationConfig": {"maxOutputTokens": 512}}
```

Gemini's SSE events come back through the transcoder as OpenAI chunks ending in `data: [DONE]`,
as they do today. Vertex AI's credentials, an OAuth access token, stay with the route.

## What changes where

- **Core:** takes `envoy.ai.llm_protocol.request` as marking an AI request with no route. It
  defaults the backend API to the client's, with no round trip through the IR. It resolves every
  key once and applies bindings at ingress and at the sink, then hands the result to AI filters.
- **Transcoder:** converts between APIs only; see [The transcoder contract](#the-transcoder-contract).
- **request_info:** reads `model` from the body for every API, so Vertex AI clients get
  `envoy.ai.model.request`.
- **Schema validation:** unchanged, and a Vertex AI body passes.
- **Token usage:** unchanged; it keys on `LLMProtocol`.

## Alternatives

- **`ANTHROPIC_MESSAGES_VERTEX`:** one value per API and provider, and every reader keyed on the
  enum gains a case. Envoy AI Gateway took this path and now overloads its `version` field.
- **A `variant` key read by the transcoder:** untyped, and invisible to the other AI filters.

## Plan

1. **API** (this change).
2. **Requests instructed by filter state alone:** activation, the backend API default, and one
   resolver.
3. **Binding objects and the APIs' own bindings,** and `UriPattern` reading every named variable
   (`Match` gains the path variables) and rendering them. No behavior change.
4. **Core ingress and `envoy.ai.binding.request`:** Vertex AI clients work;
   `envoy.ai.uri_pattern.request` is removed, along with the engine's `TO_IR` path code.
5. **Core egress and `envoy.ai.binding.response`:** requests reach Claude on Vertex AI;
   `envoy.ai.uri_pattern.response`, `rewritten_path` and the envelope are removed, and the
   transcoder stops setting `:path`.
