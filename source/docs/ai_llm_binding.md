# LLM bindings

Status: proposal, 2026-10-15. The API is in this change; the behavior lands in the follow-ups in
[Plan](#plan).

## Problem

Claude on Vertex AI (`rawPredict`, `streamRawPredict`) serves the Anthropic Messages API in a
different envelope: the model is in the path and must not be in the body, and the body needs
`anthropic_version: vertex-2023-10-16`. Today:

- An OpenAI or Gemini client cannot reach it. The transcoder's `FROM_IR` leg leaves `model` in the
  body and never writes `anthropic_version` (the TODO in the engine's `transcodeRequest()`).
- A Vertex AI client cannot be transcoded to OpenAI or Gemini. `anthropic_version` survives into
  the IR and the backend rejects it; schema validation rejects the body for lacking `model`;
  request_info records no model.
- `envoy.ai.uri_pattern.*` moves `model` between path and body only as the API's own layout says,
  and only inside the transcoder.
- Behind a dynamic forward proxy, with no per-route configuration, no AI filter runs at all, so no
  filter state key can instruct the request.

Bedrock InvokeModel, Azure OpenAI deployments and Gemini on Vertex AI follow the same pattern, so
the fix must not be specific to Vertex AI.

## Decision

1. `LLMProtocol` stays the API: schemas, stream events, usage. No per-provider values.
2. `LLMBinding` (new, `envoy.type.ai.v3`) says how a provider carries an API on HTTP: a URI
   pattern, where request fields travel other than the body (a path variable, a query parameter,
   a header), and the constants the provider requires. Bindings are data. Envoy defines named ones (`vertex_ai`); an
   operator can spell out their own.
3. The AI Protocol Manager core applies bindings at the two edges of the AI filter chain. Every AI
   filter sees the API's own document. The transcoder only converts between APIs.
4. Filter state alone can instruct a request: a filter ahead of the AI Protocol Manager sets the
   APIs, the bindings, the path and the model, with no per-route configuration, as behind a
   dynamic forward proxy. Route configuration only supplies defaults. The new `envoy.ai.binding.*`
   keys hold a binding for the request, which filters can set and update: by name, a lookup that
   is the fast path, or spelled out. The existing `envoy.ai.uri_pattern.*` keys keep setting its
   path. Both hold typed C++ objects. Existing configurations behave as today.

## API

`api/envoy/type/ai/v3/llm_binding.proto`:

```proto
message LLMBinding {
  message FieldBinding {
    string field = 1;              // a top-level request member: model, stream, ...
    oneof location {
      string path_variable = 2;    // a variable of uri_pattern
      string query_parameter = 3;
      string header = 4;
    }
    bool keep_in_body = 5;         // by default the field leaves the body
  }
  string name = 1;                         // e.g. vertex_ai; supplies defaults for the rest
  string uri_pattern = 2;                  // the transcoder's URI pattern syntax
  map<string, string> path_variables = 3;  // constants for the pattern: project, location
  repeated FieldBinding fields = 4;        // request fields outside the body
  google.protobuf.Struct body_fields = 5;  // constant body fields: anthropic_version
  map<string, string> headers = 6;         // constant headers: anthropic-version
}
```

A binding moves two kinds of data between the body and the rest of the request:

- **Request fields** (`fields`). Any top-level member of the API's request can travel in a path
  variable, a query parameter or a header, instead of the body or, with `keep_in_body`, as well as
  it. On the way in, the core reads each one back into the body.
- **Constants** the provider requires. `path_variables` fill the pattern's other variables,
  `body_fields` and `headers` are written, and a constant query goes in the pattern itself
  (`?api-version=...`). On the way in, `body_fields` are removed.

A pattern variable is filled by the field `fields` places there; else from `path_variables`; else
from the request field of the same name, which then stays in the body as well. So `{model}` alone
works as `envoy.ai.uri_pattern.*` does today. The `{unary|stream}` choice is the variable `stream`.
A variable left unfilled, or a field placed in a variable the pattern does not have, fails the
request as `unresolved`.

`RequestPerRoute.binding` and `ResponsePerRoute.binding` hold one each. Within a binding, `name`
supplies the defaults: `uri_pattern` replaces the named pattern; `path_variables`, `body_fields`
and `headers` merge over the named ones; and a non-empty `fields` replaces the named list.

Bindings Envoy defines (`{version}` defaults to `v1`):

| API | Name | `uri_pattern` | `fields` | Constants |
|---|---|---|---|---|
| `OPENAI_CHAT_COMPLETIONS` | (own) | `/v1/chat/completions` | | |
| `OPENAI_RESPONSES` | (own) | `/v1/responses` | | |
| `ANTHROPIC_MESSAGES` | (own) | `/v1/messages` | | header `anthropic-version: 2023-06-01` |
| `ANTHROPIC_MESSAGES` | `vertex_ai` | `/{version}/projects/{project}/locations/{location}/publishers/anthropic/models/{model}:{rawPredict\|streamRawPredict}` | `model` in `{model}` | body `anthropic_version: vertex-2023-10-16` |
| `GEMINI_GENERATE_CONTENT` | (own) | `/v1beta/models/{model}:{generateContent\|streamGenerateContent?alt=sse}` | `model` in `{model}`, `stream` in `{stream}` | |
| `GEMINI_GENERATE_CONTENT` | `vertex_ai` | `/{version}/projects/{project}/locations/{location}/publishers/google/models/{model}:{generateContent\|streamGenerateContent?alt=sse}` | `model` in `{model}`, `stream` in `{stream}` | |

Vertex AI Claude takes `stream` in the body as well as in the method, so its binding does not
place `stream`: the field fills `{stream}` and stays. Gemini places it, so it leaves the body. The
two Gemini rows are today's `DialectTranscodePack::envelope`. One name serves several APIs:
`vertex_ai` means Vertex AI's layout for whichever API it is used with. Vertex AI's `count-tokens`
model id is not a match: that endpoint keeps `model` in the body.

Providers Envoy does not define are configuration, not code:

| Provider | `uri_pattern` | `fields` | Constants |
|---|---|---|---|
| Bedrock InvokeModel, Claude | `/model/{model}/{invoke\|invoke-with-response-stream}` | `model` in `{model}`, `stream` in `{stream}` | body `anthropic_version: bedrock-2023-05-31` |
| Azure OpenAI deployment | `/openai/deployments/{deployment}/chat/completions?api-version=2024-10-21` | `model` in `{deployment}`, kept in the body | |
| A gateway that routes on a header | `/v1/chat/completions` | `model` in header `x-llm-model`, kept in the body | |

InvokeModel also needs its `anthropic-beta` header moved into the body and its event-stream
framing, which are later primitives (see [Other providers](#other-providers)).

## Filter state

The keys are complete on their own. A filter ahead of the AI Protocol Manager (`set_filter_state`,
Lua, a dynamic module, a C++ filter such as a model router) can instruct every request with no
per-route configuration anywhere; a route's configuration, when there is one, only fills in what
the keys leave unset.

| Key | Value | Read | When unset |
|---|---|---|---|
| `envoy.ai.llm_protocol.request` | `LLMProtocol` name | AI Protocol Manager `decodeHeaders` | the route's `request.llm_protocol`; with neither, the request is not an AI request |
| `envoy.ai.binding.request` (new) | a binding: see below | before the first AI filter | the route's `request.binding`; else the API's binding whose pattern matches the path; else the API's own |
| `envoy.ai.uri_pattern.request` | URI pattern | before the first AI filter | the client binding's pattern |
| `envoy.ai.llm_protocol.response` | `LLMProtocol` name | the backend-side transcoder leg | the route's `response.llm_protocol`; else the client's API, and nothing is transcoded |
| `envoy.ai.binding.response` (new) | a binding: see below | at the sink, after the last AI filter | the route's `response.binding`; else the binding the request arrived in, when the API did not change; else the backend API's own |
| `envoy.ai.uri_pattern.response` | URI pattern | at the sink | the backend binding's pattern |
| `envoy.ai.model.resolved` | model name | at the sink | the model the request names |
| `envoy.ai.model.request` | model name | written by request_info | |

### The binding object

`envoy.ai.binding.*` holds a binding for one request, which filters can set and update until it is
read. A name is only the fastest way to start one.

| Written as | Cost per request | Use |
|---|---|---|
| `acme_vertex` | a hash lookup, then a shared pointer | a binding the filter's `bindings` or Envoy defines: the common case, checked at config load |
| `vertex_ai?project=acme&location=us-east5` | a short parse | a defined binding with the variables chosen per request |
| `{"uri_pattern":"/llm/{model}/{messages\|messages-stream}","fields":[...],"body_fields":{...}}` | a JSON parse and a pattern compile | a binding no configuration defines, spelled out per request: an `LLMBinding` in JSON |
| a C++ `LlmBinding` | none, when built at the writer's config load | a C++ filter, which can also update the object in place |

- **The lookup is an optimization.** Whatever a name stands for can also be written out per
  request, or built in C++. Names are resolved where the binding is read, against the filter's
  `bindings` and then Envoy's, because an object factory cannot see the filter's configuration.
- **Updates.** A later filter can replace the object by writing the key again, or change only the
  path with `envoy.ai.uri_pattern.*`. A C++ filter can also update it in place
  (`getDataMutable<LlmBindingObject>()`), for example to move a request to another location after
  reading its body; the object copies its shared starting point on the first change, so a
  binding shared between requests is never modified. Changes count until the read point in the
  table; an AI filter can still change the backend's binding, which is read at the sink.
- **Merging.** Each layer is merged field by field over the one below it: the filter state object
  over the route over the named defaults. `name` and `uri_pattern` replace; `path_variables`,
  `body_fields` and `headers` merge; and a non-empty `fields` replaces. A `uri_pattern` key
  replaces the pattern last. So a route can fix a tenant's project and location while a filter
  ahead picks the binding by name.
- **Trust.** Only trusted filters write these keys: a binding can set body fields and headers.
  Never fill path variables from a client header: the client would choose the project billed
  under the gateway's credentials.
- **Validation.** A name that neither the filter's `bindings` nor Envoy defines for the API, a
  binding that does not parse or validate, or a pattern that does not parse fails the request
  with a 500, counted as `unresolved`. The factories never reject a non-empty value: an error
  travels in the object to the point of use. `set_filter_state` drops a value its factory
  rejects, at debug level, so rejecting there would send the request in the wrong shape instead of
  failing it. A separate change should build constant `set_filter_state` values once at config
  load, and reject the config when that fails; it helps every key.
- **Timing.** `envoy.ai.llm_protocol.request` must be set during an earlier filter's request
  headers, because it decides whether the body is held and parsed at all. The others can be set
  later, up to the point the table names.
- **Not AI keys.** The host stays with routing: behind a dynamic forward proxy the same filter sets
  `envoy.upstream.dynamic_host` (with `allow_dynamic_host_from_filter_state`) or `:authority`, and
  the provider's credentials.

With no binding anywhere and no `envoy.ai.binding.*` key, a pattern key behaves as today: it sets
the path, and the body keeps the API's own shape.

### Objects

```cpp
// The runtime form of an LLMBinding. Built from configuration once and shared between requests,
// or built for one request.
struct LlmBinding {
  struct FieldPlacement {
    enum class Location { PathVariable, QueryParameter, Header };
    std::string field;
    Location location;
    std::string target;  // the variable, parameter or header name
    bool keep_in_body;
  };
  std::string name;
  std::optional<UriPattern> pattern;  // compiled once
  absl::flat_hash_map<std::string, std::string> path_variables;
  std::vector<FieldPlacement> fields;
  nlohmann::json body_fields;  // an object
  std::vector<std::pair<Http::LowerCaseString, std::string>> headers;
};

// envoy.ai.binding.*: one request's binding, copied from its shared starting point on first change.
class LlmBindingObject : public Router::StringAccessor {
public:
  explicit LlmBindingObject(std::shared_ptr<const LlmBinding> binding);  // from C++
  static std::unique_ptr<LlmBindingObject> fromBytes(absl::string_view value);  // the factory
  // The binding with the name resolved; an error when it does not resolve or did not parse.
  absl::StatusOr<const LlmBinding*> resolve(const BindingTable& named, LLMProtocol api) const;
  LlmBinding& mutableBinding();       // copy on write
  absl::string_view asString() const override;  // the value as written, or the name
};

// envoy.ai.uri_pattern.*: the pattern compiled when the object is created.
class UriPatternObject : public Router::StringAccessor {
public:
  explicit UriPatternObject(absl::StatusOr<UriPattern> pattern);
  absl::string_view asString() const override;  // the pattern as written
};
```

- **Factory writers** (`set_filter_state`, Lua's `filterState():set()`, dynamic modules' typed
  setter) write any form in the table above as text.
- **String writers** (the Golang filter, dynamic modules' bytes setter) store a plain
  `Router::StringAccessor`. Readers accept one, and read its string as the factory would.
- Both objects are `StringAccessor`s, so `%FILTER_STATE(envoy.ai.uri_pattern.response:PLAIN)%`
  and other string readers of today's key keep working. Today the transcoder recompiles the
  pattern on every read; with the typed object it compiles once per write.

## Without routes

Today these keys cannot instruct a request behind a dynamic forward proxy, where no route carries
per-route configuration:

- The AI Protocol Manager reads `envoy.ai.llm_protocol.request` only on a route that declares
  `request` (`decodeHeaders()` in `filter.cc`). Elsewhere the request is not an AI request, no AI
  filter runs, and every other key is ignored.
- With no backend API declared, the transcoder's `FROM_IR` leg fails the request with a 400
  (`unresolved`), even when the backend speaks the client's API.

So this design also requires:

1. **Activation by filter state.** `envoy.ai.llm_protocol.request`, when set, makes the request an
   AI request with or without per-route configuration. Response processing and token usage treat it
   as configured.
2. **Defaults without a route.** The backend API defaults to the client's. When the two are the
   same, both transcoder legs pass the document through, with no round trip through the IR, which
   is lossy.
3. **`envoy.ai.model.resolved` at the sink**, so it applies with or without transcoding.
4. **One resolver.** The core resolves the instructions once, at the read points above, and hands
   them to AI filters through `AiFilterContext`. The transcoder and token usage stop combining
   route configuration and filter state each on their own, so they cannot disagree.

## Request flow

```
client ─▶ core ingress ─────────────▶ AI filters ─▶ core egress ───────────────▶ upstream
          match the client binding                  validate as the backend API
          read its fields into the body             render :path, place its fields
          remove its body_fields                    write body_fields and headers
```

AI filters get the API's own document: `model` and `stream` at the root whenever the request names
them, and no provider-only fields. `AiFilterContext` carries the client's binding, read-only, for
telemetry.

- Ingress runs before `FilterManager::startRequest()` in `filter.cc`; egress in `runSink()` before
  serialization in `request_filter_manager.cc`.
- Validate before adapting: Anthropic's schema requires `model`, which Vertex AI's body must not
  carry.
- A field read from outside the body wins over a body value, unless the binding keeps it in the
  body too, in which case the body's wins. (Today the body always wins.)
- A request that leaves in the binding it arrived in gets its client's `body_fields` values back.
  With `reserialize_body: DISABLE` the received bytes are forwarded only in that case; otherwise
  the core serializes.

## How each part handles rawPredict

- **Core:** identifies, normalizes and adapts, as above.
- **Transcoder:** converts between APIs only. It loses its path code: `DialectTranscodePack::envelope`
  becomes the binding table, and `TranscodeContext`'s URI patterns, `rewritten_path` and
  `modelFromRequestPath()` go. Response legs do not change: Vertex AI's responses and streams are
  the Anthropic API's.
- **request_info:** reads `model` and `stream` from the body for every API; `readGeminiTarget()`
  and the path argument go. It records the binding's name. `envoy.ai.model.request` is now set for
  Vertex AI clients too.
- **Schema validation:** validates as today, and a Vertex AI body passes because `model` has been
  lifted. Its path detection (`detectFromHeaders()`) moves into the core's recognition; payload
  detection stays as the fallback.
- **Token usage:** unchanged; it keys on the response's `LLMProtocol`.

## Examples

Every example uses this filter; only the routes differ. Credentials and clusters are as for any
route to that provider and are left out.

```yaml
http_filters:
- name: envoy.filters.http.ai_protocol_manager
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
    request_handling: {}
    filters:
    - name: envoy.http.ai_filters.schema_validation
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.http.ai_filters.schema_validation.v3.SchemaValidation
    - name: envoy.http.ai_filters.request_info
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.http.ai_filters.request_info.v3.RequestInfo
    - name: envoy.http.ai_filters.transcoder      # client side
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
        request_handling: TO_IR
        response_handling: FROM_IR
    - name: envoy.http.ai_filters.transcoder      # backend side
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
        request_handling: FROM_IR
        response_handling: TO_IR
- name: envoy.filters.http.router
```

Request bodies below are trimmed to the fields that change.

### 1. OpenAI client to Claude on Vertex AI, per route

```yaml
- match: { prefix: /v1/chat/completions }
  route: { cluster: vertex_us_east5 }
  typed_per_filter_config:
    envoy.filters.http.ai_protocol_manager:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
      request: { llm_protocol: OPENAI_CHAT_COMPLETIONS }
      response:
        llm_protocol: ANTHROPIC_MESSAGES
        binding: { name: vertex_ai, path_variables: { project: acme, location: us-east5 } }
```

```
client   POST /v1/chat/completions
         {"model": "claude-sonnet-4-5@20250929", "stream": true, "max_completion_tokens": 512,
          "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Hi"}]}

upstream POST /v1/projects/acme/locations/us-east5/publishers/anthropic/models/claude-sonnet-4-5@20250929:streamRawPredict
         {"anthropic_version": "vertex-2023-10-16", "stream": true, "max_tokens": 512,
          "system": "Be brief.", "messages": [{"role": "user", "content": "Hi"}]}
```

`stream: true` picks `streamRawPredict` and stays in the body, as Vertex AI requires. The
Anthropic SSE stream comes back as OpenAI chunks ending in `data: [DONE]`.

### 2. The same, chosen per request

A route that normally goes to the Anthropic API, with a model router or `set_filter_state` sending
some requests to Vertex AI. Three of these keys are the ones the transcoder reads today;
`envoy.ai.binding.response` is new.

```yaml
envoy.filters.http.set_filter_state:
  "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
  on_request_headers:
  - object_key: envoy.ai.llm_protocol.response
    format_string: { text_format_source: { inline_string: ANTHROPIC_MESSAGES } }
  - object_key: envoy.ai.binding.response
    format_string: { text_format_source: { inline_string: vertex_ai } }
  - object_key: envoy.ai.uri_pattern.response
    format_string:
      text_format_source:
        inline_string: "/v1/projects/acme/locations/us-east5/publishers/anthropic/models/{model}:{rawPredict|streamRawPredict}"
  - object_key: envoy.ai.model.resolved
    format_string: { text_format_source: { inline_string: "claude-sonnet-4-5@20250929" } }
```

The upstream request is the one in example 1, whatever model the client named; the response
reports the client's model. Without `envoy.ai.binding.response`, the request goes to the same
path but keeps `model` in the body and lacks `anthropic_version` (today's behavior), and Vertex AI
rejects it.

### 3. Claude on Vertex AI client to OpenAI

An `AnthropicVertex` SDK client, or Claude Code set up for Vertex AI, with its base URL pointed at
Envoy.

```yaml
- match: { prefix: /v1/projects/ }
  route: { cluster: openai }
  typed_per_filter_config:
    envoy.filters.http.ai_protocol_manager:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
      request: { llm_protocol: ANTHROPIC_MESSAGES }   # vertex_ai is recognized from the path
      response: { llm_protocol: OPENAI_CHAT_COMPLETIONS }
# plus envoy.ai.model.resolved = gpt-5, from a model router or set_filter_state
```

```
client      POST /v1/projects/acme/locations/us-east5/publishers/anthropic/models/claude-sonnet-4-5@20250929:streamRawPredict
            {"anthropic_version": "vertex-2023-10-16", "stream": true, "max_tokens": 512,
             "system": "Be brief.", "messages": [{"role": "user", "content": "Hi"}]}

AI filters  {"model": "claude-sonnet-4-5@20250929", "stream": true, "max_tokens": 512,
             "system": "Be brief.", "messages": [{"role": "user", "content": "Hi"}]}

upstream    POST /v1/chat/completions
            {"model": "gpt-5", "stream": true, "stream_options": {"include_usage": true},
             "max_completion_tokens": 512,
             "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Hi"}]}
```

Schema validation passes, request_info records `claude-sonnet-4-5@20250929` as
`envoy.ai.model.request`, and `anthropic_version` never reaches OpenAI. The OpenAI stream comes
back as Anthropic SSE events, which `AnthropicVertex` reads as it reads Vertex AI's.

### 4. Claude on Vertex AI client to Gemini on Vertex AI

As example 3, with `response: { llm_protocol: GEMINI_GENERATE_CONTENT, binding: { name: vertex_ai,
path_variables: { project: acme, location: us-central1 } } }` and `envoy.ai.model.resolved =
gemini-2.5-flash`. The same name, `vertex_ai`, now means the `google` publisher's layout.

```
upstream    POST /v1/projects/acme/locations/us-central1/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse
            {"systemInstruction": {"parts": [{"text": "Be brief."}]},
             "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
             "generationConfig": {"maxOutputTokens": 512}}
```

No `model`, `stream` or `anthropic_version` in the body: Gemini's bindings carry the first two in
the path, and the third was removed on the way in.

### 5. Claude on Vertex AI, passed through

As example 3, routed to Vertex AI and with no `response`: the backend speaks the client's API, so
the request leaves in the binding it arrived in. Path and body go out as the client sent them, `anthropic_version` included,
and the AI filters still see the model. With `envoy.ai.model.resolved =
claude-opus-4-1@20250805`, only the model in the path changes; the project and location are the
ones the client's path named.

### 6. Vertex AI behind a gateway prefix

A binding's name and pattern are set separately, so a provider's body shape can be reached at
another path. Per route:

```yaml
response:
  llm_protocol: ANTHROPIC_MESSAGES
  binding:
    name: vertex_ai
    uri_pattern: "/gw/vertex/v1/projects/{project}/locations/{location}/publishers/anthropic/models/{model}:{rawPredict|streamRawPredict}"
    path_variables: { project: acme, location: us-east5 }
```

or per request, `envoy.ai.binding.response = vertex_ai` with
`envoy.ai.uri_pattern.response = /gw/vertex/v1/projects/acme/locations/us-east5/publishers/anthropic/models/{model}:{rawPredict|streamRawPredict}`.

### 7. A provider Envoy does not define: Azure OpenAI

A binding with no name spells everything out. Azure OpenAI names the deployment in the path and
the API version in the query, and accepts `model` in the body as well:

```yaml
response:
  llm_protocol: OPENAI_CHAT_COMPLETIONS
  binding:
    uri_pattern: "/openai/deployments/{deployment}/chat/completions?api-version=2024-10-21"
    fields: [ { field: model, path_variable: deployment, keep_in_body: true } ]
# plus envoy.ai.model.resolved = gpt-4o-prod, the deployment name
```

```
upstream    POST /openai/deployments/gpt-4o-prod/chat/completions?api-version=2024-10-21
            {"model": "gpt-4o-prod", "messages": [...]}
```

Naming the variable `{model}` instead would need no `fields` entry: an unplaced field fills the
variable of its own name and stays in the body.

### 8. Behind a dynamic forward proxy, instructed by a filter ahead

One catch-all route to the dynamic forward proxy cluster, and no `typed_per_filter_config` for the
AI Protocol Manager anywhere. The operator describes the providers once, in the filter's
`bindings`; a filter ahead picks one per request by name.

```yaml
http_filters:
- name: envoy.filters.http.ext_proc          # decides; see below
- name: envoy.filters.http.set_filter_state  # copies the decision into the keys
- name: envoy.filters.http.ai_protocol_manager
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
    request_handling: {}
    filters: [ ... ]                         # as above
    bindings:
      acme_vertex:                           # Vertex AI, with the tenant's project fixed
        name: vertex_ai
        path_variables: { project: acme, location: us-east5 }
      llm_gateway:                           # an internal gateway Envoy has no binding for
        uri_pattern: "/llm/{model}/{messages|messages-stream}"
        fields: [ { field: model, path_variable: model } ]
        body_fields: { anthropic_version: vertex-2023-10-16 }
      header_gateway:                        # a gateway that routes on a header
        fields: [ { field: model, header: x-llm-model, keep_in_body: true } ]
- name: envoy.filters.http.dynamic_forward_proxy
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
    dns_cache_config: { name: dfp }
    allow_dynamic_host_from_filter_state: true
- name: envoy.filters.http.router
route_config:
  virtual_hosts:
  - name: any
    domains: ["*"]
    routes:
    - match: { prefix: / }
      route: { cluster: dynamic_forward_proxy_cluster }
```

For an OpenAI client it sends to Claude on Vertex AI, the keys end up as:

```
envoy.ai.llm_protocol.request  = OPENAI_CHAT_COMPLETIONS
envoy.ai.llm_protocol.response = ANTHROPIC_MESSAGES
envoy.ai.binding.response      = acme_vertex
envoy.ai.model.resolved        = claude-sonnet-4-5@20250929
envoy.upstream.dynamic_host    = us-east5-aiplatform.googleapis.com
```

The first key makes the request an AI request, so the AI filters run; the upstream request is
example 1's. ext_proc cannot write filter state itself: it returns its decision as dynamic
metadata, and `set_filter_state` copies each value with `%DYNAMIC_METADATA(...)%`. A C++ filter
can instead set the objects directly, with bindings it built at its own config load. The dynamic
forward proxy filter sits after the AI Protocol Manager, so an AI filter can still change the
host.

`envoy.ai.binding.response = llm_gateway` with `envoy.upstream.dynamic_host = llm-gateway.internal`
sends the request to the internal gateway:

```
upstream    POST /llm/claude-sonnet-4-5@20250929/messages-stream
            {"anthropic_version": "vertex-2023-10-16", "stream": true, "max_tokens": 512, ...}
```

`envoy.ai.binding.response = header_gateway` keeps the Anthropic API's path and adds the header:

```
upstream    POST /v1/messages
            x-llm-model: claude-sonnet-4-5@20250929
            anthropic-version: 2023-06-01
            {"model": "claude-sonnet-4-5@20250929", ...}
```

`header_gateway` has no `name`, so it starts from the Anthropic API's own binding, which also
writes `anthropic-version`.

The names are only the fast path. The same filter can choose per request what no configuration
names:

```
# another tenant's project, on the defined vertex_ai binding
envoy.ai.binding.response = vertex_ai?project=globex&location=europe-west4

# the internal gateway, spelled out instead of named
envoy.ai.binding.response = {"uri_pattern":"/llm/{model}/{messages|messages-stream}","fields":[{"field":"model","path_variable":"model"}],"body_fields":{"anthropic_version":"vertex-2023-10-16"}}
```

And a C++ AI filter that reads the body can still move the request before it leaves, for example
to keep a tenant's data in Europe:

```cpp
auto* binding = filter_state.getDataMutable<LlmBindingObject>("envoy.ai.binding.response");
binding->mutableBinding().path_variables["location"] = "europe-west4";
// and envoy.upstream.dynamic_host = europe-west4-aiplatform.googleapis.com
```

### 9. Behind a dynamic forward proxy, observed only

A Vertex AI client calls `us-east5-aiplatform.googleapis.com` through the proxy, and a filter ahead
that recognizes Vertex AI hosts writes one key:

```
envoy.ai.llm_protocol.request = ANTHROPIC_MESSAGES
```

The request is now an AI request. The core recognizes `vertex_ai` from the path, so schema
validation and request_info see the model. No backend API is named, so it is the client's: nothing
is transcoded, and the request leaves for the host the client addressed exactly as it came, as in
example 5.

## Other providers

Most providers need no binding: they serve an API in its own shape at another host or path prefix
(OpenAI-compatible servers; Bedrock and Foundry at `/anthropic/v1/messages`). A binding is needed
only where the shape changes, and the ways it changes are few:

| Primitive | When | Needed by |
|---|---|---|
| `fields`: a request field in a path variable, query parameter or header, moved or copied | now | Vertex AI and Gemini (`model`, `stream`), Bedrock InvokeModel, Azure OpenAI deployments (`model` as `{deployment}`), gateways that route on a header |
| `path_variables`, and a constant query in the pattern | now | Vertex AI's `project` and `location`; Azure OpenAI's `api-version` |
| `body_fields`, `headers` | now | Vertex AI's and Bedrock's `anthropic_version`; the Anthropic API's `anthropic-version` |
| Value maps beyond the `{unary\|stream}` choice; nested field paths | later | none known yet |
| Header to body | later | InvokeModel's `anthropic_beta` |
| Response framing | later | Bedrock's event stream |

A new provider is data: a named binding, built in or, later, defined in the filter config. Only a
new primitive is code. Nothing branches on a binding's name; an OpenTelemetry
`gen_ai.provider.name` label can be added for telemetry. Out of scope: credentials, authority,
provider-specific model ids (`envoy.ai.model.resolved` and the model table), and error bodies.

## Alternatives

- **`ANTHROPIC_MESSAGES_VERTEX` in `LLMProtocol`.** One value per API and provider, and every
  reader keyed on the enum (adapters, schemas, transcoding packs, request_info, token usage) gains a
  duplicate case. The path still needs a second knob, so it is not one knob. Gemini on Vertex AI
  already works without its own value. Envoy AI Gateway (now agent-router) took this path
  (`GCPAnthropic`, `AWSAnthropic`) and has since overloaded `version` and argued over names (#1639,
  #2867 there).
- **A `variant` string read by the transcoder.** The right axis, but untyped, invisible to schema
  validation and request_info, and with no route-level form to check at config load.
- **Deriving the body shape from the rendered path.** No new key, but implicit, and example 6 could
  not be expressed.

## Plan

1. **API** (this change): `LLMBinding`, the route `binding` fields and the filter's `bindings`
   (hidden until implemented), and `LLMProtocol` docs.
2. **Requests instructed by filter state alone:** activation by `envoy.ai.llm_protocol.request`,
   the backend API defaulting to the client's with no IR round trip, `envoy.ai.model.resolved` at
   the sink, and one resolver for the instructions. With today's keys this already serves a
   dynamic forward proxy, for example an OpenAI client sent to Gemini.
3. **Bindings and objects:** the engine's envelopes become built-in bindings; the filter's
   `bindings`; the C++ `LlmBinding`, and the typed objects for both key families with the three
   text forms and copy-on-write updates; `UriPattern::render()` fills `path_variables` and
   `match()` captures them. No behavior change.
4. **Core ingress and `envoy.ai.binding.request`:** Vertex AI clients work with schema validation,
   request_info and the transcoder (examples 3 to 5 and 9), which drop their request-path code. The
   core reads `envoy.ai.uri_pattern.request` in the transcoder's place.
5. **Core egress and `envoy.ai.binding.response`:** requests reach Claude on Vertex AI (examples 1,
   2 and 6 to 8). The core reads `envoy.ai.uri_pattern.response` in the transcoder's place; the
   route fields are shown.
6. **More:** recognizing an API from the path with no key at all, Bedrock InvokeModel, Azure
   OpenAI's `/openai/v1` form.

Open questions:

- When a provider needs them: value maps beyond the `{unary|stream}` choice, and nested field
  paths such as `generationConfig.responseMimeType`.
