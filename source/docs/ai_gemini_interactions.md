# Gemini Interactions on the AI Protocol Manager

Design only, no code. Base: upstream/main `d7b74bd624` (2026-10-19).

Clients speak Google's Gemini Interactions API, and so does the backend. Envoy recognizes the API,
meters its usage, and changes one thing in a request: the model name, when
`envoy.ai.model.resolved` names one. Nothing is converted to or from another API, and requests
that name an `agent` instead of a `model` are out of scope.

## Examples

### 1. Envoy changes the model

The route sets `envoy.ai.model.resolved` to `gemini-3-flash-preview`. The client asks for
`assistant-default`:

```
POST /v1beta/interactions
host: assistant.example.com

{"model": "assistant-default", "input": "Explain Envoy overload manager."}
```

Envoy sends Google the request with the model replaced and the gateway's own key:

```
POST /v1beta/interactions
host: generativelanguage.googleapis.com
x-goog-api-key: <gateway key>

{"input": "Explain Envoy overload manager.", "model": "gemini-3-flash-preview"}
```

Google answers:

```json
{"id": "v1_Chd...", "object": "interaction", "model": "gemini-3-flash-preview", "status": "completed",
 "steps": [{"type": "thought", "signature": "..."},
           {"type": "model_output", "content": [{"type": "text", "text": "The overload manager ..."}]}],
 "usage": {"total_input_tokens": 7, "total_output_tokens": 20, "total_thought_tokens": 22,
           "total_cached_tokens": 0, "total_tool_use_tokens": 0, "total_tokens": 49}}
```

The client gets the same response with `"model": "assistant-default"`: as for every API, the
response names the model the client asked for. The gateway keeps the one that ran:

| Where | Model |
|---|---|
| `envoy.ai.model.request`, `RequestInfo.model` | `assistant-default` |
| `envoy.ai.model.resolved` | `gemini-3-flash-preview` |
| `TokenUsage` in `envoy.ai.token_usage` | `gemini-3-flash-preview`; input 7, output 42 (20 + 22 thought), total 49 |

### 2. Streaming

With `"stream": true` in the body, Google streams named events. Envoy replaces the model in the
two events that carry it, and reads usage from the last one:

```
event: interaction.created
data: {"event_type": "interaction.created", "interaction": {"id": "v1_...", "model": "assistant-default", "status": "in_progress"}}

event: step.delta
data: {"delta": {"text": "The overload", "type": "text"}, "event_type": "step.delta", "index": 1}

event: interaction.completed
data: {"event_type": "interaction.completed", "interaction": {"id": "v1_...", "model": "assistant-default", "status": "completed", "usage": {...}}}

event: done
data: [DONE]
```

Every other event goes out with the content it came with.

### 3. The client's model goes through

A route that declares only the response API: Envoy does not hold or parse the request, and only
reads the response for usage. Its client picks the model.

### 4. Get, delete and cancel

`GET` and `DELETE /v1beta/interactions/{id}`, and `POST /v1beta/interactions/{id}/cancel`, are
plain routes with no AI config. A get returns the stored interaction with its `usage`, so a
configured route would meter that usage a second time.

## Configuration

`GEMINI_INTERACTIONS` does not exist yet. With it replaced by `GEMINI_GENERATE_CONTENT` and the CA
path adjusted, this file passes `envoy --mode validate` on a build of `d5eb7030ad` (PR #48376).

```yaml
static_resources:
  secrets:
  - name: gemini-api-key
    generic_secret:
      secret: {environment_variable: GEMINI_API_KEY}

  listeners:
  - name: ai_gateway
    address:
      socket_address: {address: 0.0.0.0, port_value: 10000}
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
                text_format_source:
                  inline_string: "%REQ(:METHOD)% %REQ(:PATH)% %RESPONSE_CODE% model=%FILTER_STATE(envoy.ai.model.request:PLAIN)% resolved=%FILTER_STATE(envoy.ai.model.resolved:PLAIN)%\n"
          route_config:
            name: ai_routes
            virtual_hosts:
            # Example 1: Envoy changes the model.
            - name: assistant
              domains: [assistant.example.com]
              request_headers_to_remove: [authorization, accept-encoding]
              routes:
              - match:
                  safe_regex: {regex: "/v1(beta)?/interactions"}
                  headers: [{name: ":method", string_match: {exact: POST}}]
                route: {cluster: gemini_api, auto_host_rewrite: true, timeout: 300s}
                typed_per_filter_config:
                  envoy.filters.http.ai_protocol_manager:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
                    request: {llm_protocol: GEMINI_INTERACTIONS}
                    response: {llm_protocol: GEMINI_INTERACTIONS}
                  envoy.filters.http.set_filter_state:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
                    on_request_headers:
                    - object_key: envoy.ai.model.resolved
                      format_string:
                        text_format_source: {inline_string: gemini-3-flash-preview}
              - match:
                  safe_regex: {regex: "/v1(beta)?/interactions/[^/]+(/cancel)?"}
                route: {cluster: gemini_api, auto_host_rewrite: true, timeout: 300s}
            # Example 3: the client's model goes through; Envoy only meters usage.
            - name: gemini
              domains: ["*"]
              request_headers_to_remove: [authorization, accept-encoding]
              routes:
              - match:
                  safe_regex: {regex: "/v1(beta)?/interactions"}
                  headers: [{name: ":method", string_match: {exact: POST}}]
                route: {cluster: gemini_api, auto_host_rewrite: true, timeout: 300s}
                typed_per_filter_config:
                  envoy.filters.http.ai_protocol_manager:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
                    response: {llm_protocol: GEMINI_INTERACTIONS}
              # Example 4: no AI config, so a stored interaction's usage is not metered again.
              - match:
                  safe_regex: {regex: "/v1(beta)?/interactions/[^/]+(/cancel)?"}
                route: {cluster: gemini_api, auto_host_rewrite: true, timeout: 300s}
          http_filters:
          # Sets filter state only where a route configures it.
          - name: envoy.filters.http.set_filter_state
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: gemini_api
    type: LOGICAL_DNS
    dns_lookup_family: V4_PREFERRED
    connect_timeout: 5s
    load_assignment:
      cluster_name: gemini_api
      endpoints:
      - lb_endpoints:
        - endpoint:
            hostname: generativelanguage.googleapis.com
            address:
              socket_address: {address: generativelanguage.googleapis.com, port_value: 443}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: generativelanguage.googleapis.com
        common_tls_context:
          alpn_protocols: [h2]
          validation_context:
            trusted_ca: {filename: /etc/ssl/certs/ca-certificates.crt}
            match_typed_subject_alt_names:
            - san_type: DNS
              matcher: {exact: generativelanguage.googleapis.com}
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
        # Runs once per attempt, after the cluster and host are picked.
        http_filters:
        - name: envoy.filters.http.credential_injector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.credential_injector.v3.CredentialInjector
            overwrite: true
            credential:
              name: envoy.http.injected_credentials.generic
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.injected_credentials.generic.v3.Generic
                credential: {name: gemini-api-key}
                header: x-goog-api-key
        - name: envoy.filters.http.ai_protocol_manager
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
            request_handling: {}
            response_handling:
              token_usage: {}
            filters:
            - name: envoy.http.ai_filters.request_info
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.ai_filters.request_info.v3.RequestInfo
            - name: envoy.http.ai_filters.transcoder
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
                request_handling: TO_IR
                response_handling: FROM_IR
            - name: envoy.http.ai_filters.transcoder
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
                request_handling: FROM_IR
                response_handling: TO_IR
        - name: envoy.filters.http.upstream_codec
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec
```

- The AI config sits in the cluster's upstream chain, so it runs once per attempt, after the host
  is picked. Upstream instances read the downstream filter state, so `envoy.ai.model.resolved` is
  set before the router and is the same for every attempt. The same AI config also works in the
  downstream chain.
- The per-route config is keyed by the upstream filter's name, which `mostSpecificPerFilterConfig()`
  resolves by (`source/common/http/filter_manager.cc:343-349`).
- `accept-encoding` is stripped because a compressed response is neither rewritten nor metered
  (`filter.cc:598-603`). `authorization` is stripped so the client's credential never reaches
  Google, and the credential injector writes `x-goog-api-key` over any the client sent.
- Vertex AI serves the same API at
  `aiplatform.googleapis.com/v1beta1/projects/{project}/locations/global/interactions`: the same
  routes, with its host and a Bearer token, e.g. from `gcp_authn`.

## How it works

**The protocol.** `GEMINI_INTERACTIONS` is a new `LLMProtocol` value, since the API shares no
request, response or stream shape with `GEMINI_GENERATE_CONTENT`:

- A request schema: exactly one of `model` and `agent`, both inline; `input` as a string, Content,
  or an array of Content or steps; text, media data and thought signatures offloadable. Unknown
  fields are allowed, as in the generateContent schema.
- A usage adapter. It reads `usage` at the root, or under `interaction` in stream events. Output
  is `total_output_tokens + total_thought_tokens`, since Google reports thought tokens apart (7 +
  20 + 22 = 49). Cached and tool-use counts are parts of the totals, not added to them, and
  `total_tokens` is kept as the provider total. Extraction ends at `interaction.completed`, and an
  `error` event marks the record partial.
- The response handler skips `step.*` events before parsing them.
- Schema validation detects the API by the path suffix `/interactions`. Today its payload check
  reads `system_instruction` and `generation_config` as generateContent and then rejects the body
  for lacking `contents`. It changes to name a body without `contents` Interactions when it
  carries `previous_interaction_id`, `agent`, or `input` with `system_instruction` or
  `generation_config`.
- Request info reads `model`, `stream`, `generation_config.max_output_tokens`, the message count
  and the tool count.

**The model change.** The two transcoder instances run as they do for any API, over a Gemini
Interactions pack that has no conversion rules:

- The `FROM_IR` leg writes `envoy.ai.model.resolved` into the body before any rule would run
  (`transcoding_engine.cc:2763-2766`), and validates the result against the Interactions schema.
- The pack has no binding, so `:path` is left as the client sent it.
- On the response, the pack's only rules put the client's model back: `model` in a unary body, and
  `interaction.model` in `interaction.created` and `interaction.completed`.
- Without `envoy.ai.model.resolved`, the request goes out with the same content; the parsed body is
  still re-serialized.

**Limits.**

- An `agent` request on a model-change route is a 400: with the model written in, it names both.
- A route with Interactions on one side and another API on the other is not converted. An
  Interactions request fails the other API's schema in Envoy. Another API's request reaches Google
  and fails there, with a 400 that names the unknown field.

## Changes

| File | Change | PR |
|---|---|---|
| `api/envoy/type/ai/v3/llm_protocol.proto` | `GEMINI_INTERACTIONS = 5`: the Interactions API, e.g. `/v1beta/interactions` on the Gemini API | 1 |
| `ai_protocol_manager/token_usage.{h,cc}`, `llm_protocol_conversion.h` | the value in the enum, its name and both conversions | 1 |
| `ai_protocol_manager/schema/gemini_interactions.{h,cc}`, `schema/BUILD` | request schema | 1 |
| `ai_protocol_manager/llm_protocol_adapters.cc`, `json_readers.h` | usage adapter, registry entry, `detect()` on `object: "interaction"` and `event_type` | 1 |
| `ai_protocol_manager/response_handler.cc` | skip `step.*` before parsing | 1 |
| `http/ai_filters/schema_validation/llm_protocol_detection.cc` | path suffix and payload markers | 1 |
| `http/ai_filters/request_info/extractor.cc` | Interactions reader | 1 |
| `ai_protocol_manager/transcoding_engine.cc` | `createGeminiInteractionsTranscodePack()`: no request rules, response rules that restore the client's model; registered in `createDefault()` | 2 |
| `ai_protocol_manager_filter.rst`, `well_known_filter_state.rst`, `changelogs/current/new_features/` | the new API in the API lists, the four examples, a release note | 1, 2 |

There is no change to the AI Protocol Manager filter, the transcoder filter, bindings or filter
state keys.

## PRs and tests

1. `ai_protocol_manager: add the Gemini Interactions protocol`. The tests:
   - the adapter on Google's unary response and stream, including an `error` event;
   - the response handler, with frames split at every byte;
   - the schema, with `model` xor `agent` and every `input` form;
   - detection, including a regression test that an Interactions body is no longer read as
     generateContent;
   - request info;
   - an integration test on the upstream chain. Example 3 meters usage once, unary and streamed
     and across a retry, and example 4 meters nothing.
2. `ai_protocol_manager: change the model of Gemini Interactions requests`. The tests:
   - engine tests: only `model` changes in the request, an `agent` request is refused, and the
     client's model returns in unary responses and in the two stream events;
   - an integration test on the upstream chain, for example 1. The upstream sees the pinned model,
     the client sees its own, and usage reports the one that ran.

## Differences from the RFC

- Dropped: Chat Completions to Interactions transcoding. With it go the Chat mapping, the forced
  `store: false`, SSE conversion, and the fail-closed fallback it needed.
- Kept: a new protocol value with its own schema and adapter; usage, detection and request info;
  no new filter; a response-only route for passthrough; and no model routing in the upstream
  chain, which runs after the host is picked.
- Corrected:
  - `Api-Revision` has been ignored since 2026-06-08.
  - Thought tokens are reported apart from output tokens, and tool-use tokens must not be added.
  - Streaming is `stream: true` in the body, without `?alt=sse`.
- Added:
  - Lifecycle routes carry no AI config.
  - `accept-encoding` is stripped.
  - The payload misdetection is fixed.
  - The response handler skips stream deltas.
  - The model change reuses the transcoder pair with a rule-free pack, instead of new code.

## Open questions

| # | Question | Recommendation |
|---|---|---|
| 1 | Should the response name the client's model or the one Google ran? | The client's, as `envoy.ai.model.resolved` documents for every API |
| 2 | Should another API's request on an Interactions route fail in Envoy, not at Google? | Not for now. Google's 400 names the field; a transcoder check that refuses a cross-API leg for a pack without rules is about ten lines if wanted |
| 3 | How is the model picked per client model, such as an alias table? | Later. It needs the model before the transcoder, so ext_proc or a model router; on main, the model is pinned per route or virtual host |

Sources, fetched 2026-10-19: https://ai.google.dev/api/interactions-api,
https://ai.google.dev/gemini-api/docs/streaming,
https://ai.google.dev/gemini-api/docs/interactions-breaking-changes-may-2026,
https://ai.google.dev/gemini-api/docs/interactions-overview.
