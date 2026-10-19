# Gemini Interactions on the AI Protocol Manager

Design only, no code. Base: upstream/main `d7b74bd624` (2026-10-19). This reviews the RFC "Gemini
Interactions API on Envoy Upstream AI Protocol Manager" against the code and Google's current API,
then gives the design, an example configuration and the changes it needs.

## 1. MVP scope

The MVP serves Gemini **models** on Google's Interactions API. A request names a Gemini `model`,
and Envoy sends it to `POST /v1beta/interactions` with that model, or with the one
`envoy.ai.model.resolved` names. Interactions requests that name an `agent` are not in the MVP.

| In the MVP | Later |
|---|---|
| OpenAI Chat Completions client to Interactions: stateless text, unary and SSE, usage | `agent` (managed agents such as Deep Research) and `background` |
| Native Interactions client to Interactions: forwarded as received, usage metered | Server-side state on converted requests: `previous_interaction_id`, `store: true` |
| The client picks the model, or the gateway pins one (`envoy.ai.model.resolved`) | Tools and function calls; multimodal input and output |
| Get, delete and cancel as plain routes | Interactions clients to other backends; picking a provider by model |

## 2. Review of the RFC

The direction holds: a new `LLMProtocol` value with its own schema, adapter and transcoding pack,
the two existing transcoder instances, and a native route that skips conversion. Several details
are wrong or missing.

**Holds.**

| RFC claim | Evidence |
|---|---|
| A new `GEMINI_INTERACTIONS` value, not `GEMINI_GENERATE_CONTENT` | The enum adds a value only for an API with schemas of its own (`api/envoy/type/ai/v3/llm_protocol.proto:28-30`); Interactions shares no request, response or stream shape with generateContent. |
| Reuse both transcoder instances, no new filter | The transcoder only picks a leg (`transcoder/filter.cc:394-408`); a dialect is an engine pack registered in `createDefault()` (`transcoding_engine.cc:2697-2710`). |
| Native requests must skip conversion | The pair never skips a same-API hop (`transcoder/filter.cc:134-171`): Interactions to IR to Interactions would drop `previous_interaction_id`, thought signatures and `store`. |
| A response-only route runs no request AI filter and still meters usage | Without `request`, `isAiEndpoint()` is false and no AI filter runs (`filter.cc:297-329`); usage runs on any configured route (`filter.cc:570-573`) against `response.llm_protocol` (`filter.h:109-111`). |
| Request legs run client then backend; response legs the reverse | `filter_manager.cc:36,47` reverse the chain for responses. |
| No routing by a transcoded model upstream | Upstream filters run after the cluster and host are picked; the transcoder edits only the body and `:path`. |
| Upstream instances share the downstream filter state | `UpstreamFilterManager::streamInfo()` returns the downstream one (`source/common/router/upstream_request.cc:56-61`); hedged attempts read it in parallel (`source/docs/upstream_filters.md`). |
| Non-2xx and headers-only responses are not transformed | `filter.cc:581-584`; headers-only requests pass at `filter.cc:291-293`. |
| The response fallback forwards source-dialect payloads | `transcoder/filter.cc:197-203,232-245`, with the existing TODO(ginama). |
| Converted requests carry `store: false` | `store` defaults to true, kept 55 days on paid tiers [OV]. |
| No `?alt=sse`; `stream: true` in the body | Both SDKs post `stream: true` to the create path without `alt`, with `Accept: text/event-stream` [SDK]. |
| One terminal sequence, no double `[DONE]` | Google ends with `event: done` / `data: [DONE]` [ST]; the engine ends a stream once (`TranscodeStreamState::terminated`, `transcoding_engine.h:534`). |

**Wrong or needs changing.**

| RFC claim | Finding |
|---|---|
| `temperature` and `top_p` are not in v1beta `GenerationConfig` | They are, marked deprecated, which the rendered page hides [R]. v1 dropped them [V1]; Vertex lists them as ordinary fields [VX]. See D2. |
| Pin `Api-Revision: 2026-05-20` once confirmed | Moot. Since 2026-06-08 only the `steps` schema is served and the header is ignored [BC]. Send nothing; pin the fixtures to the `steps` schema. |
| Cached and thought counts are breakdowns | Thought tokens are disjoint from output: 7 + 20 + 22 = 49 in [R]. Cached tokens are a part of input. `total_tool_use_tokens` must not be added: [R]'s function-call sample has 100 + 25 = 125 with 50 tool-use tokens. |
| Track step index and type in `TranscodeStreamState` | Not for text. Every `step.delta` names its own type (`text`, `thought_summary`, `thought_signature`, ...), so the grammar matches on `delta.type`. State is needed only to number streamed tool calls, in the tools phase. |
| One user message becomes an `input` string first | No special case is needed: `Step[]` carries one message as well as many. |
| An opt-in strict mode fixes the response fallback | The core forwards response headers before the body is transcoded (`filter.cc:618-634,671`), so a failure after that can only reset the stream. Failing cleanly needs the core to hold unary headers and an in-band error event for SSE, for every dialect. That is a transcoder-wide change (T1), not part of this API. |
| A revised Content-Length must be verified | Already handled: the sink rewrites an existing Content-Length (`request_filter_manager.cc:180,204-207`), and responses drop it (`filter.cc:619`). |
| PR 0 lands fixtures alone | Fixtures go with the code they test, extending `test/extensions/http/ai_filters/transcoder/testdata/response_goldens.json`. |

**Missing.**

| Gap | Why it matters |
|---|---|
| Strip `accept-encoding` on converted routes | A non-identity `content-encoding` skips both transcoding and usage (`filter.cc:598-603`): a Chat client sending `accept-encoding: gzip` would get gzipped Interactions JSON. |
| Lifecycle routes carry no AI config | `GET /interactions/{id}`, and a resumed stream (`?stream=true&last_event_id=`), return the stored interaction with its `usage`; a configured route would publish it again. |
| Interactions bodies are misdetected today | `detectFromPayload()` reads `system_instruction` and `generation_config` as generateContent (`llm_protocol_detection.cc:27-29,85`), and schema validation then rejects the body for lacking `contents`; a bare `input` reads as OpenAI Responses (`:90`). |
| SSE usage classification | `response_handler.cc:51-62` would parse every `step.delta` as JSON against `max_parsed_sse_events`; usage rides `interaction.completed`. |
| Error shapes | Errors are `{"error": {"code": "<snake_case>", "message": ...}}` [ERR], close enough to OpenAI's that Chat SDKs read an untranscoded non-2xx body. An in-stream `event: error` has to be mapped (§4.5). |
| A native route gets no schema validation or request info | It follows from the response-only declaration. §4.1 gives a variant with request info. |
| Vertex AI serves the same API | `aiplatform.googleapis.com/v1beta1/projects/{project}/locations/global/interactions`, with a Bearer token [VX]: a route `response.binding` and another credential, no new code. |

## 3. The API this designs against

Google's current schema, as of 2026-10-19 (the `steps` schema of May 2026).

| | Interactions |
|---|---|
| Create | `POST /v1beta/interactions`; `/v1/interactions` [V1], GA since June 2026 [OV] |
| Lifecycle | `GET` and `DELETE /v1beta/interactions/{id}`; `POST /v1beta/interactions/{id}/cancel` (background only); `GET ...?stream=true&last_event_id=` resumes a stream |
| Auth | `x-goog-api-key` |
| Request | exactly one of `model` and `agent`; `input`: string, Content, Content[] or Step[]; `system_instruction`: string; `generation_config`: `max_output_tokens`, `seed`, `stop_sequences`, `thinking_level`, `thinking_summaries`, `tool_choice` (and deprecated `temperature`, `top_p`); `tools`, `response_format`, `stream`, `store` (default true), `background`, `previous_interaction_id`, `service_tier` |
| Turns | No `role`: a step's `type` is `user_input`, `model_output`, `thought`, `function_call`, `function_result` or a server-tool step; content is `[{"type": "text", "text": ...}]` |
| Response | `id`, `object: "interaction"`, `model`, `status`, `created` and `updated` (RFC 3339), `steps[]`, `usage`; status `completed`, `incomplete` (max tokens), `requires_action`, `failed`, `cancelled`, `in_progress`, `queued` |
| Usage | `total_input_tokens`, `total_output_tokens`, `total_thought_tokens`, `total_cached_tokens`, `total_tool_use_tokens`, `total_tokens` |
| Stream | `interaction.created`, `interaction.status_update`, `step.start`, `step.delta`, `step.stop`, `interaction.completed` (carries `usage`), `error`, then `event: done` / `data: [DONE]`; each payload names its `event_type` |

Sources, all fetched 2026-10-19: [R] https://ai.google.dev/api/interactions-api and its OpenAPI
file; [V1] https://ai.google.dev/api/interactions-api-v1; [BC]
https://ai.google.dev/gemini-api/docs/interactions-breaking-changes-may-2026; [OV]
https://ai.google.dev/gemini-api/docs/interactions-overview; [ST]
https://ai.google.dev/gemini-api/docs/streaming; [ERR]
https://ai.google.dev/gemini-api/docs/api-errors; [VX]
https://docs.cloud.google.com/gemini-enterprise-agent-platform/reference/models/interactions-api;
[SDK] googleapis/python-genai v2.31.0 and js-genai v2.30.0.

## 4. Design

### 4.1 Routes and placement

One cluster to `generativelanguage.googleapis.com` owns how to speak to it. Its upstream filter
chain injects the API key, then runs the AI Protocol Manager with schema validation, request info
and the two transcoder instances. Routes decide what runs:

| Route | AI per-route config | What runs |
|---|---|---|
| `POST /v1/chat/completions` | `request: OPENAI_CHAT_COMPLETIONS`, `response: GEMINI_INTERACTIONS` | Chat schema validation, request info, both legs; `:path` becomes `/v1beta/interactions`; usage |
| `POST /v1(beta)/interactions` | `response: GEMINI_INTERACTIONS` | nothing on the request; usage on the response |
| get, delete, cancel | none | nothing |

- The upstream chain runs once per attempt, after the host is picked, and re-transcodes the
  router's buffered body on a retry. Instructions in filter state are read by every attempt, so
  they are set before the router and do not change per attempt. The same AI config also works in
  the downstream chain.
- The per-route config is keyed by the upstream filter's name, which is what
  `mostSpecificPerFilterConfig()` resolves by (`source/common/http/filter_manager.cc:343-349`). A
  downstream and an upstream instance with the same name read the same entry.
- The route strips `authorization` (the client's credential) and `accept-encoding`; the
  credential injector writes `x-goog-api-key` over anything the client sent.
- Variant with request info on native requests: a second cluster to the same host whose chain
  holds only request info, with `reserialize_body: DISABLE`, and native routes that declare
  `request: GEMINI_INTERACTIONS` too. The body is forwarded byte for byte, and
  `envoy.ai.model.request` and `RequestInfo` are published. See D1.

### 4.2 The protocol (PR 1)

- `GEMINI_INTERACTIONS = 5`, and `LLMProtocol::GeminiInteractions` in every exhaustive switch:
  `token_usage.cc:16`, `llm_protocol_conversion.h:16,33`, `llm_protocol_adapters.cc:343` and
  request info's `extractor.cc:132`.
- Request schema in `schema/gemini_interactions.{h,cc}`. The root allows unknown fields, as
  generateContent's does (`gemini_generate_content.cc:302`). Exactly one of `model` and `agent`,
  both inline. `input` is a string or Content, or an array of Content or Step. Offloadable: text,
  base64 `data`, thought `signature` and `summary[].text`, function `result`,
  `system_instruction`, and tool `description`.
- `GeminiInteractionsAdapter`:
  - Reads `usage` at the root, else under `interaction` (stream lifecycle events), with the
    `model` beside it. An `error` event sets `stream_error`.
  - Canonical input is `total_input_tokens`. Output is `total_output_tokens +
    total_thought_tokens`; reasoning is `total_thought_tokens`. Cached and tool-use counts are
    parts, not added. `total_tokens` is the provider total.
  - Terminal event: `event_type == "interaction.completed"`. `usagePath()` is `usage`, and
    `renderUsage()` is the inverse.
  - `AdapterRegistry::detect()` adds `object == "interaction"`, and an `event_type` starting with
    `interaction.` or `step.`.
- `response_handler.cc` skips `step.*` and `interaction.created` before parsing.
- Schema validation detection: the path suffix `/interactions`, which also covers v1 and Vertex.
  By payload, a body without `contents` is Interactions when it carries `previous_interaction_id`,
  `agent` or `agent_config`, or `input` with `system_instruction` or `generation_config`. A bare
  `{model, input}` stays OpenAI Responses: it is ambiguous, so declare the route.
- Request info: `model`, empty for an `agent`; `stream`; `generation_config.max_output_tokens`;
  message count as the `Step[]` length, or 1 for any other `input`; tool count.

### 4.3 Chat to Interactions request (PR 2)

Rules on the IR, the pack's `request.from_ir`. Every one is an existing op.

| IR | Interactions | Rule |
|---|---|---|
| (precondition) | | `require("messages", NonEmptyArray)`: a document that is not the IR, such as an Interactions client on a misconfigured route, fails here |
| `system` and `developer` messages | `system_instruction` string | `extractFromArray`, then `collectText` (several are joined, without a separator: D5) |
| `user`, `assistant` messages | `input[]` steps `user_input`, `model_output` | `move(role, type)` and `valueMap(..., Reject)`; a `tool` or `function` role is a 400 |
| string `content` or text parts | `content: [{"type": "text", "text": ...}]` | `wrapInArrayObject`, which rejects a non-text part (`transcoding_engine.cc:2292-2295`), then `setConst(type)` |
| `name`, `refusal` | dropped | `drop` |
| `max_completion_tokens`, `max_tokens` | `generation_config.max_output_tokens` | `firstOf` |
| `stop` | `generation_config.stop_sequences` | `ensureArray`, `move` |
| `seed` | `generation_config.seed` | `move` |
| `temperature`, `top_p` | `generation_config.temperature`, `top_p` | `move` (deprecated in v1beta: D2) |
| `reasoning_effort` | `generation_config.thinking_level` | `move`, `valueMap` of `minimal`, `low`, `medium`, `high` (else 400) |
| `model` | `model` | kept; `envoy.ai.model.resolved` replaces it first (`transcoding_engine.cc:2763-2766`) |
| `stream` | `stream` | kept in the body |
| `store` | `false` | `setConst`: the IR's `store` is OpenAI's stored completions |
| `stream_options`, `user`, `metadata` | dropped | no effect on the generation; usage always arrives |
| `n: 1`, `logprobs: false`, penalties of 0 | dropped | `when(fieldEquals(...))`: no-op values |
| anything else: `tools`, `n > 1`, `response_format`, `service_tier`, ... | left in the body | Google rejects a name or value it does not take with a 400 (`parameter_unknown`, `invalid_request` [ERR]), so nothing is lost silently (D6) |

The result is validated against the Interactions schema, then sent to the pack's binding,
`/v1beta/interactions`. It has no `{model}` and no mutations, so `model` and `stream` stay in the
body.

```json
{"model": "assistant-default", "max_tokens": 256, "stream": false,
 "messages": [{"role": "system", "content": "Be concise."},
              {"role": "user", "content": "Explain Envoy overload manager."}]}
```

With `envoy.ai.model.resolved` set to `gemini-3-flash-preview`, it becomes:

```json
{"model": "gemini-3-flash-preview", "system_instruction": "Be concise.",
 "input": [{"type": "user_input",
            "content": [{"type": "text", "text": "Explain Envoy overload manager."}]}],
 "generation_config": {"max_output_tokens": 256}, "stream": false, "store": false}
```

### 4.4 Interactions to Chat response (PR 2)

`response.to_ir`, run on a copy, so a failure leaves the original (`transcoding_engine.cc:2793-2810`).

| Interactions | Chat | Rule |
|---|---|---|
| `steps` | (precondition) | `require("steps", Array)` |
| `id` | `id` | kept; with `store: false` it cannot be fetched |
| `created` (RFC 3339) | `created` (Unix seconds) | `drop`, then `setFromContext(NowUnixSeconds)` |
| `model` | the client's model | `setFromContext(RequestModel)`, as every pack does |
| `usage` | IR `usage` | `convertUsage` |
| text of `model_output` steps | `choices[0].message.content` | `forEach(steps, collectText(content))`, then `collectText(steps, type == model_output)`; thought and tool steps are skipped |
| `status` | `finish_reason` | `completed` to `stop`, `incomplete` to `length`; any other fails the leg (T1) |

```json
{"id": "v1_Chd...", "object": "chat.completion", "created": 1792411200, "model": "assistant-default",
 "choices": [{"index": 0, "finish_reason": "stop",
              "message": {"role": "assistant", "content": "The overload manager ..."}}],
 "usage": {"prompt_tokens": 7, "completion_tokens": 42, "total_tokens": 49,
           "prompt_tokens_details": {"cached_tokens": 0},
           "completion_tokens_details": {"reasoning_tokens": 22}}}
```

### 4.5 Interactions to Chat stream (PR 3)

The `stream.to_ir` grammar. Cases match on the payload's `event_type`, not on the SSE `event:`
line.

| Interactions event | Chat chunk |
|---|---|
| `interaction.created` | opening chunk with `delta.role: assistant`; the interaction `id` is captured for the chunks after it |
| `step.delta` with `delta.type: text` | `delta.content`; a text past the inline threshold moves as a reference |
| `interaction.completed` | closing chunk: `finish_reason` from `interaction.status`, and `usage` |
| `error` | `data: {"error": {...}}`, unnamed, which OpenAI SDK clients raise on |
| `data: [DONE]` | `Terminate`: one `data: [DONE]` |
| anything else: `interaction.status_update`, `step.start`, `step.stop`, thought, annotation and media deltas, unknown events | dropped |
| the stream ends without `[DONE]` | `[DONE]` appended (`on_source_end`) |

The last case is a catch-all `json()` drop. Without it, an unknown event fails the grammar, and
the transcoder forwards it untranslated. Media deltas are dropped, as the generateContent pack
drops non-text parts (D8).

### 4.6 Model selection

- The client names the model on both routes. Interactions carries no model in the path, so any id
  Google accepts works, such as `gemini-3-flash-preview` or `gemini-flash-latest`. Envoy does not
  check it.
- The gateway replaces it with `envoy.ai.model.resolved`, set before the router: by
  `set_filter_state` per route or virtual host (§5), by ext_proc, or by a model router. It applies
  to converted requests only; a native body is forwarded as received.
- `RequestInfo.model` and `envoy.ai.model.request` report the client's model, and so does the
  Chat response's `model`. `TokenUsage.model` reports the model Google ran.
- A converted request always names a `model`: the IR has no `agent`. A native route forwards an
  `agent` request as it came, but a background interaction reports its usage on later gets, which
  are not metered. That is why agents are outside the MVP (D3).
- Sending a request to a provider by its model is not here. The model is in the body, so that
  choice belongs before the router picks the cluster (the AI routing track); upstream filters run
  after it.

## 5. Example configuration

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
            # The client picks the Gemini model.
            - name: gemini
              domains: ["*"]
              # The client's own credential never reaches Google, and a compressed response
              # could be neither transcoded nor metered.
              request_headers_to_remove: [authorization, accept-encoding]
              routes:
              # OpenAI Chat Completions clients.
              - match:
                  path: /v1/chat/completions
                  headers: [{name: ":method", string_match: {exact: POST}}]
                route: {cluster: gemini_api, auto_host_rewrite: true, timeout: 300s}
                typed_per_filter_config:
                  envoy.filters.http.ai_protocol_manager:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
                    request: {llm_protocol: OPENAI_CHAT_COMPLETIONS}
                    response: {llm_protocol: GEMINI_INTERACTIONS}
              # Native Interactions create: forwarded as received, only the response is read.
              - match:
                  safe_regex: {regex: "/v1(beta)?/interactions"}
                  headers: [{name: ":method", string_match: {exact: POST}}]
                route: {cluster: gemini_api, auto_host_rewrite: true, timeout: 300s}
                typed_per_filter_config:
                  envoy.filters.http.ai_protocol_manager:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
                    response: {llm_protocol: GEMINI_INTERACTIONS}
              # Get, delete and cancel. No AI config: a stored interaction's usage, which a get
              # returns, is not metered a second time.
              - match:
                  safe_regex: {regex: "/v1(beta)?/interactions/[^/]+(/cancel)?"}
                route: {cluster: gemini_api, auto_host_rewrite: true, timeout: 300s}
            # The gateway picks the Gemini model, whatever the client names.
            - name: assistant
              domains: [assistant.example.com]
              request_headers_to_remove: [authorization, accept-encoding]
              routes:
              - match:
                  path: /v1/chat/completions
                  headers: [{name: ":method", string_match: {exact: POST}}]
                route: {cluster: gemini_api, auto_host_rewrite: true, timeout: 300s}
                typed_per_filter_config:
                  envoy.filters.http.ai_protocol_manager:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
                    request: {llm_protocol: OPENAI_CHAT_COMPLETIONS}
                    response: {llm_protocol: GEMINI_INTERACTIONS}
                  envoy.filters.http.set_filter_state:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
                    on_request_headers:
                    - object_key: envoy.ai.model.resolved
                      format_string:
                        text_format_source: {inline_string: gemini-3-flash-preview}
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
            - name: envoy.http.ai_filters.schema_validation
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.ai_filters.schema_validation.v3.SchemaValidation
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

To use the stable version, a converted route adds `binding: {uri_pattern: /v1/interactions}` to
its `response`; v1 has no `temperature` or `top_p` (D2). Vertex AI takes
`binding: {uri_pattern: /v1beta1/projects/my-project/locations/global/interactions}`, its own
host, and a Bearer token, e.g. from `gcp_authn`, in place of the API key.

## 6. Changes

| Area | File | Change | PR |
|---|---|---|---|
| API | `api/envoy/type/ai/v3/llm_protocol.proto` | `GEMINI_INTERACTIONS = 5`, documented as the Interactions API, e.g. `/v1beta/interactions` on the Gemini API | 1 |
| Core | `ai_protocol_manager/token_usage.{h,cc}`, `llm_protocol_conversion.h` | enum value, name, both conversions | 1 |
| Core | `ai_protocol_manager/schema/gemini_interactions.{h,cc}`, `schema/BUILD` | request schema (§4.2) | 1 |
| Core | `ai_protocol_manager/llm_protocol_adapters.cc`, `json_readers.h`, `BUILD` | adapter, registry entry, `detect()` markers, keys such as `event_type` and `total_input_tokens` | 1 |
| Core | `ai_protocol_manager/response_handler.cc` | skip `step.*` and `interaction.created` | 1 |
| AI filters | `http/ai_filters/schema_validation/llm_protocol_detection.cc` | path suffix and payload markers (§4.2) | 1 |
| AI filters | `http/ai_filters/request_info/extractor.cc` | Interactions reader | 1 |
| Engine | `ai_protocol_manager/transcoding_engine.cc` | `createGeminiInteractionsTranscodePack()`: `request.from_ir`, `response.to_ir`, `binding = /v1beta/interactions`; registered in `createDefault()` | 2 |
| Engine | same | `stream.to_ir` grammar | 3 |
| Docs | `docs/root/configuration/http/http_filters/ai_protocol_manager_filter.rst` | the API lists (lines 66-69, 202, 236-238), the three route kinds, `accept-encoding`, supported Chat fields | 1-3 |
| Docs | `docs/root/configuration/advanced/well_known_filter_state.rst` | an Interactions example where useful | 1 |
| Release note | `changelogs/current/new_features/ai_protocol_manager__gemini-interactions.rst` | one fragment per PR, or one for the set | 1-3 |

No change to the APM filter, the transcoder filter, bindings or filter state keys. PRs 2 and 3 add
rules only; no new engine op is needed. Engine changes come later: numbering streamed tool calls
across events for tools; optionally a separator for joined system prompts (D5) and a `refuse` op
to reject IR fields before dispatch (D6).

## 7. PR plan

| PR | Title | Done when |
|---|---|---|
| 1 | `ai_protocol_manager: add the Gemini Interactions protocol` | a native route meters unary and streamed usage, and detection and request info read Interactions |
| 2 | `ai_protocol_manager: transcode OpenAI Chat to Gemini Interactions` | a Chat client gets a Chat completion from Interactions through the upstream chain, with `store: false` and the resolved model |
| 3 | `ai_protocol_manager: stream Gemini Interactions to OpenAI Chat` | a Chat client streams text, usage and errors, with exactly one `[DONE]` |
| T1 | `transcoder: fail responses it cannot transcode` | independent of this API: hold unary headers until transcoded, and an error event per dialect for SSE |
| T2 | `transcoder: skip same-API hops` | independent: a native route can declare `request` on the shared cluster, so schema validation and request info run on it |

Later: tools in both directions; Interactions clients to other backends (`request.to_ir`,
`response.from_ir`, `stream.from_ir`); `response_format` and `service_tier` mapping; Vertex AI
example; agents and background; routing by model.

## 8. Tests

- PR 1. The adapter on [R]'s unary response and [ST]'s stream: usage from
  `interaction.completed.interaction.usage`, 49 = 7 + 42 canonically, tool-use not added, and an
  `error` event degrades the record. The response handler with frames split at every byte. Schema
  accept and reject fixtures: `model` xor `agent`, every `input` form, offloaded text. Detection:
  the path suffix, including Vertex; an Interactions body no longer detected as generateContent;
  a bare `{model, input}` still Responses. Request info. An integration test on the upstream
  chain: a native create reaches the upstream byte for byte, and usage is published once, unary
  and streamed, including across a retry.
- PR 2. Engine goldens. Requests: system and user, multi-turn, several system messages, `stop` as a
  string and an array, `reasoning_effort`, `temperature`, `n: 1` dropped, `store` forced, the
  resolved model; a `tool` role and an image part are 400s. Responses: a thought step skipped, two
  `model_output` steps joined, `incomplete` to `length`, usage. An integration test on the
  upstream chain: the upstream sees `POST /v1beta/interactions` with `x-goog-api-key`, a matching
  Content-Length, and no `authorization` or `accept-encoding`; the client gets a Chat completion;
  usage metadata; the model pinned by `set_filter_state`.
- PR 3. [ST]'s stream as a golden; frames split at every byte; a thought step first; an `error`
  after the 200 becomes an error chunk and one `[DONE]`; a stream cut before
  `interaction.completed` still gets one `[DONE]`; Google's `[DONE]` never doubles.
- Outside CI, against the live API (an `experiment/` setup): D2 and D7, and the error shapes.

## 9. Open decisions

| # | Question | Recommendation |
|---|---|---|
| D1 | Native routes: response-only on the shared cluster, or a native cluster with request info? | Response-only for the MVP; the native cluster when native requests need `RequestInfo` |
| D2 | `temperature` and `top_p`: map onto v1beta's deprecated fields, drop, or reject? | Map them while v1beta accepts them; a v1 binding then fails on them |
| D3 | `agent` on native routes: forward unmetered, or block? | Forward and document; blocking needs a policy hook Envoy lacks today |
| D4 | Default version: v1beta or v1? | v1beta, which the SDKs and docs use; v1 by route binding |
| D5 | Several system messages: join without a separator, add a separator to `collectText`, or reject? | Join for the MVP; a separator is a small engine follow-up |
| D6 | Unmapped Chat fields: leave them for Google's 400, reject in Envoy, or drop? | Leave them: the failure is visible and names the field; rejecting before dispatch needs a `refuse` op |
| D7 | Streaming `Accept`: Google's SDKs send `text/event-stream`, OpenAI's send `application/json`. Does Google need it? | Verify against the live API; if it does, a binding needs a header write again |
| D8 | Media and tool deltas on a Chat stream: drop, or an error chunk? | Drop, as the generateContent pack does; they come only from media models or tools |
