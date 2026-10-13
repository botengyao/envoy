.. _config_http_filters_ai_protocol_manager:

AI Protocol Manager
===================

The AI Protocol Manager filter (alpha) manages AI API traffic on both
directions of a stream:

* On the **request (decode) path** it buffers a declared AI endpoint's payload
  off the connection manager's hot path — parsing it as it arrives — so that
  routing and admission decisions can be made on the fully received body.
* On the **response (encode) path** it runs the same AI filters over a 2xx SSE
  or JSON response, for example to publish the LLM **token usage** the provider
  reported with the :ref:`token usage
  <config_http_filters_ai_protocol_manager_token_usage>` AI filter.

Processing is enabled by the presence of :ref:`request_handling
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager.request_handling>`.

The filter acts only on requests it has a reason to inspect. A request on a
route that is not a declared AI endpoint -- and, unless
:ref:`parse_unconfigured_routes
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestHandling.parse_unconfigured_routes>`
is set, every request -- passes straight through: its headers are not held, its
body is not offloaded, and no external buffer is created for it. A filter chain
carrying this filter therefore costs ordinary pass-through for the traffic it
does not serve.

For a request it does inspect, as the body arrives the filter offloads it into an external buffer
rather than pinning it in the connection manager's in-memory buffers. Once the
stream ends, it streams the buffered bytes back into the filter chain so that
the subsequent filters observe the request unchanged. The offload/replay
round-trip is flow-controlled in both directions: ingest honors the buffer
limit, and replay is paced against filter-chain back-pressure, so the resident
footprint stays bounded regardless of payload size.

While such a body is being offloaded, the request headers are held at this filter
and released to the subsequent filters only once replay begins, so they never act
on the headers before the payload they depend on is available.

On a route declared to be an AI endpoint, the body is parsed as it is offloaded,
so that a payload which is not well-formed JSON is rejected here rather than
forwarded for the upstream to interpret differently. Parsing is incremental and shares the offload's byte
stream, so an invalid payload fails as soon as the offending byte arrives rather
than after the whole upload. Oversized string values are left in the external
buffer and referenced by offset, so a large prompt does not reappear in
per-stream memory. What counts as oversized is
:ref:`inline_string_threshold_bytes
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestParsingLimits.inline_string_threshold_bytes>`,
1KiB by default -- large enough that ordinary metadata stays inline and small
enough that conversation content does not. A declared API whose payload schema
pins its own threshold uses that instead.

Upon stream completion, the parsed document is handed to the configured
:ref:`AI filters <config_http_filters_ai_protocol_manager_ai_filters>`.
Holding it to its API's payload schema is the job of the :ref:`schema
validation <config_http_filters_ai_protocol_manager_schema_validation>` AI filter.

.. note::

  On the request path the body is offloaded to an in-memory store. Payloads are
  converted between OpenAI Chat Completions, Anthropic Messages and Gemini
  GenerateContent by the :ref:`transcoder AI filter
  <envoy_v3_api_msg_extensions.http.ai_filters.transcoder.v3.Transcoder>`.

The filter is a dual filter: besides the downstream HTTP filter chain shown
below, it can also be placed in a cluster's upstream HTTP filter chain via
:ref:`http_filters <envoy_v3_api_field_extensions.upstreams.http.v3.HttpProtocolOptions.http_filters>`,
where the offload/replay round-trip runs after load balancing and host
selection (and therefore once per retry or hedged attempt).

.. note::

  Two caveats apply to the upstream placement, and only to routes the filter
  inspects. The filter holds the request headers until the payload has been
  fully offloaded, and upstream filter
  chains have no per-upgrade-type chain selection (the
  :ref:`upgrade_configs <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.upgrade_configs>`
  escape hatch is downstream-only), so the filter must not front upgrade or
  CONNECT routes, or other requests whose body does not end promptly: such
  streams would stall until the request times out. Additionally, local replies
  raised from an upstream filter chain (such as this filter's external-buffer
  error reply) are delivered directly to the downstream client without
  consulting the router's retry or hedging logic.

* This filter should be configured with the type URL ``type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager``.
* :ref:`v3 API reference <envoy_v3_api_msg_extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager>`

Configuration
-------------

Which routes are AI endpoints is declared per route, with
:ref:`AiProtocolManagerPerRoute
<envoy_v3_api_msg_extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute>`.
A route carrying a :ref:`request
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute.request>`
declaration names the :ref:`wire API
<envoy_v3_api_enum_type.ai.v3.LLMProtocol>` its request payload follows, and
(when ``request_handling`` is enabled) its payload is parsed strictly: a
malformed body is rejected with a 400. This is normally attached to a route
matching the provider's REST path, such as ``/chat/completions``:

.. code-block:: yaml

  routes:
  - match:
      path: "/chat/completions"
    route:
      cluster: openai
    typed_per_filter_config:
      envoy.filters.http.ai_protocol_manager:
        "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
        request:
          llm_protocol: OPENAI_CHAT_COMPLETIONS

The request and response wire APIs are declared separately: an optional
:ref:`response
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute.response>`
declaration names the API of the backend, which the :ref:`transcoder
<envoy_v3_api_msg_extensions.http.ai_filters.transcoder.v3.Transcoder>` converts
to and from when it differs from the client's.

A filter ahead of this one that knows the caller better than the route does
can name the request API itself, with the ``envoy.ai.llm_protocol.request``
filter state object. On a declared AI endpoint the object wins over the route's
``llm_protocol``; one naming ``LLM_PROTOCOL_UNSPECIFIED`` leaves the route's
declaration standing. Its object factory builds it from an :ref:`LLMProtocol
<envoy_v3_api_enum_type.ai.v3.LLMProtocol>` enum-value name, so
:ref:`set_filter_state <config_http_filters_set_filter_state>`, Lua and
ext_proc can all set it. It is read when the request headers arrive. Access
logs read it with
``%FILTER_STATE(envoy.ai.llm_protocol.request:FIELD:llm_protocol)%``.

.. code-block:: yaml

  http_filters:
  - name: envoy.filters.http.set_filter_state
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
      on_request_headers:
      - object_key: envoy.ai.llm_protocol.request
        format_string:
          text_format_source:
            inline_string: "%REQ(x-llm-api)%"

The example reads a request header, which is only safe for a header the edge
strips from client requests: a caller that can set it picks the API its own
payload is read and validated as.

The filter-level configuration decides what happens on every other route. By
default those requests are passed through untouched -- not parsed, and not
offloaded; setting
:ref:`parse_unconfigured_routes
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestHandling.parse_unconfigured_routes>`
offloads and parses them too, but never fails a request over it -- a payload that
does not parse is forwarded unchanged.

.. code-block:: yaml

  http_filters:
  - name: envoy.filters.http.ai_protocol_manager
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
      request_handling:
        parse_unconfigured_routes: true

.. _config_http_filters_ai_protocol_manager_ai_filters:

AI filters
----------

After a declared AI endpoint's payload is parsed, and before it is replayed,
the filter runs the configured :ref:`AI filters
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager.filters>`
in order over the parsed document; they require ``request_handling``. An AI
filter (category ``envoy.http.ai_filters``)
may read or modify the document, or reject the request with a local reply.
Routes without a per-route request declaration, and requests without a body,
run no AI filters.

The AI filters that ran over a request also run, in reverse order, over its
response when it is a 2xx with a ``text/event-stream`` or JSON content type:
one SSE event, or one batch of JSON fields, at a time. A response with a
non-identity ``content-encoding`` cannot be read, and skips them (counted by
``unsupported_content_encoding``).

Once the AI filters finish, the parsed document is re-serialized as the
request body by default. With :ref:`reserialize_body
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestHandling.reserialize_body>`
set to ``DISABLE``, the received body is forwarded byte for byte instead, and
edits AI filters make to the document are not sent; use it only with AI filters
that read the request.

.. _config_http_filters_ai_protocol_manager_schema_validation:

Schema validation
~~~~~~~~~~~~~~~~~

The :ref:`schema validation filter
<envoy_v3_api_msg_extensions.http.ai_filters.schema_validation.v3.SchemaValidation>`
validates the payload against the payload schema of its wire API, for APIs with
a defined schema (currently ``OPENAI_CHAT_COMPLETIONS``, ``ANTHROPIC_MESSAGES``
and ``GEMINI_GENERATE_CONTENT``). Validation checks required fields, data
types, enum values, and offload rules -- metadata fields such as ``model`` and
``role`` must stay inline, while large message content may reside in the
external buffer. A payload that fails is rejected with a 400, or forwarded
unchanged with :ref:`fail_open
<envoy_v3_api_field_extensions.http.ai_filters.schema_validation.v3.SchemaValidation.fail_open>`.

Configure it first. The API it resolves is the one the AI filters after it
read, and they only see a payload that passed.

.. code-block:: yaml

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

The payload is validated against the API the request declares: the
``envoy.ai.llm_protocol.request`` filter state object, else the route's
:ref:`llm_protocol
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestPerRoute.llm_protocol>`.
A request that declares none falls back to :ref:`default_llm_protocol
<envoy_v3_api_field_extensions.http.ai_filters.schema_validation.v3.SchemaValidation.default_llm_protocol>`,
and by default the API is detected from the request: its path, matched as a
suffix against each provider's REST path (``/chat/completions``,
``/responses``, ``/v1/messages``, ``:generateContent``,
``:streamGenerateContent``); then the ``anthropic-version`` header; then the
payload's shape.

Chat Completions and Anthropic Messages share the ``messages[]`` request
shape, so only keys exclusive to one of them tell the two apart. A payload
carrying markers of both, or of neither -- including
``{"model": ..., "messages": [{"role": "user", "content": ...}]}``, which is
valid under either -- names no API, and is forwarded unvalidated.

The filter outputs statistics in the ``ai_protocol_manager.schema_validation.``
namespace:

.. csv-table::
  :header: Name, Type, Description
  :widths: 1, 1, 2

  valid, Counter, The payload passed its API's schema.
  invalid, Counter, "The payload violated its API's schema: rejected with a 400, or forwarded with ``fail_open``."
  skipped, Counter, "No API was resolved, or the resolved one has no payload schema; the payload was forwarded unvalidated."
  llm_protocol_detected, Counter, The API was detected from the request.

Request info
~~~~~~~~~~~~

The :ref:`request info filter
<envoy_v3_api_msg_extensions.http.ai_filters.request_info.v3.RequestInfo>` publishes
the requested model, streaming preference, output token cap, and message and
tool counts as :ref:`envoy.data.ai.v3.RequestInfo
<envoy_v3_api_msg_data.ai.v3.RequestInfo>` typed dynamic metadata, under
``envoy.ai.request_info`` by default. It never modifies or rejects the request.

.. code-block:: yaml

  http_filters:
  - name: envoy.filters.http.ai_protocol_manager
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
      request_handling: {}
      filters:
      - name: envoy.http.ai_filters.request_info
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.http.ai_filters.request_info.v3.RequestInfo

Attributes are read according to the request's wire API: the one it declares,
or the one the :ref:`schema validation
<config_http_filters_ai_protocol_manager_schema_validation>` filter resolved
when it runs first:

.. csv-table::
  :header: Attribute, OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, Gemini
  :widths: 1, 1, 1, 1, 1

  ``model``, ``model``, ``model``, ``model``, model segment of the request path
  ``stream``, ``stream``, ``stream``, ``stream``, "``:generateContent`` (false) or ``:streamGenerateContent`` (true) operation in the request path"
  ``max_output_tokens``, "``max_completion_tokens``, else ``max_tokens``", ``max_output_tokens``, ``max_tokens``, "``generationConfig.maxOutputTokens`` (camelCase or snake_case)"
  ``message_count``, ``messages``, "``input`` (a string counts as one message)", ``messages``, ``contents``
  ``tool_count``, ``tools``, ``tools``, ``tools``, ``tools``

Without an API, only ``model`` and ``stream`` are read. Every value is
client-declared and optional. A value Envoy cannot use (wrong type, out of
range, or a string over 256 bytes) is ignored and counted by
``request_info.partial``.

Token estimation
^^^^^^^^^^^^^^^^

Configuring :ref:`token_estimation
<envoy_v3_api_field_extensions.http.ai_filters.request_info.v3.RequestInfo.token_estimation>`
adds ``estimated_input_tokens`` to the record, for consumers that must budget
before the provider reports what it charged: a rate limit on tokens per minute,
or a load balancer weighing queued work. It is ``ceil(tokens_per_byte *
request payload bytes)`` over the body Envoy buffered, so it reads no JSON and
is published whatever the route declares:

.. code-block:: yaml

  - name: envoy.http.ai_filters.request_info
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.http.ai_filters.request_info.v3.RequestInfo
      token_estimation:
        tokens_per_byte: 0.5

The ratio is a property of the payloads a deployment sees, and a size heuristic
is not a tokenizer: an estimate does not replace the :ref:`token usage
<envoy_v3_api_msg_data.ai.v3.TokenUsage>` the response reports. Rounding up
keeps a sub-token payload from estimating zero.

The record is written before the held request headers are released, so later
decode filters see it from their first request-headers callback. An
:ref:`ext_proc <config_http_filters_ext_proc>` filter listed after this one
receives it through typed namespace forwarding:

.. code-block:: yaml

  metadata_options:
    forwarding_namespaces:
      typed:
      - envoy.ai.request_info

Only typed metadata is published. If the namespace already holds a record for
the stream, the new one is skipped and counted by ``request_info.duplicate``.

The model is also stored as the ``envoy.ai.model.request`` :ref:`filter state
object <well_known_filter_state>`, a string, so filters, the router and access
logs can read it without unpacking the record, e.g. with
``%FILTER_STATE(envoy.ai.model.request:PLAIN)%``. Nothing is stored when the
request names no usable model, and an object a filter ahead already set is
kept.

Transcoder
~~~~~~~~~~

The :ref:`transcoder filter
<envoy_v3_api_msg_extensions.http.ai_filters.transcoder.v3.Transcoder>` rewrites the
parsed payload into the request schema of the AI backend the route targets, so a client
may speak one vendor's API while the upstream speaks another.

Translation runs through a single canonical schema, OpenAI Chat Completions, rather than
pairwise between vendors. Supporting a new dialect therefore costs one mapping rather than
one per pair, and AI filters placed between the two legs only ever see the canonical shape.

.. code-block:: yaml

  http_filters:
  - name: envoy.filters.http.ai_protocol_manager
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
      request_handling: {}
      filters:
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

Two instances of the filter bracket the intermediate AI filters across both the request and
response (unary and SSE streaming) pipelines: the client-boundary instance sets
``request_handling: TO_IR`` and ``response_handling: FROM_IR`` to convert between the client's
declared protocol and the canonical OpenAI Chat Completions IR, and the backend-boundary instance
sets ``request_handling: FROM_IR`` and ``response_handling: TO_IR`` to convert between the
canonical IR and the target backend's schema. Filters configured between the two therefore only
ever see the canonical form. Leaving either ``request_handling`` or ``response_handling`` unset
(``DIRECTION_UNSPECIFIED``) disables transcoding on that leg so payloads pass through untouched.

The client-boundary instance converts from and to the API the route declares for the
:ref:`request <envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute.request>`,
and the backend-boundary instance to and from the one it declares for the
:ref:`response <envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute.response>`.
A leg whose API the route does not declare cannot be transcoded, which is counted by
``transcoder.unresolved``.

The rewritten request is validated against the target's schema before it is
replayed, so a document the upstream would reject fails locally rather than over the
network. Such a rejection is counted by ``transcoder.failed``.

Responses are converted one unary body or one SSE event at a time. An event may become none
(Anthropic's ``ping``, for example) or several, and a stream that ends without the terminator
the client's API expects is given one: an OpenAI client of a Gemini backend, whose streams just
end, still receives ``data: [DONE]``. A response or event that cannot be converted is forwarded
untranslated, since part of the response may already be on its way to the client, and is
counted by ``transcoder.failed``.

.. note::

  Gemini carries the model and the streaming mode in the request path rather than the
  body. The ``TO_IR`` leg lifts both out of the path into the canonical ``model`` and
  ``stream`` fields, and a ``FROM_IR`` leg targeting Gemini moves them back, setting the
  path to ``/v1beta/models/{model}:generateContent`` or
  ``/v1beta/models/{model}:streamGenerateContent?alt=sse``. A route in front of another
  endpoint layout rewrites that prefix, for example Vertex AI's with ``regex_rewrite``.
  Other vendor paths and authentication headers are left to the route, for example through
  ``prefix_rewrite`` and ``request_headers_to_add``.

.. _config_http_filters_ai_protocol_manager_token_usage:

Token usage
~~~~~~~~~~~

The :ref:`token usage filter
<envoy_v3_api_msg_extensions.http.ai_filters.token_usage.v3.TokenUsage>` publishes
the token usage a response reports as :ref:`envoy.data.ai.v3.TokenUsage
<envoy_v3_api_msg_data.ai.v3.TokenUsage>` typed dynamic metadata, under
``envoy.ai.token_usage``, once the response ends. It never modifies, holds or
fails the response.

It reads the response in the IR, OpenAI Chat Completions, and has no
configuration. A response from an OpenAI-compatible backend is in the IR
already; any other backend's response is converted by the transcoder's
backend-boundary instance, which the filter must come after on the response
path. Response filters run in reverse order, so the filter is listed before
that instance:

.. code-block:: yaml

  filters:
  - name: envoy.http.ai_filters.transcoder      # client API <-> IR
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
      request_handling: TO_IR
      response_handling: FROM_IR
  - name: envoy.http.ai_filters.token_usage
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.http.ai_filters.token_usage.v3.TokenUsage
  - name: envoy.http.ai_filters.transcoder      # IR <-> backend API
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
      request_handling: FROM_IR
      response_handling: TO_IR

The IR's ``usage`` cannot hold all that other APIs report: it has no place for
Gemini's tool-use prompt tokens or for a provider total that disagrees with the
computed one, and an IR response may name the model the client asked for rather
than the one that served it. So a ``TO_IR`` leg reads the usage from the
backend's own response before converting it, and hands the record of it down the
chain in the reserved ``_envoy`` member: on the converted body, or on an event
of its own at the end of a stream. The filter publishes that record when there
is one, and reads the IR's ``usage`` otherwise. The record names the backend's
API and the model it reported, and counts usage in events the transcoder could
not convert, such as Anthropic's in-band ``error``. The AI Protocol Manager
removes ``_envoy`` from a response as it enters the AI filters, so an upstream
cannot supply a record, and again before it leaves them, so a client never sees
one.

A document in another API than the IR is not read: Anthropic's
``input_tokens``, read as the IR, would leave out its cache reads. Such a
response publishes a status-only ``FAILED`` record and is counted by
``token_usage.api_mismatch``.

All published counts follow one canonical, **inclusive** contract regardless of
the provider's API: ``input_tokens`` covers all input consumed (uncached input,
cached reads, cache writes, and tool-use prompt tokens), ``output_tokens``
covers all generated output including reasoning/thought tokens, and
``total_tokens`` is computed as their sum and published only when both
components are known, so the published triple is always internally consistent.
The total the provider itself reported is preserved separately as
``provider_total_tokens``, whether or not it agrees with the canonical sum (a
disagreement is counted by ``token_usage.total_mismatch``). The breakdown fields
(``input_token_details``, ``output_token_details``) are parts of the canonical
values. Each API's native shape is normalized onto this contract — for example
Anthropic's disjoint cache buckets are summed into the canonical input, and
Gemini's thoughts are summed into the canonical output.

.. note::

  The canonical fields carry consistent *inclusion semantics* across APIs —
  which native buckets are counted — not equivalent units of work or cost.
  Tokenizer behavior, model vocabulary, cache pricing, and provider pricing
  all differ; cost accounting additionally needs provider/model identity and
  a pricing model.

Only typed metadata is published: consumers that read only untyped metadata
(``%DYNAMIC_METADATA%`` access-log formatters) do not see the record; consume it
through :ref:`ext_proc <config_http_filters_ext_proc>` typed metadata forwarding
(``metadata_options.forwarding_namespaces.typed``), ``%TYPED_CEL%``, or a filter
reading typed dynamic metadata, sharing the proto definition for safe parsing.

``llm_protocol`` names the wire API the usage was reported in, deliberately not
a provider identity: an OpenAI-compatible backend (vLLM, other gateways,
Gemini's compatibility endpoint) reports an OpenAI API. When the actual provider
identity is needed, derive it from configuration or routing (for example
cluster metadata), not from this field.

.. warning::

  Every count (and the model name) is **provider-reported and unverified**:
  Envoy does not count tokens itself. The upstream controls these values and
  can report zero, inconsistent, or inflated numbers. Treat the metadata as an
  observability signal for trusted providers; for billing or quota enforcement
  against untrusted destinations, independent verification is required.

Metadata is only published at a clean end of the HTTP response (a reset or
abandoned stream publishes nothing). ``extraction_status`` reports extraction
quality: ``COMPLETE`` means every usage document was read; ``PARTIAL`` means
usable counts were published but some usage-bearing input was lost — a known
usage field carrying a malformed value (wrong type, negative, fractional, null,
or out of range), an in-band stream error before the provider's final usage, or
a canonical sum exceeding the exactly-representable bound — so the counts may be
stale or incomplete; ``FAILED`` means usage-bearing input was observed but no
count could be read, and the record carries no counts. Usage can be
legitimately absent (for example an OpenAI stream without
``stream_options.include_usage``); this is counted by ``token_usage.missing``
and no metadata is written.

The published values are **selected-response usage**, not the total provider
cost of servicing the downstream request: with retries or hedging only the
attempt whose response the router selects publishes (a losing attempt can
still consume billable tokens upstream), and any 2xx body containing usage
fields — including one served by a cache or generated locally between this
filter and the client-facing edge — is read even though no provider call may
have occurred for it. Aggregating true per-request provider cost requires
per-attempt accounting outside this filter.

The record is written as the response ends, before the AI Protocol Manager
passes the end of the response on. A consumer that reads metadata on the encode
path — such as an ext_proc filter using
:ref:`metadata_options.forwarding_namespaces
<envoy_v3_api_field_extensions.filters.http.ext_proc.v3.ExternalProcessor.metadata_options>`
— must run *after* the AI Protocol Manager on the encode path:

* Downstream installation: encoder filters run in the reverse of the
  ``http_filters`` order, so list the consumer *before* the AI Protocol Manager.
* Upstream installation: all upstream encoder filters run before every
  downstream encoder filter, so any downstream consumer observes the metadata
  without ordering constraints.

An ext_proc consumer additionally needs a :ref:`processing mode
<envoy_v3_api_msg_extensions.filters.http.ext_proc.v3.ProcessingMode>` under
which the external processor receives a message at the end of the response —
the metadata does not exist yet at response-header time, and by default ext_proc
sends no response-body messages (``response_body_mode: NONE``) and skips
response trailers. Configure ``response_body_mode: STREAMED`` (the terminal,
end-of-stream body message carries the metadata context), or
``response_trailer_mode: SEND`` for trailer-ended responses:

.. code-block:: yaml

  processing_mode:
    response_body_mode: STREAMED   # or response_trailer_mode: SEND
  metadata_options:
    forwarding_namespaces:
      typed:
      - envoy.ai.token_usage

To publish the usage of compressed provider responses, which skip the AI
filters:

* **Downstream installation**: place the :ref:`decompressor filter
  <config_http_filters_decompressor>` so that it runs before the AI Protocol
  Manager on the encode path (list it *after* the AI Protocol Manager in
  ``http_filters``, since encoder filters run in reverse order).
* **Upstream installation**: Envoy's decompressor is a downstream-only filter
  today, so it cannot run before a cluster-installed AI Protocol Manager. The
  practical approach is to prevent compression on the provider connection —
  remove or pin the request's ``accept-encoding`` header on the cluster's
  filter chain (e.g. with the :ref:`header mutation filter
  <config_http_filters_header_mutation>`, which supports upstream
  installation) so the provider responds with identity encoding.

The filter outputs statistics in the ``ai_protocol_manager.token_usage.``
namespace:

.. csv-table::
  :header: Name, Type, Description
  :widths: 1, 1, 2

  found, Counter, "A record with counts was published (``COMPLETE`` or ``PARTIAL``)."
  partial, Counter, A published record was flagged ``extraction_status: PARTIAL``.
  failed, Counter, A status-only record was published (``extraction_status: FAILED``; no counts read).
  missing, Counter, A response ended without usage to publish.
  total_mismatch, Counter, The provider-reported total disagreed with the canonical input + output sum.
  duplicate, Counter, Publication was skipped because another installation had already published ``envoy.ai.token_usage`` for this stream.
  api_mismatch, Counter, "A response, with no record from a transcoder, was in another API than the IR, so it was not read."

Upstream (cluster) installation
-------------------------------

The filter is also registered as an upstream HTTP filter for deployments where
handling must live on the cluster — for example a dynamic-forward-proxy egress
cluster whose destination is only known per request. The upstream installation
is the full filter: the request-path offload/replay and the AI filters run there
too, once per retry or hedged attempt, with the caveats described under the
request payload offload section above. The route declares the endpoint for the
upstream installation as it does for the downstream one.

Typed dynamic metadata written from the upstream installation lands on the
downstream stream's metadata and is visible to downstream typed-metadata
consumers exactly as in a downstream installation. With the token usage filter
in both installations, the first publication owns ``envoy.ai.token_usage`` for
the stream -- the upstream instance's, since upstream encoder filters run before
downstream encoder filters -- and the later instance skips publishing (counted
by ``token_usage.duplicate``) rather than writing a second record.

Upstream retries and hedging: each upstream attempt runs its own filter
instance, but only the attempt whose response the router selects reaches a
clean end of its response through its encoder chain — and non-2xx attempts run
no AI filters — so only the winning attempt publishes metadata.

Statistics
----------

The filter outputs statistics in the ``ai_protocol_manager.`` namespace.

.. csv-table::
  :header: Name, Type, Description
  :widths: 1, 1, 2

  request_parsed, Counter, A held request payload was parsed into a document.
  request_parse_error, Counter, A declared AI endpoint's payload was not well-formed JSON and was rejected with a 400.
  request_passthrough, Counter, "A payload on an unconfigured route failed to parse under :ref:`parse_unconfigured_routes <envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestHandling.parse_unconfigured_routes>` and was forwarded unchanged; never a request failure."
  request_external_buffer_error, Counter, The external buffer failed irrecoverably on the request path and the stream was answered with a 500.
  response_external_buffer_error, Counter, The external buffer failed irrecoverably on the response path and the stream was answered with a 500.
  unsupported_content_encoding, Counter, "A response the AI filters would have run over carried a non-identity ``content-encoding``, so they did not."
  request_info.published, Counter, The request info AI filter published an ``envoy.data.ai.v3.RequestInfo`` record.
  request_info.partial, Counter, A published request info record ignored at least one value Envoy could not use.
  request_info.duplicate, Counter, Request info publication skipped because another installation of the filter had already published the namespace for this stream.
  transcoder.transcoded, Counter, "The transcoder AI filter converted a payload (a request, a unary response or an SSE event) into or out of the canonical IR."
  transcoder.unresolved, Counter, "A payload could not be transcoded because the route declared no wire API for its leg. A request is rejected; a response is forwarded untranslated and counted once, however many SSE events it has."
  transcoder.failed, Counter, "A payload could not be converted: its rules failed, or a converted request failed the target schema. A request is rejected; a response or SSE event is forwarded untranslated."
