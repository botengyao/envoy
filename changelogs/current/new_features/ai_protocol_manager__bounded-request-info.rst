Added bounded, best-effort request inspection and typed request-info metadata to
the :ref:`AI Protocol Manager filter <config_http_filters_ai_protocol_manager>`
(alpha, work-in-progress API). Eligible unencoded JSON POST requests on unconfigured routes,
including dynamic-forward-proxy traffic, can be inspected up to a configurable
prefix limit (1 MiB by default) without waiting for end of stream or buffering
the remainder of the body. Normalized OpenAI, Anthropic/Claude, and Gemini
request attributes are published as
:ref:`envoy.data.ai.v3.RequestInfo <envoy_v3_api_msg_data.ai.v3.RequestInfo>`
typed dynamic metadata, including extraction quality, stop reason, protocol
detection source, and inspected bytes. A later ext_proc filter can receive the
record in its initial request-headers ``metadata_context`` through typed
namespace forwarding without receiving or parsing the request body again.
