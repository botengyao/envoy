Added the :ref:`envoy.http.ai_filters.transcoder
<envoy_v3_api_msg_extensions.http.ai_filters.transcoder.v3.Transcoder>` AI filter to the :ref:`AI
Protocol Manager filter <config_http_filters_ai_protocol_manager>` (work in progress). It converts
requests and responses between OpenAI Chat Completions, Anthropic Messages and Gemini
generateContent, including SSE streams, and rewrites the request path for Vertex AI or the
provider's own API. Its internal leg attaches the request's internal representation for the AI
filters after it, which the filter publishes under the ``envoy.ai.request_ir`` filter state key when
:ref:`publish_request_ir
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestHandling.publish_request_ir>`
is set. A request that the AI filters leave unmodified is now forwarded byte for byte instead of
being re-serialized, unless :ref:`reserialize_body
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestHandling.reserialize_body>`
is ``ALWAYS``.
