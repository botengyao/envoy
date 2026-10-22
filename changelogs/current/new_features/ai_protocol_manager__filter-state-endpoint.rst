The :ref:`AI Protocol Manager filter <config_http_filters_ai_protocol_manager>` (alpha) treats a
request whose API the ``envoy.ai.llm_protocol.request`` filter state object names as an AI
endpoint without per-route configuration, so a route shared with other traffic, such as a dynamic
forward proxy's catch-all, can carry LLM traffic that a filter ahead of it recognizes. Response
token usage is extracted on such a stream, and on one whose backend API is in the
``envoy.ai.llm_protocol.response`` object.
