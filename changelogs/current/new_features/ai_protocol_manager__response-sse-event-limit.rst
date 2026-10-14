Added :ref:`max_sse_event_bytes
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.ResponseParsingLimits.max_sse_event_bytes>`
to the :ref:`AI Protocol Manager <config_http_filters_ai_protocol_manager>` filter's response handling.
It bounds one SSE event of a response the AI filters run over, a bound that was fixed at 64MiB, which
stays the default and the most it can be set to. An event over the limit fails the response.
