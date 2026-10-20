Added ``GEMINI_INTERACTIONS``, Gemini's Interactions API, to :ref:`LLMProtocol
<envoy_v3_api_enum_type.ai.v3.LLMProtocol>`. The :ref:`AI Protocol Manager filter
<config_http_filters_ai_protocol_manager>` extracts its token usage, the schema validation AI filter
detects it by its ``/interactions`` path or its payload, and the request info AI filter reads its
attributes.
