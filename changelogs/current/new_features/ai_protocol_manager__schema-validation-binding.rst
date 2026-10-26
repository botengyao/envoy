The :ref:`schema validation AI filter <config_http_filters_ai_protocol_manager_schema_validation>`
now validates a request as the client's :ref:`LLM binding <envoy_v3_api_msg_type.ai.v3.LLMBinding>`
carries it, the way the transcoder reads it. A field the path carries counts as sent, and a body
field the binding writes is left to it, so a Claude on Vertex AI ``rawPredict`` request without
``model`` in its body passes. The payload is forwarded unchanged.
