The :ref:`schema validation AI filter <config_http_filters_ai_protocol_manager_schema_validation>`
now reads the client's path under its :ref:`LLM binding <envoy_v3_api_msg_type.ai.v3.LLMBinding>`,
as the transcoder does, so a Claude on Vertex AI ``rawPredict`` request without ``model`` in its body
passes. The payload is forwarded unchanged.
