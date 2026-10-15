The :ref:`schema validation AI filter <config_http_filters_ai_protocol_manager_schema_validation>`
sets an API it detects as the ``envoy.ai.llm_protocol.request`` filter state object, unless one is
set already, so access logs and the HTTP filters after the :ref:`AI Protocol Manager
<config_http_filters_ai_protocol_manager>` can read it.
