The :ref:`schema validation <config_http_filters_ai_protocol_manager_schema_validation>` AI filter
validates Gemini Interactions (``GEMINI_INTERACTIONS``) requests instead of skipping them: exactly
one of ``model`` or ``agent``, the shapes of ``input``, ``tools`` and ``generation_config``, and
which fields stay inline.
