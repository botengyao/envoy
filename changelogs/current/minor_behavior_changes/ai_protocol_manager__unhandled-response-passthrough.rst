The :ref:`AI Protocol Manager filter <config_http_filters_ai_protocol_manager>` forwards a response
byte for byte when none of its :ref:`AI filters <config_http_filters_ai_protocol_manager_ai_filters>`
handles responses, as with only schema validation and request info, or no AI filters at all.
Previously, every 2xx JSON or SSE response of a request that ran the AI filters was parsed and
re-serialized in canonical form, and failed if it could not be parsed. Token usage extraction is
unaffected.
