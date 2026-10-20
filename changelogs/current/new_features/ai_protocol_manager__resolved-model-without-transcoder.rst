The :ref:`AI Protocol Manager filter <config_http_filters_ai_protocol_manager>` writes the
``envoy.ai.model.resolved`` filter state object into the request body's ``model`` when no transcoder
handles the request and the body is re-serialized, so a backend that takes the client's API gets
the resolved model without a transcoder.
