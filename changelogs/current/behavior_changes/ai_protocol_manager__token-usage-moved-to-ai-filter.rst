The :ref:`AI Protocol Manager <config_http_filters_ai_protocol_manager>` filter (alpha) no longer
extracts token usage itself: ``response_handling`` is removed in favor of the :ref:`token usage AI
filter <envoy_v3_api_msg_extensions.http.ai_filters.token_usage.v3.TokenUsage>`, which runs on
declared AI endpoints with ``request_handling`` and reads responses in the IR, OpenAI Chat
Completions; a response in another API needs the transcoder ahead of it. The record and its
``envoy.ai.token_usage`` namespace are unchanged, but the namespace is no longer configurable, and
``include_unconfigured_routes``, ``usage_signal`` and the extraction limits are gone. The token
usage counters move from ``ai_protocol_manager.token_usage_*`` to
``ai_protocol_manager.token_usage.*``. The AI Protocol Manager now also removes a top-level
``_envoy`` member from the responses it runs AI filters over.
