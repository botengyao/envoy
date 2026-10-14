The :ref:`AI Protocol Manager <config_http_filters_ai_protocol_manager>` filter (alpha) no longer
extracts token usage itself: ``response_handling.token_usage`` is removed in favor of the :ref:`token
usage AI filter <envoy_v3_api_msg_extensions.http.ai_filters.token_usage.v3.TokenUsage>`, which runs
on declared AI endpoints with ``request_handling`` and reads responses in the IR, OpenAI Chat
Completions; a response in another API needs the transcoder ahead of it. The record and its
``envoy.ai.token_usage`` namespace are unchanged, but the namespace is no longer configurable, and
``include_unconfigured_routes`` and ``usage_signal`` are gone. The extraction limits are not carried
over: the new :ref:`response limits
<envoy_v3_api_msg_extensions.filters.http.ai_protocol_manager.v3.ResponseParsingLimits>` fail a
response rather than skip its usage, so 1.40 values do not apply to them. ``response_handling`` now
requires ``request_handling``. A configuration that still sets ``response_handling.token_usage`` is
rejected when loaded statically, but over xDS it is only warned about as an unknown field unless
``--reject-unknown-dynamic-fields`` is set, so add the token usage AI filter before upgrading. The token usage counters move from
``ai_protocol_manager.token_usage_*`` to ``ai_protocol_manager.token_usage.*``. The AI Protocol
Manager now also removes a top-level ``_envoy`` member from the responses it runs AI filters over.
