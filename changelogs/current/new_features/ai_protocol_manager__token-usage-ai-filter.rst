Added the :ref:`envoy.http.ai_filters.token_usage
<envoy_v3_api_msg_extensions.http.ai_filters.token_usage.v3.TokenUsage>` AI filter (alpha) to the
:ref:`AI Protocol Manager <config_http_filters_ai_protocol_manager>` filter. It publishes the token
usage of a response in the IR, OpenAI Chat Completions, as :ref:`envoy.data.ai.v3.TokenUsage
<envoy_v3_api_msg_data.ai.v3.TokenUsage>` typed dynamic metadata. Behind the :ref:`transcoder
<envoy_v3_api_msg_extensions.http.ai_filters.transcoder.v3.Transcoder>`, a ``TO_IR`` leg now hands
the usage the backend reported in its own API down the AI filter chain in the reserved ``_envoy``
member, so the published record keeps what the IR's ``usage`` cannot hold: Gemini's tool-use
tokens, the provider's own total, the model the backend served, and usage in events the
transcoder could not convert.
