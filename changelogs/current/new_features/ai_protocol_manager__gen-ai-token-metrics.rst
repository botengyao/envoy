Added OpenTelemetry GenAI token usage metrics to the
:ref:`AI Protocol Manager filter <config_http_filters_ai_protocol_manager_gen_ai_metrics>`. When
token usage extraction finds usage, the downstream installation records the
``gen_ai.client.inference.usage.*`` counters and ``gen_ai.client.inference.operation.*`` histograms,
named and tagged as the semantic conventions define them, with no configuration.
