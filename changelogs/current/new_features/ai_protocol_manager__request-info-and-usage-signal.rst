Added request-side AI request-info publication and an end-of-stream usage
signal to the
:ref:`AI Protocol Manager filter <config_http_filters_ai_protocol_manager>`
(alpha, work-in-progress API). Setting :ref:`request_handling.request_info
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestHandling.request_info>`
publishes what a parsed request payload declares -- model, streaming, the
declared output cap, a pre-flight input-token estimate with the
:ref:`estimation method
<envoy_v3_api_enum_data.ai.v3.RequestInfo.EstimationMethod>` that produced it,
and the turn and tool counts -- as typed dynamic metadata
(:ref:`envoy.data.ai.v3.RequestInfo <envoy_v3_api_msg_data.ai.v3.RequestInfo>`,
default namespace ``envoy.ai.request_info``). Publication happens at end of
payload while the filter still holds the request headers, so every later
decode filter observes the record on its first callback: an external admission
service can act on the model and a cost bound read from ``metadata_context``
rather than being sent the body to parse again. The estimate is measured from
payload string lengths, including those of values offloaded out of the parsed
document, so a large prompt is measured without being read.
:ref:`request_info.include_unconfigured_routes
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.RequestInfoPublication.include_unconfigured_routes>`
extends publication to routes that declare no wire API, detecting it from the
request target (and, as a fallback, from unambiguous payload markers) so that a
dynamic-forward-proxy egress listener can publish without per-route
configuration. Detection names the dialect a record is read with and nothing
else: a route's own declaration always wins, schema validation still runs only
against a declared API, and an unconfigured route is never failed over its
payload.
Setting :ref:`token_usage.usage_signal
<envoy_v3_api_field_extensions.filters.http.ai_protocol_manager.v3.TokenUsageExtraction.usage_signal>`
to ``SYNTHESIZE_TRAILERS`` adds empty response trailers at a clean end of
stream when the response carries none of its own, so that a trailer-driven
consumer -- ``ext_proc`` with ``response_trailer_mode: SEND`` -- runs after the
usage record is published and receives it in ``metadata_context`` without the
response body being sent to the processor.
