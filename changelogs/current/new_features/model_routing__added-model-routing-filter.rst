Added the :ref:`model routing <config_http_filters_model_routing>` HTTP filter. It turns an ordered
:ref:`ModelRoutingPolicy <envoy_v3_api_msg_data.ai.v3.ModelRoutingPolicy>` from a policy decision
point into a per-request plan that router retries follow across models, regions and providers.
