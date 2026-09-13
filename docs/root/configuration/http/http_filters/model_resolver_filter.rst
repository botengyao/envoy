.. _config_http_filters_model_resolver:

Model resolver
==============

The model resolver filter turns an ordered model routing decision into a plan that the router's
retries follow, so that one request can fall back across models, regions and providers.

* This filter should be configured with the type URL
  ``type.googleapis.com/envoy.extensions.filters.http.model_resolver.v3.ModelResolver``.
* :ref:`v3 API reference <envoy_v3_api_msg_extensions.filters.http.model_resolver.v3.ModelResolver>`

.. attention::

  The model resolver filter is under active development.

How it works
------------

A policy decision point, for example an :ref:`external processor <config_http_filters_ext_proc>`,
writes a :ref:`ModelRoutingPolicy <envoy_v3_api_msg_data.ai.v3.ModelRoutingPolicy>` to dynamic
metadata. The policy lists target IDs in preference order. Hosts, paths and credentials only come
from the filter configuration, so the policy can only choose among configured destinations.

For each request that carries a policy, the filter:

#. Drops unknown target IDs and targets whose API protocol differs from ``client_api_protocol``.
#. Stores the ordered targets in filter state under ``envoy.ai.model_route_plan``. The same object
   is the ``envoy.upstream.dynamic_host_candidates`` host list of the
   :ref:`dynamic forward proxy cluster <envoy_v3_api_msg_extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig>`,
   so each upstream attempt connects to the host of the next target.
#. Sets ``x-envoy-max-retries`` to one less than the number of targets, capped by ``max_retries``,
   and, for plans with more than one target, sets ``x-envoy-retry-on`` and
   ``x-envoy-retriable-status-codes`` from the policy's fallback conditions.
#. Sets ``x-envoy-hedge-on-per-try-timeout: false``, because all attempts of a request share one
   request header map.
#. Sets ``x-envoy-upstream-rq-per-try-timeout-ms`` from the policy's per-try timeout when
   ``max_per_try_timeout`` is configured, capped by it.
#. Optionally resolves the hosts of fallback targets in the background.

By default, a request without a usable policy, or with a body other than uncompressed JSON, gets a
503 response. On a dynamic forward proxy route such a request would otherwise go to the host the
client names. ``continue_without_policy`` lets it continue without a plan instead.

An upstream :ref:`AI protocol manager <config_http_filters_ai_protocol_manager>` filter with
``request_handling`` enabled then rewrites each attempt for its target: the ``:path``, the
``:authority``, the credential header and the body's ``model`` field. The credential headers of all
targets are removed first, so a credential never reaches another target, and they are removed again
once the response starts.

Deployment notes
----------------

* Enable ``tls_identity_from_host`` on the dynamic forward proxy cluster, since the attempts of one
  request connect to different hosts.
* Do not add the dynamic forward proxy HTTP filter to these routes. It only resolves the request's
  ``:authority``.
* The retry headers are merged with the route's retry policy: route ``retry_on`` conditions still
  apply and ``retriable_request_headers`` can disable retries. Leave the route without its own retry
  policy.
* The request is not translated between API protocols, so targets must speak the client's protocol.
* A retry budget on the cluster keeps fallback working during an incident; the default retry
  circuit breaker allows three concurrent retries for the whole cluster.
* The request body must fit the route's buffer limit, otherwise retries are disabled.

Limitations
-----------

* A target whose host fails to resolve is skipped within an attempt without using a retry. The
  router can then run out of targets before it runs out of retries, and the extra retry ends with a
  503 ``dfp_host_candidates_exhausted`` instead of the last provider response.
* DNS resolution of targets is not bounded by the per-try timeout; ``dns_query_timeout`` of the DNS
  cache bounds each lookup.

Example
-------

.. code-block:: yaml

  http_filters:
  - name: envoy.filters.http.model_resolver
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.model_resolver.v3.ModelResolver
      client_api_protocol: OPENAI_CHAT_COMPLETIONS
      max_retries: 3
      targets:
        vertex-pro:
          host: us-central1-aiplatform.googleapis.com
          model: google/gemini-2.5-pro
          path: /v1/projects/example/locations/us-central1/endpoints/openapi/chat/completions
          credential:
            header_name: authorization
            value_prefix: "Bearer "
            generic_secret: {name: vertex-token}
        anthropic:
          host: api.anthropic.com
          model: claude-sonnet-4-5
          path: /v1/chat/completions
          credential:
            header_name: x-api-key
            generic_secret: {name: anthropic-key}
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

The upstream filters of the dynamic forward proxy cluster:

.. code-block:: yaml

  typed_extension_protocol_options:
    envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
      "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
      http_filters:
      - name: envoy.filters.http.ai_protocol_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
          request_handling: {}
      - name: envoy.filters.http.upstream_codec
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec

Logging
-------

Downstream access logs can read the plan with
``%FILTER_STATE(envoy.ai.model_route_plan:FIELD:<field>)%``, where the field is ``decision_id``,
``selected_target``, ``selected_model``, ``selected`` (the host of the latest attempt) or
``attempts``.

Router upstream logs see each attempt's target with
``%FILTER_STATE(envoy.ai.model_attempt:FIELD:<field>)%``, where the field is ``target_id``,
``model``, ``host`` or ``attempt``.

Statistics
----------

The filter emits statistics in the ``http.<stat_prefix>.model_resolver.`` namespace.

.. csv-table::
  :header: Name, Type, Description
  :widths: 1, 1, 2

  plan_created, Counter, Requests that got a plan
  no_policy, Counter, Requests without a policy
  invalid_policy, Counter, Requests whose policy was malformed or named no usable target
  unsupported_body, Counter, Requests with a policy whose body is not uncompressed JSON
  unknown_target, Counter, Policy target IDs missing from the configuration
  incompatible_target, Counter, Policy targets that speak another API protocol
  prewarm_started, Counter, Background lookups started for fallback targets
  prewarm_overflow, Counter, Background lookups skipped by the DNS cache circuit breaker
