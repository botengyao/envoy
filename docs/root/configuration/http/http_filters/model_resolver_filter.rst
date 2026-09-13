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
from the filter configuration.

For each request that carries a policy, the filter:

#. Drops unknown target IDs and targets whose API protocol differs from ``client_api_protocol``.
#. Stores the ordered targets in filter state under ``envoy.ai.model_route_plan``. The same object
   is the ``envoy.upstream.dynamic_host_candidates`` host list of the
   :ref:`dynamic forward proxy cluster <envoy_v3_api_msg_extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig>`,
   so each upstream attempt connects to the host of the next target.
#. Sets ``x-envoy-retry-on``, ``x-envoy-retriable-status-codes`` and ``x-envoy-max-retries`` from the
   policy's fallback conditions, so every fallback target gets an attempt. It also sets
   ``x-envoy-upstream-rq-per-try-timeout-ms`` when the policy has a per-try timeout.
#. Optionally resolves the hosts of fallback targets in the background.

An upstream :ref:`AI protocol manager <config_http_filters_ai_protocol_manager>` filter then rewrites
each attempt for its target: the ``:path``, the ``:authority``, the credential header and the body's
``model`` field. The credential headers of all targets are removed first, so a credential never
reaches another target.

Deployment notes
----------------

* Enable ``tls_identity_from_host`` on the dynamic forward proxy cluster, since the attempts of one
  request connect to different hosts.
* Do not add the dynamic forward proxy HTTP filter to these routes. It only resolves the request's
  ``:authority``.
* The request is not translated between API protocols, so targets must speak the client's protocol.
* A retry budget on the cluster keeps fallback working during an incident; the default retry
  circuit breaker allows three concurrent retries for the whole cluster.
* The request body must fit the route's buffer limit, otherwise retries are disabled.

Example
-------

.. code-block:: yaml

  name: envoy.filters.http.model_resolver
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

Statistics
----------

The filter emits statistics in the ``http.<stat_prefix>.model_resolver.`` namespace.

.. csv-table::
  :header: Name, Type, Description
  :widths: 1, 1, 2

  plan_created, Counter, Requests that got a plan
  no_policy, Counter, Requests without a policy
  invalid_policy, Counter, Requests whose policy was malformed or named no usable target
  unknown_target, Counter, Policy target IDs missing from the configuration
  incompatible_target, Counter, Policy targets that speak another API protocol
  prewarm_started, Counter, Background lookups started for fallback targets
  prewarm_overflow, Counter, Background lookups skipped by the DNS cache circuit breaker
