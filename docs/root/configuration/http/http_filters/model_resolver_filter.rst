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
metadata. The policy lists targets in preference order, and each target names the host, port, model
and optional path of one endpoint. The filter has no targets of its own, so only trusted filters may
write the policy's metadata namespace.

For each request that carries a valid policy, the filter:

#. Optionally orders the targets by the models the request asks for, see `Request models`_.
#. Stores the ordered targets in filter state under ``envoy.ai.model_route_plan``. The same object
   is the ``envoy.upstream.dynamic_host_candidates`` host list of the
   :ref:`dynamic forward proxy cluster <envoy_v3_api_msg_extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig>`,
   so each upstream attempt connects to the host of the next target.
#. Sets ``x-envoy-max-retries`` to one less than the number of targets and, for plans with more than
   one target, sets ``x-envoy-retry-on`` and ``x-envoy-retriable-status-codes`` from the policy's
   fallback conditions.
#. Sets ``x-envoy-hedge-on-per-try-timeout: false``, because all attempts of a request share one
   request header map, and sets ``x-envoy-upstream-rq-per-try-timeout-ms`` from the policy's
   per-try timeout.

By default, a request without a valid policy, or with a body other than uncompressed JSON, gets a
503 response. On a dynamic forward proxy route such a request would otherwise go to the host the
client names. ``continue_without_policy`` lets it continue without a plan instead.

The :ref:`dynamic forward proxy filter <config_http_filters_dynamic_forward_proxy>` after the
resolver, with ``allow_dynamic_host_from_filter_state`` set, resolves the hosts of all targets before
the request reaches the router. Targets whose host fails to resolve get no attempt, and the retries
are lowered to the number of targets that resolved.

An upstream :ref:`AI protocol manager <config_http_filters_ai_protocol_manager>` filter with
``request_handling`` enabled then rewrites each attempt for its target: the ``:path``, the
``:authority`` and the body's ``model`` field.

Request models
--------------

With ``prefer_request_models``, an AI protocol manager filter before the resolver parses the request
body on a route that declares its request API. The request's ``models`` list, or else its ``model``,
then selects the policy targets whose ``model`` matches, in the order the request lists them.
Targets that serve the same model keep their policy order. When no target matches, for example for
``"model": "auto"``, the policy is used as it is. The request can only choose among the targets of
the policy.

Deployment notes
----------------

* Enable ``tls_identity_from_host`` on the dynamic forward proxy cluster, since the attempts of one
  request connect to different hosts.
* The filter does not handle credentials. Remove the client's credential with the route's
  ``request_headers_to_remove``, and add each provider's credential with an upstream filter after
  the AI protocol manager, for example ``envoy.filters.http.credential_injector`` selected by the
  rewritten ``:authority``.
* The retry headers are merged with the route's retry policy: route ``retry_on`` conditions still
  apply and ``retriable_request_headers`` can disable retries. Leave the route without its own retry
  policy.
* The request is not translated between API protocols, so targets must speak the client's protocol.
* A retry budget on the cluster keeps fallback working during an incident; the default retry
  circuit breaker allows three concurrent retries for the whole cluster.
* The request body must fit the route's buffer limit, otherwise retries are disabled.

Limitations
-----------

* A host that resolved when the request started, but fails to resolve again before its attempt, is
  skipped within that attempt. The router can then run out of targets before it runs out of
  retries, and the extra retry ends with a 503 ``dfp_host_candidates_exhausted``.
* DNS resolution of targets is not bounded by the per-try timeout; ``dns_query_timeout`` of the DNS
  cache bounds each lookup.

Example
-------

A policy in the JSON form that a policy decision point can return as ``envoy.ai.model_routing``
dynamic metadata:

.. code-block:: json

  {
    "targets": [
      {
        "id": "vertex",
        "host": "us-central1-aiplatform.googleapis.com",
        "model": "google/gemini-2.5-pro",
        "path": "/v1/projects/example/locations/us-central1/endpoints/openapi/chat/completions"
      },
      {
        "id": "anthropic",
        "host": "api.anthropic.com",
        "model": "claude-sonnet-4-5",
        "path": "/v1/chat/completions"
      }
    ],
    "fallback_on": ["CONNECT_FAILURE", "RATE_LIMITED", "OVERLOADED"],
    "decision_id": "d-42"
  }

The filters after the policy decision point:

.. code-block:: yaml

  http_filters:
  - name: envoy.filters.http.model_resolver
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.model_resolver.v3.ModelResolver
  - name: envoy.filters.http.dynamic_forward_proxy
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
      allow_dynamic_host_from_filter_state: true
      dns_cache_config:
        name: ai_dns
        dns_lookup_family: V4_ONLY
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

The dynamic forward proxy cluster, which uses the same DNS cache:

.. code-block:: yaml

  name: ai_dfp
  lb_policy: CLUSTER_PROVIDED
  cluster_type:
    name: envoy.clusters.dynamic_forward_proxy
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
      tls_identity_from_host: true
      dns_cache_config:
        name: ai_dns
        dns_lookup_family: V4_ONLY
  typed_extension_protocol_options:
    envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
      "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
      auto_config: {}
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
  invalid_policy, Counter, Requests whose policy was malformed or named an invalid target
  unsupported_body, Counter, Requests with a policy whose body is not uncompressed JSON
  request_models_unmatched, Counter, Requests whose models matched no policy target
