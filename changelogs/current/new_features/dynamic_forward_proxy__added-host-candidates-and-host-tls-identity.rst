The dynamic forward proxy cluster now connects each upstream attempt to the next host of the
``envoy.upstream.dynamic_host_candidates`` filter state and skips hosts that fail to resolve within the
attempt. Added :ref:`tls_identity_from_host
<envoy_v3_api_field_extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig.tls_identity_from_host>`
to use each host's DNS name as the upstream SNI and verified subject alternative name.
