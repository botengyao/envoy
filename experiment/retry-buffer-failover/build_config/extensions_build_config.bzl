# Trimmed extension set for the retry-buffer failover prototype.
EXTENSIONS = {
    "envoy.access_loggers.file": "//source/extensions/access_loggers/file:config",
    "envoy.access_loggers.stdout": "//source/extensions/access_loggers/stream:config",
    "envoy.ai_protocol_manager.external_buffer.in_memory": "//source/extensions/filters/http/ai_protocol_manager:external_buffer_impl_lib",
    "envoy.clusters.static": "//source/extensions/clusters/static:static_cluster_lib",
    "envoy.clusters.strict_dns": "//source/extensions/clusters/strict_dns:strict_dns_cluster_lib",
    "envoy.filters.connection_pools.http.generic": "//source/extensions/upstreams/http/generic:config",
    "envoy.filters.http.ai_protocol_manager": "//source/extensions/filters/http/ai_protocol_manager:config",
    "envoy.filters.http.buffer": "//source/extensions/filters/http/buffer:config",
    "envoy.filters.http.credential_injector": "//source/extensions/filters/http/credential_injector:config",
    "envoy.filters.http.ext_proc": "//source/extensions/filters/http/ext_proc:config",
    "envoy.filters.http.header_mutation": "//source/extensions/filters/http/header_mutation:config",
    "envoy.filters.http.lua": "//source/extensions/filters/http/lua:config",
    "envoy.filters.http.router": "//source/extensions/filters/http/router:config",
    "envoy.filters.http.set_filter_state": "//source/extensions/filters/http/set_filter_state:config",
    "envoy.filters.http.set_metadata": "//source/extensions/filters/http/set_metadata:config",
    "envoy.filters.network.http_connection_manager": "//source/extensions/filters/network/http_connection_manager:config",
    "envoy.formatter.cel": "//source/extensions/formatter/cel:config",
    "envoy.http.ai_filters.request_info": "//source/extensions/http/ai_filters/request_info:config",
    "envoy.http.ai_filters.schema_validation": "//source/extensions/http/ai_filters/schema_validation:config",
    "envoy.http.ai_filters.transcoder": "//source/extensions/http/ai_filters/transcoder:config",
    "envoy.http.injected_credentials.generic": "//source/extensions/http/injected_credentials/generic:config",
    "envoy.http.original_ip_detection.xff": "//source/extensions/http/original_ip_detection/xff:config",
    "envoy.load_balancing_policies.cluster_provided": "//source/extensions/load_balancing_policies/cluster_provided:config",
    "envoy.load_balancing_policies.round_robin": "//source/extensions/load_balancing_policies/round_robin:config",
    "envoy.network.dns_resolver.apple": "//source/extensions/network/dns_resolver/apple:config",
    "envoy.network.dns_resolver.getaddrinfo": "//source/extensions/network/dns_resolver/getaddrinfo:config",
    "envoy.router.cluster_specifier_plugin.priority_group": "//source/extensions/router/cluster_specifiers/priority_group:config",
    "envoy.transport_sockets.raw_buffer": "//source/extensions/transport_sockets/raw_buffer:config",
    "envoy.transport_sockets.tls": "//source/extensions/transport_sockets/tls:config",
    "envoy.upstreams.http.http": "//source/extensions/upstreams/http/http:config",
    "envoy.upstreams.http.tcp": "//source/extensions/upstreams/http/tcp:config",
}
WINDOWS_EXTENSIONS = {}
EXTENSION_CONFIG_VISIBILITY = ["//:extension_config"]
EXTENSION_PACKAGE_VISIBILITY = ["//:extension_library"]
CONTRIB_EXTENSION_PACKAGE_VISIBILITY = ["//:contrib_library"]
MOBILE_PACKAGE_VISIBILITY = ["//:mobile_library"]
LEGACY_ALWAYSLINK = 1
