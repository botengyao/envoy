load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "filter_test",
    srcs = ["filter_test.cc"],
    extension_names = ["envoy.filters.http.model_resolver"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/common/stats:isolated_store_lib",
        "//source/extensions/filters/http/model_resolver:filter_lib",
        "//test/mocks/http:http_mocks",
        "//test/mocks/server:server_factory_context_mocks",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/data/ai/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test(
    name = "model_fallback_integration_test",
    size = "large",
    srcs = ["model_fallback_integration_test.cc"],
    data = ["//test/config/integration/certs"],
    extension_names = ["envoy.filters.http.model_resolver"],
    rbe_pool = "linux_x64_medium",
    deps = [
        "//source/extensions/clusters/dynamic_forward_proxy:cluster",
        "//source/extensions/filters/http/ai_protocol_manager:config",
        "//source/extensions/filters/http/model_resolver:config",
        "//source/extensions/filters/http/set_metadata:config",
        "//source/extensions/network/dns_resolver/getaddrinfo:config",
        "//test/integration:http_integration_lib",
        "//test/test_common:threadsafe_singleton_injector_lib",
        "@envoy_api//envoy/config/bootstrap/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
    ],
)
