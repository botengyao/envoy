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
    name = "water_fill_test",
    srcs = ["water_fill_test.cc"],
    extension_names = ["envoy.filters.http.ip_load_shed"],
    rbe_pool = "6gig",
    deps = [
        "//source/extensions/filters/http/ip_load_shed:water_fill_lib",
    ],
)

envoy_extension_cc_test(
    name = "config_test",
    srcs = ["config_test.cc"],
    extension_names = ["envoy.filters.http.ip_load_shed"],
    rbe_pool = "6gig",
    deps = [
        "//source/extensions/filters/http/ip_load_shed:config",
        "//test/mocks/event:event_mocks",
        "//test/mocks/http:http_mocks",
        "//test/mocks/server:factory_context_mocks",
        "@envoy_api//envoy/extensions/filters/http/ip_load_shed/v3:pkg_cc_proto",
    ],
)
