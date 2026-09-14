load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "filter_lib",
    srcs = ["filter.cc"],
    hdrs = ["filter.h"],
    deps = [
        "//envoy/http:codes_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//source/common/common:logger_lib",
        "//source/common/common:utility_lib",
        "//source/common/http:header_utility_lib",
        "//source/common/http:headers_lib",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/common/ai:model_route_plan_lib",
        "//source/extensions/common/dynamic_forward_proxy:dynamic_host_candidates_lib",
        "//source/extensions/filters/http/ai_protocol_manager:serializer_lib",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy_api//envoy/data/ai/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/model_resolver/v3:pkg_cc_proto",
        "@nlohmann_json//:json",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":filter_lib",
        "//envoy/registry",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/model_resolver/v3:pkg_cc_proto",
    ],
)
