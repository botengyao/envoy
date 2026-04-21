load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "filter_config_lib",
    srcs = ["filter_config.cc"],
    hdrs = ["filter_config.h"],
    deps = [
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//source/common/common:logger_lib",
        "@envoy_api//envoy/extensions/filters/http/ai_protocol_manager/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "filter_lib",
    srcs = ["filter.cc"],
    hdrs = ["filter.h"],
    deps = [
        ":filter_config_lib",
        "//envoy/buffer:buffer_interface",
        "//envoy/http:filter_interface",
        "//envoy/http:header_map_interface",
        "//source/common/common:logger_lib",
        "//source/extensions/filters/http/ai_protocol_manager/chain:ai_filter_chain_lib",
        "//source/extensions/filters/http/ai_protocol_manager/codec:ai_request_lib",
        "//source/extensions/filters/http/ai_protocol_manager/codec:protocol_classifier_lib",
        "//source/extensions/filters/http/ai_protocol_manager/dispatch:ai_dispatch_filter_lib",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy_api//envoy/extensions/filters/http/ai_protocol_manager/v3:pkg_cc_proto",
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
        "@envoy_api//envoy/extensions/filters/http/ai_protocol_manager/v3:pkg_cc_proto",
    ],
)
