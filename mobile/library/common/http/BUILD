load("@envoy//bazel:envoy_build_system.bzl", "envoy_cc_library", "envoy_mobile_package")

licenses(["notice"])  # Apache 2

envoy_mobile_package()

envoy_cc_library(
    name = "client_lib",
    srcs = ["client.cc"],
    hdrs = ["client.h"],
    repository = "@envoy",
    deps = [
        ":header_utility_lib",
        "//library/common:engine_types_lib",
        "//library/common/bridge:utility_lib",
        "//library/common/buffer:bridge_fragment_lib",
        "//library/common/event:provisional_dispatcher_lib",
        "//library/common/extensions/filters/http/local_error:local_error_filter_lib",
        "//library/common/extensions/filters/http/network_configuration:network_configuration_filter_lib",
        "//library/common/network:connectivity_manager_lib",
        "//library/common/network:synthetic_address_lib",
        "//library/common/stream_info:extra_stream_info_lib",
        "//library/common/system:system_helper_lib",
        "//library/common/types:c_types_lib",
        "@com_google_absl//absl/types:optional",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/common:scope_tracker_interface",
        "@envoy//envoy/event:deferred_deletable",
        "@envoy//envoy/http:api_listener_interface",
        "@envoy//envoy/http:header_map_interface",
        "@envoy//envoy/stats:stats_interface",
        "@envoy//envoy/stats:stats_macros",
        "@envoy//envoy/stats:timespan_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/buffer:watermark_buffer_lib",
        "@envoy//source/common/common:lock_guard_lib",
        "@envoy//source/common/common:minimal_logger_lib",
        "@envoy//source/common/common:random_generator_lib",
        "@envoy//source/common/http:codec_helper_lib",
        "@envoy//source/common/http:codes_lib",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/common/http:headers_lib",
        "@envoy//source/common/http:utility_lib",
        "@envoy//source/common/network:socket_lib",
        "@envoy//source/common/stats:timespan_lib",
    ],
)

envoy_cc_library(
    name = "header_utility_lib",
    srcs = ["header_utility.cc"],
    hdrs = ["header_utility.h"],
    repository = "@envoy",
    deps = [
        "//library/common/bridge:utility_lib",
        "//library/common/types:c_types_lib",
        "@envoy//envoy/buffer:buffer_interface",
        "@envoy//envoy/http:filter_interface",
        "@envoy//envoy/http:header_map_interface",
        "@envoy//source/common/http:header_map_lib",
        "@envoy//source/extensions/http/header_formatters/preserve_case:preserve_case_formatter",
    ],
)
