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
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//envoy/stream_info:stream_info_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:logger_lib",
        "//source/common/coroutine:status_macros_lib",
        "//source/common/coroutine:task_lib",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/filters/http/ai_protocol_manager:ai_filter_lib",
        "//source/extensions/filters/http/ai_protocol_manager:flattening_json_codec_lib",
        "//source/extensions/filters/http/ai_protocol_manager:llm_protocol_adapters_lib",
        "//source/extensions/filters/http/ai_protocol_manager:reserved_member_lib",
        "//source/extensions/filters/http/ai_protocol_manager:token_usage_lib",
        "//source/extensions/filters/http/ai_protocol_manager:transcoding_engine_lib",
        "//source/extensions/filters/http/ai_protocol_manager:usage_record_lib",
        "//source/extensions/http/ai_filters/common:sync_filter_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:variant",
        "@envoy_api//envoy/data/ai/v3:pkg_cc_proto",
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
        "//source/common/protobuf:utility_lib",
        "//source/extensions/filters/http/ai_protocol_manager:ai_filter_lib",
        "@envoy_api//envoy/extensions/http/ai_filters/token_usage/v3:pkg_cc_proto",
    ],
)
