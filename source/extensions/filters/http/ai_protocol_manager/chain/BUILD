load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "ai_filter_interface",
    srcs = ["ai_filter_callbacks.cc"],
    hdrs = [
        "ai_filter.h",
        "ai_filter_callbacks.h",
        "ai_filter_factory.h",
    ],
    deps = [
        "//envoy/event:dispatcher_interface",
        "//envoy/registry",
        "//envoy/stream_info:stream_info_interface",
        "//source/common/common:assert_lib",
        "//source/extensions/filters/http/ai_protocol_manager/codec:codec_lib",
    ],
)

envoy_cc_library(
    name = "ai_filter_chain_lib",
    srcs = [
        "agent_chain.cc",
        "ai_filter_chain.cc",
        "inference_chain.cc",
    ],
    hdrs = [
        "agent_chain.h",
        "ai_filter_chain.h",
        "inference_chain.h",
    ],
    deps = [
        ":ai_filter_interface",
        "//source/common/common:logger_lib",
        "//source/extensions/filters/http/ai_protocol_manager/codec:codec_lib",
    ],
)
