load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "ai_dispatch_filter_lib",
    srcs = [
        "agent_dispatch.cc",
        "ai_dispatch_filter.cc",
        "inference_dispatch.cc",
    ],
    hdrs = [
        "agent_dispatch.h",
        "ai_dispatch_filter.h",
        "inference_dispatch.h",
    ],
    deps = [
        "//envoy/buffer:buffer_interface",
        "//envoy/http:async_client_interface",
        "//envoy/http:header_map_interface",
        "//envoy/upstream:cluster_manager_interface",
        "//source/common/common:logger_lib",
        "//source/extensions/filters/http/ai_protocol_manager/chain:ai_filter_interface",
        "//source/extensions/filters/http/ai_protocol_manager/codec:ai_request_lib",
        "//source/extensions/filters/http/ai_protocol_manager/codec:ai_request_codec_lib",
        "@abseil-cpp//absl/status",
    ],
)
