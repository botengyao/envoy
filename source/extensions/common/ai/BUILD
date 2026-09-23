load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "request_ir_lib",
    srcs = ["request_ir.cc"],
    hdrs = ["request_ir.h"],
    deps = [
        "//envoy/stream_info:filter_state_interface",
        "//source/extensions/filters/http/ai_protocol_manager:json_with_ext_buf_lib",
        "//source/extensions/filters/http/ai_protocol_manager:token_usage_lib",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)
