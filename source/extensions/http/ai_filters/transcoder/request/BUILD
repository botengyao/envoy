load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "client_request_lib",
    srcs = ["client_request.cc"],
    hdrs = ["client_request.h"],
    deps = [
        "//source/common/http:utility_lib",
        "//source/extensions/filters/http/ai_protocol_manager:token_usage_lib",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)

envoy_cc_library(
    name = "request_converter_lib",
    srcs = ["request_converter.cc"],
    hdrs = ["request_converter.h"],
    deps = [
        ":client_request_lib",
        "//source/extensions/filters/http/ai_protocol_manager:json_with_ext_buf_lib",
        "//source/extensions/filters/http/ai_protocol_manager:llm_protocol_adapters_lib",
        "//source/extensions/filters/http/ai_protocol_manager:schema_lib",
        "//source/extensions/filters/http/ai_protocol_manager:token_usage_lib",
        "//source/extensions/filters/http/ai_protocol_manager:transcoding_engine_lib",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:span",
        "@nlohmann_json//:json",
    ],
)
