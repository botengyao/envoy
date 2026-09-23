load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "anthropic_messages_lib",
    srcs = ["anthropic_messages.cc"],
    hdrs = ["anthropic_messages.h"],
    deps = [
        ":response_transcoder_lib",
        "//source/extensions/filters/http/ai_protocol_manager:llm_protocol_adapters_lib",
        "//source/extensions/filters/http/ai_protocol_manager:token_usage_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)

envoy_cc_library(
    name = "gemini_generate_content_lib",
    srcs = ["gemini_generate_content.cc"],
    hdrs = ["gemini_generate_content.h"],
    deps = [
        ":response_transcoder_lib",
        "//source/extensions/filters/http/ai_protocol_manager:llm_protocol_adapters_lib",
        "//source/extensions/filters/http/ai_protocol_manager:token_usage_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)

envoy_cc_library(
    name = "response_transcoder_lib",
    srcs = ["response_transcoder.cc"],
    hdrs = ["response_transcoder.h"],
    deps = [
        "//envoy/common:pure_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@nlohmann_json//:json",
    ],
)
