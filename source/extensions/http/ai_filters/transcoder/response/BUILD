load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "converter_interface",
    hdrs = ["converter.h"],
    deps = [
        "//envoy/common:pure_lib",
        "//source/extensions/filters/http/ai_protocol_manager:token_usage_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@nlohmann_json//:json",
    ],
)

envoy_cc_library(
    name = "anthropic_lib",
    srcs = ["anthropic.cc"],
    hdrs = ["anthropic.h"],
    deps = [
        ":converter_interface",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)

envoy_cc_library(
    name = "gemini_lib",
    srcs = ["gemini.cc"],
    hdrs = ["gemini.h"],
    deps = [
        ":converter_interface",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)

envoy_cc_library(
    name = "converter_lib",
    srcs = ["converter.cc"],
    deps = [
        ":anthropic_lib",
        ":converter_interface",
        ":gemini_lib",
        "@abseil-cpp//absl/strings",
    ],
)
