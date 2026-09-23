load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "anthropic_test",
    srcs = ["anthropic_test.cc"],
    extension_names = ["envoy.http.ai_filters.transcoder"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/http/ai_filters/transcoder/response:anthropic_lib",
        "//test/test_common:utility_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)

envoy_extension_cc_test(
    name = "gemini_test",
    srcs = ["gemini_test.cc"],
    extension_names = ["envoy.http.ai_filters.transcoder"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/http/ai_filters/transcoder/response:gemini_lib",
        "//test/test_common:utility_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)

envoy_extension_cc_test(
    name = "converter_test",
    srcs = ["converter_test.cc"],
    extension_names = ["envoy.http.ai_filters.transcoder"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/http/ai_filters/transcoder/response:converter_lib",
        "//test/test_common:utility_lib",
        "@nlohmann_json//:json",
    ],
)
