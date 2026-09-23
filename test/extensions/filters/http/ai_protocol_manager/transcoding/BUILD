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
    name = "anthropic_messages_test",
    srcs = ["anthropic_messages_test.cc"],
    extension_names = ["envoy.filters.http.ai_protocol_manager"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/filters/http/ai_protocol_manager/transcoding:anthropic_messages_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)

envoy_extension_cc_test(
    name = "gemini_generate_content_test",
    srcs = ["gemini_generate_content_test.cc"],
    extension_names = ["envoy.filters.http.ai_protocol_manager"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/filters/http/ai_protocol_manager/transcoding:gemini_generate_content_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)

envoy_extension_cc_test(
    name = "response_transcoder_test",
    srcs = ["response_transcoder_test.cc"],
    extension_names = ["envoy.filters.http.ai_protocol_manager"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/filters/http/ai_protocol_manager/transcoding:anthropic_messages_lib",
        "//source/extensions/filters/http/ai_protocol_manager/transcoding:gemini_generate_content_lib",
        "//source/extensions/filters/http/ai_protocol_manager/transcoding:response_transcoder_lib",
        "@abseil-cpp//absl/status",
        "@nlohmann_json//:json",
    ],
)
