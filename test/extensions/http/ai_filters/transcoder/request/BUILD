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
    name = "client_request_test",
    srcs = ["client_request_test.cc"],
    extension_names = ["envoy.http.ai_filters.transcoder"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/http/ai_filters/transcoder/request:client_request_lib",
        "//test/test_common:status_utility_lib",
        "@nlohmann_json//:json",
    ],
)

envoy_extension_cc_test(
    name = "request_converter_test",
    srcs = ["request_converter_test.cc"],
    extension_names = ["envoy.http.ai_filters.transcoder"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/filters/http/ai_protocol_manager:transcoding_engine_lib",
        "//source/extensions/http/ai_filters/transcoder/request:request_converter_lib",
        "//test/test_common:status_utility_lib",
        "@abseil-cpp//absl/strings",
        "@nlohmann_json//:json",
    ],
)
