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
    name = "endpoint_test",
    srcs = ["endpoint_test.cc"],
    extension_names = ["envoy.http.ai_filters.transcoder"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/http/ai_filters/transcoder/endpoint:endpoint_lib",
        "//test/test_common:utility_lib",
        "@abseil-cpp//absl/strings",
        "@envoy_api//envoy/extensions/http/ai_filters/transcoder/v3:pkg_cc_proto",
        "@nlohmann_json//:json",
    ],
)
