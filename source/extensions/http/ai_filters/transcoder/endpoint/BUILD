load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "endpoint_lib",
    srcs = ["endpoint.cc"],
    hdrs = ["endpoint.h"],
    deps = [
        "//envoy/common:pure_lib",
        "//envoy/http:header_map_interface",
        "//source/common/common:macros",
        "//source/common/http:headers_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@envoy_api//envoy/extensions/http/ai_filters/transcoder/v3:pkg_cc_proto",
        "@nlohmann_json//:json",
    ],
)
