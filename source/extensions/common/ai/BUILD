load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "model_route_plan_lib",
    srcs = ["model_route_plan.cc"],
    hdrs = ["model_route_plan.h"],
    deps = [
        "//envoy/common:pure_lib",
        "//envoy/http:header_map_interface",
        "//envoy/stream_info:filter_state_interface",
        "//source/common/common:macros",
        "//source/extensions/common/dynamic_forward_proxy:dynamic_host_candidates_lib",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/strings",
        "@envoy_api//envoy/type/ai/v3:pkg_cc_proto",
    ],
)
