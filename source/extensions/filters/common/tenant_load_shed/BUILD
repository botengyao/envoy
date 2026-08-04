load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

# Pure water-fill solver, no Envoy dependencies.
envoy_cc_library(
    name = "water_fill_lib",
    srcs = ["water_fill.cc"],
    hdrs = ["water_fill.h"],
)

envoy_cc_library(
    name = "water_fill_controller_lib",
    srcs = ["water_fill_controller.cc"],
    hdrs = ["water_fill_controller.h"],
    deps = [
        ":water_fill_lib",
        "//envoy/event:dispatcher_interface",
        "//envoy/network:address_interface",
        "//envoy/network:socket_interface",
        "//envoy/server:factory_context_interface",
        "//envoy/singleton:instance_interface",
        "//envoy/singleton:manager_interface",
        "//envoy/stats:stats_macros",
        "//envoy/thread_local:thread_local_interface",
        "//source/common/common:minimal_logger_lib",
        "//source/common/memory:stats_lib",
        "//source/common/protobuf:utility_lib",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/synchronization",
        "@envoy_api//envoy/extensions/filters/common/tenant_load_shed/v3:pkg_cc_proto",
    ],
)
