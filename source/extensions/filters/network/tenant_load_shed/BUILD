load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "tenant_load_shed_lib",
    srcs = ["tenant_load_shed_filter.cc"],
    hdrs = ["tenant_load_shed_filter.h"],
    deps = [
        "//envoy/network:connection_interface",
        "//envoy/network:filter_interface",
        "//source/common/common:minimal_logger_lib",
        "//source/extensions/filters/common/tenant_load_shed:water_fill_controller_lib",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":tenant_load_shed_lib",
        "//envoy/registry",
        "//source/extensions/filters/common/tenant_load_shed:water_fill_controller_lib",
        "//source/extensions/filters/network/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/network/tenant_load_shed/v3:pkg_cc_proto",
    ],
)
