load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "water_fill_test",
    srcs = ["water_fill_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//source/extensions/filters/common/ip_load_shed:water_fill_lib",
    ],
)
