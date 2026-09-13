load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_test",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "model_route_plan_test",
    srcs = ["model_route_plan_test.cc"],
    rbe_pool = "linux_x64_small",
    deps = [
        "//source/extensions/common/ai:model_route_plan_lib",
        "//test/test_common:utility_lib",
    ],
)
