load(
    "//bazel:envoy_build_system.bzl",
    "envoy_benchmark_test",
    "envoy_cc_benchmark_binary",
    "envoy_cc_fuzz_test",
    "envoy_cc_test",
    "envoy_package",
    "envoy_proto_library",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_test(
    name = "message_validator_impl_test",
    srcs = ["message_validator_impl_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "//source/common/protobuf:message_validator_lib",
        "//test/common/stats:stat_test_utility_lib",
        "//test/test_common:logging_lib",
        "//test/test_common:utility_lib",
    ],
)

envoy_proto_library(
    name = "deterministic_hash_test_proto",
    srcs = ["deterministic_hash_test.proto"],
)

envoy_cc_test(
    name = "deterministic_hash_test",
    srcs = ["deterministic_hash_test.cc"],
    rbe_pool = "6gig",
    deps = [
        ":deterministic_hash_test_proto_cc_proto",
        "//source/common/protobuf:deterministic_hash_lib",
    ],
)

envoy_proto_library(
    name = "utility_test_protos",
    srcs = [
        "utility_test_file_wip.proto",
        "utility_test_file_wip_2.proto",
        "utility_test_message_field_wip.proto",
    ],
    deps = [
        "@com_github_cncf_xds//udpa/annotations:pkg",
        "@com_github_cncf_xds//xds/annotations/v3:pkg",
    ],
)

envoy_cc_test(
    name = "utility_test",
    srcs = ["utility_test.cc"],
    rbe_pool = "6gig",
    deps = [
        ":utility_test_protos_cc_proto",
        "//source/common/config:api_version_lib",
        "//source/common/protobuf:utility_lib",
        "//test/common/stats:stat_test_utility_lib",
        "//test/mocks/init:init_mocks",
        "//test/mocks/local_info:local_info_mocks",
        "//test/mocks/protobuf:protobuf_mocks",
        "//test/mocks/server:instance_mocks",
        "//test/proto:deprecated_proto_cc_proto",
        "//test/proto:sensitive_proto_cc_proto",
        "//test/test_common:environment_lib",
        "//test/test_common:logging_lib",
        "//test/test_common:status_utility_lib",
        "//test/test_common:test_runtime_lib",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/api/v2:pkg_cc_proto",
        "@envoy_api//envoy/api/v2/core:pkg_cc_proto",
        "@envoy_api//envoy/config/bootstrap/v2:pkg_cc_proto",
        "@envoy_api//envoy/config/bootstrap/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/cluster/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/v3:pkg_cc_proto",
    ],
)

envoy_cc_test(
    name = "proto_descriptor_test",
    srcs = ["proto_descriptor_test.cc"],
    rbe_pool = "6gig",
    deps = [
        "@envoy_api//bazel/cc_proto_descriptor_library:create_dynamic_message",
        "@envoy_api//bazel/cc_proto_descriptor_library:text_format_transcoder",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto_descriptor",
    ],
)

envoy_cc_fuzz_test(
    name = "value_util_fuzz_test",
    srcs = ["value_util_fuzz_test.cc"],
    corpus = "value_util_corpus",
    rbe_pool = "6gig",
    # Fuzzer is stable, no bugs, simple test target; avoid emitting CO2.
    tags = ["no_fuzz"],
    deps = ["//source/common/protobuf:utility_lib"],
)

envoy_cc_benchmark_binary(
    name = "utility_speed_test",
    srcs = ["utility_speed_test.cc"],
    rbe_pool = "6gig",
    deps = [
        ":deterministic_hash_test_proto_cc_proto",
        "//source/common/protobuf:utility_lib",
        "//test/test_common:test_runtime_lib",
        "@com_github_google_benchmark//:benchmark",
    ],
)

envoy_benchmark_test(
    name = "utility_speed_test_benchmark_test",
    benchmark_binary = "utility_speed_test",
)
