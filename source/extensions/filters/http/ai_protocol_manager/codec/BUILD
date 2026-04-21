load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "ai_payload_lib",
    srcs = ["ai_payload.cc"],
    hdrs = ["ai_payload.h"],
    deps = [
        "//envoy/buffer:buffer_interface",
        "@abseil-cpp//absl/strings",
    ],
)

envoy_cc_library(
    name = "ai_request_lib",
    srcs = ["ai_request.cc"],
    hdrs = [
        "agent_payload.h",
        "ai_request.h",
        "inference_payload.h",
    ],
    deps = [
        ":ai_payload_lib",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:optional",
    ],
)

envoy_cc_library(
    name = "protocol_classifier_lib",
    srcs = ["protocol_classifier.cc"],
    hdrs = ["protocol_classifier.h"],
    deps = [
        ":ai_request_lib",
        "//envoy/http:header_map_interface",
        "@abseil-cpp//absl/strings",
    ],
)

envoy_cc_library(
    name = "ai_request_codec_lib",
    srcs = [
        "ai_request_decoder.cc",
        "ai_request_encoder.cc",
    ],
    hdrs = [
        "ai_request_decoder.h",
        "ai_request_encoder.h",
    ],
    deps = [
        ":ai_payload_lib",
        ":ai_request_lib",
        "//envoy/buffer:buffer_interface",
        "//source/common/common:logger_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)

envoy_cc_library(
    name = "inference_mapping_lib",
    srcs = ["inference_mapping.cc"],
    hdrs = ["inference_mapping.h"],
    deps = [
        ":ai_request_codec_lib",
        ":ai_request_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
    ],
)

envoy_cc_library(
    name = "agent_mapping_lib",
    srcs = ["agent_mapping.cc"],
    hdrs = ["agent_mapping.h"],
    deps = [
        ":ai_request_codec_lib",
        ":ai_request_lib",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
    ],
)
