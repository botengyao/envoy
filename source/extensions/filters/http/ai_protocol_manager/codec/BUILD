load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

# Consolidated codec library. The decoder, mappers, and encoders are tightly
# coupled (decoder invokes the right mapper based on ProtocolKind; encoders
# are symmetric with mappers), so a single library avoids the inter-header
# cycles that would otherwise form.
envoy_cc_library(
    name = "codec_lib",
    srcs = [
        "agent_mapping.cc",
        "ai_payload.cc",
        "ai_request.cc",
        "ai_request_decoder.cc",
        "ai_request_encoder.cc",
        "gemini_encoder.cc",
        "inference_mapping.cc",
        "protocol_classifier.cc",
    ],
    hdrs = [
        "agent_mapping.h",
        "agent_payload.h",
        "ai_payload.h",
        "ai_request.h",
        "ai_request_decoder.h",
        "ai_request_encoder.h",
        "gemini_encoder.h",
        "inference_mapping.h",
        "inference_payload.h",
        "protocol_classifier.h",
    ],
    deps = [
        "//envoy/buffer:buffer_interface",
        "//envoy/http:header_map_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:logger_lib",
        "//source/common/json:json_loader_lib",
        "//source/common/protobuf:utility_lib",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:optional",
    ],
)
