#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request_decoder.h"

#include <limits>

#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/agent_mapping.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/inference_mapping.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

AiRequestDecoder::AiRequestDecoder(const DecoderConfig& config, PayloadStore& store,
                                   ProtocolKind protocol)
    : config_(config), store_(store), protocol_(protocol),
      accumulator_(std::make_unique<Buffer::OwnedImpl>()) {}

absl::Status AiRequestDecoder::onData(absl::string_view chunk) {
  if (ended_) {
    return absl::FailedPreconditionError("onData after onEndStream");
  }
  accumulator_->add(chunk);
  return absl::OkStatus();
}

absl::Status AiRequestDecoder::onEndStream() {
  ended_ = true;
  return absl::OkStatus();
}

absl::StatusOr<AiRequest> AiRequestDecoder::take() {
  if (!ended_) {
    return absl::FailedPreconditionError("take() before onEndStream");
  }

  AiRequest req;
  req.protocol = protocol_;
  req.payload_store = &store_;

  // Flatten the accumulated body into a string_view. The accumulator stays
  // alive for the duration of take(); the mapper copies bytes into
  // PayloadStore so dangling views are not a concern. linearize() takes
  // uint32_t; bodies above 4 GiB are not expected in inference/agent traffic,
  // but we clamp defensively.
  const uint64_t len64 = accumulator_->length();
  absl::string_view body;
  if (len64 > 0) {
    if (len64 > std::numeric_limits<uint32_t>::max()) {
      return absl::InvalidArgumentError("request body exceeds 4 GiB");
    }
    const uint32_t len = static_cast<uint32_t>(len64);
    body = absl::string_view(static_cast<const char*>(accumulator_->linearize(len)), len);
  }

  switch (protocol_) {
  case ProtocolKind::Inference: {
    // Phase 2a: invocation defaults to ChatCompletion. Phase 3 derives the
    // invocation from the request path (and the classifier result).
    auto st = parseOpenAIInferenceRequest(body, InferenceInvocation::ChatCompletion, req);
    if (!st.ok()) {
      return st;
    }
    break;
  }
  case ProtocolKind::AgentMcp: {
    auto st = parseAgentRequest(body, AgentDialect::Mcp, req);
    if (!st.ok()) {
      return st;
    }
    break;
  }
  case ProtocolKind::AgentA2a: {
    auto st = parseAgentRequest(body, AgentDialect::A2a, req);
    if (!st.ok()) {
      return st;
    }
    break;
  }
  case ProtocolKind::Unknown:
    // Leave payload as monostate; caller decides whether to pass through
    // unchanged or reject.
    break;
  }
  return req;
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
