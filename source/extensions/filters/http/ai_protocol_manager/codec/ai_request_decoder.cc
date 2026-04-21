#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request_decoder.h"

#include "source/common/buffer/buffer_impl.h"

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
  // Phase 2 plugs in the actual parsers:
  //   - Inference: plain-JSON → InferenceMapping (OpenAI shape).
  //   - AgentMcp/AgentA2a: JSON-RPC 2.0 envelope → AgentMapping.
  // Phase 1 is a no-op: yields an empty AiRequest carrying the classified
  // protocol and the store pointer so downstream scaffolding is exercised.
  AiRequest req;
  req.protocol = protocol_;
  req.payload_store = &store_;
  return req;
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
