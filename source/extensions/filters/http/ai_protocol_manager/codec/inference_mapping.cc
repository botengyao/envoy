#include "source/extensions/filters/http/ai_protocol_manager/codec/inference_mapping.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

absl::Status parseOpenAIInferenceRequest(absl::string_view /*body*/,
                                         InferenceInvocation /*invocation*/, AiRequest& /*req*/) {
  // Phase 2 will land the real JSON → InferencePayload parser per
  // OPENAI_VERTEX_SPEC.md §2. Phase 1 leaves the request untouched so that
  // higher-layer scaffolding compiles and runs.
  return absl::OkStatus();
}

absl::Status OpenAiEncoder::encode(const AiRequest& /*req*/, Buffer::Instance& /*out*/) {
  return absl::UnimplementedError("OpenAiEncoder not implemented until Phase 2");
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
