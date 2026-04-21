#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

InferencePayload* AiRequest::asInference() {
  return std::holds_alternative<InferencePayload>(payload) ? &std::get<InferencePayload>(payload)
                                                           : nullptr;
}

const InferencePayload* AiRequest::asInference() const {
  return std::holds_alternative<InferencePayload>(payload) ? &std::get<InferencePayload>(payload)
                                                           : nullptr;
}

AgentPayload* AiRequest::asAgent() {
  return std::holds_alternative<AgentPayload>(payload) ? &std::get<AgentPayload>(payload) : nullptr;
}

const AgentPayload* AiRequest::asAgent() const {
  return std::holds_alternative<AgentPayload>(payload) ? &std::get<AgentPayload>(payload) : nullptr;
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
