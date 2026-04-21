#include "source/extensions/filters/http/ai_protocol_manager/codec/agent_mapping.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

absl::Status parseAgentRequest(absl::string_view /*body*/, AgentDialect /*dialect*/,
                               AiRequest& /*req*/) {
  return absl::UnimplementedError("agent mapping lands after the OpenAI/Vertex inference path");
}

absl::Status AgentJsonRpcEncoder::encode(const AiRequest& /*req*/, Buffer::Instance& /*out*/) {
  return absl::UnimplementedError("agent encoder lands after the inference path");
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
