#include "source/extensions/filters/http/ai_protocol_manager/codec/protocol_classifier.h"

#include "absl/strings/match.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

ProtocolKind classify(const Http::RequestHeaderMap& headers, absl::string_view /*jsonrpc_method*/,
                      const ClassifierPrefixes& prefixes) {
  const auto path = headers.getPathValue();
  for (const auto& pfx : prefixes.inference_prefixes) {
    if (absl::StartsWith(path, pfx)) {
      return ProtocolKind::Inference;
    }
  }
  for (const auto& pfx : prefixes.agent_prefixes) {
    if (absl::StartsWith(path, pfx)) {
      // Dialect discrimination (A2a vs Mcp) lives in the agent mapper in V1;
      // for the classifier's purposes Mcp is the safe default since it is the
      // JSON-RPC-native dialect.
      return ProtocolKind::AgentMcp;
    }
  }
  return ProtocolKind::Unknown;
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
