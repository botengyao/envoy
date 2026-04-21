#pragma once

#include "source/extensions/filters/http/ai_protocol_manager/dispatch/ai_dispatch_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Dispatch {

// Terminal agent dispatch. Mirrors InferenceDispatchFilter but targets
// A2A/MCP backends and uses the AgentJsonRpcEncoder family. Out of scope for
// the OpenAI/Vertex line of work; stubbed so the dispatch library compiles.
class AgentDispatchFilter : public AiDispatchFilter {
public:
  AgentDispatchFilter(DispatchConfig config, Codec::AiRequestEncoderPtr encoder,
                      Upstream::ClusterManager& cluster_manager)
      : AiDispatchFilter(std::move(config), std::move(encoder), cluster_manager) {}

  absl::Status dispatch(Codec::AiRequest& req, AiDispatchCallbacks& cb) override;
};

} // namespace Dispatch
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
