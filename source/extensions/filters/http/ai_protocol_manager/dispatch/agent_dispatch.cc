#include "source/extensions/filters/http/ai_protocol_manager/dispatch/agent_dispatch.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Dispatch {

absl::Status AgentDispatchFilter::dispatch(Codec::AiRequest& /*req*/,
                                           AiDispatchCallbacks& /*cb*/) {
  return absl::UnimplementedError("agent dispatch lands after the inference path");
}

} // namespace Dispatch
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
