#include "source/extensions/filters/http/ai_protocol_manager/dispatch/ai_dispatch_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Dispatch {

AiDispatchFilter::AiDispatchFilter(DispatchConfig config, Codec::AiRequestEncoderPtr encoder,
                                   Upstream::ClusterManager& cluster_manager)
    : config_(std::move(config)), encoder_(std::move(encoder)),
      cluster_manager_(cluster_manager) {}

} // namespace Dispatch
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
