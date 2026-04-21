#include "source/extensions/filters/http/ai_protocol_manager/dispatch/inference_dispatch.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Dispatch {

InferenceDispatchFilter::InferenceDispatchFilter(InferenceDispatchConfig config,
                                                 Codec::AiRequestEncoderPtr encoder,
                                                 Upstream::ClusterManager& cluster_manager)
    : AiDispatchFilter(config.base, std::move(encoder), cluster_manager),
      inference_config_(std::move(config)) {}

absl::Status InferenceDispatchFilter::dispatch(Codec::AiRequest& /*req*/,
                                               AiDispatchCallbacks& /*cb*/) {
  // Phase 2: encode + AsyncClient send to upstream_cluster with pass-through
  // schema. Phase 3: Vertex URL rewrite + GeminiEncoder + (later) GCP auth.
  // Phase 4: response-side decode / re-encode to OpenAI shape.
  return absl::UnimplementedError("inference dispatch lands in Phase 2");
}

} // namespace Dispatch
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
