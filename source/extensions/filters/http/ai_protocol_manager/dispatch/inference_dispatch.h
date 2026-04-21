#pragma once

#include <string>

#include "source/extensions/filters/http/ai_protocol_manager/dispatch/ai_dispatch_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Dispatch {

// DESIGN.md §6 — terminal inference dispatch.
//
// Supplies:
//   - Backend selection strategy (model-based vs capability-based).
//   - Response shape (chat.completion chunk framing vs full response).
//   - Error taxonomy mapping for inference APIs.
//
// Target schema (OpenAI pass-through vs Gemini/Vertex vs Claude-on-Vertex) is
// chosen by the concrete encoder passed in; this class is schema-agnostic.
// Vertex-specific URL rewrites and auth header injection land in Phase 3.

// Inference-specific dispatch config. Extends DispatchConfig with target-
// schema knobs and GCP-specific fields that the Vertex target needs. None
// of these are wired up in Phase 1.
struct InferenceDispatchConfig {
  DispatchConfig base;

  enum class TargetSchema {
    OpenAiPassThrough,
    GeminiVertex,
    ClaudeOnVertex,
  };
  TargetSchema target_schema{TargetSchema::OpenAiPassThrough};

  // GCP-specific fields used by GeminiVertex / ClaudeOnVertex targets.
  std::string gcp_project;
  std::string gcp_location;
  // Optional override; if non-empty, supersedes the request's model field.
  std::string model_name_override;
};

class InferenceDispatchFilter : public AiDispatchFilter {
public:
  InferenceDispatchFilter(InferenceDispatchConfig config, Codec::AiRequestEncoderPtr encoder,
                          Upstream::ClusterManager& cluster_manager);

  absl::Status dispatch(Codec::AiRequest& req, AiDispatchCallbacks& cb) override;

private:
  InferenceDispatchConfig inference_config_;
};

} // namespace Dispatch
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
