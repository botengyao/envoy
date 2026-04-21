#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "envoy/extensions/filters/http/ai_protocol_manager/v3/ai_protocol_manager.pb.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/extensions/filters/http/ai_protocol_manager/codec/protocol_classifier.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// DESIGN.md §8 — AI Protocol Manager stats.
#define AI_PROTOCOL_MANAGER_STATS(COUNTER)                                                         \
  COUNTER(rq_total)                                                                                \
  COUNTER(rq_inference)                                                                            \
  COUNTER(rq_agent)                                                                                \
  COUNTER(rq_classify_unknown)                                                                     \
  COUNTER(rq_decode_error)                                                                         \
  COUNTER(rq_encode_error)                                                                         \
  COUNTER(rq_payload_offloaded)                                                                    \
  COUNTER(rq_chain_stop)                                                                           \
  COUNTER(rq_local_reply)                                                                          \
  COUNTER(rq_dispatch_failure)                                                                     \
  COUNTER(rq_dispatch_ok)                                                                          \
  COUNTER(rq_cluster_not_found)                                                                    \
  COUNTER(rq_roundtrip_ok)

struct AiProtocolManagerStats {
  AI_PROTOCOL_MANAGER_STATS(GENERATE_COUNTER_STRUCT)
};

// Resolved inference dispatch configuration.
struct InferenceDispatchConfig {
  enum class TargetSchema {
    OpenAiPassThrough,  // re-emit OpenAI-shape (default)
    GeminiVertex,       // re-emit Gemini generateContent shape
  };

  TargetSchema target_schema{TargetSchema::OpenAiPassThrough};
  std::string upstream_cluster;
  std::string upstream_path_override;  // empty ⇒ forward the downstream path (OpenAI pass-through)
  std::string upstream_host;           // empty ⇒ use the downstream host
  std::chrono::milliseconds timeout{30000};

  // GCP Vertex fields. Required when target_schema == GeminiVertex.
  std::string gcp_project;
  std::string gcp_location;
  std::string model_name_override;
};

class AiProtocolManagerConfig {
public:
  AiProtocolManagerConfig(
      const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager&
          proto_config,
      const std::string& stats_prefix, Stats::Scope& scope,
      Upstream::ClusterManager& cluster_manager);

  const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager&
  protoConfig() const {
    return proto_config_;
  }
  AiProtocolManagerStats& stats() { return stats_; }
  const Codec::ClassifierPrefixes& classifierPrefixes() const { return classifier_prefixes_; }
  std::size_t maxInlineBytes() const { return max_inline_bytes_; }
  const InferenceDispatchConfig& inferenceDispatch() const { return inference_dispatch_; }
  bool inferenceDispatchConfigured() const { return !inference_dispatch_.upstream_cluster.empty(); }
  Upstream::ClusterManager& clusterManager() { return cluster_manager_; }

private:
  const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager proto_config_;
  AiProtocolManagerStats stats_;
  Codec::ClassifierPrefixes classifier_prefixes_;
  std::size_t max_inline_bytes_{0};
  InferenceDispatchConfig inference_dispatch_;
  Upstream::ClusterManager& cluster_manager_;
};

using AiProtocolManagerConfigSharedPtr = std::shared_ptr<AiProtocolManagerConfig>;

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
