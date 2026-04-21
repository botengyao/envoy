#pragma once

#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/http/async_client.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request_encoder.h"

#include "absl/status/status.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Dispatch {

// DESIGN.md §6 — terminal dispatch that sits at the tail of a sub-chain.
// Owns the async client; not an AiFilter (by intent — it owns I/O).
//
// V0 base is abstract; InferenceDispatchFilter and AgentDispatchFilter
// specialize backend selection, encoder choice, and response framing.

class AiDispatchCallbacks {
public:
  virtual ~AiDispatchCallbacks() = default;

  // Invoked when the dispatch has an AiResponse ready for the outer
  // AiProtocolManagerFilter to forward downstream.
  virtual void onDispatchResponse(Codec::AiResponse&& response) = 0;

  // Invoked on terminal failure; outer filter should sendLocalReply with an
  // appropriate error shape.
  virtual void onDispatchError(absl::Status status) = 0;
};

struct DispatchConfig {
  // Cluster to send the outbound request to. Resolved by the outer filter via
  // ClusterManager; V0 is single-cluster, single-backend.
  std::string upstream_cluster;

  // Upstream path (after any per-backend rewrite). InferenceDispatchFilter
  // overrides this for Vertex AI in Phase 3.
  std::string upstream_path;
};

class AiDispatchFilter : public Logger::Loggable<Logger::Id::filter> {
public:
  AiDispatchFilter(DispatchConfig config, Codec::AiRequestEncoderPtr encoder,
                   Upstream::ClusterManager& cluster_manager);
  virtual ~AiDispatchFilter() = default;

  // Entry point: the chain has run, the AiRequest is final, hand it off to
  // the upstream.
  virtual absl::Status dispatch(Codec::AiRequest& req, AiDispatchCallbacks& cb) = 0;

protected:
  DispatchConfig config_;
  Codec::AiRequestEncoderPtr encoder_;
  Upstream::ClusterManager& cluster_manager_;
};

using AiDispatchFilterPtr = std::unique_ptr<AiDispatchFilter>;

} // namespace Dispatch
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
