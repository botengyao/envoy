#pragma once

#include <memory>
#include <string>

#include "envoy/extensions/filters/http/ai_protocol_manager/v3/ai_protocol_manager.pb.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

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
  COUNTER(rq_dispatch_failure)

struct AiProtocolManagerStats {
  AI_PROTOCOL_MANAGER_STATS(GENERATE_COUNTER_STRUCT)
};

class AiProtocolManagerConfig {
public:
  AiProtocolManagerConfig(
      const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager&
          proto_config,
      const std::string& stats_prefix, Stats::Scope& scope);

  const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager&
  protoConfig() const {
    return proto_config_;
  }
  AiProtocolManagerStats& stats() { return stats_; }

private:
  const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager proto_config_;
  AiProtocolManagerStats stats_;
};

using AiProtocolManagerConfigSharedPtr = std::shared_ptr<AiProtocolManagerConfig>;

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
