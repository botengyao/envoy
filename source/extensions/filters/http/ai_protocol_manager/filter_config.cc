#include "source/extensions/filters/http/ai_protocol_manager/filter_config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

AiProtocolManagerStats generateStats(const std::string& prefix, Stats::Scope& scope) {
  const std::string final_prefix = prefix + "ai_protocol_manager.";
  return AiProtocolManagerStats{AI_PROTOCOL_MANAGER_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
}

} // namespace

AiProtocolManagerConfig::AiProtocolManagerConfig(
    const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager&
        proto_config,
    const std::string& stats_prefix, Stats::Scope& scope)
    : proto_config_(proto_config), stats_(generateStats(stats_prefix, scope)) {}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
