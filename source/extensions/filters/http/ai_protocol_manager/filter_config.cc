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
    : proto_config_(proto_config), stats_(generateStats(stats_prefix, scope)) {
  if (proto_config.has_classifier()) {
    const auto& c = proto_config.classifier();
    classifier_prefixes_.inference_prefixes.assign(c.inference_path_prefixes().begin(),
                                                   c.inference_path_prefixes().end());
    classifier_prefixes_.agent_prefixes.assign(c.agent_path_prefixes().begin(),
                                               c.agent_path_prefixes().end());
  }
  if (proto_config.has_codec() && proto_config.codec().has_max_inline_bytes()) {
    max_inline_bytes_ = proto_config.codec().max_inline_bytes().value();
  }
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
