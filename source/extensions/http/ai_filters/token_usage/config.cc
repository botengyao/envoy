#include "source/extensions/http/ai_filters/token_usage/config.h"

#include "envoy/registry/registry.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/http/ai_filters/token_usage/filter.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace TokenUsage {

absl::StatusOr<HttpFilters::AiProtocolManager::AiFilterFactoryCb>
TokenUsageFilterConfigFactory::createAiFilterFactory(
    const Protobuf::Message& config, Server::Configuration::ServerFactoryContext& context,
    Stats::Scope& scope) {
  MessageUtil::downcastAndValidate<
      const envoy::extensions::http::ai_filters::token_usage::v3::TokenUsage&>(
      config, context.messageValidationVisitor());
  auto filter_config = std::make_shared<const TokenUsageFilterConfig>(scope);
  return [filter_config](const HttpFilters::AiProtocolManager::AiFilterContext& stream_context)
             -> HttpFilters::AiProtocolManager::AiFilterSharedPtr {
    return std::make_shared<TokenUsageFilter>(filter_config, stream_context.stream_info);
  };
}

REGISTER_FACTORY(TokenUsageFilterConfigFactory,
                 HttpFilters::AiProtocolManager::AiFilterConfigFactory);

} // namespace TokenUsage
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
