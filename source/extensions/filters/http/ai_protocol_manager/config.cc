#include "source/extensions/filters/http/ai_protocol_manager/config.h"

#include "envoy/registry/registry.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

Http::FilterFactoryCb AiProtocolManagerFilterConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager&
        proto_config,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {
  auto config = std::make_shared<AiProtocolManagerConfig>(proto_config, stats_prefix,
                                                          context.serverFactoryContext().scope());
  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<AiProtocolManagerFilter>(config));
  };
}

Http::FilterFactoryCb
AiProtocolManagerFilterConfigFactory::createFilterFactoryFromProtoWithServerContextTyped(
    const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager&
        proto_config,
    const std::string& stats_prefix, Server::Configuration::ServerFactoryContext& context) {
  auto config =
      std::make_shared<AiProtocolManagerConfig>(proto_config, stats_prefix, context.scope());
  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<AiProtocolManagerFilter>(config));
  };
}

/**
 * Static registration for the AI Protocol Manager filter. @see RegisterFactory.
 */
REGISTER_FACTORY(AiProtocolManagerFilterConfigFactory,
                 Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
