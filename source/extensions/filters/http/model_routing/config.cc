#include "source/extensions/filters/http/model_routing/config.h"

#include "envoy/registry/registry.h"

#include "source/extensions/filters/http/model_routing/filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelRouting {

absl::StatusOr<Envoy::Http::FilterFactoryCb>
ModelRoutingFilterFactory::createHttpFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::model_routing::v3::ModelRouting& proto_config,
    Server::Configuration::ServerFactoryContext& context,
    Server::Configuration::ExtraFactoryContext& extra_context) {
  auto config = std::make_shared<const FilterConfig>(proto_config, extra_context.stats_prefix,
                                                     extra_context.scopeOr(context));
  return [config](Envoy::Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<ModelRoutingFilter>(config));
  };
}

REGISTER_FACTORY(ModelRoutingFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace ModelRouting
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
