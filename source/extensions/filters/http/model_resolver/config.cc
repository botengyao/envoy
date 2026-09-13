#include "source/extensions/filters/http/model_resolver/config.h"

#include "envoy/registry/registry.h"

#include "source/extensions/filters/http/model_resolver/filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelResolver {

absl::StatusOr<Envoy::Http::FilterFactoryCb>
ModelResolverFilterFactory::createHttpFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::model_resolver::v3::ModelResolver& proto_config,
    Server::Configuration::ServerFactoryContext& context,
    Server::Configuration::ExtraFactoryContext& extra_context) {
  Init::Manager& init_manager = extra_context.init_manager.has_value()
                                    ? extra_context.init_manager.ref()
                                    : context.initManager();
  auto config = FilterConfig::create(proto_config, extra_context.stats_prefix,
                                     extra_context.scopeOr(context), context, init_manager);
  RETURN_IF_NOT_OK_REF(config.status());
  return [config = std::move(config.value())](
             Envoy::Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<ModelResolverFilter>(config));
  };
}

REGISTER_FACTORY(ModelResolverFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace ModelResolver
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
