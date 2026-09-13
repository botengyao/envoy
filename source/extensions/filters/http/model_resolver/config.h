#pragma once

#include "envoy/extensions/filters/http/model_resolver/v3/model_resolver.pb.h"
#include "envoy/extensions/filters/http/model_resolver/v3/model_resolver.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelResolver {

class ModelResolverFilterFactory
    : public Common::UnifiedFactoryBase<
          envoy::extensions::filters::http::model_resolver::v3::ModelResolver> {
public:
  ModelResolverFilterFactory() : UnifiedFactoryBase("envoy.filters.http.model_resolver") {}

private:
  absl::StatusOr<Envoy::Http::FilterFactoryCb> createHttpFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::model_resolver::v3::ModelResolver& proto_config,
      Server::Configuration::ServerFactoryContext& context,
      Server::Configuration::ExtraFactoryContext& extra_context) override;
};

DECLARE_FACTORY(ModelResolverFilterFactory);

} // namespace ModelResolver
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
