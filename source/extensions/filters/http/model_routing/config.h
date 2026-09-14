#pragma once

#include "envoy/extensions/filters/http/model_routing/v3/model_routing.pb.h"
#include "envoy/extensions/filters/http/model_routing/v3/model_routing.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelRouting {

class ModelRoutingFilterFactory
    : public Common::UnifiedFactoryBase<
          envoy::extensions::filters::http::model_routing::v3::ModelRouting> {
public:
  ModelRoutingFilterFactory() : UnifiedFactoryBase("envoy.filters.http.model_routing") {}

private:
  absl::StatusOr<Envoy::Http::FilterFactoryCb> createHttpFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::model_routing::v3::ModelRouting& proto_config,
      Server::Configuration::ServerFactoryContext& context,
      Server::Configuration::ExtraFactoryContext& extra_context) override;
};

DECLARE_FACTORY(ModelRoutingFilterFactory);

} // namespace ModelRouting
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
