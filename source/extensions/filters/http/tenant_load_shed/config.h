#pragma once

#include "envoy/extensions/filters/http/tenant_load_shed/v3/tenant_load_shed.pb.h"
#include "envoy/extensions/filters/http/tenant_load_shed/v3/tenant_load_shed.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TenantLoadShed {

class TenantLoadShedFilterFactory
    : public Common::ExceptionFreeFactoryBase<
          envoy::extensions::filters::http::tenant_load_shed::v3::TenantLoadShed> {
public:
  TenantLoadShedFilterFactory() : ExceptionFreeFactoryBase("envoy.filters.http.tenant_load_shed") {}

private:
  absl::StatusOr<Http::FilterFactoryCb> createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::tenant_load_shed::v3::TenantLoadShed& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace TenantLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
