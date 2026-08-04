#pragma once

#include "envoy/extensions/filters/network/tenant_load_shed/v3/tenant_load_shed.pb.h"
#include "envoy/extensions/filters/network/tenant_load_shed/v3/tenant_load_shed.pb.validate.h"

#include "source/extensions/filters/network/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace TenantLoadShed {

class TenantLoadShedConfigFactory
    : public Common::ExceptionFreeFactoryBase<
          envoy::extensions::filters::network::tenant_load_shed::v3::TenantLoadShed> {
public:
  TenantLoadShedConfigFactory() : ExceptionFreeFactoryBase("envoy.filters.network.tenant_load_shed") {}

private:
  absl::StatusOr<Network::FilterFactoryCb> createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::tenant_load_shed::v3::TenantLoadShed& proto_config,
      Server::Configuration::FactoryContext& context) override;
};

} // namespace TenantLoadShed
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
