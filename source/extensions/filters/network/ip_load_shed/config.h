#pragma once

#include "envoy/extensions/filters/network/ip_load_shed/v3/ip_load_shed.pb.h"
#include "envoy/extensions/filters/network/ip_load_shed/v3/ip_load_shed.pb.validate.h"

#include "source/extensions/filters/network/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace IpLoadShed {

class IpLoadShedConfigFactory
    : public Common::ExceptionFreeFactoryBase<
          envoy::extensions::filters::network::ip_load_shed::v3::IpLoadShed> {
public:
  IpLoadShedConfigFactory() : ExceptionFreeFactoryBase("envoy.filters.network.ip_load_shed") {}

private:
  absl::StatusOr<Network::FilterFactoryCb> createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::ip_load_shed::v3::IpLoadShed& proto_config,
      Server::Configuration::FactoryContext& context) override;
};

} // namespace IpLoadShed
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
