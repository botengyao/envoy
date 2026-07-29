#include "source/extensions/filters/network/ip_load_shed/config.h"

#include "envoy/registry/registry.h"

#include "source/extensions/filters/network/ip_load_shed/ip_load_shed_filter.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace IpLoadShed {

namespace {
constexpr uint64_t DefaultConnectionCostBytes = 32 * 1024;
} // namespace

absl::StatusOr<Network::FilterFactoryCb>
IpLoadShedConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::ip_load_shed::v3::IpLoadShed& proto_config,
    Server::Configuration::FactoryContext& context) {
  const absl::Status status =
      Filters::Common::IpLoadShed::WaterFillController::validateConfig(proto_config.water_fill());
  if (!status.ok()) {
    return status;
  }

  WaterFillControllerSharedPtr controller =
      Filters::Common::IpLoadShed::WaterFillController::getOrCreate(
          context.serverFactoryContext(), proto_config.water_fill());
  const uint64_t connection_cost = proto_config.connection_cost_bytes() != 0
                                       ? proto_config.connection_cost_bytes()
                                       : DefaultConnectionCostBytes;

  return [controller, connection_cost](Network::FilterManager& filter_manager) -> void {
    filter_manager.addFilter(std::make_shared<IpLoadShedFilter>(controller, connection_cost));
  };
}

REGISTER_FACTORY(IpLoadShedConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace IpLoadShed
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
