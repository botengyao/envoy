#include "source/extensions/filters/http/ip_load_shed/config.h"

#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"

#include "source/extensions/filters/http/ip_load_shed/ip_load_shed_filter.h"
#include "source/extensions/filters/http/ip_load_shed/water_fill_controller.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {

SINGLETON_MANAGER_REGISTRATION(water_fill_controller);

absl::StatusOr<Http::FilterFactoryCb> IpLoadShedFilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::ip_load_shed::v3::IpLoadShed& proto_config,
    const std::string&, Server::Configuration::FactoryContext& context) {
  if (proto_config.overload_action_name().empty() && proto_config.max_heap_size_bytes() == 0) {
    return absl::InvalidArgumentError(
        "ip_load_shed: one of overload_action_name or max_heap_size_bytes must be set");
  }
  if (proto_config.has_shed_start_threshold() && proto_config.has_reject_all_threshold() &&
      proto_config.shed_start_threshold().value() >=
          proto_config.reject_all_threshold().value()) {
    return absl::InvalidArgumentError(
        "ip_load_shed: shed_start_threshold must be less than reject_all_threshold");
  }

  Server::Configuration::ServerFactoryContext& server_context = context.serverFactoryContext();
  // Usage accounting and the water-fill decision are process-wide, so every filter instance
  // (across listeners and filter chains) shares one controller. The first instantiated
  // filter's config wins.
  WaterFillControllerSharedPtr controller =
      server_context.singletonManager().getTyped<WaterFillController>(
          SINGLETON_MANAGER_REGISTERED_NAME(water_fill_controller),
          [&server_context, &proto_config] {
            return std::make_shared<WaterFillController>(server_context, proto_config);
          });

  return [controller](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<IpLoadShedFilter>(controller));
  };
}

REGISTER_FACTORY(IpLoadShedFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
