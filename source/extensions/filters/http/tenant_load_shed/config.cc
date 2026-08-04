#include "source/extensions/filters/http/tenant_load_shed/config.h"

#include "envoy/registry/registry.h"

#include "source/extensions/filters/http/tenant_load_shed/tenant_load_shed_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TenantLoadShed {

namespace {
constexpr uint64_t DefaultStreamCostBytes = 64 * 1024;
} // namespace

absl::StatusOr<Http::FilterFactoryCb> TenantLoadShedFilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::tenant_load_shed::v3::TenantLoadShed& proto_config,
    const std::string&, Server::Configuration::FactoryContext& context) {
  const absl::Status status =
      Filters::Common::TenantLoadShed::WaterFillController::validateConfig(proto_config.water_fill());
  if (!status.ok()) {
    return status;
  }

  auto config = std::make_shared<const FilterConfig>(FilterConfig{
      Filters::Common::TenantLoadShed::WaterFillController::getOrCreate(
          context.serverFactoryContext(), proto_config.water_fill()),
      proto_config.stream_cost_bytes() != 0 ? proto_config.stream_cost_bytes()
                                            : DefaultStreamCostBytes,
      proto_config.rejection_status_code() != 0
          ? static_cast<Http::Code>(proto_config.rejection_status_code())
          : Http::Code::ServiceUnavailable});

  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<TenantLoadShedFilter>(config));
  };
}

REGISTER_FACTORY(TenantLoadShedFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace TenantLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
