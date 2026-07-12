#pragma once

#include "envoy/extensions/filters/http/ip_load_shed/v3/ip_load_shed.pb.h"
#include "envoy/extensions/filters/http/ip_load_shed/v3/ip_load_shed.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {

class IpLoadShedFilterFactory
    : public Common::ExceptionFreeFactoryBase<
          envoy::extensions::filters::http::ip_load_shed::v3::IpLoadShed> {
public:
  IpLoadShedFilterFactory() : ExceptionFreeFactoryBase("envoy.filters.http.ip_load_shed") {}

private:
  absl::StatusOr<Http::FilterFactoryCb> createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::ip_load_shed::v3::IpLoadShed& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
