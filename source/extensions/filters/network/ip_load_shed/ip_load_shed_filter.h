#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/network/connection.h"
#include "envoy/network/filter.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/common/ip_load_shed/water_fill_controller.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace IpLoadShed {

using Filters::Common::IpLoadShed::ShedSnapshotConstSharedPtr;
using Filters::Common::IpLoadShed::WaterFillControllerSharedPtr;

/**
 * Per-connection L4 filter sharing the process-wide water-fill controller with the HTTP
 * filter. On a new connection it either sheds (tenant above the current water level: the
 * connection is closed at accept) or admits and accounts the tenant's usage: a fixed
 * per-connection cost plus every byte seen in either direction, all released when the
 * connection is destroyed. This catches tenants an HTTP filter can never see: raw TCP
 * traffic and connections held open without issuing requests.
 *
 * Known Tier-1 accounting limitations (see filters/common/ip_load_shed/ACCOUNTING.md §2.2):
 * bytes-seen is cumulative for the connection lifetime, so a long-lived busy-but-drained
 * connection overstates its current footprint (the Tier-2 buffered-bytes ledger and/or EWMA
 * decay are the production fixes), and a paused-then-resumed read path may re-present
 * unconsumed buffer data, over-counting reads.
 */
class IpLoadShedFilter : public Network::Filter,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  IpLoadShedFilter(WaterFillControllerSharedPtr controller, uint64_t connection_cost_bytes)
      : controller_(std::move(controller)), connection_cost_bytes_(connection_cost_bytes) {}
  ~IpLoadShedFilter() override;

  // Network::ReadFilter
  Network::FilterStatus onNewConnection() override;
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    read_callbacks_ = &callbacks;
  }

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;
  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override {
    write_callbacks_ = &callbacks;
  }

private:
  void account(uint64_t bytes);

  const WaterFillControllerSharedPtr controller_;
  const uint64_t connection_cost_bytes_;
  Network::ReadFilterCallbacks* read_callbacks_{};
  Network::WriteFilterCallbacks* write_callbacks_{};
  // Tenant key per the controller's TenantKeySource config. Empty when the downstream address
  // is not an IP; such connections are neither shed nor accounted.
  std::string ip_key_;
  int64_t accounted_bytes_{0};
};

} // namespace IpLoadShed
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
