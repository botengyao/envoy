#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/http/codes.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/common/ip_load_shed/water_fill_controller.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {

using Filters::Common::IpLoadShed::ShedSnapshotConstSharedPtr;
using Filters::Common::IpLoadShed::WaterFillControllerSharedPtr;

/**
 * Per-listener filter configuration: the shared controller plus L7-specific knobs.
 */
struct FilterConfig {
  WaterFillControllerSharedPtr controller_;
  uint64_t stream_cost_bytes_;
  Http::Code rejection_status_code_;
};
using FilterConfigSharedPtr = std::shared_ptr<const FilterConfig>;

/**
 * Per-stream filter. On decodeHeaders it either sheds the stream (tenant above the current
 * water level) or admits it and starts accounting the tenant's usage: a fixed per-stream cost
 * plus every body byte seen in either direction, all released when the stream is destroyed.
 */
class IpLoadShedFilter : public Http::PassThroughFilter,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  explicit IpLoadShedFilter(FilterConfigSharedPtr config) : config_(std::move(config)) {}

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;

  // Http::StreamEncoderFilter
  Http::FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) override;

  // Http::StreamFilterBase
  void onDestroy() override;

private:
  void account(uint64_t bytes);

  const FilterConfigSharedPtr config_;
  // Tenant key per the controller's TenantKeySource config. Empty when the downstream address
  // is not an IP (e.g. unix domain sockets); such streams are neither shed nor accounted.
  std::string ip_key_;
  int64_t accounted_bytes_{0};
};

} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
