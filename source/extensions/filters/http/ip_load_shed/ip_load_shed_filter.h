#pragma once

#include <cstdint>
#include <string>

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"
#include "source/extensions/filters/http/ip_load_shed/water_fill_controller.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {

/**
 * Per-stream filter. On decodeHeaders it either sheds the stream (tenant above the current
 * water level) or admits it and starts accounting the tenant's usage: a fixed per-stream cost
 * plus every body byte seen in either direction, all released when the stream is destroyed.
 */
class IpLoadShedFilter : public Http::PassThroughFilter,
                         public Logger::Loggable<Logger::Id::filter> {
public:
  explicit IpLoadShedFilter(WaterFillControllerSharedPtr controller)
      : controller_(std::move(controller)) {}

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

  const WaterFillControllerSharedPtr controller_;
  // Tenant key: the downstream direct remote IP. Empty when the downstream address is not an
  // IP (e.g. unix domain sockets), in which case the stream is neither shed nor accounted.
  std::string ip_key_;
  int64_t accounted_bytes_{0};
};

} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
