#pragma once

#include "envoy/http/filter.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/filter_config.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// DESIGN.md §2 — terminal, decoder-only HTTP filter. Per DESIGN.md §7, the
// request lifecycle is:
//   decodeHeaders  → classify, install PayloadStore, StopIteration.
//   decodeData     → accumulate into AiRequestDecoder.
//   decodeTrailers → take() AiRequest, run sub-chain, dispatch.
//
// Phase 1 is a PassThroughFilter: the filter is registered and instantiated
// but does not yet drive the pipeline. Phase 2 onwards wires up the stages.
class AiProtocolManagerFilter : public Http::PassThroughFilter,
                                public Logger::Loggable<Logger::Id::filter> {
public:
  explicit AiProtocolManagerFilter(AiProtocolManagerConfigSharedPtr config) : config_(config) {}

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;

private:
  AiProtocolManagerConfigSharedPtr config_;
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
