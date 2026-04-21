#include "source/extensions/filters/http/ai_protocol_manager/filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Phase 1 is intentionally pass-through. The lifecycle stages (§7) are wired
// up in subsequent phases:
//
//   Phase 2 — decodeHeaders: classify protocol, install PayloadStore, pause
//             for body. decodeData: feed AiRequestDecoder. decodeTrailers:
//             take() AiRequest, run sub-chain, hand off to DispatchFilter.
//   Phase 3 — Vertex encoder + URL rewrite in the dispatch layer.
//   Phase 4 — response-side decode/re-encode.
//   Phase 5 — SSE streaming.

Http::FilterHeadersStatus AiProtocolManagerFilter::decodeHeaders(Http::RequestHeaderMap&,
                                                                 bool /*end_stream*/) {
  config_->stats().rq_total_.inc();
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus AiProtocolManagerFilter::decodeData(Buffer::Instance&,
                                                           bool /*end_stream*/) {
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus AiProtocolManagerFilter::decodeTrailers(Http::RequestTrailerMap&) {
  return Http::FilterTrailersStatus::Continue;
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
