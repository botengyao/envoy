#pragma once

#include <memory>

#include "envoy/http/filter.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/chain/ai_filter_chain.h"
#include "source/extensions/filters/http/ai_protocol_manager/chain/inference_chain.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_payload.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request_decoder.h"
#include "source/extensions/filters/http/ai_protocol_manager/filter_config.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// DESIGN.md §2 + §7 — terminal, decoder-only HTTP filter.
//
// Phase 2a lifecycle (implemented here):
//   decodeHeaders  → classify(); create AiRequestDecoder, PayloadStore;
//                    if classified, StopIteration so we get the full body.
//   decodeData     → feed decoder accumulator.
//   decodeTrailers → decoder.take() → AiRequest; run (empty) InferenceChain
//                    metadata phase; round-trip encode via OpenAiEncoder;
//                    emit stat; continue with the original body.
//
// Phase 2b (next commit) swaps the "continue with original body" tail for an
// Http::AsyncClient call to the configured upstream cluster, then pumps the
// response back to the downstream caller.
class AiProtocolManagerFilter : public Http::PassThroughFilter,
                                public Logger::Loggable<Logger::Id::filter> {
public:
  explicit AiProtocolManagerFilter(AiProtocolManagerConfigSharedPtr config);

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;

private:
  // Runs decoder finalize + chain + encoder round-trip. Called when the
  // request body stream has ended (either at decodeData with end_stream=true
  // or at decodeTrailers).
  void finalizeRequest();

  AiProtocolManagerConfigSharedPtr config_;

  // Per-stream state. Built in decodeHeaders once the protocol is classified.
  std::unique_ptr<Codec::PayloadStore> payload_store_;
  std::unique_ptr<Codec::AiRequestDecoder> decoder_;
  Chain::AiFilterChainPtr chain_;
  Codec::ProtocolKind protocol_{Codec::ProtocolKind::Unknown};
  bool classified_{false};
  bool finalized_{false};
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
