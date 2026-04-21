#include "source/extensions/filters/http/ai_protocol_manager/filter.h"

#include <limits>
#include <vector>

#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/inference_mapping.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/protocol_classifier.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

AiProtocolManagerFilter::AiProtocolManagerFilter(AiProtocolManagerConfigSharedPtr config)
    : config_(config) {}

Http::FilterHeadersStatus AiProtocolManagerFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                                 bool end_stream) {
  config_->stats().rq_total_.inc();

  // DESIGN.md §4.4 — path-prefix classification. method argument is unused
  // here; it becomes relevant once the decoder exposes the JSON-RPC method
  // token to the classifier for agent protocols.
  protocol_ = Codec::classify(headers, /*method=*/"", config_->classifierPrefixes());
  classified_ = true;

  switch (protocol_) {
  case Codec::ProtocolKind::Unknown:
    config_->stats().rq_classify_unknown_.inc();
    // Not AI traffic (or no classifier prefixes configured). Stay out of the
    // way — no decoder built, no pipeline.
    return Http::FilterHeadersStatus::Continue;
  case Codec::ProtocolKind::Inference:
    config_->stats().rq_inference_.inc();
    break;
  case Codec::ProtocolKind::AgentMcp:
  case Codec::ProtocolKind::AgentA2a:
    config_->stats().rq_agent_.inc();
    break;
  }

  payload_store_ = std::make_unique<Codec::InMemoryPayloadStore>();
  Codec::DecoderConfig dc;
  dc.max_inline_bytes = config_->maxInlineBytes();
  decoder_ = std::make_unique<Codec::AiRequestDecoder>(dc, *payload_store_, protocol_);
  // Empty chain for Phase 2a. Real AiFilter factories land in a later phase.
  chain_ = std::make_unique<Chain::AiFilterChain>(std::vector<Chain::AiFilterPtr>{});

  if (end_stream) {
    finalizeRequest();
    return Http::FilterHeadersStatus::Continue;
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus AiProtocolManagerFilter::decodeData(Buffer::Instance& data, bool end_stream) {
  if (!classified_ || protocol_ == Codec::ProtocolKind::Unknown) {
    return Http::FilterDataStatus::Continue;
  }
  if (decoder_ != nullptr && data.length() > 0) {
    const uint64_t len64 = data.length();
    if (len64 > std::numeric_limits<uint32_t>::max()) {
      config_->stats().rq_decode_error_.inc();
      decoder_.reset();
    } else {
      const uint32_t len = static_cast<uint32_t>(len64);
      const absl::string_view view(static_cast<const char*>(data.linearize(len)), len);
      auto st = decoder_->onData(view);
      if (!st.ok()) {
        config_->stats().rq_decode_error_.inc();
        decoder_.reset();
      }
    }
  }
  if (end_stream) {
    finalizeRequest();
  }
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus
AiProtocolManagerFilter::decodeTrailers(Http::RequestTrailerMap& /*trailers*/) {
  finalizeRequest();
  return Http::FilterTrailersStatus::Continue;
}

void AiProtocolManagerFilter::finalizeRequest() {
  if (finalized_ || decoder_ == nullptr) {
    return;
  }
  finalized_ = true;

  auto end_st = decoder_->onEndStream();
  if (!end_st.ok()) {
    config_->stats().rq_decode_error_.inc();
    return;
  }
  auto req_or = decoder_->take();
  if (!req_or.ok()) {
    config_->stats().rq_decode_error_.inc();
    return;
  }
  Codec::AiRequest& req = *req_or;

  // Phase 2a: run the metadata phase on an empty chain. UnreachableCallbacks
  // will panic if any filter actually calls through — fine, because the chain
  // is provably empty. A real callbacks impl lands when the filter carries
  // meaningful AiFilters.
  Chain::UnreachableCallbacks null_cb;
  (void)chain_->runMetadata(req, null_cb);

  // Round-trip encode via the default OpenAI encoder to prove the pipeline
  // composed correctly. Phase 2b replaces this with an AsyncClient outbound.
  Codec::OpenAiEncoder encoder;
  Buffer::OwnedImpl out;
  auto enc_st = encoder.encode(req, out);
  if (!enc_st.ok()) {
    config_->stats().rq_encode_error_.inc();
    return;
  }
  config_->stats().rq_roundtrip_ok_.inc();
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
