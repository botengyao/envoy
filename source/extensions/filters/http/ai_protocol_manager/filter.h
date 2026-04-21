#pragma once

#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/http/async_client.h"
#include "envoy/http/filter.h"
#include "envoy/http/header_map.h"

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
// Phase 2b lifecycle:
//   decodeHeaders  → classify; build per-stream state; capture request
//                    headers for later dispatch; StopIteration (we intend to
//                    terminate the request ourselves).
//   decodeData     → feed decoder accumulator.
//   decodeTrailers → finalizeRequest: decoder.take(), run chain, encode,
//                    send via Http::AsyncClient to the configured upstream
//                    cluster.
//   onSuccess      → pump upstream response headers + body back downstream
//                    via decoder_callbacks_->encodeHeaders / encodeData.
//   onFailure      → sendLocalReply with a synthesized upstream-error body.
//
// The filter is terminal for Inference-classified requests when an
// inference dispatch target is configured. Requests classified Unknown
// (no matching prefix) fall through — the filter stays out of the way,
// preserving the Phase 2a pass-through-observer behavior.
class AiProtocolManagerFilter : public Http::PassThroughFilter,
                                public Http::AsyncClient::Callbacks,
                                public Logger::Loggable<Logger::Id::filter> {
public:
  explicit AiProtocolManagerFilter(AiProtocolManagerConfigSharedPtr config);
  ~AiProtocolManagerFilter() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;
  void onDestroy() override;

  // Http::AsyncClient::Callbacks
  void onSuccess(const Http::AsyncClient::Request& request,
                 Http::ResponseMessagePtr&& response) override;
  void onFailure(const Http::AsyncClient::Request& request,
                 Http::AsyncClient::FailureReason reason) override;
  void onBeforeFinalizeUpstreamSpan(Tracing::Span&,
                                    const Http::ResponseHeaderMap*) override {}

private:
  enum class Mode {
    PassThrough,  // Unknown protocol or no dispatch configured — observe only.
    Dispatch,     // Inference classified and upstream cluster set — terminal.
  };

  // Build and send the outbound request. Returns false on error (stats
  // already incremented by the time we return false).
  bool sendUpstream(const Buffer::Instance& encoded_body);

  // Finalize the request pipeline: decode → chain → encode → dispatch. Called
  // from decodeData(end_stream=true) or decodeTrailers().
  void finalizeRequest();

  void cancelActiveRequest();

  AiProtocolManagerConfigSharedPtr config_;
  Mode mode_{Mode::PassThrough};

  // Per-stream state.
  std::unique_ptr<Codec::PayloadStore> payload_store_;
  std::unique_ptr<Codec::AiRequestDecoder> decoder_;
  Chain::AiFilterChainPtr chain_;
  Codec::ProtocolKind protocol_{Codec::ProtocolKind::Unknown};
  bool classified_{false};
  bool finalized_{false};

  // Captured request metadata for dispatch.
  std::string request_path_;   // downstream :path at decodeHeaders time
  std::string request_host_;   // downstream :authority
  std::string request_method_;
  std::string content_type_;
  std::string authorization_;  // Authorization header, passed through to upstream

  // Parsed during finalizeRequest, consumed by sendUpstream — needed for
  // GeminiVertex URL construction.
  std::string parsed_model_;
  bool parsed_streaming_{false};

  // AsyncClient state. active_request_ is held so we can cancel on destroy.
  Http::AsyncClient::Request* active_request_{nullptr};
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
