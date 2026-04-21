#include "source/extensions/filters/http/ai_protocol_manager/filter.h"

#include <limits>
#include <vector>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/headers.h"
#include "source/common/http/message_impl.h"
#include "source/common/http/utility.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/inference_mapping.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/protocol_classifier.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

AiProtocolManagerFilter::AiProtocolManagerFilter(AiProtocolManagerConfigSharedPtr config)
    : config_(config) {}

AiProtocolManagerFilter::~AiProtocolManagerFilter() { cancelActiveRequest(); }

void AiProtocolManagerFilter::onDestroy() { cancelActiveRequest(); }

void AiProtocolManagerFilter::cancelActiveRequest() {
  if (active_request_ != nullptr) {
    active_request_->cancel();
    active_request_ = nullptr;
  }
}

Http::FilterHeadersStatus AiProtocolManagerFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                                 bool end_stream) {
  config_->stats().rq_total_.inc();

  // DESIGN.md §4.4 — path-prefix classification.
  protocol_ = Codec::classify(headers, /*method=*/"", config_->classifierPrefixes());
  classified_ = true;

  switch (protocol_) {
  case Codec::ProtocolKind::Unknown:
    config_->stats().rq_classify_unknown_.inc();
    // Not AI traffic. Stay out of the way.
    return Http::FilterHeadersStatus::Continue;
  case Codec::ProtocolKind::Inference:
    config_->stats().rq_inference_.inc();
    break;
  case Codec::ProtocolKind::AgentMcp:
  case Codec::ProtocolKind::AgentA2a:
    config_->stats().rq_agent_.inc();
    // Agent dispatch lands alongside the agent mapper; observe only for now.
    return Http::FilterHeadersStatus::Continue;
  }

  payload_store_ = std::make_unique<Codec::InMemoryPayloadStore>();
  Codec::DecoderConfig dc;
  dc.max_inline_bytes = config_->maxInlineBytes();
  decoder_ = std::make_unique<Codec::AiRequestDecoder>(dc, *payload_store_, protocol_);
  chain_ = std::make_unique<Chain::AiFilterChain>(std::vector<Chain::AiFilterPtr>{});

  // Capture request metadata for the outbound call before the request
  // continues. Some fields (e.g. :path) can be mutated by later filters.
  request_path_ = std::string(headers.getPathValue());
  request_host_ = std::string(headers.getHostValue());
  request_method_ = std::string(headers.getMethodValue());
  content_type_ = std::string(headers.getContentTypeValue());
  if (content_type_.empty()) {
    content_type_ = Http::Headers::get().ContentTypeValues.Json;
  }

  if (config_->inferenceDispatchConfigured()) {
    mode_ = Mode::Dispatch;
  } else {
    mode_ = Mode::PassThrough;
  }

  if (end_stream) {
    finalizeRequest();
    return mode_ == Mode::Dispatch ? Http::FilterHeadersStatus::StopIteration
                                   : Http::FilterHeadersStatus::Continue;
  }

  // For Dispatch mode we intend to terminate the request ourselves and do
  // not want headers/body forwarded to the router. For PassThrough mode we
  // let the request continue so downstream filters / router can handle it.
  return mode_ == Mode::Dispatch ? Http::FilterHeadersStatus::StopIteration
                                 : Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus AiProtocolManagerFilter::decodeData(Buffer::Instance& data, bool end_stream) {
  if (!classified_ || protocol_ == Codec::ProtocolKind::Unknown || decoder_ == nullptr) {
    return Http::FilterDataStatus::Continue;
  }
  if (data.length() > 0) {
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
  return mode_ == Mode::Dispatch ? Http::FilterDataStatus::StopIterationNoBuffer
                                 : Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus
AiProtocolManagerFilter::decodeTrailers(Http::RequestTrailerMap& /*trailers*/) {
  finalizeRequest();
  return mode_ == Mode::Dispatch ? Http::FilterTrailersStatus::StopIteration
                                 : Http::FilterTrailersStatus::Continue;
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

  Chain::UnreachableCallbacks null_cb;
  (void)chain_->runMetadata(req, null_cb);

  Codec::OpenAiEncoder encoder;
  Buffer::OwnedImpl encoded;
  auto enc_st = encoder.encode(req, encoded);
  if (!enc_st.ok()) {
    config_->stats().rq_encode_error_.inc();
    if (mode_ == Mode::Dispatch) {
      decoder_callbacks_->sendLocalReply(Http::Code::InternalServerError, "encode failed", nullptr,
                                         absl::nullopt, "ai_protocol_manager_encode_error");
    }
    return;
  }
  config_->stats().rq_roundtrip_ok_.inc();

  if (mode_ != Mode::Dispatch) {
    // PassThrough: Phase 2a semantics. Do not alter or terminate the request;
    // the original body already flowed (or is being forwarded unchanged).
    return;
  }

  if (!sendUpstream(encoded)) {
    // Stat already incremented; respond 502.
    decoder_callbacks_->sendLocalReply(Http::Code::BadGateway, "upstream dispatch failed", nullptr,
                                       absl::nullopt, "ai_protocol_manager_dispatch_failed");
  }
}

bool AiProtocolManagerFilter::sendUpstream(const Buffer::Instance& encoded_body) {
  const auto& dispatch = config_->inferenceDispatch();
  auto* cluster = config_->clusterManager().getThreadLocalCluster(dispatch.upstream_cluster);
  if (cluster == nullptr) {
    config_->stats().rq_cluster_not_found_.inc();
    ENVOY_LOG(warn, "ai_protocol_manager: cluster '{}' not found", dispatch.upstream_cluster);
    return false;
  }

  const std::string& path =
      dispatch.upstream_path_override.empty() ? request_path_ : dispatch.upstream_path_override;
  const std::string& host = dispatch.upstream_host.empty() ? request_host_ : dispatch.upstream_host;
  const std::string& method = request_method_.empty() ? "POST" : request_method_;

  auto headers = Http::createHeaderMap<Http::RequestHeaderMapImpl>({
      {Http::Headers::get().Method, method},
      {Http::Headers::get().Path, path},
      {Http::Headers::get().Host, host},
      {Http::Headers::get().ContentType, content_type_},
  });
  auto message = std::make_unique<Http::RequestMessageImpl>(std::move(headers));
  // Copy the encoded body (we do not own `encoded_body`).
  message->body().add(encoded_body);

  Http::AsyncClient::RequestOptions options;
  options.setTimeout(dispatch.timeout);

  active_request_ = cluster->httpAsyncClient().send(std::move(message), *this, options);
  return active_request_ != nullptr;
}

void AiProtocolManagerFilter::onSuccess(const Http::AsyncClient::Request& /*request*/,
                                        Http::ResponseMessagePtr&& response) {
  active_request_ = nullptr;
  config_->stats().rq_dispatch_ok_.inc();

  // Materialize body and capture content-type for the synthetic reply. Phase
  // 2b is non-streaming: the entire body is buffered and handed to
  // sendLocalReply. Streaming (SSE) lives in Phase 5.
  const uint64_t status = Http::Utility::getResponseStatus(response->headers());
  std::string body = response->body().toString();

  std::string content_type;
  const auto* ct_header = response->headers().ContentType();
  if (ct_header != nullptr) {
    content_type = std::string(ct_header->value().getStringView());
  }

  decoder_callbacks_->sendLocalReply(
      static_cast<Http::Code>(status), body,
      [content_type](Http::ResponseHeaderMap& headers) {
        if (!content_type.empty()) {
          headers.setContentType(content_type);
        }
      },
      absl::nullopt, "ai_protocol_manager_dispatch_ok");
}

void AiProtocolManagerFilter::onFailure(const Http::AsyncClient::Request& /*request*/,
                                        Http::AsyncClient::FailureReason reason) {
  active_request_ = nullptr;
  config_->stats().rq_dispatch_failure_.inc();
  const char* reason_str = "unknown";
  switch (reason) {
  case Http::AsyncClient::FailureReason::Reset:
    reason_str = "upstream reset";
    break;
  case Http::AsyncClient::FailureReason::ExceedResponseBufferLimit:
    reason_str = "response buffer limit exceeded";
    break;
  }
  ENVOY_LOG(warn, "ai_protocol_manager: upstream failure ({})", reason_str);
  decoder_callbacks_->sendLocalReply(Http::Code::BadGateway, reason_str, nullptr, absl::nullopt,
                                     "ai_protocol_manager_dispatch_failed");
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
