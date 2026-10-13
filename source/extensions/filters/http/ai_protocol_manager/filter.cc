#include "source/extensions/filters/http/ai_protocol_manager/filter.h"

#include <memory>

#include "envoy/common/exception.h"
#include "envoy/http/codes.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/utility.h"
#include "source/common/config/utility.h"
#include "source/common/grpc/common.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/headers.h"
#include "source/common/http/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter_state.h"
#include "source/extensions/filters/http/ai_protocol_manager/filter_chain_bridge.h"
#include "source/extensions/filters/http/ai_protocol_manager/filter_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"
#include "source/extensions/filters/http/ai_protocol_manager/schema.h"

#include "absl/strings/match.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

constexpr absl::string_view SseContentType{"text/event-stream"};

// HTTP Content-Type is case-insensitive and may carry parameters
// (`application/json; charset=utf-8`).
bool contentTypeMatches(absl::string_view content_type, absl::string_view expected) {
  const absl::string_view normalized = StringUtil::trim(StringUtil::cropRight(content_type, ";"));
  return absl::EqualsIgnoreCase(normalized, expected);
}

// application/json or any +json structured-syntax suffix; parameters and
// case are ignored.
bool isJsonContentType(absl::string_view content_type) {
  const absl::string_view normalized = StringUtil::trim(StringUtil::cropRight(content_type, ";"));
  return absl::EqualsIgnoreCase(normalized, "application/json") ||
         absl::EndsWithIgnoreCase(normalized, "+json");
}

// Whether an unconfigured route's request can be held to end of stream.
//
// Holding the headers is only safe if the client finishes its request before it
// wants a response. A full-duplex stream -- gRPC or Connect streaming, an
// upgrade, CONNECT -- may instead wait on a response the held upstream cannot
// produce, and stall until it times out.
bool canHoldRequest(const Http::RequestHeaderMap& headers) {
  if (Grpc::Common::isGrpcRequestHeaders(headers) ||
      Grpc::Common::isConnectStreamingRequestHeaders(headers)) {
    return false;
  }
  if (Http::Utility::isUpgrade(headers) || Http::HeaderUtility::isConnect(headers)) {
    return false;
  }
  return isJsonContentType(headers.getContentTypeValue());
}

// Whether a response carries an unframed unary JSON body (`application/json`
// or a `+json` structured-syntax suffix, excluding gRPC / Connect streaming
// envelopes and upgraded connections).
bool isJsonResponse(const Http::ResponseHeaderMap& headers, bool end_stream) {
  if (Grpc::Common::isGrpcResponseHeaders(headers, end_stream) ||
      Grpc::Common::isConnectStreamingResponseHeaders(headers)) {
    return false;
  }
  if (Http::Utility::isUpgrade(headers)) {
    return false;
  }
  return isJsonContentType(headers.getContentTypeValue());
}

// Extraction requires an unencoded body: every entry and comma-separated
// coding of the (repeatable) Content-Encoding header must be `identity`.
bool contentEncodingIsIdentity(const Http::ResponseHeaderMap& headers) {
  const auto entries = headers.get(Http::CustomHeaders::get().ContentEncoding);
  for (size_t i = 0; i < entries.size(); ++i) {
    // keep_empty_string=true rejects malformed values like `identity,,`.
    for (const absl::string_view coding : StringUtil::splitToken(
             entries[i]->value().getStringView(), ",", /*keep_empty_string=*/true)) {
      if (!absl::EqualsIgnoreCase(StringUtil::trim(coding), "identity")) {
        return false;
      }
    }
  }
  return true;
}

} // namespace

FilterConfig::FilterConfig(
    const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager& proto,
    Stats::Scope& scope, AiFilterFactories ai_filter_factories)
    : stats_(AiProtocolManagerStats{
          ALL_AI_PROTOCOL_MANAGER_STATS(POOL_COUNTER_PREFIX(scope, "ai_protocol_manager."))}),
      request_handling_enabled_(proto.has_request_handling()),
      parse_unconfigured_routes_(proto.request_handling().parse_unconfigured_routes()),
      always_serialize_request_(
          proto.request_handling().reserialize_body() ==
          envoy::extensions::filters::http::ai_protocol_manager::v3::RequestHandling::ALWAYS),
      inline_string_threshold_bytes_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(
          proto.request_handling().limits(), inline_string_threshold_bytes,
          JsonWithExtBufParser::kDefaultInlineStringThresholdBytes)),
      ai_filter_factories_(std::move(ai_filter_factories)) {}

absl::StatusOr<FilterConfigSharedPtr> FilterConfig::create(
    const envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager& proto,
    Server::Configuration::ServerFactoryContext& context, Stats::Scope& scope) {
  if (proto.filters_size() > 0 && !proto.has_request_handling()) {
    return absl::InvalidArgumentError("ai_protocol_manager: filters require request_handling");
  }
  AiFilterFactories factories;
  for (const auto& entry : proto.filters()) {
    auto* factory =
        Config::Utility::getAndCheckFactory<AiFilterConfigFactory>(entry, /*is_optional=*/true);
    if (factory == nullptr) {
      return absl::InvalidArgumentError(
          fmt::format("ai_protocol_manager: unknown AI filter '{}' with type URL '{}'",
                      entry.name(), Config::Utility::getFactoryType(entry.typed_config())));
    }
    const ProtobufTypes::MessagePtr config = factory->createEmptyConfigProto();
    RETURN_IF_NOT_OK(Config::Utility::translateOpaqueConfig(
        entry.typed_config(), context.messageValidationVisitor(), *config));
    absl::StatusOr<AiFilterFactoryCb> cb = factory->createAiFilterFactory(*config, context, scope);
    RETURN_IF_NOT_OK_REF(cb.status());
    factories.push_back(std::move(cb.value()));
  }
  return std::make_shared<const FilterConfig>(proto, scope, std::move(factories));
}

void AiProtocolManagerFilter::onDestroy() {
  if (decode_bridge_ != nullptr) {
    // Detach the bridge first so all registered BufferManagers on this path are detached and
    // their callbacks disarmed before cancelling coroutines in filter_manager_.
    decode_bridge_->detachFromFilterChain();
  }
  if (decode_manager_ != nullptr) {
    decode_manager_->onDestroy();
  }
  if (encode_bridge_ != nullptr) {
    encode_bridge_->detachFromFilterChain();
  }
  if (encode_manager_ != nullptr) {
    encode_manager_->onDestroy();
  }
  if (filter_manager_ != nullptr) {
    filter_manager_->cancel();
  }
}

Http::FilterHeadersStatus AiProtocolManagerFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                                 bool end_stream) {
  request_headers_ = &headers;
  // Request-side processing is off entirely; per-route declarations still
  // matter to the encode path, which resolves them itself.
  if (!config_->requestHandlingEnabled()) {
    return Http::FilterHeadersStatus::Continue;
  }

  // A headers-only request carries no payload to inspect, so there is nothing to
  // hold the chain for: let the headers flow. (Pausing here would also deadlock,
  // since no body would ever arrive to drive the replay that releases them.)
  if (end_stream) {
    return Http::FilterHeadersStatus::Continue;
  }

  // Copy what the route declared; see the note on route_has_request_ for why the
  // config is not held by pointer.
  if (const RouteConfig* route_config =
          Http::Utility::resolveMostSpecificPerFilterConfig<RouteConfig>(decoder_callbacks_);
      route_config != nullptr) {
    route_has_request_ = route_config->hasRequest();
    request_protocol_ = route_config->requestProtocol();
    route_response_protocol_ = route_config->responseProtocol();
    if (route_has_request_) {
      if (const LLMProtocol declared =
              RequestLlmProtocol::fromFilterState(*decoder_callbacks_->streamInfo().filterState());
          declared != LLMProtocol::Unspecified) {
        request_protocol_ = declared;
      }
      ENVOY_LOG(debug, "ai_protocol_manager: AI endpoint with request API {}",
                llmProtocolName(request_protocol_));
    }
  }

  // A declared AI endpoint is parsed strictly. Any other route is parsed only if
  // the filter opted into parsing unconfigured routes, and only for a request
  // that can be held to end of stream without stalling it.
  // TODO(penguingao): on a best-effort parse failure, release the held headers
  // and buffered body immediately and pass the remainder through unbuffered,
  // rather than buffering to end-of-stream.
  if (!isAiEndpoint() && (!config_->parseUnconfiguredRoutes() || !canHoldRequest(headers))) {
    ENVOY_LOG(trace, "ai_protocol_manager: route has no payload to inspect, passing through");
    return Http::FilterHeadersStatus::Continue;
  }

  JsonWithExtBufParser::Config parser_config;
  parser_config.inline_string_threshold_bytes = inlineStringThresholdBytes();
  request_parser_ = std::make_unique<JsonWithExtBufParser>(parser_config);
  // Built here, not at setDecoderFilterCallbacks(), so a pass-through stream pays
  // for none of it: constructing it subscribes to upstream watermarks and claims
  // a schedulable callback.
  decode_bridge_ =
      std::make_unique<DecoderFilterChainBridge>(*decoder_callbacks_, config_->stats());
  // A request small enough that the chain would have buffered it anyway is held in memory and
  // replayed from there, so it costs no storage IO at all. Past that the chain would have pushed
  // back, which is exactly the point at which offloading starts to pay for itself.
  decode_manager_ = std::make_shared<BufferManager>(
      BufferManager::Config{decoder_callbacks_->decoderBufferLimit()}, buffer_factory_,
      *decode_bridge_);

  // Pin the headers so routing and admission filters do not act on them before
  // the payload is offloaded. decodeData() still fires while iteration is stopped
  // here; the headers are released when replay injects the first body frame (or,
  // for an empty/trailer-only body, when the manager continues iteration).
  ENVOY_LOG(trace, "ai_protocol_manager: holding headers until payload is offloaded");
  return Http::FilterHeadersStatus::StopIteration;
}

uint32_t AiProtocolManagerFilter::inlineStringThresholdBytes() const {
  // The filter's configured value is the default. A declared endpoint's payload
  // schema may pin its own, because what has to stay inline for the payload to
  // validate is a property of the wire API, not of the deployment.
  if (isAiEndpoint()) {
    if (const PayloadSchema* payload_schema = AdapterRegistry::get(request_protocol_).schema();
        payload_schema != nullptr) {
      if (const std::optional<uint32_t> pinned =
              payload_schema->requestInlineStringThresholdBytes();
          pinned.has_value()) {
        return *pinned;
      }
    }
  }
  return config_->inlineStringThresholdBytes();
}

bool AiProtocolManagerFilter::feedParser(const Buffer::Instance& data, bool end_stream) {
  // Feed the frame's slices where they lie: the parser accepts a split at any
  // byte boundary, so there is no need to join them into one block. Copying here
  // would reintroduce the per-stream footprint the external buffer avoids.
  absl::Status status = absl::OkStatus();
  const Buffer::RawSliceVector slices = data.getRawSlices();
  for (size_t i = 0; i < slices.size() && status.ok(); ++i) {
    // Only the final slice of a terminal frame closes the document.
    const bool last_slice = (i + 1 == slices.size());
    status = request_parser_->feed(
        absl::string_view(static_cast<const char*>(slices[i].mem_), slices[i].len_),
        last_slice && end_stream);
  }
  if (status.ok() && end_stream && slices.empty()) {
    // getRawSlices() omits empty slices, so a terminal frame carrying no bytes
    // leaves the document open; close it here.
    status = request_parser_->feed("", /*end_stream=*/true);
  }

  if (!status.ok()) {
    if (isAiEndpoint()) {
      config_->stats().request_parse_error_.inc();
      rejectInvalidPayload(status);
      return false;
    }
    // Best effort: the payload is forwarded as it stands, just without a
    // document for later filters to work from.
    config_->stats().request_passthrough_.inc();
    ENVOY_LOG(debug, "ai_protocol_manager: forwarding unparsed payload: {}", status.message());
    request_parser_.reset();
    return true;
  }

  if (end_stream) {
    request_json_ = request_parser_->takeDocument();
    request_parser_.reset();
    config_->stats().request_parsed_.inc();
  }
  return true;
}

void AiProtocolManagerFilter::rejectInvalidPayload(const absl::Status& status) {
  ENVOY_LOG(debug, "ai_protocol_manager: rejecting request: {}", status.message());
  payload_rejected_ = true;
  request_parser_.reset();
  decoder_callbacks_->sendLocalReply(Http::Code::BadRequest, status.message(), nullptr,
                                     std::nullopt, "ai_protocol_manager_invalid_json");
}

Http::FilterDataStatus AiProtocolManagerFilter::decodeData(Buffer::Instance& data,
                                                           bool end_stream) {
  if (decode_manager_ == nullptr) {
    // decodeHeaders() decided this stream is none of our business.
    return Http::FilterDataStatus::Continue;
  }
  if (payload_rejected_) {
    // Already terminated by the local reply; drop whatever is still in flight.
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }

  if (request_parser_ != nullptr) {
    // The framing promised a body but no byte of one arrived -- a chunked request
    // whose only chunk is the terminator, or an empty terminal DATA frame. There
    // is no payload to validate, so the request passes through, the same as one
    // that ended on its headers. The parser has been fed nothing exactly when the
    // manager has been given nothing, since every frame reaches both.
    if (end_stream && data.length() == 0 && decode_manager_->empty()) {
      request_parser_.reset();
    } else if (!feedParser(data, end_stream)) {
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
  }

  decode_manager_->onData(data);
  if (end_stream) {
    finalizeDecode(/*has_trailers=*/false);
  }
  // Hold the chain here; the BufferManager replays the payload once told to.
  return Http::FilterDataStatus::StopIterationNoBuffer;
}

Http::FilterTrailersStatus AiProtocolManagerFilter::decodeTrailers(Http::RequestTrailerMap&) {
  if (decode_manager_ == nullptr) {
    return Http::FilterTrailersStatus::Continue;
  }
  if (payload_rejected_) {
    return Http::FilterTrailersStatus::StopIteration;
  }
  // A trailer-only request (no body) has nothing to replay; let the trailers flow.
  if (decode_manager_->empty()) {
    return Http::FilterTrailersStatus::Continue;
  }

  // No data frame carried end_stream, so the document is still open. Closing it
  // here is what catches a truncated payload.
  if (request_parser_ != nullptr) {
    Buffer::OwnedImpl empty;
    if (!feedParser(empty, /*end_stream=*/true)) {
      return Http::FilterTrailersStatus::StopIteration;
    }
  }

  finalizeDecode(/*has_trailers=*/true);
  // Hold the trailers behind the replayed body until the replay-done callback
  // above releases them.
  return Http::FilterTrailersStatus::StopIteration;
}

void AiProtocolManagerFilter::finalizeDecode(bool has_trailers) {
  decode_manager_->endStream();
  auto on_complete = [this, has_trailers](absl::Status status) {
    if (!status.ok()) {
      ENVOY_LOG(error, "ai_protocol_manager: replay failed: {}", status.message());
      if (!payload_rejected_) {
        payload_rejected_ = true;
        decoder_callbacks_->sendLocalReply(Http::Code::BadGateway, status.message(), nullptr,
                                           std::nullopt, "ai_protocol_manager_replay_error");
      }
      return;
    }
    if (has_trailers) {
      // Body fully replayed; release the held trailers (they carry END_STREAM) so
      // they follow the body in order.
      decoder_callbacks_->continueDecoding();
    } else {
      // Terminate the stream with an empty end_stream data frame after the replayed
      // body (also releases the held headers when the body was empty).
      Buffer::OwnedImpl end_marker;
      decoder_callbacks_->injectDecodedDataToFilterChain(end_marker, /*end_stream=*/true);
    }
  };

  if (isAiEndpoint() && !decode_manager_->empty() && !payload_rejected_) {
    ASSERT(request_headers_ != nullptr);
    const AiFilterContext context{decoder_callbacks_->streamInfo(), *request_headers_,
                                  request_protocol_, decode_manager_->length(),
                                  route_response_protocol_};
    std::vector<AiFilterSharedPtr> filters;
    filters.reserve(config_->aiFilterFactories().size());
    for (const AiFilterFactoryCb& factory : config_->aiFilterFactories()) {
      if (AiFilterSharedPtr filter = factory(context); filter != nullptr) {
        filters.push_back(std::move(filter));
      }
    }
    // TODO(penguingao): Avoid always passing downstream StreamInfo when constructing
    // FilterManager; when AI Protocol Manager is placed in an upstream filter chain, it should
    // behave differently.
    filter_manager_ = std::make_unique<FilterManager>(std::move(filters));
    filter_manager_->startRequest(
        std::move(request_json_), decode_manager_.get(), decoder_callbacks_->dispatcher(),
        decoder_callbacks_->streamInfo(), std::move(on_complete), request_headers_,
        [this](Http::Code code, std::string details) {
          ENVOY_LOG(debug, "ai_protocol_manager: rejecting request via local reply: {} {}",
                    static_cast<uint32_t>(code), details);
          payload_rejected_ = true;
          decoder_callbacks_->sendLocalReply(code, details, nullptr, std::nullopt,
                                             "ai_protocol_manager_filter_rejected");
        },
        config_->alwaysSerializeRequest(), request_protocol_);
  } else {
    decode_manager_->replay(0, decode_manager_->length(), std::move(on_complete));
  }
}

Http::FilterHeadersStatus AiProtocolManagerFilter::encodeHeaders(Http::ResponseHeaderMap& headers,
                                                                 bool end_stream) {
  if (config_ == nullptr) {
    return Http::FilterHeadersStatus::Continue;
  }

  // TODO(penguingao): consider add request only / response only AI filter chain
  // when there is a need. Currently, all AI filters handle both request and
  // response.
  if (filter_manager_ == nullptr || payload_rejected_) {
    return Http::FilterHeadersStatus::Continue;
  }

  // Only successful responses run response filters; errors and local replies
  // pass through uninspected.
  const auto status = Http::Utility::getResponseStatusOrNullopt(headers);
  if (!status.has_value() || status.value() < 200 || status.value() >= 300) {
    return Http::FilterHeadersStatus::Continue;
  }

  const absl::string_view content_type = headers.getContentTypeValue();
  const bool is_sse = contentTypeMatches(content_type, SseContentType);
  const bool is_json = !is_sse && isJsonResponse(headers, end_stream);
  if (!is_sse && !is_json) {
    return Http::FilterHeadersStatus::Continue;
  }

  // A compressed body cannot be inspected here: unless the body is decompressed
  // before this filter on the encode path, the response filters are skipped
  // (the response is unaffected either way).
  if (!contentEncodingIsIdentity(headers)) {
    config_->stats().unsupported_content_encoding_.inc();
    return Http::FilterHeadersStatus::Continue;
  }

  if (end_stream) {
    return Http::FilterHeadersStatus::Continue;
  }

  headers.removeContentLength();
  encode_bridge_ = std::make_unique<EncoderFilterChainBridge>(
      *encoder_callbacks_, *decoder_callbacks_, config_->stats());
  encode_manager_ = std::make_shared<BufferManager>(
      BufferManager::Config{encoder_callbacks_->encoderBufferLimit()}, buffer_factory_,
      *encode_bridge_);
  if (is_sse) {
    filter_manager_->startSseResponse(
        buffer_factory_, *encode_bridge_, *encode_manager_,
        [this](absl::Status status) { onEncodeComplete(std::move(status)); });
  } else {
    filter_manager_->startUnaryResponse(
        buffer_factory_, *encode_bridge_, *encode_manager_,
        [this](absl::Status status) { onEncodeComplete(std::move(status)); });
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus AiProtocolManagerFilter::encodeData(Buffer::Instance& data,
                                                           bool end_stream) {
  if (encode_manager_ != nullptr) {
    if (encode_rejected_) {
      data.drain(data.length());
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
    if (end_stream) {
      encode_input_ended_ = true;
    }
    filter_manager_->onResponseData(data, end_stream);
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }

  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus AiProtocolManagerFilter::encodeTrailers(Http::ResponseTrailerMap&) {
  if (encode_manager_ != nullptr) {
    if (encode_rejected_) {
      return Http::FilterTrailersStatus::StopIteration;
    }
    encode_has_trailers_ = true;
    if (!encode_input_ended_) {
      encode_input_ended_ = true;
      Buffer::OwnedImpl empty;
      filter_manager_->onResponseData(empty, /*end_stream=*/true);
    }
    return Http::FilterTrailersStatus::StopIteration;
  }

  return Http::FilterTrailersStatus::Continue;
}

void AiProtocolManagerFilter::onEncodeComplete(absl::Status status) {
  if (!status.ok()) {
    ENVOY_LOG(error, "ai_protocol_manager: response filter chain failed: {}", status.message());
    if (!encode_rejected_) {
      encode_rejected_ = true;
      encoder_callbacks_->sendLocalReply(Http::Code::BadGateway, status.message(), nullptr,
                                         std::nullopt, "ai_protocol_manager_response_error");
    }
    return;
  }
  if (encode_has_trailers_) {
    encoder_callbacks_->continueEncoding();
  } else {
    Buffer::OwnedImpl end_marker;
    encoder_callbacks_->injectEncodedDataToFilterChain(end_marker, /*end_stream=*/true);
  }
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
