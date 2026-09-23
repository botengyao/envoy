#include "source/extensions/http/ai_filters/transcoder/filter.h"

#include <chrono>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/router/string_accessor.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/coroutine/status_macros.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/common/ai/request_ir.h"
#include "source/extensions/filters/http/ai_protocol_manager/flattening_json_codec.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_conversion.h"
#include "source/extensions/filters/http/ai_protocol_manager/sse/sse_event.h"

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

using ::Envoy::Extensions::Common::Ai::RequestIr;
using ::Envoy::Extensions::Common::Ai::UpstreamModelFilterStateKey;
using HttpFilters::AiProtocolManager::AiFilterContext;
using HttpFilters::AiProtocolManager::AiRequest;
using HttpFilters::AiProtocolManager::AiRequestPropagator;
using HttpFilters::AiProtocolManager::AiRequestPtr;
using HttpFilters::AiProtocolManager::AiRequestReceiver;
using HttpFilters::AiProtocolManager::AiResponseStreamPropagator;
using HttpFilters::AiProtocolManager::AiResponseStreamReceiver;
using HttpFilters::AiProtocolManager::BufferManagerPtr;
using HttpFilters::AiProtocolManager::FlattenJsonField;
using HttpFilters::AiProtocolManager::JsonWithExtBuf;
using HttpFilters::AiProtocolManager::LocalReplier;
using HttpFilters::AiProtocolManager::RequestHeaderEdits;
using HttpFilters::AiProtocolManager::SseEvent;
using HttpFilters::AiProtocolManager::SseEventPtr;
using HttpFilters::AiProtocolManager::SseStreamPropagator;
using HttpFilters::AiProtocolManager::SseStreamReceiver;
using HttpFilters::AiProtocolManager::TranscodingEngine;
using TranscoderProto = envoy::extensions::http::ai_filters::transcoder::v3::Transcoder;
using UpstreamProto = envoy::extensions::http::ai_filters::transcoder::v3::Upstream;

namespace {

constexpr uint32_t DefaultMaxOutputTokens = 4096;
constexpr uint64_t DefaultMaxResponseBytes = 4 * 1024 * 1024;

bool containsExternalRef(const nlohmann::json& node) {
  if (JsonWithExtBuf::isExternalRef(node)) {
    return true;
  }
  if (node.is_object() || node.is_array()) {
    for (const nlohmann::json& child : node) {
      if (containsExternalRef(child)) {
        return true;
      }
    }
  }
  return false;
}

SseFrame toFrame(SseEvent& event) {
  SseFrame frame;
  frame.event = std::string(event.event());
  if (event.is_json()) {
    frame.json = std::move(event.json().json());
  } else if (event.raw_data_ext_refs().empty()) {
    frame.data = std::string(event.raw_data_as_string());
  }
  return frame;
}

// `store` holds the upstream frame's offloaded values; every output frame that references them
// shares it.
absl::StatusOr<SseEventPtr> toEvent(SseFrame frame, const BufferManagerPtr& store) {
  auto event = std::make_unique<SseEvent>();
  if (!frame.event.empty()) {
    RETURN_IF_NOT_OK(event->set_event(frame.event));
  }
  if (!frame.json.has_value()) {
    event->set_raw_data(std::make_unique<Buffer::OwnedImpl>(frame.data));
    return event;
  }
  if (containsExternalRef(*frame.json)) {
    if (store == nullptr) {
      return absl::InternalError("converted frame references a payload its upstream frame lacks");
    }
    event->set_payload_store(store);
  }
  JsonWithExtBuf payload;
  payload.setJson(std::move(*frame.json));
  event->set_json(std::move(payload));
  return event;
}

} // namespace

TranscoderConfig::TranscoderConfig(TranscodingEngine engine, Stats::Scope& scope)
    : stats_(TranscoderStats{
          ALL_TRANSCODER_STATS(POOL_COUNTER_PREFIX(scope, "ai_protocol_manager.transcoder."))}),
      engine_(std::move(engine)) {}

absl::StatusOr<TranscoderConfigSharedPtr> TranscoderConfig::create(const TranscoderProto& proto,
                                                                   Stats::Scope& scope) {
  absl::StatusOr<TranscodingEngine> engine = TranscodingEngine::createDefault();
  RETURN_IF_NOT_OK_REF(engine.status());
  std::shared_ptr<TranscoderConfig> config(new TranscoderConfig(std::move(engine.value()), scope));
  if (!proto.has_upstream()) {
    return config;
  }
  const UpstreamProto& upstream = proto.upstream();
  absl::StatusOr<EndpointConstPtr> endpoint = createEndpoint(upstream);
  RETURN_IF_NOT_OK_REF(endpoint.status());
  config->endpoint_ = std::move(endpoint.value());
  config->upstream_protocol_ =
      HttpFilters::AiProtocolManager::protocolFromProto(upstream.llm_protocol());
  config->model_ = upstream.model();
  config->conversion_options_.default_max_output_tokens =
      PROTOBUF_GET_WRAPPED_OR_DEFAULT(upstream, default_max_output_tokens, DefaultMaxOutputTokens);
  config->conversion_options_.reject_unsupported_fields =
      upstream.unsupported_fields() == UpstreamProto::REJECT;
  config->max_response_bytes_ =
      PROTOBUF_GET_WRAPPED_OR_DEFAULT(upstream, max_response_bytes, DefaultMaxResponseBytes);
  config->always_report_usage_ = upstream.stream_usage() == UpstreamProto::ALWAYS;
  return config;
}

TranscoderFilter::TranscoderFilter(TranscoderConfigSharedPtr config, const AiFilterContext& context)
    : config_(std::move(config)), context_(context) {}

Coroutine::Task<absl::Status> TranscoderFilter::decode(AiRequestReceiver receive_request,
                                                       AiRequestPropagator propagate_request,
                                                       LocalReplier reply_locally) {
  ASSIGN_OR_CO_RETURN(AiRequestPtr request, co_await std::move(receive_request)());
  if (config_->isInternalLeg()) {
    attachRequestIr(*request);
  } else if (std::optional<Rejection> rejection = prepareUpstreamRequest(*request);
             rejection.has_value()) {
    ENVOY_LOG(debug, "ai_transcoder: rejecting request: {}", rejection->details);
    std::move(reply_locally)(rejection->code, std::move(rejection->details));
    co_return absl::OkStatus();
  }
  co_return co_await std::move(propagate_request)(std::move(request));
}

void TranscoderFilter::attachRequestIr(AiRequest& request) {
  const LLMProtocol protocol = context_.request_protocol;
  absl::StatusOr<ClientRequest> client =
      readClientRequest(protocol, request.json(), context_.request_headers.getPathValue());
  if (!client.ok()) {
    config_->stats().ir_incomplete_.inc();
    ENVOY_LOG(debug, "ai_transcoder: no IR for this request: {}", client.status().message());
    return;
  }
  nlohmann::json ir = request.json();
  std::optional<JsonWithExtBuf> document;
  if (absl::Status status = convertRequestToIr(config_->engine(), protocol, ir, *client);
      status.ok()) {
    document.emplace();
    document->setJson(std::move(ir));
  } else {
    // The routing fields are still worth carrying without the document.
    config_->stats().ir_incomplete_.inc();
    ENVOY_LOG(debug, "ai_transcoder: IR document unavailable: {}", status.message());
  }
  request.setIr(
      std::make_shared<RequestIr>(protocol, client->model, client->stream, std::move(document)));
  config_->stats().ir_built_.inc();
}

std::string TranscoderFilter::resolveModel(const ClientRequest& client) const {
  if (!config_->model().empty()) {
    return config_->model();
  }
  if (const auto* override_model =
          context_.stream_info.filterState()->getDataReadOnly<Router::StringAccessor>(
              UpstreamModelFilterStateKey);
      override_model != nullptr && !override_model->asString().empty()) {
    return std::string(override_model->asString());
  }
  return client.model;
}

std::optional<TranscoderFilter::Rejection>
TranscoderFilter::prepareUpstreamRequest(AiRequest& request) {
  TranscoderStats& stats = config_->stats();
  const LLMProtocol client_protocol = context_.request_protocol;
  const LLMProtocol upstream_protocol = config_->upstreamProtocol();
  if (client_protocol == LLMProtocol::Unspecified) {
    stats.unsupported_pair_.inc();
    return Rejection{Http::Code::InternalServerError,
                     "ai_transcoder: the route declares no request protocol"};
  }
  if (!responseConversionSupported(upstream_protocol, client_protocol)) {
    stats.unsupported_pair_.inc();
    return Rejection{Http::Code::NotImplemented,
                     absl::StrCat("ai_transcoder: cannot serve ", llmProtocolName(client_protocol),
                                  " from ", llmProtocolName(upstream_protocol))};
  }
  const absl::string_view client_path = context_.request_headers.getPathValue();
  absl::StatusOr<ClientRequest> client =
      readClientRequest(client_protocol, request.json(), client_path);
  if (!client.ok()) {
    stats.request_rejected_.inc();
    return Rejection{Http::Code::BadRequest, std::string(client.status().message())};
  }
  // A Gemini stream without alt=sse is a JSON array, which the response side does not produce.
  if (client_protocol == LLMProtocol::GeminiGenerateContent && client->stream &&
      !absl::StrContains(client_path, "alt=sse")) {
    stats.request_rejected_.inc();
    return Rejection{Http::Code::BadRequest,
                     "ai_transcoder: streamGenerateContent requires alt=sse"};
  }

  ClientRequest resolved = client.value();
  resolved.model = resolveModel(resolved);
  absl::StatusOr<UpstreamEnvelope> envelope;
  if (client_protocol == upstream_protocol) {
    // Converted on a copy, so an unchanged body is still forwarded byte for byte.
    nlohmann::json body = request.json();
    envelope = config_->endpoint().apply(body, resolved.model, resolved.stream);
    if (envelope.ok() && envelope->body_changed) {
      request.mutableJson() = std::move(body);
    }
  } else {
    nlohmann::json& body = request.mutableJson();
    std::vector<std::string> dropped;
    if (absl::Status status = convertRequest(config_->engine(), client_protocol, upstream_protocol,
                                             body, resolved, config_->conversionOptions(), dropped);
        !status.ok()) {
      stats.request_rejected_.inc();
      return Rejection{Http::Code::BadRequest, std::string(status.message())};
    }
    if (!dropped.empty()) {
      stats.request_field_dropped_.add(dropped.size());
      ENVOY_LOG(debug, "ai_transcoder: dropped request fields {}", absl::StrJoin(dropped, ","));
    }
    envelope = config_->endpoint().apply(body, resolved.model, resolved.stream);
  }
  if (!envelope.ok()) {
    stats.request_rejected_.inc();
    return Rejection{Http::Code::BadRequest, std::string(envelope.status().message())};
  }
  client_protocol == upstream_protocol ? stats.request_passthrough_.inc()
                                       : stats.request_converted_.inc();

  RequestHeaderEdits& edits = request.headerEdits();
  edits.path = std::move(envelope->path);
  edits.set = std::move(envelope->set_headers);
  edits.remove = std::move(envelope->remove_headers);

  ResponseContext response_context;
  response_context.model = resolved.model;
  response_context.created = std::chrono::duration_cast<std::chrono::seconds>(
                                 context_.stream_info.startTime().time_since_epoch())
                                 .count();
  response_context.include_usage = resolved.include_usage;
  response_context.always_report_usage = config_->alwaysReportUsage();
  response_plan_ = ResponsePlan{upstream_protocol, client_protocol, std::move(response_context)};
  return std::nullopt;
}

Coroutine::Task<absl::Status> TranscoderFilter::encodeSSE(SseStreamReceiver receive_event,
                                                          SseStreamPropagator propagate_event) {
  if (!response_plan_.has_value() || response_plan_->from == response_plan_->to) {
    co_return absl::OkStatus();
  }
  absl::StatusOr<StreamConverterPtr> converter =
      createStreamConverter(response_plan_->from, response_plan_->to, response_plan_->context);
  if (!converter.ok()) {
    config_->stats().response_failed_.inc();
    co_return converter.status();
  }
  config_->stats().response_converted_.inc();
  while (true) {
    ASSIGN_OR_CO_RETURN(std::optional<SseEventPtr> event, co_await receive_event());
    std::vector<SseFrame> frames;
    BufferManagerPtr store;
    absl::Status status;
    if (event.has_value()) {
      store = (*event)->release_payload_store();
      status = (*converter)->onFrame(toFrame(**event), frames);
    } else {
      status = (*converter)->onEnd(frames);
    }
    if (!status.ok()) {
      config_->stats().response_failed_.inc();
      co_return status;
    }
    for (SseFrame& frame : frames) {
      absl::StatusOr<SseEventPtr> converted = toEvent(std::move(frame), store);
      if (!converted.ok()) {
        config_->stats().response_failed_.inc();
        co_return converted.status();
      }
      CO_RETURN_IF_ERROR(co_await propagate_event(std::move(converted.value())));
    }
    if (!event.has_value()) {
      co_return absl::OkStatus();
    }
  }
}

Coroutine::Task<absl::Status>
TranscoderFilter::encodeUnary(AiResponseStreamReceiver receive_fields,
                              AiResponseStreamPropagator propagate_fields) {
  if (!response_plan_.has_value() || response_plan_->from == response_plan_->to) {
    co_return absl::OkStatus();
  }
  std::vector<FlattenJsonField> fields;
  uint64_t bytes = 0;
  while (true) {
    ASSIGN_OR_CO_RETURN(std::vector<FlattenJsonField> batch, co_await receive_fields());
    if (batch.empty()) {
      break;
    }
    for (FlattenJsonField& field : batch) {
      bytes += field.byteSize();
      fields.push_back(std::move(field));
    }
    if (bytes > config_->maxResponseBytes()) {
      config_->stats().response_failed_.inc();
      co_return absl::ResourceExhaustedError("ai_transcoder: response exceeds max_response_bytes");
    }
  }
  if (fields.empty()) {
    co_return co_await propagate_fields({});
  }
  absl::StatusOr<nlohmann::json> body = HttpFilters::AiProtocolManager::unflattenJson(fields);
  if (body.ok()) {
    body = convertUnaryResponse(response_plan_->from, response_plan_->to, std::move(body.value()),
                                response_plan_->context);
  }
  if (!body.ok()) {
    config_->stats().response_failed_.inc();
    co_return body.status();
  }
  config_->stats().response_converted_.inc();
  CO_RETURN_IF_ERROR(
      co_await propagate_fields(HttpFilters::AiProtocolManager::flattenJson(body.value())));
  co_return co_await propagate_fields({});
}

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
