#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "envoy/extensions/http/ai_filters/transcoder/v3/transcoder.pb.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter.h"
#include "source/extensions/filters/http/ai_protocol_manager/transcoding_engine.h"
#include "source/extensions/http/ai_filters/transcoder/endpoint/endpoint.h"
#include "source/extensions/http/ai_filters/transcoder/request/client_request.h"
#include "source/extensions/http/ai_filters/transcoder/request/request_converter.h"
#include "source/extensions/http/ai_filters/transcoder/response/converter.h"

#include "absl/status/statusor.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

#define ALL_TRANSCODER_STATS(COUNTER)                                                              \
  COUNTER(ir_built)                                                                                \
  COUNTER(ir_incomplete)                                                                           \
  COUNTER(request_converted)                                                                       \
  COUNTER(request_passthrough)                                                                     \
  COUNTER(request_rejected)                                                                        \
  COUNTER(request_field_dropped)                                                                   \
  COUNTER(unsupported_pair)                                                                        \
  COUNTER(response_converted)                                                                      \
  COUNTER(response_failed)

struct TranscoderStats {
  ALL_TRANSCODER_STATS(GENERATE_COUNTER_STRUCT)
};

class TranscoderConfig {
public:
  static absl::StatusOr<std::shared_ptr<const TranscoderConfig>>
  create(const envoy::extensions::http::ai_filters::transcoder::v3::Transcoder& proto,
         Stats::Scope& scope);

  bool isInternalLeg() const { return endpoint_ == nullptr; }
  LLMProtocol upstreamProtocol() const { return upstream_protocol_; }
  const Endpoint& endpoint() const { return *endpoint_; }
  const std::string& model() const { return model_; }
  const HttpFilters::AiProtocolManager::TranscodingEngine& engine() const { return engine_; }
  const RequestConversionOptions& conversionOptions() const { return conversion_options_; }
  uint64_t maxResponseBytes() const { return max_response_bytes_; }
  bool alwaysReportUsage() const { return always_report_usage_; }
  TranscoderStats& stats() const { return stats_; }

private:
  TranscoderConfig(HttpFilters::AiProtocolManager::TranscodingEngine engine, Stats::Scope& scope);

  // Counters are thread-safe to increment; mutable so a shared const config serves them.
  mutable TranscoderStats stats_;
  HttpFilters::AiProtocolManager::TranscodingEngine engine_;
  EndpointConstPtr endpoint_;
  LLMProtocol upstream_protocol_{LLMProtocol::Unspecified};
  std::string model_;
  RequestConversionOptions conversion_options_;
  uint64_t max_response_bytes_{0};
  bool always_report_usage_{true};
};

using TranscoderConfigSharedPtr = std::shared_ptr<const TranscoderConfig>;

// Bridges LLM protocols in two legs. The internal leg, first in a downstream AI filter chain,
// attaches the request's IR for the filters after it, and the AI Protocol Manager can publish it.
// The upstream leg converts the client's request, never the IR, to the upstream's protocol and
// endpoint, and converts the response back.
class TranscoderFilter : public HttpFilters::AiProtocolManager::AiFilter,
                         public Logger::Loggable<Logger::Id::ai_protocol_manager> {
public:
  TranscoderFilter(TranscoderConfigSharedPtr config,
                   const HttpFilters::AiProtocolManager::AiFilterContext& context);

  // HttpFilters::AiProtocolManager::AiFilter
  Coroutine::Task<absl::Status>
  decode(HttpFilters::AiProtocolManager::AiRequestReceiver receive_request,
         HttpFilters::AiProtocolManager::AiRequestPropagator propagate_request,
         HttpFilters::AiProtocolManager::LocalReplier reply_locally) override;
  Coroutine::Task<absl::Status>
  encodeSSE(HttpFilters::AiProtocolManager::SseStreamReceiver receive_event,
            HttpFilters::AiProtocolManager::SseStreamPropagator propagate_event) override;
  Coroutine::Task<absl::Status>
  encodeUnary(HttpFilters::AiProtocolManager::AiResponseStreamReceiver receive_fields,
              HttpFilters::AiProtocolManager::AiResponseStreamPropagator propagate_fields) override;

private:
  // How the response comes back, set once the upstream leg has sent the request.
  struct ResponsePlan {
    LLMProtocol from;
    LLMProtocol to;
    ResponseContext context;
  };

  void attachRequestIr(HttpFilters::AiProtocolManager::AiRequest& request);

  // Rewrites `request` for the upstream. Returns the local reply to send instead, if any.
  struct Rejection {
    Http::Code code;
    std::string details;
  };
  std::optional<Rejection>
  prepareUpstreamRequest(HttpFilters::AiProtocolManager::AiRequest& request);

  std::string resolveModel(const ClientRequest& client) const;

  TranscoderConfigSharedPtr config_;
  const HttpFilters::AiProtocolManager::AiFilterContext context_;
  std::optional<ResponsePlan> response_plan_;
};

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
