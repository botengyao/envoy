#pragma once

#include <memory>
#include <optional>
#include <vector>

#include "envoy/data/ai/v3/token_usage.pb.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter.h"
#include "source/extensions/filters/http/ai_protocol_manager/flattening_json_codec.h"
#include "source/extensions/filters/http/ai_protocol_manager/usage_record.h"
#include "source/extensions/http/ai_filters/common/sync_filter.h"

#include "absl/status/status.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace TokenUsage {

#define ALL_TOKEN_USAGE_FILTER_STATS(COUNTER)                                                      \
  COUNTER(found)                                                                                   \
  COUNTER(partial)                                                                                 \
  COUNTER(failed)                                                                                  \
  COUNTER(missing)                                                                                 \
  COUNTER(total_mismatch)                                                                          \
  COUNTER(duplicate)                                                                               \
  COUNTER(api_mismatch)

struct TokenUsageFilterStats {
  ALL_TOKEN_USAGE_FILTER_STATS(GENERATE_COUNTER_STRUCT)
};

class TokenUsageFilterConfig {
public:
  explicit TokenUsageFilterConfig(Stats::Scope& scope);

  const TokenUsageFilterStats& stats() const { return stats_; }

private:
  const TokenUsageFilterStats stats_;
};
using TokenUsageFilterConfigSharedPtr = std::shared_ptr<const TokenUsageFilterConfig>;

// Publishes the token usage of a response that reaches it in the IR, OpenAI Chat Completions, as
// envoy.data.ai.v3.TokenUsage once the response ends. The record a transcoder leg carries down the
// chain (`_envoy.token_usage`) speaks for the provider and wins; otherwise the IR's `usage` is
// read. A document in another API is not read as the IR: Anthropic's `usage`, for one, would read
// with its cache buckets missing from the input count.
class TokenUsageFilter : public Common::SyncAiFilter,
                         public Logger::Loggable<Logger::Id::ai_protocol_manager> {
public:
  TokenUsageFilter(TokenUsageFilterConfigSharedPtr config, StreamInfo::StreamInfo& stream_info);

  // Common::SyncAiFilter
  absl::Status decodeSync(HttpFilters::AiProtocolManager::AiRequest&,
                          HttpFilters::AiProtocolManager::LocalReplier) override {
    return absl::OkStatus();
  }

  // HttpFilters::AiProtocolManager::AiFilter
  Coroutine::Task<absl::Status>
  encodeSSE(HttpFilters::AiProtocolManager::SseStreamReceiver receive_event,
            HttpFilters::AiProtocolManager::SseStreamPropagator propagate_event) override;
  Coroutine::Task<absl::Status>
  encodeUnary(HttpFilters::AiProtocolManager::AiResponseStreamReceiver receive_batch,
              HttpFilters::AiProtocolManager::AiResponseStreamPropagator propagate_batch) override;

private:
  // Reads one document of the response.
  void observe(const nlohmann::json& document);
  // Keeps the leaves of a unary body that its usage and its API are read from.
  void retain(const std::vector<HttpFilters::AiProtocolManager::FlattenJsonField>& batch);
  // The record a transcoder leg carried, if there is one.
  std::optional<envoy::data::ai::v3::TokenUsage> carriedRecord() const;
  void publish();
  void countPublished(const envoy::data::ai::v3::TokenUsage& record);

  TokenUsageFilterConfigSharedPtr config_;
  StreamInfo::StreamInfo& stream_info_;
  HttpFilters::AiProtocolManager::UsageAccumulator usage_;
  std::optional<nlohmann::json> record_;
  // A document in another API than the IR went unread.
  bool api_mismatch_{false};
  std::vector<HttpFilters::AiProtocolManager::FlattenJsonField> retained_;
  // The unary body is a JSON array, which the IR never is.
  bool array_body_{false};
};

} // namespace TokenUsage
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
