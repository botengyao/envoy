#pragma once

#include <cstdint>
#include <optional>

#include "envoy/stats/scope.h"
#include "envoy/stats/stats.h"
#include "envoy/stats/tag.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/stats/symbol_table.h"
#include "source/extensions/filters/http/ai_protocol_manager/stats.h"
#include "source/extensions/filters/http/ai_protocol_manager/token_usage.h"

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Caps the attribute sets each metric keeps, as the OpenTelemetry metrics SDK does: once a metric
// holds `limit` sets, measurements for a new set go to the metric's overflow series instead.
class CardinalityLimiter {
public:
  explicit CardinalityLimiter(uint32_t limit) : limit_(limit) {}

  // Whether `tags` may be recorded as a series of its own under `metric`.
  bool admit(Stats::StatName metric, const Stats::StatNameTagVector& tags);

private:
  const uint32_t limit_;
  absl::Mutex mutex_;
  Stats::StatNameHashMap<absl::flat_hash_set<uint64_t>> sets_ ABSL_GUARDED_BY(mutex_);
};

// Records the OpenTelemetry GenAI client metrics. Stat names are the spec's metric names and tag
// names its attribute names, so a stats sink exports them as the spec defines them.
class GenAiMetrics {
public:
  // The OpenTelemetry metrics SDK's default cardinality limit.
  static constexpr uint32_t DefaultCardinalityLimit = 2000;

  GenAiMetrics(Stats::ScopeSharedPtr scope, AiProtocolManagerStats& stats,
               uint32_t cardinality_limit = DefaultCardinalityLimit);

  // Records the token usage of a finished stream. Usage that names no protocol records nothing.
  void recordUsage(const StreamInfo::StreamInfo& stream_info, const TokenUsage& usage) const;

private:
  // The spec's operation name and the provider a wire API implies.
  struct ProtocolNames {
    Stats::StatName operation;
    absl::string_view provider;
  };

  std::optional<ProtocolNames> protocolNames(LLMProtocol protocol) const;
  Stats::StatNameTagVector baseTags(const StreamInfo::StreamInfo& stream_info,
                                    const TokenUsage& usage, const ProtocolNames& names,
                                    Stats::StatNameDynamicPool& pool) const;
  Stats::Counter& counter(Stats::StatName metric, const Stats::StatNameTagVector& tags) const;
  Stats::Histogram& histogram(Stats::StatName metric, const Stats::StatNameTagVector& tags) const;
  void addIfPositive(Stats::StatName metric, const Stats::StatNameTagVector& tags,
                     const std::optional<uint64_t>& value) const;

  const Stats::ScopeSharedPtr scope_;
  AiProtocolManagerStats& stats_;
  mutable CardinalityLimiter limiter_;
  Stats::StatNamePool pool_;
  const Stats::StatName usage_input_tokens_;
  const Stats::StatName usage_output_tokens_;
  const Stats::StatName usage_cache_read_input_tokens_;
  const Stats::StatName usage_cache_write_input_tokens_;
  const Stats::StatName usage_reasoning_output_tokens_;
  const Stats::StatName operation_input_tokens_;
  const Stats::StatName operation_output_tokens_;
  const Stats::StatName operation_name_;
  const Stats::StatName provider_name_;
  const Stats::StatName request_model_;
  const Stats::StatName response_model_;
  const Stats::StatName server_address_;
  const Stats::StatName server_port_;
  const Stats::StatName token_modality_;
  const Stats::StatName chat_;
  const Stats::StatName generate_content_;
  const Stats::StatName unknown_;
  const Stats::StatNameTagVector overflow_tags_;
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
