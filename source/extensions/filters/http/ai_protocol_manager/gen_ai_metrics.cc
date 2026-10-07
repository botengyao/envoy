#include "source/extensions/filters/http/ai_protocol_manager/gen_ai_metrics.h"

#include "envoy/router/string_accessor.h"
#include "envoy/upstream/host_description.h"
#include "envoy/upstream/upstream.h"

#include "source/common/common/macros.h"
#include "source/common/config/metadata.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter_state.h"
#include "source/extensions/filters/http/ai_protocol_manager/gen_ai_convention.h"

#include "absl/algorithm/container.h"
#include "absl/hash/hash.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

constexpr size_t MaxValueLength = 128;

// Where a cluster names its provider when the wire API does not, e.g. vLLM behind the OpenAI API.
const std::string& providerMetadataNamespace() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.filters.http.ai_protocol_manager");
}

const std::string& providerMetadataKey() {
  CONSTRUCT_ON_FIRST_USE(std::string, GenAiConvention::ProviderName);
}

absl::string_view providerName(const StreamInfo::StreamInfo& stream_info,
                               absl::string_view family) {
  const OptRef<const Upstream::ClusterInfo> cluster = stream_info.upstreamClusterInfo();
  if (cluster.has_value()) {
    const std::string& named =
        Config::Metadata::metadataValue(&cluster->metadata(), providerMetadataNamespace(),
                                        providerMetadataKey())
            .string_value();
    if (!named.empty()) {
      return named;
    }
  }
  return family;
}

absl::string_view requestModel(const StreamInfo::StreamInfo& stream_info) {
  const auto* model = stream_info.filterState().getDataReadOnly<Router::StringAccessor>(
      FilterStateKeys::ModelRequest);
  return model != nullptr ? model->asString() : absl::string_view();
}

// Model and host names are reported verbatim unless they cannot be one.
absl::string_view boundedValue(absl::string_view value) {
  if (value.size() > MaxValueLength ||
      absl::c_any_of(value, [](char c) { return absl::ascii_iscntrl(c); })) {
    return GenAiConvention::Other;
  }
  return value;
}

} // namespace

bool CardinalityLimiter::admit(Stats::StatName metric, const Stats::StatNameTagVector& tags) {
  uint64_t set = 0;
  for (const auto& [name, value] : tags) {
    set = absl::HashOf(set, name, value);
  }
  absl::MutexLock lock(&mutex_);
  absl::flat_hash_set<uint64_t>& sets = sets_[metric];
  if (sets.contains(set)) {
    return true;
  }
  if (sets.size() >= limit_) {
    return false;
  }
  sets.insert(set);
  return true;
}

GenAiMetrics::GenAiMetrics(Stats::ScopeSharedPtr scope, AiProtocolManagerStats& stats,
                           uint32_t cardinality_limit)
    : scope_(std::move(scope)), stats_(stats), limiter_(cardinality_limit),
      pool_(scope_->symbolTable()),
      usage_input_tokens_(pool_.add(GenAiConvention::UsageInputTokens)),
      usage_output_tokens_(pool_.add(GenAiConvention::UsageOutputTokens)),
      usage_cache_read_input_tokens_(pool_.add(GenAiConvention::UsageCacheReadInputTokens)),
      usage_cache_write_input_tokens_(pool_.add(GenAiConvention::UsageCacheWriteInputTokens)),
      usage_reasoning_output_tokens_(pool_.add(GenAiConvention::UsageReasoningOutputTokens)),
      operation_input_tokens_(pool_.add(GenAiConvention::OperationInputTokens)),
      operation_output_tokens_(pool_.add(GenAiConvention::OperationOutputTokens)),
      operation_name_(pool_.add(GenAiConvention::OperationName)),
      provider_name_(pool_.add(GenAiConvention::ProviderName)),
      request_model_(pool_.add(GenAiConvention::RequestModel)),
      response_model_(pool_.add(GenAiConvention::ResponseModel)),
      server_address_(pool_.add(GenAiConvention::ServerAddress)),
      server_port_(pool_.add(GenAiConvention::ServerPort)),
      token_modality_(pool_.add(GenAiConvention::TokenModality)),
      chat_(pool_.add(GenAiConvention::Chat)),
      generate_content_(pool_.add(GenAiConvention::GenerateContent)),
      unknown_(pool_.add(GenAiConvention::Unknown)),
      overflow_tags_(
          {{pool_.add(GenAiConvention::MetricOverflow), pool_.add(GenAiConvention::True)}}) {}

void GenAiMetrics::recordUsage(const StreamInfo::StreamInfo& stream_info,
                               const TokenUsage& usage) const {
  const std::optional<ProtocolNames> names = protocolNames(usage.llm_protocol);
  if (!names.has_value()) {
    return;
  }
  Stats::StatNameDynamicPool pool(scope_->symbolTable());
  const Stats::StatNameTagVector tags = baseTags(stream_info, usage, *names, pool);
  Stats::StatNameTagVector usage_tags = tags;
  usage_tags.emplace_back(token_modality_, unknown_);

  if (usage.input_tokens.has_value()) {
    counter(usage_input_tokens_, usage_tags).add(*usage.input_tokens);
    histogram(operation_input_tokens_, tags).recordValue(*usage.input_tokens);
  }
  if (usage.output_tokens.has_value()) {
    counter(usage_output_tokens_, usage_tags).add(*usage.output_tokens);
    histogram(operation_output_tokens_, tags).recordValue(*usage.output_tokens);
  }
  // Providers report zero for these on most requests; skipping zeros avoids idle series.
  addIfPositive(usage_cache_read_input_tokens_, usage_tags, usage.cached_input_tokens);
  addIfPositive(usage_cache_write_input_tokens_, usage_tags, usage.cache_creation_input_tokens);
  addIfPositive(usage_reasoning_output_tokens_, usage_tags, usage.reasoning_tokens);
}

std::optional<GenAiMetrics::ProtocolNames> GenAiMetrics::protocolNames(LLMProtocol protocol) const {
  switch (protocol) {
  case LLMProtocol::OpenAiChatCompletions:
  case LLMProtocol::OpenAiResponses:
    return ProtocolNames{chat_, GenAiConvention::OpenAi};
  case LLMProtocol::AnthropicMessages:
    return ProtocolNames{chat_, GenAiConvention::Anthropic};
  case LLMProtocol::GeminiGenerateContent:
    return ProtocolNames{generate_content_, GenAiConvention::GcpGenAi};
  case LLMProtocol::Unspecified:
    break;
  }
  return std::nullopt;
}

// Values that are not fixed by the spec are always encoded dynamically: a symbolic and a dynamic
// encoding of the same string would name two different stats.
Stats::StatNameTagVector GenAiMetrics::baseTags(const StreamInfo::StreamInfo& stream_info,
                                                const TokenUsage& usage, const ProtocolNames& names,
                                                Stats::StatNameDynamicPool& pool) const {
  Stats::StatNameTagVector tags;
  tags.emplace_back(operation_name_, names.operation);
  tags.emplace_back(provider_name_, pool.add(providerName(stream_info, names.provider)));
  if (const absl::string_view model = requestModel(stream_info); !model.empty()) {
    tags.emplace_back(request_model_, pool.add(boundedValue(model)));
  }
  if (!usage.model.empty()) {
    tags.emplace_back(response_model_, pool.add(boundedValue(usage.model)));
  }
  const OptRef<const StreamInfo::UpstreamInfo> upstream = stream_info.upstreamInfo();
  const Upstream::HostDescriptionConstSharedPtr host =
      upstream.has_value() ? upstream->upstreamHost() : nullptr;
  if (host != nullptr && !host->hostname().empty()) {
    tags.emplace_back(server_address_, pool.add(boundedValue(host->hostname())));
    if (host->address() != nullptr && host->address()->ip() != nullptr) {
      tags.emplace_back(server_port_, pool.add(absl::StrCat(host->address()->ip()->port())));
    }
  }
  return tags;
}

Stats::Counter& GenAiMetrics::counter(Stats::StatName metric,
                                      const Stats::StatNameTagVector& tags) const {
  if (limiter_.admit(metric, tags)) {
    return scope_->counterFromTaggedName(metric, Stats::StatNameTagSpan(tags), Stats::StatName());
  }
  stats_.gen_ai_metrics_overflow_.inc();
  return scope_->counterFromTaggedName(metric, Stats::StatNameTagSpan(overflow_tags_),
                                       Stats::StatName());
}

Stats::Histogram& GenAiMetrics::histogram(Stats::StatName metric,
                                          const Stats::StatNameTagVector& tags) const {
  if (limiter_.admit(metric, tags)) {
    return scope_->histogramFromTaggedName(metric, Stats::StatNameTagSpan(tags), Stats::StatName(),
                                           Stats::Histogram::Unit::Unspecified);
  }
  stats_.gen_ai_metrics_overflow_.inc();
  return scope_->histogramFromTaggedName(metric, Stats::StatNameTagSpan(overflow_tags_),
                                         Stats::StatName(), Stats::Histogram::Unit::Unspecified);
}

void GenAiMetrics::addIfPositive(Stats::StatName metric, const Stats::StatNameTagVector& tags,
                                 const std::optional<uint64_t>& value) const {
  if (value.has_value() && *value > 0) {
    counter(metric, tags).add(*value);
  }
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
