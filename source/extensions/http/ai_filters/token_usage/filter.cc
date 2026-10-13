#include "source/extensions/http/ai_filters/token_usage/filter.h"

#include <string>
#include <utility>

#include "source/common/common/assert.h"
#include "source/common/coroutine/status_macros.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"
#include "source/extensions/filters/http/ai_protocol_manager/reserved_member.h"
#include "source/extensions/filters/http/ai_protocol_manager/transcoding_engine.h"

#include "absl/strings/str_cat.h"
#include "absl/types/variant.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace TokenUsage {

using HttpFilters::AiProtocolManager::AdapterRegistry;
using HttpFilters::AiProtocolManager::AiResponseStreamPropagator;
using HttpFilters::AiProtocolManager::AiResponseStreamReceiver;
using HttpFilters::AiProtocolManager::FieldPath;
using HttpFilters::AiProtocolManager::FlattenJsonField;
using HttpFilters::AiProtocolManager::LLMProtocol;
using HttpFilters::AiProtocolManager::SseEventPtr;
using HttpFilters::AiProtocolManager::SseStreamPropagator;
using HttpFilters::AiProtocolManager::SseStreamReceiver;
using HttpFilters::AiProtocolManager::TranscodingEngine;
using HttpFilters::AiProtocolManager::unflattenFields;
using HttpFilters::AiProtocolManager::usageRecordFromJson;
using UsageRecord = envoy::data::ai::v3::TokenUsage;
namespace ReservedMember = HttpFilters::AiProtocolManager::ReservedMember;

namespace {

constexpr absl::string_view MetadataNamespace = "envoy.ai.token_usage";
// Where an IR document reports its usage.
constexpr absl::string_view UsageMember = "usage";

} // namespace

TokenUsageFilterConfig::TokenUsageFilterConfig(Stats::Scope& scope)
    : stats_(TokenUsageFilterStats{ALL_TOKEN_USAGE_FILTER_STATS(
          POOL_COUNTER_PREFIX(scope, "ai_protocol_manager.token_usage."))}) {}

TokenUsageFilter::TokenUsageFilter(TokenUsageFilterConfigSharedPtr config,
                                   StreamInfo::StreamInfo& stream_info)
    : config_(std::move(config)), stream_info_(stream_info) {}

Coroutine::Task<absl::Status> TokenUsageFilter::encodeSSE(SseStreamReceiver receive_event,
                                                          SseStreamPropagator propagate_event) {
  while (true) {
    ASSIGN_OR_CO_RETURN(std::optional<SseEventPtr> event, co_await receive_event());
    if (!event.has_value()) {
      break;
    }
    if ((*event)->is_json()) {
      observe((*event)->json().json());
    }
    CO_RETURN_IF_ERROR(co_await propagate_event(std::move(*event)));
  }
  publish();
  co_return absl::OkStatus();
}

Coroutine::Task<absl::Status>
TokenUsageFilter::encodeUnary(AiResponseStreamReceiver receive_batch,
                              AiResponseStreamPropagator propagate_batch) {
  while (true) {
    ASSIGN_OR_CO_RETURN(std::vector<FlattenJsonField> batch, co_await receive_batch());
    if (batch.empty()) {
      break;
    }
    retain(batch);
    CO_RETURN_IF_ERROR(co_await propagate_batch(std::move(batch)));
  }
  if (array_body_) {
    api_mismatch_ = true;
    usage_.markDegraded();
  } else if (!retained_.empty()) {
    observe(unflattenFields(retained_));
  }
  publish();
  co_return absl::OkStatus();
}

void TokenUsageFilter::retain(const std::vector<FlattenJsonField>& batch) {
  for (const FlattenJsonField& field : batch) {
    const FieldPath path = field.field_path();
    if (path.empty()) {
      continue;
    }
    if (!absl::holds_alternative<std::string>(path.front())) {
      array_body_ = true;
      continue;
    }
    const std::string& member = absl::get<std::string>(path.front());
    if (path.size() == 1 || member == UsageMember || member == ReservedMember::Name) {
      retained_.push_back(field);
    }
  }
}

void TokenUsageFilter::observe(const nlohmann::json& document) {
  if (!document.is_object()) {
    return;
  }
  if (const auto reserved = document.find(ReservedMember::Name);
      reserved != document.end() && reserved->is_object()) {
    if (const auto record = reserved->find(ReservedMember::TokenUsageRecord);
        record != reserved->end()) {
      record_ = *record;
      return;
    }
  }
  if (record_.has_value()) {
    return;
  }
  if (const LLMProtocol api = AdapterRegistry::detect(document);
      api != LLMProtocol::Unspecified && api != TranscodingEngine::kIrProtocol) {
    api_mismatch_ = true;
    usage_.markDegraded();
    return;
  }
  usage_.add(AdapterRegistry::get(TranscodingEngine::kIrProtocol), document);
}

std::optional<UsageRecord> TokenUsageFilter::carriedRecord() const {
  if (!record_.has_value()) {
    return std::nullopt;
  }
  absl::StatusOr<UsageRecord> record = usageRecordFromJson(*record_);
  if (!record.ok()) {
    // Only Envoy writes one: the manager removes a record an upstream sends.
    IS_ENVOY_BUG(
        absl::StrCat("token_usage: cannot read the carried record: ", record.status().message()));
    return std::nullopt;
  }
  return *std::move(record);
}

void TokenUsageFilter::publish() {
  std::optional<UsageRecord> record = carriedRecord();
  if (!record.has_value()) {
    if (api_mismatch_) {
      config_->stats().api_mismatch_.inc();
    }
    if (!usage_.observed()) {
      // Legitimately absent, e.g. an OpenAI stream without `stream_options.include_usage`.
      config_->stats().missing_.inc();
      return;
    }
    record = usage_.record();
  }

  // An installation in both the downstream and the upstream filter chain would publish twice; the
  // upstream one, which runs first, owns the namespace.
  const std::string metadata_namespace(MetadataNamespace);
  if (stream_info_.dynamicMetadata().typed_filter_metadata().contains(metadata_namespace)) {
    ENVOY_LOG(debug, "token_usage: namespace {} already published; skipping", metadata_namespace);
    config_->stats().duplicate_.inc();
    return;
  }
  Protobuf::Any typed_any;
  MessageUtil::packFrom(typed_any, *record);
  stream_info_.setDynamicTypedMetadata(metadata_namespace, typed_any);
  countPublished(*record);
  ENVOY_LOG(trace, "token_usage: published to namespace {}", metadata_namespace);
}

void TokenUsageFilter::countPublished(const UsageRecord& record) {
  if (record.extraction_status() == UsageRecord::FAILED) {
    config_->stats().failed_.inc();
    return;
  }
  if (record.extraction_status() == UsageRecord::PARTIAL) {
    config_->stats().partial_.inc();
  }
  if (record.has_provider_total_tokens() && record.has_total_tokens() &&
      record.provider_total_tokens().value() != record.total_tokens().value()) {
    config_->stats().total_mismatch_.inc();
  }
  config_->stats().found_.inc();
}

} // namespace TokenUsage
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
