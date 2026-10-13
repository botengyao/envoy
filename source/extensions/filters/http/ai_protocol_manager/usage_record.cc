#include "source/extensions/filters/http/ai_protocol_manager/usage_record.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "envoy/type/ai/v3/llm_protocol.pb.h"

#include "source/extensions/filters/http/ai_protocol_manager/json_readers.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_conversion.h"

#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

using UsageRecord = envoy::data::ai::v3::TokenUsage;

// The field names of envoy.data.ai.v3.TokenUsage.
namespace RecordKeys {
constexpr absl::string_view LlmProtocol = "llm_protocol";
constexpr absl::string_view Model = "model";
constexpr absl::string_view InputTokens = "input_tokens";
constexpr absl::string_view OutputTokens = "output_tokens";
constexpr absl::string_view TotalTokens = "total_tokens";
constexpr absl::string_view InputTokenDetails = "input_token_details";
constexpr absl::string_view CachedTokens = "cached_tokens";
constexpr absl::string_view CacheCreationTokens = "cache_creation_tokens";
constexpr absl::string_view ToolUseTokens = "tool_use_tokens";
constexpr absl::string_view OutputTokenDetails = "output_token_details";
constexpr absl::string_view ReasoningTokens = "reasoning_tokens";
constexpr absl::string_view ProviderTotalTokens = "provider_total_tokens";
constexpr absl::string_view ExtractionStatus = "extraction_status";
} // namespace RecordKeys

// Converts finalized `usage` into the record. A record with no counts at all is status-only and
// reports FAILED.
UsageRecord typedUsage(const TokenUsage& usage, bool degraded) {
  UsageRecord typed;
  typed.set_llm_protocol(protocolToProto(usage.llm_protocol));
  if (!usage.model.empty()) {
    typed.set_model(usage.model);
  }
  const auto set = [](const std::optional<uint64_t>& value, auto setter) {
    if (value.has_value()) {
      setter(value.value());
    }
  };
  set(usage.input_tokens, [&typed](uint64_t v) { typed.mutable_input_tokens()->set_value(v); });
  set(usage.output_tokens, [&typed](uint64_t v) { typed.mutable_output_tokens()->set_value(v); });
  set(usage.total_tokens, [&typed](uint64_t v) { typed.mutable_total_tokens()->set_value(v); });
  set(usage.cached_input_tokens, [&typed](uint64_t v) {
    typed.mutable_input_token_details()->mutable_cached_tokens()->set_value(v);
  });
  set(usage.cache_creation_input_tokens, [&typed](uint64_t v) {
    typed.mutable_input_token_details()->mutable_cache_creation_tokens()->set_value(v);
  });
  set(usage.tool_use_input_tokens, [&typed](uint64_t v) {
    typed.mutable_input_token_details()->mutable_tool_use_tokens()->set_value(v);
  });
  set(usage.reasoning_tokens, [&typed](uint64_t v) {
    typed.mutable_output_token_details()->mutable_reasoning_tokens()->set_value(v);
  });
  set(usage.provider_total_tokens,
      [&typed](uint64_t v) { typed.mutable_provider_total_tokens()->set_value(v); });
  if (!usage.hasAny()) {
    typed.set_extraction_status(UsageRecord::FAILED);
  } else {
    typed.set_extraction_status(degraded ? UsageRecord::PARTIAL : UsageRecord::COMPLETE);
  }
  return typed;
}

void putCount(nlohmann::json& json, absl::string_view key, bool has, uint64_t value) {
  if (has) {
    json[std::string(key)] = value;
  }
}

// Reads the count at `key`, if there is one, into the wrapper `mutable_field()` returns.
template <class MutableField>
void readCountInto(const nlohmann::json& json, absl::string_view key, bool& malformed,
                   MutableField mutable_field) {
  if (const std::optional<uint64_t> count = readCount(json, key, malformed); count.has_value()) {
    mutable_field()->set_value(*count);
  }
}

} // namespace

void UsageAccumulator::add(const LLMProtocolAdapter& adapter, const nlohmann::json& document) {
  // No dialect reports usage in a scalar, an array or null.
  if (!document.is_object()) {
    return;
  }
  const ExtractionResult result = adapter.extractUsage(document);
  usage_.merge(result.usage);
  if (result.malformed || result.stream_error) {
    degraded_ = true;
  }
}

envoy::data::ai::v3::TokenUsage UsageAccumulator::record() const {
  TokenUsage usage = usage_;
  finalizeUsage(usage);
  return typedUsage(usage, degraded_ || usage.canonicalizationOverflow());
}

nlohmann::json usageRecordToJson(const envoy::data::ai::v3::TokenUsage& record) {
  nlohmann::json json = nlohmann::json::object();
  json[std::string(RecordKeys::LlmProtocol)] =
      envoy::type::ai::v3::LLMProtocol_Name(record.llm_protocol());
  if (!record.model().empty()) {
    json[std::string(RecordKeys::Model)] = record.model();
  }
  putCount(json, RecordKeys::InputTokens, record.has_input_tokens(), record.input_tokens().value());
  putCount(json, RecordKeys::OutputTokens, record.has_output_tokens(),
           record.output_tokens().value());
  putCount(json, RecordKeys::TotalTokens, record.has_total_tokens(), record.total_tokens().value());
  if (record.has_input_token_details()) {
    const envoy::data::ai::v3::InputTokenDetails& details = record.input_token_details();
    nlohmann::json out = nlohmann::json::object();
    putCount(out, RecordKeys::CachedTokens, details.has_cached_tokens(),
             details.cached_tokens().value());
    putCount(out, RecordKeys::CacheCreationTokens, details.has_cache_creation_tokens(),
             details.cache_creation_tokens().value());
    putCount(out, RecordKeys::ToolUseTokens, details.has_tool_use_tokens(),
             details.tool_use_tokens().value());
    json[std::string(RecordKeys::InputTokenDetails)] = std::move(out);
  }
  if (record.has_output_token_details()) {
    const envoy::data::ai::v3::OutputTokenDetails& details = record.output_token_details();
    nlohmann::json out = nlohmann::json::object();
    putCount(out, RecordKeys::ReasoningTokens, details.has_reasoning_tokens(),
             details.reasoning_tokens().value());
    json[std::string(RecordKeys::OutputTokenDetails)] = std::move(out);
  }
  putCount(json, RecordKeys::ProviderTotalTokens, record.has_provider_total_tokens(),
           record.provider_total_tokens().value());
  json[std::string(RecordKeys::ExtractionStatus)] =
      UsageRecord::ExtractionStatus_Name(record.extraction_status());
  return json;
}

absl::StatusOr<envoy::data::ai::v3::TokenUsage> usageRecordFromJson(const nlohmann::json& json) {
  if (!json.is_object()) {
    return absl::InvalidArgumentError("the token usage record is not an object");
  }
  UsageRecord record;
  bool malformed = false;

  if (const std::optional<std::string> name = readString(json, RecordKeys::LlmProtocol, malformed);
      name.has_value()) {
    envoy::type::ai::v3::LLMProtocol protocol;
    if (envoy::type::ai::v3::LLMProtocol_Parse(*name, &protocol)) {
      record.set_llm_protocol(protocol);
    } else {
      malformed = true;
    }
  }
  if (std::optional<std::string> model = readString(json, RecordKeys::Model, malformed);
      model.has_value()) {
    record.set_model(*std::move(model));
  }
  readCountInto(json, RecordKeys::InputTokens, malformed,
                [&record] { return record.mutable_input_tokens(); });
  readCountInto(json, RecordKeys::OutputTokens, malformed,
                [&record] { return record.mutable_output_tokens(); });
  readCountInto(json, RecordKeys::TotalTokens, malformed,
                [&record] { return record.mutable_total_tokens(); });
  if (const nlohmann::json* details = readObject(json, RecordKeys::InputTokenDetails, malformed);
      details != nullptr) {
    envoy::data::ai::v3::InputTokenDetails* out = record.mutable_input_token_details();
    readCountInto(*details, RecordKeys::CachedTokens, malformed,
                  [out] { return out->mutable_cached_tokens(); });
    readCountInto(*details, RecordKeys::CacheCreationTokens, malformed,
                  [out] { return out->mutable_cache_creation_tokens(); });
    readCountInto(*details, RecordKeys::ToolUseTokens, malformed,
                  [out] { return out->mutable_tool_use_tokens(); });
  }
  if (const nlohmann::json* details = readObject(json, RecordKeys::OutputTokenDetails, malformed);
      details != nullptr) {
    envoy::data::ai::v3::OutputTokenDetails* out = record.mutable_output_token_details();
    readCountInto(*details, RecordKeys::ReasoningTokens, malformed,
                  [out] { return out->mutable_reasoning_tokens(); });
  }
  readCountInto(json, RecordKeys::ProviderTotalTokens, malformed,
                [&record] { return record.mutable_provider_total_tokens(); });

  const std::optional<std::string> status =
      readString(json, RecordKeys::ExtractionStatus, malformed);
  UsageRecord::ExtractionStatus extraction_status;
  if (!status.has_value() || !UsageRecord::ExtractionStatus_Parse(*status, &extraction_status)) {
    malformed = true;
  } else {
    record.set_extraction_status(extraction_status);
  }

  if (malformed) {
    return absl::InvalidArgumentError("the token usage record is malformed");
  }
  return record;
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
