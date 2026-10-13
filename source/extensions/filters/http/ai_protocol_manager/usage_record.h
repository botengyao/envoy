#pragma once

#include "envoy/data/ai/v3/token_usage.pb.h"

#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"
#include "source/extensions/filters/http/ai_protocol_manager/token_usage.h"

#include "absl/status/statusor.h"
#include "nlohmann/json_fwd.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// The token usage observed over one response: what its documents report, merged in the order they
// arrive, and whether any usage-bearing input was lost on the way.
class UsageAccumulator {
public:
  // Reads `document` in `adapter`'s dialect and merges the usage it carries. A known usage field
  // that cannot be used, or an in-band stream error, marks the accumulation degraded.
  void add(const LLMProtocolAdapter& adapter, const nlohmann::json& document);

  // Records that usage-bearing input was lost.
  void markDegraded() { degraded_ = true; }

  // Whether there is anything to report: a count, or a loss.
  bool observed() const { return usage_.hasAny() || degraded_; }

  // The record of the usage so far. It canonicalizes a copy, so documents may still be added.
  envoy::data::ai::v3::TokenUsage record() const;

private:
  TokenUsage usage_;
  bool degraded_{false};
};

// The JSON form of `record` under ReservedMember::TokenUsageRecord: its fields by their proto
// names, with the counts as JSON integers.
nlohmann::json usageRecordToJson(const envoy::data::ai::v3::TokenUsage& record);

// Reads back what usageRecordToJson() wrote.
absl::StatusOr<envoy::data::ai::v3::TokenUsage> usageRecordFromJson(const nlohmann::json& json);

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
