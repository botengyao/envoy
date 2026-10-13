#include <string>

#include "envoy/data/ai/v3/token_usage.pb.h"

#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"
#include "source/extensions/filters/http/ai_protocol_manager/usage_record.h"

#include "test/test_common/status_utility.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

using ::Envoy::StatusHelpers::HasStatusCode;
using UsageRecord = envoy::data::ai::v3::TokenUsage;

const LLMProtocolAdapter& anthropic() {
  return AdapterRegistry::get(LLMProtocol::AnthropicMessages);
}

const LLMProtocolAdapter& openAiChat() {
  return AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions);
}

TEST(UsageAccumulatorTest, MergesUsageAcrossDocuments) {
  UsageAccumulator usage;
  EXPECT_FALSE(usage.observed());
  usage.add(anthropic(), nlohmann::json::parse(R"({"type": "message_start", "message": {
    "model": "claude-sonnet-4-5-20250929",
    "usage": {"input_tokens": 10, "cache_read_input_tokens": 1000,
              "cache_creation_input_tokens": 20, "output_tokens": 1}}})"));
  usage.add(anthropic(),
            nlohmann::json::parse(R"({"type": "message_delta", "usage": {"output_tokens": 5}})"));
  ASSERT_TRUE(usage.observed());

  const UsageRecord record = usage.record();
  EXPECT_EQ(record.llm_protocol(), envoy::type::ai::v3::ANTHROPIC_MESSAGES);
  EXPECT_EQ(record.model(), "claude-sonnet-4-5-20250929");
  // Anthropic's input count leaves out both cache buckets; the canonical one holds them.
  EXPECT_EQ(record.input_tokens().value(), 1030);
  EXPECT_EQ(record.output_tokens().value(), 5);
  EXPECT_EQ(record.total_tokens().value(), 1035);
  EXPECT_EQ(record.input_token_details().cached_tokens().value(), 1000);
  EXPECT_EQ(record.input_token_details().cache_creation_tokens().value(), 20);
  EXPECT_EQ(record.extraction_status(), UsageRecord::COMPLETE);
}

TEST(UsageAccumulatorTest, RecordLeavesTheAccumulationOpen) {
  UsageAccumulator usage;
  usage.add(anthropic(),
            nlohmann::json::parse(
                R"({"type": "message_start", "message": {"usage": {"input_tokens": 10}}})"));
  EXPECT_EQ(usage.record().input_tokens().value(), 10);
  EXPECT_FALSE(usage.record().has_output_tokens());

  usage.add(anthropic(),
            nlohmann::json::parse(R"({"type": "message_delta", "usage": {"output_tokens": 5}})"));
  const UsageRecord record = usage.record();
  EXPECT_EQ(record.input_tokens().value(), 10);
  EXPECT_EQ(record.output_tokens().value(), 5);
  EXPECT_EQ(record.total_tokens().value(), 15);
}

TEST(UsageAccumulatorTest, MalformedUsageFieldIsPartial) {
  UsageAccumulator usage;
  usage.add(openAiChat(), nlohmann::json::parse(R"({"object": "chat.completion",
    "usage": {"prompt_tokens": "x", "completion_tokens": 5}})"));
  const UsageRecord record = usage.record();
  EXPECT_FALSE(record.has_input_tokens());
  EXPECT_EQ(record.output_tokens().value(), 5);
  EXPECT_EQ(record.extraction_status(), UsageRecord::PARTIAL);
}

TEST(UsageAccumulatorTest, StreamErrorIsPartial) {
  UsageAccumulator usage;
  usage.add(anthropic(),
            nlohmann::json::parse(
                R"({"type": "message_start", "message": {"usage": {"input_tokens": 10}}})"));
  usage.add(anthropic(),
            nlohmann::json::parse(R"({"type": "error", "error": {"type": "overloaded_error"}})"));
  const UsageRecord record = usage.record();
  EXPECT_EQ(record.input_tokens().value(), 10);
  EXPECT_EQ(record.extraction_status(), UsageRecord::PARTIAL);
}

TEST(UsageAccumulatorTest, LossWithoutCountsIsFailed) {
  UsageAccumulator usage;
  usage.markDegraded();
  ASSERT_TRUE(usage.observed());
  const UsageRecord record = usage.record();
  EXPECT_FALSE(record.has_input_tokens());
  EXPECT_FALSE(record.has_output_tokens());
  EXPECT_EQ(record.extraction_status(), UsageRecord::FAILED);
}

TEST(UsageAccumulatorTest, IgnoresDocumentsThatAreNotObjects) {
  UsageAccumulator usage;
  usage.add(openAiChat(), nlohmann::json::array({nlohmann::json::object()}));
  usage.add(openAiChat(), "usage");
  usage.add(openAiChat(), nullptr);
  EXPECT_FALSE(usage.observed());
}

TEST(UsageRecordJsonTest, RoundTripsEveryField) {
  UsageRecord record;
  record.set_llm_protocol(envoy::type::ai::v3::GEMINI_GENERATE_CONTENT);
  record.set_model("gemini-2.5-pro");
  record.mutable_input_tokens()->set_value(16);
  record.mutable_output_tokens()->set_value(30);
  record.mutable_total_tokens()->set_value(46);
  record.mutable_input_token_details()->mutable_cached_tokens()->set_value(4);
  record.mutable_input_token_details()->mutable_cache_creation_tokens()->set_value(2);
  record.mutable_input_token_details()->mutable_tool_use_tokens()->set_value(5);
  record.mutable_output_token_details()->mutable_reasoning_tokens()->set_value(9);
  record.mutable_provider_total_tokens()->set_value(47);
  record.set_extraction_status(UsageRecord::PARTIAL);

  const nlohmann::json json = usageRecordToJson(record);
  EXPECT_EQ(json, nlohmann::json::parse(R"({
    "llm_protocol": "GEMINI_GENERATE_CONTENT",
    "model": "gemini-2.5-pro",
    "input_tokens": 16,
    "output_tokens": 30,
    "total_tokens": 46,
    "input_token_details": {"cached_tokens": 4, "cache_creation_tokens": 2, "tool_use_tokens": 5},
    "output_token_details": {"reasoning_tokens": 9},
    "provider_total_tokens": 47,
    "extraction_status": "PARTIAL"
  })"));

  const absl::StatusOr<UsageRecord> parsed = usageRecordFromJson(json);
  ASSERT_TRUE(parsed.ok()) << parsed.status();
  EXPECT_TRUE(TestUtility::protoEqual(*parsed, record));
}

TEST(UsageRecordJsonTest, RoundTripsAStatusOnlyRecord) {
  UsageRecord record;
  record.set_llm_protocol(envoy::type::ai::v3::ANTHROPIC_MESSAGES);
  record.set_extraction_status(UsageRecord::FAILED);

  const absl::StatusOr<UsageRecord> parsed = usageRecordFromJson(usageRecordToJson(record));
  ASSERT_TRUE(parsed.ok()) << parsed.status();
  EXPECT_TRUE(TestUtility::protoEqual(*parsed, record));
}

TEST(UsageRecordJsonTest, RejectsWhatItDidNotWrite) {
  for (const char* json : {
           R"([])",
           R"({})",
           R"({"extraction_status": "DONE"})",
           R"({"llm_protocol": "SOAP", "extraction_status": "COMPLETE"})",
           R"({"input_tokens": "7", "extraction_status": "COMPLETE"})",
           R"({"input_token_details": {"cached_tokens": -1}, "extraction_status": "COMPLETE"})",
           R"({"output_token_details": [], "extraction_status": "COMPLETE"})",
       }) {
    SCOPED_TRACE(json);
    EXPECT_THAT(usageRecordFromJson(nlohmann::json::parse(json)),
                HasStatusCode(absl::StatusCode::kInvalidArgument));
  }
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
