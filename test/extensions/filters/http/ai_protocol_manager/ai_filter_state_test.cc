#include <memory>
#include <string>

#include "envoy/registry/registry.h"
#include "envoy/stream_info/filter_state.h"
#include "envoy/type/ai/v3/downstream_api.pb.h"
#include "envoy/type/ai/v3/upstream_target.pb.h"

#include "source/extensions/filters/http/ai_protocol_manager/ai_filter_state.h"

#include "test/test_common/utility.h"

#include "absl/types/variant.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

const StreamInfo::FilterState::ObjectFactory& objectFactory(absl::string_view key) {
  const auto* factory =
      Registry::FactoryRegistry<StreamInfo::FilterState::ObjectFactory>::getFactory(key);
  EXPECT_NE(factory, nullptr);
  return *factory;
}

std::unique_ptr<StreamInfo::FilterState::Object> downstreamApi(absl::string_view data) {
  return objectFactory(DownstreamApiState::kFilterStateKey).createFromBytes(data);
}

const DownstreamApiState*
asDownstreamApi(const std::unique_ptr<StreamInfo::FilterState::Object>& o) {
  return dynamic_cast<const DownstreamApiState*>(o.get());
}

std::unique_ptr<StreamInfo::FilterState::Object> upstreamTarget(absl::string_view json) {
  return objectFactory(UpstreamTargetState::kFilterStateKey).createFromBytes(json);
}

const UpstreamTargetState*
asUpstreamTarget(const std::unique_ptr<StreamInfo::FilterState::Object>& o) {
  return dynamic_cast<const UpstreamTargetState*>(o.get());
}

absl::string_view stringField(const StreamInfo::FilterState::Object& object,
                              absl::string_view name) {
  const StreamInfo::FilterState::Object::FieldType field = object.getField(name);
  EXPECT_TRUE(absl::holds_alternative<absl::string_view>(field)) << name;
  return absl::holds_alternative<absl::string_view>(field) ? absl::get<absl::string_view>(field)
                                                           : absl::string_view();
}

TEST(DownstreamApiStateTest, FactoryBuildsFromShorthand) {
  const auto object = downstreamApi("OPENAI_RESPONSES");
  const DownstreamApiState* state = asDownstreamApi(object);
  ASSERT_NE(state, nullptr);
  EXPECT_EQ(state->protocol(), LLMProtocol::OpenAiResponses);
  EXPECT_FALSE(state->api()->has_endpoint());
  EXPECT_EQ(state->serializeAsString(), R"({"llm_protocol":"OPENAI_RESPONSES"})");
}

TEST(DownstreamApiStateTest, FactoryBuildsFromJson) {
  const std::string json =
      R"({"llm_protocol":"GEMINI_GENERATE_CONTENT","endpoint":{"preset":"any_preset"}})";
  const auto object = downstreamApi(json);
  const DownstreamApiState* state = asDownstreamApi(object);
  ASSERT_NE(state, nullptr);
  EXPECT_EQ(state->protocol(), LLMProtocol::GeminiGenerateContent);
  EXPECT_EQ(state->serializeAsString(), json);
  EXPECT_TRUE(TestUtility::protoEqual(*state->serializeAsProto(), *state->api()));
}

TEST(DownstreamApiStateTest, FactoryRejectsUnparsableValues) {
  EXPECT_EQ(downstreamApi("openai_chat_completions"), nullptr);
  EXPECT_EQ(downstreamApi(""), nullptr);
  EXPECT_EQ(downstreamApi(R"({"llm_protocol":99})"), nullptr);
  EXPECT_EQ(downstreamApi(R"({"llm_protocol":"ANTHROPIC_MESSAGES","authority":"x"})"), nullptr);
}

TEST(DownstreamApiStateTest, Fields) {
  const auto object = downstreamApi("ANTHROPIC_MESSAGES");
  ASSERT_NE(object, nullptr);
  EXPECT_TRUE(object->hasFieldSupport());
  EXPECT_EQ(stringField(*object, "llm_protocol"), "ANTHROPIC_MESSAGES");
  EXPECT_TRUE(absl::holds_alternative<absl::monostate>(object->getField("preset")));
}

TEST(UpstreamTargetStateTest, FieldsAndSerialization) {
  const std::string json =
      R"({"llm_protocol":"ANTHROPIC_MESSAGES","authority":"bedrock-runtime.us-east-1.amazonaws.com",)"
      R"("endpoint":{"preset":"aws_bedrock","variables":{"region":"us-east-1"}},)"
      R"("model":"anthropic.claude-sonnet-4-5","credential":"bedrock-prod"})";
  const auto object = upstreamTarget(json);
  const UpstreamTargetState* state = asUpstreamTarget(object);
  ASSERT_NE(state, nullptr);
  EXPECT_EQ(state->protocol(), LLMProtocol::AnthropicMessages);

  EXPECT_TRUE(state->hasFieldSupport());
  EXPECT_EQ(stringField(*state, "llm_protocol"), "ANTHROPIC_MESSAGES");
  EXPECT_EQ(stringField(*state, "authority"), "bedrock-runtime.us-east-1.amazonaws.com");
  EXPECT_EQ(stringField(*state, "model"), "anthropic.claude-sonnet-4-5");
  EXPECT_EQ(stringField(*state, "preset"), "aws_bedrock");
  EXPECT_TRUE(absl::holds_alternative<absl::monostate>(state->getField("credential")));

  EXPECT_EQ(state->serializeAsString(), json);
  EXPECT_TRUE(TestUtility::protoEqual(*state->serializeAsProto(), *state->target()));
}

TEST(UpstreamTargetStateTest, FactoryRejectsUnparsableValues) {
  EXPECT_EQ(upstreamTarget("{"), nullptr);
  EXPECT_EQ(upstreamTarget("ANTHROPIC_MESSAGES"), nullptr);
  EXPECT_EQ(upstreamTarget(R"({"llm_protocol":99})"), nullptr);
  EXPECT_EQ(upstreamTarget(R"({"llm_protocol":"ANTHROPIC_MESSAGES","region":"x"})"), nullptr);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
