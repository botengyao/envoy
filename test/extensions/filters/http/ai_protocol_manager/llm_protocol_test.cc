#include "envoy/registry/registry.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/stream_info/filter_state_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol.h"

#include "absl/types/variant.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

// The object is reachable by key alone, which is what lets an extension that
// cannot link this one set it.
class RequestLlmProtocolFactoryTest : public testing::Test {
protected:
  void SetUp() override {
    factory_ = Registry::FactoryRegistry<StreamInfo::FilterState::ObjectFactory>::getFactory(
        RequestLlmProtocol::kFilterStateKey);
    ASSERT_NE(factory_, nullptr);
  }

  const StreamInfo::FilterState::ObjectFactory* factory_{nullptr};
};

TEST(RequestLlmProtocolTest, SerializesAsEnumValueName) {
  EXPECT_EQ(RequestLlmProtocol(ApiProtocol::GeminiGenerateContent).serializeAsString(),
            "GEMINI_GENERATE_CONTENT");
  EXPECT_EQ(RequestLlmProtocol(ApiProtocol::Unspecified).serializeAsString(),
            "API_PROTOCOL_UNSPECIFIED");
}

TEST(RequestLlmProtocolTest, ExposesApiProtocolField) {
  const RequestLlmProtocol object(ApiProtocol::OpenAiChatCompletions);
  EXPECT_TRUE(object.hasFieldSupport());
  EXPECT_EQ(absl::get<absl::string_view>(object.getField("api_protocol")),
            "OPENAI_CHAT_COMPLETIONS");
  EXPECT_TRUE(absl::holds_alternative<absl::monostate>(object.getField("model")));
}

TEST_F(RequestLlmProtocolFactoryTest, BuildsFromEnumValueName) {
  const auto object = factory_->createFromBytes("OPENAI_RESPONSES");
  ASSERT_NE(object, nullptr);
  const auto* typed = dynamic_cast<const RequestLlmProtocol*>(object.get());
  ASSERT_NE(typed, nullptr);
  EXPECT_EQ(typed->protocol(), ApiProtocol::OpenAiResponses);
}

// An unnamed protocol is a legitimate value: it says the writer looked and did
// not know, which leaves the route's own declaration standing.
TEST_F(RequestLlmProtocolFactoryTest, BuildsUnspecified) {
  const auto object = factory_->createFromBytes("API_PROTOCOL_UNSPECIFIED");
  ASSERT_NE(object, nullptr);
  const auto* typed = dynamic_cast<const RequestLlmProtocol*>(object.get());
  ASSERT_NE(typed, nullptr);
  EXPECT_EQ(typed->protocol(), ApiProtocol::Unspecified);
}

// A name the enum does not define yields nothing, so a typo cannot read as an
// unspecified protocol.
TEST_F(RequestLlmProtocolFactoryTest, RejectsUnknownName) {
  EXPECT_EQ(factory_->createFromBytes("openai_chat_completions"), nullptr);
  EXPECT_EQ(factory_->createFromBytes("NOT_AN_API"), nullptr);
  EXPECT_EQ(factory_->createFromBytes(""), nullptr);
}

TEST(RequestLlmProtocolTest, ReadsBackFromFilterState) {
  StreamInfo::FilterStateImpl filter_state(StreamInfo::FilterState::LifeSpan::FilterChain);
  filter_state.setData(RequestLlmProtocol::kFilterStateKey,
                       std::make_shared<RequestLlmProtocol>(ApiProtocol::AnthropicMessages),
                       StreamInfo::FilterState::LifeSpan::FilterChain);

  const auto* object =
      filter_state.getDataReadOnly<RequestLlmProtocol>(RequestLlmProtocol::kFilterStateKey);
  ASSERT_NE(object, nullptr);
  EXPECT_EQ(object->protocol(), ApiProtocol::AnthropicMessages);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
