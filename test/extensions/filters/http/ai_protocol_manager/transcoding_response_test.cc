#include <string>
#include <utility>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/transcoding/anthropic_messages.h"
#include "source/extensions/filters/http/ai_protocol_manager/transcoding_engine.h"

#include "test/test_common/status_utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

using nlohmann::json;
using StatusHelpers::HasStatus;
using StatusHelpers::IsOk;
using testing::HasSubstr;

ResponseContext context() {
  ResponseContext c;
  c.model = "requested-model";
  c.created = 1700000000;
  return c;
}

class TranscodingResponseTest : public testing::Test {
public:
  TranscodingResponseTest() : engine_(TranscodingEngine::createDefault().value()) {}

  const TranscodingEngine engine_;
};

TEST_F(TranscodingResponseTest, SupportTable) {
  const std::vector<LLMProtocol> supported = {LLMProtocol::OpenAiChatCompletions,
                                              LLMProtocol::AnthropicMessages,
                                              LLMProtocol::GeminiGenerateContent};
  for (LLMProtocol from : supported) {
    for (LLMProtocol to : supported) {
      EXPECT_TRUE(engine_.canTranscodeResponse(from, to));
    }
    EXPECT_FALSE(engine_.canTranscodeResponse(from, LLMProtocol::OpenAiResponses));
    EXPECT_FALSE(engine_.canTranscodeResponse(LLMProtocol::OpenAiResponses, from));
  }
  EXPECT_TRUE(
      engine_.canTranscodeResponse(LLMProtocol::OpenAiResponses, LLMProtocol::OpenAiResponses));
}

TEST_F(TranscodingResponseTest, SameProtocolNeedsNoTranscoder) {
  auto transcoder = engine_.createResponseStreamTranscoder(
      LLMProtocol::AnthropicMessages, LLMProtocol::AnthropicMessages, context());
  ASSERT_TRUE(transcoder.ok());
  EXPECT_EQ(*transcoder, nullptr);
  auto body =
      engine_.transcodeUnaryResponse(LLMProtocol::GeminiGenerateContent,
                                     LLMProtocol::GeminiGenerateContent, json{{"a", 1}}, context());
  ASSERT_TRUE(body.ok());
  EXPECT_EQ(*body, (json{{"a", 1}}));
}

TEST_F(TranscodingResponseTest, UnsupportedPairIsAnError) {
  EXPECT_FALSE(engine_
                   .createResponseStreamTranscoder(LLMProtocol::OpenAiResponses,
                                                   LLMProtocol::OpenAiChatCompletions, context())
                   .ok());
  EXPECT_FALSE(engine_
                   .transcodeUnaryResponse(LLMProtocol::AnthropicMessages,
                                           LLMProtocol::OpenAiResponses, json::object(), context())
                   .ok());
}

TEST_F(TranscodingResponseTest, DirectTranscodersExist) {
  for (auto [from, to] : std::vector<std::pair<LLMProtocol, LLMProtocol>>{
           {LLMProtocol::AnthropicMessages, LLMProtocol::OpenAiChatCompletions},
           {LLMProtocol::GeminiGenerateContent, LLMProtocol::OpenAiChatCompletions},
           {LLMProtocol::OpenAiChatCompletions, LLMProtocol::AnthropicMessages},
           {LLMProtocol::OpenAiChatCompletions, LLMProtocol::GeminiGenerateContent}}) {
    auto transcoder = engine_.createResponseStreamTranscoder(from, to, context());
    ASSERT_TRUE(transcoder.ok());
    EXPECT_NE(*transcoder, nullptr);
  }
}

TEST_F(TranscodingResponseTest, ChainsGeminiToAnthropicUnary) {
  auto body = engine_.transcodeUnaryResponse(
      LLMProtocol::GeminiGenerateContent, LLMProtocol::AnthropicMessages,
      json::parse(
          R"({"candidates":[{"content":{"role":"model","parts":[{"text":"Red and blue."}]},)"
          R"("finishReason":"MAX_TOKENS"}],"usageMetadata":{"promptTokenCount":7,)"
          R"("candidatesTokenCount":4,"totalTokenCount":11},)"
          R"("modelVersion":"gemini-2.5-flash","responseId":"r1"})"),
      context());
  ASSERT_TRUE(body.ok()) << body.status();
  EXPECT_EQ((*body)["type"], "message");
  EXPECT_EQ((*body)["content"][0]["text"], "Red and blue.");
  EXPECT_EQ((*body)["stop_reason"], "max_tokens");
  EXPECT_EQ((*body)["usage"]["input_tokens"], 7);
  EXPECT_EQ((*body)["usage"]["output_tokens"], 4);
}

TEST_F(TranscodingResponseTest, ChainsAnthropicToGeminiUnary) {
  auto body = engine_.transcodeUnaryResponse(
      LLMProtocol::AnthropicMessages, LLMProtocol::GeminiGenerateContent,
      json::parse(R"({"id":"msg_1","type":"message","role":"assistant","model":"claude",)"
                  R"("content":[{"type":"text","text":"Hi."}],"stop_reason":"end_turn",)"
                  R"("usage":{"input_tokens":5,"output_tokens":2}})"),
      context());
  ASSERT_TRUE(body.ok()) << body.status();
  EXPECT_EQ((*body)["candidates"][0]["content"]["parts"][0]["text"], "Hi.");
  EXPECT_EQ((*body)["candidates"][0]["finishReason"], "STOP");
  EXPECT_EQ((*body)["usageMetadata"]["totalTokenCount"], 7);
}

TEST_F(TranscodingResponseTest, ChainsAGeminiStreamIntoAnthropicEvents) {
  auto transcoder = engine_.createResponseStreamTranscoder(
      LLMProtocol::GeminiGenerateContent, LLMProtocol::AnthropicMessages, context());
  ASSERT_TRUE(transcoder.ok());
  ASSERT_NE(*transcoder, nullptr);
  std::vector<SseFrame> out;
  ASSERT_TRUE((*transcoder)
                  ->onFrame(SseFrame::ofJson(
                                json::parse(R"({"candidates":[{"content":{"role":"model","parts":[)"
                                            R"({"text":"Hel"}]}}],"responseId":"r1"})")),
                            out)
                  .ok());
  ASSERT_TRUE((*transcoder)
                  ->onFrame(SseFrame::ofJson(
                                json::parse(R"({"candidates":[{"content":{"role":"model","parts":[)"
                                            R"({"text":"lo"}]},"finishReason":"STOP"}],)"
                                            R"("usageMetadata":{"promptTokenCount":3,)"
                                            R"("candidatesTokenCount":2,"totalTokenCount":5}})")),
                            out)
                  .ok());
  ASSERT_TRUE((*transcoder)->onEnd(out).ok());

  std::vector<std::string> types;
  std::string text;
  for (const SseFrame& frame : out) {
    ASSERT_TRUE(frame.json.has_value());
    const std::string type = (*frame.json)["type"];
    EXPECT_EQ(frame.event, type);
    types.push_back(type);
    if (type == "content_block_delta") {
      text += (*frame.json)["delta"]["text"].get<std::string>();
    }
    if (type == "message_delta") {
      EXPECT_EQ((*frame.json)["delta"]["stop_reason"], "end_turn");
      EXPECT_EQ((*frame.json)["usage"]["output_tokens"], 2);
    }
  }
  EXPECT_EQ(text, "Hello");
  ASSERT_FALSE(types.empty());
  EXPECT_EQ(types.front(), "message_start");
  EXPECT_EQ(types.back(), "message_stop");
}

TEST_F(TranscodingResponseTest, UnsupportedPairNamesBothProtocols) {
  EXPECT_THAT(engine_
                  .createResponseStreamTranscoder(LLMProtocol::OpenAiResponses,
                                                  LLMProtocol::OpenAiChatCompletions, context())
                  .status(),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("no response conversion from OPENAI_RESPONSES to "
                                  "OPENAI_CHAT_COMPLETIONS")));
}

// The support table follows the registered packs: a protocol is served only through its pack's
// codec, while the IR needs none.
TEST(TranscodingResponseSupportTest, FollowsRegisteredCodecs) {
  TranscodingEngine engine;
  EXPECT_FALSE(
      engine.canTranscodeResponse(LLMProtocol::AnthropicMessages, TranscodingEngine::kIrProtocol));

  DialectTranscodePack without_codec;
  without_codec.protocol = LLMProtocol::GeminiGenerateContent;
  ASSERT_THAT(engine.registerPack(std::move(without_codec)), IsOk());
  EXPECT_FALSE(engine.canTranscodeResponse(TranscodingEngine::kIrProtocol,
                                           LLMProtocol::GeminiGenerateContent));
  EXPECT_FALSE(engine
                   .transcodeUnaryResponse(TranscodingEngine::kIrProtocol,
                                           LLMProtocol::GeminiGenerateContent, json::object(),
                                           context())
                   .ok());

  DialectTranscodePack with_codec;
  with_codec.protocol = LLMProtocol::AnthropicMessages;
  with_codec.response_codec = &anthropicMessagesResponseCodec();
  ASSERT_THAT(engine.registerPack(std::move(with_codec)), IsOk());
  EXPECT_TRUE(
      engine.canTranscodeResponse(LLMProtocol::AnthropicMessages, TranscodingEngine::kIrProtocol));
  EXPECT_FALSE(engine.canTranscodeResponse(LLMProtocol::AnthropicMessages,
                                           LLMProtocol::GeminiGenerateContent));
  absl::StatusOr<ResponseStreamTranscoderPtr> transcoder = engine.createResponseStreamTranscoder(
      TranscodingEngine::kIrProtocol, LLMProtocol::AnthropicMessages, context());
  ASSERT_THAT(transcoder.status(), IsOk());
  EXPECT_NE(*transcoder, nullptr);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
