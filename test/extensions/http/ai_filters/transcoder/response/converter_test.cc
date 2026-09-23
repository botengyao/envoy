#include <string>
#include <vector>

#include "source/extensions/http/ai_filters/transcoder/response/converter.h"

#include "test/test_common/utility.h"

#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {
namespace {

using nlohmann::json;

ResponseContext context() {
  ResponseContext c;
  c.model = "requested-model";
  c.created = 1700000000;
  return c;
}

TEST(ResponseConverterTest, SupportTable) {
  const std::vector<LLMProtocol> supported = {LLMProtocol::OpenAiChatCompletions,
                                              LLMProtocol::AnthropicMessages,
                                              LLMProtocol::GeminiGenerateContent};
  for (LLMProtocol from : supported) {
    for (LLMProtocol to : supported) {
      EXPECT_TRUE(responseConversionSupported(from, to));
    }
    EXPECT_FALSE(responseConversionSupported(from, LLMProtocol::OpenAiResponses));
    EXPECT_FALSE(responseConversionSupported(LLMProtocol::OpenAiResponses, from));
  }
  EXPECT_TRUE(
      responseConversionSupported(LLMProtocol::OpenAiResponses, LLMProtocol::OpenAiResponses));
}

TEST(ResponseConverterTest, SameProtocolNeedsNoConverter) {
  auto converter = createStreamConverter(LLMProtocol::AnthropicMessages,
                                         LLMProtocol::AnthropicMessages, context());
  ASSERT_TRUE(converter.ok());
  EXPECT_EQ(*converter, nullptr);
  auto body = convertUnaryResponse(LLMProtocol::GeminiGenerateContent,
                                   LLMProtocol::GeminiGenerateContent, json{{"a", 1}}, context());
  ASSERT_TRUE(body.ok());
  EXPECT_EQ(*body, (json{{"a", 1}}));
}

TEST(ResponseConverterTest, UnsupportedPairIsAnError) {
  EXPECT_FALSE(createStreamConverter(LLMProtocol::OpenAiResponses,
                                     LLMProtocol::OpenAiChatCompletions, context())
                   .ok());
  EXPECT_FALSE(convertUnaryResponse(LLMProtocol::AnthropicMessages, LLMProtocol::OpenAiResponses,
                                    json::object(), context())
                   .ok());
}

TEST(ResponseConverterTest, DirectConvertersExist) {
  for (auto [from, to] : std::vector<std::pair<LLMProtocol, LLMProtocol>>{
           {LLMProtocol::AnthropicMessages, LLMProtocol::OpenAiChatCompletions},
           {LLMProtocol::GeminiGenerateContent, LLMProtocol::OpenAiChatCompletions},
           {LLMProtocol::OpenAiChatCompletions, LLMProtocol::AnthropicMessages},
           {LLMProtocol::OpenAiChatCompletions, LLMProtocol::GeminiGenerateContent}}) {
    auto converter = createStreamConverter(from, to, context());
    ASSERT_TRUE(converter.ok());
    EXPECT_NE(*converter, nullptr);
  }
}

TEST(ResponseConverterTest, ChainsGeminiToAnthropicUnary) {
  auto body = convertUnaryResponse(
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

TEST(ResponseConverterTest, ChainsAnthropicToGeminiUnary) {
  auto body = convertUnaryResponse(
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

TEST(ResponseConverterTest, ChainsAGeminiStreamIntoAnthropicEvents) {
  auto converter = createStreamConverter(LLMProtocol::GeminiGenerateContent,
                                         LLMProtocol::AnthropicMessages, context());
  ASSERT_TRUE(converter.ok());
  ASSERT_NE(*converter, nullptr);
  std::vector<SseFrame> out;
  ASSERT_TRUE((*converter)
                  ->onFrame(SseFrame::ofJson(
                                json::parse(R"({"candidates":[{"content":{"role":"model","parts":[)"
                                            R"({"text":"Hel"}]}}],"responseId":"r1"})")),
                            out)
                  .ok());
  ASSERT_TRUE((*converter)
                  ->onFrame(SseFrame::ofJson(
                                json::parse(R"({"candidates":[{"content":{"role":"model","parts":[)"
                                            R"({"text":"lo"}]},"finishReason":"STOP"}],)"
                                            R"("usageMetadata":{"promptTokenCount":3,)"
                                            R"("candidatesTokenCount":2,"totalTokenCount":5}})")),
                            out)
                  .ok());
  ASSERT_TRUE((*converter)->onEnd(out).ok());

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

} // namespace
} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
