#include <string>

#include "source/extensions/filters/http/ai_protocol_manager/request_protocol_classifier.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

TEST(RequestProtocolClassifierTest, ClassifiesExactOperationSuffixes) {
  EXPECT_EQ(classifyRequestPath("/v1/chat/completions").api_protocol,
            ApiProtocol::OpenAiChatCompletions);
  EXPECT_EQ(classifyRequestPath("/gateway/openai/v1/responses?trace=1").api_protocol,
            ApiProtocol::OpenAiResponses);
  EXPECT_EQ(classifyRequestPath("/v1/messages").api_protocol, ApiProtocol::AnthropicMessages);

  EXPECT_FALSE(classifyRequestPath("/v1/chat/completions/").matched());
  EXPECT_FALSE(classifyRequestPath("/v1/responses/batch").matched());
  EXPECT_FALSE(classifyRequestPath("/v1/messages/count_tokens").matched());
  EXPECT_FALSE(classifyRequestPath("/v1/not-messages").matched());
  EXPECT_FALSE(classifyRequestPath("v1/messages").matched());
}

TEST(RequestProtocolClassifierTest, UsesKnownAuthorityAsCorroboratingEvidence) {
  EXPECT_EQ(detectRequestProtocol("API.ANTHROPIC.COM:443", "/v1/messages").api_protocol,
            ApiProtocol::AnthropicMessages);
  EXPECT_EQ(detectRequestProtocol("generativelanguage.googleapis.com",
                                  "/v1beta/models/gemini-2.5-pro:generateContent")
                .api_protocol,
            ApiProtocol::GeminiGenerateContent);
  EXPECT_FALSE(detectRequestProtocol("api.openai.com", "/v1/messages").matched());
  EXPECT_FALSE(detectRequestProtocol("api.anthropic.com", "/v1/responses").matched());
  EXPECT_FALSE(detectRequestProtocol("gateway.example", "/v1/messages").matched());
}

TEST(RequestProtocolClassifierTest, ExtractsGeminiModelAndStreamingFromPath) {
  const RequestProtocolClassification generate =
      classifyRequestPath("/v1beta/models/gemini-2.5-pro:generateContent");
  ASSERT_EQ(generate.api_protocol, ApiProtocol::GeminiGenerateContent);
  EXPECT_EQ(generate.detection_source, DetectionSource::AuthorityPath);
  EXPECT_EQ(generate.model, "gemini-2.5-pro");
  EXPECT_EQ(generate.streaming, false);

  const RequestProtocolClassification stream =
      classifyRequestPath("/proxy/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse");
  ASSERT_EQ(stream.api_protocol, ApiProtocol::GeminiGenerateContent);
  EXPECT_EQ(stream.model, "gemini-2.5-flash");
  EXPECT_EQ(stream.streaming, true);
}

TEST(RequestProtocolClassifierTest, RejectsWeakGeminiMatches) {
  EXPECT_FALSE(classifyRequestPath("/v1beta/gemini-2.5-pro:generateContent").matched());
  EXPECT_FALSE(classifyRequestPath("/v1beta/models/:generateContent").matched());
  EXPECT_FALSE(classifyRequestPath("/v1beta/models/a/b:generateContent").matched());
  EXPECT_FALSE(classifyRequestPath("/v1beta/models/a:generateContent/more").matched());
  EXPECT_FALSE(classifyRequestPath("/v1beta/models/" + std::string(257, 'm') + ":generateContent")
                   .matched());
}

TEST(RequestProtocolClassifierTest, SelectsProtocolByEvidencePrecedence) {
  const RequestProtocolClassification route = selectRequestProtocol(
      ApiProtocol::AnthropicMessages, ApiProtocol::OpenAiResponses, "gateway.example",
      "/v1/chat/completions", ApiProtocol::GeminiGenerateContent);
  EXPECT_EQ(route.api_protocol, ApiProtocol::AnthropicMessages);
  EXPECT_EQ(route.detection_source, DetectionSource::Route);

  const RequestProtocolClassification configured =
      selectRequestProtocol(ApiProtocol::Unspecified, ApiProtocol::OpenAiResponses,
                            "gateway.example", "/v1/messages", ApiProtocol::AnthropicMessages);
  EXPECT_EQ(configured.api_protocol, ApiProtocol::OpenAiResponses);
  EXPECT_EQ(configured.detection_source, DetectionSource::ConfigDefault);

  const RequestProtocolClassification target =
      selectRequestProtocol(ApiProtocol::Unspecified, ApiProtocol::Unspecified, "api.anthropic.com",
                            "/v1/messages", ApiProtocol::OpenAiResponses);
  EXPECT_EQ(target.api_protocol, ApiProtocol::AnthropicMessages);
  EXPECT_EQ(target.detection_source, DetectionSource::AuthorityPath);

  const RequestProtocolClassification body =
      selectRequestProtocol(ApiProtocol::Unspecified, ApiProtocol::Unspecified, "gateway.example",
                            "/proxy/infer", ApiProtocol::OpenAiResponses);
  EXPECT_EQ(body.api_protocol, ApiProtocol::OpenAiResponses);
  EXPECT_EQ(body.detection_source, DetectionSource::Body);
}

TEST(RequestProtocolClassifierTest, PreservesMatchingGeminiPathAttributes) {
  const RequestProtocolClassification route = selectRequestProtocol(
      ApiProtocol::GeminiGenerateContent, ApiProtocol::Unspecified, "gateway.example",
      "/v1beta/models/gemini-2.5-pro:streamGenerateContent", ApiProtocol::Unspecified);
  EXPECT_EQ(route.detection_source, DetectionSource::Route);
  EXPECT_EQ(route.model, "gemini-2.5-pro");
  EXPECT_EQ(route.streaming, true);
}

TEST(RequestProtocolClassifierTest, BedrockNeedsBodyProtocolBeforeApplyingTarget) {
  constexpr absl::string_view authority{"bedrock-runtime.us-east-1.amazonaws.com"};
  constexpr absl::string_view stream_path{
      "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/invoke-with-response-stream"};
  EXPECT_FALSE(detectRequestProtocol(authority, stream_path).matched());

  RequestInfo info;
  applyRequestTarget(stream_path, ApiProtocol::Unspecified, info);
  EXPECT_FALSE(info.model.has_value());
  EXPECT_FALSE(info.streaming.has_value());

  applyRequestTarget(stream_path, ApiProtocol::AnthropicMessages, info);
  EXPECT_EQ(info.model, "anthropic.claude-3-5-sonnet-20241022-v2%3A0");
  EXPECT_EQ(info.streaming, true);

  const RequestProtocolClassification body =
      selectRequestProtocol(ApiProtocol::Unspecified, ApiProtocol::Unspecified, authority,
                            stream_path, ApiProtocol::AnthropicMessages);
  EXPECT_EQ(body.api_protocol, ApiProtocol::AnthropicMessages);
  EXPECT_EQ(body.detection_source, DetectionSource::Body);
  EXPECT_EQ(body.model, "anthropic.claude-3-5-sonnet-20241022-v2%3A0");
  EXPECT_EQ(body.streaming, true);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
