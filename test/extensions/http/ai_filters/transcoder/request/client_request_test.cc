#include "source/extensions/http/ai_filters/transcoder/request/client_request.h"

#include "test/test_common/status_utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {
namespace {

using StatusHelpers::HasStatus;
using testing::HasSubstr;

nlohmann::json parseJson(absl::string_view text) {
  nlohmann::json parsed = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
  EXPECT_FALSE(parsed.is_discarded()) << text;
  return parsed;
}

absl::StatusOr<ClientRequest> readBody(LLMProtocol protocol, absl::string_view body) {
  return readClientRequest(protocol, parseJson(body), "/v1/chat/completions");
}

absl::StatusOr<ClientRequest> readGeminiPath(absl::string_view path) {
  return readClientRequest(LLMProtocol::GeminiGenerateContent, nlohmann::json::object(), path);
}

TEST(ClientRequestTest, OpenAiUnary) {
  absl::StatusOr<ClientRequest> client =
      readBody(LLMProtocol::OpenAiChatCompletions, R"({"model": "gpt-4o", "messages": []})");
  ASSERT_TRUE(client.ok());
  EXPECT_EQ(client->model, "gpt-4o");
  EXPECT_FALSE(client->stream);
  EXPECT_FALSE(client->include_usage);
}

TEST(ClientRequestTest, OpenAiStreamWithUsage) {
  absl::StatusOr<ClientRequest> client =
      readBody(LLMProtocol::OpenAiChatCompletions,
               R"({"model": "gpt-4o", "stream": true, "stream_options": {"include_usage": true}})");
  ASSERT_TRUE(client.ok());
  EXPECT_TRUE(client->stream);
  EXPECT_TRUE(client->include_usage);
}

TEST(ClientRequestTest, OpenAiStreamWithoutUsage) {
  absl::StatusOr<ClientRequest> client = readBody(
      LLMProtocol::OpenAiChatCompletions,
      R"({"model": "gpt-4o", "stream": true, "stream_options": {"include_usage": false}})");
  ASSERT_TRUE(client.ok());
  EXPECT_TRUE(client->stream);
  EXPECT_FALSE(client->include_usage);
}

TEST(ClientRequestTest, OnlyBooleanTrueCounts) {
  absl::StatusOr<ClientRequest> client = readBody(
      LLMProtocol::OpenAiChatCompletions,
      R"({"model": "gpt-4o", "stream": "true", "stream_options": {"include_usage": "true"}})");
  ASSERT_TRUE(client.ok());
  EXPECT_FALSE(client->stream);
  EXPECT_FALSE(client->include_usage);

  client = readBody(LLMProtocol::OpenAiChatCompletions,
                    R"({"model": "gpt-4o", "stream": null, "stream_options": true})");
  ASSERT_TRUE(client.ok());
  EXPECT_FALSE(client->stream);
  EXPECT_FALSE(client->include_usage);
}

TEST(ClientRequestTest, AnthropicReadsModelAndStream) {
  absl::StatusOr<ClientRequest> client =
      readBody(LLMProtocol::AnthropicMessages,
               R"({"model": "claude-sonnet-4-5@20250929", "max_tokens": 16, "stream": true,
                   "stream_options": {"include_usage": true}})");
  ASSERT_TRUE(client.ok());
  EXPECT_EQ(client->model, "claude-sonnet-4-5@20250929");
  EXPECT_TRUE(client->stream);
  // `stream_options` is OpenAI's.
  EXPECT_FALSE(client->include_usage);
}

TEST(ClientRequestTest, BodyProtocolsRequireAModel) {
  for (LLMProtocol protocol :
       {LLMProtocol::OpenAiChatCompletions, LLMProtocol::AnthropicMessages}) {
    EXPECT_THAT(readBody(protocol, R"({"messages": []})"),
                HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("request has no model")));
    EXPECT_THAT(readBody(protocol, R"({"model": 4})"),
                HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("request has no model")));
    EXPECT_THAT(readBody(protocol, R"({"model": ""})"),
                HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("request has no model")));
    EXPECT_THAT(readBody(protocol, R"(["gpt-4o"])"),
                HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("not a JSON object")));
  }
}

TEST(ClientRequestTest, GeminiApiPath) {
  absl::StatusOr<ClientRequest> client =
      readGeminiPath("/v1beta/models/gemini-2.5-flash:generateContent");
  ASSERT_TRUE(client.ok());
  EXPECT_EQ(client->model, "gemini-2.5-flash");
  EXPECT_FALSE(client->stream);
  EXPECT_FALSE(client->include_usage);

  client = readGeminiPath("/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse");
  ASSERT_TRUE(client.ok());
  EXPECT_EQ(client->model, "gemini-2.5-flash");
  EXPECT_TRUE(client->stream);
}

TEST(ClientRequestTest, VertexPath) {
  absl::StatusOr<ClientRequest> client =
      readGeminiPath("/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-pro:"
                     "streamGenerateContent?alt=sse");
  ASSERT_TRUE(client.ok());
  EXPECT_EQ(client->model, "gemini-2.5-pro");
  EXPECT_TRUE(client->stream);

  client = readGeminiPath(
      "/v1/projects/p/locations/global/publishers/google/models/gemini-2.5-pro:generateContent");
  ASSERT_TRUE(client.ok());
  EXPECT_EQ(client->model, "gemini-2.5-pro");
  EXPECT_FALSE(client->stream);
}

TEST(ClientRequestTest, GeminiModelIsPercentDecoded) {
  absl::StatusOr<ClientRequest> client =
      readGeminiPath("/v1beta/models/my-model%4020250929:generateContent");
  ASSERT_TRUE(client.ok());
  EXPECT_EQ(client->model, "my-model@20250929");

  // The method is split off before decoding, so an encoded colon stays in the model.
  client = readGeminiPath("/v1beta/models/a%3Ab:generateContent");
  ASSERT_TRUE(client.ok());
  EXPECT_EQ(client->model, "a:b");
}

TEST(ClientRequestTest, GeminiIgnoresTheBody) {
  absl::StatusOr<ClientRequest> client = readClientRequest(
      LLMProtocol::GeminiGenerateContent, parseJson(R"({"model": "other", "stream": true})"),
      "/v1beta/models/gemini-2.5-flash:generateContent");
  ASSERT_TRUE(client.ok());
  EXPECT_EQ(client->model, "gemini-2.5-flash");
  EXPECT_FALSE(client->stream);
}

TEST(ClientRequestTest, GeminiPathErrors) {
  EXPECT_THAT(readGeminiPath("/v1beta/gemini-2.5-flash:generateContent"),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("names no model")));
  EXPECT_THAT(readGeminiPath("/v1beta/models/gemini-2.5-flash"),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("names no model")));
  EXPECT_THAT(readGeminiPath("/v1beta/models/:generateContent"),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("names no model")));
  // The query string is not part of the resource.
  EXPECT_THAT(readGeminiPath("/v1beta/models/gemini?x=/models/m:generateContent"),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("names no model")));
  EXPECT_THAT(readGeminiPath("/v1beta/models/gemini-2.5-flash:countTokens"),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("unsupported Gemini method 'countTokens'")));
  EXPECT_THAT(
      readGeminiPath("/v1beta/models/gemini-2.5-flash:generateContent/extra"),
      HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("unsupported Gemini method")));
}

TEST(ClientRequestTest, OtherProtocolsAreRejected) {
  const nlohmann::json body = parseJson(R"({"model": "gpt-4o"})");
  EXPECT_THAT(readClientRequest(LLMProtocol::OpenAiResponses, body, "/v1/responses"),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("OPENAI_RESPONSES")));
  EXPECT_THAT(readClientRequest(LLMProtocol::Unspecified, body, "/v1/chat/completions"),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("LLM_PROTOCOL_UNSPECIFIED")));
}

} // namespace
} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
