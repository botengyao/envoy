#include <string>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/transcoding_engine.h"

#include "test/test_common/status_utility.h"

#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

using StatusHelpers::HasStatus;
using StatusHelpers::IsOk;
using testing::ElementsAre;
using testing::HasSubstr;
using testing::IsEmpty;
using testing::UnorderedElementsAre;

constexpr LLMProtocol kOpenAi = LLMProtocol::OpenAiChatCompletions;
constexpr LLMProtocol kAnthropic = LLMProtocol::AnthropicMessages;
constexpr LLMProtocol kGemini = LLMProtocol::GeminiGenerateContent;

nlohmann::json parseJson(absl::string_view text) {
  nlohmann::json parsed = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
  EXPECT_FALSE(parsed.is_discarded()) << text;
  return parsed;
}

std::string dump(const nlohmann::json& json) {
  return json.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

absl::StatusOr<RequestEnvelope> readBody(LLMProtocol protocol, absl::string_view body) {
  return TranscodingEngine::readRequestEnvelope(protocol, parseJson(body), "/v1/chat/completions");
}

absl::StatusOr<RequestEnvelope> readGeminiPath(absl::string_view path) {
  return TranscodingEngine::readRequestEnvelope(LLMProtocol::GeminiGenerateContent,
                                                nlohmann::json::object(), path);
}

TEST(RequestEnvelopeTest, OpenAiUnary) {
  absl::StatusOr<RequestEnvelope> envelope =
      readBody(LLMProtocol::OpenAiChatCompletions, R"({"model": "gpt-4o", "messages": []})");
  ASSERT_TRUE(envelope.ok());
  EXPECT_EQ(envelope->model, "gpt-4o");
  EXPECT_FALSE(envelope->stream);
  EXPECT_FALSE(envelope->include_usage);
}

TEST(RequestEnvelopeTest, OpenAiStreamWithUsage) {
  absl::StatusOr<RequestEnvelope> envelope =
      readBody(LLMProtocol::OpenAiChatCompletions,
               R"({"model": "gpt-4o", "stream": true, "stream_options": {"include_usage": true}})");
  ASSERT_TRUE(envelope.ok());
  EXPECT_TRUE(envelope->stream);
  EXPECT_TRUE(envelope->include_usage);
  EXPECT_TRUE(envelope->sse);
}

TEST(RequestEnvelopeTest, OpenAiStreamWithoutUsage) {
  absl::StatusOr<RequestEnvelope> envelope = readBody(
      LLMProtocol::OpenAiChatCompletions,
      R"({"model": "gpt-4o", "stream": true, "stream_options": {"include_usage": false}})");
  ASSERT_TRUE(envelope.ok());
  EXPECT_TRUE(envelope->stream);
  EXPECT_FALSE(envelope->include_usage);
}

TEST(RequestEnvelopeTest, OnlyBooleanTrueCounts) {
  absl::StatusOr<RequestEnvelope> envelope = readBody(
      LLMProtocol::OpenAiChatCompletions,
      R"({"model": "gpt-4o", "stream": "true", "stream_options": {"include_usage": "true"}})");
  ASSERT_TRUE(envelope.ok());
  EXPECT_FALSE(envelope->stream);
  EXPECT_FALSE(envelope->include_usage);

  envelope = readBody(LLMProtocol::OpenAiChatCompletions,
                      R"({"model": "gpt-4o", "stream": null, "stream_options": true})");
  ASSERT_TRUE(envelope.ok());
  EXPECT_FALSE(envelope->stream);
  EXPECT_FALSE(envelope->include_usage);
}

TEST(RequestEnvelopeTest, AnthropicReadsModelAndStream) {
  absl::StatusOr<RequestEnvelope> envelope =
      readBody(LLMProtocol::AnthropicMessages,
               R"({"model": "claude-sonnet-4-5@20250929", "max_tokens": 16, "stream": true,
                   "stream_options": {"include_usage": true}})");
  ASSERT_TRUE(envelope.ok());
  EXPECT_EQ(envelope->model, "claude-sonnet-4-5@20250929");
  EXPECT_TRUE(envelope->stream);
  // `stream_options` is OpenAI's.
  EXPECT_FALSE(envelope->include_usage);
}

TEST(RequestEnvelopeTest, BodyProtocolsRequireAModel) {
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

TEST(RequestEnvelopeTest, GeminiApiPath) {
  absl::StatusOr<RequestEnvelope> envelope =
      readGeminiPath("/v1beta/models/gemini-2.5-flash:generateContent");
  ASSERT_TRUE(envelope.ok());
  EXPECT_EQ(envelope->model, "gemini-2.5-flash");
  EXPECT_FALSE(envelope->stream);
  EXPECT_FALSE(envelope->include_usage);
  EXPECT_TRUE(envelope->sse);

  envelope = readGeminiPath("/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse");
  ASSERT_TRUE(envelope.ok());
  EXPECT_EQ(envelope->model, "gemini-2.5-flash");
  EXPECT_TRUE(envelope->stream);
  EXPECT_TRUE(envelope->sse);
}

// Without `alt=sse` a Gemini stream is one JSON array.
TEST(RequestEnvelopeTest, GeminiStreamWithoutSse) {
  absl::StatusOr<RequestEnvelope> envelope =
      readGeminiPath("/v1beta/models/gemini-2.5-flash:streamGenerateContent");
  ASSERT_TRUE(envelope.ok());
  EXPECT_TRUE(envelope->stream);
  EXPECT_FALSE(envelope->sse);

  envelope = readGeminiPath("/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=json");
  ASSERT_TRUE(envelope.ok());
  EXPECT_FALSE(envelope->sse);
}

TEST(RequestEnvelopeTest, VertexPath) {
  absl::StatusOr<RequestEnvelope> envelope =
      readGeminiPath("/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-pro:"
                     "streamGenerateContent?alt=sse");
  ASSERT_TRUE(envelope.ok());
  EXPECT_EQ(envelope->model, "gemini-2.5-pro");
  EXPECT_TRUE(envelope->stream);

  envelope = readGeminiPath(
      "/v1/projects/p/locations/global/publishers/google/models/gemini-2.5-pro:generateContent");
  ASSERT_TRUE(envelope.ok());
  EXPECT_EQ(envelope->model, "gemini-2.5-pro");
  EXPECT_FALSE(envelope->stream);
}

TEST(RequestEnvelopeTest, GeminiModelIsPercentDecoded) {
  absl::StatusOr<RequestEnvelope> envelope =
      readGeminiPath("/v1beta/models/my-model%4020250929:generateContent");
  ASSERT_TRUE(envelope.ok());
  EXPECT_EQ(envelope->model, "my-model@20250929");

  // The method is split off before decoding, so an encoded colon stays in the model.
  envelope = readGeminiPath("/v1beta/models/a%3Ab:generateContent");
  ASSERT_TRUE(envelope.ok());
  EXPECT_EQ(envelope->model, "a:b");
}

TEST(RequestEnvelopeTest, GeminiIgnoresTheBody) {
  absl::StatusOr<RequestEnvelope> envelope = TranscodingEngine::readRequestEnvelope(
      LLMProtocol::GeminiGenerateContent, parseJson(R"({"model": "other", "stream": true})"),
      "/v1beta/models/gemini-2.5-flash:generateContent");
  ASSERT_TRUE(envelope.ok());
  EXPECT_EQ(envelope->model, "gemini-2.5-flash");
  EXPECT_FALSE(envelope->stream);
}

TEST(RequestEnvelopeTest, GeminiPathErrors) {
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

TEST(RequestEnvelopeTest, OtherProtocolsAreRejected) {
  const nlohmann::json body = parseJson(R"({"model": "gpt-4o"})");
  EXPECT_THAT(
      TranscodingEngine::readRequestEnvelope(LLMProtocol::OpenAiResponses, body, "/v1/responses"),
      HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("OPENAI_RESPONSES")));
  EXPECT_THAT(TranscodingEngine::readRequestEnvelope(LLMProtocol::Unspecified, body,
                                                     "/v1/chat/completions"),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("LLM_PROTOCOL_UNSPECIFIED")));
}

class TranscodingRequestTest : public testing::Test {
protected:
  absl::Status convert(LLMProtocol from, LLMProtocol to, absl::string_view body,
                       const RequestEnvelope& envelope) {
    body_ = parseJson(body);
    return engine_.transcodeRequest(from, to, body_, envelope, options_, report_);
  }

  absl::Status toIr(LLMProtocol from, nlohmann::json& body, const RequestEnvelope& envelope) {
    TranscodeReport report;
    return engine_.transcodeToIr(from, body, envelope, report);
  }

  void expectBody(absl::string_view expected) {
    const nlohmann::json parsed = parseJson(expected);
    EXPECT_EQ(body_, parsed) << "actual:\n" << dump(body_) << "\nexpected:\n" << dump(parsed);
  }

  static RequestEnvelope envelope(std::string model, bool stream = false) {
    RequestEnvelope envelope;
    envelope.model = std::move(model);
    envelope.stream = stream;
    return envelope;
  }

  const TranscodingEngine engine_ = TranscodingEngine::createDefault().value();
  TranscodeOptions options_;
  nlohmann::json body_;
  TranscodeReport report_;
};

TEST_F(TranscodingRequestTest, OpenAiToAnthropic) {
  ASSERT_THAT(convert(kOpenAi, kAnthropic, R"({
    "model": "claude-sonnet-4-5",
    "messages": [
      {"role": "system", "content": "Be brief."},
      {"role": "developer", "content": [{"type": "text", "text": "Answer in English."}]},
      {"role": "user", "content": "Hi"},
      {"role": "assistant", "content": "Hello!"},
      {"role": "user", "content": [{"type": "text", "text": "What is 2+2?"}]},
      {"role": "user", "content": "Show your work."}
    ],
    "max_completion_tokens": 256,
    "temperature": 0.2,
    "top_p": 0.9,
    "stop": "END",
    "user": "user-42",
    "n": 1,
    "stream": true,
    "stream_options": {"include_usage": true}
  })",
                      envelope("claude-sonnet-4-5", true)),
              IsOk());
  expectBody(R"({
    "model": "claude-sonnet-4-5",
    "system": [
      {"type": "text", "text": "Be brief."},
      {"type": "text", "text": "Answer in English."}
    ],
    "messages": [
      {"role": "user", "content": "Hi"},
      {"role": "assistant", "content": "Hello!"},
      {"role": "user", "content": [
        {"type": "text", "text": "What is 2+2?"},
        {"type": "text", "text": "Show your work."}
      ]}
    ],
    "max_tokens": 256,
    "temperature": 0.2,
    "top_p": 0.9,
    "stop_sequences": ["END"],
    "metadata": {"user_id": "user-42"},
    "stream": true
  })");
  EXPECT_THAT(report_.dropped, IsEmpty());
}

TEST_F(TranscodingRequestTest, OpenAiToAnthropicPlacesTheClientModel) {
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "alias", "max_tokens": 10,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude-sonnet-4-5@20250929")),
              IsOk());
  expectBody(R"({
    "model": "claude-sonnet-4-5@20250929",
    "max_tokens": 10,
    "messages": [{"role": "user", "content": "Hi"}]
  })");
}

TEST_F(TranscodingRequestTest, OpenAiToolsToAnthropic) {
  ASSERT_THAT(convert(kOpenAi, kAnthropic, R"({
    "model": "claude",
    "max_tokens": 64,
    "messages": [{"role": "user", "content": "Weather in Paris?"}],
    "tools": [
      {"type": "function", "function": {
        "name": "get_weather",
        "description": "Weather for a city",
        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
        "strict": true}},
      {"type": "function", "function": {"name": "now"}}
    ],
    "tool_choice": "required",
    "parallel_tool_calls": false
  })",
                      envelope("claude")),
              IsOk());
  expectBody(R"({
    "model": "claude",
    "max_tokens": 64,
    "messages": [{"role": "user", "content": "Weather in Paris?"}],
    "tools": [
      {"name": "get_weather", "description": "Weather for a city",
       "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}},
      {"name": "now", "input_schema": {"type": "object"}}
    ],
    "tool_choice": {"type": "any", "disable_parallel_tool_use": true}
  })");
  EXPECT_THAT(report_.dropped, IsEmpty());
}

TEST_F(TranscodingRequestTest, ParallelToolCallsToAnthropic) {
  constexpr absl::string_view kTools =
      R"("tools": [{"type": "function", "function": {"name": "now"}}])";
  const std::string prefix = absl::StrCat(
      R"({"model": "claude", "max_tokens": 8, "messages": [{"role": "user", "content": "Hi"}], )",
      kTools);

  // Anthropic defaults to `auto` when it is not named.
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      absl::StrCat(prefix, R"(, "parallel_tool_calls": false})"),
                      envelope("claude")),
              IsOk());
  EXPECT_EQ(body_["tool_choice"],
            parseJson(R"({"type": "auto", "disable_parallel_tool_use": true})"));

  ASSERT_THAT(
      convert(kOpenAi, kAnthropic,
              absl::StrCat(prefix, R"(, "tool_choice": "none", "parallel_tool_calls": false})"),
              envelope("claude")),
      IsOk());
  EXPECT_EQ(body_["tool_choice"], parseJson(R"({"type": "none"})"));

  // Parallel calls are already Anthropic's default.
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      absl::StrCat(prefix, R"(, "parallel_tool_calls": true})"),
                      envelope("claude")),
              IsOk());
  EXPECT_FALSE(body_.contains("tool_choice"));

  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      absl::StrCat(prefix, R"(, "parallel_tool_calls": null})"),
                      envelope("claude")),
              IsOk());
  EXPECT_FALSE(body_.contains("tool_choice"));

  // Without tools there is nothing to run in parallel.
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "parallel_tool_calls": false,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              IsOk());
  EXPECT_FALSE(body_.contains("tool_choice"));
  EXPECT_FALSE(body_.contains("parallel_tool_calls"));
  EXPECT_THAT(report_.dropped, IsEmpty());
}

TEST_F(TranscodingRequestTest, OpenAiOnlyFieldsArePrunedForAnthropic) {
  ASSERT_THAT(convert(kOpenAi, kAnthropic, R"({
    "model": "claude",
    "messages": [{"role": "user", "name": "alice", "content": "Hi"},
                 {"role": "assistant", "name": "bot", "content": "Hello", "refusal": null,
                  "tool_calls": null, "annotations": []},
                 {"role": "user", "name": "alice", "content": [
                   {"type": "text", "text": "Bye", "cache_control": null}]}],
    "max_tokens": 32,
    "seed": 7,
    "presence_penalty": 0.5,
    "frequency_penalty": 0.5,
    "logit_bias": {"50256": -100},
    "logprobs": true,
    "top_logprobs": 2,
    "response_format": {"type": "json_object"},
    "metadata": {"purpose": "eval"},
    "service_tier": "flex",
    "store": true,
    "reasoning_effort": "low",
    "modalities": ["text"],
    "prediction": {"type": "content", "content": "x"},
    "audio": {"voice": "alloy", "format": "mp3"},
    "web_search_options": {"search_context_size": "low"},
    "verbosity": "low",
    "prompt_cache_key": "k",
    "safety_identifier": "s",
    "some_future_field": 1,
    "user": null,
    "top_logprobs_unset": null,
    "stream_options": {"include_usage": true}
  })",
                      envelope("claude")),
              IsOk());
  expectBody(R"({
    "model": "claude",
    "messages": [{"role": "user", "content": "Hi"}, {"role": "assistant", "content": "Hello"},
                 {"role": "user", "content": [{"type": "text", "text": "Bye"}]}],
    "max_tokens": 32
  })");
  EXPECT_THAT(report_.dropped,
              UnorderedElementsAre("metadata.purpose", "service_tier", "seed", "presence_penalty",
                                   "frequency_penalty", "logit_bias", "logprobs", "top_logprobs",
                                   "response_format", "store", "reasoning_effort", "modalities",
                                   "prediction", "audio", "web_search_options", "verbosity",
                                   "prompt_cache_key", "safety_identifier", "some_future_field",
                                   "messages[].name"));
}

TEST_F(TranscodingRequestTest, AnthropicKeepsItsOwnServiceTier) {
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "service_tier": "auto",
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              IsOk());
  EXPECT_EQ(body_["service_tier"], "auto");
  EXPECT_THAT(report_.dropped, IsEmpty());
}

TEST_F(TranscodingRequestTest, OpenAiMetadataIsReplacedByTheUser) {
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "user": "u-1",
                          "metadata": {"purpose": "eval"},
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              IsOk());
  EXPECT_EQ(body_["metadata"], parseJson(R"({"user_id": "u-1"})"));
  EXPECT_THAT(report_.dropped, ElementsAre("metadata.purpose"));
}

TEST_F(TranscodingRequestTest, RejectModeFailsOnADroppedField) {
  options_.unsupported_fields = UnsupportedFieldPolicy::Reject;
  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "seed": 1, "logprobs": true,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("ANTHROPIC_MESSAGES cannot express request fields: logprobs, "
                                  "seed")));
  EXPECT_THAT(report_.dropped, ElementsAre("logprobs", "seed"));
}

TEST_F(TranscodingRequestTest, RejectModeAcceptsWhatTheTranscoderHandles) {
  options_.unsupported_fields = UnsupportedFieldPolicy::Reject;
  ASSERT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "gemini-2.5-flash", "stream": true, "seed": null,
                          "response_format": null, "service_tier": null, "store": null,
                          "stream_options": {"include_usage": true}, "logit_bias": {},
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("gemini-2.5-flash", true)),
              IsOk());
  expectBody(R"({"contents": [{"role": "user", "parts": [{"text": "Hi"}]}]})");
  EXPECT_THAT(report_.dropped, IsEmpty());
}

// Regression: an explicit `false`, which some clients send for every flag, counted as a dropped
// request and failed REJECT mode.
TEST_F(TranscodingRequestTest, RejectModeAcceptsFlagsThatAreOff) {
  options_.unsupported_fields = UnsupportedFieldPolicy::Reject;
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "logprobs": false, "store": false,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              IsOk());
  expectBody(R"({"model": "claude", "max_tokens": 8,
                 "messages": [{"role": "user", "content": "Hi"}]})");
  EXPECT_THAT(report_.dropped, IsEmpty());

  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "logprobs": true,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("fields: logprobs")));
}

TEST_F(TranscodingRequestTest, MultipleChoicesAreRejected) {
  for (LLMProtocol to : {kAnthropic, kGemini}) {
    EXPECT_THAT(
        convert(kOpenAi, to,
                R"({"model": "m", "n": 2, "messages": [{"role": "user", "content": "Hi"}]})",
                envelope("m")),
        HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("'n' must be 1")));
    EXPECT_THAT(
        convert(kOpenAi, to,
                R"({"model": "m", "n": "1", "messages": [{"role": "user", "content": "Hi"}]})",
                envelope("m")),
        HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("'n' must be 1")));
    for (absl::string_view n : {"1", "null"}) {
      ASSERT_THAT(convert(kOpenAi, to,
                          absl::StrCat(R"({"model": "m", "n": )", n,
                                       R"(, "messages": [{"role": "user", "content": "Hi"}]})"),
                          envelope("m")),
                  IsOk());
      EXPECT_FALSE(body_.contains("n"));
    }
  }
}

TEST_F(TranscodingRequestTest, DefaultMaxOutputTokens) {
  options_.default_max_output_tokens = 1000;
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              IsOk());
  EXPECT_EQ(body_["max_tokens"], 1000);

  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": null, "max_completion_tokens": null,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              IsOk());
  EXPECT_EQ(body_["max_tokens"], 1000);

  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 50,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              IsOk());
  EXPECT_EQ(body_["max_tokens"], 50);

  // `max_completion_tokens` supersedes the deprecated `max_tokens`.
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 50, "max_completion_tokens": 70,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              IsOk());
  EXPECT_EQ(body_["max_tokens"], 70);
  EXPECT_FALSE(body_.contains("max_completion_tokens"));
}

TEST_F(TranscodingRequestTest, AnthropicValidationFailure) {
  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "temperature": 1.5,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid ANTHROPIC_MESSAGES: field 'temperature'")));

  // Only system prompts leave no message to send.
  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "messages": [{"role": "system", "content": "Hi"}]})",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid ANTHROPIC_MESSAGES")));
}

TEST_F(TranscodingRequestTest, MalformedIrReachesValidation) {
  EXPECT_THAT(convert(kOpenAi, kAnthropic, R"({"model": "claude", "messages": ["Hi"]})",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid ANTHROPIC_MESSAGES: field 'messages[0]'")));
  EXPECT_THAT(
      convert(kOpenAi, kAnthropic, R"({"model": "claude", "messages": "Hi"})", envelope("claude")),
      HasStatus(absl::StatusCode::kInvalidArgument,
                HasSubstr("request is not valid ANTHROPIC_MESSAGES: field 'messages'")));
  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "tools": {"name": "now"},
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid ANTHROPIC_MESSAGES: field 'tools'")));
}

TEST_F(TranscodingRequestTest, OpenAiToGemini) {
  ASSERT_THAT(convert(kOpenAi, kGemini, R"({
    "model": "gemini-2.5-flash",
    "messages": [
      {"role": "system", "content": "Be brief."},
      {"role": "developer", "content": "Use metric units."},
      {"role": "user", "content": [{"type": "text", "text": "Hi"}, {"type": "text", "text": "there"}]},
      {"role": "assistant", "content": "Hello!"},
      {"role": "user", "content": "Weather?"}
    ],
    "max_tokens": 128,
    "temperature": 0.5,
    "top_p": 0.8,
    "stop": ["a", "b"],
    "seed": 7,
    "presence_penalty": 0.5,
    "frequency_penalty": -0.5,
    "response_format": {"type": "json_schema",
                        "json_schema": {"name": "r", "schema": {"type": "object"}, "strict": true}},
    "tool_choice": "none",
    "n": 1,
    "user": "u-1",
    "stream": true,
    "stream_options": {"include_usage": true}
  })",
                      envelope("gemini-2.5-flash", true)),
              IsOk());
  expectBody(R"({
    "systemInstruction": {"parts": [{"text": "Be brief."}, {"text": "Use metric units."}]},
    "contents": [
      {"role": "user", "parts": [{"text": "Hi"}, {"text": "there"}]},
      {"role": "model", "parts": [{"text": "Hello!"}]},
      {"role": "user", "parts": [{"text": "Weather?"}]}
    ],
    "generationConfig": {
      "maxOutputTokens": 128,
      "temperature": 0.5,
      "topP": 0.8,
      "stopSequences": ["a", "b"],
      "seed": 7,
      "presencePenalty": 0.5,
      "frequencyPenalty": -0.5,
      "responseMimeType": "application/json",
      "responseJsonSchema": {"type": "object"}
    }
  })");
  EXPECT_THAT(report_.dropped, ElementsAre("user"));
}

TEST_F(TranscodingRequestTest, ResponseFormatToGemini) {
  constexpr absl::string_view kMessages = R"("messages": [{"role": "user", "content": "Hi"}])";
  const auto request = [&](absl::string_view format) {
    return absl::StrCat(R"({"model": "g", )", kMessages, R"(, "response_format": )", format, "}");
  };

  ASSERT_THAT(convert(kOpenAi, kGemini, request(R"({"type": "json_object"})"), envelope("g")),
              IsOk());
  EXPECT_EQ(body_["generationConfig"], parseJson(R"({"responseMimeType": "application/json"})"));

  ASSERT_THAT(convert(kOpenAi, kGemini,
                      request(R"({"type": "json_schema", "json_schema": {"name": "r"}})"),
                      envelope("g")),
              IsOk());
  EXPECT_EQ(body_["generationConfig"], parseJson(R"({"responseMimeType": "application/json"})"));

  ASSERT_THAT(convert(kOpenAi, kGemini, request(R"({"type": "text"})"), envelope("g")), IsOk());
  EXPECT_FALSE(body_.contains("generationConfig"));
  EXPECT_THAT(report_.dropped, IsEmpty());

  ASSERT_THAT(convert(kOpenAi, kGemini, request(R"({"type": "yaml"})"), envelope("g")), IsOk());
  EXPECT_FALSE(body_.contains("generationConfig"));
  EXPECT_THAT(report_.dropped, ElementsAre("response_format"));
}

TEST_F(TranscodingRequestTest, GeminiReplacesAMalformedGenerationConfig) {
  ASSERT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "g", "generationConfig": "fast", "seed": 3,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("g")),
              IsOk());
  EXPECT_EQ(body_["generationConfig"], parseJson(R"({"seed": 3})"));
}

TEST_F(TranscodingRequestTest, GeminiKeepsFieldsItDeclares) {
  ASSERT_THAT(convert(kOpenAi, kGemini, R"({
    "model": "g",
    "messages": [{"role": "user", "content": "Hi"}],
    "safety_settings": [{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"}],
    "cachedContent": "cachedContents/1",
    "service_tier": "flex",
    "store": true
  })",
                      envelope("g")),
              IsOk());
  expectBody(R"({
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "safety_settings": [{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"}],
    "cachedContent": "cachedContents/1"
  })");
  // OpenAI's `service_tier` and `store` mean something else to Gemini.
  EXPECT_THAT(report_.dropped, ElementsAre("store", "service_tier"));
}

TEST_F(TranscodingRequestTest, GeminiValidationFailure) {
  EXPECT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "g", "stop": ["1", "2", "3", "4", "5", "6"],
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("g")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid GEMINI_GENERATE_CONTENT")));
}

TEST_F(TranscodingRequestTest, ToolsAreNotSentToGeminiYet) {
  EXPECT_THAT(convert(kOpenAi, kGemini, R"({
    "model": "g",
    "messages": [{"role": "user", "content": "Hi"}],
    "tools": [{"type": "function", "function": {"name": "now"}}]
  })",
                      envelope("g")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("tools are not supported for GEMINI_GENERATE_CONTENT yet")));

  ASSERT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "g", "tools": [],
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("g")),
              IsOk());
}

TEST_F(TranscodingRequestTest, ToolCallTurnsAreRejected) {
  for (LLMProtocol to : {kAnthropic, kGemini}) {
    EXPECT_THAT(convert(kOpenAi, to, R"({
      "model": "m",
      "messages": [
        {"role": "user", "content": "Weather?"},
        {"role": "assistant", "content": null, "tool_calls": [
          {"id": "call_1", "type": "function",
           "function": {"name": "get_weather", "arguments": "{}"}}]}
      ]
    })",
                        envelope("m")),
                HasStatus(absl::StatusCode::kInvalidArgument,
                          HasSubstr("tool calls are not supported yet: messages[1] has "
                                    "'tool_calls'")));
    EXPECT_THAT(convert(kOpenAi, to, R"({
      "model": "m",
      "messages": [
        {"role": "user", "content": "Weather?"},
        {"role": "assistant", "content": "", "tool_calls": []},
        {"role": "tool", "tool_call_id": "call_1", "content": "sunny"}
      ]
    })",
                        envelope("m")),
                HasStatus(absl::StatusCode::kInvalidArgument,
                          HasSubstr("tool call messages are not supported yet: messages[2] has "
                                    "role 'tool'")));
    EXPECT_THAT(convert(kOpenAi, to, R"({
      "model": "m",
      "messages": [
        {"role": "assistant", "content": null, "function_call": {"name": "f", "arguments": "{}"}}
      ]
    })",
                        envelope("m")),
                HasStatus(absl::StatusCode::kInvalidArgument,
                          HasSubstr("messages[0] has 'function_call'")));
    EXPECT_THAT(convert(kOpenAi, to,
                        R"({"model": "m", "messages": [{"role": "function", "name": "f",
                            "content": "x"}]})",
                        envelope("m")),
                HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("role 'function'")));
  }
}

TEST_F(TranscodingRequestTest, NonTextContentIsRejected) {
  for (LLMProtocol to : {kAnthropic, kGemini}) {
    EXPECT_THAT(convert(kOpenAi, to, R"({
      "model": "m",
      "messages": [{"role": "user", "content": [
        {"type": "text", "text": "What is this?"},
        {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}
      ]}]
    })",
                        envelope("m")),
                HasStatus(absl::StatusCode::kInvalidArgument,
                          HasSubstr("content part type image_url is not supported yet")));
    EXPECT_THAT(convert(kOpenAi, to,
                        R"({"model": "m", "messages": [{"role": "user", "content": [
                            {"text": "untyped"}]}]})",
                        envelope("m")),
                HasStatus(absl::StatusCode::kInvalidArgument,
                          HasSubstr("content part type (none) is not supported yet")));
  }
}

// Regression: a text part without text reached Anthropic, which rejects it upstream.
TEST_F(TranscodingRequestTest, TextPartsRequireText) {
  for (LLMProtocol to : {kAnthropic, kGemini}) {
    for (absl::string_view part : {R"({"type": "text"})", R"({"type": "text", "text": null})",
                                   R"({"type": "text", "text": 7})"}) {
      EXPECT_THAT(
          convert(kOpenAi, to,
                  absl::StrCat(R"({"model": "m", "messages": [{"role": "user", "content": [)", part,
                               "]}]}"),
                  envelope("m")),
          HasStatus(absl::StatusCode::kInvalidArgument,
                    HasSubstr("messages[0].content[0] is a text content part without text")));
    }
  }
}

TEST_F(TranscodingRequestTest, AnthropicToGemini) {
  ASSERT_THAT(convert(kAnthropic, kGemini, R"({
    "model": "claude-sonnet-4-5",
    "max_tokens": 100,
    "system": [{"type": "text", "text": "Be brief.", "cache_control": {"type": "ephemeral"}}],
    "messages": [
      {"role": "user", "content": "Hi"},
      {"role": "assistant", "content": [{"type": "text", "text": "Hello"}]},
      {"role": "user", "content": "More"}
    ],
    "stop_sequences": ["x"],
    "temperature": 0.3,
    "top_k": 5,
    "metadata": {"user_id": "u-1"},
    "stream": true
  })",
                      envelope("gemini-2.5-flash", true)),
              IsOk());
  expectBody(R"({
    "systemInstruction": {"parts": [{"text": "Be brief."}]},
    "contents": [
      {"role": "user", "parts": [{"text": "Hi"}]},
      {"role": "model", "parts": [{"text": "Hello"}]},
      {"role": "user", "parts": [{"text": "More"}]}
    ],
    "generationConfig": {"maxOutputTokens": 100, "temperature": 0.3, "stopSequences": ["x"]}
  })");
  EXPECT_THAT(report_.dropped, ElementsAre("messages[].content[].cache_control", "top_k", "user"));
}

TEST_F(TranscodingRequestTest, GeminiToAnthropic) {
  ASSERT_THAT(convert(kGemini, kAnthropic, R"({
    "systemInstruction": {"role": "system", "parts": [{"text": "Be brief."}]},
    "contents": [
      {"role": "user", "parts": [{"text": "Hi"}]},
      {"role": "model", "parts": [{"text": "Hello"}]},
      {"parts": [{"text": "More"}, {"text": "please"}]}
    ],
    "generation_config": {"max_output_tokens": "64", "temperature": 0.2, "top_k": 3,
                          "stop_sequences": ["z"]},
    "safetySettings": [{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"}]
  })",
                      envelope("claude-sonnet-4-5@20250929", true)),
              IsOk());
  expectBody(R"({
    "model": "claude-sonnet-4-5@20250929",
    "system": "Be brief.",
    "messages": [
      {"role": "user", "content": "Hi"},
      {"role": "assistant", "content": "Hello"},
      {"role": "user", "content": [{"type": "text", "text": "More"}, {"type": "text", "text": "please"}]}
    ],
    "max_tokens": 64,
    "temperature": 0.2,
    "stop_sequences": ["z"],
    "stream": true
  })");
  EXPECT_THAT(report_.dropped, ElementsAre("generation_config.top_k", "safetySettings"));
}

TEST_F(TranscodingRequestTest, GeminiCandidateCountToAnthropic) {
  EXPECT_THAT(convert(kGemini, kAnthropic,
                      R"({"contents": [{"parts": [{"text": "Hi"}]}],
                          "generationConfig": {"candidateCount": 2}})",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("'n' must be 1")));
}

TEST_F(TranscodingRequestTest, AnthropicToOpenAi) {
  ASSERT_THAT(convert(kAnthropic, kOpenAi, R"({
    "model": "claude-sonnet-4-5",
    "max_tokens": 100,
    "system": "Be brief.",
    "messages": [
      {"role": "user", "content": [
        {"type": "text", "text": "Hi", "cache_control": {"type": "ephemeral"}}]}
    ],
    "stop_sequences": ["x"],
    "temperature": 0.3,
    "top_k": 5,
    "metadata": {"user_id": "u-1"},
    "thinking": {"type": "enabled", "budget_tokens": 1024},
    "tools": [
      {"name": "get_weather", "description": "Weather", "input_schema": {"type": "object"}},
      {"type": "custom", "name": "now", "input_schema": {"type": "object"}}
    ],
    "tool_choice": {"type": "tool", "name": "get_weather", "disable_parallel_tool_use": true},
    "stream": true
  })",
                      envelope("gpt-4o", true)),
              IsOk());
  expectBody(R"({
    "model": "gpt-4o",
    "messages": [
      {"role": "system", "content": "Be brief."},
      {"role": "user", "content": [{"type": "text", "text": "Hi"}]}
    ],
    "max_completion_tokens": 100,
    "stop": ["x"],
    "temperature": 0.3,
    "user": "u-1",
    "tools": [
      {"type": "function",
       "function": {"name": "get_weather", "description": "Weather",
                    "parameters": {"type": "object"}}},
      {"type": "function", "function": {"name": "now", "parameters": {"type": "object"}}}
    ],
    "tool_choice": {"type": "function", "function": {"name": "get_weather"}},
    "parallel_tool_calls": false,
    "stream": true,
    "stream_options": {"include_usage": true}
  })");
  EXPECT_THAT(report_.dropped,
              ElementsAre("messages[].content[].cache_control", "thinking", "top_k"));
}

TEST_F(TranscodingRequestTest, AnthropicServerToolsAndBlocksAreRejected) {
  EXPECT_THAT(
      convert(kAnthropic, kOpenAi, R"({
    "model": "claude",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "Search"}],
    "tools": [{"type": "web_search_20250305", "name": "web_search", "max_uses": 1}]
  })",
              envelope("gpt-4o")),
      HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("tools[0] is not a function tool")));
  EXPECT_THAT(convert(kAnthropic, kOpenAi, R"({
    "model": "claude",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": [
      {"type": "tool_result", "tool_use_id": "t1", "content": "sunny"}]}]
  })",
                      envelope("gpt-4o")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("content part type tool_result is not supported yet")));
}

TEST_F(TranscodingRequestTest, GeminiToOpenAi) {
  ASSERT_THAT(convert(kGemini, kOpenAi, R"({
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "generationConfig": {"maxOutputTokens": 32, "candidateCount": 1, "seed": "42",
                         "presencePenalty": 0.1, "frequencyPenalty": "0.2",
                         "thinkingConfig": {"thinkingBudget": 0}},
    "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}},
    "cachedContent": "cachedContents/1"
  })",
                      envelope("gpt-4o")),
              IsOk());
  expectBody(R"({
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hi"}],
    "max_completion_tokens": 32,
    "n": 1,
    "seed": 42,
    "presence_penalty": 0.1,
    "frequency_penalty": 0.2
  })");
  EXPECT_THAT(report_.dropped,
              ElementsAre("generationConfig.thinkingConfig", "cachedContent", "toolConfig"));
}

TEST_F(TranscodingRequestTest, GeminiFunctionCallsAreRejected) {
  EXPECT_THAT(convert(kGemini, kOpenAi, R"({
    "contents": [
      {"role": "user", "parts": [{"text": "Weather?"}]},
      {"role": "model", "parts": [{"functionCall": {"name": "get_weather", "args": {}}}]}
    ]
  })",
                      envelope("gpt-4o")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("tool calls are not supported yet: contents[1].parts[0] has "
                                  "'functionCall'")));
  EXPECT_THAT(convert(kGemini, kAnthropic, R"({
    "contents": [
      {"role": "user", "parts": [{"text": "Weather?"}]},
      {"role": "model", "parts": [{"function_call": {"name": "get_weather"}}]},
      {"role": "user", "parts": [{"functionResponse": {"name": "get_weather",
                                                       "response": {"sky": "clear"}}}]}
    ]
  })",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("contents[1].parts[0] has 'function_call'")));
  EXPECT_THAT(
      convert(kGemini, kAnthropic, R"({
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "tools": [{"functionDeclarations": [{"name": "now"}]}]
  })",
              envelope("claude")),
      HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("tools[0] is not a function tool")));
}

TEST_F(TranscodingRequestTest, UnsupportedConversions) {
  EXPECT_THAT(convert(kOpenAi, kOpenAi, R"({"model": "m"})", envelope("m")),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("needs no conversion")));
  EXPECT_THAT(convert(kOpenAi, LLMProtocol::OpenAiResponses, R"({"model": "m"})", envelope("m")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("cannot convert a request to OPENAI_RESPONSES")));
  EXPECT_THAT(convert(LLMProtocol::Unspecified, kAnthropic, R"({"model": "m"})", envelope("m")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("cannot convert a LLM_PROTOCOL_UNSPECIFIED request")));
  EXPECT_THAT(convert(kOpenAi, kAnthropic, R"([1])", envelope("m")),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("not a JSON object")));
}

TEST_F(TranscodingRequestTest, ConvertToIrPlacesModelAndStream) {
  nlohmann::json body = parseJson(R"({"contents": [{"role": "user", "parts": [{"text": "Hi"}]}]})");
  ASSERT_THAT(toIr(kGemini, body, envelope("gemini-2.5-flash", true)), IsOk());
  EXPECT_EQ(body, parseJson(R"({
    "model": "gemini-2.5-flash",
    "stream": true,
    "messages": [{"role": "user", "content": "Hi"}]
  })"));

  body = parseJson(R"({"model": "gpt-4o", "stream": false,
                       "messages": [{"role": "user", "content": "Hi"}]})");
  ASSERT_THAT(toIr(kOpenAi, body, envelope("gpt-4o-mini")), IsOk());
  EXPECT_EQ(body, parseJson(R"({
    "model": "gpt-4o-mini",
    "stream": false,
    "messages": [{"role": "user", "content": "Hi"}]
  })"));

  body = parseJson(R"({"contents": [{"parts": [{"inlineData": {"data": "AA=="}}]}]})");
  EXPECT_THAT(toIr(kGemini, body, envelope("g")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("content part type inlineData is not supported yet")));

  // A Gemini client streams by its path; a stray body field does not count.
  body = parseJson(R"({"stream": true, "contents": [{"parts": [{"text": "Hi"}]}]})");
  ASSERT_THAT(toIr(kGemini, body, envelope("g")), IsOk());
  EXPECT_EQ(body, parseJson(R"({"model": "g", "messages": [{"role": "user", "content": "Hi"}]})"));
}

// Regression: an Anthropic tool's `cache_control` rode into the OpenAI tool object, and
// `disable_parallel_tool_use` was lost.
TEST_F(TranscodingRequestTest, AnthropicToolsToOpenAi) {
  ASSERT_THAT(convert(kAnthropic, kOpenAi, R"({
    "model": "claude",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "What time is it?"}],
    "tools": [{"name": "now", "description": "Time", "input_schema": {"type": "object"},
               "cache_control": {"type": "ephemeral"}}],
    "tool_choice": {"type": "auto", "disable_parallel_tool_use": true}
  })",
                      envelope("gpt-4o")),
              IsOk());
  expectBody(R"({
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "What time is it?"}],
    "max_completion_tokens": 8,
    "tools": [{"type": "function",
               "function": {"name": "now", "description": "Time",
                            "parameters": {"type": "object"}}}],
    "tool_choice": "auto",
    "parallel_tool_calls": false
  })");
  EXPECT_THAT(report_.dropped, ElementsAre("tools[].cache_control"));

  nlohmann::json body = parseJson(R"({
    "model": "claude", "max_tokens": 8, "messages": [{"role": "user", "content": "Hi"}],
    "tools": [{"name": "now", "input_schema": {"type": "object"}}],
    "tool_choice": {"type": "any", "disable_parallel_tool_use": false}
  })");
  ASSERT_THAT(toIr(kAnthropic, body, envelope("claude")), IsOk());
  EXPECT_EQ(body["tool_choice"], "required");
  EXPECT_FALSE(body.contains("parallel_tool_calls"));
}

// Regression: Gemini's JSON mode was dropped with the rest of `generationConfig`.
TEST_F(TranscodingRequestTest, GeminiJsonModeToOpenAi) {
  const auto request = [](absl::string_view config) {
    return absl::StrCat(R"({"contents": [{"parts": [{"text": "Hi"}]}], )", config, "}");
  };

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "application/json",
                          "responseJsonSchema": {"type": "object",
                                                 "properties": {"a": {"type": "string"}}}})"),
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["response_format"], parseJson(R"({"type": "json_schema", "json_schema": {
    "name": "response",
    "schema": {"type": "object", "properties": {"a": {"type": "string"}}}}})"));
  EXPECT_THAT(report_.dropped, IsEmpty());

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generation_config": {"response_mime_type": "application/json"})"),
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["response_format"], parseJson(R"({"type": "json_object"})"));
  EXPECT_THAT(report_.dropped, IsEmpty());

  // `responseSchema` is an OpenAPI subset, not JSON Schema, so only JSON mode survives it.
  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "application/json",
                          "responseSchema": {"type": "OBJECT"}})"),
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["response_format"], parseJson(R"({"type": "json_object"})"));
  EXPECT_THAT(report_.dropped, ElementsAre("generationConfig.responseSchema"));
  report_.dropped.clear();

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "text/plain"})"),
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("response_format"));
  EXPECT_THAT(report_.dropped, IsEmpty());

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "text/x.enum",
                          "responseJsonSchema": {"enum": ["a"]}})"),
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("response_format"));
  EXPECT_THAT(report_.dropped, ElementsAre("generationConfig.responseJsonSchema",
                                           "generationConfig.responseMimeType"));
  report_.dropped.clear();

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "application/json",
                          "responseJsonSchema": true})"),
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["response_format"], parseJson(R"({"type": "json_object"})"));
  EXPECT_THAT(report_.dropped, ElementsAre("generationConfig.responseJsonSchema"));
  report_.dropped.clear();

  // JSON mode keys on the MIME type, not on the IR's spelling of it.
  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "json_object"})"),
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("response_format"));
  EXPECT_THAT(report_.dropped, ElementsAre("generationConfig.responseMimeType"));
  report_.dropped.clear();

  ASSERT_THAT(convert(kGemini, kOpenAi, request(R"("response_format": {"type": "json_object"},
                          "generationConfig": {"responseJsonSchema": {"type": "object"}})"),
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_["response_format"].contains("json_schema"));
  EXPECT_THAT(report_.dropped, ElementsAre("generationConfig.responseJsonSchema"));
}

// Regression: the engine dropped these silently, so REJECT mode let them through.
TEST_F(TranscodingRequestTest, GeminiConfigTheIrCannotHoldIsReported) {
  options_.unsupported_fields = UnsupportedFieldPolicy::Reject;
  EXPECT_THAT(convert(kGemini, kAnthropic, R"({
    "contents": [{"parts": [{"text": "Hi"}]}],
    "generationConfig": {"maxOutputTokens": 10, "responseLogprobs": null, "topK": 5,
                         "thinkingConfig": {"thinkingBudget": 0}, "speechConfig": {}}
  })",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("ANTHROPIC_MESSAGES cannot express request fields: "
                                  "generationConfig.thinkingConfig, generationConfig.topK")));
}

// Regression: a Gemini client replaying its history sent the model's thoughts to another model
// as answer text.
TEST_F(TranscodingRequestTest, GeminiThoughtsAreDropped) {
  ASSERT_THAT(convert(kGemini, kOpenAi, R"({
    "systemInstruction": {"parts": [{"text": "Be brief."}, {"text": "hmm", "thought": true}]},
    "contents": [
      {"role": "user", "parts": [{"text": "Why is the sky blue?"}]},
      {"role": "model", "parts": [
        {"text": "**Explaining Sky's Hue**", "thought": true},
        {"text": "Rayleigh scattering.", "thoughtSignature": "c2ln"}]},
      {"role": "model", "parts": [{"text": "**Refining**", "thought": true}]},
      {"role": "user", "parts": [{"text": "Thanks"}, {"text": "!", "thought": false}]}
    ]
  })",
                      envelope("gpt-4o")),
              IsOk());
  expectBody(R"({
    "model": "gpt-4o",
    "messages": [
      {"role": "system", "content": "Be brief."},
      {"role": "user", "content": "Why is the sky blue?"},
      {"role": "assistant", "content": "Rayleigh scattering."},
      {"role": "user", "content": [{"type": "text", "text": "Thanks"},
                                   {"type": "text", "text": "!"}]}
    ]
  })");
  EXPECT_THAT(report_.dropped, ElementsAre("systemInstruction.parts[thought=true]",
                                           "contents[].parts[thought=true]"));
}

TEST_F(TranscodingRequestTest, AnthropicThinkingInHistoryIsDropped) {
  ASSERT_THAT(convert(kAnthropic, kGemini, R"({
    "model": "claude-haiku-4-5", "max_tokens": 64,
    "messages": [
      {"role": "user", "content": "Why is the sky blue?"},
      {"role": "assistant", "content": [
        {"type": "thinking", "thinking": "Rayleigh...", "signature": "c2ln"},
        {"type": "redacted_thinking", "data": "b3BhcXVl"},
        {"type": "text", "text": "Rayleigh scattering."}]},
      {"role": "user", "content": "Thanks"}
    ]
  })",
                      envelope("gemini-2.5-flash")),
              IsOk());
  expectBody(R"({
    "contents": [
      {"role": "user", "parts": [{"text": "Why is the sky blue?"}]},
      {"role": "model", "parts": [{"text": "Rayleigh scattering."}]},
      {"role": "user", "parts": [{"text": "Thanks"}]}
    ],
    "generationConfig": {"maxOutputTokens": 64}
  })");
  EXPECT_THAT(report_.dropped, UnorderedElementsAre("messages[].content[type=thinking]",
                                                    "messages[].content[type=redacted_thinking]"));
}

TEST_F(TranscodingRequestTest, GeminiDataPartsAreRejected) {
  EXPECT_THAT(convert(kGemini, kAnthropic, R"({
    "systemInstruction": {"parts": [{"fileData": {"fileUri": "gs://b/o"}}]},
    "contents": [{"parts": [{"text": "Hi"}]}]
  })",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("content part type fileData is not supported yet")));
  EXPECT_THAT(convert(kGemini, kOpenAi,
                      R"({"contents": [{"parts": [{"text": "What is this?"},
                          {"inline_data": {"mime_type": "image/png", "data": "AA=="}}]}]})",
                      envelope("gpt-4o")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("content part type inline_data is not supported yet")));
}

// Regression: an OpenAI upstream streams usage only when asked, so a converted stream reported
// none to Anthropic and Gemini clients.
TEST_F(TranscodingRequestTest, StreamsToOpenAiAskForUsage) {
  ASSERT_THAT(convert(kAnthropic, kOpenAi,
                      R"({"model": "claude", "max_tokens": 8, "stream": true,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("gpt-4o", true)),
              IsOk());
  EXPECT_EQ(body_["stream"], true);
  EXPECT_EQ(body_["stream_options"], parseJson(R"({"include_usage": true})"));

  ASSERT_THAT(convert(kGemini, kOpenAi, R"({"contents": [{"parts": [{"text": "Hi"}]}]})",
                      envelope("gpt-4o", true)),
              IsOk());
  EXPECT_EQ(body_["stream"], true);
  EXPECT_EQ(body_["stream_options"], parseJson(R"({"include_usage": true})"));

  ASSERT_THAT(convert(kAnthropic, kOpenAi,
                      R"({"model": "claude", "max_tokens": 8,
                          "stream_options": {"include_usage": true},
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("stream_options"));
  EXPECT_THAT(report_.dropped, IsEmpty());
}

// Regression: Anthropic's `standard_only` tier and Gemini's `store` reached OpenAI, where they
// are invalid or mean something else.
TEST_F(TranscodingRequestTest, ForeignFieldsDoNotCross) {
  ASSERT_THAT(convert(kAnthropic, kOpenAi,
                      R"({"model": "claude", "max_tokens": 8, "service_tier": "standard_only",
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("service_tier"));
  EXPECT_THAT(report_.dropped, ElementsAre("service_tier"));
  report_.dropped.clear();

  ASSERT_THAT(convert(kAnthropic, kOpenAi,
                      R"({"model": "claude", "max_tokens": 8, "service_tier": "auto",
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["service_tier"], "auto");
  EXPECT_THAT(report_.dropped, IsEmpty());

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      R"({"contents": [{"parts": [{"text": "Hi"}]}], "store": true,
                          "service_tier": "flex"})",
                      envelope("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("store"));
  EXPECT_FALSE(body_.contains("service_tier"));
  EXPECT_THAT(report_.dropped, ElementsAre("store", "service_tier"));
}

// Regression: a tool choice without tools became a Gemini `toolConfig` without function
// declarations, which Vertex rejects.
TEST_F(TranscodingRequestTest, ToolChoiceWithoutToolsIsDropped) {
  ASSERT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "g", "tools": [], "tool_choice": "none",
                          "parallel_tool_calls": true,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("g")),
              IsOk());
  expectBody(R"({"contents": [{"role": "user", "parts": [{"text": "Hi"}]}]})");

  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "tool_choice": "auto",
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("claude")),
              IsOk());
  EXPECT_FALSE(body_.contains("tool_choice"));
  EXPECT_THAT(report_.dropped, IsEmpty());
}

// Thinking blocks are Anthropic's, so only an Anthropic request has them dropped on the way in.
TEST_F(TranscodingRequestTest, ThinkingFromOtherProtocolsIsRejected) {
  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "messages": [
                          {"role": "assistant", "content": [{"type": "thinking", "thinking": "x"},
                                                            {"type": "text", "text": "Hi"}]}]})",
                      envelope("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("content part type thinking is not supported yet")));
}

TEST_F(TranscodingRequestTest, GeminiTurnsWithoutPartsAreRemoved) {
  ASSERT_THAT(convert(kGemini, kOpenAi,
                      R"({"contents": [{"role": "model", "parts": []},
                                       {"role": "user", "parts": [{"text": "Hi"}]}]})",
                      envelope("gpt-4o")),
              IsOk());
  expectBody(R"({"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}]})");
  EXPECT_THAT(report_.dropped, IsEmpty());
}

TEST_F(TranscodingRequestTest, StreamUsageCanBeLeftToTheClient) {
  options_.request_stream_usage = false;
  ASSERT_THAT(convert(kAnthropic, kOpenAi,
                      R"({"model": "claude", "max_tokens": 8, "stream": true,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      envelope("gpt-4o", true)),
              IsOk());
  EXPECT_EQ(body_["stream"], true);
  EXPECT_FALSE(body_.contains("stream_options"));
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
