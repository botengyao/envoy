#include <string>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/transcoding_engine.h"
#include "source/extensions/http/ai_filters/transcoder/request/request_converter.h"

#include "test/test_common/status_utility.h"

#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {
namespace {

using HttpFilters::AiProtocolManager::TranscodingEngine;
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

class RequestConverterTest : public testing::Test {
protected:
  absl::Status convert(LLMProtocol from, LLMProtocol to, absl::string_view body,
                       ClientRequest client) {
    body_ = parseJson(body);
    return convertRequest(engine_, from, to, body_, client, options_, dropped_);
  }

  void expectBody(absl::string_view expected) {
    const nlohmann::json parsed = parseJson(expected);
    EXPECT_EQ(body_, parsed) << "actual:\n" << dump(body_) << "\nexpected:\n" << dump(parsed);
  }

  static ClientRequest client(std::string model, bool stream = false) {
    ClientRequest client;
    client.model = std::move(model);
    client.stream = stream;
    return client;
  }

  const TranscodingEngine engine_ = TranscodingEngine::createDefault().value();
  RequestConversionOptions options_;
  nlohmann::json body_;
  std::vector<std::string> dropped_;
};

TEST_F(RequestConverterTest, OpenAiToAnthropic) {
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
                      client("claude-sonnet-4-5", true)),
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
  EXPECT_THAT(dropped_, IsEmpty());
}

TEST_F(RequestConverterTest, OpenAiToAnthropicPlacesTheClientModel) {
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "alias", "max_tokens": 10,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude-sonnet-4-5@20250929")),
              IsOk());
  expectBody(R"({
    "model": "claude-sonnet-4-5@20250929",
    "max_tokens": 10,
    "messages": [{"role": "user", "content": "Hi"}]
  })");
}

TEST_F(RequestConverterTest, OpenAiToolsToAnthropic) {
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
                      client("claude")),
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
  EXPECT_THAT(dropped_, IsEmpty());
}

TEST_F(RequestConverterTest, ParallelToolCallsToAnthropic) {
  constexpr absl::string_view kTools =
      R"("tools": [{"type": "function", "function": {"name": "now"}}])";
  const std::string prefix = absl::StrCat(
      R"({"model": "claude", "max_tokens": 8, "messages": [{"role": "user", "content": "Hi"}], )",
      kTools);

  // Anthropic defaults to `auto` when it is not named.
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      absl::StrCat(prefix, R"(, "parallel_tool_calls": false})"), client("claude")),
              IsOk());
  EXPECT_EQ(body_["tool_choice"],
            parseJson(R"({"type": "auto", "disable_parallel_tool_use": true})"));

  ASSERT_THAT(
      convert(kOpenAi, kAnthropic,
              absl::StrCat(prefix, R"(, "tool_choice": "none", "parallel_tool_calls": false})"),
              client("claude")),
      IsOk());
  EXPECT_EQ(body_["tool_choice"], parseJson(R"({"type": "none"})"));

  // Parallel calls are already Anthropic's default.
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      absl::StrCat(prefix, R"(, "parallel_tool_calls": true})"), client("claude")),
              IsOk());
  EXPECT_FALSE(body_.contains("tool_choice"));

  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      absl::StrCat(prefix, R"(, "parallel_tool_calls": null})"), client("claude")),
              IsOk());
  EXPECT_FALSE(body_.contains("tool_choice"));

  // Without tools there is nothing to run in parallel.
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "parallel_tool_calls": false,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              IsOk());
  EXPECT_FALSE(body_.contains("tool_choice"));
  EXPECT_FALSE(body_.contains("parallel_tool_calls"));
  EXPECT_THAT(dropped_, IsEmpty());
}

TEST_F(RequestConverterTest, OpenAiOnlyFieldsArePrunedForAnthropic) {
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
                      client("claude")),
              IsOk());
  expectBody(R"({
    "model": "claude",
    "messages": [{"role": "user", "content": "Hi"}, {"role": "assistant", "content": "Hello"},
                 {"role": "user", "content": [{"type": "text", "text": "Bye"}]}],
    "max_tokens": 32
  })");
  EXPECT_THAT(dropped_,
              UnorderedElementsAre("metadata", "service_tier", "seed", "presence_penalty",
                                   "frequency_penalty", "logit_bias", "logprobs", "top_logprobs",
                                   "response_format", "store", "reasoning_effort", "modalities",
                                   "prediction", "audio", "web_search_options", "verbosity",
                                   "prompt_cache_key", "safety_identifier", "some_future_field",
                                   "messages[].name"));
}

TEST_F(RequestConverterTest, AnthropicKeepsItsOwnServiceTier) {
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "service_tier": "auto",
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              IsOk());
  EXPECT_EQ(body_["service_tier"], "auto");
  EXPECT_THAT(dropped_, IsEmpty());
}

TEST_F(RequestConverterTest, OpenAiMetadataIsReplacedByTheUser) {
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "user": "u-1",
                          "metadata": {"purpose": "eval"},
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              IsOk());
  EXPECT_EQ(body_["metadata"], parseJson(R"({"user_id": "u-1"})"));
  EXPECT_THAT(dropped_, ElementsAre("metadata"));
}

TEST_F(RequestConverterTest, RejectModeFailsOnADroppedField) {
  options_.reject_unsupported_fields = true;
  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "seed": 1, "logprobs": true,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("ANTHROPIC_MESSAGES cannot express request fields: logprobs, "
                                  "seed")));
  EXPECT_THAT(dropped_, ElementsAre("logprobs", "seed"));
}

TEST_F(RequestConverterTest, RejectModeAcceptsWhatTheTranscoderHandles) {
  options_.reject_unsupported_fields = true;
  ASSERT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "gemini-2.5-flash", "stream": true, "seed": null,
                          "response_format": null, "service_tier": null, "store": null,
                          "stream_options": {"include_usage": true}, "logit_bias": {},
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("gemini-2.5-flash", true)),
              IsOk());
  expectBody(R"({"contents": [{"role": "user", "parts": [{"text": "Hi"}]}]})");
  EXPECT_THAT(dropped_, IsEmpty());
}

// Regression: an explicit `false`, which some clients send for every flag, counted as a dropped
// request and failed REJECT mode.
TEST_F(RequestConverterTest, RejectModeAcceptsFlagsThatAreOff) {
  options_.reject_unsupported_fields = true;
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "logprobs": false, "store": false,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              IsOk());
  expectBody(R"({"model": "claude", "max_tokens": 8,
                 "messages": [{"role": "user", "content": "Hi"}]})");
  EXPECT_THAT(dropped_, IsEmpty());

  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "logprobs": true,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("fields: logprobs")));
}

TEST_F(RequestConverterTest, MultipleChoicesAreRejected) {
  for (LLMProtocol to : {kAnthropic, kGemini}) {
    EXPECT_THAT(
        convert(kOpenAi, to,
                R"({"model": "m", "n": 2, "messages": [{"role": "user", "content": "Hi"}]})",
                client("m")),
        HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("'n' must be 1")));
    EXPECT_THAT(
        convert(kOpenAi, to,
                R"({"model": "m", "n": "1", "messages": [{"role": "user", "content": "Hi"}]})",
                client("m")),
        HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("'n' must be 1")));
    for (absl::string_view n : {"1", "null"}) {
      ASSERT_THAT(convert(kOpenAi, to,
                          absl::StrCat(R"({"model": "m", "n": )", n,
                                       R"(, "messages": [{"role": "user", "content": "Hi"}]})"),
                          client("m")),
                  IsOk());
      EXPECT_FALSE(body_.contains("n"));
    }
  }
}

TEST_F(RequestConverterTest, DefaultMaxOutputTokens) {
  options_.default_max_output_tokens = 1000;
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              IsOk());
  EXPECT_EQ(body_["max_tokens"], 1000);

  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": null, "max_completion_tokens": null,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              IsOk());
  EXPECT_EQ(body_["max_tokens"], 1000);

  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 50,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              IsOk());
  EXPECT_EQ(body_["max_tokens"], 50);

  // `max_completion_tokens` supersedes the deprecated `max_tokens`.
  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 50, "max_completion_tokens": 70,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              IsOk());
  EXPECT_EQ(body_["max_tokens"], 70);
  EXPECT_FALSE(body_.contains("max_completion_tokens"));
}

TEST_F(RequestConverterTest, AnthropicValidationFailure) {
  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "temperature": 1.5,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid ANTHROPIC_MESSAGES: field 'temperature'")));

  // Only system prompts leave no message to send.
  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "messages": [{"role": "system", "content": "Hi"}]})",
                      client("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid ANTHROPIC_MESSAGES")));
}

TEST_F(RequestConverterTest, MalformedIrReachesValidation) {
  EXPECT_THAT(
      convert(kOpenAi, kAnthropic, R"({"model": "claude", "messages": ["Hi"]})", client("claude")),
      HasStatus(absl::StatusCode::kInvalidArgument,
                HasSubstr("request is not valid ANTHROPIC_MESSAGES: field 'messages[0]'")));
  EXPECT_THAT(
      convert(kOpenAi, kAnthropic, R"({"model": "claude", "messages": "Hi"})", client("claude")),
      HasStatus(absl::StatusCode::kInvalidArgument,
                HasSubstr("request is not valid ANTHROPIC_MESSAGES: field 'messages'")));
  EXPECT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "tools": {"name": "now"},
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid ANTHROPIC_MESSAGES: field 'tools'")));
}

TEST_F(RequestConverterTest, OpenAiToGemini) {
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
                      client("gemini-2.5-flash", true)),
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
  EXPECT_THAT(dropped_, ElementsAre("user"));
}

TEST_F(RequestConverterTest, ResponseFormatToGemini) {
  constexpr absl::string_view kMessages = R"("messages": [{"role": "user", "content": "Hi"}])";
  const auto request = [&](absl::string_view format) {
    return absl::StrCat(R"({"model": "g", )", kMessages, R"(, "response_format": )", format, "}");
  };

  ASSERT_THAT(convert(kOpenAi, kGemini, request(R"({"type": "json_object"})"), client("g")),
              IsOk());
  EXPECT_EQ(body_["generationConfig"], parseJson(R"({"responseMimeType": "application/json"})"));

  ASSERT_THAT(convert(kOpenAi, kGemini,
                      request(R"({"type": "json_schema", "json_schema": {"name": "r"}})"),
                      client("g")),
              IsOk());
  EXPECT_EQ(body_["generationConfig"], parseJson(R"({"responseMimeType": "application/json"})"));

  ASSERT_THAT(convert(kOpenAi, kGemini, request(R"({"type": "text"})"), client("g")), IsOk());
  EXPECT_FALSE(body_.contains("generationConfig"));
  EXPECT_THAT(dropped_, IsEmpty());

  ASSERT_THAT(convert(kOpenAi, kGemini, request(R"({"type": "yaml"})"), client("g")), IsOk());
  EXPECT_FALSE(body_.contains("generationConfig"));
  EXPECT_THAT(dropped_, ElementsAre("response_format"));
}

TEST_F(RequestConverterTest, GeminiReplacesAMalformedGenerationConfig) {
  ASSERT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "g", "generationConfig": "fast", "seed": 3,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("g")),
              IsOk());
  EXPECT_EQ(body_["generationConfig"], parseJson(R"({"seed": 3})"));
}

TEST_F(RequestConverterTest, GeminiKeepsFieldsItDeclares) {
  ASSERT_THAT(convert(kOpenAi, kGemini, R"({
    "model": "g",
    "messages": [{"role": "user", "content": "Hi"}],
    "safety_settings": [{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"}],
    "cachedContent": "cachedContents/1",
    "service_tier": "flex",
    "store": true
  })",
                      client("g")),
              IsOk());
  expectBody(R"({
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "safety_settings": [{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"}],
    "cachedContent": "cachedContents/1"
  })");
  // OpenAI's `service_tier` and `store` mean something else to Gemini.
  EXPECT_THAT(dropped_, ElementsAre("store", "service_tier"));
}

TEST_F(RequestConverterTest, GeminiValidationFailure) {
  EXPECT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "g", "stop": ["1", "2", "3", "4", "5", "6"],
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("g")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid GEMINI_GENERATE_CONTENT")));
}

TEST_F(RequestConverterTest, ToolsAreNotSentToGeminiYet) {
  EXPECT_THAT(convert(kOpenAi, kGemini, R"({
    "model": "g",
    "messages": [{"role": "user", "content": "Hi"}],
    "tools": [{"type": "function", "function": {"name": "now"}}]
  })",
                      client("g")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("tools are not supported for GEMINI_GENERATE_CONTENT yet")));

  ASSERT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "g", "tools": [],
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("g")),
              IsOk());
}

TEST_F(RequestConverterTest, ToolCallTurnsAreRejected) {
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
                        client("m")),
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
                        client("m")),
                HasStatus(absl::StatusCode::kInvalidArgument,
                          HasSubstr("tool call messages are not supported yet: messages[2] has "
                                    "role 'tool'")));
    EXPECT_THAT(convert(kOpenAi, to, R"({
      "model": "m",
      "messages": [
        {"role": "assistant", "content": null, "function_call": {"name": "f", "arguments": "{}"}}
      ]
    })",
                        client("m")),
                HasStatus(absl::StatusCode::kInvalidArgument,
                          HasSubstr("messages[0] has 'function_call'")));
    EXPECT_THAT(convert(kOpenAi, to,
                        R"({"model": "m", "messages": [{"role": "function", "name": "f",
                            "content": "x"}]})",
                        client("m")),
                HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("role 'function'")));
  }
}

TEST_F(RequestConverterTest, NonTextContentIsRejected) {
  for (LLMProtocol to : {kAnthropic, kGemini}) {
    EXPECT_THAT(convert(kOpenAi, to, R"({
      "model": "m",
      "messages": [{"role": "user", "content": [
        {"type": "text", "text": "What is this?"},
        {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}
      ]}]
    })",
                        client("m")),
                HasStatus(absl::StatusCode::kInvalidArgument,
                          HasSubstr("content part type image_url is not supported yet")));
    EXPECT_THAT(convert(kOpenAi, to,
                        R"({"model": "m", "messages": [{"role": "user", "content": [
                            {"text": "untyped"}]}]})",
                        client("m")),
                HasStatus(absl::StatusCode::kInvalidArgument,
                          HasSubstr("content part type (none) is not supported yet")));
  }
}

// Regression: a text part without text reached Anthropic, which rejects it upstream.
TEST_F(RequestConverterTest, TextPartsRequireText) {
  for (LLMProtocol to : {kAnthropic, kGemini}) {
    for (absl::string_view part : {R"({"type": "text"})", R"({"type": "text", "text": null})",
                                   R"({"type": "text", "text": 7})"}) {
      EXPECT_THAT(
          convert(kOpenAi, to,
                  absl::StrCat(R"({"model": "m", "messages": [{"role": "user", "content": [)", part,
                               "]}]}"),
                  client("m")),
          HasStatus(absl::StatusCode::kInvalidArgument,
                    HasSubstr("messages[0] has a text content part without text")));
    }
  }
}

TEST_F(RequestConverterTest, AnthropicToGemini) {
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
                      client("gemini-2.5-flash", true)),
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
  EXPECT_THAT(dropped_, ElementsAre("messages[].content[].cache_control", "top_k", "user"));
}

TEST_F(RequestConverterTest, GeminiToAnthropic) {
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
                      client("claude-sonnet-4-5@20250929", true)),
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
  EXPECT_THAT(dropped_, ElementsAre("generation_config.top_k", "safetySettings"));
}

TEST_F(RequestConverterTest, GeminiCandidateCountToAnthropic) {
  EXPECT_THAT(convert(kGemini, kAnthropic,
                      R"({"contents": [{"parts": [{"text": "Hi"}]}],
                          "generationConfig": {"candidateCount": 2}})",
                      client("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("'n' must be 1")));
}

TEST_F(RequestConverterTest, AnthropicToOpenAi) {
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
                      client("gpt-4o", true)),
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
  EXPECT_THAT(dropped_, ElementsAre("messages[].content[].cache_control", "thinking", "top_k"));
}

TEST_F(RequestConverterTest, AnthropicServerToolsAndBlocksAreRejected) {
  EXPECT_THAT(
      convert(kAnthropic, kOpenAi, R"({
    "model": "claude",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "Search"}],
    "tools": [{"type": "web_search_20250305", "name": "web_search", "max_uses": 1}]
  })",
              client("gpt-4o")),
      HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("tools[0] is not a function tool")));
  EXPECT_THAT(convert(kAnthropic, kOpenAi, R"({
    "model": "claude",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": [
      {"type": "tool_result", "tool_use_id": "t1", "content": "sunny"}]}]
  })",
                      client("gpt-4o")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("content part type tool_result is not supported yet")));
}

TEST_F(RequestConverterTest, GeminiToOpenAi) {
  ASSERT_THAT(convert(kGemini, kOpenAi, R"({
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "generationConfig": {"maxOutputTokens": 32, "candidateCount": 1, "seed": "42",
                         "presencePenalty": 0.1, "frequencyPenalty": "0.2",
                         "thinkingConfig": {"thinkingBudget": 0}},
    "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}},
    "cachedContent": "cachedContents/1"
  })",
                      client("gpt-4o")),
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
  EXPECT_THAT(dropped_,
              ElementsAre("generationConfig.thinkingConfig", "cachedContent", "toolConfig"));
}

TEST_F(RequestConverterTest, GeminiFunctionCallsAreRejected) {
  EXPECT_THAT(convert(kGemini, kOpenAi, R"({
    "contents": [
      {"role": "user", "parts": [{"text": "Weather?"}]},
      {"role": "model", "parts": [{"functionCall": {"name": "get_weather", "args": {}}}]}
    ]
  })",
                      client("gpt-4o")),
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
                      client("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("contents[1].parts[0] has 'function_call'")));
  EXPECT_THAT(
      convert(kGemini, kAnthropic, R"({
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "tools": [{"functionDeclarations": [{"name": "now"}]}]
  })",
              client("claude")),
      HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("tools[0] is not a function tool")));
}

TEST_F(RequestConverterTest, UnsupportedConversions) {
  EXPECT_THAT(convert(kOpenAi, kOpenAi, R"({"model": "m"})", client("m")),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("needs no conversion")));
  EXPECT_THAT(convert(kOpenAi, LLMProtocol::OpenAiResponses, R"({"model": "m"})", client("m")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("cannot convert a request to OPENAI_RESPONSES")));
  EXPECT_THAT(convert(LLMProtocol::Unspecified, kAnthropic, R"({"model": "m"})", client("m")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("cannot convert a LLM_PROTOCOL_UNSPECIFIED request")));
  EXPECT_THAT(convert(kOpenAi, kAnthropic, R"([1])", client("m")),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("not a JSON object")));
}

TEST_F(RequestConverterTest, ConvertToIrPlacesModelAndStream) {
  nlohmann::json body = parseJson(R"({"contents": [{"role": "user", "parts": [{"text": "Hi"}]}]})");
  ASSERT_THAT(convertRequestToIr(engine_, kGemini, body, client("gemini-2.5-flash", true)), IsOk());
  EXPECT_EQ(body, parseJson(R"({
    "model": "gemini-2.5-flash",
    "stream": true,
    "messages": [{"role": "user", "content": "Hi"}]
  })"));

  body = parseJson(R"({"model": "gpt-4o", "stream": false,
                       "messages": [{"role": "user", "content": "Hi"}]})");
  ASSERT_THAT(convertRequestToIr(engine_, kOpenAi, body, client("gpt-4o-mini")), IsOk());
  EXPECT_EQ(body, parseJson(R"({
    "model": "gpt-4o-mini",
    "stream": false,
    "messages": [{"role": "user", "content": "Hi"}]
  })"));

  body = parseJson(R"({"contents": [{"parts": [{"inlineData": {"data": "AA=="}}]}]})");
  EXPECT_THAT(convertRequestToIr(engine_, kGemini, body, client("g")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("content part type inlineData is not supported yet")));

  // A Gemini client streams by its path; a stray body field does not count.
  body = parseJson(R"({"stream": true, "contents": [{"parts": [{"text": "Hi"}]}]})");
  ASSERT_THAT(convertRequestToIr(engine_, kGemini, body, client("g")), IsOk());
  EXPECT_EQ(body, parseJson(R"({"model": "g", "messages": [{"role": "user", "content": "Hi"}]})"));
}

// Regression: an Anthropic tool's `cache_control` rode into the OpenAI tool object, and
// `disable_parallel_tool_use` was lost.
TEST_F(RequestConverterTest, AnthropicToolsToOpenAi) {
  ASSERT_THAT(convert(kAnthropic, kOpenAi, R"({
    "model": "claude",
    "max_tokens": 8,
    "messages": [{"role": "user", "content": "What time is it?"}],
    "tools": [{"name": "now", "description": "Time", "input_schema": {"type": "object"},
               "cache_control": {"type": "ephemeral"}}],
    "tool_choice": {"type": "auto", "disable_parallel_tool_use": true}
  })",
                      client("gpt-4o")),
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
  EXPECT_THAT(dropped_, ElementsAre("tools[].cache_control"));

  nlohmann::json body = parseJson(R"({
    "model": "claude", "max_tokens": 8, "messages": [{"role": "user", "content": "Hi"}],
    "tools": [{"name": "now", "input_schema": {"type": "object"}}],
    "tool_choice": {"type": "any", "disable_parallel_tool_use": false}
  })");
  ASSERT_THAT(convertRequestToIr(engine_, kAnthropic, body, client("claude")), IsOk());
  EXPECT_EQ(body["tool_choice"], "required");
  EXPECT_FALSE(body.contains("parallel_tool_calls"));
}

// Regression: Gemini's JSON mode was dropped with the rest of `generationConfig`.
TEST_F(RequestConverterTest, GeminiJsonModeToOpenAi) {
  const auto request = [](absl::string_view config) {
    return absl::StrCat(R"({"contents": [{"parts": [{"text": "Hi"}]}], )", config, "}");
  };

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "application/json",
                          "responseJsonSchema": {"type": "object",
                                                 "properties": {"a": {"type": "string"}}}})"),
                      client("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["response_format"], parseJson(R"({"type": "json_schema", "json_schema": {
    "name": "response",
    "schema": {"type": "object", "properties": {"a": {"type": "string"}}}}})"));
  EXPECT_THAT(dropped_, IsEmpty());

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generation_config": {"response_mime_type": "application/json"})"),
                      client("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["response_format"], parseJson(R"({"type": "json_object"})"));
  EXPECT_THAT(dropped_, IsEmpty());

  // `responseSchema` is an OpenAPI subset, not JSON Schema, so only JSON mode survives it.
  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "application/json",
                          "responseSchema": {"type": "OBJECT"}})"),
                      client("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["response_format"], parseJson(R"({"type": "json_object"})"));
  EXPECT_THAT(dropped_, ElementsAre("generationConfig.responseSchema"));
  dropped_.clear();

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "text/plain"})"),
                      client("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("response_format"));
  EXPECT_THAT(dropped_, IsEmpty());

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "text/x.enum",
                          "responseJsonSchema": {"enum": ["a"]}})"),
                      client("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("response_format"));
  EXPECT_THAT(dropped_, ElementsAre("generationConfig.responseJsonSchema",
                                    "generationConfig.responseMimeType"));
  dropped_.clear();

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      request(R"("generationConfig": {"responseMimeType": "application/json",
                          "responseJsonSchema": true})"),
                      client("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["response_format"], parseJson(R"({"type": "json_object"})"));
  EXPECT_THAT(dropped_, ElementsAre("generationConfig.responseJsonSchema"));
}

// Regression: the engine drops these silently, so REJECT mode let them through.
TEST_F(RequestConverterTest, GeminiConfigTheIrCannotHoldIsReported) {
  options_.reject_unsupported_fields = true;
  EXPECT_THAT(convert(kGemini, kAnthropic, R"({
    "contents": [{"parts": [{"text": "Hi"}]}],
    "generationConfig": {"maxOutputTokens": 10, "responseLogprobs": null, "topK": 5,
                         "thinkingConfig": {"thinkingBudget": 0}, "speechConfig": {}}
  })",
                      client("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("ANTHROPIC_MESSAGES cannot express request fields: "
                                  "generationConfig.thinkingConfig, generationConfig.topK")));
}

// Regression: a Gemini client replaying its history sent the model's thoughts to another model
// as answer text.
TEST_F(RequestConverterTest, GeminiThoughtsAreDropped) {
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
                      client("gpt-4o")),
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
  EXPECT_THAT(dropped_, ElementsAre("contents[].parts[].thought"));
}

TEST_F(RequestConverterTest, AnthropicThinkingInHistoryIsDropped) {
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
                      client("gemini-2.5-flash")),
              IsOk());
  expectBody(R"({
    "contents": [
      {"role": "user", "parts": [{"text": "Why is the sky blue?"}]},
      {"role": "model", "parts": [{"text": "Rayleigh scattering."}]},
      {"role": "user", "parts": [{"text": "Thanks"}]}
    ],
    "generationConfig": {"maxOutputTokens": 64}
  })");
  EXPECT_THAT(dropped_, UnorderedElementsAre("messages[].content[].thinking",
                                             "messages[].content[].redacted_thinking"));
}

TEST_F(RequestConverterTest, GeminiDataPartsAreRejected) {
  EXPECT_THAT(convert(kGemini, kAnthropic, R"({
    "systemInstruction": {"parts": [{"fileData": {"fileUri": "gs://b/o"}}]},
    "contents": [{"parts": [{"text": "Hi"}]}]
  })",
                      client("claude")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("content part type fileData is not supported yet")));
  EXPECT_THAT(convert(kGemini, kOpenAi,
                      R"({"contents": [{"parts": [{"text": "What is this?"},
                          {"inline_data": {"mime_type": "image/png", "data": "AA=="}}]}]})",
                      client("gpt-4o")),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("content part type inline_data is not supported yet")));
}

// Regression: an OpenAI upstream streams usage only when asked, so a converted stream reported
// none to Anthropic and Gemini clients.
TEST_F(RequestConverterTest, StreamsToOpenAiAskForUsage) {
  ASSERT_THAT(convert(kAnthropic, kOpenAi,
                      R"({"model": "claude", "max_tokens": 8, "stream": true,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("gpt-4o", true)),
              IsOk());
  EXPECT_EQ(body_["stream"], true);
  EXPECT_EQ(body_["stream_options"], parseJson(R"({"include_usage": true})"));

  ASSERT_THAT(convert(kGemini, kOpenAi, R"({"contents": [{"parts": [{"text": "Hi"}]}]})",
                      client("gpt-4o", true)),
              IsOk());
  EXPECT_EQ(body_["stream"], true);
  EXPECT_EQ(body_["stream_options"], parseJson(R"({"include_usage": true})"));

  ASSERT_THAT(convert(kAnthropic, kOpenAi,
                      R"({"model": "claude", "max_tokens": 8,
                          "stream_options": {"include_usage": true},
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("stream_options"));
  EXPECT_THAT(dropped_, IsEmpty());
}

// Regression: Anthropic's `standard_only` tier and Gemini's `store` reached OpenAI, where they
// are invalid or mean something else.
TEST_F(RequestConverterTest, ForeignFieldsDoNotCross) {
  ASSERT_THAT(convert(kAnthropic, kOpenAi,
                      R"({"model": "claude", "max_tokens": 8, "service_tier": "standard_only",
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("service_tier"));
  EXPECT_THAT(dropped_, ElementsAre("service_tier"));
  dropped_.clear();

  ASSERT_THAT(convert(kAnthropic, kOpenAi,
                      R"({"model": "claude", "max_tokens": 8, "service_tier": "auto",
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("gpt-4o")),
              IsOk());
  EXPECT_EQ(body_["service_tier"], "auto");
  EXPECT_THAT(dropped_, IsEmpty());

  ASSERT_THAT(convert(kGemini, kOpenAi,
                      R"({"contents": [{"parts": [{"text": "Hi"}]}], "store": true,
                          "service_tier": "flex"})",
                      client("gpt-4o")),
              IsOk());
  EXPECT_FALSE(body_.contains("store"));
  EXPECT_FALSE(body_.contains("service_tier"));
  EXPECT_THAT(dropped_, ElementsAre("store", "service_tier"));
}

// Regression: a tool choice without tools became a Gemini `toolConfig` without function
// declarations, which Vertex rejects.
TEST_F(RequestConverterTest, ToolChoiceWithoutToolsIsDropped) {
  ASSERT_THAT(convert(kOpenAi, kGemini,
                      R"({"model": "g", "tools": [], "tool_choice": "none",
                          "parallel_tool_calls": true,
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("g")),
              IsOk());
  expectBody(R"({"contents": [{"role": "user", "parts": [{"text": "Hi"}]}]})");

  ASSERT_THAT(convert(kOpenAi, kAnthropic,
                      R"({"model": "claude", "max_tokens": 8, "tool_choice": "auto",
                          "messages": [{"role": "user", "content": "Hi"}]})",
                      client("claude")),
              IsOk());
  EXPECT_FALSE(body_.contains("tool_choice"));
  EXPECT_THAT(dropped_, IsEmpty());
}

} // namespace
} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
