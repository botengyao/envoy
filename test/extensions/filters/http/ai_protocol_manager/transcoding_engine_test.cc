#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"
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

TEST(TranscodingEngineTest, CreateDefaultRegistersCoreDialectPacks) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
}

TEST(TranscodingEngineTest, TranscodingEngineMaps_OpenAiSchema_To_AnthropicSchema) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4-5",
    "max_completion_tokens": 2048,
    "stop": ["STOP_HERE"],
    "messages": [
      {"role": "system", "content": "Be concise."},
      {"role": "user", "content": "Hello!"},
      {"role": "user", "content": "Follow-up question."}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "get_weather",
          "description": "Get weather for city",
          "parameters": {"type": "object"}
        }
      }
    ]
  })");

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());

  // System message extracted to top-level `system`
  EXPECT_EQ(payload["system"], "Be concise.");
  // Consecutive `user` messages merged into one `user` message with 2 text blocks
  ASSERT_EQ(payload["messages"].size(), 1);
  EXPECT_EQ(payload["messages"][0]["role"], "user");
  ASSERT_TRUE(payload["messages"][0]["content"].is_array());
  EXPECT_EQ(payload["messages"][0]["content"].size(), 2);
  EXPECT_EQ(payload["messages"][0]["content"][0]["text"], "Hello!");
  EXPECT_EQ(payload["messages"][0]["content"][1]["text"], "Follow-up question.");

  // Token cap and stop sequences mapped
  EXPECT_EQ(payload["max_tokens"], 2048);
  EXPECT_FALSE(payload.contains("max_completion_tokens"));
  EXPECT_EQ(payload["stop_sequences"], nlohmann::json::array({"STOP_HERE"}));

  // Tools mapped to Anthropic shape
  ASSERT_EQ(payload["tools"].size(), 1);
  EXPECT_EQ(payload["tools"][0]["name"], "get_weather");
  EXPECT_EQ(payload["tools"][0]["description"], "Get weather for city");
  EXPECT_EQ(payload["tools"][0]["input_schema"], nlohmann::json::parse(R"({"type": "object"})"));

  // Validate the transcoded payload against Anthropic's RequestSchema!
  const PayloadSchema* anthropic_schema =
      AdapterRegistry::get(LLMProtocol::AnthropicMessages).schema();
  ASSERT_NE(anthropic_schema, nullptr);
  EXPECT_THAT(anthropic_schema->validateRequest(payload), IsOk());
}

TEST(TranscodingEngineTest, TranscodingEngineMaps_OpenAiSchema_To_GeminiSchema) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gemini-2.5-pro",
    "stream": true,
    "temperature": 0.5,
    "max_completion_tokens": 1024,
    "messages": [
      {"role": "system", "content": "You are helpful."},
      {"role": "user", "content": "placeholder"},
      {"role": "assistant", "content": "Prior reply."}
    ]
  })");

  // Replace the user message content with an offloaded 50 KB ExternalRef binary node.
  const JsonWithExtBuf::ExternalRef expected_ref{/*offset=*/128, /*length=*/50000};
  payload["messages"][1]["content"] = JsonWithExtBuf::makeExternalRef(expected_ref);

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());

  // Gemini carries `model` and `stream` in the request path, not the body.
  EXPECT_FALSE(payload.contains("model"));
  EXPECT_FALSE(payload.contains("stream"));

  // `systemInstruction` created with `parts`
  EXPECT_EQ(payload["systemInstruction"]["parts"][0]["text"], "You are helpful.");

  // `contents` holds the 2 non-system messages, role `"assistant"` mapped to `"model"`
  ASSERT_EQ(payload["contents"].size(), 2);
  EXPECT_EQ(payload["contents"][0]["role"], "user");
  EXPECT_EQ(payload["contents"][1]["role"], "model");
  EXPECT_EQ(payload["contents"][1]["parts"][0]["text"], "Prior reply.");

  // Verify the 50 KB ExternalRef node was moved in O(1) without materializing or losing offset!
  const nlohmann::json& moved_part_text = payload["contents"][0]["parts"][0]["text"];
  ASSERT_TRUE(JsonWithExtBuf::isExternalRef(moved_part_text));
  auto actual_ref = JsonWithExtBuf::externalRef(moved_part_text);
  ASSERT_THAT(actual_ref.status(), IsOk());
  EXPECT_EQ(*actual_ref, expected_ref);

  // Generation parameters nested in `generationConfig`
  EXPECT_EQ(payload["generationConfig"]["maxOutputTokens"], 1024);
  EXPECT_EQ(payload["generationConfig"]["temperature"], 0.5);

  // Validate against Gemini's RequestSchema!
  const PayloadSchema* gemini_schema =
      AdapterRegistry::get(LLMProtocol::GeminiGenerateContent).schema();
  ASSERT_NE(gemini_schema, nullptr);
  EXPECT_THAT(gemini_schema->validateRequest(payload), IsOk());
}

TEST(TranscodingEngineTest, VerifierRejectsValueMapOnOffloadableField) {
  const PayloadSchema* openai_schema =
      AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).schema();
  ASSERT_NE(openai_schema, nullptr);

  // `messages[].content` is declared `.offloadable()` in OpenAI's schema, so a `ValueMap`
  // attempting to read it as an inline string must be rejected at config load time.
  TranscodeRuleSet bad_rules(
      LLMProtocol::OpenAiChatCompletions, LLMProtocol::AnthropicMessages,
      {
          TranscodeRule::forEach("messages",
                                 {
                                     TranscodeRule::valueMap("content", {{"foo", "bar"}}),
                                 }),
      });

  absl::Status status = TranscodingEngine::validateRulesAgainstSchema(bad_rules, openai_schema);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

TEST(TranscodingEngineTest, TranscodingEngineMaps_OpenAiSchema_PassthroughIr) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gpt-4o",
    "stream": true,
    "temperature": 0.8,
    "max_completion_tokens": 1024,
    "messages": [
      {"role": "system", "content": "You are a helpful assistant."},
      {"role": "user", "content": "placeholder"}
    ],
    "tools": [
      {
        "type": "function",
        "function": {
          "name": "search",
          "description": "Search docs",
          "parameters": {"type": "object"}
        }
      }
    ]
  })");

  // Attach an offloaded ExternalRef binary node to verify it is untouched during passthrough.
  const JsonWithExtBuf::ExternalRef expected_ref{/*offset=*/64, /*length=*/32768};
  payload["messages"][1]["content"] = JsonWithExtBuf::makeExternalRef(expected_ref);
  const nlohmann::json original_snapshot = payload;

  // Step 1: To IR (OpenAI -> IR)
  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::OpenAiChatCompletions, payload), IsOk());
  EXPECT_EQ(payload, original_snapshot);

  // Step 2: From IR (IR -> OpenAI). A stream asks the upstream to report usage.
  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::OpenAiChatCompletions, payload), IsOk());
  nlohmann::json expected = original_snapshot;
  expected["stream_options"] = {{"include_usage", true}};
  EXPECT_EQ(payload, expected);

  // Validate against OpenAI Chat Completions RequestSchema
  const PayloadSchema* openai_schema =
      AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).schema();
  ASSERT_NE(openai_schema, nullptr);
  EXPECT_THAT(openai_schema->validateRequest(payload), IsOk());
}

TEST(TranscodingEngineTest, TranscodingEngineMaps_AnthropicSchema_RoundTripViaIr) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json anthropic_payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4-5",
    "system": "You are a helpful coding assistant.",
    "max_tokens": 1500,
    "stop_sequences": ["END"],
    "messages": [
      {"role": "user", "content": "Write a unit test."}
    ],
    "tools": [
      {
        "name": "run_bazel_test",
        "description": "Runs a bazel test target",
        "input_schema": {"type": "object"}
      }
    ]
  })");

  // 1. To IR (`to_ir`): Anthropic -> OpenAI Chat Completions
  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::AnthropicMessages, anthropic_payload), IsOk());
  EXPECT_FALSE(anthropic_payload.contains("system"));
  ASSERT_EQ(anthropic_payload["messages"].size(), 2);
  EXPECT_EQ(anthropic_payload["messages"][0]["role"], "system");
  EXPECT_EQ(anthropic_payload["messages"][0]["content"], "You are a helpful coding assistant.");
  EXPECT_EQ(anthropic_payload["max_completion_tokens"], 1500);
  EXPECT_EQ(anthropic_payload["stop"], nlohmann::json::array({"END"}));

  const PayloadSchema* openai_schema =
      AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).schema();
  ASSERT_NE(openai_schema, nullptr);
  EXPECT_THAT(openai_schema->validateRequest(anthropic_payload), IsOk());

  // 2. From IR (`from_ir`): OpenAI Chat Completions -> Anthropic Messages
  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::AnthropicMessages, anthropic_payload), IsOk());

  EXPECT_EQ(anthropic_payload["system"], "You are a helpful coding assistant.");
  EXPECT_EQ(anthropic_payload["max_tokens"], 1500);
  EXPECT_EQ(anthropic_payload["stop_sequences"], nlohmann::json::array({"END"}));
  ASSERT_EQ(anthropic_payload["messages"].size(), 1);
  EXPECT_EQ(anthropic_payload["messages"][0]["role"], "user");
  EXPECT_EQ(anthropic_payload["messages"][0]["content"], "Write a unit test.");

  const PayloadSchema* anthropic_schema =
      AdapterRegistry::get(LLMProtocol::AnthropicMessages).schema();
  ASSERT_NE(anthropic_schema, nullptr);
  EXPECT_THAT(anthropic_schema->validateRequest(anthropic_payload), IsOk());
}

TEST(TranscodingEngineTest, TranscodingEngineMaps_AnthropicSchema_To_OpenAiSchema) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gpt-4o",
    "system": "Answer in one sentence.",
    "max_tokens": 256,
    "stop_sequences": ["DONE"],
    "messages": [
      {"role": "user", "content": "What is C++?"}
    ],
    "tools": [
      {
        "name": "lookup_doc",
        "description": "Looks up C++ reference",
        "input_schema": {"type": "object"}
      }
    ]
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::AnthropicMessages, payload), IsOk());

  EXPECT_FALSE(payload.contains("system"));
  EXPECT_EQ(payload["max_completion_tokens"], 256);
  EXPECT_EQ(payload["stop"], nlohmann::json::array({"DONE"}));
  ASSERT_EQ(payload["messages"].size(), 2);
  EXPECT_EQ(payload["messages"][0]["role"], "system");
  EXPECT_EQ(payload["messages"][0]["content"], "Answer in one sentence.");
  EXPECT_EQ(payload["messages"][1]["role"], "user");
  EXPECT_EQ(payload["messages"][1]["content"], "What is C++?");
  ASSERT_EQ(payload["tools"].size(), 1);
  EXPECT_EQ(payload["tools"][0]["type"], "function");
  EXPECT_EQ(payload["tools"][0]["function"]["name"], "lookup_doc");
}

TEST(TranscodingEngineTest, TranscodingEngineMaps_GeminiSchema_To_OpenAiSchema) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gpt-4o",
    "systemInstruction": {
      "parts": [{"text": "You are an expert engineer."}]
    },
    "contents": [
      {"role": "user", "parts": [{"text": "Hello"}]},
      {"role": "model", "parts": [{"text": "Welcome!"}]}
    ],
    "generationConfig": {
      "maxOutputTokens": 400,
      "temperature": 0.6,
      "topP": 0.9,
      "stopSequences": ["STOP"]
    }
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());

  EXPECT_FALSE(payload.contains("systemInstruction"));
  EXPECT_FALSE(payload.contains("contents"));
  EXPECT_FALSE(payload.contains("generationConfig"));
  EXPECT_EQ(payload["max_completion_tokens"], 400);
  EXPECT_EQ(payload["temperature"], 0.6);
  EXPECT_EQ(payload["top_p"], 0.9);
  EXPECT_EQ(payload["stop"], nlohmann::json::array({"STOP"}));
  ASSERT_EQ(payload["messages"].size(), 3);
  EXPECT_EQ(payload["messages"][0]["role"], "system");
  EXPECT_EQ(payload["messages"][0]["content"], "You are an expert engineer.");
  EXPECT_EQ(payload["messages"][1]["role"], "user");
  EXPECT_EQ(payload["messages"][1]["content"], "Hello");
  EXPECT_EQ(payload["messages"][2]["role"], "assistant");
  EXPECT_EQ(payload["messages"][2]["content"], "Welcome!");
}

TEST(TranscodingEngineTest, TranscodingEngineMaps_GeminiSchema_RoundTripViaIr) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gemini-2.5-pro",
    "systemInstruction": {
      "parts": [{"text": "Keep answers brief."}]
    },
    "contents": [
      {"role": "user", "parts": [{"text": "Ping"}]},
      {"role": "model", "parts": [{"text": "Pong"}]}
    ],
    "generationConfig": {
      "maxOutputTokens": 128,
      "temperature": 0.3
    }
  })");

  // 1. To IR (`to_ir`): Gemini -> OpenAI Chat Completions
  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());

  // 2. From IR (`from_ir`): OpenAI Chat Completions -> Gemini
  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());

  EXPECT_EQ(payload["systemInstruction"]["parts"][0]["text"], "Keep answers brief.");
  EXPECT_EQ(payload["generationConfig"]["maxOutputTokens"], 128);
  EXPECT_EQ(payload["generationConfig"]["temperature"], 0.3);
  ASSERT_EQ(payload["contents"].size(), 2);
  EXPECT_EQ(payload["contents"][0]["role"], "user");
  EXPECT_EQ(payload["contents"][0]["parts"][0]["text"], "Ping");
  EXPECT_EQ(payload["contents"][1]["role"], "model");
  EXPECT_EQ(payload["contents"][1]["parts"][0]["text"], "Pong");
}

TEST(TranscodingEngineTest, CustomInboundAndOutboundConfiguration) {
  TranscodingEngine engine;

  DialectTranscodePack custom_pack{
      /*protocol=*/LLMProtocol::OpenAiResponses,
      /*to_IR=*/
      TranscodeRuleSet(
          LLMProtocol::OpenAiResponses, TranscodingEngine::kIrProtocol,
          {
              TranscodeRule::move("input", "messages"),
              TranscodeRule::forEach("messages",
                                     {
                                         TranscodeRule::valueMap("role", {{"bot", "assistant"}}),
                                     }),
              TranscodeRule::move("max_output_tokens", "max_completion_tokens"),
          }),
      /*from_IR=*/
      TranscodeRuleSet(
          TranscodingEngine::kIrProtocol, LLMProtocol::OpenAiResponses,
          {
              TranscodeRule::forEach("messages",
                                     {
                                         TranscodeRule::valueMap("role", {{"assistant", "bot"}}),
                                     }),
              TranscodeRule::move("messages", "input"),
              TranscodeRule::firstOf({"max_completion_tokens", "max_tokens"}, "max_output_tokens"),
              TranscodeRule::setDefault("max_output_tokens", 1024),
          }),
  };

  ASSERT_THAT(engine.registerPack(std::move(custom_pack)), IsOk());

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "custom-model-v1",
    "max_output_tokens": 300,
    "input": [
      {"role": "user", "content": "Hi"},
      {"role": "bot", "content": "Hello there"}
    ]
  })");

  // Test custom `to_ir` configuration
  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::OpenAiResponses, payload), IsOk());
  EXPECT_EQ(payload["max_completion_tokens"], 300);
  ASSERT_EQ(payload["messages"].size(), 2);
  EXPECT_EQ(payload["messages"][1]["role"], "assistant");

  // Test custom `from_ir` configuration
  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::OpenAiResponses, payload), IsOk());
  EXPECT_EQ(payload["max_output_tokens"], 300);
  ASSERT_EQ(payload["input"].size(), 2);
  EXPECT_EQ(payload["input"][1]["role"], "bot");
}

TEST(TranscodingEngineTest, RejectsPayloadFailingTargetSchemaValidation) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  // Case 1: An OpenAI request that ONLY contains a `system` message. When transcoded to
  // Anthropic, the `system` message is extracted to top-level `"system"`, leaving `messages: []`
  // empty — which violates Anthropic's `messages` `.min(1).required()` schema rule!
  nlohmann::json system_only_payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4-5",
    "messages": [
      {"role": "system", "content": "Only a system prompt, no user message."}
    ]
  })");

  absl::Status status = engine.transcodeFromIr(LLMProtocol::AnthropicMessages, system_only_payload);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);

  // Case 2: An OpenAI request with an invalid field type (`"max_completion_tokens": -10`) that
  // violates the target schema's `.min(0)` constraint.
  nlohmann::json negative_tokens_payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4-5",
    "max_completion_tokens": -10,
    "messages": [
      {"role": "user", "content": "Hello"}
    ]
  })");

  absl::Status status2 =
      engine.transcodeFromIr(LLMProtocol::AnthropicMessages, negative_tokens_payload);
  EXPECT_FALSE(status2.ok());
  EXPECT_EQ(status2.code(), absl::StatusCode::kInvalidArgument);
}

TEST(TranscodingEngineTest, RejectsUnmappedValueWhenUnknownPolicyIsReject) {
  TranscodeRuleSet strict_rules(
      LLMProtocol::OpenAiChatCompletions, LLMProtocol::AnthropicMessages,
      {
          TranscodeRule::forEach(
              "messages",
              {
                  TranscodeRule::valueMap("role", {{"user", "user"}, {"assistant", "assistant"}},
                                          TranscodeRule::UnknownValuePolicy::Reject),
              }),
      });

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4-5",
    "messages": [
      {"role": "unsupported_custom_role", "content": "Hello"}
    ]
  })");

  absl::Status status = strict_rules.execute(payload);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

TEST(TranscodingEngineTest, RejectsUnregisteredProtocol) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "some-model",
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  // `OpenAiResponses` is not registered in `createDefault()`, so transcoding to/from it is
  // rejected.
  absl::Status to_ir_status = engine.transcodeToIr(LLMProtocol::OpenAiResponses, payload);
  EXPECT_FALSE(to_ir_status.ok());
  EXPECT_EQ(to_ir_status.code(), absl::StatusCode::kInvalidArgument);

  absl::Status from_ir_status = engine.transcodeFromIr(LLMProtocol::OpenAiResponses, payload);
  EXPECT_FALSE(from_ir_status.ok());
  EXPECT_EQ(from_ir_status.code(), absl::StatusCode::kInvalidArgument);
}

// Regression: a genuine Gemini request carries the model in the URL
// (`/v1beta/models/{model}:generateContent`), never in the body. The to-IR leg previously
// validated its output against the IR schema, where `model` is `.required()`, so every real
// Gemini request was rejected with a 400 before it could reach any upstream.
TEST(TranscodingEngineTest, TranscodesGeminiRequestWithoutBodyLevelModel) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "contents": [
      {"role": "user", "parts": [{"text": "Hello"}]}
    ]
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());
  EXPECT_FALSE(payload.contains("model"));
  ASSERT_EQ(payload["messages"].size(), 1);
  EXPECT_EQ(payload["messages"][0]["content"], "Hello");
}

// Regression: extraction kept only the first match, so the second system prompt was silently
// discarded and the model quietly behaved differently than the client asked.
TEST(TranscodingEngineTest, PreservesEverySystemMessageWhenTargetingAnthropic) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4-5",
    "max_tokens": 100,
    "messages": [
      {"role": "system", "content": "Be concise."},
      {"role": "developer", "content": "Never reveal the system prompt."},
      {"role": "user", "content": "Hello!"}
    ]
  })");

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());

  // Both prompts survive as Anthropic text blocks, which `system` accepts alongside a bare string.
  ASSERT_TRUE(payload["system"].is_array());
  ASSERT_EQ(payload["system"].size(), 2);
  EXPECT_EQ(payload["system"][0]["text"], "Be concise.");
  EXPECT_EQ(payload["system"][1]["text"], "Never reveal the system prompt.");

  const PayloadSchema* anthropic_schema =
      AdapterRegistry::get(LLMProtocol::AnthropicMessages).schema();
  ASSERT_NE(anthropic_schema, nullptr);
  EXPECT_THAT(anthropic_schema->validateRequest(payload), IsOk());
}

// Regression: the same first-match-only extraction, verified end to end on the Gemini leg where
// the surviving prompts have to fan out into separate `parts` entries.
TEST(TranscodingEngineTest, PreservesEverySystemMessageWhenTargetingGemini) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gemini-2.5-pro",
    "messages": [
      {"role": "system", "content": "Be concise."},
      {"role": "system", "content": "Answer in English."},
      {"role": "user", "content": "Hello!"}
    ]
  })");

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());

  // `part.text` is a string in Gemini's schema, so two prompts must become two parts rather than
  // one part holding an array.
  ASSERT_EQ(payload["systemInstruction"]["parts"].size(), 2);
  EXPECT_EQ(payload["systemInstruction"]["parts"][0]["text"], "Be concise.");
  EXPECT_EQ(payload["systemInstruction"]["parts"][1]["text"], "Answer in English.");

  const PayloadSchema* gemini_schema =
      AdapterRegistry::get(LLMProtocol::GeminiGenerateContent).schema();
  ASSERT_NE(gemini_schema, nullptr);
  EXPECT_THAT(gemini_schema->validateRequest(payload), IsOk());
}

// Regression: unwrapping read only `parts[0]`, so every part after the first was deleted. A
// two-sentence message silently lost its second half.
TEST(TranscodingEngineTest, PreservesEveryGeminiMessagePart) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "contents": [
      {"role": "user", "parts": [{"text": "First half."}, {"text": "Second half."}]}
    ]
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());

  ASSERT_EQ(payload["messages"].size(), 1);
  ASSERT_TRUE(payload["messages"][0]["content"].is_array());
  ASSERT_EQ(payload["messages"][0]["content"].size(), 2);
  EXPECT_EQ(payload["messages"][0]["content"][0]["text"], "First half.");
  EXPECT_EQ(payload["messages"][0]["content"][1]["text"], "Second half.");
}

// Regression: an image part has no `text` field, so the old code produced a message with no
// content at all and still passed validation, because OpenAI's `content` is not `.required()`.
// Silently stripping a user's attached image is worse than refusing the request.
TEST(TranscodingEngineTest, RejectsGeminiPartThatCarriesNoText) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "contents": [
      {
        "role": "user",
        "parts": [
          {"text": "What is in this picture?"},
          {"inlineData": {"mimeType": "image/png", "data": "aW1hZ2UtYnl0ZXM="}}
        ]
      }
    ]
  })");

  absl::Status status = engine.transcodeToIr(LLMProtocol::GeminiGenerateContent, payload);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

// Regression: merging used `operator[]`, which inserts a null member for a missing key in
// nlohmann::json. An assistant message with no `content` (a pure tool call) produced a fabricated
// `{"type": "text", "text": null}` block that the upstream would reject.
TEST(TranscodingEngineTest, MergeDoesNotFabricateContentForMessageWithoutContent) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4-5",
    "max_tokens": 100,
    "messages": [
      {"role": "user", "content": "Call the tool."},
      {"role": "user"}
    ]
  })");

  // The content-less message is left alone rather than merged, so no `null` text block is
  // invented. Anthropic's schema then rejects it on its own terms (`content` is `.required()`).
  absl::Status status = engine.transcodeFromIr(LLMProtocol::AnthropicMessages, payload);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);

  ASSERT_EQ(payload["messages"].size(), 2);
  EXPECT_EQ(payload["messages"][0]["content"], "Call the tool.");
  EXPECT_FALSE(payload["messages"][1].contains("content"));
}

// Verify that `transcodeFromIr` validates against the target dialect schema even when the target
// protocol is the IR protocol itself (`OpenAiChatCompletions`).
TEST(TranscodingEngineTest, TranscodeFromIrValidatesAgainstIrTargetSchema) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  // `temperature` is range-constrained in the OpenAI Chat Completions schema.
  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gpt-4o",
    "temperature": 99,
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  absl::Status status = engine.transcodeFromIr(LLMProtocol::OpenAiChatCompletions, payload);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

// Regression: OpenAI allows `stop` to be a bare string, but both `stop_sequences` and
// `stopSequences` are array-only, so moving the scalar straight across produced a payload the
// destination schema rejects.
TEST(TranscodingEngineTest, NormalizesScalarStopToArrayForAnthropic) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4",
    "stop": "END",
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_FALSE(payload.contains("stop"));
  EXPECT_EQ(payload["stop_sequences"], nlohmann::json::array({"END"}));
}

TEST(TranscodingEngineTest, NormalizesScalarStopToArrayForGemini) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gemini-2.5-pro",
    "stop": "END",
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());
  EXPECT_FALSE(payload.contains("stop"));
  EXPECT_EQ(payload["generationConfig"]["stopSequences"], nlohmann::json::array({"END"}));
}

TEST(TranscodingEngineTest, LeavesAnExistingStopArrayAlone) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4",
    "stop": ["END", "STOP"],
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload["stop_sequences"], nlohmann::json::array({"END", "STOP"}));
}

TEST(TranscodingEngineTest, DoesNotMaterializeStopSequencesWhenStopIsAbsent) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4",
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_FALSE(payload.contains("stop"));
  EXPECT_FALSE(payload.contains("stop_sequences"));
}

// Regression: `tool_choice` was mapped in neither direction. OpenAI spells the unconstrained
// cases as a bare string and Anthropic always uses an object, so every request that set the
// field was rejected by Anthropic's schema on the way out.
TEST(TranscodingEngineTest, MapsStringToolChoiceToAnthropicObject) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4",
    "tool_choice": "required",
    "tools": [{"type": "function", "function": {"name": "lookup_doc"}}],
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload["tool_choice"], nlohmann::json::parse(R"({"type": "any"})"));
}

TEST(TranscodingEngineTest, MapsPinnedToolChoiceToAnthropicObject) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4",
    "tool_choice": {"type": "function", "function": {"name": "lookup_doc"}},
    "tools": [{"type": "function", "function": {"name": "lookup_doc"}}],
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload["tool_choice"],
            nlohmann::json::parse(R"({"type": "tool", "name": "lookup_doc"})"));
}

TEST(TranscodingEngineTest, MapsAnthropicToolChoiceBackToAnIrString) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gpt-4o",
    "tool_choice": {"type": "auto"},
    "max_tokens": 16,
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload["tool_choice"], "auto");
}

TEST(TranscodingEngineTest, MapsAnthropicPinnedToolChoiceBackToAnIrObject) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gpt-4o",
    "tool_choice": {"type": "tool", "name": "lookup_doc"},
    "max_tokens": 16,
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload["tool_choice"],
            nlohmann::json::parse(R"({"type": "function", "function": {"name": "lookup_doc"}})"));
}

// Tools cannot be sent to Gemini yet, and a tool choice without tools asks for nothing, so no
// `toolConfig` is produced.
TEST(TranscodingEngineTest, DiscardsToolChoiceWithoutToolsForGemini) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  for (absl::string_view choice :
       {R"("none")", R"({"type": "function", "function": {"name": "lookup_doc"}})"}) {
    nlohmann::json payload = nlohmann::json::parse(absl::StrCat(
        R"({"model": "gemini-2.5-pro", "messages": [{"role": "user", "content": "Hi"}],
            "tool_choice": )",
        choice, "}"));
    ASSERT_THAT(engine.transcodeFromIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());
    EXPECT_FALSE(payload.contains("tool_choice"));
    EXPECT_FALSE(payload.contains("toolConfig"));
  }
}

// Regression: Gemini renders proto numbers through ProtoJSON, so these fields can arrive quoted.
// `firstOf` preserves the JSON type, so the string landed in an IR field declared numeric.
TEST(TranscodingEngineTest, CoercesQuotedGeminiNumbersWhenEnteringTheIr) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gpt-4o",
    "contents": [{"role": "user", "parts": [{"text": "Hello"}]}],
    "generationConfig": {
      "maxOutputTokens": "256",
      "temperature": "0.5",
      "topP": "0.9"
    }
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());
  EXPECT_TRUE(payload["max_completion_tokens"].is_number_integer());
  EXPECT_EQ(payload["max_completion_tokens"], 256);
  EXPECT_TRUE(payload["temperature"].is_number());
  EXPECT_EQ(payload["temperature"], 0.5);
  EXPECT_TRUE(payload["top_p"].is_number());
  EXPECT_EQ(payload["top_p"], 0.9);

  // Also verify that the coerced IR payload passes the OpenAI Chat Completions schema validation.
  const PayloadSchema* openai_schema =
      AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).schema();
  ASSERT_NE(openai_schema, nullptr);
  EXPECT_THAT(openai_schema->validateRequest(payload), IsOk());
}

TEST(TranscodingEngineTest, LeavesRealGeminiNumbersUntouched) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "contents": [{"role": "user", "parts": [{"text": "Hello"}]}],
    "generationConfig": {"maxOutputTokens": 256, "temperature": 0.5}
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());
  EXPECT_EQ(payload["max_completion_tokens"], 256);
  EXPECT_EQ(payload["temperature"], 0.5);
}

// Regression: Gemini leaves `role` optional (Vertex defaults it to `user`) while both other
// dialects require it, so a valid Gemini request failed the destination's role check.
TEST(TranscodingEngineTest, AppliesGeminiRoleDefaultForMessagesThatOmitIt) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "model": "gpt-4o",
    "contents": [{"parts": [{"text": "Hello"}]}]
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());
  ASSERT_EQ(payload["messages"].size(), 1);
  EXPECT_EQ(payload["messages"][0]["role"], "user");
  EXPECT_EQ(payload["messages"][0]["content"], "Hello");

  const PayloadSchema* openai_schema =
      AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).schema();
  ASSERT_NE(openai_schema, nullptr);
  EXPECT_THAT(openai_schema->validateRequest(payload), IsOk());
}

TEST(TranscodingEngineTest, DoesNotOverrideAnExplicitGeminiRole) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& engine = *engine_or;

  nlohmann::json payload = nlohmann::json::parse(R"({
    "contents": [
      {"role": "user", "parts": [{"text": "Hi"}]},
      {"role": "model", "parts": [{"text": "Hello"}]}
    ]
  })");

  ASSERT_THAT(engine.transcodeToIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());
  ASSERT_EQ(payload["messages"].size(), 2);
  EXPECT_EQ(payload["messages"][0]["role"], "user");
  EXPECT_EQ(payload["messages"][1]["role"], "assistant");
}

// Regression: `registerPack` unconditionally overwrote the pack's schema pointers with its
// arguments, so a pack that arrived with its schemas already set was silently cleared and the
// from-IR validation it expected never ran.
TEST(TranscodingEngineTest, RegisterPackKeepsSchemasAlreadySetOnThePack) {
  TranscodingEngine engine;
  const PayloadSchema* anthropic_schema =
      AdapterRegistry::get(LLMProtocol::AnthropicMessages).schema();
  ASSERT_NE(anthropic_schema, nullptr);

  DialectTranscodePack pack{
      /*protocol=*/LLMProtocol::AnthropicMessages,
      /*to_IR=*/
      TranscodeRuleSet(LLMProtocol::AnthropicMessages, TranscodingEngine::kIrProtocol, {}),
      /*from_IR=*/
      TranscodeRuleSet(TranscodingEngine::kIrProtocol, LLMProtocol::AnthropicMessages, {}),
      /*dialect_schema=*/anthropic_schema,
      /*IR_schema=*/nullptr,
  };

  // No schemas are passed as arguments, so the pack's own `dialect_schema` must survive.
  ASSERT_THAT(engine.registerPack(std::move(pack)), IsOk());

  // `model` is `.required()` in Anthropic's schema. If the pack's schema had been cleared, this
  // payload would transcode without complaint.
  nlohmann::json payload = nlohmann::json::parse(R"({
    "max_tokens": 10,
    "messages": [{"role": "user", "content": "Hi"}]
  })");

  absl::Status status = engine.transcodeFromIr(LLMProtocol::AnthropicMessages, payload);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
}

// Regression: the startup verifier previously checked `ValueMap` target paths against the
// original schema without tracking earlier structural rules. Moving `messages` to `turns` before
// running `ValueMap` on `turns[].content` bypassed the startup check even though
// `messages[].content` is offloadable.
TEST(TranscodingEngineTest, VerifierTracksOffloadableFieldProvenanceAcrossMoveAndUnwrap) {
  const PayloadSchema* openai_schema =
      AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).schema();
  ASSERT_NE(openai_schema, nullptr);

  TranscodeRuleSet moved_array_plan(
      LLMProtocol::OpenAiChatCompletions, TranscodingEngine::kIrProtocol,
      {
          TranscodeRule::move("messages", "turns"),
          TranscodeRule::forEach("turns",
                                 {
                                     TranscodeRule::valueMap("content", {{"foo", "bar"}}),
                                 }),
      });

  absl::Status moved_status =
      TranscodingEngine::validateRulesAgainstSchema(moved_array_plan, openai_schema);
  EXPECT_FALSE(moved_status.ok());
  EXPECT_EQ(moved_status.code(), absl::StatusCode::kInvalidArgument);

  const PayloadSchema* gemini_schema =
      AdapterRegistry::get(LLMProtocol::GeminiGenerateContent).schema();
  ASSERT_NE(gemini_schema, nullptr);

  TranscodeRuleSet unwrapped_part_plan(
      LLMProtocol::GeminiGenerateContent, TranscodingEngine::kIrProtocol,
      {
          TranscodeRule::move("contents", "messages"),
          TranscodeRule::forEach("messages",
                                 {
                                     TranscodeRule::unwrapArrayObject("parts", "text", "content"),
                                     TranscodeRule::valueMap("content", {{"foo", "bar"}}),
                                 }),
      });

  absl::Status unwrapped_status =
      TranscodingEngine::validateRulesAgainstSchema(unwrapped_part_plan, gemini_schema);
  EXPECT_FALSE(unwrapped_status.ok());
  EXPECT_EQ(unwrapped_status.code(), absl::StatusCode::kInvalidArgument);

  TranscodeRuleSet unwrapped_multi_part_plan(
      LLMProtocol::GeminiGenerateContent, TranscodingEngine::kIrProtocol,
      {
          TranscodeRule::move("contents", "messages"),
          TranscodeRule::forEach(
              "messages",
              {
                  TranscodeRule::unwrapArrayObject("parts", "text", "content"),
                  TranscodeRule::forEach("content",
                                         {
                                             TranscodeRule::valueMap("text", {{"foo", "bar"}}),
                                         }),
              }),
      });

  absl::Status unwrapped_multi_status =
      TranscodingEngine::validateRulesAgainstSchema(unwrapped_multi_part_plan, gemini_schema);
  EXPECT_FALSE(unwrapped_multi_status.ok());
  EXPECT_EQ(unwrapped_multi_status.code(), absl::StatusCode::kInvalidArgument);
}

nlohmann::json parseJson(absl::string_view text) {
  nlohmann::json parsed = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
  EXPECT_FALSE(parsed.is_discarded()) << text;
  return parsed;
}

// Regression: the Anthropic SDKs send a client tool's optional `type` as `custom`, which the IR
// schema rejects because only `function` tools exist there.
TEST(TranscodingEngineTest, MapsAnthropicCustomToolTypeToFunction) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());

  nlohmann::json payload = parseJson(R"({
    "model": "claude-sonnet-4-5",
    "max_tokens": 64,
    "messages": [{"role": "user", "content": "What time is it?"}],
    "tools": [
      {"type": "custom", "name": "now", "input_schema": {"type": "object"}},
      {"name": "get_weather", "input_schema": {"type": "object"}}
    ]
  })");
  ASSERT_THAT(engine_or->transcodeToIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload["tools"], parseJson(R"([
    {"type": "function", "function": {"name": "now", "parameters": {"type": "object"}}},
    {"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object"}}}
  ])"));
  EXPECT_THAT(engine_or->transcodeFromIr(TranscodingEngine::kIrProtocol, payload), IsOk());
}

// Regression: Anthropic's end-user id stayed under `metadata`, where the IR keeps OpenAI's
// free-form stored-completion tags, instead of reaching the IR's `user`.
TEST(TranscodingEngineTest, MapsAnthropicMetadataUserIdToIrUser) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());

  nlohmann::json payload = parseJson(R"({
    "model": "claude-sonnet-4-5",
    "max_tokens": 64,
    "metadata": {"user_id": "user-42"},
    "messages": [{"role": "user", "content": "Hi"}]
  })");
  ASSERT_THAT(engine_or->transcodeToIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload["user"], "user-42");
  EXPECT_FALSE(payload.contains("metadata"));
}

// Regression: `candidateCount`, `seed` and the penalties have direct IR equivalents but were
// dropped with the rest of `generationConfig`.
TEST(TranscodingEngineTest, HoistsGeminiSamplingFieldsIntoTheIr) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const PayloadSchema* ir_schema = AdapterRegistry::get(TranscodingEngine::kIrProtocol).schema();
  ASSERT_NE(ir_schema, nullptr);

  nlohmann::json camel = parseJson(R"({
    "model": "gemini-2.5-flash",
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "generationConfig": {"candidateCount": 2, "seed": "42", "presencePenalty": 0.5,
                         "frequencyPenalty": "-0.5", "topK": 40}
  })");
  ASSERT_THAT(engine_or->transcodeToIr(LLMProtocol::GeminiGenerateContent, camel), IsOk());
  EXPECT_EQ(camel, parseJson(R"({
    "model": "gemini-2.5-flash",
    "messages": [{"role": "user", "content": "Hi"}],
    "n": 2,
    "seed": 42,
    "presence_penalty": 0.5,
    "frequency_penalty": -0.5
  })"));
  EXPECT_THAT(ir_schema->validateRequest(camel), IsOk());

  nlohmann::json snake = parseJson(R"({
    "model": "gemini-2.5-flash",
    "system_instruction": {"parts": [{"text": "Be brief."}]},
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "generation_config": {"candidate_count": "1", "seed": 7, "presence_penalty": "0.25",
                          "frequency_penalty": 0.75, "max_output_tokens": 16}
  })");
  ASSERT_THAT(engine_or->transcodeToIr(LLMProtocol::GeminiGenerateContent, snake), IsOk());
  EXPECT_EQ(snake, parseJson(R"({
    "model": "gemini-2.5-flash",
    "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "Hi"}],
    "max_completion_tokens": 16,
    "n": 1,
    "seed": 7,
    "presence_penalty": 0.25,
    "frequency_penalty": 0.75
  })"));
  EXPECT_THAT(ir_schema->validateRequest(snake), IsOk());
}

// Regression: the JSON mapping's "NaN" and "Infinity" became non-finite doubles, which pass every
// range check and then serialize as null.
TEST(TranscodingEngineTest, LeavesNonFiniteGeminiNumbersForValidationToReject) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());

  nlohmann::json payload = parseJson(R"({
    "model": "gemini-2.5-flash",
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "generationConfig": {"temperature": "NaN", "topP": "Infinity", "presencePenalty": "-inf",
                         "frequencyPenalty": "0.5"}
  })");
  ASSERT_THAT(engine_or->transcodeToIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());
  EXPECT_EQ(payload["temperature"], "NaN");
  EXPECT_EQ(payload["top_p"], "Infinity");
  EXPECT_EQ(payload["presence_penalty"], "-inf");
  EXPECT_EQ(payload["frequency_penalty"], 0.5);
  EXPECT_EQ(engine_or->transcodeFromIr(LLMProtocol::AnthropicMessages, payload).code(),
            absl::StatusCode::kInvalidArgument);
}

// Regression: a system message with null content was concatenated with the other system prompts
// as a text block with null text, which Anthropic's schema rejects.
TEST(TranscodingEngineTest, SkipsNullSystemContentWhenCollectingSystemPrompts) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());

  nlohmann::json payload = parseJson(R"({
    "model": "claude-sonnet-4-5",
    "messages": [
      {"role": "system", "content": null},
      {"role": "developer", "content": "Be brief."},
      {"role": "user", "content": "Hi"}
    ]
  })");
  ASSERT_THAT(engine_or->transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload["system"], "Be brief.");

  nlohmann::json only_null = parseJson(R"({
    "model": "gemini-2.5-flash",
    "messages": [{"role": "system", "content": null}, {"role": "user", "content": "Hi"}]
  })");
  ASSERT_THAT(engine_or->transcodeFromIr(LLMProtocol::GeminiGenerateContent, only_null), IsOk());
  EXPECT_FALSE(only_null.contains("systemInstruction"));
}

// Regression: OpenAI lets a function without arguments omit `parameters`, but Anthropic requires
// every custom tool to carry `input_schema` and rejected the converted request.
TEST(TranscodingEngineTest, DefaultsAnthropicInputSchemaForFunctionsWithoutParameters) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());

  nlohmann::json payload = parseJson(R"({
    "model": "claude-sonnet-4-5",
    "messages": [{"role": "user", "content": "What time is it?"}],
    "tools": [
      {"type": "function", "function": {"name": "now", "description": "Current time"}},
      {"type": "function", "function": {"name": "get_weather",
        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}}
    ],
    "tool_choice": {"type": "function", "function": {"name": "now"}}
  })");
  ASSERT_THAT(engine_or->transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload["tools"], parseJson(R"([
    {"name": "now", "description": "Current time", "input_schema": {"type": "object"}},
    {"name": "get_weather",
     "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}}
  ])"));
  EXPECT_EQ(payload["tool_choice"], parseJson(R"({"type": "tool", "name": "now"})"));
}

TEST(TranscodingEngineTest, TranscodesARealisticOpenAiConversationToAnthropic) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());

  nlohmann::json payload = parseJson(R"({
    "model": "claude-sonnet-4-5",
    "messages": [
      {"role": "system", "content": [{"type": "text", "text": "You are terse."}]},
      {"role": "developer", "content": "Use metric units."},
      {"role": "user", "content": "Weather in Paris?"},
      {"role": "assistant", "content": [{"type": "text", "text": "Sunny, 21C."}]},
      {"role": "user", "content": [{"type": "text", "text": "And tomorrow?"}]}
    ],
    "max_tokens": 300,
    "stop": ["\n\n", "END"],
    "temperature": 0.7,
    "tool_choice": "auto",
    "tools": [{"type": "function", "function": {"name": "forecast",
                                                "parameters": {"type": "object"}}}]
  })");
  ASSERT_THAT(engine_or->transcodeFromIr(LLMProtocol::AnthropicMessages, payload), IsOk());
  EXPECT_EQ(payload, parseJson(R"({
    "model": "claude-sonnet-4-5",
    "system": [
      {"type": "text", "text": "You are terse."},
      {"type": "text", "text": "Use metric units."}
    ],
    "messages": [
      {"role": "user", "content": "Weather in Paris?"},
      {"role": "assistant", "content": [{"type": "text", "text": "Sunny, 21C."}]},
      {"role": "user", "content": [{"type": "text", "text": "And tomorrow?"}]}
    ],
    "max_tokens": 300,
    "stop_sequences": ["\n\n", "END"],
    "temperature": 0.7,
    "tool_choice": {"type": "auto"},
    "tools": [{"name": "forecast", "input_schema": {"type": "object"}}]
  })"));
}

TEST(TranscodingEngineTest, TranscodesARealisticOpenAiConversationToGemini) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());

  nlohmann::json payload = parseJson(R"({
    "model": "gemini-2.5-flash",
    "messages": [
      {"role": "system", "content": [{"type": "text", "text": "You are terse."},
                                     {"type": "text", "text": "Answer in French."}]},
      {"role": "user", "content": "Hi"},
      {"role": "assistant", "content": "Bonjour."},
      {"role": "user", "content": [{"type": "text", "text": "Weather?"}]}
    ],
    "max_completion_tokens": 50,
    "stop": "END",
    "top_p": 0.5,
    "tool_choice": "required"
  })");
  ASSERT_THAT(engine_or->transcodeFromIr(LLMProtocol::GeminiGenerateContent, payload), IsOk());
  EXPECT_EQ(payload, parseJson(R"({
    "systemInstruction": {"parts": [{"text": "You are terse."}, {"text": "Answer in French."}]},
    "contents": [
      {"role": "user", "parts": [{"text": "Hi"}]},
      {"role": "model", "parts": [{"text": "Bonjour."}]},
      {"role": "user", "parts": [{"text": "Weather?"}]}
    ],
    "generationConfig": {"maxOutputTokens": 50, "stopSequences": ["END"], "topP": 0.5}
  })"));
}

TEST(TranscodingEngineTest, CoversAllRuleAndEngineEdgeCases) {
  // 1. Exercise `TranscodeRule` introspection accessors and `std::vector<TranscodeRule>` rule set.
  TranscodeRule rule = TranscodeRule::valueMap("role", {{"bot", "assistant"}},
                                               TranscodeRule::UnknownValuePolicy::Drop);
  EXPECT_EQ(rule.op(), TranscodeRule::Op::ValueMap);
  EXPECT_EQ(rule.targetPath(), "role");
  EXPECT_EQ(rule.unknownValuePolicy(), TranscodeRule::UnknownValuePolicy::Drop);
  EXPECT_EQ(rule.valueMappings().size(), 1);

  TranscodeRule def_rule = TranscodeRule::setDefault("temperature", 0.7);
  EXPECT_EQ(def_rule.defaultValue(), 0.7);

  TranscodeRule ext_rule =
      TranscodeRule::extractFromArray("messages", "role", {"system"}, "content", "system");
  EXPECT_EQ(ext_rule.predicateField(), "role");
  EXPECT_EQ(ext_rule.extractSubpath(), "content");
  EXPECT_EQ(ext_rule.matchValues().size(), 1);

  std::vector<TranscodeRule> rule_vec = {rule};
  TranscodeRuleSet vec_rule_set(LLMProtocol::OpenAiResponses, LLMProtocol::OpenAiChatCompletions,
                                std::move(rule_vec));
  EXPECT_EQ(vec_rule_set.sourceProtocol(), LLMProtocol::OpenAiResponses);
  EXPECT_EQ(vec_rule_set.targetProtocol(), LLMProtocol::OpenAiChatCompletions);

  // 2. Exercise `JsonWithExtBuf` wrapper overloads on `TranscodeRuleSet` and `TranscodingEngine`.
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  const TranscodingEngine& default_engine = *engine_or;

  JsonWithExtBuf ext_payload;
  ext_payload.json() = nlohmann::json::parse(R"({
    "model": "claude-sonnet-4-5",
    "role": "unknown_role",
    "messages": [{"role": "user", "content": "Hi"}]
  })");
  ASSERT_THAT(vec_rule_set.execute(ext_payload), IsOk());
  EXPECT_FALSE(ext_payload.json().contains("role"));

  ASSERT_THAT(default_engine.transcodeToIr(LLMProtocol::Unspecified, ext_payload), IsOk());
  ASSERT_THAT(default_engine.transcodeFromIr(LLMProtocol::Unspecified, ext_payload), IsOk());
  ASSERT_THAT(default_engine.transcodeToIr(LLMProtocol::OpenAiChatCompletions, ext_payload),
              IsOk());
  ASSERT_THAT(default_engine.transcodeFromIr(LLMProtocol::AnthropicMessages, ext_payload), IsOk());

  // 3. Non-object root payload is rejected by `TranscodeRule::apply`.
  nlohmann::json non_obj = nlohmann::json::array({1, 2, 3});
  EXPECT_FALSE(TranscodeRule::drop("a").apply(non_obj).ok());

  // 4. Empty path, self-move (`source_path == target_path`), and intermediate non-object paths.
  nlohmann::json edge_doc = nlohmann::json::parse(R"({
    "a": "scalar",
    "single_other": {"other": 123},
    "bad_int": "not_an_int",
    "bad_num": "not_a_float",
    "non_str": 42,
    "arr_with_scalar": [123, {"k": "v"}],
    "scalar_blocks": ["hello"],
    "bad_blocks": [{"no_text": 1}],
    "non_obj_parts": [123],
    "multi_sys": [
      {"role": "system", "content": [{"type": "text", "text": "sys1"}]},
      {"role": "system", "content": "sys2"}
    ]
  })");
  EXPECT_THAT(TranscodeRule::move("", "").apply(edge_doc), IsOk());
  EXPECT_THAT(TranscodeRule::move("a", "a").apply(edge_doc), IsOk());
  EXPECT_THAT(TranscodeRule::move("a.b.c", "x.y").apply(edge_doc), IsOk());
  EXPECT_THAT(TranscodeRule::setDefault("", nlohmann::json::object()).apply(edge_doc), IsOk());
  EXPECT_THAT(TranscodeRule::unwrapSingleKeyObject("single_other", "type").apply(edge_doc), IsOk());
  EXPECT_THAT(TranscodeRule::toInteger("bad_int").apply(edge_doc), IsOk());
  EXPECT_THAT(TranscodeRule::toNumber("bad_num").apply(edge_doc), IsOk());
  EXPECT_THAT(TranscodeRule::valueMap("non_str", {{"a", "b"}}).apply(edge_doc), IsOk());
  EXPECT_THAT(TranscodeRule::forEach("arr_with_scalar", {TranscodeRule::drop("k")}).apply(edge_doc),
              IsOk());
  EXPECT_THAT(TranscodeRule::extractFromArray("missing_arr", "role", {"system"}, "content", "sys")
                  .apply(edge_doc),
              IsOk());
  EXPECT_THAT(TranscodeRule::extractFromArray("multi_sys", "role", {"system"}, "content", "sys_out")
                  .apply(edge_doc),
              IsOk());
  EXPECT_THAT(
      TranscodeRule::prependToArray("bad_int", "new_messages_arr", "role", "system", "content")
          .apply(edge_doc),
      IsOk());
  EXPECT_THAT(
      TranscodeRule::wrapInArrayObject("scalar_blocks", "wrapped_scalars", "text").apply(edge_doc),
      IsOk());
  EXPECT_FALSE(
      TranscodeRule::wrapInArrayObject("bad_blocks", "wrapped_bad", "text").apply(edge_doc).ok());
  EXPECT_FALSE(
      TranscodeRule::unwrapArrayObject("non_obj_parts", "text", "out").apply(edge_doc).ok());

  // 5. Runtime `ExternalRef` protection on `ValueMap` and `registerPack` / `transcodeFromIr` error
  //    propagation.
  nlohmann::json ext_ref_doc = nlohmann::json::object();
  ext_ref_doc["field"] = JsonWithExtBuf::makeExternalRef({0, 16});
  EXPECT_FALSE(TranscodeRule::valueMap("field", {{"a", "b"}}).apply(ext_ref_doc).ok());

  const PayloadSchema* openai_schema =
      AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).schema();
  TranscodingEngine custom_engine;
  DialectTranscodePack bad_to_ir_pack{
      /*protocol=*/LLMProtocol::OpenAiChatCompletions,
      /*to_IR=*/
      TranscodeRuleSet(
          LLMProtocol::OpenAiChatCompletions, TranscodingEngine::kIrProtocol,
          {TranscodeRule::forEach("messages", {TranscodeRule::valueMap("content", {{"a", "b"}})})}),
      /*from_IR=*/
      TranscodeRuleSet(TranscodingEngine::kIrProtocol, LLMProtocol::OpenAiChatCompletions, {}),
  };
  EXPECT_FALSE(
      custom_engine.registerPack(std::move(bad_to_ir_pack), openai_schema, openai_schema).ok());

  DialectTranscodePack bad_from_ir_pack{
      /*protocol=*/LLMProtocol::OpenAiChatCompletions,
      /*to_IR=*/
      TranscodeRuleSet(LLMProtocol::OpenAiChatCompletions, TranscodingEngine::kIrProtocol, {}),
      /*from_IR=*/
      TranscodeRuleSet(
          TranscodingEngine::kIrProtocol, LLMProtocol::OpenAiChatCompletions,
          {TranscodeRule::forEach("messages", {TranscodeRule::valueMap("content", {{"a", "b"}})})}),
  };
  EXPECT_FALSE(
      custom_engine.registerPack(std::move(bad_from_ir_pack), openai_schema, openai_schema).ok());

  DialectTranscodePack strict_from_ir_pack{
      /*protocol=*/LLMProtocol::OpenAiResponses,
      /*to_IR=*/
      TranscodeRuleSet(LLMProtocol::OpenAiResponses, TranscodingEngine::kIrProtocol, {}),
      /*from_IR=*/
      TranscodeRuleSet(TranscodingEngine::kIrProtocol, LLMProtocol::OpenAiResponses,
                       {TranscodeRule::valueMap("mode", {{"ok", "yes"}},
                                                TranscodeRule::UnknownValuePolicy::Reject)}),
  };
  ASSERT_THAT(custom_engine.registerPack(std::move(strict_from_ir_pack)), IsOk());
  nlohmann::json bad_mode = nlohmann::json::parse(R"({"mode": "invalid"})");
  EXPECT_FALSE(custom_engine.transcodeFromIr(LLMProtocol::OpenAiResponses, bad_mode).ok());
}

TEST(TranscodeReportTest, RecordsEachFieldOnce) {
  TranscodeReport report;
  report.add("b");
  report.add("a");
  report.add("b");
  EXPECT_THAT(report.dropped, ElementsAre("b", "a"));
}

TEST(TranscodeRuleTest, DropReportsWhatCarriedAValue) {
  nlohmann::json doc = parseJson(R"({
    "config": {"a": 1, "b": null, "c": false, "d": [], "e": {}, "f": "x"},
    "flag": true, "off": false, "list": [], "text": ""
  })");
  TranscodeReport report;
  const TranscodeOptions options;
  for (absl::string_view path : {"config", "flag", "off", "list", "text", "absent"}) {
    ASSERT_THAT(TranscodeRule::drop(std::string(path)).apply(doc, options, &report), IsOk());
  }
  EXPECT_EQ(doc, nlohmann::json::object());
  EXPECT_THAT(report.dropped, ElementsAre("config.a", "config.f", "flag", "text"));

  // Without a report the rule still removes the field.
  doc = parseJson(R"({"flag": true})");
  ASSERT_THAT(TranscodeRule::drop("flag").apply(doc), IsOk());
  EXPECT_EQ(doc, nlohmann::json::object());
}

TEST(TranscodeRuleTest, DiscardRemovesSilently) {
  nlohmann::json doc = parseJson(R"({"a": {"b": 1}, "c": 2})");
  TranscodeReport report;
  ASSERT_THAT(TranscodeRule::discard("a.b").apply(doc, TranscodeOptions(), &report), IsOk());
  EXPECT_EQ(doc, parseJson(R"({"c": 2})"));
  EXPECT_EQ(TranscodeRule::discard("a").op(), TranscodeRule::Op::Discard);
  EXPECT_THAT(report.dropped, IsEmpty());
}

TEST(TranscodeRuleTest, SetDefaultFromOptions) {
  TranscodeOptions options;
  options.default_max_output_tokens = 99;
  nlohmann::json doc = nlohmann::json::object();
  ASSERT_THAT(TranscodeRule::setDefault("max_tokens", TranscodeRule::Option::MaxOutputTokens)
                  .apply(doc, options, nullptr),
              IsOk());
  ASSERT_THAT(TranscodeRule::setDefault("usage.on", TranscodeRule::Option::StreamUsage)
                  .apply(doc, options, nullptr),
              IsOk());
  EXPECT_EQ(doc, parseJson(R"({"max_tokens": 99, "usage": {"on": true}})"));

  // An existing value wins, and a disabled stream usage option sets nothing.
  doc = parseJson(R"({"max_tokens": 5})");
  options.request_stream_usage = false;
  ASSERT_THAT(TranscodeRule::setDefault("max_tokens", TranscodeRule::Option::MaxOutputTokens)
                  .apply(doc, options, nullptr),
              IsOk());
  ASSERT_THAT(TranscodeRule::setDefault("usage.on", TranscodeRule::Option::StreamUsage)
                  .apply(doc, options, nullptr),
              IsOk());
  EXPECT_EQ(doc, parseJson(R"({"max_tokens": 5})"));

  // The rules without options use the defaults.
  doc = nlohmann::json::object();
  ASSERT_THAT(
      TranscodeRule::setDefault("max_tokens", TranscodeRule::Option::MaxOutputTokens).apply(doc),
      IsOk());
  EXPECT_EQ(doc["max_tokens"], 4096);
}

TEST(TranscodeRuleTest, ValueMapMapsJsonValues) {
  const TranscodeRule rule = TranscodeRule::valueMap(
      "a.v", {{true, false}, {false, nullptr}, {1, "one"}, {"x", nlohmann::json::array({1})}});
  const auto mapped = [&](absl::string_view value) {
    nlohmann::json doc = parseJson(absl::StrCat(R"({"a": {"v": )", value, R"(}, "k": 1})"));
    EXPECT_THAT(rule.apply(doc), IsOk());
    return doc;
  };
  EXPECT_EQ(mapped("true"), parseJson(R"({"a": {"v": false}, "k": 1})"));
  // A mapping to null removes the field, and the parent it leaves empty.
  EXPECT_EQ(mapped("false"), parseJson(R"({"k": 1})"));
  EXPECT_EQ(mapped("1.0"), parseJson(R"({"a": {"v": "one"}, "k": 1})"));
  EXPECT_EQ(mapped(R"("x")"), parseJson(R"({"a": {"v": [1]}, "k": 1})"));
  EXPECT_EQ(mapped(R"("1")"), parseJson(R"({"a": {"v": "1"}, "k": 1})"));
  EXPECT_EQ(mapped("null"), parseJson(R"({"a": {"v": null}, "k": 1})"));
}

TEST(TranscodeRuleTest, ValueMapUnknownValuePolicies) {
  TranscodeReport report;
  const TranscodeOptions options;
  const TranscodeRule drop =
      TranscodeRule::valueMap("v", {{"a", "b"}}, TranscodeRule::UnknownValuePolicy::Drop);
  nlohmann::json doc = parseJson(R"({"v": "z"})");
  ASSERT_THAT(drop.apply(doc, options, &report), IsOk());
  EXPECT_FALSE(doc.contains("v"));
  doc = parseJson(R"({"v": false})");
  ASSERT_THAT(drop.apply(doc, options, &report), IsOk());
  EXPECT_FALSE(doc.contains("v"));
  EXPECT_THAT(report.dropped, ElementsAre("v"));

  doc = parseJson(R"({"v": 7})");
  EXPECT_THAT(TranscodeRule::valueMap("v", {{"a", "b"}}, TranscodeRule::UnknownValuePolicy::Reject)
                  .apply(doc),
              HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("unmapped value '7'")));
}

TEST(TranscodeRuleTest, DropElementsReportsUnderTheArrayPrefix) {
  nlohmann::json doc = parseJson(R"({"messages": [
    {"content": [{"type": "thinking"}, {"type": "text", "text": "a"}, "raw", {"text": "b"},
                 {"type": "redacted_thinking"}]},
    {"content": [{"type": "thinking"}]},
    {"content": "not an array"}
  ]})");
  TranscodeReport report;
  ASSERT_THAT(
      TranscodeRule::forEach("messages", {TranscodeRule::dropElements(
                                             "content", "type", {"thinking", "redacted_thinking"})})
          .apply(doc, TranscodeOptions(), &report),
      IsOk());
  EXPECT_EQ(doc, parseJson(R"({"messages": [
    {"content": [{"type": "text", "text": "a"}, "raw", {"text": "b"}]},
    {"content": []},
    {"content": "not an array"}
  ]})"));
  EXPECT_THAT(report.dropped, ElementsAre("messages[].content[type=thinking]",
                                          "messages[].content[type=redacted_thinking]"));
}

TEST(TranscodeRuleTest, DropElementsMatchesJsonValues) {
  nlohmann::json doc = parseJson(R"({"turns": [
    {"parts": []}, {"parts": [1]}, {"role": "user"}, {"parts": null}
  ], "flags": [{"on": true}, {"on": false}]})");
  TranscodeReport report;
  const TranscodeOptions options;
  ASSERT_THAT(TranscodeRule::discardElements("turns", "parts", {nlohmann::json::array()})
                  .apply(doc, options, &report),
              IsOk());
  ASSERT_THAT(TranscodeRule::dropElements("flags", "on", {true}).apply(doc, options, &report),
              IsOk());
  ASSERT_THAT(TranscodeRule::dropElements("absent", "on", {true}).apply(doc, options, &report),
              IsOk());
  EXPECT_EQ(doc, parseJson(R"({"turns": [{"parts": [1]}, {"role": "user"}, {"parts": null}],
                               "flags": [{"on": false}]})"));
  EXPECT_THAT(report.dropped, ElementsAre("flags[on=true]"));
  EXPECT_EQ(TranscodeRule::discardElements("a", "b", {1}).op(), TranscodeRule::Op::DiscardElements);
}

TEST(TranscodeRuleTest, WhenAppliesRulesOnlyIfTheConditionHolds) {
  const auto holds = [](TranscodeCondition condition, absl::string_view doc) {
    return condition.holds(parseJson(doc));
  };
  EXPECT_TRUE(holds(TranscodeCondition::hasValue("a.b"), R"({"a": {"b": [1]}})"));
  EXPECT_FALSE(holds(TranscodeCondition::hasValue("a.b"), R"({"a": {"b": []}})"));
  EXPECT_FALSE(holds(TranscodeCondition::hasValue("a"), R"({"a": false})"));
  EXPECT_FALSE(holds(TranscodeCondition::hasValue("a"), R"({})"));
  EXPECT_TRUE(holds(TranscodeCondition::noValue("a"), R"({"a": {}})"));
  EXPECT_TRUE(holds(TranscodeCondition::noValue("a"), R"({})"));
  EXPECT_FALSE(holds(TranscodeCondition::noValue("a"), R"({"a": 0})"));
  EXPECT_TRUE(holds(TranscodeCondition::present("a"), R"({"a": false})"));
  EXPECT_FALSE(holds(TranscodeCondition::present("a"), R"({"a": null})"));
  EXPECT_FALSE(holds(TranscodeCondition::present("a"), R"({})"));
  EXPECT_TRUE(holds(TranscodeCondition::in("a", {nullptr, 1}), R"({"a": 1.0})"));
  EXPECT_TRUE(holds(TranscodeCondition::in("a", {nullptr, 1}), R"({"a": null})"));
  EXPECT_FALSE(holds(TranscodeCondition::in("a", {1}), R"({"a": "1"})"));
  EXPECT_FALSE(holds(TranscodeCondition::in("a", {1}), R"({})"));
  EXPECT_TRUE(holds(TranscodeCondition::notIn("a", {1}), R"({})"));
  EXPECT_TRUE(holds(TranscodeCondition::notIn("a", {1}), R"({"a": true})"));
  EXPECT_FALSE(holds(TranscodeCondition::notIn("a", {"x"}), R"({"a": "x"})"));
  EXPECT_TRUE(holds(TranscodeCondition::isObject("a"), R"({"a": {}})"));
  EXPECT_FALSE(holds(TranscodeCondition::isObject("a"), R"({"a": true})"));
  EXPECT_FALSE(holds(TranscodeCondition::isObject("a"), R"({})"));
  EXPECT_TRUE(holds(TranscodeCondition::notString("a"), R"({})"));
  EXPECT_TRUE(holds(TranscodeCondition::notString("a"), R"({"a": 7})"));
  EXPECT_TRUE(holds(TranscodeCondition::notString("a"), R"({"a": null})"));
  EXPECT_FALSE(holds(TranscodeCondition::notString("a"), R"({"a": ""})"));

  nlohmann::json offloaded = nlohmann::json::object();
  offloaded["a"] = JsonWithExtBuf::makeExternalRef({0, 16});
  EXPECT_FALSE(TranscodeCondition::notString("a").holds(offloaded));
  EXPECT_TRUE(TranscodeCondition::hasValue("a").holds(offloaded));

  const TranscodeRule rule =
      TranscodeRule::when(TranscodeCondition::in("kind", {"x"}),
                          {TranscodeRule::move("a", "b"), TranscodeRule::setDefault("c", 1)});
  EXPECT_EQ(rule.condition()->path(), "kind");
  EXPECT_EQ(rule.subRules().size(), 2);
  nlohmann::json doc = parseJson(R"({"kind": "x", "a": 1})");
  ASSERT_THAT(rule.apply(doc), IsOk());
  EXPECT_EQ(doc, parseJson(R"({"kind": "x", "b": 1, "c": 1})"));
  doc = parseJson(R"({"kind": "y", "a": 1})");
  ASSERT_THAT(rule.apply(doc), IsOk());
  EXPECT_EQ(doc, parseJson(R"({"kind": "y", "a": 1})"));

  doc = parseJson(R"({"kind": "x"})");
  EXPECT_THAT(TranscodeRule::when(TranscodeCondition::present("kind"),
                                  {TranscodeRule::fail("first"), TranscodeRule::fail("second")})
                  .apply(doc),
              HasStatus(absl::StatusCode::kInvalidArgument, "first"));
}

TEST(TranscodeRuleTest, FailNamesTheElementAndQuotesAValue) {
  nlohmann::json doc = parseJson(R"({"messages": [
    {"content": [{"type": "text"}]},
    {"content": [{"type": "text"}, {"type": "image_url"}]}
  ]})");
  const TranscodeRule rule = TranscodeRule::forEach(
      "messages",
      {TranscodeRule::forEach(
          "content",
          {TranscodeRule::when(TranscodeCondition::notIn("type", {"text"}),
                               {TranscodeRule::fail("{path} has {value} ({path})", "type")})})});
  EXPECT_THAT(rule.apply(doc),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        "messages[1].content[1] has image_url (messages[1].content[1])"));

  doc = parseJson(R"({"type": 5})");
  EXPECT_THAT(TranscodeRule::fail("type {value} at '{path}'", "type").apply(doc),
              HasStatus(absl::StatusCode::kInvalidArgument, "type (none) at ''"));
  EXPECT_THAT(TranscodeRule::fail("no {value}").apply(doc),
              HasStatus(absl::StatusCode::kInvalidArgument, "no (none)"));
}

TEST(TranscodeRuleTest, KeepOnlyReportsTheRemovedMembers) {
  TranscodeReport report;
  const TranscodeOptions options;
  nlohmann::json doc = parseJson(R"({"messages": [
    {"content": [{"type": "text", "text": "a", "cache_control": {"type": "ephemeral"},
                  "annotations": []}]}
  ], "config": {"keep": 1, "extra": 2}, "scalar": 1})");
  ASSERT_THAT(TranscodeRule::forEach(
                  "messages",
                  {TranscodeRule::forEach("content", {TranscodeRule::keepOnly({"type", "text"})})})
                  .apply(doc, options, &report),
              IsOk());
  ASSERT_THAT(TranscodeRule::keepOnly({"keep"}, "config").apply(doc, options, &report), IsOk());
  ASSERT_THAT(TranscodeRule::keepOnly({"keep"}, "scalar").apply(doc, options, &report), IsOk());
  ASSERT_THAT(TranscodeRule::keepOnly({"keep"}, "absent").apply(doc, options, &report), IsOk());
  EXPECT_EQ(doc, parseJson(R"({"messages": [{"content": [{"type": "text", "text": "a"}]}],
                               "config": {"keep": 1}, "scalar": 1})"));
  EXPECT_THAT(report.dropped, ElementsAre("messages[].content[].cache_control", "config.extra"));

  ASSERT_THAT(TranscodeRule::keepOnly({"messages"}).apply(doc, options, &report), IsOk());
  EXPECT_EQ(doc, parseJson(R"({"messages": [{"content": [{"type": "text", "text": "a"}]}]})"));
  EXPECT_THAT(report.dropped, ElementsAre("messages[].content[].cache_control", "config.extra",
                                          "config", "scalar"));
  EXPECT_THAT(TranscodeRule::keepOnly({"a"}).keys(), ElementsAre("a"));
}

TEST(TranscodeRuleSetTest, ExecuteThreadsOptionsAndReport) {
  TranscodeOptions options;
  options.default_max_output_tokens = 7;
  TranscodeReport report;
  const TranscodeRuleSet rules(
      LLMProtocol::OpenAiChatCompletions, LLMProtocol::AnthropicMessages,
      {TranscodeRule::drop("x"),
       TranscodeRule::setDefault("max_tokens", TranscodeRule::Option::MaxOutputTokens),
       TranscodeRule::fail("stop"), TranscodeRule::setDefault("never", 1)});
  nlohmann::json doc = parseJson(R"({"x": 1})");
  EXPECT_THAT(rules.execute(doc, options, &report),
              HasStatus(absl::StatusCode::kInvalidArgument, "stop"));
  EXPECT_EQ(doc, parseJson(R"({"max_tokens": 7})"));
  EXPECT_THAT(report.dropped, ElementsAre("x"));
}

// A verifier rejection for every rule that reads a value, each hidden behind a structural rule
// the verifier has to follow.
TEST(TranscodingEngineTest, VerifierRejectsNewValueReadsOfOffloadableFields) {
  const PayloadSchema* openai_schema =
      AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).schema();
  ASSERT_NE(openai_schema, nullptr);
  const auto verify = [&](std::vector<TranscodeRule> rules) {
    return TranscodingEngine::validateRulesAgainstSchema(
        TranscodeRuleSet(LLMProtocol::OpenAiChatCompletions, TranscodingEngine::kIrProtocol,
                         std::move(rules)),
        openai_schema);
  };

  EXPECT_THAT(verify({TranscodeRule::forEach(
                  "messages", {TranscodeRule::when(TranscodeCondition::in("content", {"x"}),
                                                   {TranscodeRule::discard("name")})})}),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("when rule cannot read offloadable field 'messages[].content'")));
  EXPECT_THAT(verify({TranscodeRule::forEach(
                  "messages", {TranscodeRule::dropElements("content", "text", {"x"})})}),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("drop_elements rule cannot read offloadable field "
                                  "'messages[].content[].text'")));
  EXPECT_THAT(
      verify({TranscodeRule::move("messages", "turns"),
              TranscodeRule::forEach(
                  "turns",
                  {TranscodeRule::forEach("content", {TranscodeRule::fail("{value}", "text")})})}),
      HasStatus(absl::StatusCode::kInvalidArgument,
                HasSubstr("fail rule cannot read offloadable field 'turns[].content[].text'")));
  EXPECT_THAT(
      verify({TranscodeRule::forEach(
          "messages", {TranscodeRule::when(TranscodeCondition::present("content"),
                                           {TranscodeRule::valueMap("content", {{"a", "b"}})})})}),
      HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("'messages[].content'")));
  // A conditional move may not run, so the old path stays offloadable too.
  EXPECT_THAT(
      verify(
          {TranscodeRule::when(TranscodeCondition::present("x"),
                               {TranscodeRule::move("messages", "turns")}),
           TranscodeRule::forEach("messages", {TranscodeRule::valueMap("content", {{"a", "b"}})}),
           TranscodeRule::forEach("turns", {TranscodeRule::valueMap("content", {{"a", "b"}})})}),
      HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("'messages[].content'")));
  EXPECT_THAT(
      verify({TranscodeRule::when(TranscodeCondition::present("x"),
                                  {TranscodeRule::move("messages", "turns")}),
              TranscodeRule::forEach("turns", {TranscodeRule::valueMap("content", {{"a", "b"}})})}),
      HasStatus(absl::StatusCode::kInvalidArgument, HasSubstr("'turns[].content'")));
}

TEST(TranscodingEngineTest, VerifierAcceptsReadsOfFieldsNoLongerOffloadable) {
  const PayloadSchema* openai_schema =
      AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).schema();
  ASSERT_NE(openai_schema, nullptr);
  const auto verify = [&](std::vector<TranscodeRule> rules) {
    return TranscodingEngine::validateRulesAgainstSchema(
        TranscodeRuleSet(LLMProtocol::OpenAiChatCompletions, TranscodingEngine::kIrProtocol,
                         std::move(rules)),
        openai_schema);
  };

  EXPECT_THAT(verify({TranscodeRule::forEach(
                  "messages", {TranscodeRule::keepOnly({"role"}),
                               TranscodeRule::when(TranscodeCondition::in("content", {"x"}), {}),
                               TranscodeRule::fail("{value}", "content")})}),
              IsOk());
  EXPECT_THAT(
      verify({TranscodeRule::forEach(
          "messages", {TranscodeRule::forEach("content", {TranscodeRule::keepOnly({"type"}, "")}),
                       TranscodeRule::dropElements("content", "text", {"x"})})}),
      IsOk());
  EXPECT_THAT(verify({TranscodeRule::keepOnly({"model"}),
                      TranscodeRule::forEach("messages",
                                             {TranscodeRule::valueMap("content", {{"a", "b"}})})}),
              IsOk());
  EXPECT_THAT(verify({TranscodeRule::forEach("messages",
                                             {TranscodeRule::discard("content"),
                                              TranscodeRule::valueMap("content", {{"a", "b"}})})}),
              IsOk());
  // Presence and type checks do not read the value.
  EXPECT_THAT(verify({TranscodeRule::forEach(
                  "messages", {TranscodeRule::when(TranscodeCondition::notString("content"),
                                                   {TranscodeRule::fail("{path}")}),
                               TranscodeRule::when(TranscodeCondition::hasValue("content"), {}),
                               TranscodeRule::dropElements("content", "type", {"x"})})}),
              IsOk());
}

// Pruning covers the root and the elements of every root array of objects, under any alias.
TEST(TranscodingEngineTest, TranscodeFromIrPrunesToTheTargetSchema) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());

  nlohmann::json payload = parseJson(R"({
    "model": "gemini-2.5-flash",
    "messages": [{"role": "user", "content": "Hi", "name": "alice"}],
    "safety_settings": [{"category": "C", "threshold": "T", "extra": 1}],
    "top_k": 0,
    "logit_bias": {"1": 2}
  })");
  TranscodeReport report;
  ASSERT_THAT(engine_or->transcodeFromIr(LLMProtocol::GeminiGenerateContent, payload,
                                         TranscodeOptions(), report),
              IsOk());
  EXPECT_EQ(payload, parseJson(R"({
    "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
    "safety_settings": [{"category": "C", "threshold": "T"}]
  })"));
  EXPECT_THAT(report.dropped,
              ElementsAre("logit_bias", "top_k", "contents[].name", "safety_settings[].extra"));

  // An element schema that declares no members does not constrain its elements.
  payload = parseJson(R"({
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hi"}],
    "functions": [{"name": "f", "parameters": {}}]
  })");
  report.dropped.clear();
  ASSERT_THAT(engine_or->transcodeFromIr(LLMProtocol::OpenAiChatCompletions, payload,
                                         TranscodeOptions(), report),
              IsOk());
  EXPECT_EQ(payload["functions"], parseJson(R"([{"name": "f", "parameters": {}}])"));
  EXPECT_THAT(report.dropped, IsEmpty());
}

TEST(TranscodingEngineTest, RejectPolicyFailsOnAnyReportedField) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  TranscodeOptions options;
  options.unsupported_fields = UnsupportedFieldPolicy::Reject;

  nlohmann::json payload = parseJson(R"({"model": "gpt-4o",
                                         "messages": [{"role": "user", "content": "Hi"}]})");
  TranscodeReport report;
  report.add("earlier");
  EXPECT_THAT(
      engine_or->transcodeFromIr(LLMProtocol::OpenAiChatCompletions, payload, options, report),
      HasStatus(absl::StatusCode::kInvalidArgument,
                "OPENAI_CHAT_COMPLETIONS cannot express request fields: earlier"));

  report.dropped.clear();
  ASSERT_THAT(
      engine_or->transcodeFromIr(LLMProtocol::OpenAiChatCompletions, payload, options, report),
      IsOk());
}

TEST(TranscodingEngineTest, EnginePathsRequireAnObject) {
  auto engine_or = TranscodingEngine::createDefault();
  ASSERT_THAT(engine_or.status(), IsOk());
  nlohmann::json payload = nlohmann::json::array();
  EXPECT_THAT(engine_or->transcodeToIr(LLMProtocol::AnthropicMessages, payload),
              HasStatus(absl::StatusCode::kInvalidArgument, "request body is not a JSON object"));
  EXPECT_THAT(engine_or->transcodeFromIr(LLMProtocol::AnthropicMessages, payload),
              HasStatus(absl::StatusCode::kInvalidArgument, "request body is not a JSON object"));
}

// Only an object root declares members to prune to.
TEST(TranscodingEngineTest, PruningSkipsANonObjectRootSchema) {
  static const PayloadSchema kStringRoot{RequestSchema{Schema::string()}};
  TranscodingEngine engine;
  ASSERT_THAT(engine.registerPack(DialectTranscodePack{
                  /*protocol=*/LLMProtocol::OpenAiResponses,
                  /*to_IR=*/{},
                  /*from_IR=*/{},
                  /*dialect_schema=*/&kStringRoot,
              }),
              IsOk());
  nlohmann::json payload = parseJson(R"({"input": "Hi"})");
  EXPECT_THAT(engine.transcodeFromIr(LLMProtocol::OpenAiResponses, payload),
              HasStatus(absl::StatusCode::kInvalidArgument,
                        HasSubstr("request is not valid OPENAI_RESPONSES")));
  EXPECT_EQ(payload, parseJson(R"({"input": "Hi"})"));
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
