#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/filters/http/ai_protocol_manager/schema/gemini_interactions.h"

#include "test/test_common/status_utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace GeminiInteractions {
namespace {

using StatusHelpers::IsOk;
using StatusHelpers::StatusCodeIs;
using testing::HasSubstr;

nlohmann::json parse(absl::string_view json) { return nlohmann::json::parse(json); }

nlohmann::json externalRef(uint64_t length) {
  return JsonWithExtBuf::makeExternalRef(JsonWithExtBuf::ExternalRef{0, length});
}

nlohmann::json withInput(nlohmann::json input) {
  return nlohmann::json{{"model", "gemini-3-flash-preview"}, {"input", std::move(input)}};
}

TEST(GeminiInteractionsTest, StandardValidPayload) {
  PayloadSchema payload_schema = createPayloadSchema();

  EXPECT_THAT(payload_schema.validateRequest(parse(R"({
    "model": "gemini-3-flash-preview",
    "input": "Hello, how are you?",
    "system_instruction": "Be concise.",
    "generation_config": {
      "max_output_tokens": 1024,
      "seed": 7,
      "stop_sequences": ["END"],
      "thinking_level": "low",
      "thinking_summaries": "auto"
    },
    "stream": true,
    "store": false,
    "background": false,
    "previous_interaction_id": "v1_ChdPU0F4YWFt",
    "service_tier": "flex"
  })")),
              IsOk());
}

// A request names a model or an agent, never both. Null leaves either unset.
TEST(GeminiInteractionsTest, ExactlyOneOfModelOrAgent) {
  PayloadSchema payload_schema = createPayloadSchema();

  EXPECT_THAT(payload_schema.validateRequest(parse(R"({
    "agent": "deep-research-preview-04-2026",
    "input": "Research the history of the transistor.",
    "agent_config": {"type": "deep-research", "thinking_summaries": "auto"},
    "background": true
  })")),
              IsOk());
  EXPECT_THAT(payload_schema.validateRequest(
                  parse(R"({"model": null, "agent": "deep-research-preview-04-2026"})")),
              IsOk());

  const absl::Status neither = payload_schema.validateRequest(parse(R"({"input": "Hi"})"));
  EXPECT_THAT(neither, StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(neither.message(), HasSubstr("model or agent"));
  EXPECT_THAT(payload_schema.validateRequest(parse(R"({"model": null, "input": "Hi"})")),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(payload_schema.validateRequest(parse(R"({
    "model": "gemini-3-flash-preview",
    "agent": "deep-research-preview-04-2026",
    "input": "Hi"
  })")),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(payload_schema.validateRequest(parse(R"({"model": 3, "input": "Hi"})")),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
}

// `input` is a string, one content item, a list of content items or a list of steps. v1beta does
// not require it, so a request may omit it.
TEST(GeminiInteractionsTest, InputForms) {
  PayloadSchema payload_schema = createPayloadSchema();

  EXPECT_THAT(payload_schema.validateRequest(withInput("Hello")), IsOk());
  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"({"type": "text", "text": "Hi"})"))),
              IsOk());
  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"([
    {"type": "text", "text": "What is in these?"},
    {"type": "image", "data": "aGVsbG8=", "mime_type": "image/png"},
    {"type": "audio", "uri": "https://example.com/a.wav", "mime_type": "audio/wav"},
    {"type": "video", "uri": "https://example.com/v.mp4"},
    {"type": "document", "data": "JVBERi0=", "mime_type": "application/pdf"}
  ])"))),
              IsOk());
  EXPECT_THAT(payload_schema.validateRequest(withInput(nlohmann::json::array())), IsOk());
  EXPECT_THAT(payload_schema.validateRequest(parse(R"({"model": "gemini-3-flash-preview"})")),
              IsOk());
}

// Steps replay a conversation, including the tool calls and results a previous response returned.
// A step kind this schema has never heard of is accepted.
TEST(GeminiInteractionsTest, InputSteps) {
  PayloadSchema payload_schema = createPayloadSchema();

  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"json([
    {"type": "user_input", "content": [{"type": "text", "text": "Weather in Boston?"}]},
    {"type": "thought", "signature": "c2ln", "summary": [{"type": "text", "text": "Look it up."}]},
    {"type": "function_call", "id": "call_1", "name": "get_weather",
     "arguments": {"location": "Boston, MA"}},
    {"type": "function_result", "call_id": "call_1", "name": "get_weather",
     "result": [{"type": "text", "text": "{\"weather\":\"sunny\"}"}]},
    {"type": "function_result", "call_id": "call_2", "result": "sunny", "is_error": false},
    {"type": "function_result", "call_id": "call_3", "result": {"temp_c": 21}},
    {"type": "code_execution_call", "id": "code_1", "arguments": {"code": "print(1)"}},
    {"type": "code_execution_result", "call_id": "code_1", "result": "1\n"},
    {"type": "google_search_call", "id": "search_1", "arguments": {"queries": ["boston"]}},
    {"type": "google_search_result", "call_id": "search_1",
     "result": [{"search_suggestions": "<div>boston</div>"}]},
    {"type": "model_output", "content": [{"type": "text", "text": "It is sunny."}]},
    {"type": "hologram_call", "id": "holo_1", "arguments": {}}
  ])json"))),
              IsOk());
}

TEST(GeminiInteractionsTest, InputRejectsMalformedContent) {
  PayloadSchema payload_schema = createPayloadSchema();

  // Text content requires its text, wherever it appears.
  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"({"type": "text"})"))),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"([{"type": "text"}])"))),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(payload_schema.validateRequest(
                  withInput(parse(R"([{"type": "user_input", "content": [{"type": "text"}]}])"))),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"({"type": "text", "text": 7})"))),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"([{"type": "image", "data": 7}])"))),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // A list holds content or steps, not both, and a content kind never reads as a step.
  const absl::Status mixed = payload_schema.validateRequest(withInput(parse(R"([
    {"type": "text", "text": "Hi"},
    {"type": "user_input", "content": [{"type": "text", "text": "Hi"}]}
  ])")));
  EXPECT_THAT(mixed, StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(mixed.message(), HasSubstr("'text' is a content type"));

  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"(["Hi"])"))),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(payload_schema.validateRequest(withInput(42)),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      payload_schema.validateRequest(withInput(parse(R"({"type": "user_input", "content": []})"))),
      StatusCodeIs(absl::StatusCode::kInvalidArgument));
}

TEST(GeminiInteractionsTest, StepMembersAreTypeChecked) {
  PayloadSchema payload_schema = createPayloadSchema();

  for (const absl::string_view step : {
           R"({"content": [{"type": "text", "text": "Hi"}]})",
           R"({"type": "user_input", "content": "Hi"})",
           R"({"type": "thought", "signature": 7})",
           R"({"type": "thought", "summary": {"type": "text", "text": "Hmm"}})",
           R"({"type": "function_call", "id": "c", "name": "f", "arguments": "{}"})",
           R"({"type": "function_result", "call_id": "c", "result": 42})",
           R"({"type": "function_result", "call_id": "c", "result": "ok", "is_error": "no"})",
       }) {
    nlohmann::json input = nlohmann::json::array({parse(step)});
    EXPECT_THAT(payload_schema.validateRequest(withInput(std::move(input))),
                StatusCodeIs(absl::StatusCode::kInvalidArgument))
        << step;
  }
}

// `temperature` and `top_p` are deprecated on v1beta but still type checked.
TEST(GeminiInteractionsTest, GenerationConfig) {
  PayloadSchema payload_schema = createPayloadSchema();

  auto with_config = [](absl::string_view config) {
    nlohmann::json request = withInput("Hi");
    request["generation_config"] = parse(config);
    return request;
  };

  for (const absl::string_view config : {
           R"({"temperature": 0.7, "top_p": 0.95})",
           R"({"tool_choice": "any"})",
           R"({"tool_choice": {"allowed_tools": {"mode": "validated", "tools": ["get_weather"]}}})",
           R"({"thinking_level": "high", "speech_config": [{"voice": "Kore"}]})",
       }) {
    EXPECT_THAT(payload_schema.validateRequest(with_config(config)), IsOk()) << config;
  }

  for (const absl::string_view config : {
           R"({"max_output_tokens": "1024"})",
           R"({"max_output_tokens": 10.5})",
           R"({"seed": true})",
           R"({"stop_sequences": "END"})",
           R"({"stop_sequences": [1]})",
           R"({"temperature": "0.7"})",
           R"({"thinking_level": 3})",
           R"({"thinking_summaries": false})",
           R"({"tool_choice": 3})",
           R"({"tool_choice": {"allowed_tools": {"tools": "get_weather"}}})",
       }) {
    EXPECT_THAT(payload_schema.validateRequest(with_config(config)),
                StatusCodeIs(absl::StatusCode::kInvalidArgument))
        << config;
  }

  nlohmann::json config_array = withInput("Hi");
  config_array["generation_config"] = nlohmann::json::array();
  EXPECT_THAT(payload_schema.validateRequest(config_array),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
}

TEST(GeminiInteractionsTest, ToolsSafetySettingsAndResponseFormat) {
  PayloadSchema payload_schema = createPayloadSchema();

  nlohmann::json request = withInput("Weather?");
  request["tools"] = parse(R"([
    {"type": "function", "name": "get_weather", "description": "Look up the weather.",
     "parameters": {"type": "object", "properties": {"location": {"type": "string"}}}},
    {"type": "google_search", "search_types": ["web_search"]},
    {"type": "code_execution"},
    {"type": "url_context"},
    {"type": "file_search", "file_search_store_names": ["fileSearchStores/a"], "top_k": 5},
    {"type": "mcp_server", "name": "docs", "url": "https://example.com/mcp",
     "headers": {"authorization": "Bearer t"}}
  ])");
  request["safety_settings"] =
      parse(R"([{"type": "harassment", "threshold": "block_only_high", "method": "severity"}])");
  request["response_format"] = parse(R"({"type": "text", "mime_type": "application/json"})");
  EXPECT_THAT(payload_schema.validateRequest(request), IsOk());

  request["response_format"] = parse(R"([{"type": "text"}, {"type": "image"}])");
  EXPECT_THAT(payload_schema.validateRequest(request), IsOk());

  for (const auto& [field, value] : std::vector<std::pair<std::string, std::string>>{
           {"tools", R"([{"name": "get_weather"}])"},
           {"tools", R"([{"type": "function", "description": 7}])"},
           {"tools", R"({"type": "code_execution"})"},
           {"safety_settings", R"([{"type": "harassment"}])"},
           {"safety_settings", R"([{"threshold": "off"}])"},
           {"response_format", R"("json")"},
           {"agent_config", R"({"thinking_summaries": "auto"})"},
           {"stream", R"("true")"},
           {"system_instruction", R"({"parts": [{"text": "Be concise."}]})"},
       }) {
    nlohmann::json bad = withInput("Hi");
    bad[field] = parse(value);
    EXPECT_THAT(payload_schema.validateRequest(bad),
                StatusCodeIs(absl::StatusCode::kInvalidArgument))
        << field << ": " << value;
  }
}

TEST(GeminiInteractionsTest, OffloadedValuesAccepted) {
  PayloadSchema payload_schema = createPayloadSchema();

  EXPECT_THAT(payload_schema.validateRequest(withInput(externalRef(50000))), IsOk());
  EXPECT_THAT(
      payload_schema.validateRequest(withInput({{"type", "text"}, {"text", externalRef(50000)}})),
      IsOk());

  nlohmann::json content_list = nlohmann::json::array({
      {{"type", "text"}, {"text", externalRef(50000)}},
      {{"type", "image"}, {"data", externalRef(900000)}, {"mime_type", "image/png"}},
      {{"type", "document"}, {"uri", externalRef(2000)}},
  });
  EXPECT_THAT(payload_schema.validateRequest(withInput(std::move(content_list))), IsOk());

  // Inside steps, including members left opaque: call arguments and a result's list items.
  nlohmann::json steps = nlohmann::json::array({
      {{"type", "user_input"},
       {"content", nlohmann::json::array({{{"type", "text"}, {"text", externalRef(50000)}}})}},
      {{"type", "thought"},
       {"signature", externalRef(4000)},
       {"summary", nlohmann::json::array({{{"type", "text"}, {"text", externalRef(3000)}}})}},
      {{"type", "code_execution_call"},
       {"id", "code_1"},
       {"arguments", {{"code", externalRef(8000)}}}},
      {{"type", "code_execution_result"}, {"call_id", "code_1"}, {"result", externalRef(9000)}},
      {{"type", "function_result"},
       {"call_id", "call_1"},
       {"result", nlohmann::json::array({{{"type", "text"}, {"text", externalRef(7000)}}})}},
      {{"type", "function_result"}, {"call_id", "call_2"}, {"result", externalRef(7000)}},
  });
  nlohmann::json request = withInput(std::move(steps));
  request["system_instruction"] = externalRef(3000);
  request["tools"] =
      nlohmann::json::array({{{"type", "function"}, {"description", externalRef(3000)}}});
  EXPECT_THAT(payload_schema.validateRequest(request), IsOk());
}

// Metadata stays inline, so an external reference in its place is rejected.
TEST(GeminiInteractionsTest, NonOffloadableFieldsRejectExternalRefs) {
  PayloadSchema payload_schema = createPayloadSchema();

  EXPECT_THAT(
      payload_schema.validateRequest(nlohmann::json{{"model", externalRef(2000)}, {"input", "Hi"}}),
      StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      payload_schema.validateRequest(nlohmann::json{{"agent", externalRef(2000)}, {"input", "Hi"}}),
      StatusCodeIs(absl::StatusCode::kInvalidArgument));

  nlohmann::json offloaded_id = withInput("Hi");
  offloaded_id["previous_interaction_id"] = externalRef(2000);
  EXPECT_THAT(payload_schema.validateRequest(offloaded_id),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(payload_schema.validateRequest(withInput(nlohmann::json::array(
                  {{{"type", "image"}, {"data", "aGk="}, {"mime_type", externalRef(2000)}}}))),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      payload_schema.validateRequest(withInput(nlohmann::json::array(
          {{{"type", "function_result"}, {"call_id", externalRef(2000)}, {"result", "ok"}}}))),
      StatusCodeIs(absl::StatusCode::kInvalidArgument));
}

// An offloaded value under a field the schema does not declare is never traversed.
TEST(GeminiInteractionsTest, OffloadedValueInUndeclaredFieldIsAccepted) {
  PayloadSchema payload_schema = createPayloadSchema();

  nlohmann::json request = withInput("Hi");
  request["environment"] = {{"type", "remote"},
                            {"sources", nlohmann::json::array({{{"content", externalRef(5000)}}})}};
  EXPECT_THAT(payload_schema.validateRequest(request), IsOk());
}

TEST(GeminiInteractionsTest, ExplicitNullsOnOptionalFields) {
  PayloadSchema payload_schema = createPayloadSchema();

  EXPECT_THAT(payload_schema.validateRequest(parse(R"({
    "model": "gemini-3-flash-preview",
    "agent": null,
    "input": null,
    "system_instruction": null,
    "tools": null,
    "response_format": null,
    "stream": null,
    "store": null,
    "background": null,
    "generation_config": null,
    "agent_config": null,
    "previous_interaction_id": null,
    "safety_settings": null,
    "service_tier": null
  })")),
              IsOk());

  nlohmann::json null_config = withInput("Hi");
  null_config["generation_config"] = parse(R"({
    "max_output_tokens": null, "seed": null, "stop_sequences": null, "temperature": null,
    "top_p": null, "thinking_level": null, "thinking_summaries": null, "tool_choice": null
  })");
  EXPECT_THAT(payload_schema.validateRequest(null_config), IsOk());

  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"([
    {"type": "image", "data": null, "uri": "https://example.com/i.png", "mime_type": null}
  ])"))),
              IsOk());
  EXPECT_THAT(payload_schema.validateRequest(withInput(parse(R"([
    {"type": "function_result", "call_id": "c", "name": null, "result": null, "is_error": null,
     "content": null, "summary": null, "signature": null, "id": null, "arguments": null}
  ])"))),
              IsOk());
}

// Null is still rejected where a value is required, and as a list element.
TEST(GeminiInteractionsTest, NullRejectedWhereRequired) {
  PayloadSchema payload_schema = createPayloadSchema();

  for (const absl::string_view input : {
           R"({"type": "text", "text": null})",
           R"([{"type": null}])",
           R"([null])",
           R"([{"type": "user_input", "content": [null]}])",
       }) {
    EXPECT_THAT(payload_schema.validateRequest(withInput(parse(input))),
                StatusCodeIs(absl::StatusCode::kInvalidArgument))
        << input;
  }

  nlohmann::json null_tool_type = withInput("Hi");
  null_tool_type["tools"] = parse(R"([{"type": null}])");
  EXPECT_THAT(payload_schema.validateRequest(null_tool_type),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
}

// Undeclared fields pass, so a field the API gains is not rejected here.
TEST(GeminiInteractionsTest, UnknownFieldsPassThrough) {
  PayloadSchema payload_schema = createPayloadSchema();

  EXPECT_THAT(payload_schema.validateRequest(parse(R"({
    "model": "gemini-3-flash-preview",
    "input": [
      {"type": "text", "text": "Hi", "annotations": []},
      {"type": "video", "uri": "gs://bucket/v.mp4", "resolution": "low", "processing": "static"}
    ],
    "environment": "env_123",
    "labels": {"team": "search"},
    "webhook_config": {"uris": ["https://example.com/hook"]},
    "response_modalities": ["text"],
    "generation_config": {"video_config": {"task": "edit"}}
  })")),
              IsOk());
}

// Pins the hand-written list against the schema walk. Any field added, removed or reordered
// in the schema changes the walk order and must be mirrored here.
TEST(GeminiInteractionsTest, CanonicalStreamableFieldOrder) {
  PayloadSchema payload_schema = createPayloadSchema();
  const std::vector<std::string> expected_order = {
      "input",
      "input.text",
      "input.data",
      "input.uri",
      "input[].text",
      "input[].data",
      "input[].uri",
      "input[].content[].text",
      "input[].content[].data",
      "input[].content[].uri",
      "input[].summary[].text",
      "input[].summary[].data",
      "input[].summary[].uri",
      "input[].signature",
      "input[].result",
      "system_instruction",
      "tools[].description",
  };
  EXPECT_EQ(payload_schema.requestStreamableFieldOrder(), expected_order);
  EXPECT_EQ(payload_schema.requestOffloadableFieldPaths(), expected_order);
}

TEST(GeminiInteractionsTest, SubSchemasDirectValidation) {
  EXPECT_THAT(contentSchema().validate(parse(R"({"type": "audio", "uri": "gs://b/a.wav"})")),
              IsOk());
  EXPECT_THAT(contentSchema().validate(parse(R"({"type": "user_input"})")),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(stepSchema().validate(parse(R"({"type": "model_output", "content": []})")), IsOk());
  EXPECT_THAT(stepSchema().validate(parse(R"({"type": "document"})")),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(toolSchema().validate(parse(R"({"type": "google_maps", "latitude": 1.5})")), IsOk());
  EXPECT_THAT(toolSchema().validate(parse(R"({"name": "f"})")),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(generationConfigSchema().validate(parse(R"({"seed": 1})")), IsOk());
  EXPECT_THAT(generationConfigSchema().validate(nlohmann::json(nullptr)), IsOk());
  EXPECT_THAT(generationConfigSchema().validate(parse(R"({"seed": "1"})")),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
}

} // namespace
} // namespace GeminiInteractions
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
