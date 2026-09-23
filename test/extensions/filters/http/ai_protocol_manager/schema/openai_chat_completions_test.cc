#include <string>
#include <utility>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/filters/http/ai_protocol_manager/schema/openai_chat_completions.h"

#include "test/test_common/status_utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace OpenAI {
namespace {

using StatusHelpers::IsOk;
using StatusHelpers::StatusCodeIs;

TEST(OpenAiChatCompletionsTest, StandardValidPayload) {
  PayloadSchema payload_schema = createPayloadSchema();

  nlohmann::json valid_req = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array({
                       {{"role", "system"}, {"content", "You are a helpful assistant."}},
                       {{"role", "user"}, {"content", "Hello!"}},
                   })},
      {"temperature", 0.7},
      {"max_tokens", 100},
      {"stream", false},
  };
  EXPECT_THAT(payload_schema.validateRequest(valid_req), IsOk());
}

TEST(OpenAiChatCompletionsTest, OffloadedMessageContent) {
  PayloadSchema payload_schema = createPayloadSchema();

  nlohmann::json offloaded_req = {
      {"model", "gpt-4o"},
      {"messages",
       nlohmann::json::array({
           {{"role", "user"},
            {"content", JsonWithExtBuf::makeExternalRef(JsonWithExtBuf::ExternalRef{100, 50000})}},
       })},
  };
  EXPECT_THAT(payload_schema.validateRequest(offloaded_req), IsOk());
}

TEST(OpenAiChatCompletionsTest, MultimodalContentParts) {
  PayloadSchema payload_schema = createPayloadSchema();

  nlohmann::json multimodal_req = {
      {"model", "gpt-4o"},
      {"messages",
       nlohmann::json::array(
           {{{"role", "user"},
             {"content",
              nlohmann::json::array(
                  {{{"type", "text"}, {"text", "What is in this image?"}},
                   {{"type", "image_url"},
                    {"image_url", {{"url", "https://example.com/image.png"}}}},
                   {{"type", "image_url"},
                    {"image_url",
                     {{"url", "data:image/jpeg;base64,/9j/4AAQSkZJRg..."}, {"detail", "high"}}}},
                   {{"type", "image_url"},
                    {"image_url",
                     {{"url",
                       JsonWithExtBuf::makeExternalRef(JsonWithExtBuf::ExternalRef{100, 50000})},
                      {"detail", "auto"}}}}})}}})},
  };
  EXPECT_THAT(payload_schema.validateRequest(multimodal_req), IsOk());
}

TEST(OpenAiChatCompletionsTest, ToolsAndToolCalls) {
  PayloadSchema payload_schema = createPayloadSchema();

  nlohmann::json tools_req = {
      {"model", "gpt-4o"},
      {"messages",
       nlohmann::json::array({
           {{"role", "assistant"},
            {"tool_calls", nlohmann::json::array({
                               {{"id", "call_123"},
                                {"type", "function"},
                                {"function",
                                 {{"name", "get_weather"},
                                  {"arguments", JsonWithExtBuf::makeExternalRef(
                                                    JsonWithExtBuf::ExternalRef{500, 200})}}}},
                           })}},
       })},
      {"tools",
       nlohmann::json::array({
           {{"type", "function"},
            {"function",
             {{"name", "get_weather"},
              {"description", "Get current weather"},
              {"parameters", {{"type", "object"}, {"properties", {{"location", "string"}}}}}}}},
       })},
      {"tool_choice", "auto"},
  };
  EXPECT_THAT(payload_schema.validateRequest(tools_req), IsOk());
}

TEST(OpenAiChatCompletionsTest, UnknownFieldsPassThrough) {
  PayloadSchema payload_schema = createPayloadSchema();

  nlohmann::json custom_fields_req = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array({
                       {{"role", "user"}, {"content", "Hi"}},
                   })},
      {"custom_routing_tag", "blue"},
      {"user_tracking_id", 9999},
  };
  EXPECT_THAT(payload_schema.validateRequest(custom_fields_req), IsOk());
}

TEST(OpenAiChatCompletionsTest, MissingRequiredFields) {
  PayloadSchema payload_schema = createPayloadSchema();

  // Missing required model.
  nlohmann::json missing_model = {
      {"messages", nlohmann::json::array({
                       {{"role", "user"}, {"content", "Hi"}},
                   })},
  };
  EXPECT_THAT(payload_schema.validateRequest(missing_model),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Missing required messages.
  nlohmann::json missing_messages = {
      {"model", "gpt-4o"},
  };
  EXPECT_THAT(payload_schema.validateRequest(missing_messages),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Empty messages array (min size is 1).
  nlohmann::json empty_messages = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array()},
  };
  EXPECT_THAT(payload_schema.validateRequest(empty_messages),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Missing required role in message.
  nlohmann::json missing_role = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array({
                       {{"content", "Hi"}},
                   })},
  };
  auto role_err = payload_schema.validateRequest(missing_role);
  EXPECT_THAT(role_err, StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_EQ(role_err.message(), "missing required field: messages[0].role");

  // Missing required url in image_url part.
  nlohmann::json missing_image_url = {
      {"model", "gpt-4o"},
      {"messages",
       nlohmann::json::array({
           {{"role", "user"},
            {"content", nlohmann::json::array({
                            {{"type", "image_url"}, {"image_url", {{"detail", "high"}}}},
                        })}},
       })},
  };
  auto img_err = payload_schema.validateRequest(missing_image_url);
  EXPECT_THAT(img_err, StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(img_err.message(),
              testing::HasSubstr("missing required field: messages[0].content[0].image_url.url"));
}

TEST(OpenAiChatCompletionsTest, CanonicalStreamableFieldOrder) {
  PayloadSchema payload_schema = createPayloadSchema();
  const std::vector<std::string> expected_order = {
      "messages[].content",
      "messages[].content[].text",
      "messages[].content[].image_url.url",
      "messages[].tool_calls[].function.arguments",
      "tools[].function.description",
  };
  EXPECT_EQ(payload_schema.requestStreamableFieldOrder(), expected_order);
  EXPECT_EQ(payload_schema.requestOffloadableFieldPaths(), expected_order);
}

TEST(OpenAiChatCompletionsTest, InvalidFieldValuesAndTypes) {
  PayloadSchema payload_schema = createPayloadSchema();

  // Invalid role enum value.
  nlohmann::json invalid_role = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array({
                       {{"role", "admin"}, {"content", "Hi"}},
                   })},
  };
  EXPECT_THAT(payload_schema.validateRequest(invalid_role),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Invalid model offload (model cannot be an ExternalRef).
  nlohmann::json offloaded_model = {
      {"model", JsonWithExtBuf::makeExternalRef(JsonWithExtBuf::ExternalRef{0, 100})},
      {"messages", nlohmann::json::array({
                       {{"role", "user"}, {"content", "Hi"}},
                   })},
  };
  EXPECT_THAT(payload_schema.validateRequest(offloaded_model),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Temperature out of bounds.
  nlohmann::json high_temp = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array({
                       {{"role", "user"}, {"content", "Hi"}},
                   })},
      {"temperature", 2.5},
  };
  EXPECT_THAT(payload_schema.validateRequest(high_temp),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Invalid image_url.url type (e.g., integer instead of string or ExternalRef).
  nlohmann::json invalid_image_url_type = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array({
                       {{"role", "user"},
                        {"content", nlohmann::json::array({
                                        {{"type", "image_url"}, {"image_url", {{"url", 12345}}}},
                                    })}},
                   })},
  };
  EXPECT_THAT(payload_schema.validateRequest(invalid_image_url_type),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Non-offloadable field in image_url (e.g. detail) cannot be an ExternalRef.
  nlohmann::json offloaded_detail = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array({
                       {{"role", "user"},
                        {"content", nlohmann::json::array({
                                        {{"type", "image_url"},
                                         {"image_url",
                                          {{"url", "https://example.com/image.png"},
                                           {"detail", JsonWithExtBuf::makeExternalRef(
                                                          JsonWithExtBuf::ExternalRef{0, 10})}}}},
                                    })}},
                   })},
  };
  auto detail_err = payload_schema.validateRequest(offloaded_detail);
  EXPECT_THAT(detail_err, StatusCodeIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(detail_err.message(),
              testing::HasSubstr("field 'messages[0].content[0].image_url.detail' cannot be "
                                 "offloaded to external buffer"));
}

TEST(OpenAiChatCompletionsTest, SubSchemasDirectValidation) {
  // Test toolCallSchema directly.
  const Schema& tool_call_schema = toolCallSchema();
  nlohmann::json valid_tool_call = {
      {"id", "call_1"},
      {"type", "function"},
      {"function",
       {{"name", "search"},
        {"arguments", JsonWithExtBuf::makeExternalRef(JsonWithExtBuf::ExternalRef{0, 100})}}},
  };
  EXPECT_THAT(tool_call_schema.validate(valid_tool_call), IsOk());

  nlohmann::json invalid_tool_call = {
      {"id", "call_1"},
      {"type", "unknown_type"},
  };
  EXPECT_THAT(tool_call_schema.validate(invalid_tool_call),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Test chatMessageSchema directly.
  const Schema& chat_message_schema = chatMessageSchema();
  nlohmann::json valid_msg = {
      {"role", "assistant"}, {"content", "Hello"},       {"refusal", "Cannot comply"},
      {"name", "bot"},       {"tool_call_id", "call_1"},
  };
  EXPECT_THAT(chat_message_schema.validate(valid_msg), IsOk());

  // Direct validation of chatMessageSchema with offloaded image_url.
  nlohmann::json multimodal_msg = {
      {"role", "user"},
      {"content",
       nlohmann::json::array({
           {{"type", "image_url"},
            {"image_url",
             {{"url", JsonWithExtBuf::makeExternalRef(JsonWithExtBuf::ExternalRef{100, 5000})}}}},
       })},
  };
  EXPECT_THAT(chat_message_schema.validate(multimodal_msg), IsOk());

  nlohmann::json msg_invalid_role = {
      {"role", "superadmin"},
  };
  EXPECT_THAT(chat_message_schema.validate(msg_invalid_role),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Test toolSchema directly.
  const Schema& tool_schema = toolSchema();
  nlohmann::json valid_tool = {
      {"type", "function"},
      {"function",
       {{"name", "fetch_info"},
        {"description", JsonWithExtBuf::makeExternalRef(JsonWithExtBuf::ExternalRef{0, 50})}}},
  };
  EXPECT_THAT(tool_schema.validate(valid_tool), IsOk());

  nlohmann::json invalid_tool = {
      {"type", "not_a_function"},
  };
  EXPECT_THAT(tool_schema.validate(invalid_tool), StatusCodeIs(absl::StatusCode::kInvalidArgument));

  // Test toolSchema with nullable optional fields.
  nlohmann::json null_fields_tool = {
      {"type", "function"},
      {"function", {{"name", "fetch_info"}, {"description", nullptr}, {"strict", nullptr}}},
  };
  EXPECT_THAT(tool_schema.validate(null_fields_tool), IsOk());
}

TEST(OpenAiChatCompletionsTest, NullableFieldsValidation) {
  PayloadSchema payload_schema = createPayloadSchema();

  // Full request payload with all optional fields explicitly set to null.
  nlohmann::json null_fields_req = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array({
                       {{"role", "user"},
                        {"content", nullptr},
                        {"name", nullptr},
                        {"tool_call_id", nullptr},
                        {"tool_calls", nullptr}},
                   })},
      {"temperature", nullptr},
      {"top_p", nullptr},
      {"n", nullptr},
      {"stream", nullptr},
      {"stop", nullptr},
      {"max_tokens", nullptr},
      {"max_completion_tokens", nullptr},
      {"presence_penalty", nullptr},
      {"frequency_penalty", nullptr},
      {"logit_bias", nullptr},
      {"user", nullptr},
      {"tools", nullptr},
      {"tool_choice", nullptr},
      {"response_format", nullptr},
      {"seed", nullptr},
      {"service_tier", nullptr},
      {"stream_options", nullptr},
      {"parallel_tool_calls", nullptr},
      {"logprobs", nullptr},
      {"top_logprobs", nullptr},
      {"reasoning_effort", nullptr},
      {"store", nullptr},
      {"metadata", nullptr},
      {"modalities", nullptr},
      {"prediction", nullptr},
      {"audio", nullptr},
      {"web_search_options", nullptr},
      {"verbosity", nullptr},
      {"prompt_cache_key", nullptr},
      {"safety_identifier", nullptr},
      {"functions", nullptr},
      {"function_call", nullptr},
  };
  EXPECT_THAT(payload_schema.validateRequest(null_fields_req), IsOk());

  // Non-nullable fields set to null must be rejected.
  nlohmann::json null_model = {
      {"model", nullptr},
      {"messages", nlohmann::json::array({
                       {{"role", "user"}, {"content", "Hi"}},
                   })},
  };
  EXPECT_THAT(payload_schema.validateRequest(null_model),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  nlohmann::json null_messages = {
      {"model", "gpt-4o"},
      {"messages", nullptr},
  };
  EXPECT_THAT(payload_schema.validateRequest(null_messages),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));

  nlohmann::json null_role = {
      {"model", "gpt-4o"},
      {"messages", nlohmann::json::array({
                       {{"role", nullptr}, {"content", "Hi"}},
                   })},
  };
  EXPECT_THAT(payload_schema.validateRequest(null_role),
              StatusCodeIs(absl::StatusCode::kInvalidArgument));
}

// A transcoder prunes a request to the fields its target declares, so every well-known request
// parameter must be declared here or a conversion to OpenAI would drop it.
TEST(OpenAiChatCompletionsTest, WellKnownRequestParameters) {
  PayloadSchema payload_schema = createPayloadSchema();

  nlohmann::json request = nlohmann::json::parse(R"({
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hi"}],
    "stream": true,
    "stream_options": {"include_usage": true, "include_obfuscation": false},
    "parallel_tool_calls": false,
    "logprobs": true,
    "top_logprobs": 3,
    "reasoning_effort": "low",
    "store": true,
    "metadata": {"purpose": "eval"},
    "modalities": ["text", "audio"],
    "prediction": {"type": "content", "content": "draft"},
    "audio": {"voice": "alloy", "format": "mp3"},
    "web_search_options": {"search_context_size": "low"},
    "verbosity": "medium",
    "prompt_cache_key": "cache-1",
    "safety_identifier": "user-hash",
    "functions": [{"name": "f", "parameters": {"type": "object"}}],
    "function_call": {"name": "f"}
  })",
                                                 nullptr, /*allow_exceptions=*/false);
  ASSERT_FALSE(request.is_discarded());
  EXPECT_THAT(payload_schema.validateRequest(request), IsOk());

  request["function_call"] = "auto";
  EXPECT_THAT(payload_schema.validateRequest(request), IsOk());

  std::vector<std::string> declared;
  for (const Schema::Property& property :
       payload_schema.requestSchema().rootSchema().properties()) {
    declared.push_back(property.name);
  }
  for (const auto& [key, value] : request.items()) {
    EXPECT_THAT(declared, testing::Contains(key));
  }
}

TEST(OpenAiChatCompletionsTest, WellKnownRequestParametersAreTypeChecked) {
  PayloadSchema payload_schema = createPayloadSchema();

  const std::vector<std::pair<std::string, nlohmann::json>> invalid = {
      {"stream_options", "include_usage"},
      {"stream_options", {{"include_usage", "yes"}}},
      {"parallel_tool_calls", "false"},
      {"logprobs", 1},
      {"top_logprobs", "3"},
      {"reasoning_effort", 1},
      {"store", "true"},
      {"metadata", nlohmann::json::array()},
      {"modalities", nlohmann::json::array({"text", 1})},
      {"prediction", "draft"},
      {"audio", "alloy"},
      {"web_search_options", true},
      {"verbosity", 2},
      {"prompt_cache_key", 3},
      {"safety_identifier", nlohmann::json::object()},
      {"functions", nlohmann::json::object()},
      {"functions", nlohmann::json::array({"f"})},
      {"function_call", 1},
  };
  for (const auto& [field, value] : invalid) {
    nlohmann::json request = {
        {"model", "gpt-4o"},
        {"messages", nlohmann::json::array({{{"role", "user"}, {"content", "Hi"}}})},
    };
    request[field] = value;
    EXPECT_THAT(payload_schema.validateRequest(request),
                StatusCodeIs(absl::StatusCode::kInvalidArgument))
        << field << ": " << value.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
  }
}

} // namespace
} // namespace OpenAI
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
