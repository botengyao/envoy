#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "source/extensions/http/ai_filters/transcoder/response/anthropic.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {
namespace {

constexpr int64_t kCreated = 1758650000;

ResponseContext makeContext(bool include_usage = false, bool always_report_usage = true) {
  ResponseContext context;
  context.model = "requested-model";
  context.created = kCreated;
  context.include_usage = include_usage;
  context.always_report_usage = always_report_usage;
  return context;
}

nlohmann::json parse(absl::string_view text) {
  nlohmann::json json = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
  EXPECT_FALSE(json.is_discarded()) << text;
  return json;
}

nlohmann::json offloaded() { return nlohmann::json::binary({1, 2, 3, 4}, 0xea1eb); }

// Splits an SSE transcript into frames, one per `data:` line; indentation is ignored.
std::vector<SseFrame> parseSse(absl::string_view transcript) {
  std::vector<SseFrame> frames;
  std::string event;
  std::optional<std::string> data;
  const auto flush = [&]() {
    if (data.has_value()) {
      nlohmann::json json = nlohmann::json::parse(*data, nullptr, /*allow_exceptions=*/false);
      EXPECT_FALSE(json.is_discarded() && absl::StartsWith(*data, "{")) << *data;
      frames.push_back(json.is_discarded() ? SseFrame::ofData(*data, event)
                                           : SseFrame::ofJson(std::move(json), event));
    }
    event.clear();
    data.reset();
  };
  for (absl::string_view line : absl::StrSplit(transcript, '\n')) {
    line = absl::StripAsciiWhitespace(line);
    if (line.empty()) {
      flush();
    } else if (absl::ConsumePrefix(&line, "event:")) {
      flush();
      event = std::string(absl::StripLeadingAsciiWhitespace(line));
    } else if (absl::ConsumePrefix(&line, "data:")) {
      if (data.has_value()) {
        flush();
      }
      data = std::string(absl::StripLeadingAsciiWhitespace(line));
    }
  }
  flush();
  return frames;
}

std::vector<SseFrame> run(StreamConverter& converter, std::vector<SseFrame> frames) {
  std::vector<SseFrame> out;
  for (SseFrame& frame : frames) {
    EXPECT_TRUE(converter.onFrame(std::move(frame), out).ok());
  }
  EXPECT_TRUE(converter.onEnd(out).ok());
  return out;
}

std::vector<SseFrame> anthropicToOpenAi(absl::string_view transcript,
                                        const ResponseContext& context = makeContext()) {
  StreamConverterPtr converter = createAnthropicToOpenAiStreamConverter(context);
  return run(*converter, parseSse(transcript));
}

std::vector<SseFrame> openAiToAnthropic(absl::string_view transcript,
                                        const ResponseContext& context = makeContext()) {
  StreamConverterPtr converter = createOpenAiToAnthropicStreamConverter(context);
  return run(*converter, parseSse(transcript));
}

// OpenAI frames have no event name; "[DONE]" is kept as its raw data.
nlohmann::json openAiPayloads(const std::vector<SseFrame>& frames) {
  nlohmann::json payloads = nlohmann::json::array();
  for (const SseFrame& frame : frames) {
    EXPECT_EQ(frame.event, "");
    payloads.push_back(frame.json.has_value() ? *frame.json : nlohmann::json(frame.data));
  }
  return payloads;
}

// Anthropic frames are named after their payload's type.
nlohmann::json anthropicPayloads(const std::vector<SseFrame>& frames) {
  nlohmann::json payloads = nlohmann::json::array();
  for (const SseFrame& frame : frames) {
    EXPECT_TRUE(frame.json.has_value());
    if (frame.json.has_value()) {
      EXPECT_EQ(frame.event, frame.json->value("type", ""));
      payloads.push_back(*frame.json);
    }
  }
  return payloads;
}

nlohmann::json chunk(const std::string& id, const std::string& model, nlohmann::json delta,
                     nlohmann::json finish_reason = nullptr) {
  nlohmann::json choice = {{"index", 0},
                           {"delta", std::move(delta)},
                           {"logprobs", nullptr},
                           {"finish_reason", std::move(finish_reason)}};
  return {{"id", id},
          {"object", "chat.completion.chunk"},
          {"created", kCreated},
          {"model", model},
          {"choices", nlohmann::json::array({std::move(choice)})}};
}

// Folds an OpenAI chunk stream into what a client ends up with.
nlohmann::json accumulateOpenAi(const std::vector<SseFrame>& frames) {
  std::string content;
  nlohmann::json tool_calls = nlohmann::json::array();
  nlohmann::json finish_reason;
  nlohmann::json usage;
  bool done = false;
  for (const SseFrame& frame : frames) {
    if (!frame.json.has_value()) {
      done = frame.data == "[DONE]";
      continue;
    }
    nlohmann::json payload = *frame.json;
    if (payload.contains("usage") && !payload["usage"].is_null()) {
      usage = payload["usage"];
    }
    for (nlohmann::json& choice : payload["choices"]) {
      nlohmann::json& delta = choice["delta"];
      if (delta.contains("content") && delta["content"].is_string()) {
        content += delta["content"].get<std::string>();
      }
      for (nlohmann::json& call : delta["tool_calls"]) {
        const size_t index = call["index"].get<size_t>();
        while (tool_calls.size() <= index) {
          tool_calls.push_back(nlohmann::json{{"id", ""}, {"name", ""}, {"arguments", ""}});
        }
        nlohmann::json& accumulated = tool_calls[index];
        if (call.contains("id")) {
          accumulated["id"] = call["id"];
        }
        nlohmann::json& function = call["function"];
        if (function.contains("name")) {
          accumulated["name"] = function["name"];
        }
        if (function.contains("arguments")) {
          accumulated["arguments"] = accumulated["arguments"].get<std::string>() +
                                     function["arguments"].get<std::string>();
        }
      }
      if (!choice["finish_reason"].is_null()) {
        finish_reason = choice["finish_reason"];
      }
    }
  }
  return {{"content", content},
          {"tool_calls", tool_calls},
          {"finish_reason", finish_reason},
          {"usage", usage},
          {"done", done}};
}

constexpr absl::string_view kTextStream = R"(
  event: message_start
  data: {"type":"message_start","message":{"id":"msg_01XFDUDYJgAACzvnptvVoYEL","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-5-20250929","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":25,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":1}}}

  event: content_block_start
  data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

  event: ping
  data: {"type": "ping"}

  event: content_block_delta
  data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

  event: content_block_delta
  data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"!"}}

  event: content_block_stop
  data: {"type":"content_block_stop","index":0}

  event: message_delta
  data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":15}}

  event: message_stop
  data: {"type":"message_stop"}
)";

constexpr absl::string_view kToolStream = R"(
  event: message_start
  data: {"type":"message_start","message":{"id":"msg_014p7gG3wDgGV9EUtLvnow3U","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","stop_sequence":null,"usage":{"input_tokens":472,"cache_creation_input_tokens":30,"cache_read_input_tokens":200,"output_tokens":2},"content":[],"stop_reason":null}}

  event: content_block_start
  data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}

  event: content_block_delta
  data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"The user wants the weather and the time."}}

  event: content_block_delta
  data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"EqQBCgIYAhIM1gbcDa9GJwZA2b3h"}}

  event: content_block_stop
  data: {"type":"content_block_stop","index":0}

  event: content_block_start
  data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}

  event: content_block_delta
  data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Checking both."}}

  event: content_block_delta
  data: {"type":"content_block_delta","index":1,"delta":{"type":"citations_delta","citation":{"type":"char_location","cited_text":"x"}}}

  event: content_block_stop
  data: {"type":"content_block_stop","index":1}

  event: content_block_start
  data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_01T1x1fJ34qAmk2tNTrN7Up6","name":"get_weather","input":{}}}

  event: content_block_delta
  data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":""}}

  event: content_block_delta
  data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"location\": \"San Fra"}}

  event: content_block_delta
  data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"ncisco, CA\"}"}}

  event: content_block_stop
  data: {"type":"content_block_stop","index":2}

  event: content_block_start
  data: {"type":"content_block_start","index":3,"content_block":{"type":"tool_use","id":"toolu_01VtGx9Ka9sLo1Ai3JvYpY2a","name":"get_time","input":{}}}

  event: content_block_delta
  data: {"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":"{\"tz\": \"PST\"}"}}

  event: content_block_stop
  data: {"type":"content_block_stop","index":3}

  event: message_delta
  data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":89}}

  event: message_stop
  data: {"type":"message_stop"}
)";

constexpr absl::string_view kOpenAiTextStream = R"(
  data: {"id":"chatcmpl-C8xAbc","object":"chat.completion.chunk","created":1758650001,"model":"gpt-4o-2024-08-06","system_fingerprint":"fp_1","choices":[{"index":0,"delta":{"role":"assistant","content":"","refusal":null},"logprobs":null,"finish_reason":null}],"usage":null}

  data: {"id":"chatcmpl-C8xAbc","object":"chat.completion.chunk","created":1758650001,"model":"gpt-4o-2024-08-06","system_fingerprint":"fp_1","choices":[{"index":0,"delta":{"content":"Hello"},"logprobs":null,"finish_reason":null}],"usage":null}

  data: {"id":"chatcmpl-C8xAbc","object":"chat.completion.chunk","created":1758650001,"model":"gpt-4o-2024-08-06","system_fingerprint":"fp_1","choices":[{"index":0,"delta":{"content":" world"},"logprobs":null,"finish_reason":null}],"usage":null}

  data: {"id":"chatcmpl-C8xAbc","object":"chat.completion.chunk","created":1758650001,"model":"gpt-4o-2024-08-06","system_fingerprint":"fp_1","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"stop"}],"usage":null}

  data: {"id":"chatcmpl-C8xAbc","object":"chat.completion.chunk","created":1758650001,"model":"gpt-4o-2024-08-06","system_fingerprint":"fp_1","choices":[],"usage":{"prompt_tokens":19,"completion_tokens":10,"total_tokens":29,"prompt_tokens_details":{"cached_tokens":0}}}

  data: [DONE]
)";

constexpr absl::string_view kOpenAiToolStream = R"(
  data: {"id":"chatcmpl-T1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":null},"finish_reason":null}]}

  data: {"id":"chatcmpl-T1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Let me check."},"finish_reason":null}]}

  data: {"id":"chatcmpl-T1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}

  data: {"id":"chatcmpl-T1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]},"finish_reason":null}]}

  data: {"id":"chatcmpl-T1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Paris\"}"}}]},"finish_reason":null}]}

  data: {"id":"chatcmpl-T1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","type":"function","function":{"name":"get_time","arguments":""}}]},"finish_reason":null}]}

  data: {"id":"chatcmpl-T1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"tz\":\"CET\"}"}}]},"finish_reason":null}]}

  data: {"id":"chatcmpl-T1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

  data: {"id":"chatcmpl-T1","object":"chat.completion.chunk","created":1,"model":"gpt-4o","choices":[],"usage":{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"prompt_tokens_details":{"cached_tokens":100}}}

  data: [DONE]
)";

TEST(AnthropicToOpenAiUnaryTest, TextToolsAndThinking) {
  nlohmann::json body = parse(R"({
    "id": "msg_01Aq9w938a90dw8q",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-4-5-20250929",
    "content": [
      {"type": "thinking", "thinking": "Let me think.", "signature": "sig"},
      {"type": "text", "text": "I'll check "},
      {"type": "redacted_thinking", "data": "abc"},
      {"type": "text", "text": "the weather."},
      {"type": "tool_use", "id": "toolu_01A", "name": "get_weather",
       "input": {"location": "San Francisco, CA", "unit": "celsius"}},
      {"type": "tool_use", "id": "toolu_01B", "name": "get_time", "input": {}}
    ],
    "stop_reason": "tool_use",
    "stop_sequence": null,
    "usage": {"input_tokens": 2095, "cache_creation_input_tokens": 10,
              "cache_read_input_tokens": 500, "output_tokens": 503}
  })");
  absl::StatusOr<nlohmann::json> converted =
      convertAnthropicToOpenAiUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok()) << converted.status();
  EXPECT_EQ(*converted, parse(R"({
    "id": "msg_01Aq9w938a90dw8q",
    "object": "chat.completion",
    "created": 1758650000,
    "model": "claude-sonnet-4-5-20250929",
    "choices": [{
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "I'll check the weather.",
        "tool_calls": [
          {"id": "toolu_01A", "type": "function",
           "function": {"name": "get_weather",
                        "arguments": "{\"location\":\"San Francisco, CA\",\"unit\":\"celsius\"}"}},
          {"id": "toolu_01B", "type": "function",
           "function": {"name": "get_time", "arguments": "{}"}}
        ]
      },
      "finish_reason": "tool_calls",
      "logprobs": null
    }],
    "usage": {"prompt_tokens": 2605, "completion_tokens": 503, "total_tokens": 3108,
              "prompt_tokens_details": {"cached_tokens": 500}}
  })"));
}

TEST(AnthropicToOpenAiUnaryTest, TextOnlyWithoutCacheFields) {
  nlohmann::json body = parse(R"({
    "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-haiku-4-5",
    "content": [{"type": "text", "text": "Hi there."}],
    "stop_reason": "end_turn", "stop_sequence": null,
    "usage": {"input_tokens": 12, "output_tokens": 4}
  })");
  absl::StatusOr<nlohmann::json> converted =
      convertAnthropicToOpenAiUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(*converted, parse(R"({
    "id": "msg_1", "object": "chat.completion", "created": 1758650000,
    "model": "claude-haiku-4-5",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi there."},
                 "finish_reason": "stop", "logprobs": null}],
    "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16}
  })"));
}

TEST(AnthropicToOpenAiUnaryTest, ToolCallsWithoutTextHaveNullContent) {
  nlohmann::json body = parse(R"({
    "id": "msg_2", "model": "claude-sonnet-4-5",
    "content": [{"type": "text", "text": ""},
                {"type": "tool_use", "id": "toolu_1", "name": "ping", "input": null},
                {"type": "tool_use", "id": "toolu_2", "name": "pong"}],
    "stop_reason": "tool_use"
  })");
  absl::StatusOr<nlohmann::json> converted =
      convertAnthropicToOpenAiUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok());
  nlohmann::json& message = (*converted)["choices"][0]["message"];
  EXPECT_TRUE(message["content"].is_null());
  EXPECT_EQ(message["tool_calls"], parse(R"([
    {"id": "toolu_1", "type": "function", "function": {"name": "ping", "arguments": "{}"}},
    {"id": "toolu_2", "type": "function", "function": {"name": "pong", "arguments": "{}"}}
  ])"));
}

TEST(AnthropicToOpenAiUnaryTest, NoContentIsEmptyString) {
  absl::StatusOr<nlohmann::json> converted = convertAnthropicToOpenAiUnary(
      parse(R"({"content": [], "stop_reason": "max_tokens"})"), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(*converted, parse(R"({
    "id": "", "object": "chat.completion", "created": 1758650000, "model": "requested-model",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": ""},
                 "finish_reason": "length", "logprobs": null}],
    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
  })"));
}

TEST(AnthropicToOpenAiUnaryTest, MalformedBlocksAreSkipped) {
  nlohmann::json body = parse(R"({
    "content": ["stray", {"text": "no type"}, {"type": "text", "text": 7}, {"type": "text"},
                {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search",
                 "input": {"query": "q"}},
                {"type": "text", "text": "kept"}]
  })");
  absl::StatusOr<nlohmann::json> converted =
      convertAnthropicToOpenAiUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["choices"][0]["message"],
            parse(R"({"role":"assistant","content":"kept"})"));

  converted = convertAnthropicToOpenAiUnary(parse(R"({"content": "not an array"})"), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["choices"][0]["message"]["content"], "");
}

TEST(AnthropicToOpenAiUnaryTest, FinishReasons) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {R"("end_turn")", "stop"},
      {R"("stop_sequence")", "stop"},
      {R"("pause_turn")", "stop"},
      {R"("max_tokens")", "length"},
      {R"("model_context_window_exceeded")", "length"},
      {R"("tool_use")", "tool_calls"},
      {R"("refusal")", "content_filter"},
      {R"("a_future_reason")", "stop"},
      {"null", "stop"},
  };
  for (const auto& [stop_reason, finish_reason] : cases) {
    absl::StatusOr<nlohmann::json> converted = convertAnthropicToOpenAiUnary(
        parse(absl::StrCat(R"({"content":[],"stop_reason":)", stop_reason, "}")), makeContext());
    ASSERT_TRUE(converted.ok());
    EXPECT_EQ((*converted)["choices"][0]["finish_reason"], finish_reason) << stop_reason;
  }
  absl::StatusOr<nlohmann::json> converted =
      convertAnthropicToOpenAiUnary(parse(R"({"content":[]})"), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["choices"][0]["finish_reason"], "stop");
}

TEST(AnthropicToOpenAiUnaryTest, UsageIgnoresUnusableCounts) {
  nlohmann::json body = {{"content", nlohmann::json::array()},
                         {"usage",
                          {{"input_tokens", 3},
                           {"output_tokens", -1},
                           {"cache_creation_input_tokens", nullptr},
                           {"cache_read_input_tokens", "7"}}}};
  absl::StatusOr<nlohmann::json> converted = convertAnthropicToOpenAiUnary(body, makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["usage"],
            parse(R"({"prompt_tokens": 3, "completion_tokens": 0, "total_tokens": 3})"));
}

TEST(AnthropicToOpenAiUnaryTest, ErrorBody) {
  nlohmann::json body = parse(R"({
    "type": "error",
    "error": {"type": "overloaded_error", "message": "Overloaded"},
    "request_id": "req_011CSHoEeqs5C35K2UUqR7Fy"
  })");
  absl::StatusOr<nlohmann::json> converted =
      convertAnthropicToOpenAiUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(*converted,
            parse(R"({"error": {"message": "Overloaded", "type": "overloaded_error"}})"));

  converted = convertAnthropicToOpenAiUnary(parse(R"({"type": "error"})"), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(*converted, parse(R"({"error": {"message": "", "type": "api_error"}})"));
}

TEST(AnthropicToOpenAiUnaryTest, VertexErrorBody) {
  nlohmann::json body = parse(R"({
    "error": {"code": 429, "message": "Quota exceeded for online_prediction_requests_per_base_model",
              "status": "RESOURCE_EXHAUSTED"}
  })");
  absl::StatusOr<nlohmann::json> converted =
      convertAnthropicToOpenAiUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(*converted, parse(R"({"error": {
    "message": "Quota exceeded for online_prediction_requests_per_base_model",
    "type": "RESOURCE_EXHAUSTED"}})"));

  converted = convertAnthropicToOpenAiUnary(
      parse(R"({"type": "message", "content": [{"type": "text", "text": "ok"}],
                "error": {"message": "not an error"}})"),
      makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["choices"][0]["message"]["content"], "ok");

  converted =
      convertAnthropicToOpenAiUnary(parse(R"({"error": "boom", "content": []})"), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["object"], "chat.completion");
}

TEST(AnthropicToOpenAiUnaryTest, OffloadedErrorMessageIsCopied) {
  nlohmann::json body = {{"type", "error"},
                         {"error", {{"type", "invalid_request_error"}, {"message", offloaded()}}}};
  absl::StatusOr<nlohmann::json> converted = convertAnthropicToOpenAiUnary(body, makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(
      *converted,
      nlohmann::json({{"error", {{"message", offloaded()}, {"type", "invalid_request_error"}}}}));
}

TEST(AnthropicToOpenAiUnaryTest, NotAnObject) {
  EXPECT_EQ(convertAnthropicToOpenAiUnary(parse("[]"), makeContext()).status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_EQ(convertAnthropicToOpenAiUnary(parse(R"("text")"), makeContext()).status().code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(AnthropicToOpenAiUnaryTest, OffloadedValues) {
  nlohmann::json single = {
      {"content", nlohmann::json::array({{{"type", "text"}, {"text", offloaded()}}})}};
  absl::StatusOr<nlohmann::json> converted = convertAnthropicToOpenAiUnary(single, makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["choices"][0]["message"]["content"], offloaded());

  nlohmann::json with_tool = single;
  with_tool["content"].push_back(
      nlohmann::json{{"type", "tool_use"}, {"id", "toolu_1"}, {"name", "f"}, {"input", {}}});
  converted = convertAnthropicToOpenAiUnary(with_tool, makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["choices"][0]["message"]["content"], offloaded());

  nlohmann::json with_empty = single;
  with_empty["content"].push_back(nlohmann::json{{"type", "text"}, {"text", ""}});
  converted = convertAnthropicToOpenAiUnary(with_empty, makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["choices"][0]["message"]["content"], offloaded());

  nlohmann::json two = single;
  two["content"].push_back(nlohmann::json{{"type", "text"}, {"text", "more"}});
  EXPECT_EQ(convertAnthropicToOpenAiUnary(two, makeContext()).status().code(),
            absl::StatusCode::kInvalidArgument);

  nlohmann::json tool = {
      {"content", nlohmann::json::array({{{"type", "tool_use"},
                                          {"id", "toolu_1"},
                                          {"name", "write_file"},
                                          {"input", {{"body", {{"text", offloaded()}}}}}}})}};
  EXPECT_EQ(convertAnthropicToOpenAiUnary(tool, makeContext()).status().code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(AnthropicToOpenAiStreamTest, Text) {
  const std::string id = "msg_01XFDUDYJgAACzvnptvVoYEL";
  const std::string model = "claude-sonnet-4-5-20250929";
  nlohmann::json finish = chunk(id, model, nlohmann::json::object(), "stop");
  finish["usage"] = parse(R"({"prompt_tokens": 25, "completion_tokens": 15, "total_tokens": 40,
                              "prompt_tokens_details": {"cached_tokens": 0}})");
  EXPECT_EQ(openAiPayloads(anthropicToOpenAi(kTextStream)),
            nlohmann::json::array({
                chunk(id, model, {{"role", "assistant"}, {"content", ""}}),
                chunk(id, model, {{"content", "Hello"}}),
                chunk(id, model, {{"content", "!"}}),
                finish,
                "[DONE]",
            }));
}

TEST(AnthropicToOpenAiStreamTest, ToolsTextAndThinking) {
  const std::string id = "msg_014p7gG3wDgGV9EUtLvnow3U";
  const std::string model = "claude-sonnet-4-5-20250929";
  nlohmann::json finish = chunk(id, model, nlohmann::json::object(), "tool_calls");
  finish["usage"] = parse(R"({"prompt_tokens": 702, "completion_tokens": 89, "total_tokens": 791,
                              "prompt_tokens_details": {"cached_tokens": 200}})");
  EXPECT_EQ(openAiPayloads(anthropicToOpenAi(kToolStream)),
            nlohmann::json::array({
                chunk(id, model, {{"role", "assistant"}, {"content", ""}}),
                chunk(id, model, {{"content", "Checking both."}}),
                chunk(id, model, parse(R"({"tool_calls": [{"index": 0,
                    "id": "toolu_01T1x1fJ34qAmk2tNTrN7Up6", "type": "function",
                    "function": {"name": "get_weather", "arguments": ""}}]})")),
                chunk(id, model, parse(R"({"tool_calls": [{"index": 0,
                    "function": {"arguments": "{\"location\": \"San Fra"}}]})")),
                chunk(id, model, parse(R"({"tool_calls": [{"index": 0,
                    "function": {"arguments": "ncisco, CA\"}"}}]})")),
                chunk(id, model, parse(R"({"tool_calls": [{"index": 1,
                    "id": "toolu_01VtGx9Ka9sLo1Ai3JvYpY2a", "type": "function",
                    "function": {"name": "get_time", "arguments": ""}}]})")),
                chunk(id, model, parse(R"({"tool_calls": [{"index": 1,
                    "function": {"arguments": "{\"tz\": \"PST\"}"}}]})")),
                finish,
                "[DONE]",
            }));
}

TEST(AnthropicToOpenAiStreamTest, ToolWithoutArgumentsGetsEmptyObject) {
  const std::vector<SseFrame> out = anthropicToOpenAi(R"(
    data: {"type":"message_start","message":{"id":"msg_1","model":"claude-haiku-4-5","usage":{"input_tokens":5,"output_tokens":1}}}
    data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"list_files","input":{}}}
    data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":""}}
    data: {"type":"content_block_stop","index":0}
    data: {"type":"content_block_stop","index":0}
    data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9}}
    data: {"type":"message_stop"}
  )");
  EXPECT_EQ(accumulateOpenAi(out), parse(R"({
    "content": "",
    "tool_calls": [{"id": "toolu_1", "name": "list_files", "arguments": "{}"}],
    "finish_reason": "tool_calls",
    "usage": {"prompt_tokens": 5, "completion_tokens": 9, "total_tokens": 14},
    "done": true
  })"));
  EXPECT_EQ(out.size(), 5U);
}

TEST(AnthropicToOpenAiStreamTest, UsagePlacement) {
  const nlohmann::json usage = parse(R"({"prompt_tokens": 25, "completion_tokens": 15,
      "total_tokens": 40, "prompt_tokens_details": {"cached_tokens": 0}})");
  {
    SCOPED_TRACE("include_usage");
    for (bool always : {true, false}) {
      nlohmann::json payloads =
          openAiPayloads(anthropicToOpenAi(kTextStream, makeContext(true, always)));
      ASSERT_EQ(payloads.size(), 6U);
      EXPECT_FALSE(payloads[3].contains("usage"));
      EXPECT_EQ(payloads[3]["choices"][0]["finish_reason"], "stop");
      EXPECT_EQ(payloads[4], parse(R"({"id": "msg_01XFDUDYJgAACzvnptvVoYEL",
          "object": "chat.completion.chunk", "created": 1758650000,
          "model": "claude-sonnet-4-5-20250929", "choices": [],
          "usage": {"prompt_tokens": 25, "completion_tokens": 15, "total_tokens": 40,
                    "prompt_tokens_details": {"cached_tokens": 0}}})"));
      EXPECT_EQ(payloads[5], "[DONE]");
    }
  }
  {
    SCOPED_TRACE("always_report_usage");
    nlohmann::json payloads =
        openAiPayloads(anthropicToOpenAi(kTextStream, makeContext(false, true)));
    ASSERT_EQ(payloads.size(), 5U);
    EXPECT_EQ(payloads[3]["usage"], usage);
  }
  {
    SCOPED_TRACE("no usage");
    nlohmann::json payloads =
        openAiPayloads(anthropicToOpenAi(kTextStream, makeContext(false, false)));
    ASSERT_EQ(payloads.size(), 5U);
    for (const nlohmann::json& payload : payloads) {
      EXPECT_FALSE(payload.is_object() && payload.contains("usage")) << payload;
    }
  }
}

TEST(AnthropicToOpenAiStreamTest, MessageDeltaUsageOverridesStart) {
  nlohmann::json accumulated = accumulateOpenAi(anthropicToOpenAi(R"(
    data: {"type":"message_start","message":{"id":"msg_1","model":"m","usage":{"input_tokens":25,"output_tokens":1}}}
    data: {"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"input_tokens":30,"cache_read_input_tokens":5,"cache_creation_input_tokens":2,"output_tokens":12}}
    data: {"type":"message_stop"}
  )"));
  EXPECT_EQ(accumulated["finish_reason"], "length");
  EXPECT_EQ(accumulated["usage"], parse(R"({"prompt_tokens": 37, "completion_tokens": 12,
      "total_tokens": 49, "prompt_tokens_details": {"cached_tokens": 5}})"));
}

TEST(AnthropicToOpenAiStreamTest, FinishReasons) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {R"("end_turn")", "stop"},
      {R"("stop_sequence")", "stop"},
      {R"("pause_turn")", "stop"},
      {R"("max_tokens")", "length"},
      {R"("model_context_window_exceeded")", "length"},
      {R"("tool_use")", "tool_calls"},
      {R"("refusal")", "content_filter"},
      {R"("a_future_reason")", "stop"},
      {"null", "stop"},
  };
  for (const auto& [stop_reason, finish_reason] : cases) {
    nlohmann::json payloads = openAiPayloads(anthropicToOpenAi(absl::StrCat(
        R"(data: {"type":"message_delta","delta":{"stop_reason":)", stop_reason, "}}")));
    ASSERT_EQ(payloads.size(), 1U);
    EXPECT_EQ(payloads[0]["choices"][0]["finish_reason"], finish_reason) << stop_reason;
  }
  nlohmann::json payloads = openAiPayloads(anthropicToOpenAi(R"(data: {"type":"message_delta"})"));
  ASSERT_EQ(payloads.size(), 1U);
  EXPECT_EQ(payloads[0]["choices"][0]["finish_reason"], "stop");
  EXPECT_EQ(payloads[0]["id"], "");
  EXPECT_EQ(payloads[0]["model"], "requested-model");
}

TEST(AnthropicToOpenAiStreamTest, ErrorEndsStream) {
  EXPECT_EQ(openAiPayloads(anthropicToOpenAi(R"(
    event: message_start
    data: {"type":"message_start","message":{"id":"msg_1","model":"m","usage":{"input_tokens":1,"output_tokens":1}}}

    event: content_block_delta
    data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}

    event: error
    data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}

    event: content_block_delta
    data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"late"}}

    event: message_stop
    data: {"type":"message_stop"}
  )")),
            nlohmann::json::array({
                chunk("msg_1", "m", {{"role", "assistant"}, {"content", ""}}),
                chunk("msg_1", "m", {{"content", "Hi"}}),
                parse(R"({"error": {"message": "Overloaded", "type": "overloaded_error"}})"),
            }));
}

TEST(AnthropicToOpenAiStreamTest, ErrorByEventNameWithoutDetails) {
  StreamConverterPtr converter = createAnthropicToOpenAiStreamConverter(makeContext());
  std::vector<SseFrame> frames;
  frames.push_back(SseFrame::ofJson(nlohmann::json::object(), "error"));
  EXPECT_EQ(openAiPayloads(run(*converter, std::move(frames))),
            parse(R"([{"error": {"message": "", "type": "api_error"}}])"));
}

TEST(AnthropicToOpenAiStreamTest, ErrorEventWithoutAnthropicPayload) {
  StreamConverterPtr converter = createAnthropicToOpenAiStreamConverter(makeContext());
  std::vector<SseFrame> frames;
  frames.push_back(SseFrame::ofJson(
      parse(R"({"type":"message_start","message":{"id":"msg_1","model":"m"}})"), "message_start"));
  frames.push_back(SseFrame::ofData("upstream connect error", "error"));
  frames.push_back(SseFrame::ofJson(parse(
      R"({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"x"}})")));
  EXPECT_EQ(openAiPayloads(run(*converter, std::move(frames))),
            nlohmann::json::array({
                chunk("msg_1", "m", {{"role", "assistant"}, {"content", ""}}),
                parse(R"({"error": {"message": "upstream connect error", "type": "api_error"}})"),
            }));

  for (const auto& [payload, message] : std::vector<std::pair<nlohmann::json, nlohmann::json>>{
           {nlohmann::json("Overloaded"), "Overloaded"},
           {nlohmann::json(42), ""},
           {nlohmann::json::array({"a"}), ""}}) {
    converter = createAnthropicToOpenAiStreamConverter(makeContext());
    frames.clear();
    frames.push_back(SseFrame::ofJson(payload, "error"));
    nlohmann::json payloads = openAiPayloads(run(*converter, std::move(frames)));
    ASSERT_EQ(payloads.size(), 1U) << payload;
    EXPECT_EQ(payloads[0],
              nlohmann::json({{"error", {{"message", message}, {"type", "api_error"}}}}))
        << payload;
  }
}

TEST(AnthropicToOpenAiStreamTest, VertexErrorFrame) {
  EXPECT_EQ(openAiPayloads(anthropicToOpenAi(R"(
    event: message_start
    data: {"type":"message_start","message":{"id":"msg_vrtx_01","model":"claude-sonnet-4-5@20250929","usage":{"input_tokens":9,"output_tokens":1}}}

    data: {"error":{"code":503,"message":"The service is currently unavailable.","status":"UNAVAILABLE"}}

    event: message_stop
    data: {"type":"message_stop"}
  )")),
            nlohmann::json::array({
                chunk("msg_vrtx_01", "claude-sonnet-4-5@20250929",
                      {{"role", "assistant"}, {"content", ""}}),
                parse(R"({"error": {"message": "The service is currently unavailable.",
                                    "type": "UNAVAILABLE"}})"),
            }));
}

TEST(AnthropicToOpenAiStreamTest, ServerToolBlocksAreDropped) {
  const std::vector<SseFrame> out = anthropicToOpenAi(R"(
    event: message_start
    data: {"type":"message_start","message":{"id":"msg_01G6kbzhA1CwbAvm8mEvCnsS","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":2679,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":3}}}

    event: content_block_start
    data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

    event: content_block_delta
    data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I'll search for that."}}

    event: content_block_stop
    data: {"type":"content_block_stop","index":0}

    event: content_block_start
    data: {"type":"content_block_start","index":1,"content_block":{"type":"server_tool_use","id":"srvtoolu_014hJH82Qum7Td6UV8gDXThB","name":"web_search","input":{}}}

    event: content_block_delta
    data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":""}}

    event: content_block_delta
    data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"query\": \"weather NYC today\"}"}}

    event: content_block_stop
    data: {"type":"content_block_stop","index":1}

    event: content_block_start
    data: {"type":"content_block_start","index":2,"content_block":{"type":"web_search_tool_result","tool_use_id":"srvtoolu_014hJH82Qum7Td6UV8gDXThB","content":[{"type":"web_search_result","title":"Weather","url":"https://example.com/nyc","encrypted_content":"Ev0DCioIAxgC","page_age":null}]}}

    event: content_block_stop
    data: {"type":"content_block_stop","index":2}

    event: content_block_start
    data: {"type":"content_block_start","index":3,"content_block":{"type":"text","text":""}}

    event: content_block_delta
    data: {"type":"content_block_delta","index":3,"delta":{"type":"text_delta","text":" It is sunny."}}

    event: content_block_stop
    data: {"type":"content_block_stop","index":3}

    event: message_delta
    data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"input_tokens":10682,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":510,"server_tool_use":{"web_search_requests":1}}}

    event: message_stop
    data: {"type":"message_stop"}
  )");
  EXPECT_EQ(accumulateOpenAi(out), parse(R"({
    "content": "I'll search for that. It is sunny.",
    "tool_calls": [],
    "finish_reason": "stop",
    "usage": {"prompt_tokens": 10682, "completion_tokens": 510, "total_tokens": 11192,
              "prompt_tokens_details": {"cached_tokens": 0}},
    "done": true
  })"));
  EXPECT_EQ(out.size(), 5U);
}

TEST(AnthropicToOpenAiStreamTest, UnusableFramesAreDropped) {
  StreamConverterPtr converter = createAnthropicToOpenAiStreamConverter(makeContext());
  std::vector<SseFrame> frames;
  frames.push_back(SseFrame::ofData("not json", "content_block_delta"));
  frames.push_back(SseFrame::ofJson(parse("[1, 2]"), "content_block_delta"));
  frames.push_back(SseFrame::ofJson(parse(R"({"type": "a_future_event"})"), "a_future_event"));
  frames.push_back(SseFrame::ofJson(parse(R"({"index": 0})")));
  frames.push_back(SseFrame::ofJson(parse(R"({"type": "content_block_start", "index": 0})")));
  frames.push_back(SseFrame::ofJson(
      parse(R"({"type": "content_block_start", "index": 0, "content_block": {}})")));
  frames.push_back(SseFrame::ofJson(parse(
      R"({"type": "content_block_start", "content_block": {"type": "tool_use", "id": "t"}})")));
  frames.push_back(SseFrame::ofJson(parse(R"({"type": "content_block_delta", "index": 0})")));
  frames.push_back(SseFrame::ofJson(parse(
      R"({"type": "content_block_delta", "index": 9, "delta": {"type": "input_json_delta", "partial_json": "{}"}})")));
  frames.push_back(SseFrame::ofJson(parse(
      R"({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": ""}})")));
  frames.push_back(SseFrame::ofJson(parse(R"({"type": "content_block_stop", "index": 0})")));
  frames.push_back(SseFrame::ofJson(parse(R"({"type": "content_block_stop"})")));
  frames.push_back(SseFrame::ofJson(parse(R"({"type": "ping"})")));
  EXPECT_TRUE(run(*converter, std::move(frames)).empty());
}

TEST(AnthropicToOpenAiStreamTest, EventNameFallbackAndStartText) {
  StreamConverterPtr converter = createAnthropicToOpenAiStreamConverter(makeContext());
  std::vector<SseFrame> frames;
  frames.push_back(SseFrame::ofJson(nlohmann::json::object(), "message_start"));
  frames.push_back(
      SseFrame::ofJson(parse(R"({"index": 0, "content_block": {"type": "text", "text": "Hi"}})"),
                       "content_block_start"));
  frames.push_back(
      SseFrame::ofJson(parse(R"({"index": 0, "delta": {"type": "text_delta", "text": " there"}})"),
                       "content_block_delta"));
  EXPECT_EQ(openAiPayloads(run(*converter, std::move(frames))),
            nlohmann::json::array({
                chunk("", "requested-model", {{"role", "assistant"}, {"content", ""}}),
                chunk("", "requested-model", {{"content", "Hi"}}),
                chunk("", "requested-model", {{"content", " there"}}),
            }));
}

TEST(AnthropicToOpenAiStreamTest, TruncatedStreamHasNoDone) {
  const std::vector<SseFrame> out = anthropicToOpenAi(R"(
    data: {"type":"message_start","message":{"id":"msg_1","model":"m"}}
    data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}
    data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"cut"}}
  )");
  ASSERT_EQ(out.size(), 2U);
  EXPECT_FALSE(accumulateOpenAi(out)["done"].get<bool>());
}

TEST(AnthropicToOpenAiStreamTest, FramesAfterMessageStopAreIgnored) {
  nlohmann::json payloads = openAiPayloads(anthropicToOpenAi(R"(
    data: {"type":"message_stop"}
    data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"late"}}
    data: {"type":"message_stop"}
  )"));
  EXPECT_EQ(payloads, parse(R"(["[DONE]"])"));
}

TEST(AnthropicToOpenAiStreamTest, OffloadedValuesAreCopied) {
  StreamConverterPtr converter = createAnthropicToOpenAiStreamConverter(makeContext());
  std::vector<SseFrame> frames;
  frames.push_back(SseFrame::ofJson({{"type", "content_block_delta"},
                                     {"index", 0},
                                     {"delta", {{"type", "text_delta"}, {"text", offloaded()}}}}));
  frames.push_back(SseFrame::ofJson(parse(
      R"({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t","name":"f"}})")));
  frames.push_back(
      SseFrame::ofJson({{"type", "content_block_delta"},
                        {"index", 1},
                        {"delta", {{"type", "input_json_delta"}, {"partial_json", offloaded()}}}}));
  frames.push_back(SseFrame::ofJson(parse(R"({"type":"content_block_stop","index":1})")));
  nlohmann::json payloads = openAiPayloads(run(*converter, std::move(frames)));
  ASSERT_EQ(payloads.size(), 3U);
  EXPECT_EQ(payloads[0]["choices"][0]["delta"]["content"], offloaded());
  EXPECT_EQ(payloads[2]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            offloaded());
}

TEST(OpenAiToAnthropicUnaryTest, TextWithCachedUsage) {
  nlohmann::json body = parse(R"({
    "id": "chatcmpl-B9MHDbslfkBeAs8l4bebGdFOJ6PeG",
    "object": "chat.completion",
    "created": 1741570283,
    "model": "gpt-4o-2024-08-06",
    "choices": [{
      "index": 0,
      "message": {"role": "assistant", "content": "The image shows a boardwalk.",
                  "refusal": null, "annotations": []},
      "logprobs": null,
      "finish_reason": "stop"
    }],
    "usage": {"prompt_tokens": 1117, "completion_tokens": 46, "total_tokens": 1163,
              "prompt_tokens_details": {"cached_tokens": 1024, "audio_tokens": 0},
              "completion_tokens_details": {"reasoning_tokens": 0}},
    "service_tier": "default",
    "system_fingerprint": "fp_fc9f1d7035"
  })");
  absl::StatusOr<nlohmann::json> converted =
      convertOpenAiToAnthropicUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok()) << converted.status();
  EXPECT_EQ(*converted, parse(R"({
    "id": "chatcmpl-B9MHDbslfkBeAs8l4bebGdFOJ6PeG",
    "type": "message",
    "role": "assistant",
    "model": "gpt-4o-2024-08-06",
    "content": [{"type": "text", "text": "The image shows a boardwalk."}],
    "stop_reason": "end_turn",
    "stop_sequence": null,
    "usage": {"input_tokens": 93, "output_tokens": 46, "cache_read_input_tokens": 1024}
  })"));
}

TEST(OpenAiToAnthropicUnaryTest, ToolCalls) {
  nlohmann::json body = parse(R"({
    "id": "chatcmpl-abc123",
    "model": "gpt-4o",
    "choices": [{
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Calling tools.",
        "tool_calls": [
          {"id": "call_1", "type": "function",
           "function": {"name": "get_weather", "arguments": "{\"location\": \"Boston, MA\"}"}},
          {"id": "call_2", "type": "function", "function": {"name": "now", "arguments": ""}},
          {"id": "call_3", "type": "function", "function": {"name": "noop", "arguments": null}},
          {"id": "call_4", "type": "function", "function": {"name": "bare"}},
          {"type": "function"}
        ]
      },
      "finish_reason": "tool_calls"
    }],
    "usage": {"prompt_tokens": 82, "completion_tokens": 17, "total_tokens": 99}
  })");
  absl::StatusOr<nlohmann::json> converted =
      convertOpenAiToAnthropicUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok()) << converted.status();
  EXPECT_EQ(*converted, parse(R"({
    "id": "chatcmpl-abc123",
    "type": "message",
    "role": "assistant",
    "model": "gpt-4o",
    "content": [
      {"type": "text", "text": "Calling tools."},
      {"type": "tool_use", "id": "call_1", "name": "get_weather",
       "input": {"location": "Boston, MA"}},
      {"type": "tool_use", "id": "call_2", "name": "now", "input": {}},
      {"type": "tool_use", "id": "call_3", "name": "noop", "input": {}},
      {"type": "tool_use", "id": "call_4", "name": "bare", "input": {}},
      {"type": "tool_use", "id": "", "name": "", "input": {}}
    ],
    "stop_reason": "tool_use",
    "stop_sequence": null,
    "usage": {"input_tokens": 82, "output_tokens": 17}
  })"));
}

TEST(OpenAiToAnthropicUnaryTest, InvalidToolArguments) {
  for (const nlohmann::json& arguments :
       {nlohmann::json("{\"unterminated\": "), nlohmann::json("[1, 2]"), nlohmann::json("42"),
        nlohmann::json({{"a", 1}}), offloaded()}) {
    nlohmann::json body = {
        {"choices",
         nlohmann::json::array(
             {{{"message",
                {{"tool_calls",
                  nlohmann::json::array(
                      {{{"id", "call_1"},
                        {"function", {{"name", "f"}, {"arguments", arguments}}}}})}}}}})}};
    EXPECT_EQ(convertOpenAiToAnthropicUnary(body, makeContext()).status().code(),
              absl::StatusCode::kInvalidArgument)
        << body;
  }
}

TEST(OpenAiToAnthropicUnaryTest, FinishReasons) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {R"("stop")", "end_turn"},
      {R"("length")", "max_tokens"},
      {R"("tool_calls")", "tool_use"},
      {R"("function_call")", "tool_use"},
      {R"("content_filter")", "refusal"},
      {R"("a_future_reason")", "end_turn"},
      {"null", "end_turn"},
  };
  for (const auto& [finish_reason, stop_reason] : cases) {
    absl::StatusOr<nlohmann::json> converted = convertOpenAiToAnthropicUnary(
        parse(absl::StrCat(R"({"choices":[{"message":{"content":null},"finish_reason":)",
                           finish_reason, "}]}")),
        makeContext());
    ASSERT_TRUE(converted.ok());
    EXPECT_EQ((*converted)["stop_reason"], stop_reason) << finish_reason;
    EXPECT_EQ((*converted)["content"], nlohmann::json::array());
  }
}

TEST(OpenAiToAnthropicUnaryTest, ToolCallsImplyToolUse) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {R"("stop")", "tool_use"},
      {"null", "tool_use"},
      {R"("a_future_reason")", "tool_use"},
      {R"("length")", "max_tokens"},
      {R"("content_filter")", "refusal"},
  };
  for (const auto& [finish_reason, stop_reason] : cases) {
    absl::StatusOr<nlohmann::json> converted = convertOpenAiToAnthropicUnary(
        parse(absl::StrCat(R"({"choices":[{"message":{"content":null,"tool_calls":[)",
                           R"({"id":"call_1","type":"function",)",
                           R"("function":{"name":"extract","arguments":"{\"a\":1}"}}]},)",
                           R"("finish_reason":)", finish_reason, "}]}")),
        makeContext());
    ASSERT_TRUE(converted.ok());
    EXPECT_EQ((*converted)["stop_reason"], stop_reason) << finish_reason;
  }
}

TEST(OpenAiToAnthropicUnaryTest, MissingChoices) {
  for (absl::string_view body : {R"({})", R"({"choices": []})", R"({"choices": {}})",
                                 R"({"choices": [{"finish_reason": "stop"}]})"}) {
    absl::StatusOr<nlohmann::json> converted =
        convertOpenAiToAnthropicUnary(parse(body), makeContext());
    ASSERT_TRUE(converted.ok());
    EXPECT_EQ(*converted, parse(R"({
      "id": "", "type": "message", "role": "assistant", "model": "requested-model",
      "content": [], "stop_reason": "end_turn", "stop_sequence": null,
      "usage": {"input_tokens": 0, "output_tokens": 0}
    })"))
        << body;
  }
}

TEST(OpenAiToAnthropicUnaryTest, CachedTokensAreClamped) {
  nlohmann::json body = parse(R"({"usage": {"prompt_tokens": 10, "completion_tokens": 2,
                                            "prompt_tokens_details": {"cached_tokens": 50}}})");
  absl::StatusOr<nlohmann::json> converted =
      convertOpenAiToAnthropicUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["usage"],
            parse(R"({"input_tokens": 0, "output_tokens": 2, "cache_read_input_tokens": 10})"));
}

TEST(OpenAiToAnthropicUnaryTest, OffloadedContentIsCopied) {
  nlohmann::json body = {
      {"choices", nlohmann::json::array({{{"message", {{"content", offloaded()}}}}})}};
  absl::StatusOr<nlohmann::json> converted = convertOpenAiToAnthropicUnary(body, makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["content"],
            nlohmann::json::array({{{"type", "text"}, {"text", offloaded()}}}));
}

TEST(OpenAiToAnthropicUnaryTest, ErrorBody) {
  nlohmann::json body = parse(R"({
    "error": {"message": "Rate limit reached for gpt-4o", "type": "requests",
              "param": null, "code": "rate_limit_exceeded"}
  })");
  absl::StatusOr<nlohmann::json> converted =
      convertOpenAiToAnthropicUnary(std::move(body), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(*converted, parse(R"({"type": "error",
      "error": {"type": "requests", "message": "Rate limit reached for gpt-4o"}})"));

  converted = convertOpenAiToAnthropicUnary(
      parse(R"({"error": {"message": "boom", "type": null}})"), makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(*converted,
            parse(R"({"type": "error", "error": {"type": "api_error", "message": "boom"}})"));
}

TEST(OpenAiToAnthropicUnaryTest, OffloadedErrorMessageIsCopied) {
  nlohmann::json body = {{"error", {{"message", offloaded()}, {"type", "invalid_request_error"}}}};
  absl::StatusOr<nlohmann::json> converted = convertOpenAiToAnthropicUnary(body, makeContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(
      *converted,
      nlohmann::json({{"type", "error"},
                      {"error", {{"type", "invalid_request_error"}, {"message", offloaded()}}}}));
}

TEST(OpenAiToAnthropicUnaryTest, NotAnObject) {
  EXPECT_EQ(convertOpenAiToAnthropicUnary(parse("[]"), makeContext()).status().code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(OpenAiToAnthropicStreamTest, Text) {
  EXPECT_EQ(anthropicPayloads(openAiToAnthropic(kOpenAiTextStream)), parse(R"([
    {"type": "message_start", "message": {"id": "chatcmpl-C8xAbc", "type": "message",
      "role": "assistant", "model": "gpt-4o-2024-08-06", "content": [], "stop_reason": null,
      "stop_sequence": null, "usage": {"input_tokens": 0, "output_tokens": 0}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello"}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": " world"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null},
     "usage": {"input_tokens": 19, "output_tokens": 10, "cache_read_input_tokens": 0}},
    {"type": "message_stop"}
  ])"));
}

TEST(OpenAiToAnthropicStreamTest, TextThenTools) {
  EXPECT_EQ(anthropicPayloads(openAiToAnthropic(kOpenAiToolStream)), parse(R"([
    {"type": "message_start", "message": {"id": "chatcmpl-T1", "type": "message",
      "role": "assistant", "model": "gpt-4o", "content": [], "stop_reason": null,
      "stop_sequence": null, "usage": {"input_tokens": 0, "output_tokens": 0}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0,
     "delta": {"type": "text_delta", "text": "Let me check."}},
    {"type": "content_block_stop", "index": 0},
    {"type": "content_block_start", "index": 1,
     "content_block": {"type": "tool_use", "id": "call_a", "name": "get_weather", "input": {}}},
    {"type": "content_block_delta", "index": 1,
     "delta": {"type": "input_json_delta", "partial_json": "{\"city\":"}},
    {"type": "content_block_delta", "index": 1,
     "delta": {"type": "input_json_delta", "partial_json": "\"Paris\"}"}},
    {"type": "content_block_stop", "index": 1},
    {"type": "content_block_start", "index": 2,
     "content_block": {"type": "tool_use", "id": "call_b", "name": "get_time", "input": {}}},
    {"type": "content_block_delta", "index": 2,
     "delta": {"type": "input_json_delta", "partial_json": "{\"tz\":\"CET\"}"}},
    {"type": "content_block_stop", "index": 2},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": null},
     "usage": {"input_tokens": 20, "output_tokens": 40, "cache_read_input_tokens": 100}},
    {"type": "message_stop"}
  ])"));
}

TEST(OpenAiToAnthropicStreamTest, InterleavedTextAndTools) {
  EXPECT_EQ(anthropicPayloads(openAiToAnthropic(R"(
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"a","arguments":"{\"x\":1}"}}]}}]}
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"content":"between"}}]}
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":""}}]}}]}
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":5,"function":{"arguments":"{\"orphan\":1}"}},{"id":"call_c","function":{"name":"c"}}]}}]}
    data: {"id":"c","model":"m","choices":[{"index":1,"delta":{"content":"other choice"},"finish_reason":"length"}]}
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"content":"after"},"finish_reason":"tool_calls"}]}
    data: [DONE]
  )")),
            parse(R"([
    {"type": "message_start", "message": {"id": "c", "type": "message", "role": "assistant",
      "model": "m", "content": [], "stop_reason": null, "stop_sequence": null,
      "usage": {"input_tokens": 0, "output_tokens": 0}}},
    {"type": "content_block_start", "index": 0,
     "content_block": {"type": "tool_use", "id": "call_a", "name": "a", "input": {}}},
    {"type": "content_block_delta", "index": 0,
     "delta": {"type": "input_json_delta", "partial_json": "{\"x\":1}"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "between"}},
    {"type": "content_block_stop", "index": 1},
    {"type": "content_block_start", "index": 2,
     "content_block": {"type": "tool_use", "id": "call_c", "name": "c", "input": {}}},
    {"type": "content_block_stop", "index": 2},
    {"type": "content_block_start", "index": 3, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 3, "delta": {"type": "text_delta", "text": "after"}},
    {"type": "content_block_stop", "index": 3},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": null},
     "usage": {"input_tokens": 0, "output_tokens": 0}},
    {"type": "message_stop"}
  ])"));
}

TEST(OpenAiToAnthropicStreamTest, ToolCallsImplyToolUse) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {R"("stop")", "tool_use"},
      {R"("length")", "max_tokens"},
      {R"("content_filter")", "refusal"},
  };
  for (const auto& [finish_reason, stop_reason] : cases) {
    nlohmann::json payloads = anthropicPayloads(openAiToAnthropic(absl::StrCat(
        R"(data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,)",
        R"("id":"call_1","type":"function","function":{"name":"extract","arguments":"{}"}}]}}]})",
        "\n\n", R"(data: {"id":"c","model":"m","choices":[{"index":0,"delta":{},"finish_reason":)",
        finish_reason, "}]}\n\ndata: [DONE]")));
    ASSERT_EQ(payloads.size(), 6U) << finish_reason;
    EXPECT_EQ(payloads[4]["delta"]["stop_reason"], stop_reason) << finish_reason;
  }

  nlohmann::json payloads = anthropicPayloads(openAiToAnthropic(R"(
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"f","arguments":"{}"}}]}}]}
    data: [DONE]
  )"));
  ASSERT_EQ(payloads.size(), 6U);
  EXPECT_EQ(payloads[4]["delta"]["stop_reason"], "tool_use");
}

TEST(OpenAiToAnthropicStreamTest, ToolCallWithoutId) {
  nlohmann::json payloads = anthropicPayloads(openAiToAnthropic(R"(
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"f","arguments":"{}"}}]}}]}
  )"));
  ASSERT_EQ(payloads.size(), 3U);
  EXPECT_EQ(payloads[1], parse(R"({"type": "content_block_start", "index": 0,
      "content_block": {"type": "tool_use", "id": "", "name": "f", "input": {}}})"));
}

TEST(OpenAiToAnthropicStreamTest, LateArgumentsGoToTheirBlock) {
  nlohmann::json payloads = anthropicPayloads(openAiToAnthropic(R"(
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"a","arguments":"{\"x\":"}}]}}]}
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"b","arguments":"{}"}}]}}]}
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}
    data: [DONE]
  )"));
  ASSERT_EQ(payloads.size(), 10U);
  EXPECT_EQ(payloads[6], parse(R"({"type": "content_block_delta", "index": 0,
      "delta": {"type": "input_json_delta", "partial_json": "1}"}})"));
}

TEST(OpenAiToAnthropicStreamTest, ErrorEndsStream) {
  EXPECT_EQ(anthropicPayloads(openAiToAnthropic(R"(
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"content":"Hi"}}]}
    data: {"error":{"message":"The server had an error","type":"server_error","param":null,"code":null}}
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"content":"late"},"finish_reason":"stop"}]}
    data: [DONE]
  )")),
            parse(R"([
    {"type": "message_start", "message": {"id": "c", "type": "message", "role": "assistant",
      "model": "m", "content": [], "stop_reason": null, "stop_sequence": null,
      "usage": {"input_tokens": 0, "output_tokens": 0}}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi"}},
    {"type": "error", "error": {"type": "server_error", "message": "The server had an error"}}
  ])"));

  EXPECT_EQ(anthropicPayloads(openAiToAnthropic(R"(data: {"error":{"message":"bad"}})")),
            parse(R"([{"type": "error", "error": {"type": "api_error", "message": "bad"}}])"));
}

TEST(OpenAiToAnthropicStreamTest, OffloadedErrorMessageIsCopied) {
  StreamConverterPtr converter = createOpenAiToAnthropicStreamConverter(makeContext());
  std::vector<SseFrame> frames;
  frames.push_back(SseFrame::ofJson({{"error", {{"message", offloaded()}}}}));
  nlohmann::json payloads = anthropicPayloads(run(*converter, std::move(frames)));
  ASSERT_EQ(payloads.size(), 1U);
  EXPECT_EQ(payloads[0],
            nlohmann::json(
                {{"type", "error"}, {"error", {{"type", "api_error"}, {"message", offloaded()}}}}));
}

TEST(OpenAiToAnthropicStreamTest, MissingDoneFinishesOnEndAfterFinishReason) {
  nlohmann::json payloads = anthropicPayloads(openAiToAnthropic(R"(
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{},"finish_reason":"length"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}
  )"));
  ASSERT_EQ(payloads.size(), 6U);
  EXPECT_EQ(payloads[3], parse(R"({"type": "content_block_stop", "index": 0})"));
  EXPECT_EQ(payloads[4], parse(R"({"type": "message_delta",
      "delta": {"stop_reason": "max_tokens", "stop_sequence": null},
      "usage": {"input_tokens": 3, "output_tokens": 1}})"));
  EXPECT_EQ(payloads[5], parse(R"({"type": "message_stop"})"));
}

TEST(OpenAiToAnthropicStreamTest, TruncatedWithoutFinishReasonDoesNotStop) {
  nlohmann::json payloads = anthropicPayloads(openAiToAnthropic(R"(
    data: {"id":"c","model":"m","choices":[{"index":0,"delta":{"content":"cut"},"finish_reason":null}]}
  )"));
  ASSERT_EQ(payloads.size(), 3U);
  EXPECT_EQ(payloads[2]["type"], "content_block_delta");
}

TEST(OpenAiToAnthropicStreamTest, DoneWithoutChunks) {
  EXPECT_EQ(anthropicPayloads(openAiToAnthropic("data: [DONE]")), parse(R"([
    {"type": "message_start", "message": {"id": "", "type": "message", "role": "assistant",
      "model": "requested-model", "content": [], "stop_reason": null, "stop_sequence": null,
      "usage": {"input_tokens": 0, "output_tokens": 0}}},
    {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null},
     "usage": {"input_tokens": 0, "output_tokens": 0}},
    {"type": "message_stop"}
  ])"));
}

TEST(OpenAiToAnthropicStreamTest, UnusableFramesAreDroppedAndDoneIsFinal) {
  StreamConverterPtr converter = createOpenAiToAnthropicStreamConverter(makeContext());
  std::vector<SseFrame> frames;
  frames.push_back(SseFrame::ofData("not json"));
  frames.push_back(SseFrame::ofJson(parse("[1]")));
  frames.push_back(SseFrame::ofJson(parse(R"({"choices":[{"delta":"bad"},"bad"]})")));
  frames.push_back(SseFrame::ofData("[DONE]"));
  frames.push_back(SseFrame::ofJson(parse(R"({"choices":[{"delta":{"content":"late"}}]})")));
  frames.push_back(SseFrame::ofData("[DONE]"));
  EXPECT_EQ(anthropicPayloads(run(*converter, std::move(frames))).size(), 3U);
}

TEST(OpenAiToAnthropicStreamTest, OffloadedValuesAreCopied) {
  StreamConverterPtr converter = createOpenAiToAnthropicStreamConverter(makeContext());
  std::vector<SseFrame> frames;
  frames.push_back(SseFrame::ofJson(
      {{"choices", nlohmann::json::array({{{"delta", {{"content", offloaded()}}}}})}}));
  frames.push_back(SseFrame::ofJson(
      {{"choices",
        nlohmann::json::array(
            {{{"delta",
               {{"tool_calls",
                 nlohmann::json::array(
                     {{{"index", 0},
                       {"id", "call_1"},
                       {"function", {{"name", "f"}, {"arguments", offloaded()}}}}})}}}}})}}));
  nlohmann::json payloads = anthropicPayloads(run(*converter, std::move(frames)));
  ASSERT_EQ(payloads.size(), 6U);
  EXPECT_EQ(payloads[2]["delta"]["text"], offloaded());
  EXPECT_EQ(payloads[5]["delta"]["partial_json"], offloaded());
}

TEST(RoundTripTest, UnaryOpenAiThroughAnthropic) {
  const nlohmann::json original = parse(R"({
    "id": "chatcmpl-1", "object": "chat.completion", "created": 1758650000, "model": "gpt-4o",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Sure.",
      "tool_calls": [
        {"id": "call_1", "type": "function",
         "function": {"name": "search", "arguments": "{\"limit\":5,\"q\":\"envoy\"}"}},
        {"id": "call_2", "type": "function", "function": {"name": "now", "arguments": "{}"}}
      ]}, "finish_reason": "tool_calls", "logprobs": null}],
    "usage": {"prompt_tokens": 50, "completion_tokens": 7, "total_tokens": 57,
              "prompt_tokens_details": {"cached_tokens": 20}}
  })");
  absl::StatusOr<nlohmann::json> anthropic = convertOpenAiToAnthropicUnary(original, makeContext());
  ASSERT_TRUE(anthropic.ok());
  absl::StatusOr<nlohmann::json> back =
      convertAnthropicToOpenAiUnary(std::move(*anthropic), makeContext());
  ASSERT_TRUE(back.ok());
  EXPECT_EQ(*back, original);
}

TEST(RoundTripTest, StreamOpenAiThroughAnthropic) {
  StreamConverterPtr to_anthropic = createOpenAiToAnthropicStreamConverter(makeContext());
  StreamConverterPtr to_openai = createAnthropicToOpenAiStreamConverter(makeContext(true));
  const std::vector<SseFrame> anthropic = run(*to_anthropic, parseSse(kOpenAiToolStream));
  const std::vector<SseFrame> back = run(*to_openai, anthropic);
  nlohmann::json expected = accumulateOpenAi(parseSse(kOpenAiToolStream));
  EXPECT_EQ(expected["content"], "Let me check.");
  EXPECT_EQ(expected["tool_calls"].size(), 2U);
  EXPECT_EQ(accumulateOpenAi(back), expected);
}

} // namespace
} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
