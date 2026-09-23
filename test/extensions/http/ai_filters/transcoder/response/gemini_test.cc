#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "source/extensions/http/ai_filters/transcoder/response/gemini.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
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

using json = nlohmann::json;

constexpr int64_t Created = 1700000000;

// Captured from Gemini 2.5 Flash on Vertex AI, trimmed.
constexpr absl::string_view GeminiUnaryText = R"json({
  "candidates": [{"content": {"role": "model", "parts": [{"text": "Red, Blue"}]},
                  "finishReason": "STOP", "avgLogprobs": -0.16921446720759073}],
  "usageMetadata": {"promptTokenCount": 8, "candidatesTokenCount": 3, "totalTokenCount": 11,
                    "trafficType": "ON_DEMAND",
                    "promptTokensDetails": [{"modality": "TEXT", "tokenCount": 8}]},
  "modelVersion": "gemini-2.5-flash",
  "createTime": "2026-09-23T18:23:51.721906Z",
  "responseId": "Nxm0avKHLI_csbwPndDMcQ"
})json";

constexpr absl::string_view GeminiUnaryFunctionCall = R"json({
  "candidates": [{"content": {"role": "model",
                              "parts": [{"functionCall": {"name": "get_weather",
                                                          "args": {"city": "Paris"}}}]},
                  "finishReason": "STOP", "avgLogprobs": -0.013967220485210419}],
  "usageMetadata": {"promptTokenCount": 19, "candidatesTokenCount": 5, "totalTokenCount": 24,
                    "trafficType": "ON_DEMAND"},
  "modelVersion": "gemini-2.5-flash",
  "createTime": "2026-09-23T18:23:52.336985Z",
  "responseId": "OBm0atnIFMuSsbwPiefy0Qk"
})json";

constexpr absl::string_view GeminiSseText =
    R"(data: {"candidates": [{"content": {"role": "model","parts": [{"text": "1"}]}}],"usageMetadata": {"trafficType": "ON_DEMAND"},"modelVersion": "gemini-2.5-flash","createTime": "2026-09-23T18:14:28.713244Z","responseId": "BBe0apzEK8uSsbwPiefy0Qk"}

data: {"candidates": [{"content": {"role": "model","parts": [{"text": ", 2, "}]}}],"usageMetadata": {"trafficType": "ON_DEMAND"},"modelVersion": "gemini-2.5-flash","createTime": "2026-09-23T18:14:28.713244Z","responseId": "BBe0apzEK8uSsbwPiefy0Qk"}

data: {"candidates": [{"content": {"role": "model","parts": [{"text": "3, 4, 5"}]},"finishReason": "STOP"}],"usageMetadata": {"promptTokenCount": 11,"candidatesTokenCount": 13,"totalTokenCount": 24,"trafficType": "ON_DEMAND","candidatesTokensDetails": [{"modality": "TEXT","tokenCount": 13}]},"modelVersion": "gemini-2.5-flash","createTime": "2026-09-23T18:14:28.713244Z","responseId": "BBe0apzEK8uSsbwPiefy0Qk"}

)";

constexpr absl::string_view GeminiSseFunctionCall =
    R"(data: {"candidates": [{"content": {"role": "model","parts": [{"functionCall": {"name": "get_weather","args": {"city": "Paris"}}},{"functionCall": {"name": "get_weather","args": {"city": "Tokyo"}}}]},"finishReason": "STOP"}],"usageMetadata": {"promptTokenCount": 27,"candidatesTokenCount": 10,"totalTokenCount": 37,"trafficType": "ON_DEMAND"},"modelVersion": "gemini-2.5-flash","createTime": "2026-09-23T18:23:52.923885Z","responseId": "OBm0au2xONiUotQP-NP1sAM"}

)";

constexpr absl::string_view GeminiSseThoughts =
    R"(data: {"candidates": [{"content": {"role": "model","parts": [{"text": "**Explaining Sky's Hue**\n\nI'm focusing on Rayleigh scattering.\n\n","thought": true}]}}],"usageMetadata": {"trafficType": "ON_DEMAND"},"modelVersion": "gemini-2.5-flash","responseId": "ORm0av7TIN2fsbwPhreo8A0"}

data: {"candidates": [{"content": {"role": "model","parts": [{"text": "**Refining Scattering Concept**\n\nShorter wavelengths scatter more.\n\n","thought": true}]}}],"usageMetadata": {"trafficType": "ON_DEMAND"},"modelVersion": "gemini-2.5-flash","responseId": "ORm0av7TIN2fsbwPhreo8A0"}

data: {"candidates": [{"content": {"role": "model","parts": [{"text": "The sky is blue because of Rayleigh scattering."}]},"finishReason": "STOP"}],"usageMetadata": {"promptTokenCount": 9,"candidatesTokenCount": 30,"totalTokenCount": 151,"trafficType": "ON_DEMAND","thoughtsTokenCount": 112},"modelVersion": "gemini-2.5-flash","responseId": "ORm0av7TIN2fsbwPhreo8A0"}

)";

ResponseContext testContext(bool include_usage = false, bool always_report_usage = true) {
  ResponseContext context;
  context.model = "requested-model";
  context.created = Created;
  context.include_usage = include_usage;
  context.always_report_usage = always_report_usage;
  return context;
}

json parse(absl::string_view text) {
  json parsed = json::parse(text.begin(), text.end(), nullptr, /*allow_exceptions=*/false);
  EXPECT_FALSE(parsed.is_discarded()) << text;
  return parsed;
}

SseFrame frame(absl::string_view text) { return SseFrame::ofJson(parse(text)); }

std::vector<SseFrame> sseFrames(absl::string_view body) {
  std::vector<SseFrame> frames;
  for (absl::string_view line : absl::StrSplit(body, '\n')) {
    if (absl::ConsumePrefix(&line, "data: ")) {
      frames.push_back(frame(line));
    }
  }
  return frames;
}

// Output frames as a JSON array: the JSON payload, or the raw data string.
json render(const std::vector<SseFrame>& frames) {
  json rendered = json::array();
  for (const SseFrame& out : frames) {
    EXPECT_TRUE(out.event.empty());
    rendered.push_back(out.json.has_value() ? *out.json : json(out.data));
  }
  return rendered;
}

json runStream(StreamConverter& converter, std::vector<SseFrame> frames) {
  std::vector<SseFrame> out;
  for (SseFrame& in : frames) {
    const absl::Status status = converter.onFrame(std::move(in), out);
    EXPECT_TRUE(status.ok()) << status;
  }
  const absl::Status status = converter.onEnd(out);
  EXPECT_TRUE(status.ok()) << status;
  return render(out);
}

json geminiToOpenAiStream(std::vector<SseFrame> frames,
                          const ResponseContext& context = testContext()) {
  StreamConverterPtr converter = createGeminiToOpenAiStreamConverter(context);
  return runStream(*converter, std::move(frames));
}

json openAiToGeminiStream(std::vector<SseFrame> frames,
                          const ResponseContext& context = testContext()) {
  StreamConverterPtr converter = createOpenAiToGeminiStreamConverter(context);
  return runStream(*converter, std::move(frames));
}

json openAiChunk(const std::string& id, const std::string& model, json delta,
                 json finish_reason = nullptr) {
  json choice = {{"index", 0}, {"delta", std::move(delta)}, {"finish_reason", finish_reason}};
  return {{"id", id},
          {"object", "chat.completion.chunk"},
          {"created", Created},
          {"model", model},
          {"choices", json::array({choice})}};
}

json roleDelta() { return {{"role", "assistant"}, {"content", ""}}; }

json contentDelta(const json& content) { return {{"content", content}}; }

json finishChunk(const std::string& id, const std::string& model, const std::string& reason,
                 std::optional<json> usage = std::nullopt) {
  json chunk = openAiChunk(id, model, json::object(), reason);
  if (usage.has_value()) {
    chunk["usage"] = *usage;
  }
  return chunk;
}

json usageChunk(const std::string& id, const std::string& model, json usage) {
  return {{"id", id},       {"object", "chat.completion.chunk"}, {"created", Created},
          {"model", model}, {"choices", json::array()},          {"usage", std::move(usage)}};
}

json geminiUnaryToOpenAi(absl::string_view body) {
  absl::StatusOr<json> converted = convertGeminiToOpenAiUnary(parse(body), testContext());
  EXPECT_TRUE(converted.ok()) << converted.status();
  return converted.ok() ? *converted : json();
}

json openAiUnaryToGemini(absl::string_view body) {
  absl::StatusOr<json> converted = convertOpenAiToGeminiUnary(parse(body), testContext());
  EXPECT_TRUE(converted.ok()) << converted.status();
  return converted.ok() ? *converted : json();
}

json offloaded() { return json::binary({1, 2, 3, 4}, 0xea1eb); }

std::string nestedObjects(int levels) {
  std::string text;
  for (int i = 0; i < levels; ++i) {
    text += "{\"a\":";
  }
  return text + "1" + std::string(levels, '}');
}

std::string nestedArrays(int levels) {
  return "{\"a\":" + std::string(levels, '[') + std::string(levels, ']') + "}";
}

json toolCallBody(json arguments) {
  json body = parse(R"({"choices": [{"message": {"tool_calls": [
    {"id": "call_a", "type": "function", "function": {"name": "f"}}]}}]})");
  body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = std::move(arguments);
  return body;
}

TEST(GeminiToOpenAiUnaryTest, CapturedText) {
  EXPECT_EQ(geminiUnaryToOpenAi(GeminiUnaryText), parse(R"json({
    "id": "Nxm0avKHLI_csbwPndDMcQ", "object": "chat.completion", "created": 1700000000,
    "model": "gemini-2.5-flash",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Red, Blue"},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11}
  })json"));
}

TEST(GeminiToOpenAiUnaryTest, CapturedFunctionCall) {
  EXPECT_EQ(geminiUnaryToOpenAi(GeminiUnaryFunctionCall), parse(R"json({
    "id": "OBm0atnIFMuSsbwPiefy0Qk", "object": "chat.completion", "created": 1700000000,
    "model": "gemini-2.5-flash",
    "choices": [{"index": 0,
                 "message": {"role": "assistant", "content": null,
                             "tool_calls": [{"id": "call_0", "type": "function",
                                             "function": {"name": "get_weather",
                                                          "arguments": "{\"city\":\"Paris\"}"}}]},
                 "finish_reason": "tool_calls"}],
    "usage": {"prompt_tokens": 19, "completion_tokens": 5, "total_tokens": 24}
  })json"));
}

TEST(GeminiToOpenAiUnaryTest, ThoughtsDroppedAndCountedAsReasoning) {
  EXPECT_EQ(geminiUnaryToOpenAi(R"json({
    "candidates": [{"content": {"role": "model",
                                "parts": [{"text": "**Thinking**", "thought": true},
                                          {"text": "The sky is blue.", "thoughtSignature": "c2ln"},
                                          {"text": "", "thought": false}]},
                    "finishReason": "STOP"}],
    "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 30, "totalTokenCount": 151,
                      "thoughtsTokenCount": 112, "cachedContentTokenCount": 4,
                      "toolUsePromptTokenCount": 2},
    "modelVersion": "gemini-2.5-flash", "responseId": "r"
  })json"),
            parse(R"json({
    "id": "r", "object": "chat.completion", "created": 1700000000, "model": "gemini-2.5-flash",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "The sky is blue."},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 11, "completion_tokens": 142, "total_tokens": 151,
              "prompt_tokens_details": {"cached_tokens": 4},
              "completion_tokens_details": {"reasoning_tokens": 112}}
  })json"));
}

TEST(GeminiToOpenAiUnaryTest, MultipleCandidatesAndCalls) {
  EXPECT_EQ(geminiUnaryToOpenAi(R"json({
    "candidates": [
      {"content": {"role": "model",
                   "parts": [{"text": "Checking "}, {"text": "both."},
                             {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}},
                             {"functionCall": {"name": "get_time", "args": null}},
                             {"inlineData": {"mimeType": "image/png", "data": "AA=="}}]},
       "finishReason": "STOP"},
      {"index": 1,
       "content": {"role": "model",
                   "parts": [{"functionCall": {"id": "fc-7", "name": "get_weather",
                                               "args": {"city": "Tokyo", "units": ["c"]}}}]},
       "finishReason": "STOP"}],
    "modelVersion": "gemini-2.5-pro", "responseId": "r1"
  })json"),
            parse(R"json({
    "id": "r1", "object": "chat.completion", "created": 1700000000, "model": "gemini-2.5-pro",
    "choices": [
      {"index": 0,
       "message": {"role": "assistant", "content": "Checking both.",
                   "tool_calls": [
                     {"id": "call_0", "type": "function",
                      "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}},
                     {"id": "call_1", "type": "function",
                      "function": {"name": "get_time", "arguments": "{}"}}]},
       "finish_reason": "tool_calls"},
      {"index": 1,
       "message": {"role": "assistant", "content": null,
                   "tool_calls": [
                     {"id": "fc-7", "type": "function",
                      "function": {"name": "get_weather",
                                   "arguments": "{\"city\":\"Tokyo\",\"units\":[\"c\"]}"}}]},
       "finish_reason": "tool_calls"}]
  })json"));
}

TEST(GeminiToOpenAiUnaryTest, CandidateWithoutContent) {
  EXPECT_EQ(geminiUnaryToOpenAi(R"json({
    "candidates": [{"finishReason": "MAX_TOKENS"},
                   {"index": 1, "content": {"role": "model"}, "finishReason": "MAX_TOKENS"}],
    "usageMetadata": {"promptTokenCount": 5, "totalTokenCount": 69, "thoughtsTokenCount": 64}
  })json"),
            parse(R"json({
    "id": "chatcmpl-envoy", "object": "chat.completion", "created": 1700000000,
    "model": "requested-model",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": ""},
                 "finish_reason": "length"},
                {"index": 1, "message": {"role": "assistant", "content": ""},
                 "finish_reason": "length"}],
    "usage": {"prompt_tokens": 5, "completion_tokens": 64, "total_tokens": 69,
              "completion_tokens_details": {"reasoning_tokens": 64}}
  })json"));
}

TEST(GeminiToOpenAiUnaryTest, MalformedCandidates) {
  EXPECT_EQ(geminiUnaryToOpenAi(R"json({"candidates": [
    null, "x", {"content": "bad", "finishReason": 7},
    {"content": {"parts": [null, {"text": 5}, {"functionCall": "f"}]}}]})json")["choices"],
            parse(R"json([
    {"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"},
    {"index": 1, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"},
    {"index": 2, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"},
    {"index": 3, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}
  ])json"));
}

TEST(GeminiToOpenAiUnaryTest, CountsAsNumericStrings) {
  json converted = geminiUnaryToOpenAi(R"json({
    "candidates": [{"content": {"parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
    "usageMetadata": {"promptTokenCount": "8", "candidatesTokenCount": "3",
                      "thoughtsTokenCount": "2", "cachedContentTokenCount": 1.0}
  })json");
  EXPECT_EQ(converted["usage"], parse(R"json({
    "prompt_tokens": 8, "completion_tokens": 5, "total_tokens": 13,
    "prompt_tokens_details": {"cached_tokens": 1},
    "completion_tokens_details": {"reasoning_tokens": 2}
  })json"));
}

TEST(GeminiToOpenAiUnaryTest, UnusableCountsIgnored) {
  json converted = geminiUnaryToOpenAi(R"json({
    "candidates": [{"content": {"parts": [{"text": "hi"}]}}],
    "usageMetadata": {"promptTokenCount": "abc", "candidatesTokenCount": -1,
                      "totalTokenCount": 1.5, "thoughtsTokenCount": true,
                      "cachedContentTokenCount": "9007199254740992",
                      "toolUsePromptTokenCount": 1e300, "trafficType": "ON_DEMAND"}
  })json");
  EXPECT_FALSE(converted.contains("usage"));
  EXPECT_EQ(converted["choices"][0]["finish_reason"], "stop");

  json signed_count = parse(R"json({"candidates": [], "usageMetadata": {}})json");
  signed_count["usageMetadata"]["promptTokenCount"] = int64_t{7};
  absl::StatusOr<json> result = convertGeminiToOpenAiUnary(signed_count, testContext());
  ASSERT_TRUE(result.ok());
  EXPECT_EQ((*result)["usage"],
            parse(R"({"prompt_tokens": 7, "completion_tokens": 0, "total_tokens": 7})"));
}

TEST(GeminiToOpenAiUnaryTest, FinishReasons) {
  struct Case {
    std::optional<std::string> gemini;
    bool with_call;
    std::string openai;
  };
  const std::vector<Case> cases = {
      {"STOP", false, "stop"},
      {"STOP", true, "tool_calls"},
      {"MAX_TOKENS", false, "length"},
      {"MAX_TOKENS", true, "length"},
      {"SAFETY", false, "content_filter"},
      {"RECITATION", false, "content_filter"},
      {"BLOCKLIST", false, "content_filter"},
      {"PROHIBITED_CONTENT", false, "content_filter"},
      {"SPII", false, "content_filter"},
      {"IMAGE_SAFETY", false, "content_filter"},
      {"IMAGE_PROHIBITED_CONTENT", false, "content_filter"},
      {"LANGUAGE", false, "content_filter"},
      {"OTHER", false, "stop"},
      {"MALFORMED_FUNCTION_CALL", false, "stop"},
      {"FINISH_REASON_UNSPECIFIED", false, "stop"},
      {std::nullopt, false, "stop"},
      {std::nullopt, true, "stop"},
  };
  for (const Case& test_case : cases) {
    json candidate = {{"content", {{"parts", json::array()}}}};
    candidate["content"]["parts"].push_back(
        test_case.with_call ? json{{"functionCall", {{"name", "f"}}}} : json{{"text", "x"}});
    if (test_case.gemini.has_value()) {
      candidate["finishReason"] = *test_case.gemini;
    }
    json body = json::object();
    body["candidates"] = json::array({candidate});
    absl::StatusOr<json> converted = convertGeminiToOpenAiUnary(body, testContext());
    ASSERT_TRUE(converted.ok());
    EXPECT_EQ((*converted)["choices"][0]["finish_reason"], test_case.openai)
        << test_case.gemini.value_or("<missing>");
  }
}

TEST(GeminiToOpenAiUnaryTest, PromptBlocked) {
  EXPECT_EQ(geminiUnaryToOpenAi(R"json({
    "promptFeedback": {"blockReason": "SAFETY"},
    "usageMetadata": {"promptTokenCount": 3, "totalTokenCount": 3},
    "modelVersion": "gemini-2.5-flash", "responseId": "blocked"
  })json"),
            parse(R"json({
    "id": "blocked", "object": "chat.completion", "created": 1700000000,
    "model": "gemini-2.5-flash",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": ""},
                 "finish_reason": "content_filter"}],
    "usage": {"prompt_tokens": 3, "completion_tokens": 0, "total_tokens": 3}
  })json"));
}

TEST(GeminiToOpenAiUnaryTest, NoCandidates) {
  EXPECT_EQ(geminiUnaryToOpenAi(R"({"candidates": [], "promptFeedback": {}})")["choices"],
            json::array());
}

TEST(GeminiToOpenAiUnaryTest, FunctionCallWithoutName) {
  EXPECT_EQ(geminiUnaryToOpenAi(R"json({"candidates": [{"content": {"parts": [
    {"functionCall": {"name": 3}}]}, "finishReason": "STOP"}]})json")["choices"][0]["message"],
            parse(R"json({"role": "assistant", "content": null, "tool_calls": [
              {"id": "call_0", "type": "function",
               "function": {"name": "", "arguments": "{}"}}]})json"));
}

TEST(GeminiToOpenAiUnaryTest, ErrorBody) {
  EXPECT_EQ(geminiUnaryToOpenAi(R"json({
    "error": {"code": 429, "message": "Quota exceeded.", "status": "RESOURCE_EXHAUSTED"}
  })json"),
            parse(R"json({
    "error": {"message": "Quota exceeded.", "type": "RESOURCE_EXHAUSTED", "code": 429}
  })json"));
  EXPECT_EQ(geminiUnaryToOpenAi(R"({"error": {"message": 7}})"),
            parse(R"({"error": {"message": "", "type": "api_error", "code": null}})"));
}

TEST(GeminiToOpenAiUnaryTest, NotAnObject) {
  EXPECT_EQ(convertGeminiToOpenAiUnary(json::array(), testContext()).status().code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_EQ(convertGeminiToOpenAiUnary(json("text"), testContext()).status().code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(GeminiToOpenAiUnaryTest, OffloadedValues) {
  json body = parse(R"({"candidates": [{"content": {"parts": [{"text": ""}]}}]})");
  body["candidates"][0]["content"]["parts"][0]["text"] = offloaded();
  absl::StatusOr<json> converted = convertGeminiToOpenAiUnary(body, testContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["choices"][0]["message"]["content"], offloaded());

  body["candidates"][0]["content"]["parts"].push_back({{"text", "tail"}});
  EXPECT_EQ(convertGeminiToOpenAiUnary(body, testContext()).status().code(),
            absl::StatusCode::kUnimplemented);

  json call = parse(R"({"candidates": [{"content": {"parts": [{"functionCall": {}}]}}]})");
  call["candidates"][0]["content"]["parts"][0]["functionCall"]["args"] = {{"text", offloaded()}};
  EXPECT_EQ(convertGeminiToOpenAiUnary(call, testContext()).status().code(),
            absl::StatusCode::kUnimplemented);
}

TEST(GeminiToOpenAiStreamTest, CapturedText) {
  const std::string id = "BBe0apzEK8uSsbwPiefy0Qk";
  const std::string model = "gemini-2.5-flash";
  EXPECT_EQ(
      geminiToOpenAiStream(sseFrames(GeminiSseText)),
      json::array(
          {openAiChunk(id, model, roleDelta()), openAiChunk(id, model, contentDelta("1")),
           openAiChunk(id, model, contentDelta(", 2, ")),
           openAiChunk(id, model, contentDelta("3, 4, 5")),
           finishChunk(id, model, "stop", parse(R"({"prompt_tokens": 11, "completion_tokens": 13,
                                               "total_tokens": 24})")),
           "[DONE]"}));
}

TEST(GeminiToOpenAiStreamTest, CapturedFunctionCalls) {
  const std::string id = "OBm0au2xONiUotQP-NP1sAM";
  const std::string model = "gemini-2.5-flash";
  EXPECT_EQ(geminiToOpenAiStream(sseFrames(GeminiSseFunctionCall)),
            json::array({openAiChunk(id, model, roleDelta()),
                         openAiChunk(id, model, parse(R"json({"tool_calls": [
                           {"index": 0, "id": "call_0", "type": "function",
                            "function": {"name": "get_weather",
                                         "arguments": "{\"city\":\"Paris\"}"}}]})json")),
                         openAiChunk(id, model, parse(R"json({"tool_calls": [
                           {"index": 1, "id": "call_1", "type": "function",
                            "function": {"name": "get_weather",
                                         "arguments": "{\"city\":\"Tokyo\"}"}}]})json")),
                         finishChunk(id, model, "tool_calls",
                                     parse(R"({"prompt_tokens": 27, "completion_tokens": 10,
                                               "total_tokens": 37})")),
                         "[DONE]"}));
}

TEST(GeminiToOpenAiStreamTest, CapturedThoughts) {
  const std::string id = "ORm0av7TIN2fsbwPhreo8A0";
  const std::string model = "gemini-2.5-flash";
  EXPECT_EQ(
      geminiToOpenAiStream(sseFrames(GeminiSseThoughts)),
      json::array(
          {openAiChunk(id, model, roleDelta()),
           openAiChunk(id, model, contentDelta("The sky is blue because of Rayleigh scattering.")),
           finishChunk(id, model, "stop", parse(R"json({
             "prompt_tokens": 9, "completion_tokens": 142, "total_tokens": 151,
             "completion_tokens_details": {"reasoning_tokens": 112}})json")),
           "[DONE]"}));
}

TEST(GeminiToOpenAiStreamTest, UsageReporting) {
  const std::string id = "BBe0apzEK8uSsbwPiefy0Qk";
  const std::string model = "gemini-2.5-flash";
  const json usage = parse(R"({"prompt_tokens": 11, "completion_tokens": 13, "total_tokens": 24})");
  auto last_frame = [] { return std::vector<SseFrame>{std::move(sseFrames(GeminiSseText)[2])}; };

  for (const bool always_report_usage : {true, false}) {
    EXPECT_EQ(
        geminiToOpenAiStream(last_frame(), testContext(true, always_report_usage)),
        json::array({openAiChunk(id, model, roleDelta()),
                     openAiChunk(id, model, contentDelta("3, 4, 5")),
                     finishChunk(id, model, "stop"), usageChunk(id, model, usage), "[DONE]"}));
  }
  EXPECT_EQ(geminiToOpenAiStream(last_frame(), testContext(false, false)),
            json::array({openAiChunk(id, model, roleDelta()),
                         openAiChunk(id, model, contentDelta("3, 4, 5")),
                         finishChunk(id, model, "stop"), "[DONE]"}));

  std::vector<SseFrame> without_counts = sseFrames(GeminiSseText);
  (*without_counts[2].json)["usageMetadata"] = {{"trafficType", "ON_DEMAND"}};
  json converted = geminiToOpenAiStream(std::move(without_counts), testContext(true));
  ASSERT_EQ(converted.size(), 6U);
  EXPECT_EQ(converted[4], finishChunk(id, model, "stop"));
  EXPECT_EQ(converted[5], "[DONE]");
}

TEST(GeminiToOpenAiStreamTest, TruncatedStreamEmitsNoTerminator) {
  std::vector<SseFrame> frames = sseFrames(GeminiSseText);
  frames.pop_back();
  const std::string id = "BBe0apzEK8uSsbwPiefy0Qk";
  const std::string model = "gemini-2.5-flash";
  EXPECT_EQ(
      geminiToOpenAiStream(std::move(frames), testContext(true)),
      json::array({openAiChunk(id, model, roleDelta()), openAiChunk(id, model, contentDelta("1")),
                   openAiChunk(id, model, contentDelta(", 2, "))}));
}

TEST(GeminiToOpenAiStreamTest, ErrorFrameEndsStream) {
  std::vector<SseFrame> frames = sseFrames(GeminiSseText);
  frames[1] = frame(R"json({"error": {"code": 503, "message": "The model is overloaded.",
                                      "status": "UNAVAILABLE"}})json");
  const std::string id = "BBe0apzEK8uSsbwPiefy0Qk";
  const std::string model = "gemini-2.5-flash";
  EXPECT_EQ(
      geminiToOpenAiStream(std::move(frames)),
      json::array({openAiChunk(id, model, roleDelta()), openAiChunk(id, model, contentDelta("1")),
                   parse(R"json({"error": {"message": "The model is overloaded.",
                                                 "type": "UNAVAILABLE", "code": 503}})json")}));

  std::vector<SseFrame> error_first;
  error_first.push_back(frame(R"({"error": {"code": 400, "message": "bad"}})"));
  EXPECT_EQ(geminiToOpenAiStream(std::move(error_first)),
            json::array({parse(R"({"error": {"message": "bad", "type": "api_error",
                                             "code": 400}})")}));
}

TEST(GeminiToOpenAiStreamTest, PromptBlocked) {
  std::vector<SseFrame> frames;
  frames.push_back(frame(R"json({"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"},
                                 "usageMetadata": {"promptTokenCount": 4, "totalTokenCount": 4},
                                 "modelVersion": "gemini-2.5-flash", "responseId": "b1"})json"));
  EXPECT_EQ(geminiToOpenAiStream(std::move(frames)),
            json::array({openAiChunk("b1", "gemini-2.5-flash", roleDelta()),
                         finishChunk("b1", "gemini-2.5-flash", "content_filter",
                                     parse(R"({"prompt_tokens": 4, "completion_tokens": 0,
                                               "total_tokens": 4})")),
                         "[DONE]"}));
}

TEST(GeminiToOpenAiStreamTest, DroppedFramesAndLateUsage) {
  std::vector<SseFrame> frames;
  frames.push_back(SseFrame::ofData("not json"));
  frames.push_back(frame("[1, 2]"));
  frames.push_back(frame(R"({"usageMetadata": {"trafficType": "ON_DEMAND"}})"));
  frames.push_back(frame(R"({"candidates": [{"finishReason": "MAX_TOKENS"}]})"));
  frames.push_back(frame(R"json({"candidates": [{"content": {"parts": [{"text": "late"}]},
                                                 "finishReason": "STOP"}],
                                 "usageMetadata": {"promptTokenCount": 2,
                                                   "totalTokenCount": 66,
                                                   "thoughtsTokenCount": 64}})json"));
  const std::string id = "chatcmpl-envoy";
  const std::string model = "requested-model";
  EXPECT_EQ(geminiToOpenAiStream(std::move(frames), testContext(true)),
            json::array({openAiChunk(id, model, roleDelta()), finishChunk(id, model, "length"),
                         usageChunk(id, model, parse(R"json({
                           "prompt_tokens": 2, "completion_tokens": 64, "total_tokens": 66,
                           "completion_tokens_details": {"reasoning_tokens": 64}})json")),
                         "[DONE]"}));
}

TEST(GeminiToOpenAiStreamTest, OnlyCandidateZero) {
  std::vector<SseFrame> frames;
  frames.push_back(frame(R"json({"candidates": [
    {"content": {"parts": [{"text": "a"}, {"text": "b", "thought": true}, {"text": "c"}]}},
    {"index": 1, "content": {"parts": [{"text": "other"}]}, "finishReason": "STOP"}]})json"));
  frames.push_back(frame(R"json({"candidates": [
    {"index": 1, "content": {"parts": [{"text": "more"}]}, "finishReason": "MAX_TOKENS"}]})json"));
  frames.push_back(frame(R"json({"candidates": [
    {"index": "1", "content": {"parts": [{"text": "last"}]}},
    {"content": {"parts": [{"text": "d"}]}, "finishReason": "STOP"}]})json"));
  const std::string id = "chatcmpl-envoy";
  const std::string model = "requested-model";
  EXPECT_EQ(
      geminiToOpenAiStream(std::move(frames)),
      json::array({openAiChunk(id, model, roleDelta()), openAiChunk(id, model, contentDelta("ac")),
                   openAiChunk(id, model, contentDelta("d")), finishChunk(id, model, "stop"),
                   "[DONE]"}));
}

TEST(GeminiToOpenAiStreamTest, MalformedCandidates) {
  std::vector<SseFrame> frames;
  frames.push_back(frame(R"({"candidates": [null]})"));
  frames.push_back(frame(R"({"candidates": "x"})"));
  frames.push_back(frame(R"({"candidates": [{"content": {"parts": "x"}, "finishReason": 3}]})"));
  frames.push_back(frame(R"({"candidates": [{"content": {"parts": [null, {"text": 5}]}}]})"));
  EXPECT_EQ(geminiToOpenAiStream(std::move(frames)),
            json::array({openAiChunk("chatcmpl-envoy", "requested-model", roleDelta())}));
}

TEST(GeminiToOpenAiStreamTest, OffloadedValues) {
  json body =
      parse(R"({"candidates": [{"content": {"parts": [{}, {"text": "a"}, {"text": "b"}]}}]})");
  body["candidates"][0]["content"]["parts"][0]["text"] = offloaded();
  StreamConverterPtr converter = createGeminiToOpenAiStreamConverter(testContext());
  std::vector<SseFrame> out;
  ASSERT_TRUE(converter->onFrame(SseFrame::ofJson(body), out).ok());
  const std::string id = "chatcmpl-envoy";
  const std::string model = "requested-model";
  EXPECT_EQ(render(out), json::array({openAiChunk(id, model, roleDelta()),
                                      openAiChunk(id, model, contentDelta(offloaded())),
                                      openAiChunk(id, model, contentDelta("ab"))}));

  json call =
      parse(R"({"candidates": [{"content": {"parts": [{"functionCall": {"name": "f"}}]}}]})");
  call["candidates"][0]["content"]["parts"][0]["functionCall"]["args"] = {
      {"list", json::array({offloaded()})}};
  EXPECT_EQ(converter->onFrame(SseFrame::ofJson(call), out).code(),
            absl::StatusCode::kUnimplemented);
}

TEST(OpenAiToGeminiUnaryTest, Text) {
  EXPECT_EQ(openAiUnaryToGemini(R"json({
    "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-4o",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello!"},
                 "finish_reason": "stop", "logprobs": null}],
    "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}
  })json"),
            parse(R"json({
    "candidates": [{"content": {"role": "model", "parts": [{"text": "Hello!"}]},
                    "finishReason": "STOP", "index": 0}],
    "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 2, "totalTokenCount": 7},
    "modelVersion": "gpt-4o", "responseId": "chatcmpl-1"
  })json"));
}

TEST(OpenAiToGeminiUnaryTest, ToolCallsAndDetailedUsage) {
  EXPECT_EQ(openAiUnaryToGemini(R"json({
    "id": "chatcmpl-2", "model": "gpt-4o",
    "choices": [{"index": 0,
                 "message": {"role": "assistant", "content": "Let me check.",
                             "tool_calls": [
                               {"id": "call_a", "type": "function",
                                "function": {"name": "get_weather",
                                             "arguments": "{\"city\": \"Paris\"}"}},
                               {"id": "call_b", "type": "function",
                                "function": {"name": "get_time", "arguments": " "}},
                               {"id": "call_c", "type": "function",
                                "function": {"name": "noop", "arguments": null}},
                               {"id": "call_d", "type": "function"}]},
                 "finish_reason": "tool_calls"}],
    "usage": {"prompt_tokens": 10, "completion_tokens": 50, "total_tokens": 60,
              "prompt_tokens_details": {"cached_tokens": 4},
              "completion_tokens_details": {"reasoning_tokens": 20}}
  })json"),
            parse(R"json({
    "candidates": [{"content": {"role": "model",
                                "parts": [{"text": "Let me check."},
                                          {"functionCall": {"name": "get_weather",
                                                            "args": {"city": "Paris"}}},
                                          {"functionCall": {"name": "get_time", "args": {}}},
                                          {"functionCall": {"name": "noop", "args": {}}},
                                          {"functionCall": {"name": "", "args": {}}}]},
                    "finishReason": "STOP", "index": 0}],
    "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 30, "totalTokenCount": 60,
                      "thoughtsTokenCount": 20, "cachedContentTokenCount": 4},
    "modelVersion": "gpt-4o", "responseId": "chatcmpl-2"
  })json"));
}

TEST(OpenAiToGeminiUnaryTest, FinishReasons) {
  const std::vector<std::pair<json, std::string>> cases = {
      {"stop", "STOP"},          {"length", "MAX_TOKENS"},  {"content_filter", "SAFETY"},
      {"tool_calls", "STOP"},    {"function_call", "STOP"}, {nullptr, "STOP"},
      {"something_new", "STOP"},
  };
  for (const auto& [openai, gemini] : cases) {
    json body = {{"choices", json::array({{{"finish_reason", openai}}})}};
    absl::StatusOr<json> converted = convertOpenAiToGeminiUnary(body, testContext());
    ASSERT_TRUE(converted.ok());
    EXPECT_EQ((*converted)["candidates"][0]["finishReason"], gemini) << openai;
  }
}

TEST(OpenAiToGeminiUnaryTest, Defaults) {
  EXPECT_EQ(openAiUnaryToGemini(R"json({
    "choices": [{"message": {"role": "assistant", "content": null}},
                {"index": 3, "message": {"content": ""}},
                {"finish_reason": "length"},
                "not a choice"],
    "usage": {"completion_tokens": 3, "completion_tokens_details": {"reasoning_tokens": 5}}
  })json"),
            parse(R"json({
    "candidates": [
      {"content": {"role": "model", "parts": [{"text": ""}]}, "finishReason": "STOP", "index": 0},
      {"content": {"role": "model", "parts": [{"text": ""}]}, "finishReason": "STOP", "index": 3},
      {"content": {"role": "model", "parts": [{"text": ""}]}, "finishReason": "MAX_TOKENS",
       "index": 2},
      {"content": {"role": "model", "parts": [{"text": ""}]}, "finishReason": "STOP", "index": 3}],
    "usageMetadata": {"candidatesTokenCount": 0, "thoughtsTokenCount": 5},
    "modelVersion": "requested-model"
  })json"));
}

TEST(OpenAiToGeminiUnaryTest, OffloadedContentIsCopied) {
  json body = parse(R"({"choices": [{"message": {"content": ""}}]})");
  body["choices"][0]["message"]["content"] = offloaded();
  absl::StatusOr<json> converted = convertOpenAiToGeminiUnary(body, testContext());
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ((*converted)["candidates"][0]["content"]["parts"][0]["text"], offloaded());
}

TEST(OpenAiToGeminiUnaryTest, InvalidArguments) {
  for (const json& arguments :
       {json("{not json"), json("[1, 2]"), json("\"text\""), json(42), offloaded()}) {
    EXPECT_EQ(convertOpenAiToGeminiUnary(toolCallBody(arguments), testContext()).status().code(),
              absl::StatusCode::kInvalidArgument)
        << arguments;
  }
}

TEST(OpenAiToGeminiUnaryTest, ToolCallCutOffAtLength) {
  EXPECT_EQ(openAiUnaryToGemini(R"json({
    "id": "chatcmpl-3", "model": "gpt-4o",
    "choices": [{"index": 0,
                 "message": {"role": "assistant", "content": null, "tool_calls": [
                   {"id": "call_a", "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\": \"Paris\"}"}},
                   {"id": "call_b", "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\": \"Tok"}}]},
                 "finish_reason": "length"}]
  })json"),
            parse(R"json({
    "candidates": [{"content": {"role": "model",
                                "parts": [{"functionCall": {"name": "get_weather",
                                                            "args": {"city": "Paris"}}}]},
                    "finishReason": "MAX_TOKENS", "index": 0}],
    "modelVersion": "gpt-4o", "responseId": "chatcmpl-3"
  })json"));
}

TEST(OpenAiToGeminiUnaryTest, ArgumentsNestingIsBounded) {
  for (const std::string& arguments : {nestedObjects(101), nestedArrays(100)}) {
    absl::StatusOr<json> converted =
        convertOpenAiToGeminiUnary(toolCallBody(arguments), testContext());
    ASSERT_TRUE(converted.ok()) << converted.status();
    EXPECT_EQ((*converted)["candidates"][0]["content"]["parts"][0]["functionCall"]["args"],
              parse(arguments));
  }
  for (const std::string& arguments :
       {nestedObjects(102), nestedArrays(101), nestedObjects(100000), nestedArrays(100000)}) {
    absl::StatusOr<json> converted =
        convertOpenAiToGeminiUnary(toolCallBody(arguments), testContext());
    EXPECT_EQ(converted.status().code(), absl::StatusCode::kInvalidArgument);
    EXPECT_EQ(converted.status().message(), "tool call 'f' arguments nest deeper than 100 levels");
  }
}

TEST(OpenAiToGeminiUnaryTest, ErrorBody) {
  EXPECT_EQ(openAiUnaryToGemini(R"json({"error": {"message": "Bad request",
                                                  "type": "invalid_request_error",
                                                  "param": null, "code": "invalid_value"}})json"),
            parse(R"json({"error": {"code": 400, "message": "Bad request",
                                    "status": "INVALID_ARGUMENT"}})json"));
  EXPECT_EQ(openAiUnaryToGemini(R"({"error": {"message": "x", "type": "overloaded_error",
                                              "code": 529}})"),
            parse(R"({"error": {"code": 529, "message": "x", "status": "UNAVAILABLE"}})"));
  EXPECT_EQ(openAiUnaryToGemini(R"({"error": {"type": "server_error"}})"),
            parse(R"({"error": {"code": 500, "message": "", "status": "INTERNAL"}})"));
  EXPECT_EQ(openAiUnaryToGemini(R"({"error": {"message": "slow down", "type": "requests",
                                              "code": 429}})"),
            parse(R"({"error": {"code": 429, "message": "slow down",
                                "status": "RESOURCE_EXHAUSTED"}})"));
  EXPECT_EQ(openAiUnaryToGemini(R"({"error": {"message": "m", "code": 503}})"),
            parse(R"({"error": {"code": 503, "message": "m", "status": "UNAVAILABLE"}})"));
  EXPECT_EQ(openAiUnaryToGemini(R"({"error": {"message": "m", "type": "tokens", "code": 418}})"),
            parse(R"({"error": {"code": 418, "message": "m", "status": "INTERNAL"}})"));

  const std::vector<std::tuple<std::string, std::string, int>> types = {
      {"authentication_error", "UNAUTHENTICATED", 401},
      {"permission_error", "PERMISSION_DENIED", 403},
      {"not_found_error", "NOT_FOUND", 404},
      {"rate_limit_error", "RESOURCE_EXHAUSTED", 429},
      {"insufficient_quota", "RESOURCE_EXHAUSTED", 429},
  };
  for (const auto& [type, status, code] : types) {
    json body = {{"error", {{"message", "m"}, {"type", type}}}};
    absl::StatusOr<json> converted = convertOpenAiToGeminiUnary(body, testContext());
    ASSERT_TRUE(converted.ok());
    EXPECT_EQ(*converted, json({{"error", {{"code", code}, {"message", "m"}, {"status", status}}}}))
        << type;
  }
}

TEST(OpenAiToGeminiUnaryTest, NotAnObject) {
  EXPECT_EQ(convertOpenAiToGeminiUnary(json::array(), testContext()).status().code(),
            absl::StatusCode::kInvalidArgument);
}

std::vector<SseFrame> openAiTextStream() {
  std::vector<SseFrame> frames;
  frames.push_back(frame(R"json({"id": "chatcmpl-9", "object": "chat.completion.chunk",
    "created": 1, "model": "gpt-4o", "usage": null,
    "choices": [{"index": 0, "delta": {"role": "assistant", "content": "", "refusal": null},
                 "logprobs": null, "finish_reason": null}]})json"));
  frames.push_back(frame(R"json({"id": "chatcmpl-9", "object": "chat.completion.chunk",
    "created": 1, "model": "gpt-4o", "usage": null,
    "choices": [{"index": 0, "delta": {"content": "Hello"}, "logprobs": null,
                 "finish_reason": null}]})json"));
  frames.push_back(frame(R"json({"id": "chatcmpl-9", "object": "chat.completion.chunk",
    "created": 1, "model": "gpt-4o", "usage": null,
    "choices": [{"index": 0, "delta": {"content": " world"}, "logprobs": null,
                 "finish_reason": null}]})json"));
  frames.push_back(frame(R"json({"id": "chatcmpl-9", "object": "chat.completion.chunk",
    "created": 1, "model": "gpt-4o", "usage": null,
    "choices": [{"index": 0, "delta": {}, "logprobs": null, "finish_reason": "stop"}]})json"));
  frames.push_back(frame(R"json({"id": "chatcmpl-9", "object": "chat.completion.chunk",
    "created": 1, "model": "gpt-4o", "choices": [],
    "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}})json"));
  frames.push_back(SseFrame::ofData("[DONE]"));
  return frames;
}

json geminiTextFrame(const std::string& text) {
  json result = {{"candidates", json::array({{{"index", 0}}})},
                 {"modelVersion", "gpt-4o"},
                 {"responseId", "chatcmpl-9"}};
  result["candidates"][0]["content"] = {{"role", "model"}, {"parts", json::array()}};
  result["candidates"][0]["content"]["parts"].push_back({{"text", text}});
  return result;
}

TEST(OpenAiToGeminiStreamTest, Text) {
  EXPECT_EQ(openAiToGeminiStream(openAiTextStream()),
            json::array({geminiTextFrame("Hello"), geminiTextFrame(" world"), parse(R"json({
              "candidates": [{"content": {"role": "model", "parts": [{"text": ""}]},
                              "finishReason": "STOP", "index": 0}],
              "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 2,
                                "totalTokenCount": 6},
              "modelVersion": "gpt-4o", "responseId": "chatcmpl-9"})json")}));
}

TEST(OpenAiToGeminiStreamTest, FragmentedToolCalls) {
  std::vector<SseFrame> frames;
  frames.push_back(frame(R"json({"id": "chatcmpl-t", "model": "gpt-4o", "choices": [
    {"index": 0, "delta": {"role": "assistant", "content": null, "tool_calls": [
      {"index": 1, "id": "call_b", "type": "function",
       "function": {"name": "get_time", "arguments": ""}}]}}]})json"));
  frames.push_back(frame(R"json({"id": "chatcmpl-t", "model": "gpt-4o", "choices": [
    {"index": 0, "delta": {"tool_calls": [
      {"index": 0, "id": "call_a", "type": "function",
       "function": {"name": "get_weather", "arguments": "{\"ci"}}]}}]})json"));
  frames.push_back(frame(R"json({"id": "chatcmpl-t", "model": "gpt-4o", "choices": [
    {"index": 0, "delta": {"tool_calls": [
      {"index": 0, "function": {"arguments": "ty\": \"Paris\"}"}},
      {"index": 1, "function": {"name": "", "arguments": "{}"}},
      {"index": 2}]}}]})json"));
  frames.push_back(frame(R"json({"id": "chatcmpl-t", "model": "gpt-4o", "choices": [
    {"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
    "usage": {"prompt_tokens": 3, "completion_tokens": 9, "total_tokens": 12}})json"));
  frames.push_back(SseFrame::ofData("[DONE]\n"));
  EXPECT_EQ(openAiToGeminiStream(std::move(frames)), json::array({parse(R"json({
    "candidates": [{"content": {"role": "model",
                                "parts": [{"functionCall": {"name": "get_weather",
                                                            "args": {"city": "Paris"}}},
                                          {"functionCall": {"name": "get_time", "args": {}}},
                                          {"functionCall": {"name": "", "args": {}}}]},
                    "finishReason": "STOP", "index": 0}],
    "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 9, "totalTokenCount": 12},
    "modelVersion": "gpt-4o", "responseId": "chatcmpl-t"})json")}));
}

TEST(OpenAiToGeminiStreamTest, ToolCallsWithoutIndex) {
  std::vector<SseFrame> frames;
  frames.push_back(frame(R"json({"choices": [{"index": 0, "delta": {"tool_calls": [
    {"id": "call_a", "type": "function", "function": {"name": "a", "arguments": "{\"x\":1}"}},
    {"id": "call_b", "type": "function", "function": {"name": "b", "arguments": "{}"}}]},
    "finish_reason": "tool_calls"}]})json"));
  frames.push_back(SseFrame::ofData("[DONE]"));
  EXPECT_EQ(openAiToGeminiStream(std::move(frames)), parse(R"json([{
    "candidates": [{"content": {"role": "model",
                                "parts": [{"functionCall": {"name": "a", "args": {"x": 1}}},
                                          {"functionCall": {"name": "b", "args": {}}}]},
                    "finishReason": "STOP", "index": 0}],
    "modelVersion": "requested-model"}])json"));
}

TEST(OpenAiToGeminiStreamTest, ToolCallCutOffAtLength) {
  std::vector<SseFrame> frames;
  frames.push_back(frame(R"json({"id": "chatcmpl-l", "model": "gpt-4o", "choices": [
    {"index": 0, "delta": {"tool_calls": [
      {"index": 0, "id": "call_a", "type": "function",
       "function": {"name": "get_weather", "arguments": "{\"ci"}}]}}]})json"));
  frames.push_back(frame(R"json({"id": "chatcmpl-l", "model": "gpt-4o", "choices": [
    {"index": 0, "delta": {}, "finish_reason": "length"}]})json"));
  frames.push_back(SseFrame::ofData("[DONE]"));
  EXPECT_EQ(openAiToGeminiStream(std::move(frames)), json::array({parse(R"json({
    "candidates": [{"content": {"role": "model", "parts": [{"text": ""}]},
                    "finishReason": "MAX_TOKENS", "index": 0}],
    "modelVersion": "gpt-4o", "responseId": "chatcmpl-l"})json")}));
}

TEST(OpenAiToGeminiStreamTest, FinishWithoutDone) {
  std::vector<SseFrame> frames;
  frames.push_back(frame(R"({"choices": [{"index": 0, "delta": {"content": "cut"}}]})"));
  frames.push_back(frame(R"({"choices": [{"index": 0, "finish_reason": "length"}]})"));
  EXPECT_EQ(openAiToGeminiStream(std::move(frames)), parse(R"json([
    {"candidates": [{"content": {"role": "model", "parts": [{"text": "cut"}]}, "index": 0}],
     "modelVersion": "requested-model"},
    {"candidates": [{"content": {"role": "model", "parts": [{"text": ""}]},
                     "finishReason": "MAX_TOKENS", "index": 0}],
     "modelVersion": "requested-model"}])json"));
}

TEST(OpenAiToGeminiStreamTest, TruncatedStreamEmitsNoFinalFrame) {
  std::vector<SseFrame> frames = openAiTextStream();
  frames.resize(3);
  EXPECT_EQ(openAiToGeminiStream(std::move(frames)),
            json::array({geminiTextFrame("Hello"), geminiTextFrame(" world")}));
  EXPECT_EQ(openAiToGeminiStream({}), json::array());
}

TEST(OpenAiToGeminiStreamTest, ErrorFrameEndsStream) {
  std::vector<SseFrame> frames = openAiTextStream();
  frames[2] = frame(R"({"error": {"message": "overloaded", "type": "overloaded_error"}})");
  EXPECT_EQ(openAiToGeminiStream(std::move(frames)),
            json::array(
                {geminiTextFrame("Hello"), parse(R"({"error": {"code": 503, "message": "overloaded",
                                             "status": "UNAVAILABLE"}})")}));
}

TEST(OpenAiToGeminiStreamTest, IgnoredFrames) {
  std::vector<SseFrame> frames = openAiTextStream();
  frames.insert(frames.begin() + 1, SseFrame::ofData(": keep-alive"));
  frames.insert(frames.begin() + 1, frame("[1]"));
  frames.insert(frames.begin() + 1, frame(R"({"id": "chatcmpl-9", "choices": [
    {"index": 1, "delta": {"content": "second choice"}, "finish_reason": "length"}]})"));
  frames.push_back(SseFrame::ofData("[DONE]"));
  json converted = openAiToGeminiStream(std::move(frames));
  ASSERT_EQ(converted.size(), 3U);
  EXPECT_EQ(converted[0], geminiTextFrame("Hello"));
  EXPECT_EQ(converted[2]["candidates"][0]["finishReason"], "STOP");
}

TEST(OpenAiToGeminiStreamTest, InvalidToolCallArguments) {
  StreamConverterPtr converter = createOpenAiToGeminiStreamConverter(testContext());
  std::vector<SseFrame> out;
  ASSERT_TRUE(converter
                  ->onFrame(frame(R"json({"choices": [{"index": 0, "delta": {"tool_calls": [
                    {"index": 0, "function": {"name": "f", "arguments": "{oops"}}]},
                    "finish_reason": "tool_calls"}]})json"),
                            out)
                  .ok());
  EXPECT_EQ(converter->onFrame(SseFrame::ofData("[DONE]"), out).code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_TRUE(out.empty());

  StreamConverterPtr deep = createOpenAiToGeminiStreamConverter(testContext());
  const std::string arguments = nestedObjects(100000);
  for (size_t offset = 0; offset < arguments.size(); offset += arguments.size() / 4 + 1) {
    json chunk = parse(R"json({"choices": [{"index": 0, "delta": {"tool_calls": [
      {"index": 0, "function": {"name": "f"}}]}}]})json");
    chunk["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] =
        arguments.substr(offset, arguments.size() / 4 + 1);
    ASSERT_TRUE(deep->onFrame(SseFrame::ofJson(std::move(chunk)), out).ok());
  }
  EXPECT_EQ(deep->onFrame(SseFrame::ofData("[DONE]"), out).code(),
            absl::StatusCode::kInvalidArgument);
  EXPECT_TRUE(out.empty());

  StreamConverterPtr non_string = createOpenAiToGeminiStreamConverter(testContext());
  EXPECT_EQ(non_string
                ->onFrame(frame(R"json({"choices": [{"index": 0, "delta": {"tool_calls": [
                  {"index": 0, "function": {"name": "f", "arguments": 5}}]}}]})json"),
                          out)
                .code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(GeminiRoundTripTest, Unary) {
  const json original = parse(R"json({
    "id": "chatcmpl-rt", "object": "chat.completion", "created": 1700000000, "model": "gpt-4o",
    "choices": [{"index": 0,
                 "message": {"role": "assistant", "content": "Calling.",
                             "tool_calls": [{"id": "call_0", "type": "function",
                                             "function": {"name": "get_weather",
                                                          "arguments": "{\"city\":\"Paris\"}"}}]},
                 "finish_reason": "tool_calls"}],
    "usage": {"prompt_tokens": 10, "completion_tokens": 50, "total_tokens": 60,
              "prompt_tokens_details": {"cached_tokens": 4},
              "completion_tokens_details": {"reasoning_tokens": 20}}
  })json");
  absl::StatusOr<json> gemini = convertOpenAiToGeminiUnary(original, testContext());
  ASSERT_TRUE(gemini.ok());
  absl::StatusOr<json> openai = convertGeminiToOpenAiUnary(*gemini, testContext());
  ASSERT_TRUE(openai.ok());
  EXPECT_EQ(*openai, original);
}

TEST(GeminiRoundTripTest, Stream) {
  StreamConverterPtr to_gemini = createOpenAiToGeminiStreamConverter(testContext());
  StreamConverterPtr to_openai = createGeminiToOpenAiStreamConverter(testContext());
  std::vector<SseFrame> frames = openAiTextStream();
  frames.insert(frames.begin() + 3, frame(R"json({"id": "chatcmpl-9", "model": "gpt-4o",
    "choices": [{"index": 0, "delta": {"tool_calls": [
      {"index": 0, "id": "call_x", "type": "function",
       "function": {"name": "lookup", "arguments": "{\"q\":1}"}}]}}]})json"));
  std::vector<SseFrame> gemini;
  for (SseFrame& in : frames) {
    ASSERT_TRUE(to_gemini->onFrame(std::move(in), gemini).ok());
  }
  ASSERT_TRUE(to_gemini->onEnd(gemini).ok());

  std::vector<SseFrame> openai;
  for (SseFrame& in : gemini) {
    ASSERT_TRUE(to_openai->onFrame(std::move(in), openai).ok());
  }
  ASSERT_TRUE(to_openai->onEnd(openai).ok());
  const std::string id = "chatcmpl-9";
  const std::string model = "gpt-4o";
  EXPECT_EQ(render(openai),
            json::array({openAiChunk(id, model, roleDelta()),
                         openAiChunk(id, model, contentDelta("Hello")),
                         openAiChunk(id, model, contentDelta(" world")),
                         openAiChunk(id, model, parse(R"json({"tool_calls": [
                                           {"index": 0, "id": "call_0", "type": "function",
                                            "function": {"name": "lookup",
                                                         "arguments": "{\"q\":1}"}}]})json")),
                         finishChunk(id, model, "tool_calls", parse(R"({"prompt_tokens": 4,
                                                               "completion_tokens": 2,
                                                               "total_tokens": 6})")),
                         "[DONE]"}));
}

} // namespace
} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
