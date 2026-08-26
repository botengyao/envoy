#include <algorithm>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/api_protocol_adapter.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_readers.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/filters/http/ai_protocol_manager/schema.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

nlohmann::json parse(const std::string& json) {
  nlohmann::json result = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
  EXPECT_FALSE(result.is_discarded()) << json;
  return result;
}

// Most cases only need the usage half of the extraction result; malformed-flag
// behavior is covered by the dedicated tests below.
TokenUsage extractUsage(ApiProtocol format, const nlohmann::json& json) {
  return AdapterRegistry::get(format).extractUsage(json).usage;
}

// ---------------------------------------------------------------------------
// Provider detection.

TEST(DetectFormatTest, OpenAiChatCompletion) {
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"object":"chat.completion","model":"gpt-4o"})")),
            ApiProtocol::OpenAiChatCompletions);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"object":"chat.completion.chunk","choices":[]})")),
            ApiProtocol::OpenAiChatCompletions);
}

TEST(DetectFormatTest, OpenAiResponsesApi) {
  // Non-streaming Response object and streaming lifecycle events.
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"object":"response","output":[]})")),
            ApiProtocol::OpenAiResponses);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"response.completed","response":{}})")),
            ApiProtocol::OpenAiResponses);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"response.output_text.delta","delta":"hi"})")),
            ApiProtocol::OpenAiResponses);
}

TEST(DetectFormatTest, Anthropic) {
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"message","role":"assistant"})")),
            ApiProtocol::AnthropicMessages);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"message_start","message":{}})")),
            ApiProtocol::AnthropicMessages);
  EXPECT_EQ(
      AdapterRegistry::detect(parse(R"({"type":"message_delta","usage":{"output_tokens":3}})")),
      ApiProtocol::AnthropicMessages);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"message","usage":{"input_tokens":1}})")),
            ApiProtocol::AnthropicMessages);
  // A mid-stream join: the first observed event is a usage-less message_delta,
  // identified by its `delta` object.
  EXPECT_EQ(AdapterRegistry::detect(
                parse(R"({"type":"message_delta","delta":{"stop_reason":"end_turn"}})")),
            ApiProtocol::AnthropicMessages);
}

// The human-readable protocol names match the proto enum value names, so log
// lines and metadata agree.
TEST(ApiProtocolNameTest, NamesMatchProtoEnumValueNames) {
  EXPECT_EQ(apiProtocolName(ApiProtocol::OpenAiChatCompletions), "OPENAI_CHAT_COMPLETIONS");
  EXPECT_EQ(apiProtocolName(ApiProtocol::OpenAiResponses), "OPENAI_RESPONSES");
  EXPECT_EQ(apiProtocolName(ApiProtocol::AnthropicMessages), "ANTHROPIC_MESSAGES");
  EXPECT_EQ(apiProtocolName(ApiProtocol::GeminiGenerateContent), "GEMINI_GENERATE_CONTENT");
  EXPECT_EQ(apiProtocolName(ApiProtocol::Unspecified), "API_PROTOCOL_UNSPECIFIED");
}

// An unspecified wire API extracts nothing: extraction requires a concrete
// dialect (callers detect one first).
TEST(ExtractTest, UnspecifiedFormatExtractsNothing) {
  const auto result = AdapterRegistry::get(ApiProtocol::Unspecified)
                          .extractUsage(parse(R"({"usage":{"input_tokens":1,"output_tokens":2}})"));
  EXPECT_FALSE(result.usage.hasAny());
  EXPECT_FALSE(result.malformed);
}

TEST(DetectFormatTest, StructurelessAnthropicShapedTypesDoNotLock) {
  // A bare `type` string with no corroborating structure is generic: any
  // gateway can emit it, and none of these can carry usage, so treating them
  // as evidence risks poisoning a foreign stream (a lone message_stop would
  // even terminate extraction). In a genuine Anthropic stream, message_start
  // or the non-streaming Message locks the format first.
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"message"})")), ApiProtocol::Unspecified);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"message_stop"})")), ApiProtocol::Unspecified);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"content_block_delta"})")),
            ApiProtocol::Unspecified);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"message_start"})")),
            ApiProtocol::Unspecified);
}

TEST(DetectFormatTest, Gemini) {
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"candidates":[{"content":{}}]})")),
            ApiProtocol::GeminiGenerateContent);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"usageMetadata":{}})")),
            ApiProtocol::GeminiGenerateContent);
}

TEST(DetectFormatTest, Unknown) {
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"foo":"bar"})")), ApiProtocol::Unspecified);
  // A bare content delta with no discriminating markers.
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"text":"hello"})")), ApiProtocol::Unspecified);
  // `ping` is a weak marker any gateway may emit: it must not lock detection.
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"type":"ping"})")), ApiProtocol::Unspecified);
}

TEST(DetectFormatTest, TypeMismatchedMarkersDoNotLock) {
  // Marker keys are generic names; only the Gemini value *shape* counts.
  // hasObject()-style key presence alone must not lock the stream: detection
  // is stream-global, and a foreign document with a `candidates` string would
  // otherwise poison every later event.
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"candidates":"not-gemini"})")),
            ApiProtocol::Unspecified);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"usageMetadata":"nope"})")),
            ApiProtocol::Unspecified);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"usageMetadata":[1]})")), ApiProtocol::Unspecified);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"modelVersion":42})")), ApiProtocol::Unspecified);
  // An array of non-objects is not a Gemini candidates list, and neither is
  // an empty array: real GenerateContentResponse chunks carry candidate
  // objects, so an empty generic `candidates` must not lock the stream.
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"candidates":[1,"x",null]})")),
            ApiProtocol::Unspecified);
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"candidates":[]})")), ApiProtocol::Unspecified);
  // The correctly-shaped markers still detect.
  EXPECT_EQ(AdapterRegistry::detect(parse(R"({"modelVersion":"gemini-2.5-pro"})")),
            ApiProtocol::GeminiGenerateContent);
}

// ---------------------------------------------------------------------------
// OpenAI extraction.

TEST(ExtractOpenAiTest, ChatCompletionNonStreaming) {
  const auto usage = extractUsage(ApiProtocol::OpenAiChatCompletions, parse(R"(
      {"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o-2024-08-06",
       "choices":[{"message":{"content":"hi"}}],
       "usage":{"prompt_tokens":19,"completion_tokens":10,"total_tokens":29,
                "prompt_tokens_details":{"cached_tokens":8,"cache_write_tokens":4},
                "completion_tokens_details":{"reasoning_tokens":3}}})"));
  EXPECT_EQ(usage.input_tokens, 19);
  EXPECT_EQ(usage.output_tokens, 10);
  EXPECT_EQ(usage.total_tokens, 29);
  EXPECT_EQ(usage.cached_input_tokens, 8);
  EXPECT_EQ(usage.cache_creation_input_tokens, 4);
  EXPECT_EQ(usage.reasoning_tokens, 3);
  EXPECT_EQ(usage.model, "gpt-4o-2024-08-06");
  EXPECT_EQ(usage.api_protocol, ApiProtocol::OpenAiChatCompletions);
}

TEST(ExtractOpenAiTest, ChatCompletionUsageChunk) {
  // The include_usage terminal chunk: empty choices, populated usage.
  const auto usage = extractUsage(ApiProtocol::OpenAiChatCompletions, parse(R"(
      {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o-mini",
       "choices":[],"usage":{"prompt_tokens":19,"completion_tokens":10,"total_tokens":29}})"));
  EXPECT_EQ(usage.input_tokens, 19);
  EXPECT_EQ(usage.output_tokens, 10);
  EXPECT_EQ(usage.total_tokens, 29);
}

TEST(ExtractOpenAiTest, UsageNullChunkYieldsNothing) {
  const auto usage = extractUsage(ApiProtocol::OpenAiChatCompletions, parse(R"(
      {"object":"chat.completion.chunk","model":"gpt-4o",
       "choices":[{"delta":{"content":"hi"}}],"usage":null})"));
  EXPECT_FALSE(usage.hasAny());
  EXPECT_EQ(usage.model, "gpt-4o");
}

TEST(ExtractOpenAiTest, ResponsesApiCompletedEvent) {
  const nlohmann::json json = parse(R"(
      {"type":"response.completed","sequence_number":7,
       "response":{"id":"resp_1","object":"response","status":"completed","model":"gpt-5.4",
                   "usage":{"input_tokens":36,
                            "input_tokens_details":{"cached_tokens":12,"cache_write_tokens":6},
                            "output_tokens":87,
                            "output_tokens_details":{"reasoning_tokens":40},
                            "total_tokens":123}}})");
  const auto usage = extractUsage(ApiProtocol::OpenAiResponses, json);
  EXPECT_EQ(usage.input_tokens, 36);
  EXPECT_EQ(usage.output_tokens, 87);
  EXPECT_EQ(usage.total_tokens, 123);
  EXPECT_EQ(usage.cached_input_tokens, 12);
  EXPECT_EQ(usage.cache_creation_input_tokens, 6);
  EXPECT_EQ(usage.reasoning_tokens, 40);
  EXPECT_EQ(usage.model, "gpt-5.4");
  // Terminal lifecycle events end extraction.
  EXPECT_TRUE(AdapterRegistry::get(ApiProtocol::OpenAiResponses).isTerminalEvent(json));
}

// Chat Completions and Gemini have no in-band JSON terminator: a `type`
// field never ends their extraction.
TEST(ExtractOpenAiTest, TypeKeyedDocumentsNotTerminalForOtherDialects) {
  EXPECT_FALSE(AdapterRegistry::get(ApiProtocol::OpenAiChatCompletions)
                   .isTerminalEvent(parse(R"({"type":"response.completed"})")));
  EXPECT_FALSE(AdapterRegistry::get(ApiProtocol::GeminiGenerateContent)
                   .isTerminalEvent(parse(R"({"type":"message_stop"})")));
}

TEST(ExtractOpenAiTest, ResponsesApiFailedAndIncompleteAreTerminal) {
  EXPECT_TRUE(AdapterRegistry::get(ApiProtocol::OpenAiResponses)
                  .isTerminalEvent(parse(R"({"type":"response.failed","response":{}})")));
  EXPECT_TRUE(AdapterRegistry::get(ApiProtocol::OpenAiResponses)
                  .isTerminalEvent(parse(R"({"type":"response.incomplete","response":{}})")));
  EXPECT_FALSE(AdapterRegistry::get(ApiProtocol::OpenAiResponses)
                   .isTerminalEvent(parse(R"({"type":"response.in_progress","response":{}})")));
}

// ---------------------------------------------------------------------------
// Anthropic extraction.

TEST(ExtractAnthropicTest, NonStreaming) {
  const auto usage = extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5",
       "usage":{"input_tokens":2095,"output_tokens":503,
                "cache_creation_input_tokens":2051,"cache_read_input_tokens":1024,
                "output_tokens_details":{"thinking_tokens":77}}})"));
  // extract() reports the dialect's native counts (input excludes the two
  // disjoint cache buckets); finalize() computes the canonical inclusive sum.
  EXPECT_EQ(usage.input_tokens, 2095);
  EXPECT_FALSE(usage.total_tokens.has_value());
  TokenUsage finalized = usage;
  finalizeUsage(finalized);
  // Canonical inclusive input: 2095 uncached + 2051 cache writes + 1024
  // cache reads.
  EXPECT_EQ(finalized.input_tokens, 5170);
  EXPECT_EQ(finalized.output_tokens, 503);
  // No native total in this dialect; computed from the canonical components.
  EXPECT_EQ(finalized.total_tokens, 5673);
  EXPECT_FALSE(finalized.provider_total_tokens.has_value());
  EXPECT_EQ(finalized.cached_input_tokens, 1024);
  EXPECT_EQ(finalized.cache_creation_input_tokens, 2051);
  EXPECT_EQ(finalized.reasoning_tokens, 77);
  EXPECT_EQ(usage.model, "claude-opus-5");
}

TEST(ExtractAnthropicTest, StreamingAccumulation) {
  TokenUsage accumulated;

  // message_start carries the input side and the model, nested under `message`.
  accumulated.merge(extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant",
       "model":"claude-opus-5","content":[],
       "usage":{"input_tokens":2679,"cache_creation_input_tokens":0,
                "cache_read_input_tokens":0,"output_tokens":3}}})")));
  // Cumulative message_delta events; the last one wins.
  accumulated.merge(
      extractUsage(ApiProtocol::AnthropicMessages,
                   parse(R"({"type":"message_delta","delta":{},"usage":{"output_tokens":7}})")));
  accumulated.merge(extractUsage(
      ApiProtocol::AnthropicMessages,
      parse(
          R"({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":15}})")));

  finalizeUsage(accumulated);
  EXPECT_EQ(accumulated.input_tokens, 2679);
  EXPECT_EQ(accumulated.output_tokens, 15);
  EXPECT_EQ(accumulated.total_tokens, 2694);
  EXPECT_EQ(accumulated.model, "claude-opus-5");
}

TEST(ExtractAnthropicTest, FatMessageDeltaOverridesInputSide) {
  // Newer responses repeat input-side counts in message_delta; last wins.
  TokenUsage accumulated;
  accumulated.merge(extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"type":"message_start","message":{"model":"claude-opus-5",
       "usage":{"input_tokens":100,"output_tokens":1}}})")));
  accumulated.merge(extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"type":"message_delta","delta":{"stop_reason":"end_turn"},
       "usage":{"input_tokens":10682,"cache_creation_input_tokens":0,
                "cache_read_input_tokens":0,"output_tokens":510}})")));
  EXPECT_EQ(accumulated.input_tokens, 10682);
  EXPECT_EQ(accumulated.output_tokens, 510);
}

TEST(ExtractAnthropicTest, MessageStartWithoutUsageIsTolerated) {
  const auto usage =
      extractUsage(ApiProtocol::AnthropicMessages,
                   parse(R"({"type":"message_start","message":{"model":"claude-opus-5"}})"));
  EXPECT_FALSE(usage.hasAny());
  EXPECT_EQ(usage.model, "claude-opus-5");
}

TEST(ExtractAnthropicTest, MessageStopIsTerminal) {
  EXPECT_TRUE(AdapterRegistry::get(ApiProtocol::AnthropicMessages)
                  .isTerminalEvent(parse(R"({"type":"message_stop"})")));
  EXPECT_FALSE(AdapterRegistry::get(ApiProtocol::AnthropicMessages)
                   .isTerminalEvent(parse(R"({"type":"message_delta"})")));
}

// ---------------------------------------------------------------------------
// Gemini extraction.

TEST(ExtractGeminiTest, UsageMetadata) {
  const auto usage = extractUsage(ApiProtocol::GeminiGenerateContent, parse(R"(
      {"candidates":[{"content":{"parts":[{"text":"hi"}],"role":"model"},"finishReason":"STOP"}],
       "usageMetadata":{"promptTokenCount":6,"candidatesTokenCount":149,"totalTokenCount":167,
                        "cachedContentTokenCount":2,"thoughtsTokenCount":12},
       "modelVersion":"gemini-2.5-flash"})"));
  EXPECT_EQ(usage.output_tokens, 149); // Native candidates count, thoughts excluded.
  TokenUsage finalized = usage;
  finalizeUsage(finalized);
  EXPECT_EQ(finalized.input_tokens, 6);
  // Canonical inclusive output: 149 candidates + 12 thoughts (Gemini reports
  // thoughts outside candidatesTokenCount).
  EXPECT_EQ(finalized.output_tokens, 161);
  // Computed canonical total (6 + 161) agrees with the provider total, which
  // is already inclusive; the provider total is preserved alongside.
  EXPECT_EQ(finalized.total_tokens, 167);
  EXPECT_EQ(finalized.provider_total_tokens, 167);
  EXPECT_EQ(finalized.cached_input_tokens, 2);
  EXPECT_EQ(finalized.reasoning_tokens, 12);
  EXPECT_EQ(finalized.model, "gemini-2.5-flash");
}

TEST(ExtractGeminiTest, ToolUseAndThoughtsAccounting) {
  // Reviewer merge-gate case: canonical input adds tool-use prompt tokens,
  // canonical output adds thoughts, and both match the provider total.
  auto usage = extractUsage(ApiProtocol::GeminiGenerateContent, parse(R"(
      {"usageMetadata":{"promptTokenCount":6,"toolUsePromptTokenCount":5,
                        "candidatesTokenCount":149,"thoughtsTokenCount":12,
                        "totalTokenCount":172}})"));
  finalizeUsage(usage);
  EXPECT_EQ(usage.input_tokens, 11);
  EXPECT_EQ(usage.output_tokens, 161);
  EXPECT_EQ(usage.total_tokens, 172);
  EXPECT_EQ(usage.provider_total_tokens, 172);
  EXPECT_EQ(usage.tool_use_input_tokens, 5);
  EXPECT_EQ(usage.reasoning_tokens, 12);
}

TEST(ExtractAnthropicTest, CanonicalInclusiveAccounting) {
  // Reviewer merge-gate case: input 100 + cache-creation 20 + cache-read 30
  // yields canonical input 150 and (with output 10) total 160.
  auto usage = extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"type":"message","usage":{"input_tokens":100,"cache_creation_input_tokens":20,
       "cache_read_input_tokens":30,"output_tokens":10}})"));
  finalizeUsage(usage);
  EXPECT_EQ(usage.input_tokens, 150);
  EXPECT_EQ(usage.cached_input_tokens, 30);
  EXPECT_EQ(usage.cache_creation_input_tokens, 20);
  EXPECT_EQ(usage.total_tokens, 160);
}

TEST(ExtractAnthropicTest, PartialInputUpdatePreservesCacheBuckets) {
  // Anthropic's streaming usage fields are independently optional and
  // cumulative. A later message_delta repeating input_tokens but omitting the
  // cache buckets must not regress the canonical inclusive input -- native
  // components accumulate independently and are summed only at finalize.
  TokenUsage accumulated;
  accumulated.merge(extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"type":"message_start","message":{"usage":{"input_tokens":100,
       "cache_read_input_tokens":30,"cache_creation_input_tokens":20,
       "output_tokens":1}}})")));
  accumulated.merge(extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"type":"message_delta","delta":{"stop_reason":"end_turn"},
       "usage":{"input_tokens":100,"output_tokens":50}})")));
  finalizeUsage(accumulated);
  EXPECT_EQ(accumulated.input_tokens, 150); // 100 + 30 + 20, not regressed to 100.
  EXPECT_EQ(accumulated.cached_input_tokens, 30);
  EXPECT_EQ(accumulated.cache_creation_input_tokens, 20);
  EXPECT_EQ(accumulated.output_tokens, 50);
  EXPECT_EQ(accumulated.total_tokens, 200);
}

TEST(ExtractGeminiTest, CumulativeChunksLastWins) {
  TokenUsage accumulated;
  accumulated.merge(extractUsage(ApiProtocol::GeminiGenerateContent, parse(R"(
      {"candidates":[{"content":{"parts":[{"text":"a"}]}}],
       "usageMetadata":{"promptTokenCount":6,"candidatesTokenCount":16,"totalTokenCount":22}})")));
  accumulated.merge(extractUsage(ApiProtocol::GeminiGenerateContent, parse(R"(
      {"candidates":[{"content":{"parts":[{"text":"b"}]},"finishReason":"STOP"}],
       "usageMetadata":{"promptTokenCount":6,"candidatesTokenCount":149,"totalTokenCount":155},
       "modelVersion":"gemini-2.5-flash"})")));
  finalizeUsage(accumulated);
  EXPECT_EQ(accumulated.output_tokens, 149);
  EXPECT_EQ(accumulated.total_tokens, 155);
  EXPECT_EQ(accumulated.model, "gemini-2.5-flash");
}

TEST(ExtractGeminiTest, ChunkWithoutUsageMetadataYieldsNothing) {
  const auto usage =
      extractUsage(ApiProtocol::GeminiGenerateContent,
                   parse(R"({"candidates":[{"content":{"parts":[{"text":"a"}]}}]})"));
  EXPECT_FALSE(usage.hasAny());
}

// ---------------------------------------------------------------------------
// Merge and normalization mechanics.

TEST(TokenUsageTest, PresentButInvalidFieldsAreFlaggedMalformed) {
  // A missing key is not malformed...
  EXPECT_FALSE(AdapterRegistry::get(ApiProtocol::AnthropicMessages)
                   .extractUsage(parse(R"({"usage":{"output_tokens":5}})"))
                   .malformed);
  // ...but a known field that is present with an unusable value is: wrong
  // scalar type, wrong container type, negative, fractional, out of range,
  // and a non-object usage node itself.
  for (const std::string& body : {std::string(R"({"usage":{"output_tokens":"5"}})"),
                                  std::string(R"({"usage":{"output_tokens":{}}})"),
                                  std::string(R"({"usage":{"output_tokens":[5]}})"),
                                  std::string(R"({"usage":{"output_tokens":-5}})"),
                                  std::string(R"({"usage":{"output_tokens":5.5}})"),
                                  std::string(R"({"usage":{"output_tokens":9007199254740992}})"),
                                  std::string(R"({"usage":"not-an-object"})")}) {
    EXPECT_TRUE(
        AdapterRegistry::get(ApiProtocol::AnthropicMessages).extractUsage(parse(body)).malformed)
        << body;
  }
  // Null handling is specific to the position. OpenAI documents `"usage": null` as the
  // placeholder on non-terminal chunks (and failed responses): benignly
  // absent, not malformed, and not degraded.
  EXPECT_FALSE(AdapterRegistry::get(ApiProtocol::OpenAiChatCompletions)
                   .extractUsage(parse(R"({"usage":null})"))
                   .malformed);
  EXPECT_FALSE(
      AdapterRegistry::get(ApiProtocol::OpenAiChatCompletions)
          .extractUsage(parse(R"({"usage":{"prompt_tokens":3,"prompt_tokens_details":null}})"))
          .malformed);
  // A null in a *count* position is malformed in every dialect (the counters
  // are required integers): a corrupt final cumulative update must not leave
  // an earlier value published as complete.
  EXPECT_TRUE(AdapterRegistry::get(ApiProtocol::AnthropicMessages)
                  .extractUsage(parse(R"({"usage":{"output_tokens":null}})"))
                  .malformed);
  EXPECT_TRUE(AdapterRegistry::get(ApiProtocol::OpenAiChatCompletions)
                  .extractUsage(parse(R"({"usage":{"prompt_tokens":null}})"))
                  .malformed);
  // Null in a required structural position is malformed structure.
  EXPECT_TRUE(AdapterRegistry::get(ApiProtocol::OpenAiChatCompletions)
                  .extractUsage(parse(R"({"type":"response.completed","response":null})"))
                  .malformed);
  EXPECT_TRUE(AdapterRegistry::get(ApiProtocol::AnthropicMessages)
                  .extractUsage(parse(R"({"type":"message_start","message":null})"))
                  .malformed);
  // Valid fields alongside a malformed one still extract.
  const auto result =
      AdapterRegistry::get(ApiProtocol::AnthropicMessages)
          .extractUsage(parse(R"({"usage":{"input_tokens":7,"output_tokens":"nope"}})"));
  EXPECT_TRUE(result.malformed);
  EXPECT_EQ(result.usage.input_tokens, 7);
}

TEST(TokenUsageTest, NullCountRegressionScenario) {
  // The reviewer reproduction: a final cumulative message_delta whose output_tokens
  // is null must flag the stream, so the surviving earlier count publishes as
  // partial rather than complete.
  TokenUsage accumulated;
  bool degraded = false;
  auto merge = [&](const std::string& body) {
    const auto result =
        AdapterRegistry::get(ApiProtocol::AnthropicMessages).extractUsage(parse(body));
    accumulated.merge(result.usage);
    degraded |= result.malformed;
  };
  merge(R"({"type":"message_start","message":{"usage":{"input_tokens":10,"output_tokens":3}}})");
  merge(R"({"type":"message_delta","delta":{"stop_reason":"end_turn"},)"
        R"("usage":{"output_tokens":null}})");
  finalizeUsage(accumulated);
  EXPECT_EQ(accumulated.output_tokens, 3); // Earlier value survives...
  EXPECT_TRUE(degraded);                   // ...but the stream is flagged.
}

TEST(TokenUsageTest, CanonicalizationOverflowIsSurfaced) {
  // Individually valid fields summing above 2^53-1: the component is dropped
  // rather than published imprecisely, and the record is flagged so the
  // caller publishes partial instead of a silently non-canonical complete.
  auto usage = extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"usage":{"input_tokens":9007199254740991,"cache_read_input_tokens":1,
                "output_tokens":0}})"));
  finalizeUsage(usage);
  EXPECT_FALSE(usage.input_tokens.has_value());
  EXPECT_TRUE(usage.canonicalizationOverflow());

  auto fine = extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"usage":{"input_tokens":100,"cache_read_input_tokens":1,"output_tokens":0}})"));
  finalizeUsage(fine);
  EXPECT_FALSE(fine.canonicalizationOverflow());
}

TEST(TokenUsageTest, MergeAfterFinalizeIsRejected) {
  TokenUsage usage;
  usage.api_protocol = ApiProtocol::AnthropicMessages;
  usage.input_tokens = 1;
  finalizeUsage(usage);
  TokenUsage update;
  update.output_tokens = 2;
  EXPECT_DEBUG_DEATH(usage.merge(update), "");
}

TEST(TokenUsageTest, FinalizeIsSingleUse) {
  TokenUsage usage;
  usage.api_protocol = ApiProtocol::AnthropicMessages;
  usage.input_tokens = 100;
  usage.cached_input_tokens = 30;
  usage.cache_creation_input_tokens = 20;
  usage.output_tokens = 10;
  finalizeUsage(usage);
  EXPECT_EQ(usage.input_tokens, 150);
  EXPECT_EQ(usage.total_tokens, 160);
  // A second call must not re-add the cache buckets: it asserts in debug
  // builds and is a no-op in release builds.
  EXPECT_DEBUG_DEATH(finalizeUsage(usage), "");
  EXPECT_EQ(usage.input_tokens, 150);
  EXPECT_EQ(usage.total_tokens, 160);
}

TEST(TokenUsageTest, MergeIncludesToolUseInputTokens) {
  // Every field the extractors populate must survive merge(): the Gemini
  // extractor reports tool_use_input_tokens, and all documents -- including a
  // single non-streaming JSON response -- pass through merge() before
  // publication.
  TokenUsage base;
  TokenUsage update;
  update.tool_use_input_tokens = 5;
  base.merge(update);
  EXPECT_EQ(base.tool_use_input_tokens, 5);
}

TEST(TokenUsageTest, MergeLaterNonNullWins) {
  TokenUsage base;
  base.input_tokens = 10;
  base.model = "a";

  TokenUsage update;
  update.output_tokens = 5;
  TokenUsage empty_update;

  base.merge(update);
  base.merge(empty_update); // An empty update must not clear anything.
  EXPECT_EQ(base.input_tokens, 10);
  EXPECT_EQ(base.output_tokens, 5);
  EXPECT_EQ(base.model, "a");
}

TEST(TokenUsageTest, FinalizeComputesCanonicalTotal) {
  TokenUsage usage;
  usage.input_tokens = 3;
  usage.output_tokens = 4;
  finalizeUsage(usage);
  EXPECT_EQ(usage.total_tokens, 7);
  EXPECT_FALSE(usage.provider_total_tokens.has_value());

  TokenUsage partial;
  partial.output_tokens = 4; // No input: the total cannot be computed.
  finalizeUsage(partial);
  EXPECT_FALSE(partial.total_tokens.has_value());

  TokenUsage partial_with_reported;
  partial_with_reported.output_tokens = 4;
  partial_with_reported.total_tokens = 9; // Native total; components incomplete.
  finalizeUsage(partial_with_reported);
  // The provider total never substitutes for the canonical sum; it is
  // preserved in its own field.
  EXPECT_FALSE(partial_with_reported.total_tokens.has_value());
  EXPECT_EQ(partial_with_reported.provider_total_tokens, 9);
}

TEST(TokenUsageTest, ProviderTotalPreservedSeparately) {
  // The canonical contract guarantees total == input + output. The provider's
  // own total is always preserved alongside, so a disagreeing one
  // (inconsistent response, or a bucket unknown to the extractor) never
  // breaks that invariant and stays observable.
  TokenUsage usage;
  usage.input_tokens = 3;
  usage.output_tokens = 4;
  usage.total_tokens = 100;
  finalizeUsage(usage);
  EXPECT_EQ(usage.total_tokens, 7);
  EXPECT_EQ(usage.provider_total_tokens, 100);

  // An agreeing provider total is preserved just the same.
  TokenUsage agreeing;
  agreeing.input_tokens = 3;
  agreeing.output_tokens = 4;
  agreeing.total_tokens = 7;
  finalizeUsage(agreeing);
  EXPECT_EQ(agreeing.total_tokens, 7);
  EXPECT_EQ(agreeing.provider_total_tokens, 7);
}

TEST(TokenUsageTest, NumericEdgeCases) {
  // Counts serialized as JSON doubles are accepted; negatives are ignored.
  const auto usage = extractUsage(ApiProtocol::AnthropicMessages,
                                  parse(R"({"usage":{"input_tokens":12.0,"output_tokens":-5}})"));
  EXPECT_EQ(usage.input_tokens, 12);
  EXPECT_FALSE(usage.output_tokens.has_value());
}

TEST(TokenUsageTest, UntrustedNumericValuesRejected) {
  // Fractional, astronomically large, out-of-double-precision, and wrong-typed
  // values are rejected rather than coerced: these feed billing/accounting
  // metadata, and casting e.g. 1e300 to an integer is undefined behavior.
  const auto usage = extractUsage(ApiProtocol::AnthropicMessages, parse(R"(
      {"usage":{"input_tokens":12.5,
                "output_tokens":1e300,
                "cache_read_input_tokens":9007199254740992,
                "cache_creation_input_tokens":9007199254740991,
                "output_tokens_details":{"thinking_tokens":"7"}}})"));
  EXPECT_FALSE(usage.input_tokens.has_value());  // fractional
  EXPECT_FALSE(usage.output_tokens.has_value()); // not representable
  // 2^53 is beyond the exactly-representable bound; 2^53-1 is the maximum.
  EXPECT_FALSE(usage.cached_input_tokens.has_value());
  EXPECT_EQ(usage.cache_creation_input_tokens, uint64_t(9007199254740991));
  EXPECT_FALSE(usage.reasoning_tokens.has_value()); // string, not a number
}

TEST(TokenUsageTest, ComputedTotalPublishedOnlyWhenDoubleExact) {
  // readCount caps each addend at 2^53-1, so the sum cannot overflow uint64_t;
  // but a sum above 2^53-1 may not be exactly representable by the
  // double-backed metadata field (e.g. an odd sum above 2^53 rounds), so the
  // computed total is published only within the same metadata-safe bound as
  // every other field.
  TokenUsage in_range;
  in_range.input_tokens = uint64_t(9007199254740000);
  in_range.output_tokens = uint64_t(991);
  finalizeUsage(in_range);
  EXPECT_EQ(in_range.total_tokens, uint64_t(9007199254740991)); // == 2^53-1, exact.

  TokenUsage out_of_range;
  out_of_range.input_tokens = uint64_t(9007199254740991);  // 2^53-1
  out_of_range.output_tokens = uint64_t(9007199254740990); // sum = 2^54-3, odd, inexact
  finalizeUsage(out_of_range);
  EXPECT_FALSE(out_of_range.total_tokens.has_value());

  // With both components present but the sum unpublishable, a provider total
  // must not slip in as total_tokens (it would necessarily violate
  // total == input + output); it stays in provider_total_tokens.
  TokenUsage out_of_range_reported;
  out_of_range_reported.input_tokens = uint64_t(9007199254740991);
  out_of_range_reported.output_tokens = uint64_t(9007199254740991);
  out_of_range_reported.total_tokens = 5;
  finalizeUsage(out_of_range_reported);
  EXPECT_FALSE(out_of_range_reported.total_tokens.has_value());
  EXPECT_EQ(out_of_range_reported.provider_total_tokens, 5);
}

TEST(TokenUsageTest, OversizedModelNameOmitted) {
  // The response-reported model is upstream-controlled: values beyond a small
  // bound are dropped so metadata and access-log entries stay small.
  const auto usage =
      extractUsage(ApiProtocol::AnthropicMessages,
                   parse("{\"type\":\"message\",\"model\":\"" + std::string(5000, 'm') +
                         "\",\"usage\":{\"input_tokens\":5,\"output_tokens\":7}}"));
  EXPECT_TRUE(usage.model.empty());
  EXPECT_EQ(usage.input_tokens, 5); // Counts are unaffected.
}

TEST(TokenUsageTest, SecondaryOnlyCountsStillPublish) {
  // A usage object carrying only cache/reasoning counts is still a result.
  const auto usage = extractUsage(ApiProtocol::AnthropicMessages,
                                  parse(R"({"usage":{"cache_read_input_tokens":64}})"));
  EXPECT_TRUE(usage.hasAny());
  EXPECT_EQ(usage.cached_input_tokens, 64);
}

// ---------------------------------------------------------------------------
// Adapter registry.

TEST(AdapterRegistryTest, SchemaLookup) {
  // Chat Completions carries the one defined payload schema; APIs without a
  // schema are not validated.
  EXPECT_NE(AdapterRegistry::get(ApiProtocol::OpenAiChatCompletions).schema(), nullptr);
  EXPECT_EQ(AdapterRegistry::get(ApiProtocol::Unspecified).schema(), nullptr);
  EXPECT_EQ(AdapterRegistry::get(ApiProtocol::OpenAiResponses).schema(), nullptr);
  EXPECT_EQ(AdapterRegistry::get(ApiProtocol::AnthropicMessages).schema(), nullptr);
  EXPECT_EQ(AdapterRegistry::get(ApiProtocol::GeminiGenerateContent).schema(), nullptr);
}

TEST(AdapterRegistryTest, AdaptersReportTheirProtocol) {
  for (const ApiProtocol protocol :
       {ApiProtocol::Unspecified, ApiProtocol::OpenAiChatCompletions, ApiProtocol::OpenAiResponses,
        ApiProtocol::AnthropicMessages, ApiProtocol::GeminiGenerateContent}) {
    EXPECT_EQ(AdapterRegistry::get(protocol).protocol(), protocol);
  }
}

TEST(AdapterRegistryTest, AllDeclaredOffloadableFieldsInStreamOrder) {
  // Every defined schema must list each of its offloadable field paths in its
  // streamable field order.
  for (const ApiProtocol protocol :
       {ApiProtocol::OpenAiChatCompletions, ApiProtocol::OpenAiResponses,
        ApiProtocol::AnthropicMessages, ApiProtocol::GeminiGenerateContent}) {
    const PayloadSchema* schema = AdapterRegistry::get(protocol).schema();
    if (schema == nullptr) {
      continue;
    }

    const std::vector<std::string> offloadable_paths = schema->requestOffloadableFieldPaths();
    const std::vector<std::string>& stream_order = schema->requestStreamableFieldOrder();

    EXPECT_FALSE(offloadable_paths.empty());
    for (const std::string& offloadable_path : offloadable_paths) {
      EXPECT_NE(std::find(stream_order.begin(), stream_order.end(), offloadable_path),
                stream_order.end())
          << "Declared offloadable field path '" << offloadable_path
          << "' is missing from the streamable field order list for protocol "
          << apiProtocolName(protocol);
    }
  }
}

// ---------------------------------------------------------------------------
// Request-side extraction.

RequestInfo extractRequest(ApiProtocol format, const std::string& json,
                           absl::string_view path = "") {
  return AdapterRegistry::get(format).extractRequestInfo(parse(json), path);
}

TEST(RequestInfoTest, OpenAiChatCompletions) {
  const RequestInfo info = extractRequest(ApiProtocol::OpenAiChatCompletions, R"({
    "model": "gpt-4o-mini",
    "stream": true,
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "hello there"}]
  })");
  EXPECT_EQ(info.api_protocol, ApiProtocol::OpenAiChatCompletions);
  EXPECT_EQ(info.model, "gpt-4o-mini");
  EXPECT_TRUE(info.streaming);
  EXPECT_EQ(info.requested_max_output_tokens, 256);
  EXPECT_EQ(info.message_count, 1);
  EXPECT_FALSE(info.tool_count.has_value());
  EXPECT_TRUE(info.estimated_input_tokens.has_value());
  EXPECT_TRUE(info.hasAny());
}

TEST(RequestInfoTest, OpenAiChatCompletionsPrefersMaxCompletionTokens) {
  // The current spelling wins when a client sends both.
  EXPECT_EQ(extractRequest(ApiProtocol::OpenAiChatCompletions,
                           R"({"max_tokens": 10, "max_completion_tokens": 20})")
                .requested_max_output_tokens,
            20);
  // The deprecated spelling is still what most clients send.
  EXPECT_EQ(extractRequest(ApiProtocol::OpenAiChatCompletions, R"({"max_tokens": 10})")
                .requested_max_output_tokens,
            10);
}

TEST(RequestInfoTest, OpenAiChatCompletionsCountsTools) {
  const RequestInfo info = extractRequest(ApiProtocol::OpenAiChatCompletions, R"({
    "messages": [{"role": "user", "content": "hi"}],
    "tools": [{"type": "function", "function": {"name": "a"}},
              {"type": "function", "function": {"name": "b"}}]
  })");
  EXPECT_EQ(info.tool_count, 2);
  // An empty tools list is a declaration, not an absence.
  EXPECT_EQ(extractRequest(ApiProtocol::OpenAiChatCompletions, R"({"tools": []})").tool_count, 0);
}

TEST(RequestInfoTest, OpenAiChatCompletionsAbsenceIsPreserved) {
  const RequestInfo info =
      extractRequest(ApiProtocol::OpenAiChatCompletions, R"({"model": "gpt-4o-mini"})");
  EXPECT_FALSE(info.streaming);
  EXPECT_FALSE(info.requested_max_output_tokens.has_value());
  EXPECT_FALSE(info.message_count.has_value());
  EXPECT_FALSE(info.tool_count.has_value());
}

TEST(RequestInfoTest, OpenAiChatCompletionsUnusableFieldsReadAsAbsent) {
  // A malformed request field costs that field only; nothing else degrades.
  const RequestInfo info = extractRequest(ApiProtocol::OpenAiChatCompletions, R"({
    "model": "gpt-4o-mini", "max_tokens": "lots", "stream": "yes", "messages": {}
  })");
  EXPECT_EQ(info.model, "gpt-4o-mini");
  EXPECT_FALSE(info.requested_max_output_tokens.has_value());
  EXPECT_FALSE(info.streaming);
  EXPECT_FALSE(info.message_count.has_value());
}

TEST(RequestInfoTest, OpenAiResponses) {
  const RequestInfo info = extractRequest(ApiProtocol::OpenAiResponses, R"({
    "model": "gpt-4o-mini",
    "max_output_tokens": 512,
    "instructions": "be terse",
    "input": "what is 2+2"
  })");
  EXPECT_EQ(info.model, "gpt-4o-mini");
  EXPECT_EQ(info.requested_max_output_tokens, 512);
  // A bare-string `input` has no turn structure to count.
  EXPECT_FALSE(info.message_count.has_value());
  EXPECT_TRUE(info.estimated_input_tokens.has_value());

  const RequestInfo list_input = extractRequest(ApiProtocol::OpenAiResponses, R"({
    "input": [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]
  })");
  EXPECT_EQ(list_input.message_count, 2);
}

TEST(RequestInfoTest, AnthropicMessages) {
  const RequestInfo info = extractRequest(ApiProtocol::AnthropicMessages, R"({
    "model": "claude-haiku-4-5",
    "max_tokens": 1024,
    "system": "you are terse",
    "messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]
  })");
  EXPECT_EQ(info.api_protocol, ApiProtocol::AnthropicMessages);
  EXPECT_EQ(info.model, "claude-haiku-4-5");
  EXPECT_EQ(info.requested_max_output_tokens, 1024);
  EXPECT_EQ(info.message_count, 2);
  EXPECT_FALSE(info.streaming);
}

TEST(RequestInfoTest, AnthropicSystemBlocksCountTowardEstimate) {
  // The system prompt is a top-level member, and a long one must move the
  // estimate even though it is not a turn.
  const RequestInfo without =
      extractRequest(ApiProtocol::AnthropicMessages, R"({"messages": [{"content": "hi"}]})");
  const RequestInfo with = extractRequest(ApiProtocol::AnthropicMessages, R"({
    "messages": [{"content": "hi"}],
    "system": [{"type": "text", "text": "0123456789012345678901234567890123456789"}]
  })");
  ASSERT_TRUE(without.estimated_input_tokens.has_value());
  ASSERT_TRUE(with.estimated_input_tokens.has_value());
  EXPECT_GT(with.estimated_input_tokens.value(), without.estimated_input_tokens.value());
}

TEST(RequestInfoTest, GeminiReadsModelAndStreamingFromPath) {
  const RequestInfo json_call = extractRequest(ApiProtocol::GeminiGenerateContent, R"({})",
                                               "/v1beta/models/gemini-2.5-flash:generateContent");
  EXPECT_EQ(json_call.model, "gemini-2.5-flash");
  EXPECT_FALSE(json_call.streaming);

  const RequestInfo stream_call =
      extractRequest(ApiProtocol::GeminiGenerateContent, R"({})",
                     "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse");
  EXPECT_EQ(stream_call.model, "gemini-2.5-flash");
  EXPECT_TRUE(stream_call.streaming);

  // A gateway prefix ahead of the API path must not confuse the scan, and a
  // prefix containing the word "models" must not win over the real segment.
  EXPECT_EQ(extractRequest(ApiProtocol::GeminiGenerateContent, R"({})",
                           "/models/proxy/v1beta/models/gemini-3-pro:generateContent")
                .model,
            "gemini-3-pro");
}

TEST(RequestInfoTest, GeminiUnrecognizedPathYieldsNoModel) {
  EXPECT_TRUE(extractRequest(ApiProtocol::GeminiGenerateContent, R"({})", "/v1beta/generate")
                  .model.empty());
  EXPECT_TRUE(extractRequest(ApiProtocol::GeminiGenerateContent, R"({})", "").model.empty());
  // Empty model segment.
  EXPECT_TRUE(
      extractRequest(ApiProtocol::GeminiGenerateContent, R"({})", "/v1beta/models/:generateContent")
          .model.empty());
  // A path segment is upstream-influenced; an oversized one is not published.
  const std::string long_model(MaxStringValueSize + 1, 'm');
  EXPECT_TRUE(extractRequest(ApiProtocol::GeminiGenerateContent, R"({})",
                             "/v1beta/models/" + long_model + ":generateContent")
                  .model.empty());
}

TEST(RequestInfoTest, GeminiGenerationConfigBothSpellings) {
  EXPECT_EQ(extractRequest(ApiProtocol::GeminiGenerateContent,
                           R"({"generationConfig": {"maxOutputTokens": 300}})")
                .requested_max_output_tokens,
            300);
  EXPECT_EQ(extractRequest(ApiProtocol::GeminiGenerateContent,
                           R"({"generation_config": {"max_output_tokens": 400}})")
                .requested_max_output_tokens,
            400);
}

TEST(RequestInfoTest, GeminiCountsContents) {
  const RequestInfo info = extractRequest(ApiProtocol::GeminiGenerateContent, R"({
    "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
    "systemInstruction": {"parts": [{"text": "be terse"}]}
  })",
                                          "/v1beta/models/gemini-2.5-flash:generateContent");
  EXPECT_EQ(info.message_count, 1);
  EXPECT_TRUE(info.estimated_input_tokens.has_value());
}

TEST(RequestInfoTest, UnspecifiedProtocolExtractsNothing) {
  const RequestInfo info =
      extractRequest(ApiProtocol::Unspecified, R"({"model": "gpt-4o-mini", "max_tokens": 10})");
  EXPECT_FALSE(info.hasAny());
  EXPECT_TRUE(info.model.empty());
}

// ---------------------------------------------------------------------------
// The estimator itself.

TEST(EstimateInputTokensTest, RoundsUpAndAddsFraming) {
  EXPECT_EQ(estimateInputTokens(0, 0), 0);
  // Any text at all costs at least one token.
  EXPECT_EQ(estimateInputTokens(1, 0), 1);
  EXPECT_EQ(estimateInputTokens(BytesPerTokenEstimate, 0), 1);
  EXPECT_EQ(estimateInputTokens(BytesPerTokenEstimate + 1, 0), 2);
  EXPECT_EQ(estimateInputTokens(0, 3), 3 * MessageFramingTokens);
}

TEST(EstimateInputTokensTest, StaysWithinTheMetadataSafeBound) {
  // The estimate is published in the same uint64 record as the real counts, so
  // it must respect the same bound no matter what the payload declared. The
  // divide by BytesPerTokenEstimate means the largest measurable payload is
  // already well inside it; the guard is what keeps that true if either
  // constant changes.
  EXPECT_LE(estimateInputTokens(MaxSafeCount, 0xffffffff), MaxSafeCount);
  EXPECT_GT(estimateInputTokens(MaxSafeCount, 0xffffffff), 0);
  // Monotonic in payload size -- the one property the heuristic guarantees.
  EXPECT_GT(estimateInputTokens(1000, 0), estimateInputTokens(100, 0));
}

TEST(MeasureTextBytesTest, SumsStringValuesOnly) {
  // Keys are not counted, values are; nested containers are descended.
  EXPECT_EQ(measureTextBytes(parse(R"({"role": "user"})")), 4);
  EXPECT_EQ(measureTextBytes(parse(R"([{"text": "ab"}, {"text": "cde"}])")), 5);
  // Numbers, booleans and nulls contribute nothing.
  EXPECT_EQ(measureTextBytes(parse(R"({"n": 12345, "b": true, "z": null})")), 0);
}

TEST(MeasureTextBytesTest, CountsOffloadedStringsByRecordedLength) {
  // The whole point: a prompt too large to sit in the DOM still contributes
  // its length, without its bytes ever being read here.
  nlohmann::json doc = nlohmann::json::object();
  doc["content"] = JsonWithExtBuf::makeExternalRef({/*offset=*/64, /*length=*/4096});
  EXPECT_EQ(measureTextBytes(doc), 4096);
  ASSERT_TRUE(estimateInputTokens(measureTextBytes(doc), 1) > 1000);
}

TEST(MeasureTextBytesTest, StopsAtDepthCap) {
  // Build a chain deeper than the cap and check the walk terminates without
  // counting past it.
  nlohmann::json deep = "leaf";
  for (int i = 0; i < MaxTextWalkDepth + 5; ++i) {
    nlohmann::json wrapper = nlohmann::json::array();
    wrapper.push_back(std::move(deep));
    deep = std::move(wrapper);
  }
  EXPECT_EQ(measureTextBytes(deep), 0);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
