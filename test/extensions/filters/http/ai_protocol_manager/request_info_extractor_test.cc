#include <string>
#include <utility>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/request_info_extractor.h"

#include "test/test_common/status_utility.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

TEST(RequestInfoExtractorTest, CapturesTopLevelFieldsAndPreservesPresence) {
  RequestInfoExtractor extractor;
  ASSERT_OK(extractor.feed(
      R"({"model":"claude-4","stream":false,"max_tokens":0,"messages":[{},{}],"tools":[]})",
      /*closed=*/true));

  const RequestInfo info = extractor.finalizeForProtocol(ApiProtocol::AnthropicMessages);
  ASSERT_TRUE(info.model.has_value());
  EXPECT_EQ(info.model.value(), "claude-4");
  ASSERT_TRUE(info.streaming.has_value());
  EXPECT_FALSE(info.streaming.value());
  ASSERT_TRUE(info.max_output_tokens.has_value());
  EXPECT_EQ(info.max_output_tokens.value(), 0);
  ASSERT_TRUE(info.message_count.has_value());
  EXPECT_EQ(info.message_count.value(), 2);
  ASSERT_TRUE(info.tool_count.has_value());
  EXPECT_EQ(info.tool_count.value(), 0);
  EXPECT_TRUE(extractor.rootClosed());
}

TEST(RequestInfoExtractorTest, LeavesAbsentFieldsUnset) {
  RequestInfoExtractor extractor;
  ASSERT_OK(extractor.feed("{}", /*closed=*/true));

  const RequestInfo info = extractor.finalizeForProtocol(ApiProtocol::Unspecified);
  EXPECT_FALSE(info.model.has_value());
  EXPECT_FALSE(info.streaming.has_value());
  EXPECT_FALSE(info.max_output_tokens.has_value());
  EXPECT_FALSE(info.message_count.has_value());
  EXPECT_FALSE(info.tool_count.has_value());
}

TEST(RequestInfoExtractorTest, EmptyModelPreservesPresence) {
  RequestInfoExtractor extractor;
  ASSERT_OK(extractor.feed(R"({"model":""})", /*closed=*/true));

  const RequestInfo info = extractor.finalizeForProtocol(ApiProtocol::OpenAiChatCompletions);
  ASSERT_TRUE(info.model.has_value());
  EXPECT_TRUE(info.model->empty());
}

TEST(RequestInfoExtractorTest, StreamsAcrossArbitraryChunkBoundaries) {
  RequestInfoExtractor extractor;
  ASSERT_OK(extractor.feed(R"({"model":"gem)", /*closed=*/false));
  ASSERT_OK(extractor.feed(R"(ini","stream":t)", /*closed=*/false));
  ASSERT_OK(extractor.feed(R"(rue,"max_output_tokens":17})", /*closed=*/true));

  const RequestInfo info = extractor.finalizeForProtocol(ApiProtocol::OpenAiResponses);
  EXPECT_EQ(info.model, std::optional<std::string>("gemini"));
  EXPECT_EQ(info.streaming, std::optional<bool>(true));
  EXPECT_EQ(info.max_output_tokens, std::optional<uint64_t>(17));
}

TEST(RequestInfoExtractorTest, RootCloseDoesNotWaitForHttpEndStream) {
  RequestInfoExtractor extractor;
  ASSERT_OK(extractor.feed(R"({"model":"gpt-4o"})", /*closed=*/false));

  EXPECT_TRUE(extractor.rootClosed());
  EXPECT_EQ(extractor.finalizeForProtocol(ApiProtocol::OpenAiChatCompletions).model,
            std::optional<std::string>("gpt-4o"));
}

TEST(RequestInfoExtractorTest, ScalarRootsCompleteWithAndWithoutHttpEndStream) {
  for (const absl::string_view scalar : {R"("text")", "42", "true", "null"}) {
    RequestInfoExtractor terminal;
    ASSERT_OK(terminal.feed(scalar, /*closed=*/true)) << scalar;
    EXPECT_TRUE(terminal.rootClosed()) << scalar;
  }

  RequestInfoExtractor nonterminal;
  ASSERT_OK(nonterminal.feed(R"("text")", /*closed=*/false));
  EXPECT_TRUE(nonterminal.rootClosed());
}

TEST(RequestInfoExtractorTest, ModelCaptureIsBounded) {
  const std::string at_limit(RequestInfoExtractor::MaxModelBytes, 'm');
  RequestInfoExtractor accepted;
  ASSERT_OK(accepted.feed("{\"model\":\"" + at_limit + "\"}", /*closed=*/true));
  EXPECT_EQ(accepted.finalizeForProtocol(ApiProtocol::Unspecified).model,
            std::optional<std::string>(at_limit));

  RequestInfoExtractor dropped;
  ASSERT_OK(dropped.feed("{\"model\":\"" + at_limit + "x\"}", /*closed=*/true));
  EXPECT_FALSE(dropped.finalizeForProtocol(ApiProtocol::Unspecified).model.has_value());
}

TEST(RequestInfoExtractorTest, PromptStringsAreNotCaptured) {
  const std::string prompt(64 * 1024, 'p');
  RequestInfoExtractor extractor;
  ASSERT_OK(extractor.feed("{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"" +
                               prompt + "\"}]}",
                           /*closed=*/true));

  const RequestInfo info = extractor.finalizeForProtocol(ApiProtocol::OpenAiChatCompletions);
  EXPECT_EQ(info.model, std::optional<std::string>("gpt-4o"));
  EXPECT_EQ(info.message_count, std::optional<uint32_t>(1));
}

TEST(RequestInfoExtractorTest, CountsEveryDirectArrayElementWithoutRetainingIt) {
  struct Case {
    absl::string_view key;
    ApiProtocol protocol;
  };
  const std::vector<Case> cases = {{"messages", ApiProtocol::OpenAiChatCompletions},
                                   {"input", ApiProtocol::OpenAiResponses},
                                   {"contents", ApiProtocol::GeminiGenerateContent}};
  for (const auto& test_case : cases) {
    RequestInfoExtractor extractor;
    ASSERT_OK(extractor.feed(absl::StrCat("{\"", test_case.key, "\":[{},[],\"x\",1,true,null]}"),
                             /*closed=*/true));
    EXPECT_EQ(extractor.finalizeForProtocol(test_case.protocol).message_count,
              std::optional<uint32_t>(6))
        << test_case.key;
  }

  RequestInfoExtractor tools;
  ASSERT_OK(tools.feed(R"({"tools":[{},[],"x",1,true,null]})", /*closed=*/true));
  EXPECT_EQ(tools.finalizeForProtocol(ApiProtocol::Unspecified).tool_count,
            std::optional<uint32_t>(6));
}

TEST(RequestInfoExtractorTest, ArrayCountIsCommittedOnlyAtArrayClose) {
  RequestInfoExtractor extractor;
  ASSERT_OK(extractor.feed(R"({"messages":[{},)", /*closed=*/false));
  EXPECT_FALSE(
      extractor.finalizeForProtocol(ApiProtocol::OpenAiChatCompletions).message_count.has_value());

  ASSERT_OK(extractor.feed(R"({}]})", /*closed=*/true));
  EXPECT_EQ(extractor.finalizeForProtocol(ApiProtocol::OpenAiChatCompletions).message_count,
            std::optional<uint32_t>(2));

  RequestInfoExtractor malformed;
  ASSERT_FALSE(malformed.feed(R"({"tools":[{},bad)", /*closed=*/true).ok());
  EXPECT_FALSE(
      malformed.finalizeForProtocol(ApiProtocol::AnthropicMessages).tool_count.has_value());
}

TEST(RequestInfoExtractorTest, CurrentTopLevelLimitAliasesBeatLegacyAlias) {
  RequestInfoExtractor extractor;
  ASSERT_OK(extractor.feed(R"({"max_tokens":1,"max_output_tokens":2,"max_completion_tokens":3})",
                           /*closed=*/true));
  EXPECT_EQ(extractor.finalizeForProtocol(ApiProtocol::OpenAiChatCompletions).max_output_tokens,
            std::optional<uint64_t>(3));
  EXPECT_EQ(extractor.finalizeForProtocol(ApiProtocol::OpenAiResponses).max_output_tokens,
            std::optional<uint64_t>(2));
  EXPECT_EQ(extractor.finalizeForProtocol(ApiProtocol::AnthropicMessages).max_output_tokens,
            std::optional<uint64_t>(1));

  RequestInfoExtractor reverse_order;
  ASSERT_OK(
      reverse_order.feed(R"({"max_completion_tokens":3,"max_output_tokens":2,"max_tokens":1})",
                         /*closed=*/true));
  EXPECT_EQ(reverse_order.finalizeForProtocol(ApiProtocol::OpenAiChatCompletions).max_output_tokens,
            std::optional<uint64_t>(3));
}

TEST(RequestInfoExtractorTest, ReadsGeminiLimitSpellings) {
  RequestInfoExtractor camel;
  ASSERT_OK(camel.feed(R"({"generationConfig":{"maxOutputTokens":41}})", /*closed=*/true));
  EXPECT_EQ(camel.finalizeForProtocol(ApiProtocol::GeminiGenerateContent).max_output_tokens,
            std::optional<uint64_t>(41));
  EXPECT_EQ(camel.bodyDetectedProtocol(), ApiProtocol::GeminiGenerateContent);

  RequestInfoExtractor snake;
  ASSERT_OK(snake.feed(R"({"generation_config":{"max_output_tokens":42}})", /*closed=*/true));
  EXPECT_EQ(snake.finalizeForProtocol(ApiProtocol::GeminiGenerateContent).max_output_tokens,
            std::optional<uint64_t>(42));
  EXPECT_EQ(snake.bodyDetectedProtocol(), ApiProtocol::GeminiGenerateContent);

  RequestInfoExtractor both;
  ASSERT_OK(both.feed(R"({"generationConfig":{"max_output_tokens":42,"maxOutputTokens":41}})",
                      /*closed=*/true));
  EXPECT_EQ(both.finalizeForProtocol(ApiProtocol::GeminiGenerateContent).max_output_tokens,
            std::optional<uint64_t>(41));
}

TEST(RequestInfoExtractorTest, IgnoresNonIntegerTokenLimits) {
  RequestInfoExtractor extractor;
  ASSERT_OK(
      extractor.feed(R"({"max_completion_tokens":1.5,"max_output_tokens":-1,"max_tokens":"12"})",
                     /*closed=*/true));
  EXPECT_FALSE(extractor.finalizeForProtocol(ApiProtocol::OpenAiChatCompletions)
                   .max_output_tokens.has_value());
}

TEST(RequestInfoExtractorTest, DetectsOnlyStrongBodyProtocolMarkers) {
  RequestInfoExtractor anthropic;
  ASSERT_OK(anthropic.feed(R"({"anthropic_version":"2023-06-01","messages":[]})",
                           /*closed=*/true));
  EXPECT_EQ(anthropic.bodyDetectedProtocol(), ApiProtocol::AnthropicMessages);

  RequestInfoExtractor weak_contents;
  ASSERT_OK(weak_contents.feed(R"({"contents":[]})", /*closed=*/true));
  EXPECT_EQ(weak_contents.bodyDetectedProtocol(), ApiProtocol::Unspecified);

  RequestInfoExtractor gemini_config;
  ASSERT_OK(gemini_config.feed(R"({"generationConfig":{}})", /*closed=*/true));
  EXPECT_EQ(gemini_config.bodyDetectedProtocol(), ApiProtocol::GeminiGenerateContent);

  RequestInfoExtractor generic;
  ASSERT_OK(generic.feed(R"({"model":"claude-4","messages":[],"tools":[],"stream":true})",
                         /*closed=*/true));
  EXPECT_EQ(generic.bodyDetectedProtocol(), ApiProtocol::Unspecified);
}

TEST(RequestInfoExtractorTest, MarkerTypesAndConflictsRemainUnspecified) {
  RequestInfoExtractor wrong_types;
  ASSERT_OK(wrong_types.feed(R"({"anthropic_version":1,"generationConfig":[],"contents":{}})",
                             /*closed=*/true));
  EXPECT_EQ(wrong_types.bodyDetectedProtocol(), ApiProtocol::Unspecified);

  RequestInfoExtractor conflict;
  ASSERT_OK(conflict.feed(R"({"anthropic_version":"2023-06-01","generationConfig":{}})",
                          /*closed=*/true));
  EXPECT_EQ(conflict.bodyDetectedProtocol(), ApiProtocol::Unspecified);

  RequestInfoExtractor incomplete_marker;
  ASSERT_OK(incomplete_marker.feed(R"({"anthropic_version":"2023-)", /*closed=*/false));
  EXPECT_EQ(incomplete_marker.bodyDetectedProtocol(), ApiProtocol::Unspecified);
}

TEST(RequestInfoExtractorTest, ReportsMalformedAndIncompleteJson) {
  RequestInfoExtractor malformed;
  const absl::Status malformed_status = malformed.feed(R"({"model" "gpt-4o"})", /*closed=*/true);
  EXPECT_EQ(malformed_status.code(), absl::StatusCode::kInvalidArgument);

  RequestInfoExtractor incomplete;
  const absl::Status incomplete_status = incomplete.feed(R"({"model":"gpt-4o")", /*closed=*/true);
  EXPECT_EQ(incomplete_status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_FALSE(incomplete.rootClosed());
}

TEST(RequestInfoExtractorTest, ParseErrorsAreSticky) {
  RequestInfoExtractor extractor;
  const absl::Status first = extractor.feed(R"({"model" 1})", /*closed=*/false);
  ASSERT_FALSE(first.ok());
  const absl::Status second = extractor.feed("{}", /*closed=*/true);
  EXPECT_EQ(second.code(), first.code());
  EXPECT_EQ(second.message(), first.message());
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
