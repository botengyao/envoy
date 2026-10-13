#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "envoy/data/ai/v3/token_usage.pb.h"
#include "envoy/extensions/http/ai_filters/transcoder/v3/transcoder.pb.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/stream_info/stream_info_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter.h"
#include "source/extensions/filters/http/ai_protocol_manager/buffer_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/filter_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/transcoding_engine.h"
#include "source/extensions/http/ai_filters/token_usage/filter.h"
#include "source/extensions/http/ai_filters/transcoder/filter.h"

#include "test/extensions/filters/http/ai_protocol_manager/fake_bridge.h"
#include "test/mocks/stats/mocks.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace TokenUsage {
namespace {

using HttpFilters::AiProtocolManager::AiFilter;
using HttpFilters::AiProtocolManager::AiFilterContext;
using HttpFilters::AiProtocolManager::AiFilterSharedPtr;
using HttpFilters::AiProtocolManager::AiRequestPropagator;
using HttpFilters::AiProtocolManager::AiRequestReceiver;
using HttpFilters::AiProtocolManager::BufferManager;
using HttpFilters::AiProtocolManager::FakeBridge;
using HttpFilters::AiProtocolManager::FilterManager;
using HttpFilters::AiProtocolManager::InMemoryExternalBufferFactory;
using HttpFilters::AiProtocolManager::JsonWithExtBuf;
using HttpFilters::AiProtocolManager::LLMProtocol;
using HttpFilters::AiProtocolManager::LocalReplier;
using HttpFilters::AiProtocolManager::SseEvent;
using HttpFilters::AiProtocolManager::SseStreamPropagator;
using HttpFilters::AiProtocolManager::SseStreamReceiver;
using HttpFilters::AiProtocolManager::TranscodingEngine;
using TranscoderProto = envoy::extensions::http::ai_filters::transcoder::v3::Transcoder;
using UsageRecord = envoy::data::ai::v3::TokenUsage;

constexpr absl::string_view MetadataNamespace = "envoy.ai.token_usage";

// Stands in for a transcoder leg: hands `record` down the chain, in an event of its own, ahead of
// the response.
class RecordCarryingFilter : public AiFilter {
public:
  explicit RecordCarryingFilter(nlohmann::json record) : record_(std::move(record)) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver, AiRequestPropagator,
                                       LocalReplier) override {
    co_return absl::OkStatus();
  }

  Coroutine::Task<absl::Status> encodeSSE(SseStreamReceiver receive,
                                          SseStreamPropagator propagate) override {
    auto carrier = std::make_unique<SseEvent>();
    JsonWithExtBuf payload;
    payload.setJson(nlohmann::json{{"_envoy", {{"token_usage", record_}}}});
    carrier->set_json(std::move(payload));
    CO_RETURN_IF_ERROR(co_await propagate(std::move(carrier)));
    while (true) {
      ASSIGN_OR_CO_RETURN(auto event, co_await receive());
      if (!event.has_value()) {
        co_return absl::OkStatus();
      }
      CO_RETURN_IF_ERROR(co_await propagate(std::move(*event)));
    }
  }

private:
  const nlohmann::json record_;
};

class TokenUsageFilterTest : public testing::Test {
public:
  TokenUsageFilterTest()
      : api_(Api::createApiForTest()), dispatcher_(api_->allocateDispatcher("test")),
        stream_info_(api_->timeSource(), nullptr, StreamInfo::FilterState::LifeSpan::FilterChain),
        config_(std::make_shared<const TokenUsageFilterConfig>(*stats_store_.rootScope())) {}

  AiFilterSharedPtr tokenUsage() {
    return std::make_shared<TokenUsageFilter>(config_, stream_info_);
  }

  // The transcoder leg next to `backend`, which converts the backend's response into the IR.
  AiFilterSharedPtr backendLeg(LLMProtocol backend) {
    TranscoderProto proto;
    proto.set_request_handling(TranscoderProto::FROM_IR);
    proto.set_response_handling(TranscoderProto::TO_IR);
    absl::StatusOr<TranscodingEngine> engine = TranscodingEngine::createDefault();
    EXPECT_TRUE(engine.ok()) << engine.status();
    auto config = std::make_shared<const Transcoder::TranscoderFilterConfig>(
        proto, std::move(*engine), *stats_store_.rootScope());
    return std::make_shared<Transcoder::TranscoderFilter>(
        config, AiFilterContext{.stream_info = stream_info_,
                                .request_headers = request_headers_,
                                .request_protocol = LLMProtocol::OpenAiChatCompletions,
                                .response_protocol = backend});
  }

  // Runs `body` through the response chain of `filters`, which runs them last to first, and
  // returns what reaches the client.
  std::string runResponse(std::vector<AiFilterSharedPtr> filters, const std::string& body,
                          bool sse) {
    FilterManager manager(std::move(filters));
    FakeBridge bridge(*dispatcher_);
    BufferManager out(BufferManager::Config{}, factory_, bridge);
    absl::Status status;
    bool done = false;
    const auto on_done = [&](absl::Status s) {
      status = std::move(s);
      done = true;
    };
    if (sse) {
      manager.startSseResponse(factory_, bridge, out, on_done);
    } else {
      manager.startUnaryResponse(factory_, bridge, out, on_done);
    }
    Buffer::OwnedImpl data(body);
    manager.onResponseData(data, /*end_stream=*/true);
    for (int i = 0; i < 20; ++i) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }
    EXPECT_TRUE(done);
    EXPECT_TRUE(status.ok()) << status;
    const std::string wire = bridge.injected_.toString();
    out.onDestroy();
    return wire;
  }

  std::optional<UsageRecord> published() {
    const auto& metadata = stream_info_.dynamicMetadata().typed_filter_metadata();
    const auto entry = metadata.find(std::string(MetadataNamespace));
    if (entry == metadata.end()) {
      return std::nullopt;
    }
    UsageRecord record;
    EXPECT_TRUE(entry->second.UnpackTo(&record));
    return record;
  }

  uint64_t counterValue(const std::string& name) {
    const auto counter =
        TestUtility::findCounter(stats_store_, "ai_protocol_manager.token_usage." + name);
    return counter != nullptr ? counter->value() : 0;
  }

  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;
  InMemoryExternalBufferFactory factory_;
  NiceMock<Stats::MockIsolatedStatsStore> stats_store_;
  StreamInfo::StreamInfoImpl stream_info_;
  Http::TestRequestHeaderMapImpl request_headers_{{":method", "POST"},
                                                  {":path", "/v1/chat/completions"}};
  TokenUsageFilterConfigSharedPtr config_;
};

// The chain re-serializes each event with its members sorted, so these are, and the stream that
// reaches the client is the one the backend sent.
TEST_F(TokenUsageFilterTest, PublishesTheUsageOfAnIrStream) {
  const std::string body =
      "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"index\":0}],\"model\":\"gpt-4o\","
      "\"object\":\"chat.completion.chunk\"}\n\n"
      "data: {\"choices\":[],\"model\":\"gpt-4o-2024-08-06\",\"object\":\"chat.completion.chunk\","
      "\"usage\":{\"completion_tokens\":10,\"prompt_tokens\":19,"
      "\"prompt_tokens_details\":{\"cached_tokens\":4},\"total_tokens\":29}}\n\n"
      "data: [DONE]\n\n";
  EXPECT_EQ(runResponse({tokenUsage()}, body, /*sse=*/true), body);

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->llm_protocol(), envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS);
  EXPECT_EQ(record->model(), "gpt-4o-2024-08-06");
  EXPECT_EQ(record->input_tokens().value(), 19);
  EXPECT_EQ(record->output_tokens().value(), 10);
  EXPECT_EQ(record->total_tokens().value(), 29);
  EXPECT_EQ(record->input_token_details().cached_tokens().value(), 4);
  EXPECT_EQ(record->provider_total_tokens().value(), 29);
  EXPECT_EQ(record->extraction_status(), UsageRecord::COMPLETE);
  EXPECT_EQ(counterValue("found"), 1);
  EXPECT_EQ(counterValue("partial"), 0);
}

TEST_F(TokenUsageFilterTest, PublishesTheUsageOfAnIrResponse) {
  const std::string body =
      R"({"choices":[{"finish_reason":"stop","index":0,"message":{"content":"Hi","role":"assistant"}}],)"
      R"("model":"gpt-4o","object":"chat.completion",)"
      R"("usage":{"completion_tokens":7,"prompt_tokens":5,"total_tokens":12}})";
  EXPECT_EQ(runResponse({tokenUsage()}, body, /*sse=*/false), body);

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->model(), "gpt-4o");
  EXPECT_EQ(record->input_tokens().value(), 5);
  EXPECT_EQ(record->output_tokens().value(), 7);
  EXPECT_EQ(record->total_tokens().value(), 12);
  EXPECT_EQ(record->extraction_status(), UsageRecord::COMPLETE);
  EXPECT_EQ(counterValue("found"), 1);
}

// An OpenAI stream reports its usage only when the request asked for it.
TEST_F(TokenUsageFilterTest, CountsAResponseWithoutUsageAsMissing) {
  runResponse({tokenUsage()},
              "data: {\"choices\":[],\"object\":\"chat.completion.chunk\"}\n\ndata: [DONE]\n\n",
              /*sse=*/true);
  EXPECT_FALSE(published().has_value());
  EXPECT_EQ(counterValue("missing"), 1);
  EXPECT_EQ(counterValue("found"), 0);
}

TEST_F(TokenUsageFilterTest, PublishesAMalformedCountAsPartial) {
  runResponse({tokenUsage()},
              R"({"object":"chat.completion","usage":{"completion_tokens":7,"prompt_tokens":"5"}})",
              /*sse=*/false);

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_FALSE(record->has_input_tokens());
  EXPECT_EQ(record->output_tokens().value(), 7);
  EXPECT_EQ(record->extraction_status(), UsageRecord::PARTIAL);
  EXPECT_EQ(counterValue("partial"), 1);
  EXPECT_EQ(counterValue("found"), 1);
}

TEST_F(TokenUsageFilterTest, CountsAProviderTotalThatDisagrees) {
  runResponse(
      {tokenUsage()},
      R"({"object":"chat.completion","usage":{"completion_tokens":7,"prompt_tokens":5,"total_tokens":13}})",
      /*sse=*/false);

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->total_tokens().value(), 12);
  EXPECT_EQ(record->provider_total_tokens().value(), 13);
  EXPECT_EQ(counterValue("total_mismatch"), 1);
}

// Read as the IR, Anthropic's `input_tokens` would leave out the 1000 cache reads; the filter
// reads no other API, and says so.
TEST_F(TokenUsageFilterTest, DoesNotReadAnotherApiAsTheIr) {
  runResponse(
      {tokenUsage()},
      R"({"content":[{"text":"Hi","type":"text"}],"model":"claude-sonnet-4-5","role":"assistant",)"
      R"("type":"message","usage":{"cache_read_input_tokens":1000,"input_tokens":10,"output_tokens":5}})",
      /*sse=*/false);

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_FALSE(record->has_input_tokens());
  EXPECT_EQ(record->extraction_status(), UsageRecord::FAILED);
  EXPECT_EQ(counterValue("api_mismatch"), 1);
  EXPECT_EQ(counterValue("failed"), 1);
  EXPECT_EQ(counterValue("found"), 0);
}

TEST_F(TokenUsageFilterTest, IgnoresDocumentsThatAreNotObjects) {
  runResponse({tokenUsage()}, "data: [1]\n\ndata: \"x\"\n\ndata: [DONE]\n\n", /*sse=*/true);
  runResponse({tokenUsage()}, R"("x")", /*sse=*/false);
  EXPECT_FALSE(published().has_value());
  EXPECT_EQ(counterValue("missing"), 2);
}

// The IR is never a JSON array, while Gemini's default stream is one.
TEST_F(TokenUsageFilterTest, DoesNotReadAnArrayBody) {
  runResponse({tokenUsage()}, R"([{"usageMetadata":{"promptTokenCount":3}}])", /*sse=*/false);

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->extraction_status(), UsageRecord::FAILED);
  EXPECT_EQ(counterValue("api_mismatch"), 1);
}

// The record is Envoy's to write: one in the upstream's response is gone before the filter reads.
TEST_F(TokenUsageFilterTest, AnUpstreamCannotSupplyTheRecord) {
  const std::string wire = runResponse(
      {tokenUsage()},
      R"({"_envoy":{"token_usage":{"extraction_status":"COMPLETE","input_tokens":1000000}},)"
      R"("object":"chat.completion","usage":{"completion_tokens":7,"prompt_tokens":5}})",
      /*sse=*/false);
  EXPECT_EQ(wire,
            R"({"object":"chat.completion","usage":{"completion_tokens":7,"prompt_tokens":5}})");

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->input_tokens().value(), 5);
}

TEST_F(TokenUsageFilterTest, LeavesAnEarlierRecordInPlace) {
  UsageRecord earlier;
  earlier.mutable_input_tokens()->set_value(1);
  earlier.set_extraction_status(UsageRecord::COMPLETE);
  Protobuf::Any any;
  MessageUtil::packFrom(any, earlier);
  stream_info_.setDynamicTypedMetadata(std::string(MetadataNamespace), any);

  runResponse({tokenUsage()},
              R"({"object":"chat.completion","usage":{"completion_tokens":7,"prompt_tokens":5}})",
              /*sse=*/false);

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->input_tokens().value(), 1);
  EXPECT_EQ(counterValue("duplicate"), 1);
  EXPECT_EQ(counterValue("found"), 0);
}

// The record speaks for the provider wherever in the stream it arrives.
TEST_F(TokenUsageFilterTest, PrefersTheCarriedRecord) {
  runResponse({tokenUsage(), std::make_shared<RecordCarryingFilter>(nlohmann::json::parse(R"({
                 "llm_protocol": "ANTHROPIC_MESSAGES", "input_tokens": 1030,
                 "extraction_status": "COMPLETE"})"))},
              "data: {\"choices\":[],\"object\":\"chat.completion.chunk\","
              "\"usage\":{\"completion_tokens\":5,\"prompt_tokens\":10}}\n\n",
              /*sse=*/true);

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->llm_protocol(), envoy::type::ai::v3::ANTHROPIC_MESSAGES);
  EXPECT_EQ(record->input_tokens().value(), 1030);
  EXPECT_FALSE(record->has_output_tokens());
}

// Only Envoy writes the record, so one it cannot read is a bug rather than traffic.
TEST_F(TokenUsageFilterTest, ReportsACarriedRecordItCannotRead) {
  EXPECT_ENVOY_BUG(
      runResponse(
          {tokenUsage(), std::make_shared<RecordCarryingFilter>(nlohmann::json::parse(
                             R"({"input_tokens": "1030", "extraction_status": "COMPLETE"})"))},
          "data: [DONE]\n\n", /*sse=*/true),
      "cannot read the carried record");
}

// Behind the transcoder, the filter publishes what Anthropic reported in its own API: the cache
// buckets, and the model it served.
TEST_F(TokenUsageFilterTest, PublishesTheRecordOfATranscodedStream) {
  const std::string wire = runResponse(
      {tokenUsage(), backendLeg(LLMProtocol::AnthropicMessages)},
      "event: message_start\n"
      R"(data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-5-20250929",)"
      R"("usage":{"input_tokens":10,"cache_read_input_tokens":1000,"cache_creation_input_tokens":20,)"
      R"("output_tokens":1}}})"
      "\n\n"
      "event: content_block_delta\n"
      R"(data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}})"
      "\n\n"
      "event: message_delta\n"
      R"(data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}})"
      "\n\n"
      "event: message_stop\n"
      R"(data: {"type":"message_stop"})"
      "\n\n",
      /*sse=*/true);
  EXPECT_THAT(wire, testing::HasSubstr("chat.completion.chunk"));
  EXPECT_THAT(wire, testing::HasSubstr("data: [DONE]"));
  EXPECT_THAT(wire, testing::Not(testing::HasSubstr("_envoy")));

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->llm_protocol(), envoy::type::ai::v3::ANTHROPIC_MESSAGES);
  EXPECT_EQ(record->model(), "claude-sonnet-4-5-20250929");
  EXPECT_EQ(record->input_tokens().value(), 1030);
  EXPECT_EQ(record->output_tokens().value(), 5);
  EXPECT_EQ(record->total_tokens().value(), 1035);
  EXPECT_EQ(record->input_token_details().cached_tokens().value(), 1000);
  EXPECT_EQ(record->input_token_details().cache_creation_tokens().value(), 20);
  EXPECT_EQ(record->extraction_status(), UsageRecord::COMPLETE);
  EXPECT_EQ(counterValue("api_mismatch"), 0);
}

// The IR's `usage` has no place for Gemini's tool-use count, and holds the computed total rather
// than the one Gemini reported; the record has both.
TEST_F(TokenUsageFilterTest, PublishesTheRecordOfATranscodedResponse) {
  const std::string wire = runResponse(
      {tokenUsage(), backendLeg(LLMProtocol::GeminiGenerateContent)},
      R"({"candidates":[{"content":{"parts":[{"text":"Hi"}],"role":"model"},"finishReason":"STOP"}],)"
      R"("modelVersion":"gemini-2.5-pro","usageMetadata":{"candidatesTokenCount":10,)"
      R"("promptTokenCount":6,"toolUsePromptTokenCount":5,"totalTokenCount":22}})",
      /*sse=*/false);
  EXPECT_EQ(nlohmann::json::parse(wire)["object"], "chat.completion");
  EXPECT_THAT(wire, testing::Not(testing::HasSubstr("_envoy")));

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->llm_protocol(), envoy::type::ai::v3::GEMINI_GENERATE_CONTENT);
  EXPECT_EQ(record->model(), "gemini-2.5-pro");
  EXPECT_EQ(record->input_tokens().value(), 11);
  EXPECT_EQ(record->output_tokens().value(), 10);
  EXPECT_EQ(record->total_tokens().value(), 21);
  EXPECT_EQ(record->input_token_details().tool_use_tokens().value(), 5);
  EXPECT_EQ(record->provider_total_tokens().value(), 22);
  EXPECT_EQ(counterValue("total_mismatch"), 1);
}

// Anthropic's in-band error ends the stream early, and the transcoder forwards it untranslated:
// the record still reports the input the provider counted, flagged partial.
TEST_F(TokenUsageFilterTest, PublishesThePartialRecordOfAStreamThatFailed) {
  runResponse(
      {tokenUsage(), backendLeg(LLMProtocol::AnthropicMessages)},
      "event: message_start\n"
      R"(data: {"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4-5",)"
      R"("usage":{"input_tokens":10,"output_tokens":1}}})"
      "\n\n"
      "event: error\n"
      R"(data: {"type":"error","error":{"type":"overloaded_error"}})"
      "\n\n",
      /*sse=*/true);

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->input_tokens().value(), 10);
  EXPECT_EQ(record->extraction_status(), UsageRecord::PARTIAL);
  EXPECT_EQ(counterValue("partial"), 1);
  EXPECT_EQ(counterValue("api_mismatch"), 0);
}

// A response the transcoder cannot convert reaches the filter as the backend sent it, with the
// record of its usage.
TEST_F(TokenUsageFilterTest, PublishesTheRecordOfAResponseTheTranscoderCannotConvert) {
  const std::string body =
      R"({"model":"claude-sonnet-4-5","type":"message","usage":{"input_tokens":7,"output_tokens":3}})";
  const std::string wire =
      runResponse({tokenUsage(), backendLeg(LLMProtocol::AnthropicMessages)}, body, /*sse=*/false);
  EXPECT_EQ(nlohmann::json::parse(wire), nlohmann::json::parse(body));

  const std::optional<UsageRecord> record = published();
  ASSERT_TRUE(record.has_value());
  EXPECT_EQ(record->llm_protocol(), envoy::type::ai::v3::ANTHROPIC_MESSAGES);
  EXPECT_EQ(record->input_tokens().value(), 7);
  EXPECT_EQ(record->output_tokens().value(), 3);
  EXPECT_EQ(record->extraction_status(), UsageRecord::COMPLETE);
  EXPECT_EQ(counterValue("api_mismatch"), 0);
}

} // namespace
} // namespace TokenUsage
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
