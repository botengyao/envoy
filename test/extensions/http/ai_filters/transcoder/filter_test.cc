#include <memory>
#include <string>
#include <vector>

#include "envoy/extensions/http/ai_filters/transcoder/v3/transcoder.pb.h"

#include "source/common/coroutine/status_macros.h"
#include "source/common/router/string_accessor_impl.h"
#include "source/common/stream_info/stream_info_impl.h"
#include "source/extensions/common/ai/request_ir.h"
#include "source/extensions/filters/http/ai_protocol_manager/buffer_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/filter_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/http/ai_filters/transcoder/filter.h"

#include "test/extensions/filters/http/ai_protocol_manager/fake_bridge.h"
#include "test/mocks/stats/mocks.h"
#include "test/test_common/utility.h"

#include "absl/strings/str_split.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {
namespace {

using ::Envoy::Extensions::Common::Ai::RequestIr;
using ::Envoy::Extensions::Common::Ai::UpstreamModelFilterStateKey;
using HttpFilters::AiProtocolManager::AiFilterContext;
using HttpFilters::AiProtocolManager::AiFilterSharedPtr;
using HttpFilters::AiProtocolManager::BufferManager;
using HttpFilters::AiProtocolManager::FakeBridge;
using HttpFilters::AiProtocolManager::FilterManager;
using HttpFilters::AiProtocolManager::InMemoryExternalBufferFactory;
using HttpFilters::AiProtocolManager::JsonWithExtBuf;
using testing::NiceMock;

constexpr absl::string_view GeminiVertex = R"EOF(
upstream:
  llm_protocol: GEMINI_GENERATE_CONTENT
  vertex_ai: {project: p, location: global}
)EOF";

constexpr absl::string_view AnthropicVertex = R"EOF(
upstream:
  llm_protocol: ANTHROPIC_MESSAGES
  vertex_ai: {project: p, location: us-east5}
)EOF";

class TranscoderFilterTest : public testing::Test {
public:
  TranscoderFilterTest()
      : api_(Api::createApiForTest()), dispatcher_(api_->allocateDispatcher("test")),
        bridge_(*dispatcher_), buffer_manager_(BufferManager::Config{}, factory_, bridge_),
        stream_info_(api_->timeSource(), nullptr, StreamInfo::FilterState::LifeSpan::FilterChain) {}

  ~TranscoderFilterTest() override {
    manager_.reset();
    if (response_out_ != nullptr) {
      response_out_->onDestroy();
    }
    buffer_manager_.onDestroy();
  }

  TranscoderConfigSharedPtr makeConfig(absl::string_view yaml) {
    envoy::extensions::http::ai_filters::transcoder::v3::Transcoder proto;
    TestUtility::loadFromYaml(std::string(yaml), proto);
    auto config = TranscoderConfig::create(proto, *stats_store_.rootScope());
    EXPECT_TRUE(config.ok()) << config.status();
    return config.value();
  }

  void drain() {
    for (int i = 0; i < 40; ++i) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }
  }

  // Runs the request chain over `body`, the transcoder first, and returns what was forwarded.
  std::string decode(absl::string_view yaml, LLMProtocol protocol, absl::string_view path,
                     absl::string_view body, std::vector<AiFilterSharedPtr> after = {}) {
    headers_ = Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                              {":path", std::string(path)},
                                              {"content-type", "application/json"},
                                              {"content-length", absl::StrCat(body.size())},
                                              {"accept-encoding", "gzip"}};
    JsonWithExtBuf doc;
    doc.setJson(nlohmann::json::parse(body));
    Buffer::OwnedImpl raw(body);
    buffer_manager_.onData(raw);
    buffer_manager_.endStream();
    std::vector<AiFilterSharedPtr> filters{std::make_shared<TranscoderFilter>(
        makeConfig(yaml), AiFilterContext{stream_info_, headers_, protocol})};
    for (AiFilterSharedPtr& filter : after) {
      filters.push_back(std::move(filter));
    }
    manager_ = std::make_unique<FilterManager>(std::move(filters));
    manager_->startRequest(
        std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
        [this](absl::Status status) {
          request_done_ = true;
          request_status_ = std::move(status);
        },
        &headers_,
        [this](Http::Code code, std::string details) {
          reply_code_ = code;
          reply_details_ = std::move(details);
        },
        HttpFilters::AiProtocolManager::RequestFilterManager::SinkOptions{publish_request_ir_});
    drain();
    return bridge_.injected_.toString();
  }

  // Runs the response chain over `body` and returns what reached the client.
  std::string encode(absl::string_view body, bool sse) {
    response_bridge_ = std::make_unique<FakeBridge>(*dispatcher_);
    response_out_ =
        std::make_unique<BufferManager>(BufferManager::Config{}, factory_, *response_bridge_);
    auto on_complete = [this](absl::Status status) { response_status_ = std::move(status); };
    if (sse) {
      manager_->startSseResponse(factory_, *response_bridge_, *response_out_, on_complete);
    } else {
      manager_->startUnaryResponse(factory_, *response_bridge_, *response_out_, on_complete);
    }
    Buffer::OwnedImpl data(body);
    manager_->onResponseData(data, true);
    drain();
    return response_bridge_->injected_.toString();
  }

  static std::vector<std::string> sseData(absl::string_view body) {
    std::vector<std::string> data;
    for (absl::string_view line : absl::StrSplit(body, '\n')) {
      if (absl::ConsumePrefix(&line, "data: ") || absl::ConsumePrefix(&line, "data:")) {
        data.emplace_back(line);
      }
    }
    return data;
  }

  const RequestIr* requestIr() {
    return stream_info_.filterState()->getDataReadOnly<RequestIr>(RequestIr::FilterStateKey);
  }

  uint64_t counter(absl::string_view name) {
    return TestUtility::findCounter(stats_store_,
                                    absl::StrCat("ai_protocol_manager.transcoder.", name))
        ->value();
  }

  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;
  InMemoryExternalBufferFactory factory_;
  FakeBridge bridge_;
  BufferManager buffer_manager_;
  StreamInfo::StreamInfoImpl stream_info_;
  NiceMock<Stats::MockIsolatedStatsStore> stats_store_;
  Http::TestRequestHeaderMapImpl headers_;
  std::unique_ptr<FilterManager> manager_;
  std::unique_ptr<FakeBridge> response_bridge_;
  std::unique_ptr<BufferManager> response_out_;
  bool request_done_{false};
  absl::Status request_status_;
  bool publish_request_ir_{true};
  std::optional<Http::Code> reply_code_;
  std::string reply_details_;
  absl::Status response_status_ = absl::UnknownError("response never completed");
};

// Records the IR the filters before it attached, and optionally edits the request.
class IrProbeFilter : public HttpFilters::AiProtocolManager::AiFilter {
public:
  explicit IrProbeFilter(bool edit = false) : edit_(edit) {}

  Coroutine::Task<absl::Status>
  decode(HttpFilters::AiProtocolManager::AiRequestReceiver receive_request,
         HttpFilters::AiProtocolManager::AiRequestPropagator propagate_request,
         HttpFilters::AiProtocolManager::LocalReplier) override {
    ASSIGN_OR_CO_RETURN(HttpFilters::AiProtocolManager::AiRequestPtr request,
                        co_await std::move(receive_request)());
    if (edit_) {
      request->mutableJson()["temperature"] = 0.5;
    }
    if (const RequestIr* ir = request->ir(); ir != nullptr) {
      model_ = ir->model();
      has_document_ = ir->document() != nullptr;
    }
    co_return co_await std::move(propagate_request)(std::move(request));
  }

  const bool edit_;
  std::optional<std::string> model_;
  bool has_document_{false};
};

TEST_F(TranscoderFilterTest, InternalLegFeedsTheFiltersAfterIt) {
  auto probe = std::make_shared<IrProbeFilter>();
  decode(
      "internal: {}", LLMProtocol::AnthropicMessages, "/v1/messages",
      R"({"model":"claude-haiku-4-5","max_tokens":8,"messages":[{"role":"user","content":"hi"}]})",
      {probe});
  EXPECT_EQ(probe->model_, "claude-haiku-4-5");
  EXPECT_TRUE(probe->has_document_);
  // The manager published the very object the filters read.
  ASSERT_NE(requestIr(), nullptr);
  EXPECT_EQ(requestIr()->model(), "claude-haiku-4-5");
}

TEST_F(TranscoderFilterTest, PublishingIsTheManagersChoice) {
  publish_request_ir_ = false;
  auto probe = std::make_shared<IrProbeFilter>();
  decode("internal: {}", LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
         R"({"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]})", {probe});
  EXPECT_EQ(probe->model_, "gemini-2.5-flash");
  EXPECT_EQ(requestIr(), nullptr);
  EXPECT_EQ(counter("ir_built"), 1);
}

TEST_F(TranscoderFilterTest, EditingTheRequestDropsTheIr) {
  auto editor = std::make_shared<IrProbeFilter>(/*edit=*/true);
  const std::string forwarded = decode(
      "internal: {}", LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
      R"({"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]})", {editor});
  EXPECT_EQ(editor->model_, std::nullopt);
  EXPECT_EQ(requestIr(), nullptr);
  EXPECT_EQ(nlohmann::json::parse(forwarded)["temperature"], 0.5);
}

TEST_F(TranscoderFilterTest, InternalLegPublishesTheViewAndForwardsTheBodyUntouched) {
  const std::string body = "{ \"messages\": [{\"role\": \"user\", \"content\": \"hi\"}],\n  "
                           "\"model\": \"gemini-2.5-flash\","
                           " \"stream\": true }";
  EXPECT_EQ(
      decode("internal: {}", LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions", body),
      body);
  EXPECT_TRUE(request_status_.ok()) << request_status_;
  EXPECT_EQ(headers_.getPathValue(), "/v1/chat/completions");
  EXPECT_EQ(headers_.getContentLengthValue(), absl::StrCat(body.size()));

  const RequestIr* ir = requestIr();
  ASSERT_NE(ir, nullptr);
  EXPECT_EQ(ir->clientProtocol(), LLMProtocol::OpenAiChatCompletions);
  EXPECT_EQ(ir->model(), "gemini-2.5-flash");
  EXPECT_EQ(ir->stream(), true);
  ASSERT_NE(ir->document(), nullptr);
  EXPECT_EQ(ir->document()->json(), nlohmann::json::parse(body));
  EXPECT_EQ(absl::get<absl::string_view>(ir->getField("model")), "gemini-2.5-flash");
  EXPECT_EQ(absl::get<absl::string_view>(ir->getField("stream")), "true");
  EXPECT_EQ(absl::get<absl::string_view>(ir->getField("client_protocol")),
            "OPENAI_CHAT_COMPLETIONS");
  EXPECT_TRUE(absl::holds_alternative<absl::monostate>(ir->getField("nope")));
  EXPECT_EQ(nlohmann::json::parse(ir->serializeAsString().value()),
            nlohmann::json::parse(R"({"client_protocol":"OPENAI_CHAT_COMPLETIONS",)"
                                  R"("model":"gemini-2.5-flash","stream":true})"));
  EXPECT_EQ(counter("ir_built"), 1);
}

TEST_F(TranscoderFilterTest, InternalLegNormalizesAnthropic) {
  decode("internal: {}", LLMProtocol::AnthropicMessages, "/v1/messages",
         R"({"model":"claude-sonnet-4-5","max_tokens":64,"system":"Be terse.",)"
         R"("messages":[{"role":"user","content":"hi"}]})");
  const RequestIr* ir = requestIr();
  ASSERT_NE(ir, nullptr);
  ASSERT_NE(ir->document(), nullptr);
  const nlohmann::json& doc = ir->document()->json();
  EXPECT_EQ(doc["max_completion_tokens"], 64);
  EXPECT_EQ(doc["messages"][0]["role"], "system");
  EXPECT_EQ(doc["model"], "claude-sonnet-4-5");
}

TEST_F(TranscoderFilterTest, InternalLegLiftsGeminiPathFields) {
  decode("internal: {}", LLMProtocol::GeminiGenerateContent,
         "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
         R"({"contents":[{"role":"user","parts":[{"text":"hi"}]}]})");
  const RequestIr* ir = requestIr();
  ASSERT_NE(ir, nullptr);
  EXPECT_EQ(ir->model(), "gemini-2.5-flash");
  EXPECT_EQ(ir->stream(), true);
  ASSERT_NE(ir->document(), nullptr);
  EXPECT_EQ(ir->document()->json()["model"], "gemini-2.5-flash");
  EXPECT_EQ(ir->document()->json()["stream"], true);
  EXPECT_EQ(ir->document()->json()["messages"][0]["content"], "hi");
}

TEST_F(TranscoderFilterTest, InternalLegSkipsARequestWithoutAModel) {
  const std::string body = R"({"messages":[{"role":"user","content":"hi"}]})";
  EXPECT_EQ(
      decode("internal: {}", LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions", body),
      body);
  EXPECT_EQ(requestIr(), nullptr);
  EXPECT_EQ(counter("ir_incomplete"), 1);
  EXPECT_EQ(counter("ir_built"), 0);
}

TEST_F(TranscoderFilterTest, InternalLegPublishesFieldsWhenTheDocumentCannotBeConverted) {
  // Gemini's to-IR rules reject non-text parts.
  decode("internal: {}", LLMProtocol::GeminiGenerateContent,
         "/v1beta/models/gemini-2.5-flash:generateContent",
         R"({"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png",)"
         R"("data":"AAAA"}}]}]})");
  const RequestIr* ir = requestIr();
  ASSERT_NE(ir, nullptr);
  EXPECT_EQ(ir->model(), "gemini-2.5-flash");
  EXPECT_EQ(ir->document(), nullptr);
  EXPECT_EQ(counter("ir_incomplete"), 1);
}

TEST_F(TranscoderFilterTest, InternalLegKeepsTheFirstView) {
  auto first = std::make_shared<RequestIr>(LLMProtocol::AnthropicMessages, "first", std::nullopt,
                                           std::nullopt);
  stream_info_.filterState()->setData(RequestIr::FilterStateKey, first,
                                      StreamInfo::FilterState::LifeSpan::FilterChain);
  decode("internal: {}", LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
         R"({"model":"second","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(requestIr()->model(), "first");
  EXPECT_EQ(counter("ir_built"), 1);
}

TEST_F(TranscoderFilterTest, UpstreamLegConvertsOpenAiToGemini) {
  const std::string forwarded =
      decode(GeminiVertex, LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
             R"({"model":"gemini-2.5-flash","max_tokens":32,"stream":true,)"
             R"("stream_options":{"include_usage":true},)"
             R"("messages":[{"role":"system","content":"Be terse."},)"
             R"({"role":"user","content":"hi"}]})");
  EXPECT_TRUE(request_status_.ok()) << request_status_;
  EXPECT_EQ(nlohmann::json::parse(forwarded),
            nlohmann::json::parse(R"({"systemInstruction":{"parts":[{"text":"Be terse."}]},)"
                                  R"("contents":[{"role":"user","parts":[{"text":"hi"}]}],)"
                                  R"("generationConfig":{"maxOutputTokens":32}})"));
  EXPECT_EQ(headers_.getPathValue(), "/v1/projects/p/locations/global/publishers/google/models/"
                                     "gemini-2.5-flash:streamGenerateContent?alt=sse");
  EXPECT_TRUE(headers_.get(Http::LowerCaseString("accept-encoding")).empty());
  EXPECT_EQ(headers_.getContentLengthValue(), absl::StrCat(forwarded.size()));
  EXPECT_EQ(counter("request_converted"), 1);
}

TEST_F(TranscoderFilterTest, UpstreamLegPassesTheSameProtocolThroughByteForByte) {
  const std::string body =
      "{ \"contents\": [{\"role\": \"user\", \"parts\": [{\"text\": \"hi\"}]}] }";
  EXPECT_EQ(decode(GeminiVertex, LLMProtocol::GeminiGenerateContent,
                   "/v1beta/models/gemini-2.5-flash:generateContent", body),
            body);
  EXPECT_EQ(headers_.getPathValue(),
            "/v1/projects/p/locations/global/publishers/google/models/gemini-2.5-flash:"
            "generateContent");
  EXPECT_EQ(counter("request_passthrough"), 1);
}

TEST_F(TranscoderFilterTest, UpstreamLegAppliesTheVertexAnthropicEnvelope) {
  const std::string forwarded =
      decode(AnthropicVertex, LLMProtocol::AnthropicMessages, "/v1/messages",
             R"({"model":"claude-sonnet-4-5@20250929","max_tokens":8,"top_k":3,)"
             R"("messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(nlohmann::json::parse(forwarded),
            nlohmann::json::parse(R"({"anthropic_version":"vertex-2023-10-16","max_tokens":8,)"
                                  R"("top_k":3,"messages":[{"role":"user","content":"hi"}]})"));
  EXPECT_EQ(headers_.getPathValue(), "/v1/projects/p/locations/us-east5/publishers/anthropic/"
                                     "models/claude-sonnet-4-5%4020250929:rawPredict");
}

TEST_F(TranscoderFilterTest, ConfiguredModelWinsOverTheOverrideAndTheRequest) {
  stream_info_.filterState()->setData(
      UpstreamModelFilterStateKey, std::make_shared<Router::StringAccessorImpl>("gemini-2.5-pro"),
      StreamInfo::FilterState::LifeSpan::FilterChain);
  decode(absl::StrCat(GeminiVertex, "  model: gemini-2.0-flash\n"),
         LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
         R"({"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_TRUE(absl::EndsWith(headers_.getPathValue(), "/gemini-2.0-flash:generateContent"));
}

TEST_F(TranscoderFilterTest, FilterStateOverrideWinsOverTheRequest) {
  stream_info_.filterState()->setData(
      UpstreamModelFilterStateKey, std::make_shared<Router::StringAccessorImpl>("gemini-2.5-pro"),
      StreamInfo::FilterState::LifeSpan::FilterChain);
  decode(GeminiVertex, LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
         R"({"model":"gemini-2.5-flash","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_TRUE(absl::EndsWith(headers_.getPathValue(), "/gemini-2.5-pro:generateContent"));
}

struct RejectionCase {
  std::string name;
  std::string config;
  LLMProtocol protocol;
  std::string path;
  std::string body;
  Http::Code code;
};

class TranscoderRejectionTest : public TranscoderFilterTest,
                                public testing::WithParamInterface<RejectionCase> {};

TEST_P(TranscoderRejectionTest, RepliesLocally) {
  const RejectionCase& c = GetParam();
  EXPECT_EQ(decode(c.config, c.protocol, c.path, c.body), "");
  ASSERT_TRUE(reply_code_.has_value());
  EXPECT_EQ(*reply_code_, c.code) << reply_details_;
}

INSTANTIATE_TEST_SUITE_P(
    Rejections, TranscoderRejectionTest,
    testing::Values(
        RejectionCase{"UndeclaredClientProtocol", std::string(GeminiVertex),
                      LLMProtocol::Unspecified, "/x", R"({"model":"m"})",
                      Http::Code::InternalServerError},
        RejectionCase{"UnsupportedPair", std::string(GeminiVertex), LLMProtocol::OpenAiResponses,
                      "/v1/responses", R"({"model":"m","input":"hi"})", Http::Code::NotImplemented},
        RejectionCase{"MissingModel", std::string(GeminiVertex), LLMProtocol::OpenAiChatCompletions,
                      "/v1/chat/completions", R"({"messages":[{"role":"user","content":"hi"}]})",
                      Http::Code::BadRequest},
        RejectionCase{"UnsafeModel", std::string(GeminiVertex), LLMProtocol::OpenAiChatCompletions,
                      "/v1/chat/completions",
                      R"({"model":"../x","messages":[{"role":"user","content":"hi"}]})",
                      Http::Code::BadRequest},
        RejectionCase{
            "GeminiStreamWithoutSse", std::string(GeminiVertex), LLMProtocol::GeminiGenerateContent,
            "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
            R"({"contents":[{"role":"user","parts":[{"text":"hi"}]}]})", Http::Code::BadRequest},
        RejectionCase{"ConversionFailure", std::string(AnthropicVertex),
                      LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
                      R"({"model":"claude","n":2,"messages":[{"role":"user","content":"hi"}]})",
                      Http::Code::BadRequest}),
    [](const testing::TestParamInfo<RejectionCase>& info) { return info.param.name; });

TEST_F(TranscoderFilterTest, ConvertsAGeminiStreamToOpenAiChunks) {
  decode(GeminiVertex, LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
         R"({"model":"gemini-2.5-flash","stream":true,)"
         R"("messages":[{"role":"user","content":"hi"}]})");
  const std::string out = encode(
      "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hel\"}]}}],"
      "\"responseId\":\"r1\",\"modelVersion\":\"gemini-2.5-flash\"}\n\n"
      "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"lo\"}]},"
      "\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":2,"
      "\"candidatesTokenCount\":2,\"totalTokenCount\":4},\"responseId\":\"r1\"}\n\n",
      /*sse=*/true);
  EXPECT_TRUE(response_status_.ok()) << response_status_;
  const std::vector<std::string> data = sseData(out);
  ASSERT_GE(data.size(), 4) << out;
  EXPECT_EQ(data.back(), "[DONE]");
  std::string content;
  for (size_t i = 0; i + 1 < data.size(); ++i) {
    const nlohmann::json chunk = nlohmann::json::parse(data[i]);
    EXPECT_EQ(chunk["object"], "chat.completion.chunk");
    const nlohmann::json& delta = chunk["choices"][0]["delta"];
    if (delta.contains("content")) {
      content += delta["content"].get<std::string>();
    }
  }
  EXPECT_EQ(content, "Hello");
  EXPECT_EQ(counter("response_converted"), 1);
}

TEST_F(TranscoderFilterTest, ConvertsAnAnthropicBodyToOpenAi) {
  decode(AnthropicVertex, LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
         R"({"model":"claude","messages":[{"role":"user","content":"hi"}]})");
  const std::string out =
      encode(R"({"id":"msg_1","type":"message","role":"assistant","model":"claude",)"
             R"("content":[{"type":"text","text":"Hello."}],"stop_reason":"max_tokens",)"
             R"("usage":{"input_tokens":3,"output_tokens":2}})",
             /*sse=*/false);
  EXPECT_TRUE(response_status_.ok()) << response_status_;
  const nlohmann::json body = nlohmann::json::parse(out);
  EXPECT_EQ(body["object"], "chat.completion");
  EXPECT_EQ(body["choices"][0]["message"]["content"], "Hello.");
  EXPECT_EQ(body["choices"][0]["finish_reason"], "length");
  EXPECT_EQ(body["usage"]["total_tokens"], 5);
}

TEST_F(TranscoderFilterTest, FailsAnOversizedUnaryResponse) {
  decode(absl::StrCat(AnthropicVertex, "  max_response_bytes: 16\n"),
         LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
         R"({"model":"claude","messages":[{"role":"user","content":"hi"}]})");
  encode(R"({"id":"msg_1","type":"message","content":[{"type":"text","text":"a long answer"}]})",
         /*sse=*/false);
  EXPECT_EQ(response_status_.code(), absl::StatusCode::kResourceExhausted);
  EXPECT_EQ(counter("response_failed"), 1);
}

TEST_F(TranscoderFilterTest, FailsAnUnconvertibleUnaryResponse) {
  decode(AnthropicVertex, LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
         R"({"model":"claude","messages":[{"role":"user","content":"hi"}]})");
  encode("[1, 2]", /*sse=*/false);
  EXPECT_FALSE(response_status_.ok());
  EXPECT_EQ(counter("response_failed"), 1);
}

TEST_F(TranscoderFilterTest, LeavesASameProtocolResponseAlone) {
  decode(GeminiVertex, LLMProtocol::GeminiGenerateContent,
         "/v1beta/models/gemini-2.5-flash:generateContent",
         R"({"contents":[{"role":"user","parts":[{"text":"hi"}]}]})");
  const std::string upstream = R"({"candidates":[{"finishReason":"STOP"}]})";
  EXPECT_EQ(nlohmann::json::parse(encode(upstream, /*sse=*/false)),
            nlohmann::json::parse(upstream));
  EXPECT_EQ(counter("response_converted"), 0);
}

TEST_F(TranscoderFilterTest, InternalLegLeavesTheResponseAlone) {
  decode("internal: {}", LLMProtocol::OpenAiChatCompletions, "/v1/chat/completions",
         R"({"model":"m","messages":[{"role":"user","content":"hi"}]})");
  const std::string upstream = "data: {\"x\":1}\n\ndata: [DONE]\n\n";
  EXPECT_EQ(sseData(encode(upstream, /*sse=*/true)),
            (std::vector<std::string>{"{\"x\":1}", "[DONE]"}));
}

} // namespace
} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
