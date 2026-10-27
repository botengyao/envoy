#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "envoy/extensions/http/ai_filters/schema_validation/v3/schema_validation.pb.h"

#include "source/common/stream_info/stream_info_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter_state.h"
#include "source/extensions/filters/http/ai_protocol_manager/buffer_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/filter_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/http/ai_filters/common/sync_filter.h"
#include "source/extensions/http/ai_filters/schema_validation/filter.h"

#include "test/extensions/filters/http/ai_protocol_manager/fake_bridge.h"
#include "test/mocks/stats/mocks.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace SchemaValidation {
namespace {

using HttpFilters::AiProtocolManager::AiFilterContext;
using HttpFilters::AiProtocolManager::AiFilterSharedPtr;
using HttpFilters::AiProtocolManager::AiRequest;
using HttpFilters::AiProtocolManager::BufferManager;
using HttpFilters::AiProtocolManager::FakeBridge;
using HttpFilters::AiProtocolManager::FilterManager;
using HttpFilters::AiProtocolManager::InMemoryExternalBufferFactory;
using HttpFilters::AiProtocolManager::JsonWithExtBuf;
using HttpFilters::AiProtocolManager::LlmBinding;
using HttpFilters::AiProtocolManager::LlmBindingConstSharedPtr;
using HttpFilters::AiProtocolManager::LlmBindingObject;
using HttpFilters::AiProtocolManager::LLMProtocol;
using HttpFilters::AiProtocolManager::LocalReplier;

constexpr absl::string_view ChatPayload =
    R"({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]})";
// Claude on Vertex AI names the model in the path alone, and the Vertex AI API version in the body.
constexpr absl::string_view VertexClaudePayload =
    R"({"anthropic_version":"vertex-2023-10-16","max_tokens":8,)"
    R"("messages":[{"role":"user","content":"hi"}]})";
constexpr absl::string_view VertexClaudePath =
    "/v1/projects/acme/locations/us-east5/publishers/anthropic/models/"
    "claude-sonnet-4-5@20250929:rawPredict";
constexpr absl::string_view GeminiPayload =
    R"({"contents":[{"role":"user","parts":[{"text":"hi"}]}]})";

// Stands in for the filters after this one, to show what they are handed.
class ProtocolRecordingFilter : public Common::SyncAiFilter {
public:
  explicit ProtocolRecordingFilter(std::optional<LLMProtocol>& seen) : seen_(seen) {}

  absl::Status decodeSync(AiRequest& request, LocalReplier) override {
    seen_ = request.protocol();
    return absl::OkStatus();
  }

private:
  std::optional<LLMProtocol>& seen_;
};

class SchemaValidationFilterTest : public testing::Test {
public:
  SchemaValidationFilterTest()
      : api_(Api::createApiForTest()), dispatcher_(api_->allocateDispatcher("test")),
        bridge_(*dispatcher_), buffer_manager_(BufferManager::Config{}, factory_, bridge_),
        stream_info_(api_->timeSource(), nullptr, StreamInfo::FilterState::LifeSpan::FilterChain) {}

  ~SchemaValidationFilterTest() override { buffer_manager_.onDestroy(); }

  void run(JsonWithExtBuf doc, LLMProtocol declared_protocol,
           absl::string_view path = "/v1/chat/completions") {
    request_headers_ =
        Http::TestRequestHeaderMapImpl{{":method", "POST"}, {":path", std::string(path)}};
    envoy::extensions::http::ai_filters::schema_validation::v3::SchemaValidation proto;
    proto.set_default_llm_protocol(default_llm_protocol_);
    proto.set_fail_open(fail_open_);
    std::vector<AiFilterSharedPtr> filters;
    filters.push_back(std::make_shared<SchemaValidationFilter>(
        std::make_shared<const SchemaValidationFilterConfig>(proto, *stats_store_.rootScope()),
        AiFilterContext{.stream_info = stream_info_,
                        .request_headers = request_headers_,
                        .request_protocol = declared_protocol,
                        .request_binding = route_binding_}));
    filters.push_back(std::make_shared<ProtocolRecordingFilter>(seen_protocol_));
    FilterManager manager(std::move(filters));

    manager.startRequest(
        std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
        [this](absl::Status status) { status_ = std::move(status); }, &request_headers_,
        [this](Http::Code code, std::string details) {
          reply_code_ = code;
          reply_details_ = std::move(details);
        },
        /*always_serialize=*/true, declared_protocol);
    for (int i = 0; i < 20; ++i) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }
    ASSERT_TRUE(status_.has_value());
  }

  void run(absl::string_view payload, LLMProtocol declared_protocol,
           absl::string_view path = "/v1/chat/completions") {
    JsonWithExtBuf doc;
    doc.setJson(nlohmann::json::parse(payload));
    run(std::move(doc), declared_protocol, path);
  }

  void expectForwarded() {
    EXPECT_TRUE(status_->ok()) << *status_;
    EXPECT_FALSE(reply_code_.has_value());
    EXPECT_GT(bridge_.injected_.length(), 0);
  }

  void expectForwardedUnchanged(absl::string_view payload) {
    expectForwarded();
    EXPECT_EQ(nlohmann::json::parse(bridge_.injected_.toString()), nlohmann::json::parse(payload));
    EXPECT_EQ(counterValue("valid"), 1);
  }

  void expectRejected() {
    EXPECT_FALSE(status_->ok());
    EXPECT_EQ(reply_code_, Http::Code::BadRequest);
    EXPECT_FALSE(reply_details_.empty());
    EXPECT_FALSE(seen_protocol_.has_value());
    EXPECT_EQ(bridge_.injected_.length(), 0);
    EXPECT_EQ(counterValue("invalid"), 1);
  }

  void setRequestBinding(absl::string_view value) {
    stream_info_.filterState()->setData(
        HttpFilters::AiProtocolManager::FilterStateKeys::BindingRequest,
        std::make_shared<LlmBindingObject>(value), StreamInfo::FilterState::LifeSpan::FilterChain);
  }

  uint64_t counterValue(const std::string& name) {
    const auto counter =
        TestUtility::findCounter(stats_store_, "ai_protocol_manager.schema_validation." + name);
    return counter != nullptr ? counter->value() : 0;
  }

  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;
  InMemoryExternalBufferFactory factory_;
  FakeBridge bridge_;
  BufferManager buffer_manager_;
  StreamInfo::StreamInfoImpl stream_info_;
  NiceMock<Stats::MockIsolatedStatsStore> stats_store_;
  Http::TestRequestHeaderMapImpl request_headers_;
  envoy::type::ai::v3::LLMProtocol default_llm_protocol_{
      envoy::type::ai::v3::LLM_PROTOCOL_UNSPECIFIED};
  bool fail_open_{false};
  LlmBindingConstSharedPtr route_binding_;

  std::optional<absl::Status> status_;
  std::optional<Http::Code> reply_code_;
  std::string reply_details_;
  std::optional<LLMProtocol> seen_protocol_;
};

TEST_F(SchemaValidationFilterTest, ForwardsPayloadMatchingTheDeclaredSchema) {
  run(ChatPayload, LLMProtocol::OpenAiChatCompletions);
  expectForwarded();
  EXPECT_EQ(nlohmann::json::parse(bridge_.injected_.toString()),
            nlohmann::json::parse(ChatPayload));
  EXPECT_EQ(seen_protocol_, LLMProtocol::OpenAiChatCompletions);
  EXPECT_EQ(counterValue("valid"), 1);
  EXPECT_EQ(counterValue("invalid"), 0);
  EXPECT_EQ(counterValue("skipped"), 0);
}

TEST_F(SchemaValidationFilterTest, RejectsPayloadViolatingTheDeclaredSchema) {
  run(R"({"model":"gpt-4o"})", LLMProtocol::OpenAiChatCompletions);
  expectRejected();
  EXPECT_EQ(counterValue("valid"), 0);
}

// `model` must stay inline; an offloaded one is rejected rather than read from the buffer.
TEST_F(SchemaValidationFilterTest, RejectsOffloadedModel) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{
      {"model", JsonWithExtBuf::makeExternalRef(JsonWithExtBuf::ExternalRef{9, 2000})},
      {"messages", nlohmann::json::array({{{"role", "user"}, {"content", "hi"}}})}});
  run(std::move(doc), LLMProtocol::OpenAiChatCompletions);
  expectRejected();
}

TEST_F(SchemaValidationFilterTest, FailOpenForwardsAnInvalidPayload) {
  fail_open_ = true;
  run(R"({"model":"gpt-4o"})", LLMProtocol::OpenAiChatCompletions);
  expectForwarded();
  EXPECT_EQ(nlohmann::json::parse(bridge_.injected_.toString()),
            nlohmann::json::parse(R"({"model":"gpt-4o"})"));
  EXPECT_EQ(seen_protocol_, LLMProtocol::OpenAiChatCompletions);
  EXPECT_EQ(counterValue("invalid"), 1);
  EXPECT_EQ(counterValue("valid"), 0);
}

TEST_F(SchemaValidationFilterTest, SkipsAnApiWithoutASchema) {
  run(R"({"model":"gpt-5","input":7})", LLMProtocol::OpenAiResponses, "/v1/responses");
  expectForwarded();
  EXPECT_EQ(seen_protocol_, LLMProtocol::OpenAiResponses);
  EXPECT_EQ(counterValue("skipped"), 1);
}

// Anthropic requires `max_tokens`, which a Chat Completions payload lacks.
TEST_F(SchemaValidationFilterTest, DefaultAppliesWhenNoneIsDeclared) {
  default_llm_protocol_ = envoy::type::ai::v3::ANTHROPIC_MESSAGES;
  run(ChatPayload, LLMProtocol::Unspecified);
  expectRejected();
  EXPECT_EQ(counterValue("llm_protocol_detected"), 0);
}

TEST_F(SchemaValidationFilterTest, DetectsTheApiFromThePath) {
  run(ChatPayload, LLMProtocol::Unspecified, "/anthropic/v1/messages");
  expectRejected();
  EXPECT_EQ(counterValue("llm_protocol_detected"), 1);
}

TEST_F(SchemaValidationFilterTest, DetectsTheApiFromThePayload) {
  run(R"({"contents":[{"role":"user","parts":[{"text":"hi"}]}]})", LLMProtocol::Unspecified,
      "/generate");
  expectForwarded();
  EXPECT_EQ(seen_protocol_, LLMProtocol::GeminiGenerateContent);
  EXPECT_EQ(counterValue("llm_protocol_detected"), 1);
  EXPECT_EQ(counterValue("valid"), 1);
}

TEST_F(SchemaValidationFilterTest, UndetectedApiIsForwardedUnvalidated) {
  run(ChatPayload, LLMProtocol::Unspecified, "/generate");
  expectForwarded();
  EXPECT_EQ(seen_protocol_, LLMProtocol::Unspecified);
  EXPECT_EQ(counterValue("llm_protocol_detected"), 0);
  EXPECT_EQ(counterValue("skipped"), 1);
}

// Neither the default nor detection second-guesses a declared API.
TEST_F(SchemaValidationFilterTest, DeclaredApiOutranksDefaultAndDetection) {
  default_llm_protocol_ = envoy::type::ai::v3::ANTHROPIC_MESSAGES;
  run(ChatPayload, LLMProtocol::OpenAiChatCompletions, "/v1/messages");
  expectForwarded();
  EXPECT_EQ(seen_protocol_, LLMProtocol::OpenAiChatCompletions);
  EXPECT_EQ(counterValue("llm_protocol_detected"), 0);
}

// The path supplies `model` under the binding Envoy defines for Claude on Vertex AI, which also
// writes `anthropic_version`. Neither change reaches the payload forwarded.
TEST_F(SchemaValidationFilterTest, VertexClaudeRawPredictBodyIsValid) {
  run(VertexClaudePayload, LLMProtocol::AnthropicMessages, VertexClaudePath);
  expectForwardedUnchanged(VertexClaudePayload);
}

// The binding removes `model`, so the path's is validated in place of the body's, which the
// payload forwarded keeps.
TEST_F(SchemaValidationFilterTest, KeepsTheFieldsTheBodySent) {
  constexpr absl::string_view payload =
      R"({"anthropic_version":"vertex-2023-10-16","model":"claude-haiku-4-5","max_tokens":8,)"
      R"("messages":[{"role":"user","content":"hi"}]})";
  run(payload, LLMProtocol::AnthropicMessages, VertexClaudePath);
  expectForwardedUnchanged(payload);
}

TEST_F(SchemaValidationFilterTest, MalformedVertexClaudeBodyIsRejected) {
  run(R"({"anthropic_version":"vertex-2023-10-16","messages":[{"role":"user","content":"hi"}]})",
      LLMProtocol::AnthropicMessages, VertexClaudePath);
  expectRejected();
  EXPECT_EQ(reply_details_, "missing required field: max_tokens");
}

TEST_F(SchemaValidationFilterTest, NonObjectBodyIsRejectedUnderABinding) {
  run("[]", LLMProtocol::AnthropicMessages, VertexClaudePath);
  expectRejected();
}

// No binding matches the Anthropic API's own path, so the body must name the model.
TEST_F(SchemaValidationFilterTest, ModelIsRequiredOffABinding) {
  run(VertexClaudePayload, LLMProtocol::AnthropicMessages, "/v1/messages");
  expectRejected();
  EXPECT_EQ(reply_details_, "missing required field: model");
}

// The route's binding takes a gateway prefix, and keeps the edits of Gemini's own.
TEST_F(SchemaValidationFilterTest, PrefixedGeminiRouteBindingIsApplied) {
  route_binding_ = *LlmBinding::parse(
      "/gemini/v1beta/models/{model}:{generateContent|streamGenerateContent?alt=sse}");
  run(GeminiPayload, LLMProtocol::GeminiGenerateContent,
      "/gemini/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse");
  expectForwardedUnchanged(GeminiPayload);
}

// A route binding that puts the model in the path satisfies an API that requires `model`.
TEST_F(SchemaValidationFilterTest, RouteBindingSuppliesTheModel) {
  constexpr absl::string_view payload = R"({"messages":[{"role":"user","content":"hi"}]})";
  route_binding_ = *LlmBinding::parse("/openai/deployments/{model}/chat/completions");
  run(payload, LLMProtocol::OpenAiChatCompletions,
      "/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21");
  expectForwardedUnchanged(payload);
}

// A binding given replaces the ones Envoy defines, as it does for the transcoder.
TEST_F(SchemaValidationFilterTest, RouteBindingThatDoesNotMatchReadsNothing) {
  route_binding_ = *LlmBinding::parse("/claude/{model}/messages");
  run(VertexClaudePayload, LLMProtocol::AnthropicMessages, VertexClaudePath);
  expectRejected();
}

TEST_F(SchemaValidationFilterTest, FilterStateBindingReplacesTheRoutes) {
  constexpr absl::string_view payload =
      R"({"max_tokens":8,"messages":[{"role":"user","content":"hi"}]})";
  route_binding_ = *LlmBinding::parse("/route/{model}/messages");
  setRequestBinding("/state/{model}/messages");
  run(payload, LLMProtocol::AnthropicMessages, "/state/claude-haiku-4-5/messages");
  expectForwardedUnchanged(payload);
}

// The transcoder fails the request for a binding that does not parse; validation reads the path
// as if it were unset.
TEST_F(SchemaValidationFilterTest, UnparsableFilterStateBindingIsIgnored) {
  setRequestBinding("not a binding");
  run(VertexClaudePayload, LLMProtocol::AnthropicMessages, VertexClaudePath);
  expectForwardedUnchanged(VertexClaudePayload);
}

} // namespace
} // namespace SchemaValidation
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
