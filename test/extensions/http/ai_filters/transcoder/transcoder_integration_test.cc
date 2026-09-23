#include <string>

#include "envoy/extensions/filters/http/ai_protocol_manager/v3/ai_protocol_manager.pb.h"

#include "test/integration/http_integration.h"
#include "test/test_common/utility.h"

#include "absl/strings/match.h"
#include "absl/strings/str_split.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace {

// Two-stage deployment: the downstream AI Protocol Manager publishes the IR view, the router picks
// the cluster, and the upstream AI Protocol Manager converts the client's request for the provider
// and converts the provider's response back.
class TranscoderIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                  public HttpIntegrationTest {
public:
  TranscoderIntegrationTest() : HttpIntegrationTest(Http::CodecType::HTTP1, GetParam()) {}

  void TearDown() override { cleanupUpstreamAndDownstream(); }

  void initializeFor(envoy::type::ai::v3::LLMProtocol client_protocol,
                     absl::string_view upstream_leg) {
    config_helper_.addConfigModifier([client_protocol](ConfigHelper::HttpConnectionManager& hcm) {
      envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManagerPerRoute
          per_route;
      per_route.mutable_request()->set_llm_protocol(client_protocol);
      auto* route = hcm.mutable_route_config()->mutable_virtual_hosts(0)->mutable_routes(0);
      std::ignore =
          (*route->mutable_typed_per_filter_config())["envoy.filters.http.ai_protocol_manager"]
              .PackFrom(per_route);
    });
    // Upstream HTTP filters need the cluster's protocol options.
    config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      ConfigHelper::HttpProtocolOptions options;
      options.mutable_explicit_http_config()->mutable_http_protocol_options();
      ConfigHelper::setProtocolOptions(*bootstrap.mutable_static_resources()->mutable_clusters(0),
                                       options);
    });
    config_helper_.prependFilter(fmt::format(R"EOF(
name: envoy.filters.http.ai_protocol_manager
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
  request_handling: {{}}
  filters:
  - name: envoy.http.ai_filters.transcoder
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
      upstream:
        {}
)EOF",
                                             upstream_leg),
                                 /*downstream=*/false);
    config_helper_.prependFilter(R"EOF(
name: envoy.filters.http.ai_protocol_manager
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
  request_handling:
    publish_request_ir: true
  response_handling:
    token_usage: {}
  filters:
  - name: envoy.http.ai_filters.transcoder
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
      internal: {}
)EOF");
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
  }

  IntegrationStreamDecoderPtr send(absl::string_view path, absl::string_view body) {
    return codec_client_->makeRequestWithBody(
        Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                       {":path", std::string(path)},
                                       {":scheme", "http"},
                                       {":authority", "sni.lyft.com"},
                                       {"content-type", "application/json"},
                                       {"accept-encoding", "gzip, deflate"}},
        std::string(body));
  }

  void respond(absl::string_view content_type, absl::string_view body) {
    upstream_request_->encodeHeaders(
        Http::TestResponseHeaderMapImpl{{":status", "200"},
                                        {"content-type", std::string(content_type)}},
        false);
    upstream_request_->encodeData(std::string(body), true);
  }

  // The `data:` payloads of an SSE body, in order.
  static std::vector<std::string> sseData(absl::string_view body) {
    std::vector<std::string> data;
    for (absl::string_view line : absl::StrSplit(body, '\n')) {
      if (absl::ConsumePrefix(&line, "data: ") || absl::ConsumePrefix(&line, "data:")) {
        data.emplace_back(line);
      }
    }
    return data;
  }

  // Sums the counter across the downstream (HCM) and upstream (cluster) scopes.
  uint64_t counter(absl::string_view name) {
    uint64_t total = 0;
    for (const auto& counter : test_server_->counters()) {
      if (absl::EndsWith(counter->name(), name)) {
        total += counter->value();
      }
    }
    return total;
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, TranscoderIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

constexpr absl::string_view GeminiUpstream = R"({
          "llm_protocol": "GEMINI_GENERATE_CONTENT",
          "vertex_ai": {"project": "my-project", "location": "global"}})";

constexpr absl::string_view AnthropicUpstream = R"({
          "llm_protocol": "ANTHROPIC_MESSAGES",
          "vertex_ai": {"project": "my-project", "location": "us-east5"}})";

constexpr absl::string_view OpenAiRequest =
    R"({"model":"gemini-2.5-flash","messages":[{"role":"system","content":"Be terse."},)"
    R"({"role":"user","content":"Name two primary colors."}],"max_tokens":64,"user":"u-1"})";

TEST_P(TranscoderIntegrationTest, OpenAiToGeminiUnary) {
  initializeFor(envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS, GeminiUpstream);
  auto response = send("/v1/chat/completions", OpenAiRequest);

  waitForNextUpstreamRequest();
  EXPECT_EQ(upstream_request_->headers().getPathValue(),
            "/v1/projects/my-project/locations/global/publishers/google/models/"
            "gemini-2.5-flash:generateContent");
  EXPECT_TRUE(upstream_request_->headers().get(Http::LowerCaseString("accept-encoding")).empty());
  const nlohmann::json sent = nlohmann::json::parse(upstream_request_->body().toString());
  EXPECT_EQ(sent,
            nlohmann::json::parse(
                R"({"systemInstruction":{"parts":[{"text":"Be terse."}]},)"
                R"("contents":[{"role":"user","parts":[{"text":"Name two primary colors."}]}],)"
                R"("generationConfig":{"maxOutputTokens":64}})"));

  respond("application/json; charset=UTF-8",
          R"({"candidates":[{"content":{"role":"model","parts":[{"text":"Red and blue."}]},)"
          R"("finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9,)"
          R"("candidatesTokenCount":4,"totalTokenCount":13},"modelVersion":"gemini-2.5-flash",)"
          R"("responseId":"resp-1"})");
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("200", response->headers().getStatusValue());
  const nlohmann::json body = nlohmann::json::parse(response->body());
  EXPECT_EQ(body["object"], "chat.completion");
  EXPECT_EQ(body["model"], "gemini-2.5-flash");
  EXPECT_EQ(body["choices"][0]["message"]["content"], "Red and blue.");
  EXPECT_EQ(body["choices"][0]["finish_reason"], "stop");
  EXPECT_EQ(body["usage"]["prompt_tokens"], 9);
  EXPECT_EQ(body["usage"]["completion_tokens"], 4);
  EXPECT_EQ(body["usage"]["total_tokens"], 13);
  EXPECT_EQ(counter("ai_protocol_manager.transcoder.ir_built"), 1);
  EXPECT_EQ(counter("ai_protocol_manager.transcoder.request_converted"), 1);
  EXPECT_EQ(counter("ai_protocol_manager.transcoder.response_converted"), 1);
  // Gemini has no `user`.
  EXPECT_EQ(counter("ai_protocol_manager.transcoder.request_field_dropped"), 1);
}

TEST_P(TranscoderIntegrationTest, OpenAiToGeminiStream) {
  initializeFor(envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS, GeminiUpstream);
  auto response =
      send("/v1/chat/completions", R"({"model":"gemini-2.5-flash","stream":true,)"
                                   R"("stream_options":{"include_usage":true},)"
                                   R"("messages":[{"role":"user","content":"Count to 3."}]})");

  waitForNextUpstreamRequest();
  EXPECT_EQ(upstream_request_->headers().getPathValue(),
            "/v1/projects/my-project/locations/global/publishers/google/models/"
            "gemini-2.5-flash:streamGenerateContent?alt=sse");
  const nlohmann::json sent = nlohmann::json::parse(upstream_request_->body().toString());
  EXPECT_FALSE(sent.contains("stream"));
  EXPECT_FALSE(sent.contains("stream_options"));

  respond(
      "text/event-stream",
      "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"1, \"}]}}],"
      "\"modelVersion\":\"gemini-2.5-flash\",\"responseId\":\"resp-2\"}\n\n"
      "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"2, 3\"}]},"
      "\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":5,"
      "\"candidatesTokenCount\":5,\"totalTokenCount\":10},\"modelVersion\":\"gemini-2.5-flash\","
      "\"responseId\":\"resp-2\"}\n\n");
  ASSERT_TRUE(response->waitForEndStream());
  const std::vector<std::string> data = sseData(response->body());
  ASSERT_GE(data.size(), 4) << response->body();
  EXPECT_EQ(data.back(), "[DONE]");
  std::string content;
  bool saw_finish = false;
  bool saw_usage = false;
  for (size_t i = 0; i + 1 < data.size(); ++i) {
    const nlohmann::json chunk = nlohmann::json::parse(data[i]);
    EXPECT_EQ(chunk["object"], "chat.completion.chunk");
    if (chunk.contains("usage") && chunk["choices"].empty()) {
      saw_usage = true;
      EXPECT_EQ(chunk["usage"]["total_tokens"], 10);
      continue;
    }
    const nlohmann::json& choice = chunk["choices"][0];
    if (choice["delta"].contains("content")) {
      content += choice["delta"]["content"].get<std::string>();
    }
    saw_finish |= choice["finish_reason"] == "stop";
  }
  EXPECT_EQ(content, "1, 2, 3");
  EXPECT_TRUE(saw_finish);
  EXPECT_TRUE(saw_usage);
}

TEST_P(TranscoderIntegrationTest, OpenAiToAnthropicUnary) {
  initializeFor(envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS, AnthropicUpstream);
  auto response =
      send("/v1/chat/completions",
           R"({"model":"claude-sonnet-4-5@20250929","messages":[)"
           R"({"role":"system","content":"Be terse."},{"role":"user","content":"Hi"}]})");

  waitForNextUpstreamRequest();
  EXPECT_EQ(upstream_request_->headers().getPathValue(),
            "/v1/projects/my-project/locations/us-east5/publishers/anthropic/models/"
            "claude-sonnet-4-5%4020250929:rawPredict");
  const nlohmann::json sent = nlohmann::json::parse(upstream_request_->body().toString());
  EXPECT_FALSE(sent.contains("model"));
  EXPECT_EQ(sent["anthropic_version"], "vertex-2023-10-16");
  EXPECT_EQ(sent["system"], "Be terse.");
  EXPECT_EQ(sent["max_tokens"], 4096);
  EXPECT_EQ(sent["messages"], nlohmann::json::parse(R"([{"role":"user","content":"Hi"}])"));

  respond("application/json",
          R"({"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5",)"
          R"("content":[{"type":"text","text":"Hello."}],"stop_reason":"end_turn",)"
          R"("stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":3}})");
  ASSERT_TRUE(response->waitForEndStream());
  const nlohmann::json body = nlohmann::json::parse(response->body());
  EXPECT_EQ(body["object"], "chat.completion");
  EXPECT_EQ(body["choices"][0]["message"]["content"], "Hello.");
  EXPECT_EQ(body["choices"][0]["finish_reason"], "stop");
  EXPECT_EQ(body["usage"]["prompt_tokens"], 12);
  EXPECT_EQ(body["usage"]["completion_tokens"], 3);
}

TEST_P(TranscoderIntegrationTest, OpenAiToAnthropicStream) {
  initializeFor(envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS, AnthropicUpstream);
  auto response = send("/v1/chat/completions",
                       R"({"model":"claude-sonnet-4-5@20250929","stream":true,)"
                       R"("messages":[{"role":"user","content":"Hi"}],"max_tokens":32})");

  waitForNextUpstreamRequest();
  EXPECT_TRUE(absl::EndsWith(upstream_request_->headers().getPathValue(),
                             "claude-sonnet-4-5%4020250929:streamRawPredict"));
  const nlohmann::json sent = nlohmann::json::parse(upstream_request_->body().toString());
  EXPECT_EQ(sent["stream"], true);
  EXPECT_EQ(sent["max_tokens"], 32);

  respond("text/event-stream",
          "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_2\","
          "\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-5\","
          "\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":8,\"output_tokens\":1}}}"
          "\n\n"
          "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,"
          "\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
          "event: ping\ndata: {\"type\":\"ping\"}\n\n"
          "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,"
          "\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n"
          "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,"
          "\"delta\":{\"type\":\"text_delta\",\"text\":\"lo\"}}\n\n"
          "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
          "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":"
          "\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":2}}\n\n"
          "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
  ASSERT_TRUE(response->waitForEndStream());
  const std::vector<std::string> data = sseData(response->body());
  ASSERT_FALSE(data.empty());
  EXPECT_EQ(data.back(), "[DONE]");
  std::string content;
  nlohmann::json finish;
  for (size_t i = 0; i + 1 < data.size(); ++i) {
    const nlohmann::json chunk = nlohmann::json::parse(data[i]);
    const nlohmann::json& choice = chunk["choices"][0];
    if (choice["delta"].contains("content")) {
      content += choice["delta"]["content"].get<std::string>();
    }
    if (!choice["finish_reason"].is_null()) {
      finish = chunk;
    }
  }
  EXPECT_EQ(content, "Hello");
  EXPECT_EQ(finish["choices"][0]["finish_reason"], "stop");
  // ALWAYS: usage rides the finish chunk when the client did not ask for it.
  EXPECT_EQ(finish["usage"]["prompt_tokens"], 8);
  EXPECT_EQ(finish["usage"]["completion_tokens"], 2);
}

TEST_P(TranscoderIntegrationTest, AnthropicClientPassesThroughToVertexAnthropic) {
  initializeFor(envoy::type::ai::v3::ANTHROPIC_MESSAGES, AnthropicUpstream);
  const std::string request =
      R"({"model":"claude-sonnet-4-5@20250929","max_tokens":100,"top_k":5,)"
      R"("thinking":{"type":"enabled","budget_tokens":64},)"
      R"("system":[{"type":"text","text":"Be terse.","cache_control":{"type":"ephemeral"}}],)"
      R"("messages":[{"role":"user","content":"Hi"}]})";
  auto response = send("/v1/messages", request);

  waitForNextUpstreamRequest();
  EXPECT_TRUE(absl::EndsWith(upstream_request_->headers().getPathValue(),
                             "claude-sonnet-4-5%4020250929:rawPredict"));
  nlohmann::json expected = nlohmann::json::parse(request);
  expected.erase("model");
  expected["anthropic_version"] = "vertex-2023-10-16";
  EXPECT_EQ(nlohmann::json::parse(upstream_request_->body().toString()), expected);

  const std::string upstream_body =
      R"({"id":"msg_3","type":"message","role":"assistant","model":"claude-sonnet-4-5",)"
      R"("content":[{"type":"thinking","thinking":"...","signature":"sig"},)"
      R"({"type":"text","text":"Hi."}],"stop_reason":"end_turn","stop_sequence":null,)"
      R"("usage":{"input_tokens":12,"output_tokens":3}})";
  respond("application/json", upstream_body);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ(nlohmann::json::parse(response->body()), nlohmann::json::parse(upstream_body));
  EXPECT_EQ(counter("ai_protocol_manager.transcoder.request_passthrough"), 1);
}

TEST_P(TranscoderIntegrationTest, GeminiClientForwardsBodyByteForByte) {
  initializeFor(envoy::type::ai::v3::GEMINI_GENERATE_CONTENT, GeminiUpstream);
  const std::string request =
      "{ \"contents\": [{\"role\": \"user\", \"parts\": [{\"text\": \"Hi\"}]}],\n"
      "  \"safetySettings\": [{\"category\": \"HARM_CATEGORY_HATE_SPEECH\", \"threshold\": "
      "\"BLOCK_ONLY_HIGH\"}] }";
  auto response = send("/v1beta/models/gemini-2.5-flash:generateContent", request);

  waitForNextUpstreamRequest();
  EXPECT_EQ(upstream_request_->headers().getPathValue(),
            "/v1/projects/my-project/locations/global/publishers/google/models/"
            "gemini-2.5-flash:generateContent");
  EXPECT_EQ(upstream_request_->body().toString(), request);

  const std::string upstream_body =
      R"({"candidates":[{"content":{"role":"model","parts":[{"text":"Hello"}]},)"
      R"("finishReason":"STOP"}]})";
  respond("application/json", upstream_body);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ(nlohmann::json::parse(response->body()), nlohmann::json::parse(upstream_body));
}

TEST_P(TranscoderIntegrationTest, RejectsUnsafeModelName) {
  initializeFor(envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS, GeminiUpstream);
  auto response = send("/v1/chat/completions",
                       R"({"model":"../gemini","messages":[{"role":"user","content":"Hi"}]})");
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ(counter("ai_protocol_manager.transcoder.request_rejected"), 1);
}

TEST_P(TranscoderIntegrationTest, RejectsRequestTheUpstreamCannotExpress) {
  initializeFor(envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS, AnthropicUpstream);
  auto response = send("/v1/chat/completions", R"({"model":"claude-sonnet-4-5@20250929","n":2,)"
                                               R"("messages":[{"role":"user","content":"Hi"}]})");
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("400", response->headers().getStatusValue());
}

} // namespace
} // namespace Envoy
