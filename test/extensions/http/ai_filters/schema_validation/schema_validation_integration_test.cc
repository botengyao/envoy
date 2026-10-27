#include <string>

#include "envoy/extensions/filters/http/ai_protocol_manager/v3/ai_protocol_manager.pb.h"
#include "envoy/type/ai/v3/llm_protocol.pb.h"

#include "test/integration/http_integration.h"

#include "nlohmann/json.hpp"

namespace Envoy {
namespace {

constexpr absl::string_view AnthropicPayload =
    R"({"model":"claude","max_tokens":8,"messages":[{"role":"user","content":"hi"}]})";
// Claude on Vertex AI names the model in the path alone, and the Vertex AI API version in the body.
constexpr absl::string_view VertexClaudePayload =
    R"({"anthropic_version":"vertex-2023-10-16","max_tokens":8,)"
    R"("messages":[{"role":"user","content":"hi"}]})";
constexpr absl::string_view VertexClaudePath =
    "/v1/projects/acme/locations/us-east5/publishers/anthropic/models/"
    "claude-sonnet-4-5@20250929:rawPredict";

class SchemaValidationIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                        public HttpIntegrationTest {
public:
  SchemaValidationIntegrationTest() : HttpIntegrationTest(Http::CodecType::HTTP1, GetParam()) {}

  // The route declares an AI endpoint as `route_request_` does, by default without naming its API.
  void initializeFilters(bool with_filter_state, bool fail_open = false) {
    config_helper_.addConfigModifier([this](ConfigHelper::HttpConnectionManager& hcm) {
      envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManagerPerRoute
          per_route;
      *per_route.mutable_request() = route_request_;
      auto* route = hcm.mutable_route_config()->mutable_virtual_hosts(0)->mutable_routes(0);
      std::ignore =
          (*route->mutable_typed_per_filter_config())["envoy.filters.http.ai_protocol_manager"]
              .PackFrom(per_route);
    });

    config_helper_.prependFilter(fmt::format(R"EOF(
name: envoy.filters.http.ai_protocol_manager
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
  request_handling: {{}}
  filters:
  - name: envoy.http.ai_filters.schema_validation
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.http.ai_filters.schema_validation.v3.SchemaValidation
      fail_open: {}
)EOF",
                                             fail_open));

    if (with_filter_state) {
      config_helper_.prependFilter(R"EOF(
name: envoy.filters.http.set_filter_state
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
  on_request_headers:
  - object_key: envoy.ai.llm_protocol.request
    format_string:
      text_format_source:
        inline_string: "%REQ(x-llm-api)%"
)EOF");
    }

    initialize();
  }

  IntegrationStreamDecoderPtr sendRequest(absl::string_view path, absl::string_view payload,
                                          absl::string_view llm_api = "") {
    Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                           {":path", std::string(path)},
                                           {":scheme", "http"},
                                           {":authority", "host"},
                                           {"content-type", "application/json"}};
    if (!llm_api.empty()) {
      headers.addCopy("x-llm-api", std::string(llm_api));
    }
    codec_client_ = makeHttpConnection(lookupPort("http"));
    return codec_client_->makeRequestWithBody(headers, std::string(payload));
  }

  void expectForwarded(IntegrationStreamDecoderPtr response, absl::string_view payload) {
    waitForNextUpstreamRequest();
    EXPECT_EQ(nlohmann::json::parse(upstream_request_->body().toString()),
              nlohmann::json::parse(payload));
    upstream_request_->encodeHeaders(default_response_headers_, true);
    ASSERT_TRUE(response->waitForEndStream());
    EXPECT_EQ("200", response->headers().getStatusValue());
  }

  void expectRejected(IntegrationStreamDecoderPtr response) {
    ASSERT_TRUE(response->waitForEndStream());
    EXPECT_EQ("400", response->headers().getStatusValue());
    test_server_->waitForCounter("ai_protocol_manager.schema_validation.invalid", testing::Eq(1));
  }

  envoy::extensions::filters::http::ai_protocol_manager::v3::RequestPerRoute route_request_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, SchemaValidationIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

TEST_P(SchemaValidationIntegrationTest, DetectedApiPayloadIsForwarded) {
  initializeFilters(/*with_filter_state=*/false);
  expectForwarded(sendRequest("/v1/messages", AnthropicPayload), AnthropicPayload);
  test_server_->waitForCounter("ai_protocol_manager.schema_validation.valid", testing::Eq(1));
  test_server_->waitForCounter("ai_protocol_manager.schema_validation.llm_protocol_detected",
                               testing::Eq(1));
}

TEST_P(SchemaValidationIntegrationTest, DetectedApiViolationIsRejected) {
  initializeFilters(/*with_filter_state=*/false);
  expectRejected(sendRequest("/v1/messages", R"({"model":"claude","messages":[]})"));
}

TEST_P(SchemaValidationIntegrationTest, FailOpenForwardsAViolation) {
  initializeFilters(/*with_filter_state=*/false, /*fail_open=*/true);
  const std::string payload = R"({"model":"claude","messages":[]})";
  expectForwarded(sendRequest("/v1/messages", payload), payload);
  test_server_->waitForCounter("ai_protocol_manager.schema_validation.invalid", testing::Eq(1));
}

// set_filter_state builds the core's filter state object from its enum-value name. The payload is
// valid Chat Completions, as the path would have detected, so only Anthropic rejects it.
TEST_P(SchemaValidationIntegrationTest, FilterStateNamesTheApi) {
  initializeFilters(/*with_filter_state=*/true);
  expectRejected(sendRequest("/v1/chat/completions",
                             R"({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]})",
                             "ANTHROPIC_MESSAGES"));
  EXPECT_EQ(
      test_server_->counter("ai_protocol_manager.schema_validation.llm_protocol_detected")->value(),
      0);
}

// The route names the API and no binding, so the client's path is read under the bindings Envoy
// defines for it. The body goes upstream as the client sent it.
TEST_P(SchemaValidationIntegrationTest, VertexClaudeRawPredictIsForwardedUnchanged) {
  route_request_.set_llm_protocol(envoy::type::ai::v3::ANTHROPIC_MESSAGES);
  initializeFilters(/*with_filter_state=*/false);
  expectForwarded(sendRequest(VertexClaudePath, VertexClaudePayload), VertexClaudePayload);
  test_server_->waitForCounter("ai_protocol_manager.schema_validation.valid", testing::Eq(1));
}

TEST_P(SchemaValidationIntegrationTest, MalformedVertexClaudeBodyIsRejected) {
  route_request_.set_llm_protocol(envoy::type::ai::v3::ANTHROPIC_MESSAGES);
  initializeFilters(/*with_filter_state=*/false);
  expectRejected(sendRequest(VertexClaudePath, R"({"anthropic_version":"vertex-2023-10-16",)"
                                               R"("messages":[{"role":"user","content":"hi"}]})"));
}

// The route's binding serves Gemini under a gateway prefix. Schema validation applies it, so the
// route counts no unused binding.
TEST_P(SchemaValidationIntegrationTest, PrefixedGeminiRouteBindingIsForwardedUnchanged) {
  route_request_.set_llm_protocol(envoy::type::ai::v3::GEMINI_GENERATE_CONTENT);
  route_request_.mutable_binding()->set_uri_pattern(
      "/gemini/v1beta/models/{model}:{generateContent|streamGenerateContent?alt=sse}");
  initializeFilters(/*with_filter_state=*/false);
  const std::string payload = R"({"contents":[{"role":"user","parts":[{"text":"hi"}]}]})";
  expectForwarded(
      sendRequest("/gemini/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse", payload),
      payload);
  test_server_->waitForCounter("ai_protocol_manager.schema_validation.valid", testing::Eq(1));
  EXPECT_EQ(test_server_->counter("ai_protocol_manager.route_binding_unused")->value(), 0);
}

} // namespace
} // namespace Envoy
