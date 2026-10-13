#include <string>

#include "envoy/data/ai/v3/token_usage.pb.h"
#include "envoy/extensions/filters/http/ai_protocol_manager/v3/ai_protocol_manager.pb.h"
#include "envoy/extensions/filters/http/ext_proc/v3/ext_proc.pb.h"
#include "envoy/service/ext_proc/v3/external_processor.pb.h"

#include "test/extensions/filters/http/ext_proc/test_processor.h"
#include "test/integration/http_integration.h"
#include "test/test_common/simulated_time_system.h"

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/notification.h"

namespace Envoy {
namespace {

using UsageRecord = envoy::data::ai::v3::TokenUsage;

constexpr absl::string_view TokenUsageFilter = R"EOF(
  - name: envoy.http.ai_filters.token_usage
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.http.ai_filters.token_usage.v3.TokenUsage
)EOF";

// The leg next to the backend, which converts the backend's response into the IR.
constexpr absl::string_view BackendLeg = R"EOF(
  - name: envoy.http.ai_filters.transcoder
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.http.ai_filters.transcoder.v3.Transcoder
      request_handling: FROM_IR
      response_handling: TO_IR
)EOF";

std::string aiProtocolManager(absl::string_view ai_filters) {
  return absl::StrCat(R"EOF(
name: envoy.filters.http.ai_protocol_manager
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
  request_handling: {}
  filters:)EOF",
                      ai_filters);
}

// Declares the route an AI endpoint: an OpenAI Chat Completions client of a `backend`.
void declareRoute(ConfigHelper& config_helper, envoy::type::ai::v3::LLMProtocol backend) {
  config_helper.addConfigModifier([backend](ConfigHelper::HttpConnectionManager& hcm) {
    envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManagerPerRoute per_route;
    per_route.mutable_request()->set_llm_protocol(envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS);
    per_route.mutable_response()->set_llm_protocol(backend);
    auto* route = hcm.mutable_route_config()->mutable_virtual_hosts(0)->mutable_routes(0);
    std::ignore =
        (*route->mutable_typed_per_filter_config())["envoy.filters.http.ai_protocol_manager"]
            .PackFrom(per_route);
  });
}

Http::TestRequestHeaderMapImpl requestHeaders() {
  return Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                        {":path", "/v1/chat/completions"},
                                        {":scheme", "http"},
                                        {":authority", "sni.lyft.com"},
                                        {"content-type", "application/json"}};
}

constexpr absl::string_view RequestBody =
    R"({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":16})";

constexpr absl::string_view JsonUsageBody =
    R"({"choices":[{"finish_reason":"stop","index":0,"message":{"content":"Hi","role":"assistant"}}],)"
    R"("model":"gpt-4o","object":"chat.completion",)"
    R"("usage":{"completion_tokens":7,"prompt_tokens":5,"total_tokens":12}})";

uint64_t sumCounters(IntegrationTestServer& server, absl::string_view suffix) {
  uint64_t total = 0;
  for (const auto& counter : server.counters()) {
    if (absl::EndsWith(counter->name(), suffix)) {
      total += counter->value();
    }
  }
  return total;
}

// The token usage record reaches an external processor through typed namespace forwarding, in
// the message that ends the response. ext_proc is listed first, so on the encode path it runs
// after the AI Protocol Manager in the downstream chain, and after every upstream filter.
class TokenUsageIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                  public HttpIntegrationTest {
public:
  TokenUsageIntegrationTest() : HttpIntegrationTest(Http::CodecType::HTTP2, GetParam()) {}

  void SetUp() override {
    setDownstreamProtocol(Http::CodecType::HTTP2);
    // Upstream HTTP filters need the cluster's upstream protocol options.
    setUpstreamProtocol(Http::CodecType::HTTP2);
  }

  void TearDown() override {
    cleanupUpstreamAndDownstream();
    test_processor_.shutdown();
  }

  void initializeWithExtProc(
      absl::string_view ai_filters, bool upstream_filter,
      envoy::type::ai::v3::LLMProtocol backend = envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS) {
    test_processor_.start(
        GetParam(),
        [this](grpc::ServerReaderWriter<envoy::service::ext_proc::v3::ProcessingResponse,
                                        envoy::service::ext_proc::v3::ProcessingRequest>* stream) {
          envoy::service::ext_proc::v3::ProcessingRequest request;
          while (stream->Read(&request)) {
            if (!request.has_response_body() || !request.response_body().end_of_stream() ||
                record_seen_.HasBeenNotified()) {
              continue;
            }
            const auto& typed_metadata = request.metadata_context().typed_filter_metadata();
            const auto entry = typed_metadata.find("envoy.ai.token_usage");
            if (entry != typed_metadata.end()) {
              ASSERT_TRUE(entry->second.UnpackTo(&record_));
              record_seen_.Notify();
            }
          }
        });

    config_helper_.prependFilter(aiProtocolManager(ai_filters), /*downstream=*/!upstream_filter);
    declareRoute(config_helper_, backend);
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* processor_cluster = bootstrap.mutable_static_resources()->add_clusters();
      processor_cluster->set_name("ext_proc_server");
      processor_cluster->mutable_load_assignment()->set_cluster_name("ext_proc_server");
      auto* address = processor_cluster->mutable_load_assignment()
                          ->add_endpoints()
                          ->add_lb_endpoints()
                          ->mutable_endpoint()
                          ->mutable_address()
                          ->mutable_socket_address();
      address->set_address(Network::Test::getLoopbackAddressString(GetParam()));
      address->set_port_value(test_processor_.port());
      ConfigHelper::setHttp2(*processor_cluster);

      envoy::extensions::filters::http::ext_proc::v3::ExternalProcessor ext_proc;
      ext_proc.mutable_grpc_service()->mutable_envoy_grpc()->set_cluster_name("ext_proc_server");
      ext_proc.set_observability_mode(true);
      ext_proc.mutable_processing_mode()->set_request_header_mode(
          envoy::extensions::filters::http::ext_proc::v3::ProcessingMode::SKIP);
      ext_proc.mutable_processing_mode()->set_response_header_mode(
          envoy::extensions::filters::http::ext_proc::v3::ProcessingMode::SKIP);
      ext_proc.mutable_processing_mode()->set_response_body_mode(
          envoy::extensions::filters::http::ext_proc::v3::ProcessingMode::STREAMED);
      ext_proc.mutable_metadata_options()->mutable_forwarding_namespaces()->add_typed(
          "envoy.ai.token_usage");
      envoy::config::listener::v3::Filter ext_proc_filter;
      ext_proc_filter.set_name("envoy.filters.http.ext_proc");
      std::ignore = ext_proc_filter.mutable_typed_config()->PackFrom(ext_proc);
      config_helper_.prependFilter(MessageUtil::getJsonStringFromMessageOrError(ext_proc_filter));
    });
    initialize();
  }

  // Sends the request, answers it with `body`, and returns what reaches the client.
  std::string exchange(absl::string_view content_type, absl::string_view body) {
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeRequestWithBody(requestHeaders(), std::string(RequestBody));
    waitForNextUpstreamRequest();
    upstream_request_->encodeHeaders(
        Http::TestResponseHeaderMapImpl{{":status", "200"},
                                        {"content-type", std::string(content_type)}},
        false);
    upstream_request_->encodeData(std::string(body), true);
    EXPECT_TRUE(response->waitForEndStream());
    EXPECT_TRUE(response->complete());
    EXPECT_EQ("200", response->headers().getStatusValue());
    return response->body();
  }

  Extensions::HttpFilters::ExternalProcessing::TestProcessor test_processor_;
  absl::Notification record_seen_;
  UsageRecord record_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, TokenUsageIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

TEST_P(TokenUsageIntegrationTest, PublishesTheUsageOfAnIrResponse) {
  initializeWithExtProc(TokenUsageFilter, /*upstream_filter=*/false);
  EXPECT_EQ(exchange("application/json", JsonUsageBody), JsonUsageBody);

  ASSERT_TRUE(record_seen_.WaitForNotificationWithTimeout(absl::Seconds(5)));
  EXPECT_EQ(record_.llm_protocol(), envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS);
  EXPECT_EQ(record_.input_tokens().value(), 5);
  EXPECT_EQ(record_.output_tokens().value(), 7);
  EXPECT_EQ(record_.total_tokens().value(), 12);
  EXPECT_EQ(record_.extraction_status(), UsageRecord::COMPLETE);
}

// Installed on the cluster, the filter publishes to the downstream request's stream info.
TEST_P(TokenUsageIntegrationTest, PublishesFromTheUpstreamFilterChain) {
  initializeWithExtProc(TokenUsageFilter, /*upstream_filter=*/true);
  EXPECT_EQ(exchange("application/json", JsonUsageBody), JsonUsageBody);

  ASSERT_TRUE(record_seen_.WaitForNotificationWithTimeout(absl::Seconds(5)));
  EXPECT_EQ(record_.input_tokens().value(), 5);
  EXPECT_EQ(record_.output_tokens().value(), 7);
}

// Between the transcoder legs, the filter publishes the usage Anthropic reported, cache buckets
// and served model included, and the client's stream carries none of it.
TEST_P(TokenUsageIntegrationTest, PublishesTheRecordOfATranscodedStream) {
  initializeWithExtProc(absl::StrCat(TokenUsageFilter, BackendLeg), /*upstream_filter=*/false,
                        envoy::type::ai::v3::ANTHROPIC_MESSAGES);
  const std::string body = exchange(
      "text/event-stream",
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
      "\n\n");
  EXPECT_THAT(body, testing::HasSubstr("chat.completion.chunk"));
  EXPECT_THAT(body, testing::Not(testing::HasSubstr("_envoy")));

  ASSERT_TRUE(record_seen_.WaitForNotificationWithTimeout(absl::Seconds(5)));
  EXPECT_EQ(record_.llm_protocol(), envoy::type::ai::v3::ANTHROPIC_MESSAGES);
  EXPECT_EQ(record_.model(), "claude-sonnet-4-5-20250929");
  EXPECT_EQ(record_.input_tokens().value(), 1030);
  EXPECT_EQ(record_.output_tokens().value(), 5);
  EXPECT_EQ(record_.input_token_details().cached_tokens().value(), 1000);
  EXPECT_EQ(record_.input_token_details().cache_creation_tokens().value(), 20);
  EXPECT_EQ(record_.extraction_status(), UsageRecord::COMPLETE);
}

// The filter in both chains publishes once: the upstream instance runs first and owns the
// namespace.
class TokenUsagePlacementIntegrationTest
    : public testing::TestWithParam<Network::Address::IpVersion>,
      public HttpIntegrationTest {
public:
  TokenUsagePlacementIntegrationTest() : HttpIntegrationTest(Http::CodecType::HTTP2, GetParam()) {}

  void SetUp() override {
    setDownstreamProtocol(Http::CodecType::HTTP2);
    setUpstreamProtocol(Http::CodecType::HTTP2);
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, TokenUsagePlacementIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

TEST_P(TokenUsagePlacementIntegrationTest, BothPlacementsPublishOnce) {
  config_helper_.prependFilter(aiProtocolManager(TokenUsageFilter), /*downstream=*/false);
  config_helper_.prependFilter(aiProtocolManager(TokenUsageFilter), /*downstream=*/true);
  declareRoute(config_helper_, envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS);
  initialize();

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(requestHeaders(), std::string(RequestBody));
  waitForNextUpstreamRequest();
  upstream_request_->encodeHeaders(
      Http::TestResponseHeaderMapImpl{{":status", "200"}, {"content-type", "application/json"}},
      false);
  upstream_request_->encodeData(std::string(JsonUsageBody), true);
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(response->complete());

  EXPECT_EQ(sumCounters(*test_server_, "ai_protocol_manager.token_usage.found"), 1);
  EXPECT_EQ(sumCounters(*test_server_, "ai_protocol_manager.token_usage.duplicate"), 1);
}

// Each retry runs its own upstream filter instances, but only the attempt the router keeps ends
// cleanly, so only it publishes. The failed attempt is a 5xx, which no AI filter sees.
TEST_P(TokenUsagePlacementIntegrationTest, RetryPublishesTheWinningAttemptOnly) {
  config_helper_.addConfigModifier([](ConfigHelper::HttpConnectionManager& hcm) {
    auto* retry_policy = hcm.mutable_route_config()
                             ->mutable_virtual_hosts(0)
                             ->mutable_routes(0)
                             ->mutable_route()
                             ->mutable_retry_policy();
    retry_policy->set_retry_on("5xx");
    retry_policy->mutable_num_retries()->set_value(1);
  });
  config_helper_.prependFilter(aiProtocolManager(TokenUsageFilter), /*downstream=*/false);
  declareRoute(config_helper_, envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS);
  initialize();

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeRequestWithBody(requestHeaders(), std::string(RequestBody));
  waitForNextUpstreamRequest();
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "503"}}, true);

  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  upstream_request_->encodeHeaders(
      Http::TestResponseHeaderMapImpl{{":status", "200"}, {"content-type", "application/json"}},
      false);
  upstream_request_->encodeData(std::string(JsonUsageBody), true);
  ASSERT_TRUE(response->waitForEndStream());
  ASSERT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().getStatusValue());

  EXPECT_EQ(sumCounters(*test_server_, "ai_protocol_manager.token_usage.found"), 1);
  EXPECT_EQ(sumCounters(*test_server_, "ai_protocol_manager.token_usage.duplicate"), 0);
}

// Hedged attempts run concurrently, each with its own upstream filter instances. The router resets
// the attempt it does not keep, so that instance never reaches the end of its response.
class TokenUsageHedgeIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                       public Event::TestUsingSimulatedTime,
                                       public HttpIntegrationTest {
public:
  TokenUsageHedgeIntegrationTest() : HttpIntegrationTest(Http::CodecType::HTTP2, GetParam()) {}

  void SetUp() override {
    setDownstreamProtocol(Http::CodecType::HTTP2);
    setUpstreamProtocol(Http::CodecType::HTTP2);
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, TokenUsageHedgeIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

TEST_P(TokenUsageHedgeIntegrationTest, HedgedRequestPublishesTheWinnerOnly) {
  config_helper_.prependFilter(aiProtocolManager(TokenUsageFilter), /*downstream=*/false);
  declareRoute(config_helper_, envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS);
  initialize();

  codec_client_ = makeHttpConnection(makeClientConnection(lookupPort("http")));
  Http::TestRequestHeaderMapImpl headers = requestHeaders();
  // Marks the request internal, so the x-envoy-* timeout and hedge headers are honored.
  headers.addCopy("x-forwarded-for", "10.0.0.1");
  headers.addCopy("x-envoy-retry-on", "5xx");
  headers.addCopy("x-envoy-hedge-on-per-try-timeout", "true");
  headers.addCopy("x-envoy-upstream-rq-timeout-ms", "5000");
  headers.addCopy("x-envoy-upstream-rq-per-try-timeout-ms", "400");
  auto response = codec_client_->makeRequestWithBody(headers, std::string(RequestBody));

  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
  ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));

  // The per-try timeout fires, the first attempt stays alive, and the hedged second attempt goes
  // out after the 25ms retry backoff.
  timeSystem().advanceTimeWait(std::chrono::milliseconds(400));
  timeSystem().advanceTimeWait(std::chrono::milliseconds(26));

  FakeStreamPtr upstream_request2;
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request2));
  ASSERT_TRUE(upstream_request2->waitForEndStream(*dispatcher_));
  upstream_request2->encodeHeaders(
      Http::TestResponseHeaderMapImpl{{":status", "200"}, {"content-type", "application/json"}},
      false);
  upstream_request2->encodeData(std::string(JsonUsageBody), true);
  ASSERT_TRUE(response->waitForEndStream());

  ASSERT_TRUE(upstream_request_->waitForReset(std::chrono::seconds(15)));
  codec_client_->close();

  EXPECT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ(sumCounters(*test_server_, "ai_protocol_manager.token_usage.found"), 1);
}

} // namespace
} // namespace Envoy
