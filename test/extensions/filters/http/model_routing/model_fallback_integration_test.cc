#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/extensions/filters/http/ai_protocol_manager/v3/ai_protocol_manager.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"
#include "envoy/type/ai/v3/api_protocol.pb.h"

#include "source/common/tls/ssl_handshaker.h"

#include "test/integration/http_integration.h"
#include "test/integration/ssl_utility.h"
#include "test/integration/utility.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/threadsafe_singleton_injector.h"

#include "absl/strings/match.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "gtest/gtest.h"

using testing::HasSubstr;

namespace Envoy {
namespace {

// Resolves every *.lyft.com provider host to loopback. The test certificate covers *.lyft.com.
class ProviderDns : public OsSysCallsWithMockedDns {
public:
  Api::SysCallIntResult getaddrinfo(const char* node, const char* service, const addrinfo* hints,
                                    addrinfo** res) override {
    if (absl::EndsWith(node, ".lyft.com")) {
      return OsSysCallsWithMockedDns::getaddrinfo("localhost", service, hints, res);
    }
    return OsSysCallsWithMockedDns::getaddrinfo(node, service, hints, res);
  }
};

constexpr absl::string_view CentralPath =
    "/v1/projects/demo/locations/us-central1/endpoints/openapi/chat/completions";
constexpr absl::string_view EastPath =
    "/v1/projects/demo/locations/us-east1/endpoints/openapi/chat/completions";
constexpr absl::string_view AnthropicPath = "/v1/chat/completions";
constexpr absl::string_view ChatBody =
    R"({"model":"auto","messages":[{"role":"user","content":"hello"}]})";

class ModelFallbackIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                                     public HttpIntegrationTest {
public:
  ModelFallbackIntegrationTest() : HttpIntegrationTest(Http::CodecType::HTTP1, GetParam()) {
    dns_.setIpVersion(GetParam());
  }

  void TearDown() override {
    test_server_.reset();
    cleanupUpstreamAndDownstream();
    fake_upstreams_.clear();
  }

  // Upstream 0 is us-central1, upstream 1 is us-east1 and upstream 2 is the Anthropic endpoint.
  void createUpstreams() override {
    for (int i = 0; i < 3; ++i) {
      addFakeUpstream(
          Ssl::createFakeUpstreamSslContext("upstream", context_manager_, factory_context_),
          Http::CodecType::HTTP1, /*autonomous_upstream=*/false);
    }
  }

  void initializeWithPolicy(const std::string& target_ids, const std::string& fallback_on = "") {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      bootstrap.mutable_static_resources()->clear_clusters();
      TestUtility::loadFromYaml(clusterYaml(),
                                *bootstrap.mutable_static_resources()->add_clusters());
    });
    config_helper_.addConfigModifier(
        [this, target_ids, fallback_on](
            envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
                hcm) {
          auto* route = hcm.mutable_route_config()->mutable_virtual_hosts(0)->mutable_routes(0);
          route->mutable_route()->set_cluster("ai_dfp");
          // The client's credential is for the gateway, not for the providers.
          route->add_request_headers_to_remove("authorization");
          if (rewrite_openai_prefix_) {
            route->mutable_match()->set_prefix("/openai/");
            route->mutable_route()->set_prefix_rewrite("/");
          }
          // Filters are prepended, so they are added in reverse order. Config modifiers run after
          // the fake upstreams exist, so target ports are known here.
          prependHttpFilter(hcm, dfpFilterYaml());
          prependHttpFilter(hcm, routingYaml());
          if (parse_request_) {
            prependHttpFilter(hcm, R"EOF(
name: envoy.filters.http.ai_protocol_manager
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
  request_handling: {}
)EOF");
            envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManagerPerRoute
                per_route;
            per_route.mutable_request()->set_api_protocol(
                envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS);
            std::ignore =
                (*route
                      ->mutable_typed_per_filter_config())["envoy.filters.http.ai_protocol_manager"]
                    .PackFrom(per_route);
          }
          if (!target_ids.empty()) {
            prependHttpFilter(hcm, policyYaml(target_ids, fallback_on));
          }
        });
    HttpIntegrationTest::initialize();
  }

  IntegrationStreamDecoderPtr sendChatRequest(const std::string& path = "/v1/chat/completions",
                                              absl::string_view body = ChatBody) {
    codec_client_ = makeHttpConnection(lookupPort("http"));
    return codec_client_->makeRequestWithBody(
        Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                       {":path", path},
                                       {":scheme", "http"},
                                       {":authority", "gateway.example.com"},
                                       {"content-type", "application/json"},
                                       {"authorization", "Bearer client-token"}},
        std::string(body));
  }

  void waitForAttempt(int upstream) {
    ASSERT_TRUE(
        fake_upstreams_[upstream]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
    ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));
    ASSERT_TRUE(upstream_request_->waitForEndStream(*dispatcher_));
  }

  void failAttempt(const std::string& status) {
    upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", status}}, true);
    ASSERT_TRUE(fake_upstream_connection_->close());
    ASSERT_TRUE(fake_upstream_connection_->waitForDisconnect());
    fake_upstream_connection_.reset();
  }

  void succeedAttempt() {
    upstream_request_->encodeHeaders(default_response_headers_, false);
    upstream_request_->encodeData(R"({"id":"done"})", true);
  }

  std::string serverName() {
    const auto* handshaker =
        dynamic_cast<const Extensions::TransportSockets::Tls::SslHandshakerImpl*>(
            fake_upstream_connection_->connection().ssl().get());
    const char* name = SSL_get_servername(handshaker->ssl(), TLSEXT_NAMETYPE_host_name);
    return name == nullptr ? "" : name;
  }

  std::string header(absl::string_view name) {
    const auto values = upstream_request_->headers().get(Http::LowerCaseString(name));
    return values.empty() ? "" : std::string(values[0]->value().getStringView());
  }

  void expectAttempt(int upstream, absl::string_view host, absl::string_view path,
                     absl::string_view model) {
    EXPECT_EQ(absl::StrCat(host, ":", port(upstream)), upstream_request_->headers().getHostValue());
    EXPECT_EQ(path, upstream_request_->headers().getPathValue());
    EXPECT_THAT(upstream_request_->body().toString(),
                HasSubstr(absl::StrCat("\"model\":\"", model, "\"")));
    EXPECT_EQ(host, serverName());
    EXPECT_EQ("", header("authorization"));
  }

  uint32_t port(int upstream) const {
    return fake_upstreams_[upstream]->localAddress()->ip()->port();
  }

  uint64_t counter(const std::string& name) { return test_server_->counter(name)->value(); }

private:
  static void prependHttpFilter(
      envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager& hcm,
      const std::string& yaml) {
    auto* filters = hcm.mutable_http_filters();
    TestUtility::loadFromYaml(yaml, *filters->Add());
    for (int i = filters->size() - 1; i > 0; --i) {
      filters->SwapElements(i, i - 1);
    }
  }

  std::string targetYaml(absl::string_view name) const {
    const auto target = [name](absl::string_view host, uint32_t target_port,
                               absl::string_view model, absl::string_view path) {
      return absl::StrCat("{id: ", name, ", host: ", host, ", port: ", target_port,
                          ", model: ", model,
                          path.empty() ? "" : absl::StrCat(", path: \"", path, "\""), "}");
    };
    if (name == "vertex-pro") {
      return target("vertex-us-central1.lyft.com", port(0), "gemini-2.5-pro", CentralPath);
    }
    if (name == "vertex-flash") {
      return target("vertex-us-central1.lyft.com", port(0), "gemini-2.5-flash", CentralPath);
    }
    if (name == "vertex-east") {
      return target("vertex-us-east1.lyft.com", port(1), "gemini-2.5-pro", EastPath);
    }
    if (name == "anthropic") {
      return target("anthropic.lyft.com", port(2), "claude-sonnet-4-5", AnthropicPath);
    }
    if (name == "passthrough") {
      return target("anthropic.lyft.com", port(2), "claude-sonnet-4-5", "");
    }
    EXPECT_EQ("unresolvable", name);
    return target("doesnotexist.example.com", port(2), "never-used", "");
  }

  std::string policyYaml(const std::string& target_ids, const std::string& fallback_on) const {
    std::vector<std::string> targets;
    for (absl::string_view name : absl::StrSplit(target_ids, ", ")) {
      targets.push_back(targetYaml(name));
    }
    return fmt::format(R"EOF(
name: envoy.filters.http.set_metadata
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.set_metadata.v3.Config
  metadata:
  - metadata_namespace: envoy.ai.model_routing
    typed_value:
      "@type": type.googleapis.com/envoy.data.ai.v3.ModelRoutingPolicy
      targets: [{}]
      fallback_on: [{}]
      decision_id: decision-1
)EOF",
                       absl::StrJoin(targets, ", "), fallback_on);
  }

  std::string routingYaml() const {
    return fmt::format(R"EOF(
name: envoy.filters.http.model_routing
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.model_routing.v3.ModelRouting
  prefer_request_models: {}
)EOF",
                       prefer_request_models_);
  }

  // The HTTP filter and the cluster share one DNS cache, so their configurations must match.
  std::string dnsCacheYaml(absl::string_view indent) const {
    const std::string yaml = fmt::format(R"EOF(
name: ai_dns
dns_lookup_family: {}
typed_dns_resolver_config:
  name: envoy.network.dns_resolver.getaddrinfo
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.getaddrinfo.v3.GetAddrInfoDnsResolverConfig
)EOF",
                                         Network::Test::ipVersionToDnsFamily(GetParam()));
    std::vector<std::string> lines;
    for (absl::string_view line : absl::StrSplit(yaml, '\n', absl::SkipEmpty())) {
      lines.push_back(absl::StrCat(indent, line));
    }
    return absl::StrJoin(lines, "\n");
  }

  std::string dfpFilterYaml() const {
    return absl::StrCat(R"EOF(
name: envoy.filters.http.dynamic_forward_proxy
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
  allow_dynamic_host_from_filter_state: true
  dns_cache_config:
)EOF",
                        dnsCacheYaml("    "), "\n");
  }

  std::string clusterYaml() const {
    return fmt::format(
        R"EOF(
name: ai_dfp
connect_timeout: 5s
lb_policy: CLUSTER_PROVIDED
cluster_type:
  name: envoy.clusters.dynamic_forward_proxy
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
    tls_identity_from_host: true
    dns_cache_config:
{}
typed_extension_protocol_options:
  envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
    "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
    upstream_http_protocol_options:
      auto_sni: true
      auto_san_validation: true
    explicit_http_config:
      http_protocol_options: {{}}
    http_filters:
    - name: envoy.filters.http.ai_protocol_manager
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
        request_handling: {{}}
    - name: envoy.filters.http.upstream_codec
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec
transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
    common_tls_context:
      validation_context:
        trusted_ca:
          filename: {}
)EOF",
        dnsCacheYaml("      "),
        TestEnvironment::runfilesPath("test/config/integration/certs/upstreamcacert.pem"));
  }

  ProviderDns dns_;
  TestThreadsafeSingletonInjector<Api::OsSysCallsImpl> os_calls_{&dns_};

protected:
  bool rewrite_openai_prefix_{false};
  bool parse_request_{false};
  bool prefer_request_models_{false};
};

INSTANTIATE_TEST_SUITE_P(IpVersions, ModelFallbackIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// A quota error on one model falls back to another model on the same host.
TEST_P(ModelFallbackIntegrationTest, SameHostModelFallbackOnRateLimit) {
  initializeWithPolicy("vertex-pro, vertex-flash");
  auto response = sendChatRequest();

  waitForAttempt(0);
  expectAttempt(0, "vertex-us-central1.lyft.com", CentralPath, "gemini-2.5-pro");
  failAttempt("429");

  waitForAttempt(0);
  expectAttempt(0, "vertex-us-central1.lyft.com", CentralPath, "gemini-2.5-flash");
  succeedAttempt();

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ(1, counter("cluster.ai_dfp.upstream_rq_retry"));
  EXPECT_EQ(1, counter("http.config_test.model_routing.plan_created"));
}

// Each attempt reaches a different host with its own TLS identity, path and model.
TEST_P(ModelFallbackIntegrationTest, CrossRegionThenCrossProviderFallback) {
  useAccessLog("%FILTER_STATE(envoy.ai.model_route_plan:FIELD:selected_target)% "
               "%FILTER_STATE(envoy.ai.model_route_plan:FIELD:decision_id)% "
               "%UPSTREAM_REQUEST_ATTEMPT_COUNT% %REQ(authorization)%");
  initializeWithPolicy("vertex-pro, vertex-east, anthropic");
  auto response = sendChatRequest();

  waitForAttempt(0);
  expectAttempt(0, "vertex-us-central1.lyft.com", CentralPath, "gemini-2.5-pro");
  failAttempt("503");

  waitForAttempt(1);
  expectAttempt(1, "vertex-us-east1.lyft.com", EastPath, "gemini-2.5-pro");
  failAttempt("503");

  waitForAttempt(2);
  expectAttempt(2, "anthropic.lyft.com", AnthropicPath, "claude-sonnet-4-5");
  succeedAttempt();

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ(2, counter("cluster.ai_dfp.upstream_rq_retry"));
  EXPECT_EQ("anthropic decision-1 3 -", waitForAccessLog(access_log_name_));
}

// Without a policy the request is rejected rather than sent to the authority the client names.
TEST_P(ModelFallbackIntegrationTest, MissingPolicyFailsClosed) {
  useAccessLog("%RESPONSE_CODE_DETAILS%");
  initializeWithPolicy("");
  auto response = sendChatRequest();

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("503", response->headers().getStatusValue());
  EXPECT_EQ("model_routing_no_policy", waitForAccessLog(access_log_name_));
  EXPECT_EQ(1, counter("http.config_test.model_routing.no_policy"));
}

// A target without its own path receives the request path after the route rewrite.
TEST_P(ModelFallbackIntegrationTest, TargetWithoutPathKeepsTheRewrittenPath) {
  rewrite_openai_prefix_ = true;
  initializeWithPolicy("passthrough");
  auto response = sendChatRequest("/openai/v1/chat/completions");

  waitForAttempt(2);
  expectAttempt(2, "anthropic.lyft.com", "/v1/chat/completions", "claude-sonnet-4-5");
  succeedAttempt();

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("200", response->headers().getStatusValue());
}

// A target whose host does not resolve gets no attempt.
TEST_P(ModelFallbackIntegrationTest, UnresolvableTargetSkipped) {
  initializeWithPolicy("unresolvable, vertex-pro");
  auto response = sendChatRequest();

  waitForAttempt(0);
  expectAttempt(0, "vertex-us-central1.lyft.com", CentralPath, "gemini-2.5-pro");
  succeedAttempt();

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ(0, counter("cluster.ai_dfp.upstream_rq_retry"));
}

// The dynamic forward proxy filter resolves every target first and limits the retries to the
// targets that resolved, so the client gets the last provider's error rather than a local reply.
TEST_P(ModelFallbackIntegrationTest, UnresolvableTargetLeavesNoExtraRetry) {
  initializeWithPolicy("vertex-pro, unresolvable, vertex-east");
  auto response = sendChatRequest();

  waitForAttempt(0);
  failAttempt("429");

  waitForAttempt(1);
  expectAttempt(1, "vertex-us-east1.lyft.com", EastPath, "gemini-2.5-pro");
  failAttempt("429");

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("429", response->headers().getStatusValue());
  EXPECT_EQ(1, counter("cluster.ai_dfp.upstream_rq_retry"));
}

// A client error is not a fallback condition, so the provider response is returned as is.
TEST_P(ModelFallbackIntegrationTest, NonRetriableResponseStopsFallback) {
  initializeWithPolicy("vertex-pro, anthropic");
  auto response = sendChatRequest();

  waitForAttempt(0);
  failAttempt("400");

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("400", response->headers().getStatusValue());
  EXPECT_EQ(0, counter("cluster.ai_dfp.upstream_rq_retry"));
  FakeHttpConnectionPtr unexpected;
  EXPECT_FALSE(fake_upstreams_[2]->waitForHttpConnection(*dispatcher_, unexpected,
                                                         std::chrono::milliseconds(100)));
}

// When every target fails, the last provider's error reaches the client.
TEST_P(ModelFallbackIntegrationTest, ExhaustedPlanReturnsLastProviderError) {
  initializeWithPolicy("vertex-pro, anthropic");
  auto response = sendChatRequest();

  waitForAttempt(0);
  failAttempt("503");
  waitForAttempt(2);
  failAttempt("529");

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("529", response->headers().getStatusValue());
  EXPECT_EQ(1, counter("cluster.ai_dfp.upstream_rq_retry"));
}

// The policy's fallback conditions replace the defaults.
TEST_P(ModelFallbackIntegrationTest, PolicyFallbackConditionsReplaceDefaults) {
  initializeWithPolicy("vertex-pro, anthropic", "SERVER_ERROR");
  auto response = sendChatRequest();

  waitForAttempt(0);
  failAttempt("429");

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("429", response->headers().getStatusValue());
  EXPECT_EQ(0, counter("cluster.ai_dfp.upstream_rq_retry"));
}

// The models the client lists, as parsed by the AI protocol manager, reorder the policy.
TEST_P(ModelFallbackIntegrationTest, RequestModelsReorderThePolicy) {
  parse_request_ = true;
  prefer_request_models_ = true;
  initializeWithPolicy("vertex-pro, anthropic");
  auto response = sendChatRequest(
      "/v1/chat/completions",
      R"({"model":"auto","models":["claude-sonnet-4-5","gemini-2.5-pro"],"messages":[{"role":"user","content":"hello"}]})");

  waitForAttempt(2);
  expectAttempt(2, "anthropic.lyft.com", AnthropicPath, "claude-sonnet-4-5");
  failAttempt("429");

  waitForAttempt(0);
  expectAttempt(0, "vertex-us-central1.lyft.com", CentralPath, "gemini-2.5-pro");
  succeedAttempt();

  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_EQ(1, counter("cluster.ai_dfp.upstream_rq_retry"));
}

} // namespace
} // namespace Envoy
