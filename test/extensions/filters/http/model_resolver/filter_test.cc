#include "envoy/config/core/v3/base.pb.h"
#include "envoy/data/ai/v3/model_routing_policy.pb.h"

#include "source/common/stats/isolated_store_impl.h"
#include "source/extensions/filters/http/model_resolver/filter.h"

#include "test/extensions/common/dynamic_forward_proxy/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/mocks/upstream/basic_resource_limit.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::Return;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelResolver {
namespace {

constexpr absl::string_view BaseConfig = R"EOF(
client_api_protocol: OPENAI_CHAT_COMPLETIONS
max_retries: 2
max_per_try_timeout: 5s
targets:
  a: {host: a.example.com, model: model-a}
  b: {host: b.example.com, port: 8443, model: model-b, path: "/v1/models/{model}"}
  c: {host: c.example.com, model: model-c}
  d: {host: d.example.com, model: model-d, api_protocol: ANTHROPIC_MESSAGES}
)EOF";

class TestDnsCacheManagerFactory : public DfpCommon::DnsCacheManagerFactory {
public:
  DfpCommon::DnsCacheManagerSharedPtr get() override { return manager_; }

  std::shared_ptr<NiceMock<DfpCommon::MockDnsCacheManager>> manager_{
      std::make_shared<NiceMock<DfpCommon::MockDnsCacheManager>>()};
};

class ModelResolverFilterTest : public testing::Test {
protected:
  absl::StatusOr<FilterConfigConstSharedPtr> createConfig(absl::string_view extra_config) {
    ModelResolverProto proto;
    TestUtility::loadFromYaml(absl::StrCat(BaseConfig, extra_config), proto);
    return FilterConfig::create(proto, "test.", *stats_.rootScope(), context_,
                                context_.initManager(), dns_cache_manager_factory_);
  }

  void initialize(absl::string_view extra_config = "") {
    auto config = createConfig(extra_config);
    ASSERT_TRUE(config.ok()) << config.status();
    filter_ = std::make_unique<ModelResolverFilter>(config.value());
    filter_->setDecoderFilterCallbacks(callbacks_);
  }

  void setTypedPolicy(const ModelRoutingPolicy& policy) {
    std::ignore = (*callbacks_.stream_info_.metadata_
                        .mutable_typed_filter_metadata())["envoy.ai.model_routing"]
                      .PackFrom(policy);
  }

  void setTypedPolicy(const std::string& yaml) {
    ModelRoutingPolicy policy;
    TestUtility::loadFromYaml(yaml, policy);
    setTypedPolicy(policy);
  }

  void setStructPolicy(const std::string& json) {
    Protobuf::Struct policy;
    MessageUtil::loadFromJson(json, policy);
    (*callbacks_.stream_info_.metadata_.mutable_filter_metadata())["envoy.ai.model_routing"] =
        policy;
  }

  const AiCommon::ModelRoutePlan* plan() {
    return callbacks_.stream_info_.filterState()->getDataReadOnly<AiCommon::ModelRoutePlan>(
        AiCommon::ModelRoutePlan::key());
  }

  uint64_t counter(absl::string_view name) {
    return TestUtility::findCounter(stats_, absl::StrCat("test.model_resolver.", name))->value();
  }

  DfpCommon::MockDnsCache& dnsCache() { return *dns_cache_manager_factory_.manager_->dns_cache_; }

  NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  Stats::IsolatedStoreImpl stats_;
  TestDnsCacheManagerFactory dns_cache_manager_factory_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks_;
  std::unique_ptr<ModelResolverFilter> filter_;
  Http::TestRequestHeaderMapImpl headers_{{":method", "POST"},
                                          {":path", "/v1/chat/completions"},
                                          {":authority", "gateway"},
                                          {"content-type", "application/json"}};
};

TEST_F(ModelResolverFilterTest, TypedPolicyBuildsPlanAndEnablesRetries) {
  initialize();
  setTypedPolicy("{target_ids: [a, b, c], decision_id: d-1}");

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("a,b,c", plan()->serializeAsString().value());
  EXPECT_EQ("d-1", plan()->decisionId());
  // Recorded by the upstream filter, after route rewrites.
  EXPECT_FALSE(plan()->canonicalPath().has_value());
  // The same object is the dynamic forward proxy host candidate list.
  EXPECT_EQ(
      plan(),
      callbacks_.stream_info_.filterState()->getDataReadOnly<DfpCommon::DynamicHostCandidates>(
          DfpCommon::DynamicHostCandidates::key()));

  EXPECT_EQ("connect-failure,retriable-status-codes,gateway-error",
            headers_.get_("x-envoy-retry-on"));
  EXPECT_EQ("429,503,529", headers_.get_("x-envoy-retriable-status-codes"));
  EXPECT_EQ("2", headers_.get_("x-envoy-max-retries"));
  EXPECT_EQ("false", headers_.get_("x-envoy-hedge-on-per-try-timeout"));
  EXPECT_FALSE(headers_.has("x-envoy-upstream-rq-per-try-timeout-ms"));
  EXPECT_EQ(1, counter("plan_created"));
}

TEST_F(ModelResolverFilterTest, StructPolicyConditionsAndPerTryTimeout) {
  initialize();
  setStructPolicy(
      R"({"target_ids":["a","b","c","a"],"fallback_on":["RESET","SERVER_ERROR"],"per_try_timeout":"9s"})");

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("a,b,c,a", plan()->serializeAsString().value());
  EXPECT_EQ("reset,5xx", headers_.get_("x-envoy-retry-on"));
  EXPECT_FALSE(headers_.has("x-envoy-retriable-status-codes"));
  // Capped by max_retries.
  EXPECT_EQ("2", headers_.get_("x-envoy-max-retries"));
  // Capped by max_per_try_timeout.
  EXPECT_EQ("5000", headers_.get_("x-envoy-upstream-rq-per-try-timeout-ms"));
}

TEST_F(ModelResolverFilterTest, StructPolicyWithUnknownFields) {
  initialize();
  setStructPolicy(R"({"target_ids":["a","b"],"reason":"quota"})");

  filter_->decodeHeaders(headers_, false);
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("a,b", plan()->serializeAsString().value());
}

TEST_F(ModelResolverFilterTest, SingleTargetDisablesRouteRetries) {
  initialize();
  setTypedPolicy("{target_ids: [b], per_try_timeout: 2s}");

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
  EXPECT_FALSE(headers_.has("x-envoy-retry-on"));
  EXPECT_EQ("0", headers_.get_("x-envoy-max-retries"));
  EXPECT_EQ("2000", headers_.get_("x-envoy-upstream-rq-per-try-timeout-ms"));
}

TEST_F(ModelResolverFilterTest, ZeroPerTryTimeoutIgnored) {
  initialize();
  ModelRoutingPolicy policy;
  policy.add_target_ids("a");
  policy.mutable_per_try_timeout();
  setTypedPolicy(policy);

  filter_->decodeHeaders(headers_, false);
  ASSERT_NE(nullptr, plan());
  EXPECT_FALSE(headers_.has("x-envoy-upstream-rq-per-try-timeout-ms"));
}

TEST_F(ModelResolverFilterTest, PerTryTimeoutIgnoredWithoutUpperBound) {
  ModelResolverProto proto;
  TestUtility::loadFromYaml(std::string(BaseConfig), proto);
  proto.clear_max_per_try_timeout();
  auto config = FilterConfig::create(proto, "test.", *stats_.rootScope(), context_,
                                     context_.initManager(), dns_cache_manager_factory_);
  ASSERT_TRUE(config.ok());
  filter_ = std::make_unique<ModelResolverFilter>(config.value());
  filter_->setDecoderFilterCallbacks(callbacks_);
  setTypedPolicy("{target_ids: [a], per_try_timeout: 2s}");

  filter_->decodeHeaders(headers_, false);
  EXPECT_FALSE(headers_.has("x-envoy-upstream-rq-per-try-timeout-ms"));
}

TEST_F(ModelResolverFilterTest, UnknownAndIncompatibleTargetsAreDropped) {
  initialize();
  setTypedPolicy("{target_ids: [missing, d, c]}");

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("c", plan()->serializeAsString().value());
  EXPECT_EQ(1, counter("unknown_target"));
  EXPECT_EQ(1, counter("incompatible_target"));
}

TEST_F(ModelResolverFilterTest, MissingPolicyRejectedByDefault) {
  initialize();
  EXPECT_CALL(callbacks_,
              sendLocalReply(Http::Code::ServiceUnavailable, "", _, _, "model_resolver_no_policy"));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(1, counter("no_policy"));
}

TEST_F(ModelResolverFilterTest, MissingPolicyContinuesWhenAllowed) {
  initialize("continue_without_policy: true\n");
  EXPECT_CALL(callbacks_, sendLocalReply(_, _, _, _, _)).Times(0);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_FALSE(headers_.has("x-envoy-retry-on"));
  EXPECT_EQ(1, counter("no_policy"));
}

TEST_F(ModelResolverFilterTest, PolicyWithoutUsableTargetRejected) {
  initialize();
  setTypedPolicy("{target_ids: [missing, d]}");
  EXPECT_CALL(callbacks_, sendLocalReply(Http::Code::ServiceUnavailable, "", _, _,
                                         "model_resolver_invalid_policy"));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(1, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, BodyTheUpstreamFilterCannotRewrite) {
  initialize();
  setTypedPolicy("{target_ids: [a, b]}");
  EXPECT_CALL(callbacks_, sendLocalReply(Http::Code::ServiceUnavailable, "", _, _,
                                         "model_resolver_unsupported_body"))
      .Times(2);

  headers_.setContentType("multipart/form-data; boundary=x");
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers_, false));

  headers_.setContentType("application/json; charset=utf-8");
  headers_.addCopy(Http::LowerCaseString("content-encoding"), "gzip");
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(2, counter("unsupported_body"));
}

TEST_F(ModelResolverFilterTest, IdentityEncodedJsonAndHeadersOnlyRequests) {
  initialize();
  setTypedPolicy("{target_ids: [a]}");
  headers_.setContentType("application/vnd.api+json");
  headers_.addCopy(Http::LowerCaseString("content-encoding"), "identity");
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));

  Http::TestRequestHeaderMapImpl headers_only{{":method", "GET"}, {":path", "/v1/models"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_only, true));
  EXPECT_EQ(2, counter("plan_created"));
}

TEST_F(ModelResolverFilterTest, TypedMetadataOfAnotherType) {
  initialize("continue_without_policy: true\n");
  envoy::config::core::v3::Metadata other;
  std::ignore =
      (*callbacks_.stream_info_.metadata_.mutable_typed_filter_metadata())["envoy.ai.model_routing"]
          .PackFrom(other);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(1, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, StructPolicyWithWrongShape) {
  initialize("continue_without_policy: true\n");
  setStructPolicy(R"({"target_ids":[{"id":"a"}]})");
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(1, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, PolicyOutOfBounds) {
  initialize("continue_without_policy: true\n");
  ModelRoutingPolicy policy;
  for (int i = 0; i < 17; ++i) {
    policy.add_target_ids("a");
  }
  setTypedPolicy(policy);
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(nullptr, plan());

  policy.Clear();
  policy.add_target_ids("");
  setTypedPolicy(policy);
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(nullptr, plan());

  policy.Clear();
  policy.add_target_ids("a");
  policy.add_fallback_on(ModelRoutingPolicy::FALLBACK_CONDITION_UNSPECIFIED);
  setTypedPolicy(policy);
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(3, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, CustomPolicyNamespaceAndDefaults) {
  initialize("policy_metadata_namespace: pdp.decision\ndefault_fallback_on: [RESET]\n");
  ModelRoutingPolicy policy;
  policy.add_target_ids("a");
  policy.add_target_ids("b");
  std::ignore =
      (*callbacks_.stream_info_.metadata_.mutable_typed_filter_metadata())["pdp.decision"].PackFrom(
          policy);

  filter_->decodeHeaders(headers_, false);
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("reset", headers_.get_("x-envoy-retry-on"));
  EXPECT_EQ("1", headers_.get_("x-envoy-max-retries"));
}

TEST_F(ModelResolverFilterTest, PrewarmsFallbackHosts) {
  initialize("dns_cache_config: {name: ai}\nprewarm_fallback_targets: 2\n");
  setTypedPolicy("{target_ids: [a, b, c]}");
  NiceMock<Upstream::MockBasicResourceLimit> pending_requests;
  EXPECT_CALL(dnsCache(), canCreateDnsRequest_()).Times(2).WillRepeatedly(testing::Invoke([&]() {
    return new Upstream::ResourceAutoIncDec(pending_requests);
  }));
  auto* handle = new NiceMock<DfpCommon::MockLoadDnsCacheEntryHandle>();
  EXPECT_CALL(*handle, onDestroy());
  EXPECT_CALL(dnsCache(), loadDnsCacheEntry_("b.example.com", 8443, false, _))
      .WillOnce(Return(DfpCommon::MockDnsCache::MockLoadDnsCacheEntryResult{
          DfpCommon::DnsCache::LoadDnsCacheEntryStatus::Loading, handle, std::nullopt}));
  // Targets without a port use the TLS default.
  EXPECT_CALL(dnsCache(), loadDnsCacheEntry_("c.example.com", 443, false, _))
      .WillOnce(Return(DfpCommon::MockDnsCache::MockLoadDnsCacheEntryResult{
          DfpCommon::DnsCache::LoadDnsCacheEntryStatus::InCache, nullptr, std::nullopt}));

  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(1, counter("prewarm_started"));
}

TEST_F(ModelResolverFilterTest, PrewarmStopsAtTheDnsCacheCircuitBreaker) {
  initialize("dns_cache_config: {name: ai}\nprewarm_fallback_targets: 2\n");
  setTypedPolicy("{target_ids: [a, b, c]}");
  EXPECT_CALL(dnsCache(), canCreateDnsRequest_()).WillOnce(Return(nullptr));
  EXPECT_CALL(dnsCache(), loadDnsCacheEntry_(_, _, _, _)).Times(0);

  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(1, counter("prewarm_overflow"));
  EXPECT_EQ(0, counter("prewarm_started"));
}

TEST_F(ModelResolverFilterTest, NoPrewarmWithoutDnsCache) {
  initialize("prewarm_fallback_targets: 2\n");
  setTypedPolicy("{target_ids: [a, b, c]}");
  EXPECT_CALL(dnsCache(), canCreateDnsRequest_()).Times(0);
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(0, counter("prewarm_started"));
}

TEST_F(ModelResolverFilterTest, InvalidDefaultFallbackCondition) {
  EXPECT_FALSE(createConfig("default_fallback_on: [0]\n").ok());
}

TEST_F(ModelResolverFilterTest, InvalidTargetHostRejected) {
  EXPECT_FALSE(createConfig("  e: {host: \"e.example.com:443\", model: model-e}\n").ok());
  EXPECT_FALSE(createConfig("  e: {host: \"2001:db8::1\", model: model-e}\n").ok());
  EXPECT_TRUE(createConfig("  e: {host: \"[2001:db8::1]\", model: model-e}\n").ok());
}

TEST_F(ModelResolverFilterTest, UnknownStaticSecretRejected) {
  const auto config = createConfig(R"EOF(
  e:
    host: e.example.com
    model: model-e
    credential:
      header_name: x-api-key
      generic_secret: {name: missing-secret}
)EOF");
  EXPECT_FALSE(config.ok());
}

} // namespace
} // namespace ModelResolver
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
