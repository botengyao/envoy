#include "envoy/config/core/v3/base.pb.h"
#include "envoy/data/ai/v3/model_routing_policy.pb.h"

#include "source/common/stats/isolated_store_impl.h"
#include "source/extensions/filters/http/model_resolver/filter.h"

#include "test/mocks/http/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;

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

class ModelResolverFilterTest : public testing::Test {
protected:
  void initialize(absl::string_view extra_config = "") {
    ModelResolverProto proto;
    TestUtility::loadFromYaml(absl::StrCat(BaseConfig, extra_config), proto);
    auto config =
        FilterConfig::create(proto, "test.", *stats_.rootScope(), context_, context_.initManager());
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

  NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  Stats::IsolatedStoreImpl stats_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks_;
  std::unique_ptr<ModelResolverFilter> filter_;
  Http::TestRequestHeaderMapImpl headers_{
      {":method", "POST"}, {":path", "/v1/chat/completions"}, {":authority", "gateway"}};
};

TEST_F(ModelResolverFilterTest, TypedPolicyBuildsPlanAndEnablesRetries) {
  initialize();
  setTypedPolicy("{target_ids: [a, b, c], decision_id: d-1}");

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("a,b,c", plan()->serializeAsString().value());
  EXPECT_EQ("d-1", plan()->decisionId());
  EXPECT_EQ("/v1/chat/completions", plan()->canonicalPath());
  // The same object is the dynamic forward proxy host candidate list.
  EXPECT_EQ(
      plan(),
      callbacks_.stream_info_.filterState()->getDataReadOnly<DfpCommon::DynamicHostCandidates>(
          DfpCommon::DynamicHostCandidates::key()));

  EXPECT_EQ("connect-failure,retriable-status-codes,gateway-error",
            headers_.get_("x-envoy-retry-on"));
  EXPECT_EQ("429,503,529", headers_.get_("x-envoy-retriable-status-codes"));
  EXPECT_EQ("2", headers_.get_("x-envoy-max-retries"));
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

TEST_F(ModelResolverFilterTest, SingleTargetLeavesRetriesToTheRoute) {
  initialize();
  setTypedPolicy("{target_ids: [b], per_try_timeout: 2s}");

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
  EXPECT_FALSE(headers_.has("x-envoy-retry-on"));
  EXPECT_FALSE(headers_.has("x-envoy-max-retries"));
  EXPECT_EQ("2000", headers_.get_("x-envoy-upstream-rq-per-try-timeout-ms"));
}

TEST_F(ModelResolverFilterTest, PerTryTimeoutIgnoredWithoutUpperBound) {
  ModelResolverProto proto;
  TestUtility::loadFromYaml(std::string(BaseConfig), proto);
  proto.clear_max_per_try_timeout();
  auto config =
      FilterConfig::create(proto, "test.", *stats_.rootScope(), context_, context_.initManager());
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

TEST_F(ModelResolverFilterTest, MissingPolicyContinuesWithoutPlan) {
  initialize();
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_FALSE(headers_.has("x-envoy-retry-on"));
  EXPECT_EQ(1, counter("no_policy"));
}

TEST_F(ModelResolverFilterTest, MissingPolicyRejected) {
  initialize("reject_without_policy: true\n");
  EXPECT_CALL(callbacks_,
              sendLocalReply(Http::Code::ServiceUnavailable, "", _, _, "model_resolver_no_policy"));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers_, false));
}

TEST_F(ModelResolverFilterTest, PolicyWithoutUsableTargetRejected) {
  initialize("reject_without_policy: true\n");
  setTypedPolicy("{target_ids: [missing, d]}");
  EXPECT_CALL(callbacks_, sendLocalReply(Http::Code::ServiceUnavailable, "", _, _,
                                         "model_resolver_invalid_policy"));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(1, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, TypedMetadataOfAnotherType) {
  initialize();
  envoy::config::core::v3::Metadata other;
  std::ignore =
      (*callbacks_.stream_info_.metadata_.mutable_typed_filter_metadata())["envoy.ai.model_routing"]
          .PackFrom(other);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(1, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, StructPolicyWithWrongShape) {
  initialize();
  setStructPolicy(R"({"target_ids":[{"id":"a"}]})");
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(1, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, PolicyOutOfBounds) {
  initialize();
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

TEST_F(ModelResolverFilterTest, InvalidDefaultFallbackCondition) {
  ModelResolverProto proto;
  TestUtility::loadFromYaml(absl::StrCat(BaseConfig, "default_fallback_on: [0]\n"), proto);
  EXPECT_FALSE(
      FilterConfig::create(proto, "test.", *stats_.rootScope(), context_, context_.initManager())
          .ok());
}

TEST_F(ModelResolverFilterTest, UnknownStaticSecretRejected) {
  ModelResolverProto proto;
  TestUtility::loadFromYaml(absl::StrCat(BaseConfig, R"EOF(
  e:
    host: e.example.com
    model: model-e
    credential:
      header_name: x-api-key
      generic_secret: {name: missing-secret}
)EOF"),
                            proto);
  const auto config =
      FilterConfig::create(proto, "test.", *stats_.rootScope(), context_, context_.initManager());
  EXPECT_FALSE(config.ok());
}

} // namespace
} // namespace ModelResolver
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
