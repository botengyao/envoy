#include "envoy/config/core/v3/base.pb.h"
#include "envoy/data/ai/v3/model_routing_policy.pb.h"

#include "source/common/stats/isolated_store_impl.h"
#include "source/extensions/common/dynamic_forward_proxy/dynamic_host_candidates.h"
#include "source/extensions/filters/http/ai_protocol_manager/serializer.h"
#include "source/extensions/filters/http/model_resolver/filter.h"

#include "test/mocks/http/mocks.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

using testing::_;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelResolver {
namespace {

using DynamicHostCandidates = Envoy::Extensions::Common::DynamicForwardProxy::DynamicHostCandidates;

constexpr absl::string_view ThreeTargets = R"EOF(
targets:
- {id: a, host: a.example.com, model: model-a}
- {host: b.example.com, port: 8443, model: model-b, path: "/v1/models/{model}"}
- {host: c.example.com, model: model-c}
)EOF";

class ModelResolverFilterTest : public testing::Test {
protected:
  void initialize(absl::string_view config = "{}") {
    ModelResolverProto proto;
    TestUtility::loadFromYaml(std::string(config), proto);
    filter_ = std::make_unique<ModelResolverFilter>(
        std::make_shared<const FilterConfig>(proto, "test.", *stats_.rootScope()));
    filter_->setDecoderFilterCallbacks(callbacks_);
  }

  void setTypedPolicy(const ModelRoutingPolicy& policy,
                      const std::string& metadata_namespace = "envoy.ai.model_routing") {
    std::ignore =
        (*callbacks_.stream_info_.metadata_.mutable_typed_filter_metadata())[metadata_namespace]
            .PackFrom(policy);
  }

  void setTypedPolicy(absl::string_view yaml) {
    ModelRoutingPolicy policy;
    TestUtility::loadFromYaml(std::string(yaml), policy);
    setTypedPolicy(policy);
  }

  void setStructPolicy(absl::string_view json) {
    Protobuf::Struct policy;
    MessageUtil::loadFromJson(std::string(json), policy);
    (*callbacks_.stream_info_.metadata_.mutable_filter_metadata())["envoy.ai.model_routing"] =
        policy;
  }

  // The request body as an AI protocol manager filter earlier in the chain parsed it.
  void setParsedRequestBody(absl::string_view json) {
    AiProtocolManager::JsonWithExtBuf index;
    index.setJson(nlohmann::json::parse(json));
    callbacks_.stream_info_.filterState()->setData(
        AiProtocolManager::APMRequestPayloadIndex::kFilterStateKey,
        std::make_shared<AiProtocolManager::APMRequestPayloadIndex>(std::move(index)),
        StreamInfo::FilterState::LifeSpan::Request);
  }

  const AiCommon::ModelRoutePlan* plan() {
    return callbacks_.stream_info_.filterState()->getDataReadOnly<AiCommon::ModelRoutePlan>(
        AiCommon::ModelRoutePlan::key());
  }

  uint64_t counter(absl::string_view name) {
    return TestUtility::findCounter(stats_, absl::StrCat("test.model_resolver.", name))->value();
  }

  Stats::IsolatedStoreImpl stats_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks_;
  std::unique_ptr<ModelResolverFilter> filter_;
  Http::TestRequestHeaderMapImpl headers_{{":method", "POST"},
                                          {":path", "/v1/chat/completions"},
                                          {":authority", "gateway"},
                                          {"content-type", "application/json"}};
};

TEST_F(ModelResolverFilterTest, TypedPolicyBuildsPlanAndEnablesRetries) {
  initialize();
  setTypedPolicy(absl::StrCat(ThreeTargets, "decision_id: d-1\n"));

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
  // A target without an ID is named by its model.
  EXPECT_EQ("a,model-b,model-c", plan()->serializeAsString().value());
  EXPECT_EQ("d-1", plan()->decisionId());
  EXPECT_EQ("b.example.com", plan()->target(1).host);
  EXPECT_EQ(8443, plan()->target(1).port);
  EXPECT_EQ("/v1/models/{model}", plan()->target(1).path);
  // Recorded by the upstream filter, after route rewrites.
  EXPECT_FALSE(plan()->canonicalPath().has_value());
  // The same object is the dynamic forward proxy host candidate list.
  EXPECT_EQ(plan(), callbacks_.stream_info_.filterState()->getDataReadOnly<DynamicHostCandidates>(
                        DynamicHostCandidates::key()));

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
  setStructPolicy(R"({"targets":[{"host":"a.example.com","model":"model-a"},
                                 {"host":"b.example.com","model":"model-b"}],
                      "fallback_on":["RESET","SERVER_ERROR"],"per_try_timeout":"9s",
                      "reason":"quota"})");

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("model-a,model-b", plan()->serializeAsString().value());
  EXPECT_EQ("reset,5xx", headers_.get_("x-envoy-retry-on"));
  EXPECT_FALSE(headers_.has("x-envoy-retriable-status-codes"));
  EXPECT_EQ("1", headers_.get_("x-envoy-max-retries"));
  EXPECT_EQ("9000", headers_.get_("x-envoy-upstream-rq-per-try-timeout-ms"));
}

TEST_F(ModelResolverFilterTest, SingleTargetDisablesRouteRetries) {
  initialize();
  setTypedPolicy("{targets: [{host: b.example.com, model: model-b}], per_try_timeout: 2s}");

  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
  EXPECT_FALSE(headers_.has("x-envoy-retry-on"));
  EXPECT_EQ("0", headers_.get_("x-envoy-max-retries"));
  EXPECT_EQ("2000", headers_.get_("x-envoy-upstream-rq-per-try-timeout-ms"));
}

TEST_F(ModelResolverFilterTest, ZeroPerTryTimeoutIgnored) {
  initialize();
  ModelRoutingPolicy policy;
  auto* target = policy.add_targets();
  target->set_host("a.example.com");
  target->set_model("model-a");
  policy.mutable_per_try_timeout();
  setTypedPolicy(policy);

  filter_->decodeHeaders(headers_, false);
  ASSERT_NE(nullptr, plan());
  EXPECT_FALSE(headers_.has("x-envoy-upstream-rq-per-try-timeout-ms"));
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
  initialize("continue_without_policy: true");
  EXPECT_CALL(callbacks_, sendLocalReply(_, _, _, _, _)).Times(0);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_FALSE(headers_.has("x-envoy-retry-on"));
  EXPECT_EQ(1, counter("no_policy"));
}

TEST_F(ModelResolverFilterTest, InvalidTargetRejectsPolicy) {
  initialize();
  const std::vector<std::string> invalid_targets = {
      R"({host: "a.example.com:443", model: m})",
      R"({host: "2001:db8::1", model: m})",
      R"({host: "", model: m})",
      R"({host: a.example.com, port: 70000, model: m})",
      R"({host: a.example.com})",
      R"({host: a.example.com, model: m, path: v1})",
      R"({host: a.example.com, model: "a\nb", path: "/v1/{model}"})",
  };
  EXPECT_CALL(callbacks_, sendLocalReply(Http::Code::ServiceUnavailable, "", _, _,
                                         "model_resolver_invalid_policy"))
      .Times(invalid_targets.size());
  for (const std::string& target : invalid_targets) {
    setTypedPolicy(absl::StrCat("targets: [", target, "]"));
    EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(headers_, false))
        << target;
  }
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(invalid_targets.size(), counter("invalid_policy"));

  setTypedPolicy(R"(targets: [{host: "[2001:db8::1]", model: m, path: "/v1/{model}"}])");
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  ASSERT_NE(nullptr, plan());
}

TEST_F(ModelResolverFilterTest, BodyTheUpstreamFilterCannotRewrite) {
  initialize();
  setTypedPolicy(ThreeTargets);
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
  setTypedPolicy(ThreeTargets);
  headers_.setContentType("application/vnd.api+json");
  headers_.addCopy(Http::LowerCaseString("content-encoding"), "identity");
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));

  Http::TestRequestHeaderMapImpl headers_only{{":method", "GET"}, {":path", "/v1/models"}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_only, true));
  EXPECT_EQ(2, counter("plan_created"));
}

TEST_F(ModelResolverFilterTest, TypedMetadataOfAnotherType) {
  initialize("continue_without_policy: true");
  envoy::config::core::v3::Metadata other;
  std::ignore =
      (*callbacks_.stream_info_.metadata_.mutable_typed_filter_metadata())["envoy.ai.model_routing"]
          .PackFrom(other);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(headers_, false));
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(1, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, StructPolicyWithWrongShape) {
  initialize("continue_without_policy: true");
  setStructPolicy(R"({"targets":[{"host":{"name":"a.example.com"},"model":"m"}]})");
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(1, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, PolicyOutOfBounds) {
  initialize("continue_without_policy: true");
  ModelRoutingPolicy policy;
  for (int i = 0; i < 17; ++i) {
    auto* target = policy.add_targets();
    target->set_host("a.example.com");
    target->set_model("m");
  }
  setTypedPolicy(policy);
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(nullptr, plan());

  policy.mutable_targets()->DeleteSubrange(1, 16);
  policy.set_decision_id(std::string(129, 'd'));
  setTypedPolicy(policy);
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(nullptr, plan());

  policy.clear_decision_id();
  policy.add_fallback_on(ModelRoutingPolicy::FALLBACK_CONDITION_UNSPECIFIED);
  setTypedPolicy(policy);
  filter_->decodeHeaders(headers_, false);
  EXPECT_EQ(nullptr, plan());
  EXPECT_EQ(3, counter("invalid_policy"));
}

TEST_F(ModelResolverFilterTest, CustomPolicyNamespace) {
  initialize("policy_metadata_namespace: pdp.decision");
  ModelRoutingPolicy policy;
  TestUtility::loadFromYaml(std::string(ThreeTargets), policy);
  setTypedPolicy(policy, "pdp.decision");

  filter_->decodeHeaders(headers_, false);
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("2", headers_.get_("x-envoy-max-retries"));
}

TEST_F(ModelResolverFilterTest, RequestModelsOrderThePlan) {
  initialize("prefer_request_models: true");
  setTypedPolicy(R"EOF(
targets:
- {id: a, host: a.example.com, model: model-a}
- {host: b.example.com, model: model-b}
- {host: c.example.com, model: model-c}
- {id: a-east, host: a-east.example.com, model: model-a}
)EOF");
  setParsedRequestBody(R"({"model":"auto","models":["model-c","model-a","unknown"]})");

  filter_->decodeHeaders(headers_, false);
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("model-c,a,a-east", plan()->serializeAsString().value());
  EXPECT_EQ("2", headers_.get_("x-envoy-max-retries"));
}

TEST_F(ModelResolverFilterTest, RequestModelSelectsTargets) {
  initialize("prefer_request_models: true");
  setTypedPolicy(ThreeTargets);
  setParsedRequestBody(R"({"model":"model-b","messages":[]})");

  filter_->decodeHeaders(headers_, false);
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("model-b", plan()->serializeAsString().value());
  EXPECT_EQ("0", headers_.get_("x-envoy-max-retries"));
}

TEST_F(ModelResolverFilterTest, UnmatchedRequestModelsKeepThePolicy) {
  initialize("prefer_request_models: true");
  setTypedPolicy(ThreeTargets);
  setParsedRequestBody(R"({"model":"auto"})");

  filter_->decodeHeaders(headers_, false);
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("a,model-b,model-c", plan()->serializeAsString().value());
  EXPECT_EQ(1, counter("request_models_unmatched"));
}

TEST_F(ModelResolverFilterTest, RequestModelsIgnoredByDefault) {
  initialize();
  setTypedPolicy(ThreeTargets);
  setParsedRequestBody(R"({"model":"model-b"})");

  filter_->decodeHeaders(headers_, false);
  ASSERT_NE(nullptr, plan());
  EXPECT_EQ("a,model-b,model-c", plan()->serializeAsString().value());
  EXPECT_EQ(0, counter("request_models_unmatched"));
}

} // namespace
} // namespace ModelResolver
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
