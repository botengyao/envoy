#include "source/extensions/common/ai/model_route_plan.h"

#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Ai {
namespace {

class StaticCredential : public CredentialSource {
public:
  explicit StaticCredential(std::string value) : value_(std::move(value)) {}
  absl::string_view credential() const override { return value_; }

private:
  const std::string value_;
};

ModelTarget makeTarget(std::string id, std::string host, uint16_t port, std::string model,
                       std::string path, absl::string_view header = "", std::string prefix = "",
                       std::string secret = "") {
  ModelTarget target;
  target.id = std::move(id);
  target.host = std::move(host);
  target.port = port;
  target.model = std::move(model);
  target.path = std::move(path);
  if (!header.empty()) {
    target.credential_header = Http::LowerCaseString(header);
    target.credential_prefix = std::move(prefix);
    target.credential = std::make_shared<StaticCredential>(std::move(secret));
  }
  return target;
}

class ModelRoutePlanTest : public testing::Test {
protected:
  ModelRoutePlanTest()
      : registry_(std::make_shared<const ModelTargetRegistry>(std::vector<ModelTarget>{
            makeTarget("vertex", "us-central1-aiplatform.googleapis.com", 0, "gemini-2.5-pro",
                       "/v1/models/{model}:generateContent", "authorization", "Bearer ",
                       "gcp-token\n"),
            makeTarget("anthropic", "api.anthropic.com", 8443, "claude-sonnet-4-5", "", "x-api-key",
                       "", "sk-test"),
            makeTarget("pending", "api.example.com", 0, "model", "", "x-api-key", "", "")})),
        plan_(registry_,
              {registry_->find("vertex"), registry_->find("anthropic"), registry_->find("pending")},
              "/v1/chat/completions", "decision-7") {}

  const ModelTargetRegistrySharedPtr registry_;
  ModelRoutePlan plan_;
};

TEST_F(ModelRoutePlanTest, RegistryLookup) {
  EXPECT_EQ(nullptr, registry_->find("missing"));
  ASSERT_NE(nullptr, registry_->find("vertex"));
  EXPECT_EQ("gemini-2.5-pro", registry_->find("vertex")->model);
  EXPECT_EQ(2, registry_->credentialHeaders().size());
}

TEST_F(ModelRoutePlanTest, EachTargetOwnsTheRequestHeaders) {
  Http::TestRequestHeaderMapImpl headers{{":path", "/v1/chat/completions"},
                                         {":authority", "gateway.example.com"},
                                         {"authorization", "Bearer client-token"},
                                         {"x-api-key", "client-key"}};

  plan_.applyToHeaders(0, headers);
  EXPECT_EQ("/v1/models/gemini-2.5-pro:generateContent", headers.getPathValue());
  EXPECT_EQ("us-central1-aiplatform.googleapis.com", headers.getHostValue());
  EXPECT_EQ("Bearer gcp-token", headers.get_("authorization"));
  EXPECT_FALSE(headers.has("x-api-key"));

  // A later attempt on the same header map must not carry the previous target's values.
  plan_.applyToHeaders(1, headers);
  EXPECT_EQ("/v1/chat/completions", headers.getPathValue());
  EXPECT_EQ("api.anthropic.com:8443", headers.getHostValue());
  EXPECT_EQ("sk-test", headers.get_("x-api-key"));
  EXPECT_FALSE(headers.has("authorization"));
}

TEST_F(ModelRoutePlanTest, UnavailableCredentialSendsNone) {
  Http::TestRequestHeaderMapImpl headers{
      {":path", "/"}, {":authority", "gateway.example.com"}, {"x-api-key", "client-key"}};
  plan_.applyToHeaders(2, headers);
  EXPECT_EQ("api.example.com", headers.getHostValue());
  EXPECT_FALSE(headers.has("x-api-key"));
}

TEST_F(ModelRoutePlanTest, HostCandidatesFollowTargets) {
  ASSERT_EQ(3, plan_.candidates().size());
  EXPECT_EQ("us-central1-aiplatform.googleapis.com", plan_.candidates()[0].host);
  EXPECT_EQ(0, plan_.candidates()[0].port);
  EXPECT_EQ("api.anthropic.com", plan_.candidates()[1].host);
  EXPECT_EQ(8443, plan_.candidates()[1].port);
}

TEST_F(ModelRoutePlanTest, Fields) {
  EXPECT_EQ("vertex,anthropic,pending", plan_.serializeAsString().value());
  EXPECT_EQ("decision-7", absl::get<absl::string_view>(plan_.getField("decision_id")));
  EXPECT_TRUE(absl::holds_alternative<absl::monostate>(plan_.getField("selected_target")));

  EXPECT_EQ(0U, plan_.selectForAttempt(1));
  EXPECT_EQ(1U, plan_.selectForAttempt(2));
  EXPECT_EQ("anthropic", absl::get<absl::string_view>(plan_.getField("selected_target")));
  EXPECT_EQ("claude-sonnet-4-5", absl::get<absl::string_view>(plan_.getField("selected_model")));
  EXPECT_EQ(2, absl::get<int64_t>(plan_.getField("attempts")));
}

TEST_F(ModelRoutePlanTest, AttemptRecord) {
  ModelAttempt attempt(2, plan_.target(1));
  EXPECT_EQ("anthropic", attempt.serializeAsString().value());
  EXPECT_EQ("anthropic", absl::get<absl::string_view>(attempt.getField("target_id")));
  EXPECT_EQ("claude-sonnet-4-5", absl::get<absl::string_view>(attempt.getField("model")));
  EXPECT_EQ("api.anthropic.com", absl::get<absl::string_view>(attempt.getField("host")));
  EXPECT_EQ(2, absl::get<int64_t>(attempt.getField("attempt")));
  EXPECT_TRUE(absl::holds_alternative<absl::monostate>(attempt.getField("unknown")));
}

} // namespace
} // namespace Ai
} // namespace Common
} // namespace Extensions
} // namespace Envoy
