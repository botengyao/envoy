#include "source/extensions/common/ai/model_route_plan.h"

#include "test/test_common/utility.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Ai {
namespace {

ModelTarget makeTarget(std::string id, std::string host, uint16_t port, std::string model,
                       std::string path) {
  ModelTarget target;
  target.id = std::move(id);
  target.host = std::move(host);
  target.port = port;
  target.model = std::move(model);
  target.path = std::move(path);
  return target;
}

class ModelRoutePlanTest : public testing::Test {
protected:
  ModelRoutePlan plan_{
      {makeTarget("vertex", "us-central1-aiplatform.googleapis.com", 0, "gemini-2.5-pro",
                  "/v1/models/{model}:generateContent"),
       makeTarget("anthropic", "api.anthropic.com", 8443, "claude-sonnet-4-5", "")},
      "decision-7"};
};

TEST_F(ModelRoutePlanTest, EachTargetOwnsPathAndAuthority) {
  Http::TestRequestHeaderMapImpl headers{{":path", "/v1/chat/completions"},
                                         {":authority", "gateway.example.com"},
                                         {"authorization", "Bearer client-token"}};

  EXPECT_FALSE(plan_.canonicalPath().has_value());
  plan_.applyToHeaders(0, headers);
  EXPECT_EQ("/v1/chat/completions", plan_.canonicalPath().value());
  EXPECT_EQ("/v1/models/gemini-2.5-pro:generateContent", headers.getPathValue());
  EXPECT_EQ("us-central1-aiplatform.googleapis.com", headers.getHostValue());

  // A later attempt on the same header map starts from the canonical path.
  plan_.applyToHeaders(1, headers);
  EXPECT_EQ("/v1/chat/completions", headers.getPathValue());
  EXPECT_EQ("api.anthropic.com:8443", headers.getHostValue());
  EXPECT_EQ("Bearer client-token", headers.get_("authorization"));
}

TEST_F(ModelRoutePlanTest, HostCandidatesFollowTargets) {
  ASSERT_EQ(2, plan_.candidates().size());
  EXPECT_EQ("us-central1-aiplatform.googleapis.com", plan_.candidates()[0].host);
  EXPECT_EQ(0, plan_.candidates()[0].port);
  EXPECT_EQ("api.anthropic.com", plan_.candidates()[1].host);
  EXPECT_EQ(8443, plan_.candidates()[1].port);
}

TEST_F(ModelRoutePlanTest, Fields) {
  EXPECT_EQ("vertex,anthropic", plan_.serializeAsString().value());
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
