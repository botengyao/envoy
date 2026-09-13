#include "source/extensions/common/dynamic_forward_proxy/dynamic_host_candidates.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace DynamicForwardProxy {
namespace {

TEST(DynamicHostCandidatesTest, ParsesHostsAndPorts) {
  auto candidates =
      DynamicHostCandidates::fromString("a.example.com, b.example.com:8443,[::1]:9000,127.0.0.1");
  ASSERT_NE(nullptr, candidates);
  ASSERT_EQ(4, candidates->candidates().size());
  EXPECT_EQ("a.example.com", candidates->candidates()[0].host);
  EXPECT_EQ(0, candidates->candidates()[0].port);
  EXPECT_EQ("b.example.com", candidates->candidates()[1].host);
  EXPECT_EQ(8443, candidates->candidates()[1].port);
  EXPECT_EQ("[::1]", candidates->candidates()[2].host);
  EXPECT_EQ(9000, candidates->candidates()[2].port);
  EXPECT_EQ("127.0.0.1", candidates->candidates()[3].host);
  EXPECT_EQ("a.example.com,b.example.com:8443,[::1]:9000,127.0.0.1",
            candidates->serializeAsString().value());
}

TEST(DynamicHostCandidatesTest, RejectsMalformedLists) {
  EXPECT_EQ(nullptr, DynamicHostCandidates::fromString(""));
  EXPECT_EQ(nullptr, DynamicHostCandidates::fromString("a.example.com,,b.example.com"));
  EXPECT_EQ(nullptr, DynamicHostCandidates::fromString("a.example.com:0"));
  EXPECT_EQ(nullptr, DynamicHostCandidates::fromString(":443"));
}

TEST(DynamicHostCandidatesTest, EachAttemptConsumesTheNextCandidate) {
  DynamicHostCandidates candidates({{"a", 0}, {"b", 0}, {"c", 0}});
  EXPECT_EQ(0U, candidates.selectForAttempt(1));
  EXPECT_EQ(0U, candidates.selectForAttempt(1));
  EXPECT_EQ(1U, candidates.selectForAttempt(2));
  EXPECT_EQ(2U, candidates.selectForAttempt(3));
  EXPECT_EQ(std::nullopt, candidates.selectForAttempt(4));
  EXPECT_EQ(1U, candidates.selectionForAttempt(2));
  EXPECT_EQ(std::nullopt, candidates.selectionForAttempt(5));
  EXPECT_EQ(std::nullopt, candidates.selectionForAttempt(0));
}

TEST(DynamicHostCandidatesTest, AttemptsSkippingTheSameHost) {
  DynamicHostCandidates candidates({{"a", 0}, {"b", 0}, {"a", 0}, {"c", 0}});
  EXPECT_EQ(0U, candidates.selectForAttempt(1));
  EXPECT_EQ(1U, candidates.skipForAttempt(1));
  // Index 2 names the host that already failed.
  EXPECT_EQ(3U, candidates.selectForAttempt(2));
  EXPECT_EQ(std::nullopt, candidates.skipForAttempt(2));
  EXPECT_EQ(std::nullopt, candidates.selectForAttempt(3));
  EXPECT_EQ(std::nullopt, candidates.skipForAttempt(3));
  EXPECT_EQ(std::nullopt, candidates.skipForAttempt(7));
}

TEST(DynamicHostCandidatesTest, RetryingTheSameHostUsesARepeatedEntry) {
  DynamicHostCandidates candidates({{"a", 0}, {"a", 0}, {"b", 443}});
  EXPECT_EQ(0U, candidates.selectForAttempt(1));
  EXPECT_EQ(1U, candidates.selectForAttempt(2));
  EXPECT_EQ(2U, candidates.selectForAttempt(3));
}

TEST(DynamicHostCandidatesTest, Fields) {
  DynamicHostCandidates candidates({{"a", 443}, {"b", 0}});
  EXPECT_EQ("", absl::get<absl::string_view>(candidates.getField("selected")));
  EXPECT_EQ(0, absl::get<int64_t>(candidates.getField("attempts")));
  candidates.selectForAttempt(2);
  EXPECT_EQ("b", absl::get<absl::string_view>(candidates.getField("selected")));
  EXPECT_EQ(2, absl::get<int64_t>(candidates.getField("attempts")));
  EXPECT_EQ(std::nullopt, candidates.skipForAttempt(2));
  EXPECT_EQ("", absl::get<absl::string_view>(candidates.getField("selected")));
  EXPECT_TRUE(absl::holds_alternative<absl::monostate>(candidates.getField("unknown")));
}

} // namespace
} // namespace DynamicForwardProxy
} // namespace Common
} // namespace Extensions
} // namespace Envoy
