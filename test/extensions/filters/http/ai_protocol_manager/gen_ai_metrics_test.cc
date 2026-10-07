#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "source/common/protobuf/utility.h"
#include "source/common/router/string_accessor_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter_state.h"
#include "source/extensions/filters/http/ai_protocol_manager/gen_ai_metrics.h"

#include "test/mocks/stats/mocks.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/mocks/upstream/cluster_info.h"
#include "test/mocks/upstream/host.h"

#include "absl/strings/match.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

using testing::NiceMock;
using testing::UnorderedElementsAre;

struct RecordedValue {
  std::string name;
  Stats::TagVector tags;
  uint64_t value;

  bool operator==(const RecordedValue& other) const {
    return name == other.name && tags == other.tags && value == other.value;
  }
};

class GenAiMetricsTest : public testing::Test {
public:
  GenAiMetricsTest() {
    ON_CALL(store_, deliverHistogramToSinks(testing::_, testing::_))
        .WillByDefault(testing::Invoke([this](const Stats::Histogram& histogram, uint64_t value) {
          histogram_values_.push_back({histogram.tagExtractedName(), histogram.tags(), value});
        }));
    stream_info_.upstream_info_ = upstream_info_;
  }

  void createMetrics(uint32_t cardinality_limit = GenAiMetrics::DefaultCardinalityLimit) {
    metrics_ = std::make_unique<GenAiMetrics>(store_.rootScope(), stats_, cardinality_limit);
  }

  std::optional<uint64_t> counter(absl::string_view name, const Stats::TagVector& tags) {
    for (const Stats::CounterSharedPtr& counter : store_.counters()) {
      if (counter->tagExtractedName() == name && counter->tags() == tags) {
        return counter->value();
      }
    }
    return std::nullopt;
  }

  bool anyGenAiCounter() {
    for (const Stats::CounterSharedPtr& counter : store_.counters()) {
      if (absl::StartsWith(counter->tagExtractedName(), "gen_ai.")) {
        return true;
      }
    }
    return false;
  }

  void setRequestModel(absl::string_view model) {
    stream_info_.filter_state_->setData(FilterStateKeys::ModelRequest,
                                        std::make_shared<Router::StringAccessorImpl>(model),
                                        StreamInfo::FilterState::LifeSpan::FilterChain);
  }

  // The mock host's address is 10.0.0.1:443.
  void setUpstreamHostname(const std::string& hostname) {
    auto host = std::make_shared<NiceMock<Upstream::MockHostDescription>>();
    host->hostname_ = hostname;
    upstream_info_->upstream_host_ = host;
  }

  static TokenUsage usage(LLMProtocol protocol, absl::string_view model, uint64_t input,
                          uint64_t output) {
    TokenUsage usage;
    usage.llm_protocol = protocol;
    usage.model = std::string(model);
    usage.input_tokens = input;
    usage.output_tokens = output;
    return usage;
  }

  NiceMock<Stats::MockIsolatedStatsStore> store_;
  AiProtocolManagerStats stats_{ALL_AI_PROTOCOL_MANAGER_STATS(
      POOL_COUNTER_PREFIX(*store_.rootScope(), "ai_protocol_manager."))};
  std::shared_ptr<NiceMock<StreamInfo::MockUpstreamInfo>> upstream_info_{
      std::make_shared<NiceMock<StreamInfo::MockUpstreamInfo>>()};
  NiceMock<StreamInfo::MockStreamInfo> stream_info_;
  std::unique_ptr<GenAiMetrics> metrics_;
  std::vector<RecordedValue> histogram_values_;
};

TEST_F(GenAiMetricsTest, RecordsOpenAiUsageWithSpecAttributes) {
  createMetrics();
  setRequestModel("gpt-4o");
  setUpstreamHostname("api.openai.com");
  TokenUsage openai = usage(LLMProtocol::OpenAiChatCompletions, "gpt-4o-2024-08-06", 19, 10);
  openai.cached_input_tokens = 4;
  openai.cache_creation_input_tokens = 0;
  openai.reasoning_tokens = 2;
  metrics_->recordUsage(stream_info_, openai);

  const Stats::TagVector base{
      {"gen_ai.operation.name", "chat"},    {"gen_ai.provider.name", "openai"},
      {"gen_ai.request.model", "gpt-4o"},   {"gen_ai.response.model", "gpt-4o-2024-08-06"},
      {"server.address", "api.openai.com"}, {"server.port", "443"}};
  Stats::TagVector usage_tags = base;
  usage_tags.push_back({"gen_ai.token.modality", "unknown"});
  EXPECT_EQ(counter("gen_ai.client.inference.usage.input_tokens", usage_tags), 19);
  EXPECT_EQ(counter("gen_ai.client.inference.usage.output_tokens", usage_tags), 10);
  EXPECT_EQ(counter("gen_ai.client.inference.usage.cache_read.input_tokens", usage_tags), 4);
  EXPECT_EQ(counter("gen_ai.client.inference.usage.reasoning.output_tokens", usage_tags), 2);
  // A zero count records no series.
  EXPECT_EQ(counter("gen_ai.client.inference.usage.cache_write.input_tokens", usage_tags),
            std::nullopt);
  EXPECT_THAT(histogram_values_,
              UnorderedElementsAre(
                  RecordedValue{"gen_ai.client.inference.operation.input_tokens", base, 19},
                  RecordedValue{"gen_ai.client.inference.operation.output_tokens", base, 10}));
  EXPECT_EQ(stats_.gen_ai_metrics_overflow_.value(), 0);
}

TEST_F(GenAiMetricsTest, GeminiIsGenerateContentAndOmitsUnknownAttributes) {
  createMetrics();
  metrics_->recordUsage(stream_info_,
                        usage(LLMProtocol::GeminiGenerateContent, "gemini-2.0-flash", 6, 16));

  // No request model, and the upstream host has no hostname.
  EXPECT_EQ(counter("gen_ai.client.inference.usage.input_tokens",
                    {{"gen_ai.operation.name", "generate_content"},
                     {"gen_ai.provider.name", "gcp.gen_ai"},
                     {"gen_ai.response.model", "gemini-2.0-flash"},
                     {"gen_ai.token.modality", "unknown"}}),
            6);
}

TEST_F(GenAiMetricsTest, ClusterMetadataNamesTheProvider) {
  createMetrics();
  auto cluster = std::make_shared<NiceMock<Upstream::MockClusterInfo>>();
  (*cluster->metadata_.mutable_filter_metadata())["envoy.filters.http.ai_protocol_manager"]
      .mutable_fields()
      ->insert({"gen_ai.provider.name", ValueUtil::stringValue("groq")});
  stream_info_.upstream_cluster_info_ = cluster;
  metrics_->recordUsage(stream_info_, usage(LLMProtocol::OpenAiChatCompletions, "", 3, 4));

  EXPECT_EQ(counter("gen_ai.client.inference.usage.output_tokens",
                    {{"gen_ai.operation.name", "chat"},
                     {"gen_ai.provider.name", "groq"},
                     {"gen_ai.token.modality", "unknown"}}),
            4);
}

TEST_F(GenAiMetricsTest, UnusableModelNamesAreOther) {
  createMetrics();
  setRequestModel(std::string(129, 'm'));
  metrics_->recordUsage(stream_info_,
                        usage(LLMProtocol::AnthropicMessages, "claude\nsonnet", 1, 2));

  EXPECT_EQ(
      counter("gen_ai.client.inference.usage.input_tokens", {{"gen_ai.operation.name", "chat"},
                                                             {"gen_ai.provider.name", "anthropic"},
                                                             {"gen_ai.request.model", "_OTHER"},
                                                             {"gen_ai.response.model", "_OTHER"},
                                                             {"gen_ai.token.modality", "unknown"}}),
      1);
}

TEST_F(GenAiMetricsTest, UnspecifiedProtocolRecordsNothing) {
  createMetrics();
  metrics_->recordUsage(stream_info_, usage(LLMProtocol::Unspecified, "model", 1, 2));

  EXPECT_FALSE(anyGenAiCounter());
  EXPECT_TRUE(histogram_values_.empty());
}

TEST_F(GenAiMetricsTest, NewAttributeSetsOverflowPastTheLimit) {
  createMetrics(/*cardinality_limit=*/1);
  metrics_->recordUsage(stream_info_, usage(LLMProtocol::OpenAiResponses, "a", 1, 2));
  metrics_->recordUsage(stream_info_, usage(LLMProtocol::OpenAiResponses, "b", 10, 20));
  // A set seen before the limit was reached keeps its own series.
  metrics_->recordUsage(stream_info_, usage(LLMProtocol::OpenAiResponses, "a", 100, 200));

  const Stats::TagVector a{{"gen_ai.operation.name", "chat"},
                           {"gen_ai.provider.name", "openai"},
                           {"gen_ai.response.model", "a"},
                           {"gen_ai.token.modality", "unknown"}};
  const Stats::TagVector overflow{{"otel.metric.overflow", "true"}};
  EXPECT_EQ(counter("gen_ai.client.inference.usage.input_tokens", a), 101);
  EXPECT_EQ(counter("gen_ai.client.inference.usage.input_tokens", overflow), 10);
  EXPECT_EQ(counter("gen_ai.client.inference.usage.output_tokens", overflow), 20);
  EXPECT_THAT(histogram_values_,
              testing::Contains(
                  RecordedValue{"gen_ai.client.inference.operation.input_tokens", overflow, 10}));
  // Two counters and two histograms of the second record overflowed.
  EXPECT_EQ(stats_.gen_ai_metrics_overflow_.value(), 4);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
