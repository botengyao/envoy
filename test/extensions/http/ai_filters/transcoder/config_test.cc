#include "envoy/extensions/http/ai_filters/transcoder/v3/transcoder.pb.h"
#include "envoy/registry/registry.h"

#include "source/extensions/filters/http/ai_protocol_manager/ai_filter.h"
#include "source/extensions/http/ai_filters/transcoder/config.h"
#include "source/extensions/http/ai_filters/transcoder/filter.h"

#include "test/mocks/server/server_factory_context.h"
#include "test/mocks/stats/mocks.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {
namespace {

using HttpFilters::AiProtocolManager::AiFilterConfigFactory;
using HttpFilters::AiProtocolManager::AiFilterContext;
using HttpFilters::AiProtocolManager::UnsupportedFieldPolicy;
using TranscoderProto = envoy::extensions::http::ai_filters::transcoder::v3::Transcoder;

TranscoderProto parse(const std::string& yaml) {
  TranscoderProto proto;
  TestUtility::loadFromYaml(yaml, proto);
  return proto;
}

TEST(TranscoderConfigTest, IsRegistered) {
  auto* factory = Registry::FactoryRegistry<AiFilterConfigFactory>::getFactory(
      "envoy.http.ai_filters.transcoder");
  ASSERT_NE(factory, nullptr);
  EXPECT_EQ(factory->category(), "envoy.http.ai_filters");
}

TEST(TranscoderConfigTest, CreatesFilterForEitherLeg) {
  TranscoderFilterConfigFactory factory;
  NiceMock<Server::Configuration::MockServerFactoryContext> context;
  NiceMock<Stats::MockIsolatedStatsStore> stats_store;
  NiceMock<StreamInfo::MockStreamInfo> stream_info;
  const Http::TestRequestHeaderMapImpl headers{{":method", "POST"}, {":path", "/"}};
  const AiFilterContext stream_context{stream_info, headers, LLMProtocol::OpenAiChatCompletions};

  for (const std::string yaml : {std::string("internal: {}"), std::string(R"EOF(
upstream:
  llm_protocol: GEMINI_GENERATE_CONTENT
  vertex_ai: {project: p, location: global}
)EOF")}) {
    const auto factory_cb =
        factory.createAiFilterFactory(parse(yaml), context, *stats_store.rootScope());
    ASSERT_TRUE(factory_cb.ok()) << factory_cb.status();
    EXPECT_NE((*factory_cb)(stream_context), nullptr);
  }
}

TEST(TranscoderConfigTest, UpstreamDefaultsAndOverrides) {
  NiceMock<Stats::MockIsolatedStatsStore> stats_store;
  auto config = TranscoderConfig::create(parse(R"EOF(
upstream:
  llm_protocol: ANTHROPIC_MESSAGES
  vertex_ai: {project: p, location: us-east5}
)EOF"),
                                         *stats_store.rootScope());
  ASSERT_TRUE(config.ok()) << config.status();
  EXPECT_FALSE((*config)->isInternalLeg());
  EXPECT_EQ((*config)->upstreamProtocol(), LLMProtocol::AnthropicMessages);
  EXPECT_EQ((*config)->transcodeOptions().default_max_output_tokens, 4096);
  EXPECT_EQ((*config)->transcodeOptions().unsupported_fields, UnsupportedFieldPolicy::Drop);
  EXPECT_EQ((*config)->maxResponseBytes(), 4 * 1024 * 1024);
  EXPECT_TRUE((*config)->alwaysReportUsage());
  EXPECT_TRUE((*config)->model().empty());

  config = TranscoderConfig::create(parse(R"EOF(
upstream:
  llm_protocol: GEMINI_GENERATE_CONTENT
  native: {}
  model: gemini-2.5-pro
  default_max_output_tokens: 128
  max_response_bytes: 1024
  stream_usage: IF_REQUESTED
  unsupported_fields: REJECT
)EOF"),
                                    *stats_store.rootScope());
  ASSERT_TRUE(config.ok()) << config.status();
  EXPECT_EQ((*config)->model(), "gemini-2.5-pro");
  EXPECT_EQ((*config)->transcodeOptions().default_max_output_tokens, 128);
  EXPECT_EQ((*config)->transcodeOptions().unsupported_fields, UnsupportedFieldPolicy::Reject);
  EXPECT_EQ((*config)->maxResponseBytes(), 1024);
  EXPECT_FALSE((*config)->alwaysReportUsage());
}

TEST(TranscoderConfigTest, RejectsInvalidEndpoint) {
  NiceMock<Stats::MockIsolatedStatsStore> stats_store;
  // Project without location.
  EXPECT_FALSE(TranscoderConfig::create(parse(R"EOF(
upstream:
  llm_protocol: GEMINI_GENERATE_CONTENT
  vertex_ai: {project: p}
)EOF"),
                                        *stats_store.rootScope())
                   .ok());
}

TEST(TranscoderConfigTest, InternalLegHasNoEndpoint) {
  NiceMock<Stats::MockIsolatedStatsStore> stats_store;
  auto config = TranscoderConfig::create(parse("internal: {}"), *stats_store.rootScope());
  ASSERT_TRUE(config.ok());
  EXPECT_TRUE((*config)->isInternalLeg());
}

} // namespace
} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
