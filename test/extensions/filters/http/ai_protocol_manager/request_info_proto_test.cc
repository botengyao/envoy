#include "envoy/data/ai/v3/request_info.pb.h"

#include "source/extensions/filters/http/ai_protocol_manager/request_info_proto.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

TEST(RequestInfoProtoTest, PreservesPresenceAndExtractionOutcome) {
  RequestInfo info;
  info.api_protocol = ApiProtocol::GeminiGenerateContent;
  info.model = "gemini-2.5-pro";
  info.streaming = false;
  info.max_output_tokens = 0;
  info.message_count = 0;
  info.tool_count = 2;
  info.extraction_status = ExtractionStatus::Partial;
  info.stop_reason = StopReason::ByteLimit;
  info.detection_source = DetectionSource::AuthorityPath;
  info.inspected_bytes = 1024 * 1024;

  const envoy::data::ai::v3::RequestInfo proto = requestInfoToProto(info);
  EXPECT_EQ(proto.api_protocol(), envoy::type::ai::v3::GEMINI_GENERATE_CONTENT);
  ASSERT_TRUE(proto.has_model());
  EXPECT_EQ(proto.model().value(), "gemini-2.5-pro");
  ASSERT_TRUE(proto.has_streaming());
  EXPECT_FALSE(proto.streaming().value());
  ASSERT_TRUE(proto.has_requested_max_output_tokens());
  EXPECT_EQ(proto.requested_max_output_tokens().value(), 0);
  ASSERT_TRUE(proto.has_message_count());
  EXPECT_EQ(proto.message_count().value(), 0);
  ASSERT_TRUE(proto.has_tool_count());
  EXPECT_EQ(proto.tool_count().value(), 2);
  EXPECT_EQ(proto.extraction_status(), envoy::data::ai::v3::RequestInfo::PARTIAL);
  EXPECT_EQ(proto.stop_reason(), envoy::data::ai::v3::RequestInfo::BYTE_LIMIT);
  EXPECT_EQ(proto.detection_source(), envoy::data::ai::v3::RequestInfo::AUTHORITY_PATH);
  EXPECT_EQ(proto.inspected_bytes(), 1024 * 1024);
}

TEST(RequestInfoProtoTest, LeavesAbsentAttributesAbsent) {
  RequestInfo info;
  info.extraction_status = ExtractionStatus::Failed;
  info.stop_reason = StopReason::ParseError;
  info.detection_source = DetectionSource::Body;

  const envoy::data::ai::v3::RequestInfo proto = requestInfoToProto(info);
  EXPECT_EQ(proto.api_protocol(), envoy::type::ai::v3::API_PROTOCOL_UNSPECIFIED);
  EXPECT_FALSE(proto.has_model());
  EXPECT_FALSE(proto.has_streaming());
  EXPECT_FALSE(proto.has_requested_max_output_tokens());
  EXPECT_FALSE(proto.has_message_count());
  EXPECT_FALSE(proto.has_tool_count());
  EXPECT_EQ(proto.extraction_status(), envoy::data::ai::v3::RequestInfo::FAILED);
  EXPECT_EQ(proto.stop_reason(), envoy::data::ai::v3::RequestInfo::PARSE_ERROR);
  EXPECT_EQ(proto.detection_source(), envoy::data::ai::v3::RequestInfo::BODY);
}

TEST(RequestInfoProtoTest, ConvertsEveryEnumValue) {
  RequestInfo info;

  info.api_protocol = ApiProtocol::OpenAiChatCompletions;
  EXPECT_EQ(requestInfoToProto(info).api_protocol(), envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS);
  info.api_protocol = ApiProtocol::OpenAiResponses;
  EXPECT_EQ(requestInfoToProto(info).api_protocol(), envoy::type::ai::v3::OPENAI_RESPONSES);
  info.api_protocol = ApiProtocol::AnthropicMessages;
  EXPECT_EQ(requestInfoToProto(info).api_protocol(), envoy::type::ai::v3::ANTHROPIC_MESSAGES);

  info.extraction_status = ExtractionStatus::Complete;
  EXPECT_EQ(requestInfoToProto(info).extraction_status(),
            envoy::data::ai::v3::RequestInfo::COMPLETE);
  info.extraction_status = ExtractionStatus::Partial;
  EXPECT_EQ(requestInfoToProto(info).extraction_status(),
            envoy::data::ai::v3::RequestInfo::PARTIAL);

  info.stop_reason = StopReason::EndStream;
  EXPECT_EQ(requestInfoToProto(info).stop_reason(), envoy::data::ai::v3::RequestInfo::END_STREAM);
  info.stop_reason = StopReason::RootClosed;
  EXPECT_EQ(requestInfoToProto(info).stop_reason(), envoy::data::ai::v3::RequestInfo::ROOT_CLOSED);

  info.detection_source = DetectionSource::Route;
  EXPECT_EQ(requestInfoToProto(info).detection_source(), envoy::data::ai::v3::RequestInfo::ROUTE);
  info.detection_source = DetectionSource::ConfigDefault;
  EXPECT_EQ(requestInfoToProto(info).detection_source(),
            envoy::data::ai::v3::RequestInfo::CONFIG_DEFAULT);
}

TEST(RequestInfoProtoTest, UnknownInternalEnumsFailClosedToUnspecified) {
  RequestInfo info;
  info.api_protocol = static_cast<ApiProtocol>(255);
  info.extraction_status = static_cast<ExtractionStatus>(255);
  info.stop_reason = static_cast<StopReason>(255);
  info.detection_source = static_cast<DetectionSource>(255);

  const envoy::data::ai::v3::RequestInfo proto = requestInfoToProto(info);
  EXPECT_EQ(proto.api_protocol(), envoy::type::ai::v3::API_PROTOCOL_UNSPECIFIED);
  EXPECT_EQ(proto.extraction_status(),
            envoy::data::ai::v3::RequestInfo::EXTRACTION_STATUS_UNSPECIFIED);
  EXPECT_EQ(proto.stop_reason(), envoy::data::ai::v3::RequestInfo::STOP_REASON_UNSPECIFIED);
  EXPECT_EQ(proto.detection_source(),
            envoy::data::ai::v3::RequestInfo::DETECTION_SOURCE_UNSPECIFIED);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
