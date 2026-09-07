#include "source/extensions/filters/http/ai_protocol_manager/request_info_proto.h"

#include "envoy/data/ai/v3/request_info.pb.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

envoy::type::ai::v3::ApiProtocol protocolToProto(ApiProtocol protocol) {
  switch (protocol) {
  case ApiProtocol::OpenAiChatCompletions:
    return envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS;
  case ApiProtocol::OpenAiResponses:
    return envoy::type::ai::v3::OPENAI_RESPONSES;
  case ApiProtocol::AnthropicMessages:
    return envoy::type::ai::v3::ANTHROPIC_MESSAGES;
  case ApiProtocol::GeminiGenerateContent:
    return envoy::type::ai::v3::GEMINI_GENERATE_CONTENT;
  case ApiProtocol::Unspecified:
    break;
  }
  return envoy::type::ai::v3::API_PROTOCOL_UNSPECIFIED;
}

envoy::data::ai::v3::RequestInfo::ExtractionStatus
extractionStatusToProto(ExtractionStatus status) {
  switch (status) {
  case ExtractionStatus::Unspecified:
    return envoy::data::ai::v3::RequestInfo::EXTRACTION_STATUS_UNSPECIFIED;
  case ExtractionStatus::Complete:
    return envoy::data::ai::v3::RequestInfo::COMPLETE;
  case ExtractionStatus::Partial:
    return envoy::data::ai::v3::RequestInfo::PARTIAL;
  case ExtractionStatus::Failed:
    return envoy::data::ai::v3::RequestInfo::FAILED;
  }
  return envoy::data::ai::v3::RequestInfo::EXTRACTION_STATUS_UNSPECIFIED;
}

envoy::data::ai::v3::RequestInfo::StopReason stopReasonToProto(StopReason reason) {
  switch (reason) {
  case StopReason::Unspecified:
    return envoy::data::ai::v3::RequestInfo::STOP_REASON_UNSPECIFIED;
  case StopReason::EndStream:
    return envoy::data::ai::v3::RequestInfo::END_STREAM;
  case StopReason::RootClosed:
    return envoy::data::ai::v3::RequestInfo::ROOT_CLOSED;
  case StopReason::ByteLimit:
    return envoy::data::ai::v3::RequestInfo::BYTE_LIMIT;
  case StopReason::ParseError:
    return envoy::data::ai::v3::RequestInfo::PARSE_ERROR;
  }
  return envoy::data::ai::v3::RequestInfo::STOP_REASON_UNSPECIFIED;
}

envoy::data::ai::v3::RequestInfo::DetectionSource detectionSourceToProto(DetectionSource source) {
  switch (source) {
  case DetectionSource::Unspecified:
    return envoy::data::ai::v3::RequestInfo::DETECTION_SOURCE_UNSPECIFIED;
  case DetectionSource::Route:
    return envoy::data::ai::v3::RequestInfo::ROUTE;
  case DetectionSource::ConfigDefault:
    return envoy::data::ai::v3::RequestInfo::CONFIG_DEFAULT;
  case DetectionSource::AuthorityPath:
    return envoy::data::ai::v3::RequestInfo::AUTHORITY_PATH;
  case DetectionSource::Body:
    return envoy::data::ai::v3::RequestInfo::BODY;
  }
  return envoy::data::ai::v3::RequestInfo::DETECTION_SOURCE_UNSPECIFIED;
}

} // namespace

envoy::data::ai::v3::RequestInfo requestInfoToProto(const RequestInfo& info) {
  envoy::data::ai::v3::RequestInfo proto;
  proto.set_api_protocol(protocolToProto(info.api_protocol));
  if (info.model.has_value()) {
    proto.mutable_model()->set_value(info.model.value());
  }
  if (info.streaming.has_value()) {
    proto.mutable_streaming()->set_value(info.streaming.value());
  }
  if (info.max_output_tokens.has_value()) {
    proto.mutable_requested_max_output_tokens()->set_value(info.max_output_tokens.value());
  }
  if (info.message_count.has_value()) {
    proto.mutable_message_count()->set_value(info.message_count.value());
  }
  if (info.tool_count.has_value()) {
    proto.mutable_tool_count()->set_value(info.tool_count.value());
  }
  proto.set_extraction_status(extractionStatusToProto(info.extraction_status));
  proto.set_stop_reason(stopReasonToProto(info.stop_reason));
  proto.set_detection_source(detectionSourceToProto(info.detection_source));
  proto.set_inspected_bytes(info.inspected_bytes);
  return proto;
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
