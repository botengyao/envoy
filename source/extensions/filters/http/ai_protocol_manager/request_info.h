#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "source/extensions/filters/http/ai_protocol_manager/token_usage.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Quality of the attributes extracted from a request payload.
enum class ExtractionStatus { Unspecified, Complete, Partial, Failed };

// The event that ended request inspection.
enum class StopReason { Unspecified, EndStream, RootClosed, ByteLimit, ParseError };

// The evidence that selected the request's wire protocol.
enum class DetectionSource { Unspecified, Route, ConfigDefault, AuthorityPath, Body };

// Internal, presence-preserving request attribute record. This deliberately
// does not depend on protobuf so parsers and future payload filters can share
// it without taking a metadata/API dependency.
//
// The status/source defaults describe a record that has not yet been
// finalized. Callers replace them when extraction reaches a terminal state.
struct RequestInfo {
  ApiProtocol api_protocol{ApiProtocol::Unspecified};
  std::optional<std::string> model;
  std::optional<bool> streaming;
  std::optional<uint64_t> max_output_tokens;
  std::optional<uint32_t> message_count;
  std::optional<uint32_t> tool_count;
  ExtractionStatus extraction_status{ExtractionStatus::Unspecified};
  StopReason stop_reason{StopReason::Unspecified};
  DetectionSource detection_source{DetectionSource::Unspecified};
  uint64_t inspected_bytes{0};
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
