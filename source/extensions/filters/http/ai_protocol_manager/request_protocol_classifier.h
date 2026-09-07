#pragma once

#include <optional>
#include <string>

#include "source/extensions/filters/http/ai_protocol_manager/request_info.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// One conservative protocol-selection result. When api_protocol is
// Unspecified, detection_source is not meaningful.
struct RequestProtocolClassification {
  ApiProtocol api_protocol{ApiProtocol::Unspecified};
  DetectionSource detection_source{DetectionSource::Unspecified};
  std::optional<std::string> model;
  std::optional<bool> streaming;

  bool matched() const { return api_protocol != ApiProtocol::Unspecified; }
};

// Classifies only exact operation suffixes corroborated by a recognized direct
// provider authority. Unknown authorities require a configured default or
// body evidence instead, and a recognized authority that contradicts the path
// does not match. Bedrock invoke targets never select Anthropic from
// authority/path alone because Bedrock serves multiple model families.
RequestProtocolClassification detectRequestProtocol(absl::string_view authority,
                                                    absl::string_view path);

// Path-only convenience for callers that do not retain :authority. The query
// string is ignored, but a trailing slash, extra path component, incomplete
// operation, or empty Gemini model does not match.
RequestProtocolClassification classifyRequestPath(absl::string_view path);

// Applies attributes encoded in the request target after the protocol is
// known. This extracts Gemini's model/streaming operation and, after body
// detection has selected Anthropic semantics, a Bedrock model ID and invoke
// streaming operation. Unrecognized or protocol-incompatible targets leave
// info unchanged.
void applyRequestTarget(absl::string_view path, ApiProtocol protocol, RequestInfo& info);

// Applies the protocol evidence precedence used by request handling:
// explicit route, configured default, request path, then body. If the path
// agrees with an earlier selection, its path-derived model/streaming fields
// are retained while the earlier source remains authoritative.
RequestProtocolClassification selectRequestProtocol(ApiProtocol route_protocol,
                                                    ApiProtocol config_default_protocol,
                                                    absl::string_view authority,
                                                    absl::string_view path,
                                                    ApiProtocol body_protocol);

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
