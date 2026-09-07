#pragma once

#include "source/extensions/filters/http/ai_protocol_manager/request_info.h"

namespace envoy {
namespace data {
namespace ai {
namespace v3 {
class RequestInfo;
} // namespace v3
} // namespace ai
} // namespace data
} // namespace envoy

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Converts the internal record to the typed dynamic-metadata contract. Kept
// in a separate target so request parsing does not depend on generated API
// code.
envoy::data::ai::v3::RequestInfo requestInfoToProto(const RequestInfo& info);

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
