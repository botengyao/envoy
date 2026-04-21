#pragma once

#include "envoy/http/header_map.h"

#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

// DESIGN.md §4.4 — decides Inference vs Agent (and which agent dialect) from
// headers + JSON-RPC method token.
//
// V0 implementation is path-prefix based. The filter's config supplies the
// prefix sets.

struct ClassifierPrefixes {
  std::vector<std::string> inference_prefixes;
  std::vector<std::string> agent_prefixes;
};

ProtocolKind classify(const Http::RequestHeaderMap& headers, absl::string_view jsonrpc_method,
                      const ClassifierPrefixes& prefixes);

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
