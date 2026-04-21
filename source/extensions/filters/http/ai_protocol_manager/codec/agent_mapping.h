#pragma once

#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request_encoder.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

// Agent-side mapping: A2A + MCP.
//
// Agent bodies *are* JSON-RPC 2.0 (MCP strictly; A2A over HTTP typically).
// The {"jsonrpc","id","method","params"} envelope is honored and split out
// into AiRequest identity + AgentPayload variant fields.
//
// Out of scope for the OpenAI↔Vertex work; stubs kept so the chain layer
// compiles and so the agent sub-chain has a parsing entry point.

absl::Status parseAgentRequest(absl::string_view body, AgentDialect dialect, AiRequest& req);

class AgentJsonRpcEncoder : public AiRequestEncoder {
public:
  absl::Status encode(const AiRequest& req, Buffer::Instance& out) override;
};

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
