#pragma once

#include <any>
#include <string>
#include <variant>

#include "source/extensions/filters/http/ai_protocol_manager/codec/agent_payload.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_payload.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/inference_payload.h"

#include "absl/container/flat_hash_map.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

// DESIGN.md §4.1 — shared envelope + variant payload.

enum class ProtocolKind { Unknown, Inference, AgentA2a, AgentMcp };

// Per-filter scratch shared across sub-chain filters; not serialized, not
// cross-request.
using AiScratch = absl::flat_hash_map<std::string, std::any>;

class AiRequest {
public:
  AiRequest() = default;

  // --- JSON-RPC identity ---
  std::string jsonrpc_id;  // empty ⇒ notification
  std::string method;      // raw "method" token

  // --- Protocol discriminator + variant payload ---
  ProtocolKind protocol{ProtocolKind::Unknown};
  std::variant<std::monostate, InferencePayload, AgentPayload> payload;

  // --- Neutral scalars that arrived with the request (tenant, user id,
  //     request-id, routing hints). Cross-cutting filters read from here. ---
  absl::flat_hash_map<std::string, std::string> attributes;

  // --- Streaming intent (OpenAI stream:true, A2A/MCP SSE subscribe). ---
  bool streaming{false};

  // --- Payload offload: not owned; outer filter owns the store. ---
  PayloadStore* payload_store{nullptr};

  // --- Filter-to-filter scratch within this request. ---
  AiScratch scratch;

  // --- Typed accessors. Return nullptr on wrong variant. ---
  InferencePayload* asInference();
  const InferencePayload* asInference() const;
  AgentPayload* asAgent();
  const AgentPayload* asAgent() const;
};

// Response envelope — kept minimal for V0. DESIGN.md §4.1.5 notes we apply the
// same envelope+variant pattern if response-side logic grows protocol-specific.
struct AiResponse {
  int status_code{0};
  absl::flat_hash_map<std::string, std::string> headers;
  // Response body is left as a raw buffer handle in V0; the response-side
  // variant is specified when we design the response phase.
  std::unique_ptr<Buffer::Instance> body;
};

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
