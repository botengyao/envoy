#pragma once

#include <memory>

#include "envoy/buffer/buffer.h"

#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

// Request body encoder — dual of AiRequestDecoder.
//
// Emits either plain JSON (inference APIs — OpenAI, Gemini, embeddings) or
// JSON-RPC 2.0 (agent APIs — MCP, A2A) depending on the concrete encoder. The
// decision of *which* encoder runs belongs to the dispatch layer, which is
// the only place that knows both the AiRequest's protocol family and the
// target backend's expected schema.
//
// DESIGN.md originally named this "JsonRpcEncoder"; the interface is
// shape-agnostic and the type is renamed to match the neutral AiRequest
// contract.
class AiRequestEncoder {
public:
  virtual ~AiRequestEncoder() = default;

  // Encode `req` into `out`. Returns error for malformed or unsupported
  // requests; implementations should produce actionable status messages.
  virtual absl::Status encode(const AiRequest& req, Buffer::Instance& out) = 0;
};

using AiRequestEncoderPtr = std::unique_ptr<AiRequestEncoder>;

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
