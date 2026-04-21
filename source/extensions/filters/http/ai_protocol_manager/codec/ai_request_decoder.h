#pragma once

#include <memory>

#include "envoy/buffer/buffer.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_payload.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

// Request body decoder — produces an AiRequest from an incoming body.
//
// The filter handles two input shapes, dispatched by ProtocolKind:
//   - Plain JSON — inference APIs (OpenAI chat/completions, /completions,
//     /responses, /embeddings; Gemini generateContent). No envelope. The
//     AiRequest.jsonrpc_id and .method fields stay empty; parsing is driven
//     by InferenceMapping.
//   - JSON-RPC 2.0 — agent protocols (MCP, A2A-over-JSON-RPC). The
//     {jsonrpc,id,method,params} envelope is honored; parsing then
//     dispatches to AgentMapping.
//
// DESIGN.md originally named this "JsonRpcDecoder"; that name was rooted in
// the agent protocol and did not cover the inference path. The type and file
// are renamed to reflect the neutral AiRequest contract.
//
// V0 is a whole-body decoder: feed bytes with onData, mark end with
// onEndStream, then call take() to consume the resulting AiRequest.

struct DecoderConfig {
  // Maximum inline bytes before a field is offloaded to PayloadStore as
  // External. Zero disables offload (everything Inline/Buffered).
  std::size_t max_inline_bytes{0};
};

class AiRequestDecoder : public Logger::Loggable<Logger::Id::filter> {
public:
  AiRequestDecoder(const DecoderConfig& config, PayloadStore& store, ProtocolKind protocol);

  absl::Status onData(absl::string_view chunk);
  absl::Status onEndStream();
  absl::StatusOr<AiRequest> take();

private:
  DecoderConfig config_;
  PayloadStore& store_;
  ProtocolKind protocol_;
  std::unique_ptr<Buffer::Instance> accumulator_;
  bool ended_{false};
};

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
