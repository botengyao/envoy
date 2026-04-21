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

// OpenAI-side mapping for the Inference protocol family.
//
// Inference bodies are plain JSON, not JSON-RPC — no jsonrpc/id/method
// envelope — so the mapping parses the raw JSON body directly. The
// invocation kind (ChatCompletion / Completion / Responses / Embeddings)
// is derived from the request path and carried on the InferencePayload.
//
// Coverage planned by phase:
//   Phase 2: chat/completions (parse + emit OpenAI JSON, non-streaming).
//   Phase 4: embeddings.
//   Phase 5: streaming chunks.

absl::Status parseOpenAIInferenceRequest(absl::string_view body, InferenceInvocation invocation,
                                         AiRequest& req);

// Pass-through encoder that emits OpenAI-shaped JSON. Target-schema encoders
// (GeminiEncoder, Claude-on-Vertex encoder, ...) live alongside their
// dispatch implementations under dispatch/.
class OpenAiEncoder : public AiRequestEncoder {
public:
  absl::Status encode(const AiRequest& req, Buffer::Instance& out) override;
};

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
