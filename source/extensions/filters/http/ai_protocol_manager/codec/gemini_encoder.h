#pragma once

#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request_encoder.h"

#include "absl/status/status.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

// Gemini generateContent encoder.
//
// Re-emits AiRequest.InferencePayload as a Gemini GenerateContentRequest JSON
// body per OPENAI_VERTEX_SPEC.md §2 and §2.1. Phase 3a covers the core subset:
//   - contents[] with role user/model and single text part
//   - systemInstruction merged from all system / developer OpenAI messages
//   - generationConfig (temperature, topP, maxOutputTokens, stopSequences, ...)
//
// Phase 3b: tools.functionDeclarations, toolConfig.functionCallingConfig,
// responseFormat.
// Phase 3c: multimodal content parts (inlineData / fileData).
// Phase 3d: thinkingConfig, reasoningEffort mapping.
// Phase 3e: safety_settings, vendor fields, model-version feature gates.
class GeminiEncoder : public AiRequestEncoder {
public:
  absl::Status encode(const AiRequest& req, Buffer::Instance& out) override;
};

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
