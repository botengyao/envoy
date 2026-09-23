#pragma once

#include "source/extensions/filters/http/ai_protocol_manager/transcoding/response_transcoder.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Gemini generateContent -> OpenAI Chat Completions (the IR).
ResponseStreamTranscoderPtr createGeminiToOpenAiStreamTranscoder(const ResponseContext& context);
absl::StatusOr<nlohmann::json> transcodeGeminiToOpenAiUnary(nlohmann::json body,
                                                            const ResponseContext& context);

// OpenAI Chat Completions (the IR) -> Gemini generateContent.
ResponseStreamTranscoderPtr createOpenAiToGeminiStreamTranscoder(const ResponseContext& context);
absl::StatusOr<nlohmann::json> transcodeOpenAiToGeminiUnary(nlohmann::json body,
                                                            const ResponseContext& context);

// The four functions above as the dialect's response codec.
const ResponseCodec& geminiGenerateContentResponseCodec();

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
