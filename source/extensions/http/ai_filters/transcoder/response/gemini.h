#pragma once

#include "source/extensions/http/ai_filters/transcoder/response/converter.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

// Gemini generateContent -> OpenAI Chat Completions (the IR).
StreamConverterPtr createGeminiToOpenAiStreamConverter(const ResponseContext& context);
absl::StatusOr<nlohmann::json> convertGeminiToOpenAiUnary(nlohmann::json body,
                                                          const ResponseContext& context);

// OpenAI Chat Completions (the IR) -> Gemini generateContent.
StreamConverterPtr createOpenAiToGeminiStreamConverter(const ResponseContext& context);
absl::StatusOr<nlohmann::json> convertOpenAiToGeminiUnary(nlohmann::json body,
                                                          const ResponseContext& context);

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
