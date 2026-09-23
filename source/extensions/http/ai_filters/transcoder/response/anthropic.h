#pragma once

#include "source/extensions/http/ai_filters/transcoder/response/converter.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

// Anthropic Messages -> OpenAI Chat Completions (the IR).
StreamConverterPtr createAnthropicToOpenAiStreamConverter(const ResponseContext& context);
absl::StatusOr<nlohmann::json> convertAnthropicToOpenAiUnary(nlohmann::json body,
                                                             const ResponseContext& context);

// OpenAI Chat Completions (the IR) -> Anthropic Messages.
StreamConverterPtr createOpenAiToAnthropicStreamConverter(const ResponseContext& context);
absl::StatusOr<nlohmann::json> convertOpenAiToAnthropicUnary(nlohmann::json body,
                                                             const ResponseContext& context);

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
