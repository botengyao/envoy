#pragma once

#include "source/extensions/filters/http/ai_protocol_manager/transcoding/response_transcoder.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Anthropic Messages -> OpenAI Chat Completions (the IR).
ResponseStreamTranscoderPtr createAnthropicToOpenAiStreamTranscoder(const ResponseContext& context);
absl::StatusOr<nlohmann::json> transcodeAnthropicToOpenAiUnary(nlohmann::json body,
                                                               const ResponseContext& context);

// OpenAI Chat Completions (the IR) -> Anthropic Messages.
ResponseStreamTranscoderPtr createOpenAiToAnthropicStreamTranscoder(const ResponseContext& context);
absl::StatusOr<nlohmann::json> transcodeOpenAiToAnthropicUnary(nlohmann::json body,
                                                               const ResponseContext& context);

// The four functions above as the dialect's response codec.
const ResponseCodec& anthropicMessagesResponseCodec();

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
