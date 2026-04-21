#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_payload.h"

#include "absl/container/flat_hash_map.h"
#include "absl/types/optional.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

// DESIGN.md §4.1 Inference variant.

enum class InferenceInvocation {
  Unknown,
  ChatCompletion,  // POST /v1/chat/completions
  Completion,      // POST /v1/completions
  Responses,       // POST /v1/responses
  Embeddings,      // POST /v1/embeddings
};

struct ModelTarget {
  std::string name;           // e.g. "gpt-4o-mini", "gemini-1.5-pro"
  std::string provider_hint;  // optional: "openai", "vertex", "anthropic"
};

struct SamplingParams {
  absl::optional<double> temperature;
  absl::optional<double> top_p;
  absl::optional<int32_t> max_tokens;
  absl::optional<int32_t> n;
  std::vector<std::string> stop;
  absl::optional<int64_t> seed;
  absl::optional<double> frequency_penalty;
  absl::optional<double> presence_penalty;
};

// A single chat turn in parsed form. V0 covers text-only content; multimodal
// parts (image_url / input_audio) and thinking / refusal blocks are added in
// later phases of §2.1. Role is normalized: "system", "user", "assistant",
// "tool", "developer".
struct ChatMessage {
  std::string role;
  std::string text;
};

// OPENAI_VERTEX_SPEC.md §2.1 rule: system + developer messages merge into a
// single systemInstruction when encoded for Gemini. We keep them split out
// here because the OpenAI encoder needs them interleaved with user/assistant
// turns if it's ever used as the OPENAI_PASSTHROUGH encoder from a parsed
// payload (rather than residual bytes).
struct InferencePayload {
  InferenceInvocation invocation{InferenceInvocation::Unknown};
  ModelTarget target;

  // Parsed chat turns (user / assistant / tool). system / developer turns go
  // into `system_instructions` so the encoder can emit Gemini
  // systemInstruction cleanly.
  std::vector<ChatMessage> chat;
  std::vector<std::string> system_instructions;

  // Phase 3b: tools, tool_choice, response_format. Phase 3c: multimodal
  // attachments. Phase 3d: thinking / reasoning_effort. For 3a these are
  // carried forward only as residual bytes.

  SamplingParams sampling;

  bool streaming{false};

  // Raw body bytes, kept so the OPENAI_PASSTHROUGH encoder can round-trip
  // without re-synthesizing from parsed fields. Phase 3b+ will emit from
  // parsed fields directly.
  PayloadRef residual_params;
};

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
