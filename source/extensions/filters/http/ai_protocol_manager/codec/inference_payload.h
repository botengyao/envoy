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
  // Audio, Moderations, Images — added as needed.
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
  // Rarer knobs (presence_penalty, frequency_penalty, logprobs, ...) live in
  // InferencePayload::extra_params to keep this struct narrow.
};

struct InferencePayload {
  InferenceInvocation invocation{InferenceInvocation::Unknown};
  ModelTarget target;

  // Potentially large — always PayloadRef so the decoder can offload.
  std::vector<PayloadRef> messages;     // chat turns
  std::vector<PayloadRef> tools;        // tool / function definitions
  std::vector<PayloadRef> attachments;  // images, audio, files

  // tool_choice, response_format, service_tier, user, plus any params the
  // mapper didn't claim. String-valued because the decoder stores raw JSON
  // fragments here; callers re-parse when needed.
  absl::flat_hash_map<std::string, std::string> extra_params;

  SamplingParams sampling;

  bool streaming{false};

  // Everything the mapper did not pull apart — keeps pass-through honest.
  PayloadRef residual_params;
};

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
