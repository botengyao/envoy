#pragma once

#include <string>

#include "source/extensions/filters/http/ai_protocol_manager/token_usage.h"

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

using HttpFilters::AiProtocolManager::LLMProtocol;

// What the client asked for, wherever its protocol keeps it.
struct ClientRequest {
  std::string model;
  bool stream{false};
  // OpenAI's `stream_options.include_usage`.
  bool include_usage{false};
};

// Reads the model and streaming choice from the body for OpenAI Chat Completions and Anthropic
// Messages, and from the path for Gemini: `.../models/{model}:generateContent` or
// `...:streamGenerateContent`, Gemini API and Vertex AI paths alike, with a percent-encoded model
// decoded. InvalidArgument when the model cannot be found.
absl::StatusOr<ClientRequest> readClientRequest(LLMProtocol protocol, const nlohmann::json& body,
                                                absl::string_view path);

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
