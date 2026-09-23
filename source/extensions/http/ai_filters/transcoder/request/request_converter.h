#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/transcoding_engine.h"
#include "source/extensions/http/ai_filters/transcoder/request/client_request.h"

#include "absl/status/status.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

struct RequestConversionOptions {
  // `max_tokens` sent to Anthropic when the request sets no output cap.
  uint32_t default_max_output_tokens{4096};
  // Fail on a field the upstream's protocol cannot express, rather than dropping it.
  bool reject_unsupported_fields{false};
};

// Converts a request body in place from `from` to `to`, `from != to`: through the IR when `from`
// is not the IR, then prepared for, pruned to, and validated against `to`'s request schema.
// `client` carries what the client asked for; Gemini keeps the model and streaming choice out of
// the body. The model is left in the body for protocols that carry it there, for the endpoint to
// place. `dropped` receives the request fields `to` cannot express. InvalidArgument when the
// request cannot be expressed in `to`, or a dropped field is rejected by `options`.
absl::Status convertRequest(const HttpFilters::AiProtocolManager::TranscodingEngine& engine,
                            LLMProtocol from, LLMProtocol to, nlohmann::json& body,
                            const ClientRequest& client, const RequestConversionOptions& options,
                            std::vector<std::string>& dropped);

// Converts a request body in place from `from` to the IR, with the model and streaming choice
// placed in the body even when `from` keeps them in the path.
absl::Status convertRequestToIr(const HttpFilters::AiProtocolManager::TranscodingEngine& engine,
                                LLMProtocol from, nlohmann::json& body,
                                const ClientRequest& client);

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
