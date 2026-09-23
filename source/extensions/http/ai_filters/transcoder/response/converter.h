#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "envoy/common/pure.h"

#include "source/extensions/filters/http/ai_protocol_manager/token_usage.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

using HttpFilters::AiProtocolManager::LLMProtocol;

// One Server-Sent Events frame as the converters see it.
struct SseFrame {
  // The `event:` name; empty for the default "message".
  std::string event;
  // The data payload when it parsed as JSON. It may hold ExternalRef nodes for values the SSE
  // decoder offloaded; converters may copy such nodes but never read them.
  std::optional<nlohmann::json> json;
  // The data payload when it is not JSON, such as OpenAI's "[DONE]".
  std::string data;

  static SseFrame ofJson(nlohmann::json payload, std::string event = "") {
    SseFrame frame;
    frame.event = std::move(event);
    frame.json = std::move(payload);
    return frame;
  }
  static SseFrame ofData(std::string payload, std::string event = "") {
    SseFrame frame;
    frame.event = std::move(event);
    frame.data = std::move(payload);
    return frame;
  }
};

// What a converter knows about the request that produced the response.
struct ResponseContext {
  // The model the upstream was asked for; used when the response does not name one.
  std::string model;
  // Seconds since the epoch, for OpenAI's `created`.
  int64_t created{0};
  // The client set OpenAI's `stream_options.include_usage`.
  bool include_usage{false};
  // Report usage on an OpenAI stream even when the client did not ask for it, on the chunk that
  // carries `finish_reason` (Upstream.StreamUsage.ALWAYS).
  bool always_report_usage{true};
};

// Converts a response stream frame by frame. Frames in and out need not correspond: a converter
// may emit several frames for one, or none.
class StreamConverter {
public:
  virtual ~StreamConverter() = default;

  // Converts one upstream frame, appending any output frames to `out`.
  virtual absl::Status onFrame(SseFrame frame, std::vector<SseFrame>& out) PURE;

  // Called once after the last frame, to append closing frames such as OpenAI's "[DONE]".
  virtual absl::Status onEnd(std::vector<SseFrame>& out) PURE;
};

using StreamConverterPtr = std::unique_ptr<StreamConverter>;

// Whether a response in `from` can be converted to `to`.
bool responseConversionSupported(LLMProtocol from, LLMProtocol to);

// A converter from `from` to `to`, through the IR when neither side is the IR; nullptr when the
// protocols match. InvalidArgument for an unsupported pair.
absl::StatusOr<StreamConverterPtr> createStreamConverter(LLMProtocol from, LLMProtocol to,
                                                         const ResponseContext& context);

// Converts a whole unary response body from `from` to `to`, through the IR when neither side is
// the IR. Returns `body` unchanged when the protocols match.
absl::StatusOr<nlohmann::json> convertUnaryResponse(LLMProtocol from, LLMProtocol to,
                                                    nlohmann::json body,
                                                    const ResponseContext& context);

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
