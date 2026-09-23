#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "envoy/common/pure.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// One Server-Sent Events frame as a response transcoder sees it.
struct SseFrame {
  // The `event:` name; empty for the default "message".
  std::string event;
  // The data payload when it parsed as JSON. It may hold ExternalRef nodes for values the SSE
  // decoder offloaded; a transcoder may copy such nodes but never read them.
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

// What a transcoder knows about the request that produced the response.
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

// Transcodes a response stream frame by frame. Frames in and out need not correspond: a
// transcoder may emit several frames for one, or none.
class ResponseStreamTranscoder {
public:
  virtual ~ResponseStreamTranscoder() = default;

  // Transcodes one upstream frame, appending any output frames to `out`.
  virtual absl::Status onFrame(SseFrame frame, std::vector<SseFrame>& out) PURE;

  // Called once after the last frame, to append closing frames such as OpenAI's "[DONE]".
  virtual absl::Status onEnd(std::vector<SseFrame>& out) PURE;
};

using ResponseStreamTranscoderPtr = std::unique_ptr<ResponseStreamTranscoder>;

// One dialect's single-hop response codec, to and from the IR (OpenAI Chat Completions).
struct ResponseCodec {
  ResponseStreamTranscoderPtr (*stream_to_ir)(const ResponseContext& context);
  ResponseStreamTranscoderPtr (*stream_from_ir)(const ResponseContext& context);
  absl::StatusOr<nlohmann::json> (*unary_to_ir)(nlohmann::json body,
                                                const ResponseContext& context);
  absl::StatusOr<nlohmann::json> (*unary_from_ir)(nlohmann::json body,
                                                  const ResponseContext& context);
};

// A transcoder between two sides, each given by its codec or by nullptr for the IR, chaining
// through the IR when neither side is the IR. nullptr when both sides are the IR.
ResponseStreamTranscoderPtr createResponseStreamTranscoderViaIr(const ResponseCodec* from,
                                                                const ResponseCodec* to,
                                                                const ResponseContext& context);

// Transcodes a whole unary response body between two sides given as above. Returns `body`
// unchanged when both sides are the IR.
absl::StatusOr<nlohmann::json> transcodeUnaryResponseViaIr(const ResponseCodec* from,
                                                           const ResponseCodec* to,
                                                           nlohmann::json body,
                                                           const ResponseContext& context);

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
