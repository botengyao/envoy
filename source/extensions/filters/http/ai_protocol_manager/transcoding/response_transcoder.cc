#include "source/extensions/filters/http/ai_protocol_manager/transcoding/response_transcoder.h"

#include <utility>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

// Feeds every frame the first transcoder emits into the second.
class ChainedResponseStreamTranscoder : public ResponseStreamTranscoder {
public:
  ChainedResponseStreamTranscoder(ResponseStreamTranscoderPtr first,
                                  ResponseStreamTranscoderPtr second)
      : first_(std::move(first)), second_(std::move(second)) {}

  absl::Status onFrame(SseFrame frame, std::vector<SseFrame>& out) override {
    std::vector<SseFrame> middle;
    if (absl::Status status = first_->onFrame(std::move(frame), middle); !status.ok()) {
      return status;
    }
    return forward(middle, out);
  }

  absl::Status onEnd(std::vector<SseFrame>& out) override {
    std::vector<SseFrame> middle;
    if (absl::Status status = first_->onEnd(middle); !status.ok()) {
      return status;
    }
    if (absl::Status status = forward(middle, out); !status.ok()) {
      return status;
    }
    return second_->onEnd(out);
  }

private:
  absl::Status forward(std::vector<SseFrame>& middle, std::vector<SseFrame>& out) {
    for (SseFrame& frame : middle) {
      if (absl::Status status = second_->onFrame(std::move(frame), out); !status.ok()) {
        return status;
      }
    }
    return absl::OkStatus();
  }

  ResponseStreamTranscoderPtr first_;
  ResponseStreamTranscoderPtr second_;
};

// The intermediate IR stream always carries usage, so the second transcoder can report it.
ResponseContext intermediateContext(const ResponseContext& context) {
  ResponseContext intermediate = context;
  intermediate.include_usage = false;
  intermediate.always_report_usage = true;
  return intermediate;
}

} // namespace

ResponseStreamTranscoderPtr createResponseStreamTranscoderViaIr(const ResponseCodec* from,
                                                                const ResponseCodec* to,
                                                                const ResponseContext& context) {
  if (from == nullptr) {
    return to == nullptr ? nullptr : to->stream_from_ir(context);
  }
  if (to == nullptr) {
    return from->stream_to_ir(context);
  }
  return std::make_unique<ChainedResponseStreamTranscoder>(
      from->stream_to_ir(intermediateContext(context)), to->stream_from_ir(context));
}

absl::StatusOr<nlohmann::json> transcodeUnaryResponseViaIr(const ResponseCodec* from,
                                                           const ResponseCodec* to,
                                                           nlohmann::json body,
                                                           const ResponseContext& context) {
  if (from != nullptr) {
    absl::StatusOr<nlohmann::json> ir = from->unary_to_ir(std::move(body), context);
    if (!ir.ok() || to == nullptr) {
      return ir;
    }
    body = std::move(ir.value());
  }
  if (to == nullptr) {
    return body;
  }
  return to->unary_from_ir(std::move(body), context);
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
