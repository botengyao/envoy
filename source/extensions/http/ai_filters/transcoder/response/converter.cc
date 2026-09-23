#include "source/extensions/http/ai_filters/transcoder/response/converter.h"

#include <utility>

#include "source/extensions/http/ai_filters/transcoder/response/anthropic.h"
#include "source/extensions/http/ai_filters/transcoder/response/gemini.h"

#include "absl/strings/str_cat.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

namespace {

constexpr LLMProtocol IrProtocol = LLMProtocol::OpenAiChatCompletions;

bool hasIrConverters(LLMProtocol protocol) {
  return protocol == LLMProtocol::AnthropicMessages ||
         protocol == LLMProtocol::GeminiGenerateContent;
}

StreamConverterPtr toIrStream(LLMProtocol from, const ResponseContext& context) {
  return from == LLMProtocol::AnthropicMessages ? createAnthropicToOpenAiStreamConverter(context)
                                                : createGeminiToOpenAiStreamConverter(context);
}

StreamConverterPtr fromIrStream(LLMProtocol to, const ResponseContext& context) {
  return to == LLMProtocol::AnthropicMessages ? createOpenAiToAnthropicStreamConverter(context)
                                              : createOpenAiToGeminiStreamConverter(context);
}

// Feeds every frame the first converter emits into the second.
class ChainedStreamConverter : public StreamConverter {
public:
  ChainedStreamConverter(StreamConverterPtr first, StreamConverterPtr second)
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

  StreamConverterPtr first_;
  StreamConverterPtr second_;
};

absl::Status unsupported(LLMProtocol from, LLMProtocol to) {
  return absl::InvalidArgumentError(absl::StrCat(
      "no response conversion from ", llmProtocolName(from), " to ", llmProtocolName(to)));
}

// The intermediate IR stream always carries usage, so the second converter can report it.
ResponseContext intermediateContext(const ResponseContext& context) {
  ResponseContext intermediate = context;
  intermediate.include_usage = false;
  intermediate.always_report_usage = true;
  return intermediate;
}

} // namespace

bool responseConversionSupported(LLMProtocol from, LLMProtocol to) {
  if (from == to) {
    return true;
  }
  return (from == IrProtocol || hasIrConverters(from)) && (to == IrProtocol || hasIrConverters(to));
}

absl::StatusOr<StreamConverterPtr> createStreamConverter(LLMProtocol from, LLMProtocol to,
                                                         const ResponseContext& context) {
  if (from == to) {
    return nullptr;
  }
  if (!responseConversionSupported(from, to)) {
    return unsupported(from, to);
  }
  if (to == IrProtocol) {
    return toIrStream(from, context);
  }
  if (from == IrProtocol) {
    return fromIrStream(to, context);
  }
  return std::make_unique<ChainedStreamConverter>(toIrStream(from, intermediateContext(context)),
                                                  fromIrStream(to, context));
}

absl::StatusOr<nlohmann::json> convertUnaryResponse(LLMProtocol from, LLMProtocol to,
                                                    nlohmann::json body,
                                                    const ResponseContext& context) {
  if (from == to) {
    return body;
  }
  if (!responseConversionSupported(from, to)) {
    return unsupported(from, to);
  }
  if (from != IrProtocol) {
    absl::StatusOr<nlohmann::json> ir =
        from == LLMProtocol::AnthropicMessages
            ? convertAnthropicToOpenAiUnary(std::move(body), context)
            : convertGeminiToOpenAiUnary(std::move(body), context);
    if (!ir.ok() || to == IrProtocol) {
      return ir;
    }
    body = std::move(ir.value());
  }
  return to == LLMProtocol::AnthropicMessages
             ? convertOpenAiToAnthropicUnary(std::move(body), context)
             : convertOpenAiToGeminiUnary(std::move(body), context);
}

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
