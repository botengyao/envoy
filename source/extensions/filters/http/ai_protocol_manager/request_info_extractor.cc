#include "source/extensions/filters/http/ai_protocol_manager/request_info_extractor.h"

#include <limits>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/numbers.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

constexpr absl::string_view Model = "model";
constexpr absl::string_view Stream = "stream";
constexpr absl::string_view AnthropicVersion = "anthropic_version";
constexpr absl::string_view Messages = "messages";
constexpr absl::string_view Input = "input";
constexpr absl::string_view Contents = "contents";
constexpr absl::string_view Tools = "tools";
constexpr absl::string_view MaxCompletionTokens = "max_completion_tokens";
constexpr absl::string_view MaxOutputTokens = "max_output_tokens";
constexpr absl::string_view MaxTokens = "max_tokens";
constexpr absl::string_view GenerationConfig = "generationConfig";
constexpr absl::string_view GenerationConfigSnake = "generation_config";
constexpr absl::string_view MaxOutputTokensCamel = "maxOutputTokens";

} // namespace

RequestInfoExtractor::RequestInfoExtractor() : cursor_(*this) {}

absl::Status RequestInfoExtractor::feed(absl::string_view chunk, bool closed) {
  if (!status_.ok()) {
    return status_;
  }
  if (input_closed_) {
    return absl::FailedPreconditionError("request info: feed called after end of input");
  }

  const absl::Status cursor_status = cursor_.feed(chunk, closed);
  // A callback without a Status return may have reported a more specific
  // resource error through status_. Preserve it over the cursor's result.
  if (!status_.ok()) {
    return status_;
  }
  if (!cursor_status.ok()) {
    status_ = cursor_status;
    return status_;
  }

  input_closed_ = closed;
  if (closed && !root_closed_) {
    status_ = absl::InvalidArgumentError("request info: incomplete JSON root value");
  }
  return status_;
}

ApiProtocol RequestInfoExtractor::bodyDetectedProtocol() const {
  if (saw_anthropic_marker_ == saw_gemini_marker_) {
    return ApiProtocol::Unspecified;
  }
  return saw_anthropic_marker_ ? ApiProtocol::AnthropicMessages
                               : ApiProtocol::GeminiGenerateContent;
}

RequestInfo RequestInfoExtractor::finalizeForProtocol(ApiProtocol protocol) const {
  RequestInfo result = request_info_;
  result.api_protocol = protocol;
  result.tool_count = tools_count_;

  switch (protocol) {
  case ApiProtocol::OpenAiChatCompletions:
    result.max_output_tokens =
        max_completion_tokens_.has_value() ? max_completion_tokens_ : max_tokens_;
    result.message_count = messages_count_;
    break;
  case ApiProtocol::OpenAiResponses:
    result.max_output_tokens = top_level_max_output_tokens_;
    result.message_count = input_count_;
    break;
  case ApiProtocol::AnthropicMessages:
    result.max_output_tokens = max_tokens_;
    result.message_count = messages_count_;
    break;
  case ApiProtocol::GeminiGenerateContent:
    result.max_output_tokens = gemini_max_output_tokens_camel_.has_value()
                                   ? gemini_max_output_tokens_camel_
                                   : gemini_max_output_tokens_snake_;
    result.message_count = contents_count_;
    break;
  case ApiProtocol::Unspecified:
    break;
  }
  return result;
}

bool RequestInfoExtractor::openStringCapture(absl::string_view key, int depth, size_t) {
  countArrayScalar(depth, key);

  // The marker's string type is the evidence; its value is neither needed nor
  // retained.
  observing_anthropic_marker_ = depth == 1 && key == AnthropicVersion;
  if (observing_anthropic_marker_) {
    return false;
  }

  capturing_model_ = depth == 1 && key == Model;
  if (!capturing_model_) {
    return false;
  }
  pending_model_.clear();
  model_over_limit_ = false;
  return true;
}

bool RequestInfoExtractor::onStringChunk(absl::string_view, int, absl::string_view chunk) {
  if (model_over_limit_) {
    return false;
  }
  if (chunk.size() > MaxModelBytes - pending_model_.size()) {
    pending_model_.clear();
    model_over_limit_ = true;
    return false;
  }
  pending_model_.append(chunk.data(), chunk.size());
  return true;
}

void RequestInfoExtractor::closeStringCapture(absl::string_view, int depth, size_t) {
  if (depth == 0) {
    root_closed_ = true;
  }
  if (observing_anthropic_marker_) {
    saw_anthropic_marker_ = true;
    observing_anthropic_marker_ = false;
    return;
  }
  if (!capturing_model_) {
    return;
  }
  if (model_over_limit_) {
    request_info_.model.reset();
  } else {
    request_info_.model = std::move(pending_model_);
  }
  pending_model_.clear();
  capturing_model_ = false;
  model_over_limit_ = false;
}

absl::Status RequestInfoExtractor::onKey(absl::string_view, int, size_t) {
  return absl::OkStatus();
}

absl::Status RequestInfoExtractor::onNumber(absl::string_view key, absl::string_view raw, int depth,
                                            size_t, size_t) {
  countArrayScalar(depth, key);
  if (depth == 0) {
    root_closed_ = true;
  }

  uint64_t value = 0;
  if (!absl::SimpleAtoi(raw, &value)) {
    // A syntactically valid non-uint number is not an integer token limit.
    return status_;
  }
  if (depth == 1) {
    recordTopLevelLimit(key, value);
  } else if (depth == 2 && in_generation_config_) {
    recordGeminiLimit(key, value);
  }
  return status_;
}

absl::Status RequestInfoExtractor::onBoolean(absl::string_view key, bool value, int depth, size_t,
                                             size_t) {
  countArrayScalar(depth, key);
  if (depth == 0) {
    root_closed_ = true;
  }
  if (depth == 1 && key == Stream) {
    request_info_.streaming = value;
  }
  return status_;
}

void RequestInfoExtractor::onNull(absl::string_view key, int depth, size_t, size_t) {
  countArrayScalar(depth, key);
  if (depth == 0) {
    root_closed_ = true;
  }
}

void RequestInfoExtractor::onContainerOpen(absl::string_view key, bool is_dict, int depth, size_t) {
  if (active_array_ != CountedArray::None && depth == 3) {
    incrementActiveArray();
  }

  if (depth != 2) {
    return;
  }
  if (is_dict && (key == GenerationConfig || key == GenerationConfigSnake)) {
    in_generation_config_ = true;
    saw_gemini_marker_ = true;
    return;
  }
  if (!is_dict) {
    beginCountedArray(key);
  }
}

void RequestInfoExtractor::onContainerClose(int depth, size_t) {
  if (depth == 2) {
    completeCountedArray();
    active_array_ = CountedArray::None;
    in_generation_config_ = false;
  } else if (depth == 1) {
    root_closed_ = true;
  }
}

void RequestInfoExtractor::beginCountedArray(absl::string_view key) {
  if (key == Messages) {
    active_array_ = CountedArray::Messages;
  } else if (key == Input) {
    active_array_ = CountedArray::Input;
  } else if (key == Contents) {
    active_array_ = CountedArray::Contents;
  } else if (key == Tools) {
    active_array_ = CountedArray::Tools;
  } else {
    return;
  }

  active_array_count_ = 0;
}

void RequestInfoExtractor::completeCountedArray() {
  switch (active_array_) {
  case CountedArray::Messages:
    messages_count_ = active_array_count_;
    break;
  case CountedArray::Input:
    input_count_ = active_array_count_;
    break;
  case CountedArray::Contents:
    contents_count_ = active_array_count_;
    break;
  case CountedArray::Tools:
    tools_count_ = active_array_count_;
    break;
  case CountedArray::None:
    break;
  }
}

void RequestInfoExtractor::countArrayScalar(int depth, absl::string_view key) {
  if (active_array_ != CountedArray::None && depth == 2 && key.empty()) {
    incrementActiveArray();
  }
}

void RequestInfoExtractor::incrementActiveArray() {
  if (active_array_ == CountedArray::None) {
    return;
  }
  if (active_array_count_ == std::numeric_limits<uint32_t>::max()) {
    status_ = absl::ResourceExhaustedError("request info: counted array exceeds uint32 range");
    return;
  }
  ++active_array_count_;
}

void RequestInfoExtractor::recordTopLevelLimit(absl::string_view key, uint64_t value) {
  if (key == MaxCompletionTokens) {
    max_completion_tokens_ = value;
  } else if (key == MaxOutputTokens) {
    top_level_max_output_tokens_ = value;
  } else if (key == MaxTokens) {
    max_tokens_ = value;
  } else {
    return;
  }
}

void RequestInfoExtractor::recordGeminiLimit(absl::string_view key, uint64_t value) {
  if (key == MaxOutputTokensCamel) {
    gemini_max_output_tokens_camel_ = value;
  } else if (key == MaxOutputTokens) {
    gemini_max_output_tokens_snake_ = value;
  } else {
    return;
  }
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
