#include "source/extensions/filters/http/ai_protocol_manager/transcoding/gemini_generate_content.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"

#include "absl/strings/ascii.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

using json = nlohmann::json;

constexpr absl::string_view DefaultResponseId = "chatcmpl-envoy";
constexpr absl::string_view OpenAiDone = "[DONE]";
constexpr uint64_t MaxCount = (uint64_t(1) << 53) - 1;
// Serializing arguments is recursive, and upstream argument text has no depth limit.
constexpr int MaxArgumentsDepth = 100;

constexpr absl::string_view ContentFilterReasons[] = {"SAFETY",
                                                      "RECITATION",
                                                      "BLOCKLIST",
                                                      "PROHIBITED_CONTENT",
                                                      "SPII",
                                                      "IMAGE_SAFETY",
                                                      "IMAGE_PROHIBITED_CONTENT",
                                                      "LANGUAGE"};

struct ErrorStatus {
  absl::string_view openai_type;
  const char* status;
  int code;
};

constexpr ErrorStatus ErrorStatuses[] = {
    {"invalid_request_error", "INVALID_ARGUMENT", 400},
    {"authentication_error", "UNAUTHENTICATED", 401},
    {"permission_error", "PERMISSION_DENIED", 403},
    {"not_found_error", "NOT_FOUND", 404},
    {"rate_limit_error", "RESOURCE_EXHAUSTED", 429},
    {"insufficient_quota", "RESOURCE_EXHAUSTED", 429},
    {"overloaded_error", "UNAVAILABLE", 503},
};

template <class Json> Json* member(Json& node, const char* key) {
  if (!node.is_object()) {
    return nullptr;
  }
  const auto it = node.find(key);
  return it == node.end() ? nullptr : &*it;
}

template <class Json> Json* objectMember(Json& node, const char* key) {
  Json* value = member(node, key);
  return value != nullptr && value->is_object() ? value : nullptr;
}

template <class Json> Json* arrayMember(Json& node, const char* key) {
  Json* value = member(node, key);
  return value != nullptr && value->is_array() ? value : nullptr;
}

std::string stringMember(const json& node, const char* key, absl::string_view fallback) {
  const json* value = member(node, key);
  if (value != nullptr && value->is_string() && !value->get_ref<const std::string&>().empty()) {
    return value->get<std::string>();
  }
  return std::string(fallback);
}

// Binary nodes are strings the SSE decoder offloaded: they may be copied but never read.
bool isText(const json& value) { return value.is_string() || value.is_binary(); }

bool isNonEmptyText(const json& value) {
  return value.is_binary() || (value.is_string() && !value.get_ref<const std::string&>().empty());
}

bool containsBinary(const json& value) {
  if (value.is_binary()) {
    return true;
  }
  if (value.is_structured()) {
    for (const json& child : value) {
      if (containsBinary(child)) {
        return true;
      }
    }
  }
  return false;
}

// ProtoJSON renders 64-bit integers as strings.
std::optional<uint64_t> readCount(const json& node, const char* key) {
  const json* value = member(node, key);
  if (value == nullptr) {
    return std::nullopt;
  }
  uint64_t count = 0;
  if (value->is_number_unsigned()) {
    count = value->get<uint64_t>();
  } else if (value->is_number_integer()) {
    const int64_t signed_count = value->get<int64_t>();
    if (signed_count < 0) {
      return std::nullopt;
    }
    count = static_cast<uint64_t>(signed_count);
  } else if (value->is_number_float()) {
    const double as_double = value->get<double>();
    if (!std::isfinite(as_double) || as_double < 0 || as_double > static_cast<double>(MaxCount) ||
        std::trunc(as_double) != as_double) {
      return std::nullopt;
    }
    count = static_cast<uint64_t>(as_double);
  } else if (!value->is_string() ||
             !absl::SimpleAtoi(value->get_ref<const std::string&>(), &count)) {
    return std::nullopt;
  }
  if (count > MaxCount) {
    return std::nullopt;
  }
  return count;
}

bool promptBlocked(const json& body) {
  const json* feedback = objectMember(body, "promptFeedback");
  return feedback != nullptr && !stringMember(*feedback, "blockReason", "").empty();
}

std::optional<json> openAiUsage(const json& metadata) {
  const std::optional<uint64_t> prompt = readCount(metadata, "promptTokenCount");
  const std::optional<uint64_t> tool_use = readCount(metadata, "toolUsePromptTokenCount");
  const std::optional<uint64_t> candidates = readCount(metadata, "candidatesTokenCount");
  const std::optional<uint64_t> thoughts = readCount(metadata, "thoughtsTokenCount");
  const std::optional<uint64_t> total = readCount(metadata, "totalTokenCount");
  const std::optional<uint64_t> cached = readCount(metadata, "cachedContentTokenCount");
  if (!prompt && !tool_use && !candidates && !thoughts && !total && !cached) {
    return std::nullopt;
  }
  const uint64_t prompt_tokens = prompt.value_or(0) + tool_use.value_or(0);
  const uint64_t completion_tokens = candidates.value_or(0) + thoughts.value_or(0);
  json usage = {{"prompt_tokens", prompt_tokens},
                {"completion_tokens", completion_tokens},
                {"total_tokens", total.value_or(prompt_tokens + completion_tokens)}};
  if (cached) {
    usage["prompt_tokens_details"] = {{"cached_tokens", *cached}};
  }
  if (thoughts) {
    usage["completion_tokens_details"] = {{"reasoning_tokens", *thoughts}};
  }
  return usage;
}

json openAiError(const json& error) {
  json converted = {
      {"message", ""}, {"type", stringMember(error, "status", "api_error")}, {"code", nullptr}};
  if (const json* message = member(error, "message"); message != nullptr && isText(*message)) {
    converted["message"] = *message;
  }
  if (const json* code = member(error, "code"); code != nullptr) {
    converted["code"] = *code;
  }
  json response = json::object();
  response["error"] = std::move(converted);
  return response;
}

const char* openAiFinishReason(absl::string_view reason, bool has_tool_calls) {
  if (reason == "STOP") {
    return has_tool_calls ? "tool_calls" : "stop";
  }
  if (reason == "MAX_TOKENS") {
    return "length";
  }
  if (std::find(std::begin(ContentFilterReasons), std::end(ContentFilterReasons), reason) !=
      std::end(ContentFilterReasons)) {
    return "content_filter";
  }
  return "stop";
}

struct CandidateParts {
  std::vector<json> texts;
  std::vector<const json*> calls;
};

// Moves the candidate's non-thought texts out; `calls` points into the candidate.
CandidateParts takeParts(json& candidate) {
  CandidateParts parts;
  json* content = objectMember(candidate, "content");
  json* list = content == nullptr ? nullptr : arrayMember(*content, "parts");
  if (list == nullptr) {
    return parts;
  }
  for (json& part : *list) {
    if (const json* call = objectMember(part, "functionCall"); call != nullptr) {
      parts.calls.push_back(call);
      continue;
    }
    const json* thought = member(part, "thought");
    if (thought != nullptr && thought->is_boolean() && thought->get<bool>()) {
      continue;
    }
    if (json* text = member(part, "text"); text != nullptr && isNonEmptyText(*text)) {
      parts.texts.push_back(std::move(*text));
    }
  }
  return parts;
}

// Joins adjacent strings; an offloaded piece stays on its own since it cannot be read.
std::vector<json> coalesceTexts(std::vector<json> texts) {
  std::vector<json> joined;
  for (json& text : texts) {
    if (text.is_string() && !joined.empty() && joined.back().is_string()) {
      joined.back().get_ref<std::string&>() += text.get_ref<const std::string&>();
    } else {
      joined.push_back(std::move(text));
    }
  }
  return joined;
}

absl::StatusOr<json> openAiToolCall(const json& call, uint64_t ordinal) {
  std::string arguments = "{}";
  if (const json* args = member(call, "args"); args != nullptr && !args->is_null()) {
    if (containsBinary(*args)) {
      return absl::UnimplementedError("Gemini functionCall args hold an offloaded value");
    }
    arguments = args->dump(-1, ' ', false, json::error_handler_t::replace);
  }
  json function = {{"name", ""}, {"arguments", std::move(arguments)}};
  if (const json* name = member(call, "name"); name != nullptr && isText(*name)) {
    function["name"] = *name;
  }
  json tool_call = {{"id", stringMember(call, "id", absl::StrCat("call_", ordinal))},
                    {"type", "function"}};
  tool_call["function"] = std::move(function);
  return tool_call;
}

// ProtoJSON omits the index of candidate 0.
json* candidateZero(json& candidates) {
  for (json& candidate : candidates) {
    if (readCount(candidate, "index").value_or(0) == 0) {
      return &candidate;
    }
  }
  return nullptr;
}

absl::StatusOr<json> openAiChoice(json& candidate, uint64_t position, uint64_t& calls_seen) {
  CandidateParts parts = takeParts(candidate);
  json tool_calls = json::array();
  for (const json* call : parts.calls) {
    absl::StatusOr<json> tool_call = openAiToolCall(*call, calls_seen++);
    if (!tool_call.ok()) {
      return tool_call.status();
    }
    tool_calls.push_back(std::move(*tool_call));
  }
  std::vector<json> texts = coalesceTexts(std::move(parts.texts));
  if (texts.size() > 1) {
    return absl::UnimplementedError("cannot join an offloaded Gemini text part");
  }
  const bool has_tool_calls = !tool_calls.empty();
  json message = {{"role", "assistant"}};
  if (!texts.empty()) {
    message["content"] = std::move(texts.front());
  } else {
    message["content"] = has_tool_calls ? json(nullptr) : json("");
  }
  if (has_tool_calls) {
    message["tool_calls"] = std::move(tool_calls);
  }
  json choice = {{"index", readCount(candidate, "index").value_or(position)},
                 {"finish_reason",
                  openAiFinishReason(stringMember(candidate, "finishReason", ""), has_tool_calls)}};
  choice["message"] = std::move(message);
  return choice;
}

class GeminiToOpenAiStream : public ResponseStreamTranscoder {
public:
  explicit GeminiToOpenAiStream(const ResponseContext& context) : context_(context) {}

  absl::Status onFrame(SseFrame frame, std::vector<SseFrame>& out) override {
    if (errored_ || !frame.json.has_value() || !frame.json->is_object()) {
      return absl::OkStatus();
    }
    json& body = *frame.json;
    if (const json* error = objectMember(body, "error"); error != nullptr) {
      out.push_back(SseFrame::ofJson(openAiError(*error)));
      errored_ = true;
      return absl::OkStatus();
    }
    if (!started_) {
      started_ = true;
      id_ = stringMember(body, "responseId", DefaultResponseId);
      model_ = stringMember(body, "modelVersion", context_.model);
      out.push_back(chunk({{"role", "assistant"}, {"content", ""}}, nullptr));
    }
    if (const json* metadata = objectMember(body, "usageMetadata"); metadata != nullptr) {
      if (std::optional<json> usage = openAiUsage(*metadata); usage.has_value()) {
        usage_ = std::move(usage);
      }
    }
    if (finished_) {
      return absl::OkStatus();
    }
    json* candidates = arrayMember(body, "candidates");
    if (candidates == nullptr || candidates->empty()) {
      if (promptBlocked(body)) {
        finish("content_filter", out);
      }
      return absl::OkStatus();
    }
    json* candidate = candidateZero(*candidates);
    if (candidate == nullptr) {
      return absl::OkStatus();
    }
    CandidateParts parts = takeParts(*candidate);
    for (json& text : coalesceTexts(std::move(parts.texts))) {
      json delta = json::object();
      delta["content"] = std::move(text);
      out.push_back(chunk(std::move(delta), nullptr));
    }
    for (const json* call : parts.calls) {
      absl::StatusOr<json> tool_call = openAiToolCall(*call, tool_calls_);
      if (!tool_call.ok()) {
        return tool_call.status();
      }
      (*tool_call)["index"] = tool_calls_++;
      json delta = {{"tool_calls", json::array()}};
      delta["tool_calls"].push_back(std::move(*tool_call));
      out.push_back(chunk(std::move(delta), nullptr));
    }
    if (const json* reason = member(*candidate, "finishReason");
        reason != nullptr && reason->is_string()) {
      finish(openAiFinishReason(reason->get_ref<const std::string&>(), tool_calls_ > 0), out);
    }
    return absl::OkStatus();
  }

  absl::Status onEnd(std::vector<SseFrame>& out) override {
    if (errored_ || !finished_) {
      return absl::OkStatus();
    }
    if (context_.include_usage && usage_.has_value()) {
      json usage_chunk = header();
      usage_chunk["choices"] = json::array();
      usage_chunk["usage"] = *usage_;
      out.push_back(SseFrame::ofJson(std::move(usage_chunk)));
    }
    out.push_back(SseFrame::ofData(std::string(OpenAiDone)));
    return absl::OkStatus();
  }

private:
  json header() const {
    return {{"id", id_},
            {"object", "chat.completion.chunk"},
            {"created", context_.created},
            {"model", model_}};
  }

  json chunkJson(json delta, json finish_reason) const {
    json choice = {{"index", 0}, {"finish_reason", std::move(finish_reason)}};
    choice["delta"] = std::move(delta);
    json result = header();
    result["choices"] = json::array();
    result["choices"].push_back(std::move(choice));
    return result;
  }

  SseFrame chunk(json delta, json finish_reason) const {
    return SseFrame::ofJson(chunkJson(std::move(delta), std::move(finish_reason)));
  }

  void finish(const char* reason, std::vector<SseFrame>& out) {
    finished_ = true;
    json result = chunkJson(json::object(), reason);
    if (context_.always_report_usage && !context_.include_usage && usage_.has_value()) {
      result["usage"] = *usage_;
    }
    out.push_back(SseFrame::ofJson(std::move(result)));
  }

  const ResponseContext context_;
  std::string id_;
  std::string model_;
  std::optional<json> usage_;
  uint64_t tool_calls_{0};
  bool started_{false};
  bool finished_{false};
  bool errored_{false};
};

const ErrorStatus* errorStatus(const json& error) {
  const std::string type = stringMember(error, "type", "");
  for (const ErrorStatus& mapping : ErrorStatuses) {
    if (mapping.openai_type == type) {
      return &mapping;
    }
  }
  const json* code = member(error, "code");
  if (code == nullptr || !code->is_number_integer()) {
    return nullptr;
  }
  for (const ErrorStatus& mapping : ErrorStatuses) {
    if (*code == mapping.code) {
      return &mapping;
    }
  }
  return nullptr;
}

json geminiError(const json& error) {
  const ErrorStatus* mapping = errorStatus(error);
  json converted = {{"code", mapping == nullptr ? 500 : mapping->code},
                    {"message", ""},
                    {"status", mapping == nullptr ? "INTERNAL" : mapping->status}};
  if (const json* numeric = member(error, "code");
      numeric != nullptr && numeric->is_number_integer()) {
    converted["code"] = *numeric;
  }
  if (const json* message = member(error, "message"); message != nullptr && isText(*message)) {
    converted["message"] = *message;
  }
  json response = json::object();
  response["error"] = std::move(converted);
  return response;
}

const char* geminiFinishReason(absl::string_view reason) {
  if (reason == "length") {
    return "MAX_TOKENS";
  }
  if (reason == "content_filter") {
    return "SAFETY";
  }
  return "STOP";
}

// A tool call cut off at the token limit has partial arguments, and Gemini has no partial calls.
bool dropsUnparsableCalls(absl::string_view finish_reason) { return finish_reason == "length"; }

TokenUsage readOpenAiUsage(const json& document) {
  return AdapterRegistry::get(LLMProtocol::OpenAiChatCompletions).extractUsage(document).usage;
}

json geminiUsage(const TokenUsage& usage) {
  json metadata = json::object();
  if (usage.input_tokens) {
    metadata["promptTokenCount"] = *usage.input_tokens;
  }
  if (usage.output_tokens) {
    metadata["candidatesTokenCount"] =
        *usage.output_tokens - std::min(*usage.output_tokens, usage.reasoning_tokens.value_or(0));
  }
  if (usage.total_tokens) {
    metadata["totalTokenCount"] = *usage.total_tokens;
  }
  if (usage.reasoning_tokens) {
    metadata["thoughtsTokenCount"] = *usage.reasoning_tokens;
  }
  if (usage.cached_input_tokens) {
    metadata["cachedContentTokenCount"] = *usage.cached_input_tokens;
  }
  return metadata;
}

absl::StatusOr<json> functionCallPart(std::string name, absl::string_view arguments) {
  json args = json::object();
  if (!absl::StripAsciiWhitespace(arguments).empty()) {
    bool too_deep = false;
    args = json::parse(
        arguments.begin(), arguments.end(),
        [&too_deep](int depth, json::parse_event_t event, json&) {
          if (depth > MaxArgumentsDepth && (event == json::parse_event_t::object_start ||
                                            event == json::parse_event_t::array_start)) {
            too_deep = true;
            return false;
          }
          return true;
        },
        /*allow_exceptions=*/false);
    if (too_deep) {
      return absl::InvalidArgumentError(absl::StrCat(
          "tool call '", name, "' arguments nest deeper than ", MaxArgumentsDepth, " levels"));
    }
    if (args.is_discarded() || !args.is_object()) {
      return absl::InvalidArgumentError(
          absl::StrCat("tool call '", name, "' arguments are not a JSON object"));
    }
  }
  json call = {{"name", std::move(name)}};
  call["args"] = std::move(args);
  json part = json::object();
  part["functionCall"] = std::move(call);
  return part;
}

absl::StatusOr<json> geminiFunctionCallPart(const json& tool_call) {
  const json* function = objectMember(tool_call, "function");
  if (function == nullptr) {
    return functionCallPart("", "");
  }
  absl::string_view arguments;
  if (const json* value = member(*function, "arguments"); value != nullptr && !value->is_null()) {
    if (!value->is_string()) {
      return absl::InvalidArgumentError("tool call arguments are not a string");
    }
    arguments = value->get_ref<const std::string&>();
  }
  return functionCallPart(stringMember(*function, "name", ""), arguments);
}

json geminiContent(json parts) {
  if (parts.empty()) {
    parts.push_back({{"text", ""}});
  }
  json content = {{"role", "model"}};
  content["parts"] = std::move(parts);
  return content;
}

absl::StatusOr<json> geminiCandidate(json& choice, uint64_t position) {
  const std::string finish_reason = stringMember(choice, "finish_reason", "");
  json parts = json::array();
  if (json* message = objectMember(choice, "message"); message != nullptr) {
    if (json* content = member(*message, "content");
        content != nullptr && isNonEmptyText(*content)) {
      json part = json::object();
      part["text"] = std::move(*content);
      parts.push_back(std::move(part));
    }
    if (const json* tool_calls = arrayMember(*message, "tool_calls"); tool_calls != nullptr) {
      for (const json& tool_call : *tool_calls) {
        absl::StatusOr<json> part = geminiFunctionCallPart(tool_call);
        if (!part.ok()) {
          if (dropsUnparsableCalls(finish_reason)) {
            continue;
          }
          return part.status();
        }
        parts.push_back(std::move(*part));
      }
    }
  }
  json candidate = {{"finishReason", geminiFinishReason(finish_reason)},
                    {"index", readCount(choice, "index").value_or(position)}};
  candidate["content"] = geminiContent(std::move(parts));
  return candidate;
}

class OpenAiToGeminiStream : public ResponseStreamTranscoder {
public:
  explicit OpenAiToGeminiStream(const ResponseContext& context) : model_(context.model) {}

  absl::Status onFrame(SseFrame frame, std::vector<SseFrame>& out) override {
    if (done_) {
      return absl::OkStatus();
    }
    if (!frame.json.has_value()) {
      if (absl::StripAsciiWhitespace(frame.data) == OpenAiDone) {
        return emitFinal(out);
      }
      return absl::OkStatus();
    }
    json& chunk = *frame.json;
    if (const json* error = objectMember(chunk, "error"); error != nullptr) {
      out.push_back(SseFrame::ofJson(geminiError(*error)));
      done_ = true;
      return absl::OkStatus();
    }
    response_id_ = stringMember(chunk, "id", response_id_);
    model_ = stringMember(chunk, "model", model_);
    // Each usage object replaces the last one whole.
    if (objectMember(chunk, "usage") != nullptr) {
      usage_ = readOpenAiUsage(chunk);
    }
    json* choices = arrayMember(chunk, "choices");
    if (choices == nullptr) {
      return absl::OkStatus();
    }
    for (json& choice : *choices) {
      if (readCount(choice, "index").value_or(0) != 0) {
        continue;
      }
      if (json* delta = objectMember(choice, "delta"); delta != nullptr) {
        if (json* content = member(*delta, "content");
            content != nullptr && isNonEmptyText(*content)) {
          json part = json::object();
          part["text"] = std::move(*content);
          json parts = json::array();
          parts.push_back(std::move(part));
          json candidate = {{"index", 0}};
          candidate["content"] = geminiContent(std::move(parts));
          out.push_back(SseFrame::ofJson(response(std::move(candidate))));
        }
        if (absl::Status status = accumulateToolCalls(*delta); !status.ok()) {
          return status;
        }
      }
      if (const json* reason = member(choice, "finish_reason");
          reason != nullptr && reason->is_string()) {
        finish_reason_ = reason->get<std::string>();
      }
    }
    return absl::OkStatus();
  }

  absl::Status onEnd(std::vector<SseFrame>& out) override {
    if (done_ || !finish_reason_.has_value()) {
      return absl::OkStatus();
    }
    return emitFinal(out);
  }

private:
  struct PendingCall {
    std::string name;
    std::string arguments;
  };

  absl::Status accumulateToolCalls(const json& delta) {
    const json* tool_calls = arrayMember(delta, "tool_calls");
    if (tool_calls == nullptr) {
      return absl::OkStatus();
    }
    uint64_t position = 0;
    for (const json& tool_call : *tool_calls) {
      PendingCall& call = calls_[readCount(tool_call, "index").value_or(position++)];
      const json* function = objectMember(tool_call, "function");
      if (function == nullptr) {
        continue;
      }
      if (call.name.empty()) {
        call.name = stringMember(*function, "name", "");
      }
      if (const json* fragment = member(*function, "arguments");
          fragment != nullptr && !fragment->is_null()) {
        if (!fragment->is_string()) {
          return absl::InvalidArgumentError("tool call arguments are not a string");
        }
        call.arguments += fragment->get_ref<const std::string&>();
      }
    }
    return absl::OkStatus();
  }

  json response(json candidate) const {
    json result = json::object();
    result["candidates"] = json::array();
    result["candidates"].push_back(std::move(candidate));
    result["modelVersion"] = model_;
    if (!response_id_.empty()) {
      result["responseId"] = response_id_;
    }
    return result;
  }

  absl::Status emitFinal(std::vector<SseFrame>& out) {
    done_ = true;
    json parts = json::array();
    const std::string finish_reason = finish_reason_.value_or("");
    for (auto& [index, call] : calls_) {
      absl::StatusOr<json> part = functionCallPart(std::move(call.name), call.arguments);
      if (!part.ok()) {
        if (dropsUnparsableCalls(finish_reason)) {
          continue;
        }
        return part.status();
      }
      parts.push_back(std::move(*part));
    }
    json candidate = {{"finishReason", geminiFinishReason(finish_reason)}, {"index", 0}};
    candidate["content"] = geminiContent(std::move(parts));
    json result = response(std::move(candidate));
    if (usage_.has_value()) {
      result["usageMetadata"] = geminiUsage(*usage_);
    }
    out.push_back(SseFrame::ofJson(std::move(result)));
    return absl::OkStatus();
  }

  std::string model_;
  std::string response_id_;
  std::optional<std::string> finish_reason_;
  std::optional<TokenUsage> usage_;
  std::map<uint64_t, PendingCall> calls_;
  bool done_{false};
};

} // namespace

ResponseStreamTranscoderPtr createGeminiToOpenAiStreamTranscoder(const ResponseContext& context) {
  return std::make_unique<GeminiToOpenAiStream>(context);
}

absl::StatusOr<nlohmann::json> transcodeGeminiToOpenAiUnary(nlohmann::json body,
                                                            const ResponseContext& context) {
  if (!body.is_object()) {
    return absl::InvalidArgumentError("Gemini response is not a JSON object");
  }
  if (const json* error = objectMember(body, "error"); error != nullptr) {
    return openAiError(*error);
  }
  json choices = json::array();
  uint64_t calls_seen = 0;
  if (json* candidates = arrayMember(body, "candidates");
      candidates != nullptr && !candidates->empty()) {
    for (uint64_t position = 0; position < candidates->size(); ++position) {
      absl::StatusOr<json> choice = openAiChoice((*candidates)[position], position, calls_seen);
      if (!choice.ok()) {
        return choice.status();
      }
      choices.push_back(std::move(*choice));
    }
  } else if (promptBlocked(body)) {
    choices.push_back({{"index", 0},
                       {"message", {{"role", "assistant"}, {"content", ""}}},
                       {"finish_reason", "content_filter"}});
  }
  json response = {{"id", stringMember(body, "responseId", DefaultResponseId)},
                   {"object", "chat.completion"},
                   {"created", context.created},
                   {"model", stringMember(body, "modelVersion", context.model)}};
  response["choices"] = std::move(choices);
  if (const json* metadata = objectMember(body, "usageMetadata"); metadata != nullptr) {
    if (std::optional<json> usage = openAiUsage(*metadata); usage.has_value()) {
      response["usage"] = std::move(*usage);
    }
  }
  return response;
}

ResponseStreamTranscoderPtr createOpenAiToGeminiStreamTranscoder(const ResponseContext& context) {
  return std::make_unique<OpenAiToGeminiStream>(context);
}

absl::StatusOr<nlohmann::json> transcodeOpenAiToGeminiUnary(nlohmann::json body,
                                                            const ResponseContext& context) {
  if (!body.is_object()) {
    return absl::InvalidArgumentError("OpenAI response is not a JSON object");
  }
  if (const json* error = objectMember(body, "error"); error != nullptr) {
    return geminiError(*error);
  }
  json candidates = json::array();
  if (json* choices = arrayMember(body, "choices"); choices != nullptr) {
    for (uint64_t position = 0; position < choices->size(); ++position) {
      absl::StatusOr<json> candidate = geminiCandidate((*choices)[position], position);
      if (!candidate.ok()) {
        return candidate.status();
      }
      candidates.push_back(std::move(*candidate));
    }
  }
  json response = json::object();
  response["candidates"] = std::move(candidates);
  if (objectMember(body, "usage") != nullptr) {
    response["usageMetadata"] = geminiUsage(readOpenAiUsage(body));
  }
  response["modelVersion"] = stringMember(body, "model", context.model);
  if (const std::string id = stringMember(body, "id", ""); !id.empty()) {
    response["responseId"] = id;
  }
  return response;
}

const ResponseCodec& geminiGenerateContentResponseCodec() {
  static constexpr ResponseCodec codec = {
      createGeminiToOpenAiStreamTranscoder, createOpenAiToGeminiStreamTranscoder,
      transcodeGeminiToOpenAiUnary, transcodeOpenAiToGeminiUnary};
  return codec;
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
