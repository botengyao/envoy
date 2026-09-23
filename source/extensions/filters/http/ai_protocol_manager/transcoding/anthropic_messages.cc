#include "source/extensions/filters/http/ai_protocol_manager/transcoding/anthropic_messages.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

const nlohmann::json* findField(const nlohmann::json& object, const char* key) {
  if (!object.is_object()) {
    return nullptr;
  }
  const auto it = object.find(key);
  return it == object.end() ? nullptr : &*it;
}

nlohmann::json* findField(nlohmann::json& object, const char* key) {
  if (!object.is_object()) {
    return nullptr;
  }
  const auto it = object.find(key);
  return it == object.end() ? nullptr : &*it;
}

const std::string* stringField(const nlohmann::json& object, const char* key) {
  const nlohmann::json* value = findField(object, key);
  return value != nullptr && value->is_string() ? &value->get_ref<const std::string&>() : nullptr;
}

std::string stringOr(const nlohmann::json* object, const char* key, absl::string_view fallback) {
  const std::string* value = object != nullptr ? stringField(*object, key) : nullptr;
  return value != nullptr ? *value : std::string(fallback);
}

std::optional<int64_t> indexField(const nlohmann::json& object, const char* key) {
  const nlohmann::json* value = findField(object, key);
  if (value == nullptr || !value->is_number_integer()) {
    return std::nullopt;
  }
  return value->get<int64_t>();
}

// Binary nodes are offloaded strings (ExternalRef): copyable, never readable here.
bool hasText(const nlohmann::json& value) {
  return value.is_binary() || (value.is_string() && !value.get_ref<const std::string&>().empty());
}

bool containsBinary(const nlohmann::json& value) {
  if (value.is_binary()) {
    return true;
  }
  if (value.is_structured()) {
    for (const nlohmann::json& element : value) {
      if (containsBinary(element)) {
        return true;
      }
    }
  }
  return false;
}

const char* openAiFinishReason(const nlohmann::json* stop_reason) {
  if (stop_reason == nullptr || !stop_reason->is_string()) {
    return "stop";
  }
  const std::string& reason = stop_reason->get_ref<const std::string&>();
  if (reason == "max_tokens" || reason == "model_context_window_exceeded") {
    return "length";
  }
  if (reason == "tool_use") {
    return "tool_calls";
  }
  if (reason == "refusal") {
    return "content_filter";
  }
  return "stop";
}

// OpenAI reports "stop" for a tool_choice-forced call; Anthropic clients act on "tool_use".
const char* anthropicStopReason(absl::string_view finish_reason, bool has_tool_use) {
  if (finish_reason == "length") {
    return "max_tokens";
  }
  if (finish_reason == "content_filter") {
    return "refusal";
  }
  if (finish_reason == "tool_calls" || finish_reason == "function_call" || has_tool_use) {
    return "tool_use";
  }
  return "end_turn";
}

nlohmann::json errorMessage(const nlohmann::json* error) {
  const nlohmann::json* message = error != nullptr ? findField(*error, "message") : nullptr;
  if (message != nullptr && (message->is_string() || message->is_binary())) {
    return *message;
  }
  return "";
}

nlohmann::json openAiError(const nlohmann::json* error) {
  return {{"error",
           {{"message", errorMessage(error)},
            {"type", stringOr(error, "type", stringOr(error, "status", "api_error"))}}}};
}

nlohmann::json anthropicError(const nlohmann::json* error) {
  return {{"type", "error"},
          {"error",
           {{"type", stringOr(error, "type", "api_error")}, {"message", errorMessage(error)}}}};
}

const nlohmann::json* errorObject(const nlohmann::json& body) {
  const nlohmann::json* error = findField(body, "error");
  return error != nullptr && error->is_object() ? error : nullptr;
}

// Vertex reports platform errors as a bare Google `error` object, without Anthropic's type.
bool isAnthropicError(const nlohmann::json& body, absl::string_view type) {
  return type == "error" || (stringField(body, "type") == nullptr && errorObject(body) != nullptr);
}

void mergeUsage(LLMProtocol protocol, const nlohmann::json& document, TokenUsage& usage) {
  usage.merge(AdapterRegistry::get(protocol).extractUsage(document).usage);
}

nlohmann::json openAiUsage(const TokenUsage& usage) {
  const uint64_t prompt = usage.input_tokens.value_or(0) +
                          usage.cache_creation_input_tokens.value_or(0) +
                          usage.cached_input_tokens.value_or(0);
  const uint64_t completion = usage.output_tokens.value_or(0);
  nlohmann::json converted = {{"prompt_tokens", prompt},
                              {"completion_tokens", completion},
                              {"total_tokens", prompt + completion}};
  if (usage.cached_input_tokens.has_value()) {
    converted["prompt_tokens_details"] = {{"cached_tokens", *usage.cached_input_tokens}};
  }
  return converted;
}

// OpenAI's prompt_tokens includes cached reads; Anthropic's input_tokens excludes them.
nlohmann::json anthropicUsage(const TokenUsage& usage) {
  const uint64_t prompt = usage.input_tokens.value_or(0);
  const uint64_t cached = std::min(usage.cached_input_tokens.value_or(0), prompt);
  nlohmann::json converted = {{"input_tokens", prompt - cached},
                              {"output_tokens", usage.output_tokens.value_or(0)}};
  if (usage.cached_input_tokens.has_value()) {
    converted["cache_read_input_tokens"] = cached;
  }
  return converted;
}

// A lone node is moved as is, since it may be offloaded; offloaded nodes cannot be concatenated.
absl::StatusOr<nlohmann::json> joinText(std::vector<nlohmann::json> parts) {
  if (parts.size() == 1) {
    return std::move(parts.front());
  }
  std::string joined;
  for (const nlohmann::json& part : parts) {
    if (!part.is_string()) {
      return absl::InvalidArgumentError("cannot join offloaded text blocks");
    }
    joined += part.get_ref<const std::string&>();
  }
  return nlohmann::json(std::move(joined));
}

absl::StatusOr<nlohmann::json> openAiToolCall(const nlohmann::json& block) {
  std::string arguments = "{}";
  if (const nlohmann::json* input = findField(block, "input");
      input != nullptr && !input->is_null()) {
    if (containsBinary(*input)) {
      return absl::InvalidArgumentError("tool_use input holds an offloaded value");
    }
    arguments = input->dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
  }
  return nlohmann::json{
      {"id", stringOr(&block, "id", "")},
      {"type", "function"},
      {"function", {{"name", stringOr(&block, "name", "")}, {"arguments", std::move(arguments)}}}};
}

absl::StatusOr<nlohmann::json> anthropicToolUse(const nlohmann::json& call) {
  const nlohmann::json* function = findField(call, "function");
  const nlohmann::json* arguments =
      function != nullptr ? findField(*function, "arguments") : nullptr;
  nlohmann::json input = nlohmann::json::object();
  if (arguments != nullptr && !arguments->is_null() &&
      !(arguments->is_string() && arguments->get_ref<const std::string&>().empty())) {
    if (!arguments->is_string()) {
      return absl::InvalidArgumentError("tool call arguments are not a string");
    }
    input = nlohmann::json::parse(arguments->get_ref<const std::string&>(), nullptr,
                                  /*allow_exceptions=*/false);
    if (input.is_discarded() || !input.is_object()) {
      return absl::InvalidArgumentError("tool call arguments are not a JSON object");
    }
  }
  return nlohmann::json{{"type", "tool_use"},
                        {"id", stringOr(&call, "id", "")},
                        {"name", stringOr(function, "name", "")},
                        {"input", std::move(input)}};
}

class AnthropicToOpenAiStream : public ResponseStreamTranscoder {
public:
  explicit AnthropicToOpenAiStream(const ResponseContext& context)
      : context_(context), model_(context.model) {}

  absl::Status onFrame(SseFrame frame, std::vector<SseFrame>& out) override {
    if (done_) {
      return absl::OkStatus();
    }
    if (!frame.json.has_value() || !frame.json->is_object()) {
      if (frame.event == "error") {
        const nlohmann::json error = {{"message", frame.json.has_value()
                                                      ? std::move(*frame.json)
                                                      : nlohmann::json(frame.data)}};
        fail(&error, out);
      }
      return absl::OkStatus();
    }
    nlohmann::json& event = *frame.json;
    const std::string type = stringOr(&event, "type", frame.event);
    if (type == "message_start") {
      onMessageStart(event, out);
    } else if (type == "content_block_start") {
      onContentBlockStart(event, out);
    } else if (type == "content_block_delta") {
      onContentBlockDelta(event, out);
    } else if (type == "content_block_stop") {
      onContentBlockStop(event, out);
    } else if (type == "message_delta") {
      onMessageDelta(event, out);
    } else if (type == "message_stop") {
      onMessageStop(out);
    } else if (isAnthropicError(event, type)) {
      fail(findField(event, "error"), out);
    }
    return absl::OkStatus();
  }

  // A stream cut before message_stop ends without [DONE], so the client sees the truncation.
  absl::Status onEnd(std::vector<SseFrame>&) override { return absl::OkStatus(); }

private:
  struct ToolBlock {
    int64_t tool_index;
    bool has_arguments{false};
  };

  void onMessageStart(const nlohmann::json& event, std::vector<SseFrame>& out) {
    if (const nlohmann::json* message = findField(event, "message"); message != nullptr) {
      if (const std::string* id = stringField(*message, "id"); id != nullptr) {
        id_ = *id;
      }
      if (const std::string* model = stringField(*message, "model"); model != nullptr) {
        model_ = *model;
      }
      mergeUsage(LLMProtocol::AnthropicMessages, *message, usage_);
    }
    emitDelta({{"role", "assistant"}, {"content", ""}}, out);
  }

  void onContentBlockStart(nlohmann::json& event, std::vector<SseFrame>& out) {
    nlohmann::json* block = findField(event, "content_block");
    const std::string* type = block != nullptr ? stringField(*block, "type") : nullptr;
    if (type == nullptr) {
      return;
    }
    if (*type == "text") {
      if (nlohmann::json* text = findField(*block, "text"); text != nullptr && hasText(*text)) {
        emitDelta({{"content", std::move(*text)}}, out);
      }
      return;
    }
    const std::optional<int64_t> index = indexField(event, "index");
    if (*type != "tool_use" || !index.has_value()) {
      return;
    }
    const int64_t tool_index = next_tool_index_++;
    tool_blocks_[*index] = ToolBlock{tool_index};
    nlohmann::json call = {
        {"index", tool_index},
        {"id", stringOr(block, "id", "")},
        {"type", "function"},
        {"function", {{"name", stringOr(block, "name", "")}, {"arguments", ""}}}};
    emitDelta({{"tool_calls", nlohmann::json::array({std::move(call)})}}, out);
  }

  void onContentBlockDelta(nlohmann::json& event, std::vector<SseFrame>& out) {
    nlohmann::json* delta = findField(event, "delta");
    const std::string* type = delta != nullptr ? stringField(*delta, "type") : nullptr;
    if (type == nullptr) {
      return;
    }
    if (*type == "text_delta") {
      if (nlohmann::json* text = findField(*delta, "text"); text != nullptr && hasText(*text)) {
        emitDelta({{"content", std::move(*text)}}, out);
      }
    } else if (*type == "input_json_delta") {
      ToolBlock* tool = toolBlock(event);
      nlohmann::json* partial = findField(*delta, "partial_json");
      if (tool != nullptr && partial != nullptr && hasText(*partial)) {
        tool->has_arguments = true;
        emitToolArguments(tool->tool_index, std::move(*partial), out);
      }
    }
  }

  void onContentBlockStop(const nlohmann::json& event, std::vector<SseFrame>& out) {
    ToolBlock* tool = toolBlock(event);
    if (tool != nullptr && !tool->has_arguments) {
      // A call without arguments streams no fragments; OpenAI clients parse the result as JSON.
      tool->has_arguments = true;
      emitToolArguments(tool->tool_index, "{}", out);
    }
  }

  void onMessageDelta(const nlohmann::json& event, std::vector<SseFrame>& out) {
    const nlohmann::json* delta = findField(event, "delta");
    const char* finish_reason =
        openAiFinishReason(delta != nullptr ? findField(*delta, "stop_reason") : nullptr);
    mergeUsage(LLMProtocol::AnthropicMessages, event, usage_);
    nlohmann::json chunk = choiceChunk(nlohmann::json::object(), finish_reason);
    if (context_.always_report_usage && !context_.include_usage) {
      chunk["usage"] = openAiUsage(usage_);
    }
    out.push_back(SseFrame::ofJson(std::move(chunk)));
  }

  void onMessageStop(std::vector<SseFrame>& out) {
    if (context_.include_usage) {
      nlohmann::json chunk = makeChunk(nlohmann::json::array());
      chunk["usage"] = openAiUsage(usage_);
      out.push_back(SseFrame::ofJson(std::move(chunk)));
    }
    out.push_back(SseFrame::ofData("[DONE]"));
    done_ = true;
  }

  void fail(const nlohmann::json* error, std::vector<SseFrame>& out) {
    out.push_back(SseFrame::ofJson(openAiError(error)));
    done_ = true;
  }

  ToolBlock* toolBlock(const nlohmann::json& event) {
    const std::optional<int64_t> index = indexField(event, "index");
    if (!index.has_value()) {
      return nullptr;
    }
    const auto it = tool_blocks_.find(*index);
    return it == tool_blocks_.end() ? nullptr : &it->second;
  }

  void emitToolArguments(int64_t tool_index, nlohmann::json arguments, std::vector<SseFrame>& out) {
    nlohmann::json call = {{"index", tool_index},
                           {"function", {{"arguments", std::move(arguments)}}}};
    emitDelta({{"tool_calls", nlohmann::json::array({std::move(call)})}}, out);
  }

  void emitDelta(nlohmann::json delta, std::vector<SseFrame>& out) {
    out.push_back(SseFrame::ofJson(choiceChunk(std::move(delta), nullptr)));
  }

  nlohmann::json choiceChunk(nlohmann::json delta, nlohmann::json finish_reason) const {
    nlohmann::json choice = {{"index", 0},
                             {"delta", std::move(delta)},
                             {"logprobs", nullptr},
                             {"finish_reason", std::move(finish_reason)}};
    return makeChunk(nlohmann::json::array({std::move(choice)}));
  }

  nlohmann::json makeChunk(nlohmann::json choices) const {
    return {{"id", id_},
            {"object", "chat.completion.chunk"},
            {"created", context_.created},
            {"model", model_},
            {"choices", std::move(choices)}};
  }

  const ResponseContext context_;
  std::string id_;
  std::string model_;
  TokenUsage usage_;
  // Anthropic content block index -> OpenAI tool call index.
  std::map<int64_t, ToolBlock> tool_blocks_;
  int64_t next_tool_index_{0};
  bool done_{false};
};

class OpenAiToAnthropicStream : public ResponseStreamTranscoder {
public:
  explicit OpenAiToAnthropicStream(const ResponseContext& context) : context_(context) {}

  absl::Status onFrame(SseFrame frame, std::vector<SseFrame>& out) override {
    if (done_) {
      return absl::OkStatus();
    }
    if (!frame.json.has_value()) {
      if (frame.data == "[DONE]") {
        finish(out);
      }
      return absl::OkStatus();
    }
    nlohmann::json& chunk = *frame.json;
    if (!chunk.is_object()) {
      return absl::OkStatus();
    }
    if (const nlohmann::json* error = errorObject(chunk); error != nullptr) {
      emit("error", anthropicError(error), out);
      done_ = true;
      return absl::OkStatus();
    }
    start(&chunk, out);
    mergeUsage(LLMProtocol::OpenAiChatCompletions, chunk, usage_);
    if (nlohmann::json* choices = findField(chunk, "choices");
        choices != nullptr && choices->is_array()) {
      for (nlohmann::json& choice : *choices) {
        if (indexField(choice, "index").value_or(0) == 0) {
          onChoice(choice, out);
        }
      }
    }
    return absl::OkStatus();
  }

  absl::Status onEnd(std::vector<SseFrame>& out) override {
    if (!done_ && finish_reason_.has_value()) {
      finish(out);
    }
    return absl::OkStatus();
  }

private:
  enum class Block { None, Text, ToolUse };

  void start(const nlohmann::json* chunk, std::vector<SseFrame>& out) {
    if (started_) {
      return;
    }
    started_ = true;
    emit("message_start",
         {{"message",
           {{"id", stringOr(chunk, "id", "")},
            {"type", "message"},
            {"role", "assistant"},
            {"model", stringOr(chunk, "model", context_.model)},
            {"content", nlohmann::json::array()},
            {"stop_reason", nullptr},
            {"stop_sequence", nullptr},
            {"usage", {{"input_tokens", 0}, {"output_tokens", 0}}}}}},
         out);
  }

  void onChoice(nlohmann::json& choice, std::vector<SseFrame>& out) {
    if (nlohmann::json* delta = findField(choice, "delta"); delta != nullptr) {
      if (nlohmann::json* text = findField(*delta, "content"); text != nullptr && hasText(*text)) {
        if (open_block_ != Block::Text) {
          openBlock(Block::Text, {{"type", "text"}, {"text", ""}}, out);
        }
        emit("content_block_delta",
             {{"index", open_index_},
              {"delta", {{"type", "text_delta"}, {"text", std::move(*text)}}}},
             out);
      }
      if (nlohmann::json* calls = findField(*delta, "tool_calls");
          calls != nullptr && calls->is_array()) {
        int64_t position = 0;
        for (nlohmann::json& call : *calls) {
          onToolCall(call, position++, out);
        }
      }
    }
    if (const std::string* finish_reason = stringField(choice, "finish_reason");
        finish_reason != nullptr) {
      finish_reason_ = *finish_reason;
    }
  }

  void onToolCall(nlohmann::json& call, int64_t position, std::vector<SseFrame>& out) {
    const int64_t tool_index = indexField(call, "index").value_or(position);
    nlohmann::json* function = findField(call, "function");
    auto it = tool_blocks_.find(tool_index);
    if (it == tool_blocks_.end()) {
      const std::string* id = stringField(call, "id");
      const std::string* name = function != nullptr ? stringField(*function, "name") : nullptr;
      if (id == nullptr && name == nullptr) {
        return;
      }
      openBlock(Block::ToolUse,
                {{"type", "tool_use"},
                 {"id", id != nullptr ? *id : ""},
                 {"name", name != nullptr ? *name : ""},
                 {"input", nlohmann::json::object()}},
                out);
      it = tool_blocks_.emplace(tool_index, open_index_).first;
    }
    nlohmann::json* arguments = function != nullptr ? findField(*function, "arguments") : nullptr;
    if (arguments != nullptr && hasText(*arguments)) {
      emit("content_block_delta",
           {{"index", it->second},
            {"delta", {{"type", "input_json_delta"}, {"partial_json", std::move(*arguments)}}}},
           out);
    }
  }

  void openBlock(Block kind, nlohmann::json content_block, std::vector<SseFrame>& out) {
    closeBlock(out);
    open_block_ = kind;
    open_index_ = next_index_++;
    emit("content_block_start",
         {{"index", open_index_}, {"content_block", std::move(content_block)}}, out);
  }

  void closeBlock(std::vector<SseFrame>& out) {
    if (open_block_ == Block::None) {
      return;
    }
    open_block_ = Block::None;
    emit("content_block_stop", {{"index", open_index_}}, out);
  }

  void finish(std::vector<SseFrame>& out) {
    start(nullptr, out);
    closeBlock(out);
    emit(
        "message_delta",
        {{"delta",
          {{"stop_reason", anthropicStopReason(finish_reason_.value_or(""), !tool_blocks_.empty())},
           {"stop_sequence", nullptr}}},
         {"usage", anthropicUsage(usage_)}},
        out);
    emit("message_stop", nlohmann::json::object(), out);
    done_ = true;
  }

  static void emit(const char* type, nlohmann::json payload, std::vector<SseFrame>& out) {
    payload["type"] = type;
    out.push_back(SseFrame::ofJson(std::move(payload), type));
  }

  const ResponseContext context_;
  TokenUsage usage_;
  std::optional<std::string> finish_reason_;
  // OpenAI tool call index -> Anthropic content block index.
  std::map<int64_t, int64_t> tool_blocks_;
  Block open_block_{Block::None};
  int64_t open_index_{0};
  int64_t next_index_{0};
  bool started_{false};
  bool done_{false};
};

} // namespace

ResponseStreamTranscoderPtr
createAnthropicToOpenAiStreamTranscoder(const ResponseContext& context) {
  return std::make_unique<AnthropicToOpenAiStream>(context);
}

absl::StatusOr<nlohmann::json> transcodeAnthropicToOpenAiUnary(nlohmann::json body,
                                                               const ResponseContext& context) {
  if (!body.is_object()) {
    return absl::InvalidArgumentError("Anthropic response is not a JSON object");
  }
  if (isAnthropicError(body, stringOr(&body, "type", ""))) {
    return openAiError(findField(body, "error"));
  }
  std::vector<nlohmann::json> texts;
  nlohmann::json tool_calls = nlohmann::json::array();
  if (nlohmann::json* content = findField(body, "content");
      content != nullptr && content->is_array()) {
    for (nlohmann::json& block : *content) {
      const std::string* type = stringField(block, "type");
      if (type == nullptr) {
        continue;
      }
      if (*type == "text") {
        nlohmann::json* text = findField(block, "text");
        if (text != nullptr && hasText(*text)) {
          texts.push_back(std::move(*text));
        }
      } else if (*type == "tool_use") {
        absl::StatusOr<nlohmann::json> call = openAiToolCall(block);
        if (!call.ok()) {
          return call.status();
        }
        tool_calls.push_back(std::move(*call));
      }
    }
  }
  absl::StatusOr<nlohmann::json> text = joinText(std::move(texts));
  if (!text.ok()) {
    return text.status();
  }
  nlohmann::json message = {{"role", "assistant"}, {"content", std::move(*text)}};
  if (!tool_calls.empty()) {
    if (!hasText(message["content"])) {
      message["content"] = nullptr;
    }
    message["tool_calls"] = std::move(tool_calls);
  }
  TokenUsage usage;
  mergeUsage(LLMProtocol::AnthropicMessages, body, usage);
  nlohmann::json choice = {{"index", 0},
                           {"message", std::move(message)},
                           {"finish_reason", openAiFinishReason(findField(body, "stop_reason"))},
                           {"logprobs", nullptr}};
  return nlohmann::json{{"id", stringOr(&body, "id", "")},
                        {"object", "chat.completion"},
                        {"created", context.created},
                        {"model", stringOr(&body, "model", context.model)},
                        {"choices", nlohmann::json::array({std::move(choice)})},
                        {"usage", openAiUsage(usage)}};
}

ResponseStreamTranscoderPtr
createOpenAiToAnthropicStreamTranscoder(const ResponseContext& context) {
  return std::make_unique<OpenAiToAnthropicStream>(context);
}

absl::StatusOr<nlohmann::json> transcodeOpenAiToAnthropicUnary(nlohmann::json body,
                                                               const ResponseContext& context) {
  if (!body.is_object()) {
    return absl::InvalidArgumentError("OpenAI response is not a JSON object");
  }
  if (const nlohmann::json* error = errorObject(body); error != nullptr) {
    return anthropicError(error);
  }
  nlohmann::json content = nlohmann::json::array();
  std::string finish_reason;
  bool has_tool_use = false;
  if (nlohmann::json* choices = findField(body, "choices");
      choices != nullptr && choices->is_array() && !choices->empty()) {
    nlohmann::json& choice = choices->front();
    if (const std::string* reason = stringField(choice, "finish_reason"); reason != nullptr) {
      finish_reason = *reason;
    }
    if (nlohmann::json* message = findField(choice, "message"); message != nullptr) {
      if (nlohmann::json* text = findField(*message, "content");
          text != nullptr && hasText(*text)) {
        content.push_back(nlohmann::json{{"type", "text"}, {"text", std::move(*text)}});
      }
      if (const nlohmann::json* calls = findField(*message, "tool_calls");
          calls != nullptr && calls->is_array()) {
        for (const nlohmann::json& call : *calls) {
          absl::StatusOr<nlohmann::json> block = anthropicToolUse(call);
          if (!block.ok()) {
            return block.status();
          }
          content.push_back(std::move(*block));
          has_tool_use = true;
        }
      }
    }
  }
  TokenUsage usage;
  mergeUsage(LLMProtocol::OpenAiChatCompletions, body, usage);
  return nlohmann::json{{"id", stringOr(&body, "id", "")},
                        {"type", "message"},
                        {"role", "assistant"},
                        {"model", stringOr(&body, "model", context.model)},
                        {"content", std::move(content)},
                        {"stop_reason", anthropicStopReason(finish_reason, has_tool_use)},
                        {"stop_sequence", nullptr},
                        {"usage", anthropicUsage(usage)}};
}

const ResponseCodec& anthropicMessagesResponseCodec() {
  static constexpr ResponseCodec codec = {
      createAnthropicToOpenAiStreamTranscoder, createOpenAiToAnthropicStreamTranscoder,
      transcodeAnthropicToOpenAiUnary, transcodeOpenAiToAnthropicUnary};
  return codec;
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
