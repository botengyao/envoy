#include "source/extensions/http/ai_filters/transcoder/request/request_converter.h"

#include <algorithm>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"
#include "source/extensions/filters/http/ai_protocol_manager/schema.h"

#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/types/span.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

namespace {

using HttpFilters::AiProtocolManager::AdapterRegistry;
using HttpFilters::AiProtocolManager::DialectTranscodePack;
using HttpFilters::AiProtocolManager::JsonWithExtBuf;
using HttpFilters::AiProtocolManager::llmProtocolName;
using HttpFilters::AiProtocolManager::PayloadSchema;
using HttpFilters::AiProtocolManager::Schema;
using HttpFilters::AiProtocolManager::TranscodingEngine;

// The transcoder places these itself, so pruning them loses nothing the client asked for.
constexpr absl::string_view kTranscoderFields[] = {"model", "stream", "stream_options"};

constexpr std::pair<const char*, const char*> kGenerationConfigFields[] = {
    {"seed", "seed"},
    {"presence_penalty", "presencePenalty"},
    {"frequency_penalty", "frequencyPenalty"},
};

// The `generationConfig` members the engine carries into the IR; it drops the rest.
constexpr absl::string_view kHoistedGeminiConfigFields[] = {
    "maxOutputTokens",
    "max_output_tokens",
    "temperature",
    "topP",
    "top_p",
    "stopSequences",
    "stop_sequences",
    "candidateCount",
    "candidate_count",
    "seed",
    "presencePenalty",
    "presence_penalty",
    "frequencyPenalty",
    "frequency_penalty",
};

constexpr const char* kGeminiToolParts[] = {"functionCall", "function_call", "functionResponse",
                                            "function_response"};

constexpr const char* kGeminiDataParts[] = {
    "inlineData",          "inline_data",           "fileData",
    "file_data",           "executableCode",        "executable_code",
    "codeExecutionResult", "code_execution_result",
};

// A null, false or empty value asks for nothing, so removing it is not a loss worth reporting.
// `parallel_tool_calls`, the one flag that defaults to true, is mapped rather than removed.
bool carriesValue(const nlohmann::json& value) {
  if (value.is_array() || value.is_object()) {
    return !value.empty();
  }
  if (value.is_boolean()) {
    return value.get<bool>();
  }
  return !value.is_null();
}

bool isSet(const nlohmann::json& object, const char* key) {
  auto it = object.find(key);
  return it != object.end() && !it->is_null();
}

bool isTrue(const nlohmann::json& object, const char* key) {
  auto it = object.find(key);
  return it != object.end() && it->is_boolean() && it->get<bool>();
}

absl::string_view stringOrEmpty(const nlohmann::json& object, const char* key) {
  auto it = object.find(key);
  if (it == object.end() || !it->is_string()) {
    return {};
  }
  return it->get_ref<const std::string&>();
}

bool hasTools(const nlohmann::json& body) {
  auto tools = body.find("tools");
  return tools != body.end() && carriesValue(*tools);
}

void record(std::vector<std::string>& removed, std::string field) {
  if (std::find(removed.begin(), removed.end(), field) == removed.end()) {
    removed.push_back(std::move(field));
  }
}

void dropField(nlohmann::json& body, const char* key, std::vector<std::string>& removed) {
  auto it = body.find(key);
  if (it == body.end()) {
    return;
  }
  if (carriesValue(*it)) {
    record(removed, key);
  }
  body.erase(it);
}

// Moves `keys` out of `body` into `stash`, to be applied after the target's rules.
void stashFields(nlohmann::json& body, std::initializer_list<const char*> keys,
                 nlohmann::json& stash) {
  for (const char* key : keys) {
    if (auto it = body.find(key); it != body.end()) {
      stash[key] = std::move(*it);
      body.erase(it);
    }
  }
}

// Keeps the parts of a Gemini `Content` that the IR can hold. A thought is the model's own
// reasoning, so it is dropped rather than replayed to another model as answer text.
absl::Status keepGeminiTextParts(nlohmann::json& content, absl::string_view where,
                                 std::vector<std::string>& removed) {
  auto parts = content.find("parts");
  if (parts == content.end() || !parts->is_array()) {
    return absl::OkStatus();
  }
  nlohmann::json kept = nlohmann::json::array();
  for (size_t i = 0; i < parts->size(); ++i) {
    nlohmann::json& part = (*parts)[i];
    if (part.is_object()) {
      for (const char* key : kGeminiToolParts) {
        if (isSet(part, key)) {
          return absl::InvalidArgumentError(absl::StrCat(
              "tool calls are not supported yet: ", where, ".parts[", i, "] has '", key, "'"));
        }
      }
      for (const char* key : kGeminiDataParts) {
        if (isSet(part, key)) {
          return absl::InvalidArgumentError(
              absl::StrCat("content part type ", key, " is not supported yet"));
        }
      }
      if (isTrue(part, "thought")) {
        record(removed, "contents[].parts[].thought");
        continue;
      }
    }
    kept.push_back(std::move(part));
  }
  *parts = std::move(kept);
  return absl::OkStatus();
}

absl::Status prepareGeminiContents(nlohmann::json& body, std::vector<std::string>& removed) {
  for (const char* key : {"systemInstruction", "system_instruction"}) {
    if (auto system = body.find(key); system != body.end() && system->is_object()) {
      if (absl::Status status = keepGeminiTextParts(*system, key, removed); !status.ok()) {
        return status;
      }
    }
  }
  auto contents = body.find("contents");
  if (contents == body.end() || !contents->is_array()) {
    return absl::OkStatus();
  }
  nlohmann::json kept = nlohmann::json::array();
  for (size_t i = 0; i < contents->size(); ++i) {
    nlohmann::json& content = (*contents)[i];
    if (content.is_object()) {
      auto parts = content.find("parts");
      const bool had_parts = parts != content.end() && parts->is_array() && !parts->empty();
      if (absl::Status status =
              keepGeminiTextParts(content, absl::StrCat("contents[", i, "]"), removed);
          !status.ok()) {
        return status;
      }
      // A turn that held only thoughts has nothing left to send.
      if (had_parts && content["parts"].empty()) {
        continue;
      }
    }
    kept.push_back(std::move(content));
  }
  *contents = std::move(kept);
  return absl::OkStatus();
}

// Reports the `generationConfig` members the IR cannot hold, and maps JSON mode to
// `response_format`.
void prepareGeminiConfig(nlohmann::json& body, nlohmann::json& response_format,
                         std::vector<std::string>& removed) {
  for (const char* name : {"generationConfig", "generation_config"}) {
    auto config = body.find(name);
    if (config == body.end() || !config->is_object()) {
      continue;
    }
    absl::string_view mime = stringOrEmpty(*config, "responseMimeType");
    if (mime.empty()) {
      mime = stringOrEmpty(*config, "response_mime_type");
    }
    const bool json_mode = mime == "application/json";
    nlohmann::json schema;
    for (auto it = config->begin(); it != config->end(); ++it) {
      const std::string& key = it.key();
      if (!carriesValue(*it) ||
          std::find(std::begin(kHoistedGeminiConfigFields), std::end(kHoistedGeminiConfigFields),
                    key) != std::end(kHoistedGeminiConfigFields)) {
        continue;
      }
      if ((key == "responseMimeType" || key == "response_mime_type") &&
          (json_mode || mime == "text/plain")) {
        continue;
      }
      if ((key == "responseJsonSchema" || key == "response_json_schema") && json_mode &&
          it->is_object()) {
        schema = std::move(*it);
        continue;
      }
      record(removed, absl::StrCat(name, ".", key));
    }
    if (!json_mode) {
      continue;
    }
    response_format = nlohmann::json::object();
    if (schema.is_object()) {
      response_format["type"] = "json_schema";
      nlohmann::json& json_schema = response_format["json_schema"];
      json_schema["name"] = "response";
      json_schema["schema"] = std::move(schema);
    } else {
      response_format["type"] = "json_object";
    }
  }
}

absl::Status toIr(const TranscodingEngine& engine, LLMProtocol from, nlohmann::json& body,
                  const ClientRequest& client, std::vector<std::string>& removed) {
  if (!body.is_object()) {
    return absl::InvalidArgumentError("request body is not a JSON object");
  }
  if (engine.pack(from) == nullptr) {
    return absl::InvalidArgumentError(
        absl::StrCat("cannot convert a ", llmProtocolName(from), " request"));
  }
  nlohmann::json response_format;
  bool serial_tool_calls = false;
  if (from == LLMProtocol::GeminiGenerateContent) {
    if (absl::Status status = prepareGeminiContents(body, removed); !status.ok()) {
      return status;
    }
    prepareGeminiConfig(body, response_format, removed);
  } else if (from == LLMProtocol::AnthropicMessages) {
    // The engine drops this, having no rule that negates a boolean.
    auto choice = body.find("tool_choice");
    serial_tool_calls =
        choice != body.end() && choice->is_object() && isTrue(*choice, "disable_parallel_tool_use");
  }
  if (absl::Status status = engine.transcodeToIr(from, body); !status.ok()) {
    return status;
  }
  if (!response_format.is_null()) {
    body["response_format"] = std::move(response_format);
  }
  if (serial_tool_calls) {
    body["parallel_tool_calls"] = false;
  }
  body["model"] = client.model;
  if (client.stream) {
    body["stream"] = true;
  } else if (from == LLMProtocol::GeminiGenerateContent) {
    // The path, not the body, says whether a Gemini client streams.
    body.erase("stream");
  }
  return absl::OkStatus();
}

absl::Status checkTools(const nlohmann::json& body, LLMProtocol to) {
  if (!hasTools(body)) {
    return absl::OkStatus();
  }
  if (to == LLMProtocol::GeminiGenerateContent) {
    return absl::InvalidArgumentError(
        absl::StrCat("tools are not supported for ", llmProtocolName(to), " yet"));
  }
  const nlohmann::json& tools = *body.find("tools");
  if (!tools.is_array()) {
    return absl::OkStatus();
  }
  size_t i = 0;
  for (const nlohmann::json& tool : tools) {
    if (stringOrEmpty(tool, "type") != "function") {
      return absl::InvalidArgumentError(
          absl::StrCat("tools[", i, "] is not a function tool; other tools are not supported yet"));
    }
    ++i;
  }
  return absl::OkStatus();
}

// Tool-call turns and non-text content cannot be converted yet, and would otherwise reach the
// upstream in a shape it rejects. Text parts keep only what every protocol can carry.
absl::Status checkMessages(nlohmann::json& body, std::vector<std::string>& removed) {
  auto messages = body.find("messages");
  if (messages == body.end() || !messages->is_array()) {
    return absl::OkStatus();
  }
  for (size_t i = 0; i < messages->size(); ++i) {
    nlohmann::json& message = (*messages)[i];
    const absl::string_view role = stringOrEmpty(message, "role");
    if (role == "tool" || role == "function") {
      return absl::InvalidArgumentError(absl::StrCat(
          "tool call messages are not supported yet: messages[", i, "] has role '", role, "'"));
    }
    for (const char* key : {"tool_calls", "function_call"}) {
      if (auto it = message.find(key); it != message.end() && carriesValue(*it)) {
        return absl::InvalidArgumentError(
            absl::StrCat("tool calls are not supported yet: messages[", i, "] has '", key, "'"));
      }
    }
    auto content = message.find("content");
    if (content == message.end() || !content->is_array()) {
      continue;
    }
    for (auto part_it = content->begin(); part_it != content->end();) {
      nlohmann::json& part = *part_it;
      const absl::string_view type = stringOrEmpty(part, "type");
      // Anthropic clients replay their thinking every turn; no other protocol can take it.
      if (type == "thinking" || type == "redacted_thinking") {
        record(removed, absl::StrCat("messages[].content[].", type));
        part_it = content->erase(part_it);
        continue;
      }
      if (type != "text") {
        return absl::InvalidArgumentError(absl::StrCat(
            "content part type ", type.empty() ? "(none)" : type, " is not supported yet"));
      }
      auto text = part.find("text");
      if (text == part.end() || !(text->is_string() || JsonWithExtBuf::isExternalRef(*text))) {
        return absl::InvalidArgumentError(
            absl::StrCat("messages[", i, "] has a text content part without text"));
      }
      for (auto it = part.begin(); it != part.end();) {
        if (it.key() == "type" || it.key() == "text") {
          ++it;
          continue;
        }
        if (carriesValue(*it)) {
          record(removed, absl::StrCat("messages[].content[].", it.key()));
        }
        it = part.erase(it);
      }
      ++part_it;
    }
  }
  return absl::OkStatus();
}

// Fields every protocol spells alike but gives its own meaning or value set.
void dropForeignFields(nlohmann::json& body, LLMProtocol to, std::vector<std::string>& removed) {
  dropField(body, "store", removed);
  // Only `auto` means the same to OpenAI and Anthropic; Gemini has no such tier.
  if (auto tier = body.find("service_tier");
      tier != body.end() && (to == LLMProtocol::GeminiGenerateContent || *tier != "auto")) {
    dropField(body, "service_tier", removed);
  }
  // A tool choice without tools asks for nothing, and some upstreams reject it.
  if (!hasTools(body)) {
    body.erase("tools");
    body.erase("tool_choice");
    body.erase("parallel_tool_calls");
  }
}

absl::Status requireSingleChoice(nlohmann::json& body, LLMProtocol to) {
  auto n = body.find("n");
  if (n == body.end()) {
    return absl::OkStatus();
  }
  if (!n->is_null() && !(n->is_number() && *n == 1)) {
    return absl::InvalidArgumentError(
        absl::StrCat(llmProtocolName(to), " returns a single choice: 'n' must be 1"));
  }
  body.erase(n);
  return absl::OkStatus();
}

absl::Status prepareForAnthropic(nlohmann::json& body, const RequestConversionOptions& options,
                                 nlohmann::json& stash, std::vector<std::string>& removed) {
  if (absl::Status status = requireSingleChoice(body, LLMProtocol::AnthropicMessages);
      !status.ok()) {
    return status;
  }
  // OpenAI's `metadata` is a free-form map; Anthropic's carries only the end user's id.
  dropField(body, "metadata", removed);
  if (auto user = body.find("user"); user != body.end() && user->is_string()) {
    nlohmann::json metadata = nlohmann::json::object();
    metadata["user_id"] = std::move(*user);
    body.erase(user);
    body["metadata"] = std::move(metadata);
  }
  if (!isSet(body, "max_tokens") && !isSet(body, "max_completion_tokens")) {
    body["max_tokens"] = options.default_max_output_tokens;
  }
  body.erase("stream_options");
  stashFields(body, {"parallel_tool_calls"}, stash);
  return absl::OkStatus();
}

void finishForAnthropic(nlohmann::json& body, nlohmann::json& stash) {
  auto parallel = stash.find("parallel_tool_calls");
  if (parallel == stash.end() || !parallel->is_boolean() || parallel->get<bool>()) {
    return;
  }
  nlohmann::json& choice = body["tool_choice"];
  if (choice.is_null()) {
    choice = nlohmann::json::object();
    choice["type"] = "auto";
  }
  if (choice.is_object() && stringOrEmpty(choice, "type") != "none") {
    choice["disable_parallel_tool_use"] = true;
  }
}

absl::Status prepareForGemini(nlohmann::json& body, nlohmann::json& stash) {
  if (absl::Status status = requireSingleChoice(body, LLMProtocol::GeminiGenerateContent);
      !status.ok()) {
    return status;
  }
  stashFields(body, {"seed", "presence_penalty", "frequency_penalty", "response_format"}, stash);
  return absl::OkStatus();
}

void finishForGemini(nlohmann::json& body, nlohmann::json& stash,
                     std::vector<std::string>& removed) {
  if (stash.empty()) {
    return;
  }
  nlohmann::json& config = body["generationConfig"];
  if (!config.is_object()) {
    config = nlohmann::json::object();
  }
  for (const auto& [ir_field, gemini_field] : kGenerationConfigFields) {
    if (auto it = stash.find(ir_field); it != stash.end() && !it->is_null()) {
      config[gemini_field] = std::move(*it);
    }
  }
  if (auto format = stash.find("response_format"); format != stash.end() && !format->is_null()) {
    const absl::string_view type = stringOrEmpty(*format, "type");
    if (type == "json_object" || type == "json_schema") {
      config["responseMimeType"] = "application/json";
      if (auto json_schema = format->find("json_schema");
          json_schema != format->end() && json_schema->is_object()) {
        if (auto schema = json_schema->find("schema");
            schema != json_schema->end() && !schema->is_null()) {
          config["responseJsonSchema"] = std::move(*schema);
        }
      }
    } else if (type != "text") {
      record(removed, "response_format");
    }
  }
  if (config.empty()) {
    body.erase("generationConfig");
  }
}

// The upstream streams usage only when asked, and the response side needs it to report usage in
// the client's protocol.
void prepareForOpenAi(nlohmann::json& body, const ClientRequest& client) {
  if (!client.stream) {
    body.erase("stream_options");
    return;
  }
  nlohmann::json stream_options = nlohmann::json::object();
  stream_options["include_usage"] = true;
  body["stream_options"] = std::move(stream_options);
}

// Removes the members of `object` that `schema` does not declare, recording those that asked for
// something as `prefix` + name unless they are `silent`.
void pruneUndeclared(nlohmann::json& object, const Schema& schema, absl::string_view prefix,
                     absl::Span<const absl::string_view> silent,
                     std::vector<std::string>& removed) {
  absl::flat_hash_set<absl::string_view> declared;
  for (const Schema::Property& property : schema.properties()) {
    declared.insert(property.name);
    declared.insert(property.aliases.begin(), property.aliases.end());
  }
  for (auto it = object.begin(); it != object.end();) {
    if (declared.contains(it.key())) {
      ++it;
      continue;
    }
    if (carriesValue(*it) && std::find(silent.begin(), silent.end(), it.key()) == silent.end()) {
      record(removed, absl::StrCat(prefix, it.key()));
    }
    it = object.erase(it);
  }
}

// Prunes each object in the array `body[field]` to the root schema's element schema for it.
void pruneElements(nlohmann::json& body, const Schema& root, absl::string_view field,
                   absl::string_view prefix, std::vector<std::string>& removed) {
  const Schema* element = nullptr;
  for (const Schema::Property& property : root.properties()) {
    if (property.name == field && property.schema != nullptr) {
      element = property.schema->elementSchema();
    }
  }
  auto array = body.find(field);
  if (element == nullptr || element->type() != Schema::Type::Object || array == body.end() ||
      !array->is_array()) {
    return;
  }
  for (nlohmann::json& item : *array) {
    if (item.is_object()) {
      pruneUndeclared(item, *element, prefix, {}, removed);
    }
  }
}

void pruneToSchema(nlohmann::json& body, LLMProtocol to, const Schema& root,
                   std::vector<std::string>& removed) {
  pruneUndeclared(body, root, "", kTranscoderFields, removed);
  pruneElements(body, root, to == LLMProtocol::GeminiGenerateContent ? "contents" : "messages",
                "messages[].", removed);
  pruneElements(body, root, "tools", "tools[].", removed);
}

} // namespace

absl::Status convertRequestToIr(const TranscodingEngine& engine, LLMProtocol from,
                                nlohmann::json& body, const ClientRequest& client) {
  std::vector<std::string> removed;
  return toIr(engine, from, body, client, removed);
}

absl::Status convertRequest(const TranscodingEngine& engine, LLMProtocol from, LLMProtocol to,
                            nlohmann::json& body, const ClientRequest& client,
                            const RequestConversionOptions& options,
                            std::vector<std::string>& dropped) {
  if (from == to) {
    return absl::InvalidArgumentError(
        absl::StrCat("a ", llmProtocolName(from), " request needs no conversion"));
  }
  const DialectTranscodePack* target = engine.pack(to);
  const PayloadSchema* schema = AdapterRegistry::get(to).schema();
  if (target == nullptr || schema == nullptr) {
    return absl::InvalidArgumentError(
        absl::StrCat("cannot convert a request to ", llmProtocolName(to)));
  }
  std::vector<std::string> removed;
  if (absl::Status status = toIr(engine, from, body, client, removed); !status.ok()) {
    return status;
  }
  if (absl::Status status = checkTools(body, to); !status.ok()) {
    return status;
  }
  if (absl::Status status = checkMessages(body, removed); !status.ok()) {
    return status;
  }
  dropForeignFields(body, to, removed);
  nlohmann::json stash = nlohmann::json::object();
  absl::Status status = absl::OkStatus();
  if (to == LLMProtocol::AnthropicMessages) {
    status = prepareForAnthropic(body, options, stash, removed);
  } else if (to == LLMProtocol::GeminiGenerateContent) {
    status = prepareForGemini(body, stash);
  } else if (to == LLMProtocol::OpenAiChatCompletions) {
    prepareForOpenAi(body, client);
  }
  if (!status.ok()) {
    return status;
  }
  // Validation waits until the body is pruned to what the target declares.
  if (to != TranscodingEngine::kIrProtocol) {
    if (status = target->from_ir.execute(body); !status.ok()) {
      return status;
    }
  }
  if (to == LLMProtocol::AnthropicMessages) {
    finishForAnthropic(body, stash);
  } else if (to == LLMProtocol::GeminiGenerateContent) {
    finishForGemini(body, stash, removed);
  }
  pruneToSchema(body, to, schema->requestSchema().rootSchema(), removed);

  dropped.insert(dropped.end(), removed.begin(), removed.end());
  if (options.reject_unsupported_fields && !removed.empty()) {
    return absl::InvalidArgumentError(absl::StrCat(
        llmProtocolName(to), " cannot express request fields: ", absl::StrJoin(removed, ", ")));
  }
  if (status = schema->validateRequest(body); !status.ok()) {
    return absl::InvalidArgumentError(
        absl::StrCat("request is not valid ", llmProtocolName(to), ": ", status.message()));
  }
  return absl::OkStatus();
}

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
