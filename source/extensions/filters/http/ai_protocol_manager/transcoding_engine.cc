#include "source/extensions/filters/http/ai_protocol_manager/transcoding_engine.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <optional>

#include "source/common/http/utility.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"
#include "source/extensions/filters/http/ai_protocol_manager/transcoding/anthropic_messages.h"
#include "source/extensions/filters/http/ai_protocol_manager/transcoding/gemini_generate_content.h"

#include "absl/container/flat_hash_set.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Where a rule runs: the options, the report, and the array elements enclosing the current
// object. Paths are rendered only when a rule reports or fails.
class TranscodeRule::Scope {
public:
  Scope(const TranscodeOptions& options, TranscodeReport* report)
      : options_(options), report_(report) {}
  Scope(const Scope& parent, absl::string_view array_path, size_t index)
      : parent_(&parent), array_path_(array_path), index_(index), options_(parent.options_),
        report_(parent.report_) {}

  const TranscodeOptions& options() const { return options_; }

  void report(absl::string_view field) const {
    if (report_ != nullptr) {
      report_->add(absl::StrCat(prefix(), field));
    }
  }

  // The current object as report entries spell it, e.g. `messages[].content[].`.
  std::string prefix() const {
    if (parent_ == nullptr) {
      return "";
    }
    return absl::StrCat(parent_->prefix(), array_path_, "[].");
  }

  // The current object as error messages spell it, e.g. `messages[1].content[0]`.
  std::string location() const {
    if (parent_ == nullptr) {
      return "";
    }
    const std::string parent = parent_->location();
    return absl::StrCat(parent, parent.empty() ? "" : ".", array_path_, "[", index_, "]");
  }

private:
  const Scope* parent_{nullptr};
  absl::string_view array_path_;
  size_t index_{0};
  const TranscodeOptions& options_;
  TranscodeReport* report_;
};

namespace {

// Splits a dot-delimited JSON path (e.g. "generationConfig.maxOutputTokens") into owned segments
// at rule construction time so execution never re-tokenizes paths per message.
std::vector<std::string> splitPath(absl::string_view path) {
  if (path.empty()) {
    return {};
  }
  return absl::StrSplit(path, '.');
}

// A null, false or empty value asks for nothing, so removing it is not a loss worth reporting.
bool carriesValue(const nlohmann::json& value) {
  if (value.is_array() || value.is_object()) {
    return !value.empty();
  }
  if (value.is_boolean()) {
    return value.get<bool>();
  }
  return !value.is_null();
}

std::string renderValue(const nlohmann::json& value) {
  if (value.is_string()) {
    return value.get<std::string>();
  }
  return value.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

const TranscodeOptions& defaultOptions() {
  static const TranscodeOptions options;
  return options;
}

// Extracts and removes the node at `parts` from `root`, returning `std::nullopt` if any
// segment is absent or not an object. Cleans up empty parent objects created along `parts`.
std::optional<nlohmann::json> extractNodeByPath(nlohmann::json& root,
                                                absl::Span<const std::string> parts) {
  if (parts.empty() || !root.is_object()) {
    return std::nullopt;
  }

  std::vector<nlohmann::json*> parents;
  nlohmann::json* curr = &root;
  for (size_t i = 0; i + 1 < parts.size(); ++i) {
    auto it = curr->find(parts[i]);
    if (it == curr->end() || !it->is_object()) {
      return std::nullopt;
    }
    parents.push_back(curr);
    curr = &(*it);
  }

  auto last_it = curr->find(parts.back());
  if (last_it == curr->end()) {
    return std::nullopt;
  }

  nlohmann::json extracted = std::move(*last_it);
  curr->erase(last_it);

  // Prune any intermediate objects that became empty after removing the leaf.
  for (size_t i = parents.size(); i > 0; --i) {
    nlohmann::json* parent = parents[i - 1];
    const std::string& child_key = parts[i - 1];
    auto child_it = parent->find(child_key);
    if (child_it != parent->end() && child_it->is_object() && child_it->empty()) {
      parent->erase(child_it);
    } else {
      break;
    }
  }

  return extracted;
}

// Navigates to `parts` inside `root` (read/write), returning `nullptr` if absent.
nlohmann::json* findNodeByPath(nlohmann::json& root, absl::Span<const std::string> parts) {
  if (parts.empty()) {
    return &root;
  }
  nlohmann::json* curr = &root;
  for (const std::string& part : parts) {
    if (!curr->is_object()) {
      return nullptr;
    }
    auto it = curr->find(part);
    if (it == curr->end()) {
      return nullptr;
    }
    curr = &(*it);
  }
  return curr;
}

const nlohmann::json* findNodeByPath(const nlohmann::json& root,
                                     absl::Span<const std::string> parts) {
  return findNodeByPath(const_cast<nlohmann::json&>(root), parts);
}

// Writes `value` into `root` at `parts`, creating intermediate objects as needed.
void setNodeByPath(nlohmann::json& root, absl::Span<const std::string> parts,
                   nlohmann::json&& value) {
  if (parts.empty()) {
    root = std::move(value);
    return;
  }
  if (!root.is_object()) {
    root = nlohmann::json::object();
  }
  nlohmann::json* curr = &root;
  for (size_t i = 0; i + 1 < parts.size(); ++i) {
    const std::string& key = parts[i];
    auto it = curr->find(key);
    if (it == curr->end() || !it->is_object()) {
      (*curr)[key] = nlohmann::json::object();
    }
    curr = &((*curr)[key]);
  }
  (*curr)[parts.back()] = std::move(value);
}

// Converts any message content node (string, ExternalRef, or array of blocks) into a normalized
// array of content block objects (`{"type": "text", "text": <moved_node>}`) so consecutive
// messages can be combined without stringifying `ExternalRef` nodes.
nlohmann::json toContentBlockArray(nlohmann::json&& content) {
  if (content.is_array()) {
    return std::move(content);
  }
  nlohmann::json block = nlohmann::json::object();
  block["type"] = "text";
  block["text"] = std::move(content);
  nlohmann::json arr = nlohmann::json::array();
  arr.push_back(std::move(block));
  return arr;
}

std::string joinRulePath(absl::string_view prefix, absl::string_view relative_path) {
  if (prefix.empty()) {
    return std::string(relative_path);
  }
  if (relative_path.empty()) {
    return std::string(prefix);
  }
  return absl::StrCat(prefix, ".", relative_path);
}

// When a rule moves `from_prefix` to `to_prefix`, checks if `path` is that field itself or a
// child field inside it (e.g. moving `"messages"` -> `"turns"` rewrites `"messages[].content"`
// to `"turns[].content"`, while ignoring unrelated fields like `"messages_count"` or `"tools"`).
// Returns the new path if affected, or `std::nullopt` if `path` did not move.
std::optional<std::string> rewritePathPrefix(absl::string_view path, absl::string_view from_prefix,
                                             absl::string_view to_prefix) {
  if (path == from_prefix) {
    return std::string(to_prefix);
  }
  if (absl::StartsWith(path, from_prefix)) {
    const absl::string_view suffix = path.substr(from_prefix.size());
    if (absl::StartsWith(suffix, ".") || absl::StartsWith(suffix, "[]")) {
      return absl::StrCat(to_prefix, suffix);
    }
  }
  return std::nullopt;
}

// Moves every offloadable path under `from_prefix` to `to_prefix`. When `keep_source` is true
// (e.g. `ExtractFromArray`, which leaves non-matching elements in the source array), the source
// path also stays offloadable.
void relocateOffloadablePaths(absl::flat_hash_set<std::string>& offloadable_set,
                              absl::string_view from_prefix, absl::string_view to_prefix,
                              bool keep_source = false) {
  std::vector<std::string> to_remove;
  std::vector<std::string> to_insert;
  for (const std::string& path : offloadable_set) {
    if (auto rewritten = rewritePathPrefix(path, from_prefix, to_prefix); rewritten.has_value()) {
      if (!keep_source) {
        to_remove.push_back(path);
      }
      to_insert.push_back(*std::move(rewritten));
    }
  }
  for (const std::string& path : to_remove) {
    offloadable_set.erase(path);
  }
  for (std::string& path : to_insert) {
    offloadable_set.insert(std::move(path));
  }
}

void dropOffloadablePaths(absl::flat_hash_set<std::string>& offloadable_set,
                          absl::string_view dropped_prefix) {
  for (auto it = offloadable_set.begin(); it != offloadable_set.end();) {
    if (rewritePathPrefix(*it, dropped_prefix, "").has_value()) {
      offloadable_set.erase(it++);
    } else {
      ++it;
    }
  }
}

// Drops the offloadable paths inside `object_path` whose member is not in `keys`.
void keepOnlyOffloadablePaths(absl::flat_hash_set<std::string>& offloadable_set,
                              absl::string_view object_path, const std::vector<std::string>& keys) {
  for (auto it = offloadable_set.begin(); it != offloadable_set.end();) {
    absl::string_view rest = *it;
    if (!object_path.empty()) {
      if (!absl::StartsWith(rest, object_path) ||
          !absl::StartsWith(rest.substr(object_path.size()), ".")) {
        ++it;
        continue;
      }
      rest.remove_prefix(object_path.size() + 1);
    }
    const absl::string_view member = rest.substr(0, rest.find_first_of(".["));
    if (std::find(keys.begin(), keys.end(), member) == keys.end()) {
      offloadable_set.erase(it++);
    } else {
      ++it;
    }
  }
}

absl::Status rejectOffloadableRead(const absl::flat_hash_set<std::string>& offloadable_set,
                                   const std::string& path, absl::string_view rule) {
  if (offloadable_set.contains(path)) {
    return absl::InvalidArgumentError(
        absl::StrCat("transcoding verifier error: ", rule, " rule cannot read offloadable field '",
                     path, "' because large values are represented as ExternalRef nodes"));
  }
  return absl::OkStatus();
}

// Walks `rules` in execution order, evolving `offloadable_set` as structural rules relocate fields
// and rejecting any rule that reads the value of a field that is currently offloadable.
absl::Status verifyRulesTrackProvenance(const std::vector<TranscodeRule>& rules,
                                        absl::string_view prefix,
                                        absl::flat_hash_set<std::string>& offloadable_set) {
  for (const TranscodeRule& rule : rules) {
    switch (rule.op()) {
    case TranscodeRule::Op::Move:
      relocateOffloadablePaths(offloadable_set, joinRulePath(prefix, rule.sourcePath()),
                               joinRulePath(prefix, rule.targetPath()));
      break;
    case TranscodeRule::Op::FirstOf: {
      const std::string target = joinRulePath(prefix, rule.targetPath());
      for (const std::string& candidate : rule.sourcePaths()) {
        relocateOffloadablePaths(offloadable_set, joinRulePath(prefix, candidate), target);
      }
      break;
    }
    case TranscodeRule::Op::Drop:
    case TranscodeRule::Op::Discard:
      dropOffloadablePaths(offloadable_set, joinRulePath(prefix, rule.sourcePath()));
      break;
    case TranscodeRule::Op::KeepOnly:
      keepOnlyOffloadablePaths(offloadable_set, joinRulePath(prefix, rule.targetPath()),
                               rule.keys());
      break;
    case TranscodeRule::Op::EnsureObject: {
      const std::string target = joinRulePath(prefix, rule.targetPath());
      relocateOffloadablePaths(offloadable_set, target,
                               absl::StrCat(target, ".", rule.extractSubpath()),
                               /*keep_source=*/true);
      break;
    }
    case TranscodeRule::Op::UnwrapSingleKeyObject: {
      const std::string target = joinRulePath(prefix, rule.targetPath());
      relocateOffloadablePaths(offloadable_set, absl::StrCat(target, ".", rule.extractSubpath()),
                               target, /*keep_source=*/true);
      break;
    }
    case TranscodeRule::Op::WrapInArrayObject:
      relocateOffloadablePaths(
          offloadable_set, joinRulePath(prefix, rule.sourcePath()),
          absl::StrCat(joinRulePath(prefix, rule.targetPath()), "[].", rule.extractSubpath()));
      break;
    case TranscodeRule::Op::UnwrapArrayObject: {
      const std::string target = joinRulePath(prefix, rule.targetPath());
      relocateOffloadablePaths(
          offloadable_set,
          absl::StrCat(joinRulePath(prefix, rule.sourcePath()), "[].", rule.extractSubpath()),
          target);
      // Multiple unwrapped parts fan out into `[{"type": "text", "text": ...}]` blocks.
      relocateOffloadablePaths(offloadable_set, target, absl::StrCat(target, "[].text"),
                               /*keep_source=*/true);
      break;
    }
    case TranscodeRule::Op::ExtractFromArray: {
      const std::string target = joinRulePath(prefix, rule.targetPath());
      relocateOffloadablePaths(
          offloadable_set,
          absl::StrCat(joinRulePath(prefix, rule.sourcePath()), "[].", rule.extractSubpath()),
          target, /*keep_source=*/true);
      // Multiple matched elements concatenate into `[{"type": "text", "text": ...}]` blocks.
      relocateOffloadablePaths(offloadable_set, target, absl::StrCat(target, "[].text"),
                               /*keep_source=*/true);
      break;
    }
    case TranscodeRule::Op::PrependToArray:
      relocateOffloadablePaths(
          offloadable_set, joinRulePath(prefix, rule.sourcePath()),
          absl::StrCat(joinRulePath(prefix, rule.targetPath()), "[].", rule.extractSubpath()));
      break;
    case TranscodeRule::Op::ValueMap: {
      const std::string full_path = joinRulePath(prefix, rule.targetPath());
      if (offloadable_set.contains(full_path)) {
        return absl::InvalidArgumentError(absl::StrCat(
            "transcoding verifier error: value_map rule cannot target offloadable field '",
            full_path, "' because large values are represented as ExternalRef nodes"));
      }
      break;
    }
    case TranscodeRule::Op::DropElements:
    case TranscodeRule::Op::DiscardElements: {
      // Which elements go is only known at runtime, so the survivors keep their provenance.
      absl::Status status = rejectOffloadableRead(
          offloadable_set,
          absl::StrCat(joinRulePath(prefix, rule.sourcePath()), "[].", rule.predicateField()),
          "drop_elements");
      if (!status.ok()) {
        return status;
      }
      break;
    }
    case TranscodeRule::Op::Fail:
      if (!rule.sourcePath().empty()) {
        absl::Status status =
            rejectOffloadableRead(offloadable_set, joinRulePath(prefix, rule.sourcePath()), "fail");
        if (!status.ok()) {
          return status;
        }
      }
      break;
    case TranscodeRule::Op::When: {
      if (rule.condition()->readsValue()) {
        absl::Status status = rejectOffloadableRead(
            offloadable_set, joinRulePath(prefix, rule.condition()->path()), "when");
        if (!status.ok()) {
          return status;
        }
      }
      // The sub-rules may or may not run, so a field keeps every provenance either path gives it.
      absl::flat_hash_set<std::string> applied = offloadable_set;
      absl::Status status = verifyRulesTrackProvenance(rule.subRules(), prefix, applied);
      if (!status.ok()) {
        return status;
      }
      offloadable_set.insert(applied.begin(), applied.end());
      break;
    }
    case TranscodeRule::Op::ForEach: {
      const std::string array_prefix = absl::StrCat(joinRulePath(prefix, rule.targetPath()), "[]");
      absl::Status status =
          verifyRulesTrackProvenance(rule.subRules(), array_prefix, offloadable_set);
      if (!status.ok()) {
        return status;
      }
      break;
    }
    case TranscodeRule::Op::EnsureArray: {
      const std::string target = joinRulePath(prefix, rule.targetPath());
      relocateOffloadablePaths(offloadable_set, target, absl::StrCat(target, "[]"),
                               /*keep_source=*/true);
      break;
    }
    case TranscodeRule::Op::MergeConsecutiveByKey: {
      const std::string merge_field =
          absl::StrCat(joinRulePath(prefix, rule.targetPath()), "[].", rule.extractSubpath());
      relocateOffloadablePaths(offloadable_set, merge_field, absl::StrCat(merge_field, "[].text"),
                               /*keep_source=*/true);
      break;
    }
    case TranscodeRule::Op::SetDefault:
    case TranscodeRule::Op::CoerceNumeric:
      break;
    }
  }
  return absl::OkStatus();
}

std::vector<TranscodeRule> concat(std::initializer_list<std::vector<TranscodeRule>> groups) {
  std::vector<TranscodeRule> rules;
  for (const std::vector<TranscodeRule>& group : groups) {
    rules.insert(rules.end(), group.begin(), group.end());
  }
  return rules;
}

// Only function tools can be converted yet; other tool types would reach the upstream in a shape
// it rejects.
std::vector<TranscodeRule> functionToolsOnly() {
  return {TranscodeRule::forEach(
      "tools", {TranscodeRule::when(
                   TranscodeCondition::notIn("type", {"function"}),
                   {TranscodeRule::fail(
                       "{path} is not a function tool; other tools are not supported yet")})})};
}

// Tool-call turns and non-text content cannot be converted yet. Text parts keep only what every
// protocol can carry.
std::vector<TranscodeRule> textOnlyMessages() {
  return {TranscodeRule::forEach(
      "messages",
      {
          TranscodeRule::when(TranscodeCondition::in("role", {"tool"}),
                              {TranscodeRule::fail("tool call messages are not supported yet: "
                                                   "{path} has role 'tool'")}),
          TranscodeRule::when(TranscodeCondition::in("role", {"function"}),
                              {TranscodeRule::fail("tool call messages are not supported yet: "
                                                   "{path} has role 'function'")}),
          TranscodeRule::when(
              TranscodeCondition::hasValue("tool_calls"),
              {TranscodeRule::fail("tool calls are not supported yet: {path} has 'tool_calls'")}),
          TranscodeRule::when(TranscodeCondition::hasValue("function_call"),
                              {TranscodeRule::fail(
                                  "tool calls are not supported yet: {path} has 'function_call'")}),
          TranscodeRule::forEach(
              "content",
              {
                  TranscodeRule::when(
                      TranscodeCondition::notIn("type", {"text"}),
                      {TranscodeRule::fail("content part type {value} is not supported yet",
                                           "type")}),
                  TranscodeRule::when(
                      TranscodeCondition::notString("text"),
                      {TranscodeRule::fail("{path} is a text content part without text")}),
                  TranscodeRule::keepOnly({"type", "text"}),
              }),
      })};
}

// Fields every protocol spells alike but gives its own meaning or value set.
std::vector<TranscodeRule> foreignFields(LLMProtocol target) {
  return {
      TranscodeRule::drop("store"),
      // Only `auto` means the same to OpenAI and Anthropic; Gemini has no such tier.
      target == LLMProtocol::GeminiGenerateContent
          ? TranscodeRule::drop("service_tier")
          : TranscodeRule::when(TranscodeCondition::notIn("service_tier", {"auto"}),
                                {TranscodeRule::drop("service_tier")}),
      // A tool choice without tools asks for nothing, and some upstreams reject it.
      TranscodeRule::when(TranscodeCondition::noValue("tools"),
                          {TranscodeRule::discard("tools"), TranscodeRule::discard("tool_choice"),
                           TranscodeRule::discard("parallel_tool_calls")}),
  };
}

std::vector<TranscodeRule> singleChoice(LLMProtocol target) {
  return {
      TranscodeRule::when(TranscodeCondition::present("n"),
                          {TranscodeRule::when(TranscodeCondition::notIn("n", {1}),
                                               {TranscodeRule::fail(absl::StrCat(
                                                   llmProtocolName(target),
                                                   " returns a single choice: 'n' must be 1"))})}),
      TranscodeRule::discard("n"),
  };
}

// Keeps the parts of a Gemini `Content` that the IR can hold. A thought is the model's own
// reasoning, so it is dropped rather than replayed to another model as answer text.
std::vector<TranscodeRule> geminiTextParts(const std::string& parts_path) {
  std::vector<TranscodeRule> part_rules;
  for (const char* key :
       {"functionCall", "function_call", "functionResponse", "function_response"}) {
    part_rules.push_back(
        TranscodeRule::when(TranscodeCondition::present(key),
                            {TranscodeRule::fail(absl::StrCat(
                                "tool calls are not supported yet: {path} has '", key, "'"))}));
  }
  for (const char* key : {"inlineData", "inline_data", "fileData", "file_data", "executableCode",
                          "executable_code", "codeExecutionResult", "code_execution_result"}) {
    part_rules.push_back(TranscodeRule::when(
        TranscodeCondition::present(key),
        {TranscodeRule::fail(absl::StrCat("content part type ", key, " is not supported yet"))}));
  }
  return {
      TranscodeRule::forEach(parts_path, std::move(part_rules)),
      TranscodeRule::dropElements(parts_path, "thought", {true}),
  };
}

// Gemini's JSON mode, `responseMimeType: application/json` with an optional JSON Schema, is the
// IR's `response_format`. `text/plain` is the default and asks for nothing.
std::vector<TranscodeRule> geminiJsonMode() {
  std::vector<TranscodeRule> rules;
  for (const char* config : {"generationConfig", "generation_config"}) {
    std::vector<TranscodeRule> json_mode;
    // `responseSchema` is an OpenAPI subset, not JSON Schema, so it is left to be reported.
    for (const char* key : {"responseJsonSchema", "response_json_schema"}) {
      const std::string path = absl::StrCat(config, ".", key);
      json_mode.push_back(
          TranscodeRule::when(TranscodeCondition::isObject(path),
                              {TranscodeRule::move(path, "response_format.json_schema.schema")}));
    }
    json_mode.push_back(TranscodeRule::setDefault("response_format.type", "json_object"));
    for (const char* key : {"responseMimeType", "response_mime_type"}) {
      const std::string path = absl::StrCat(config, ".", key);
      std::vector<TranscodeRule> enable = json_mode;
      enable.push_back(TranscodeRule::discard(path));
      rules.push_back(TranscodeRule::when(TranscodeCondition::in(path, {"application/json"}),
                                          std::move(enable)));
      rules.push_back(TranscodeRule::valueMap(path, {{"text/plain", nullptr}}));
    }
  }
  rules.push_back(TranscodeRule::when(
      TranscodeCondition::isObject("response_format.json_schema.schema"),
      {
          TranscodeRule::valueMap("response_format.type", {{"json_object", "json_schema"}}),
          TranscodeRule::setDefault("response_format.json_schema.name", "response"),
      }));
  return rules;
}

// Builds the declarative transcoding pack for Anthropic Messages <-> IR (OpenAI Chat).
DialectTranscodePack createAnthropicTranscodePack() {
  return DialectTranscodePack{
      /*protocol=*/LLMProtocol::AnthropicMessages,
      /*to_IR=*/
      TranscodeRuleSet(
          LLMProtocol::AnthropicMessages, TranscodingEngine::kIrProtocol,
          {
              // Anthropic clients replay their thinking every turn; no other protocol can take it.
              TranscodeRule::forEach("messages",
                                     {
                                         TranscodeRule::dropElements(
                                             "content", "type", {"thinking", "redacted_thinking"}),
                                     }),
              // 1. Prepend top-level `system` prompt into `messages[]` as `{role: "system", ...}`
              TranscodeRule::prependToArray("system", "messages", "role", "system", "content"),
              // 2. Map Anthropic `max_tokens` and `stop_sequences` to IR (OpenAI Chat) names
              TranscodeRule::move("max_tokens", "max_completion_tokens"),
              TranscodeRule::move("stop_sequences", "stop"),
              TranscodeRule::move("metadata.user_id", "user"),
              // 3. Map Anthropic `tools[]` (`{name, description, input_schema}`) to OpenAI
              //    `tools[]` (`{type: "function", function: {name, description, parameters}}`)
              TranscodeRule::forEach(
                  "tools",
                  {
                      TranscodeRule::move("name", "function.name"),
                      TranscodeRule::move("description", "function.description"),
                      TranscodeRule::move("input_schema", "function.parameters"),
                      TranscodeRule::setDefault("type", "function"),
                      // Anthropic's SDK spells a client tool's optional type `custom`.
                      TranscodeRule::valueMap("type", {{"custom", "function"}}),
                  }),
              // 4. Convert Anthropic `tool_choice` (always an object) to OpenAI IR:
              //      {"type": "auto"|"none"}        -> "auto" | "none"
              //      {"type": "any"}                -> "required"
              //      {"type": "tool", "name": "fn"} -> {"type": "function", "function": {"name":
              //      "fn"}}
              //    `disable_parallel_tool_use` becomes the IR's `parallel_tool_calls` and must
              //    leave first so `unwrapSingleKeyObject` sees a single-key `{"type": "..."}`
              //    object and collapses it to a string (leaving two-key `{"type": "function",
              //    "function": {...}}` intact).
              TranscodeRule::valueMap("tool_choice.disable_parallel_tool_use",
                                      {{true, false}, {false, nullptr}}),
              TranscodeRule::firstOf({"tool_choice.disable_parallel_tool_use"},
                                     "parallel_tool_calls"),
              TranscodeRule::valueMap("tool_choice.type",
                                      {{"any", "required"}, {"tool", "function"}}),
              TranscodeRule::move("tool_choice.name", "tool_choice.function.name"),
              TranscodeRule::unwrapSingleKeyObject("tool_choice", "type"),
          }),
      /*from_IR=*/
      TranscodeRuleSet(
          TranscodingEngine::kIrProtocol, LLMProtocol::AnthropicMessages,
          concat({
              functionToolsOnly(),
              textOnlyMessages(),
              foreignFields(LLMProtocol::AnthropicMessages),
              singleChoice(LLMProtocol::AnthropicMessages),
              {
                  // OpenAI's `metadata` is a free-form map; Anthropic's carries only the end
                  // user's id.
                  TranscodeRule::drop("metadata"),
                  TranscodeRule::when(TranscodeCondition::present("user"),
                                      {TranscodeRule::move("user", "metadata.user_id")}),
                  TranscodeRule::discard("stream_options"),
                  // 1. Extract `system` / `developer` messages from `messages[]` into top-level
                  // `system`
                  TranscodeRule::extractFromArray("messages", "role", {"system", "developer"},
                                                  "content", "system"),
                  // 2. Map OpenAI `tool` / `function` roles to `user` and merge adjacent
                  //    same-role messages (Anthropic requires strictly alternating `user` /
                  //    `assistant` roles)
                  TranscodeRule::forEach(
                      "messages",
                      {
                          TranscodeRule::valueMap("role", {{"tool", "user"}, {"function", "user"}}),
                      }),
                  TranscodeRule::mergeConsecutiveByKey("messages", "role", "content"),
                  // 3. Map token cap (`max_completion_tokens` or `max_tokens`) and apply
                  //    Anthropic's required `max_tokens` default if the client omitted both
                  TranscodeRule::firstOf({"max_completion_tokens", "max_tokens"}, "max_tokens"),
                  TranscodeRule::setDefault("max_tokens", TranscodeRule::Option::MaxOutputTokens),
                  // 4. Map `stop` -> `stop_sequences`. The IR accepts either a bare string or an
                  //    array here, while `stop_sequences` is array-only, so normalize first.
                  TranscodeRule::ensureArray("stop"),
                  TranscodeRule::move("stop", "stop_sequences"),
                  // 5. Map OpenAI `tools[]` (`function.{name, description, parameters}`) to
                  //    Anthropic `tools[]` (`{name, description, input_schema}`)
                  TranscodeRule::forEach(
                      "tools",
                      {
                          TranscodeRule::move("function.name", "name"),
                          TranscodeRule::move("function.description", "description"),
                          TranscodeRule::move("function.parameters", "input_schema"),
                          // OpenAI lets a function without arguments omit `parameters`, while
                          // Anthropic requires `input_schema`.
                          TranscodeRule::setDefault("input_schema",
                                                    nlohmann::json::object({{"type", "object"}})),
                          TranscodeRule::discard("type"),
                          TranscodeRule::discard("function"),
                      }),
                  // 6. Map `tool_choice` into Anthropic's object-only form. The wrap turns the
                  //    IR's bare `"auto"` / `"none"` / `"required"` into `{"type": ...}`; the
                  //    pinned-tool object is already an object and passes through the wrap
                  //    untouched.
                  TranscodeRule::ensureObject("tool_choice", "type"),
                  TranscodeRule::valueMap("tool_choice.type",
                                          {{"required", "any"}, {"function", "tool"}}),
                  TranscodeRule::move("tool_choice.function.name", "tool_choice.name"),
                  TranscodeRule::discard("tool_choice.function"),
                  // 7. Serial tool calls are a flag on Anthropic's tool choice, which defaults
                  //    to `auto`; a choice of no tool has nothing to serialize.
                  TranscodeRule::when(
                      TranscodeCondition::in("parallel_tool_calls", {false}),
                      {
                          TranscodeRule::setDefault("tool_choice",
                                                    nlohmann::json::object({{"type", "auto"}})),
                          TranscodeRule::when(
                              TranscodeCondition::notIn("tool_choice.type", {"none"}),
                              {TranscodeRule::setDefault("tool_choice.disable_parallel_tool_use",
                                                         true)}),
                      }),
                  TranscodeRule::discard("parallel_tool_calls"),
              },
          })),
      /*dialect_schema=*/nullptr,
      /*IR_schema=*/nullptr,
      /*response_codec=*/&anthropicMessagesResponseCodec(),
  };
}

// Builds the declarative transcoding pack for Gemini GenerateContent <-> IR (OpenAI Chat).
DialectTranscodePack createGeminiTranscodePack() {
  return DialectTranscodePack{
      /*protocol=*/LLMProtocol::GeminiGenerateContent,
      /*to_IR=*/
      TranscodeRuleSet(
          LLMProtocol::GeminiGenerateContent, TranscodingEngine::kIrProtocol,
          concat({
              {
                  // The path, not the body, says whether a Gemini client streams.
                  TranscodeRule::discard("stream"),
              },
              geminiTextParts("systemInstruction.parts"),
              geminiTextParts("system_instruction.parts"),
              {
                  TranscodeRule::forEach("contents", geminiTextParts("parts")),
                  // A turn that held only thoughts has nothing left to send.
                  TranscodeRule::discardElements("contents", "parts", {nlohmann::json::array()}),
                  // 1. Unwrap `systemInstruction.parts[0].text` -> `system`, then prepend to
                  //    `contents` before renaming `contents` -> `messages`
                  TranscodeRule::unwrapArrayObject("systemInstruction.parts", "text", "system"),
                  TranscodeRule::discard("systemInstruction"),
                  TranscodeRule::unwrapArrayObject("system_instruction.parts", "text", "system"),
                  TranscodeRule::discard("system_instruction"),
                  // 2. Move `contents` -> `messages`, unwrap `parts[0].text` -> `content`, and
                  //    map Gemini role `"model"` -> `"assistant"`
                  TranscodeRule::move("contents", "messages"),
                  TranscodeRule::forEach(
                      "messages",
                      {
                          // Gemini leaves `role` optional and Vertex defaults it to `user`. Both
                          // other dialects require it, so materialize the source default here
                          // rather than let an otherwise valid request fail their role check.
                          TranscodeRule::setDefault("role", "user"),
                          TranscodeRule::valueMap("role", {{"model", "assistant"}}),
                          TranscodeRule::unwrapArrayObject("parts", "text", "content"),
                      }),
                  TranscodeRule::prependToArray("system", "messages", "role", "system", "content"),
                  // 3. Hoist `generationConfig` / `generation_config` parameters to top-level IR
                  //    fields. Gemini renders proto numbers through ProtoJSON, so each of these
                  //    may arrive quoted (`"maxOutputTokens": "256"`). The IR and both other
                  //    dialects declare them as real numbers, so coerce after the hoist: the
                  //    destination path is single, while each source has up to four spellings.
                  TranscodeRule::firstOf(
                      {"generationConfig.maxOutputTokens", "generationConfig.max_output_tokens",
                       "generation_config.maxOutputTokens", "generation_config.max_output_tokens"},
                      "max_completion_tokens"),
                  TranscodeRule::toInteger("max_completion_tokens"),
                  TranscodeRule::firstOf(
                      {"generationConfig.temperature", "generation_config.temperature"},
                      "temperature"),
                  TranscodeRule::toNumber("temperature"),
                  TranscodeRule::firstOf({"generationConfig.topP", "generationConfig.top_p",
                                          "generation_config.topP", "generation_config.top_p"},
                                         "top_p"),
                  TranscodeRule::toNumber("top_p"),
                  // `stopSequences` is already an array of strings in both dialects.
                  TranscodeRule::firstOf(
                      {"generationConfig.stopSequences", "generationConfig.stop_sequences",
                       "generation_config.stopSequences", "generation_config.stop_sequences"},
                      "stop"),
                  TranscodeRule::firstOf(
                      {"generationConfig.candidateCount", "generationConfig.candidate_count",
                       "generation_config.candidateCount", "generation_config.candidate_count"},
                      "n"),
                  TranscodeRule::toInteger("n"),
                  TranscodeRule::firstOf({"generationConfig.seed", "generation_config.seed"},
                                         "seed"),
                  TranscodeRule::toInteger("seed"),
                  TranscodeRule::firstOf(
                      {"generationConfig.presencePenalty", "generationConfig.presence_penalty",
                       "generation_config.presencePenalty", "generation_config.presence_penalty"},
                      "presence_penalty"),
                  TranscodeRule::toNumber("presence_penalty"),
                  TranscodeRule::firstOf(
                      {"generationConfig.frequencyPenalty", "generationConfig.frequency_penalty",
                       "generation_config.frequencyPenalty", "generation_config.frequency_penalty"},
                      "frequency_penalty"),
                  TranscodeRule::toNumber("frequency_penalty"),
              },
              geminiJsonMode(),
              {
                  // Dropping the rest of `generationConfig` also masks a latent version of the
                  // coercion above: `topK`, `logprobs` and `thinkingConfig.thinkingBudget` are
                  // all declared number-or-string too. Whoever makes the IR lossless must coerce
                  // them on the way through, or they reach the destination quoted.
                  TranscodeRule::drop("generationConfig"),
                  TranscodeRule::drop("generation_config"),
                  // TODO(ginama): Map `toolConfig.functionCallingConfig` -> `tool_choice`.
                  // Gemini uses `mode: "ANY"` for both `"required"` (when `allowedFunctionNames`
                  // is omitted) and `{"type": "function", "function": {"name": "fn"}}` (when
                  // `allowedFunctionNames` is set), which requires conditional mapping support.
              },
          })),
      /*from_IR=*/
      TranscodeRuleSet(
          TranscodingEngine::kIrProtocol, LLMProtocol::GeminiGenerateContent,
          concat({
              {
                  // TODO(botengyao): Map `tool_choice` to `toolConfig.functionCallingConfig` with
                  // the tools.
                  TranscodeRule::when(
                      TranscodeCondition::hasValue("tools"),
                      {TranscodeRule::fail(absl::StrCat(
                          "tools are not supported for ",
                          llmProtocolName(LLMProtocol::GeminiGenerateContent), " yet"))}),
              },
              textOnlyMessages(),
              foreignFields(LLMProtocol::GeminiGenerateContent),
              singleChoice(LLMProtocol::GeminiGenerateContent),
              {
                  // 1. Extract `system` / `developer` messages from `messages[]` and wrap into
                  //    `systemInstruction.parts[{text: ...}]`
                  TranscodeRule::extractFromArray("messages", "role", {"system", "developer"},
                                                  "content", "systemInstruction.content"),
                  TranscodeRule::wrapInArrayObject("systemInstruction.content",
                                                   "systemInstruction.parts", "text"),
                  // 2. Transform `messages[]` -> `contents[]`, mapping `"assistant"` -> `"model"`
                  //    and wrapping `content` -> `parts: [{text: <moved_node>}]`
                  TranscodeRule::forEach(
                      "messages",
                      {
                          TranscodeRule::valueMap("role",
                                                  {{"assistant", "model"}, {"tool", "user"}}),
                          TranscodeRule::wrapInArrayObject("content", "parts", "text"),
                      }),
                  TranscodeRule::move("messages", "contents"),
                  // 3. Nest generation parameters under `generationConfig`
                  TranscodeRule::firstOf({"max_completion_tokens", "max_tokens"},
                                         "generationConfig.maxOutputTokens"),
                  TranscodeRule::move("temperature", "generationConfig.temperature"),
                  TranscodeRule::move("top_p", "generationConfig.topP"),
                  // `stopSequences` is array-only, while the IR also allows a bare string.
                  TranscodeRule::ensureArray("stop"),
                  TranscodeRule::move("stop", "generationConfig.stopSequences"),
                  TranscodeRule::firstOf({"seed"}, "generationConfig.seed"),
                  TranscodeRule::firstOf({"presence_penalty"}, "generationConfig.presencePenalty"),
                  TranscodeRule::firstOf({"frequency_penalty"},
                                         "generationConfig.frequencyPenalty"),
                  // Any other `response_format` is left for pruning to report.
                  TranscodeRule::when(
                      TranscodeCondition::in("response_format.type",
                                             {"json_object", "json_schema"}),
                      {
                          TranscodeRule::setDefault("generationConfig.responseMimeType",
                                                    "application/json"),
                          TranscodeRule::firstOf({"response_format.json_schema.schema"},
                                                 "generationConfig.responseJsonSchema"),
                          TranscodeRule::discard("response_format"),
                      }),
                  TranscodeRule::when(TranscodeCondition::in("response_format.type", {"text"}),
                                      {TranscodeRule::discard("response_format")}),
                  // 4. Gemini carries the model and the streaming choice in the request path.
                  TranscodeRule::discard("model"),
                  TranscodeRule::discard("stream"),
                  TranscodeRule::discard("stream_options"),
              },
          })),
      /*dialect_schema=*/nullptr,
      /*IR_schema=*/nullptr,
      /*response_codec=*/&geminiGenerateContentResponseCodec(),
  };
}

// Builds the pack for OpenAI Chat Completions (the IR protocol). Its from-IR rules gate what a
// request converted from another protocol may carry to an OpenAI upstream.
DialectTranscodePack createOpenAiChatTranscodePack() {
  return DialectTranscodePack{
      /*protocol=*/LLMProtocol::OpenAiChatCompletions,
      /*to_IR=*/
      TranscodeRuleSet(LLMProtocol::OpenAiChatCompletions, TranscodingEngine::kIrProtocol, {}),
      /*from_IR=*/
      TranscodeRuleSet(TranscodingEngine::kIrProtocol, LLMProtocol::OpenAiChatCompletions,
                       concat({
                           functionToolsOnly(),
                           textOnlyMessages(),
                           foreignFields(LLMProtocol::OpenAiChatCompletions),
                           {
                               // The upstream streams usage only when asked, and the response side
                               // needs it to report usage in the client's protocol.
                               TranscodeRule::discard("stream_options"),
                               TranscodeRule::when(
                                   TranscodeCondition::in("stream", {true}),
                                   {TranscodeRule::setDefault("stream_options.include_usage",
                                                              TranscodeRule::Option::StreamUsage)}),
                           },
                       })),
  };
}

absl::flat_hash_set<absl::string_view> declaredNames(const Schema& schema) {
  absl::flat_hash_set<absl::string_view> declared;
  for (const Schema::Property& property : schema.properties()) {
    declared.insert(property.name);
    declared.insert(property.aliases.begin(), property.aliases.end());
  }
  return declared;
}

// Removes the members of `object` that `schema` does not declare, reporting those that carried a
// value as `prefix` + name.
void pruneUndeclared(nlohmann::json& object, const Schema& schema, absl::string_view prefix,
                     TranscodeReport& report) {
  const absl::flat_hash_set<absl::string_view> declared = declaredNames(schema);
  for (auto it = object.begin(); it != object.end();) {
    if (declared.contains(it.key())) {
      ++it;
      continue;
    }
    if (carriesValue(*it)) {
      report.add(absl::StrCat(prefix, it.key()));
    }
    it = object.erase(it);
  }
}

// Prunes the root, and the elements of every root array of objects, to what `root` declares. An
// element schema that declares no members constrains nothing, so its elements are left alone.
void pruneToSchema(nlohmann::json& body, const Schema& root, TranscodeReport& report) {
  if (root.type() != Schema::Type::Object) {
    return;
  }
  pruneUndeclared(body, root, "", report);
  for (const Schema::Property& property : root.properties()) {
    if (property.schema == nullptr || property.schema->type() != Schema::Type::Array) {
      continue;
    }
    const Schema* element = property.schema->elementSchema();
    if (element == nullptr || element->type() != Schema::Type::Object ||
        element->properties().empty()) {
      continue;
    }
    std::vector<absl::string_view> names = {property.name};
    names.insert(names.end(), property.aliases.begin(), property.aliases.end());
    for (absl::string_view name : names) {
      auto array = body.find(name);
      if (array == body.end() || !array->is_array()) {
        continue;
      }
      const std::string prefix = absl::StrCat(name, "[].");
      for (nlohmann::json& item : *array) {
        if (item.is_object()) {
          pruneUndeclared(item, *element, prefix, report);
        }
      }
    }
  }
}

constexpr absl::string_view kModelsSegment = "/models/";

bool isTrue(const nlohmann::json& object, const char* key) {
  auto it = object.find(key);
  return it != object.end() && it->is_boolean() && it->get<bool>();
}

absl::StatusOr<RequestEnvelope> readEnvelopeFromBody(LLMProtocol protocol,
                                                     const nlohmann::json& body) {
  if (!body.is_object()) {
    return absl::InvalidArgumentError("request body is not a JSON object");
  }
  auto model = body.find("model");
  if (model == body.end() || !model->is_string() || model->get_ref<const std::string&>().empty()) {
    return absl::InvalidArgumentError("request has no model: 'model' must be a non-empty string");
  }
  RequestEnvelope envelope;
  envelope.model = model->get<std::string>();
  envelope.stream = isTrue(body, "stream");
  if (protocol == LLMProtocol::OpenAiChatCompletions) {
    auto options = body.find("stream_options");
    envelope.include_usage =
        options != body.end() && options->is_object() && isTrue(*options, "include_usage");
  }
  return envelope;
}

// Gemini API and Vertex AI paths alike end in `/models/{model}:{method}`.
absl::StatusOr<RequestEnvelope> readEnvelopeFromGeminiPath(absl::string_view full_path) {
  const absl::string_view path = Http::Utility::stripQueryStringView(full_path);
  const size_t models = path.rfind(kModelsSegment);
  if (models == absl::string_view::npos) {
    return absl::InvalidArgumentError(absl::StrCat(
        "request path '", path, "' names no model: expected '.../models/{model}:...'"));
  }
  const absl::string_view resource = path.substr(models + kModelsSegment.size());
  const size_t colon = resource.rfind(':');
  if (colon == absl::string_view::npos || colon == 0) {
    return absl::InvalidArgumentError(absl::StrCat(
        "request path '", path, "' names no model: expected '.../models/{model}:{method}'"));
  }
  RequestEnvelope envelope;
  const absl::string_view method = resource.substr(colon + 1);
  if (method == "generateContent") {
    envelope.stream = false;
  } else if (method == "streamGenerateContent") {
    envelope.stream = true;
    // Without `alt=sse` the stream is one JSON array rather than SSE events.
    envelope.sse = absl::StrContains(full_path, "alt=sse");
  } else {
    return absl::InvalidArgumentError(
        absl::StrCat("unsupported Gemini method '", method,
                     "': expected 'generateContent' or 'streamGenerateContent'"));
  }
  envelope.model = Http::Utility::PercentEncoding::decode(resource.substr(0, colon));
  return envelope;
}

absl::Status unsupportedResponsePair(LLMProtocol from, LLMProtocol to) {
  return absl::InvalidArgumentError(absl::StrCat(
      "no response conversion from ", llmProtocolName(from), " to ", llmProtocolName(to)));
}

} // namespace

void TranscodeReport::add(std::string field) {
  if (std::find(dropped.begin(), dropped.end(), field) == dropped.end()) {
    dropped.push_back(std::move(field));
  }
}

TranscodeCondition::TranscodeCondition(Kind kind, bool negated, std::string path)
    : kind_(kind), negated_(negated), segments_(splitPath(path)) {
  path_ = std::move(path);
}

TranscodeCondition TranscodeCondition::hasValue(std::string path) {
  return {Kind::HasValue, false, std::move(path)};
}

TranscodeCondition TranscodeCondition::noValue(std::string path) {
  return {Kind::HasValue, true, std::move(path)};
}

TranscodeCondition TranscodeCondition::present(std::string path) {
  return {Kind::Present, false, std::move(path)};
}

TranscodeCondition TranscodeCondition::in(std::string path, std::vector<nlohmann::json> values) {
  TranscodeCondition condition(Kind::In, false, std::move(path));
  condition.values_ = std::move(values);
  return condition;
}

TranscodeCondition TranscodeCondition::notIn(std::string path, std::vector<nlohmann::json> values) {
  TranscodeCondition condition(Kind::In, true, std::move(path));
  condition.values_ = std::move(values);
  return condition;
}

TranscodeCondition TranscodeCondition::isObject(std::string path) {
  return {Kind::IsObject, false, std::move(path)};
}

TranscodeCondition TranscodeCondition::notString(std::string path) {
  return {Kind::IsString, true, std::move(path)};
}

bool TranscodeCondition::holds(const nlohmann::json& object) const {
  const nlohmann::json* node = findNodeByPath(object, segments_);
  bool result = false;
  if (node != nullptr) {
    switch (kind_) {
    case Kind::HasValue:
      result = carriesValue(*node);
      break;
    case Kind::Present:
      result = !node->is_null();
      break;
    case Kind::In:
      result = std::find(values_.begin(), values_.end(), *node) != values_.end();
      break;
    case Kind::IsObject:
      result = node->is_object();
      break;
    case Kind::IsString:
      result = node->is_string() || JsonWithExtBuf::isExternalRef(*node);
      break;
    }
  }
  return result != negated_;
}

TranscodeRule TranscodeRule::move(std::string from_path, std::string to_path) {
  TranscodeRule rule(Op::Move);
  rule.source_segments_ = splitPath(from_path);
  rule.source_path_ = std::move(from_path);
  rule.target_segments_ = splitPath(to_path);
  rule.target_path_ = std::move(to_path);
  return rule;
}

TranscodeRule TranscodeRule::firstOf(std::initializer_list<std::string> from_paths,
                                     std::string to_path) {
  TranscodeRule rule(Op::FirstOf);
  rule.source_paths_.assign(from_paths.begin(), from_paths.end());
  rule.source_paths_segments_.reserve(rule.source_paths_.size());
  for (const std::string& candidate : rule.source_paths_) {
    rule.source_paths_segments_.push_back(splitPath(candidate));
  }
  rule.target_segments_ = splitPath(to_path);
  rule.target_path_ = std::move(to_path);
  return rule;
}

TranscodeRule TranscodeRule::drop(std::string path) {
  TranscodeRule rule(Op::Drop);
  rule.source_segments_ = splitPath(path);
  rule.source_path_ = std::move(path);
  return rule;
}

TranscodeRule TranscodeRule::discard(std::string path) {
  TranscodeRule rule(Op::Discard);
  rule.source_segments_ = splitPath(path);
  rule.source_path_ = std::move(path);
  return rule;
}

TranscodeRule TranscodeRule::setDefault(std::string path, nlohmann::json default_value) {
  TranscodeRule rule(Op::SetDefault);
  rule.target_segments_ = splitPath(path);
  rule.target_path_ = std::move(path);
  rule.default_value_ = std::move(default_value);
  return rule;
}

TranscodeRule TranscodeRule::setDefault(std::string path, Option option) {
  TranscodeRule rule(Op::SetDefault);
  rule.target_segments_ = splitPath(path);
  rule.target_path_ = std::move(path);
  rule.option_ = option;
  return rule;
}

TranscodeRule TranscodeRule::ensureArray(std::string path) {
  TranscodeRule rule(Op::EnsureArray);
  rule.target_segments_ = splitPath(path);
  rule.target_path_ = std::move(path);
  return rule;
}

TranscodeRule TranscodeRule::ensureObject(std::string path, std::string key) {
  TranscodeRule rule(Op::EnsureObject);
  rule.target_segments_ = splitPath(path);
  rule.target_path_ = std::move(path);
  rule.extract_subpath_ = std::move(key);
  return rule;
}

TranscodeRule TranscodeRule::unwrapSingleKeyObject(std::string path, std::string key) {
  TranscodeRule rule(Op::UnwrapSingleKeyObject);
  rule.target_segments_ = splitPath(path);
  rule.target_path_ = std::move(path);
  rule.extract_subpath_ = std::move(key);
  return rule;
}

TranscodeRule TranscodeRule::toNumber(std::string path) {
  TranscodeRule rule(Op::CoerceNumeric);
  rule.target_segments_ = splitPath(path);
  rule.target_path_ = std::move(path);
  return rule;
}

TranscodeRule TranscodeRule::toInteger(std::string path) {
  TranscodeRule rule(Op::CoerceNumeric);
  rule.target_segments_ = splitPath(path);
  rule.target_path_ = std::move(path);
  rule.integral_ = true;
  return rule;
}

TranscodeRule TranscodeRule::valueMap(std::string path,
                                      std::initializer_list<ValueMapping> mappings,
                                      UnknownValuePolicy unknown_policy) {
  TranscodeRule rule(Op::ValueMap);
  rule.target_segments_ = splitPath(path);
  rule.target_path_ = std::move(path);
  rule.value_mappings_.assign(mappings.begin(), mappings.end());
  rule.unknown_policy_ = unknown_policy;
  return rule;
}

TranscodeRule TranscodeRule::forEach(std::string array_path, std::vector<TranscodeRule> rules) {
  TranscodeRule rule(Op::ForEach);
  rule.target_segments_ = splitPath(array_path);
  rule.target_path_ = std::move(array_path);
  rule.sub_rules_ = std::move(rules);
  return rule;
}

TranscodeRule TranscodeRule::extractFromArray(std::string array_path, std::string predicate_field,
                                              std::initializer_list<std::string> match_values,
                                              std::string extract_subpath,
                                              std::string target_path) {
  TranscodeRule rule(Op::ExtractFromArray);
  rule.source_segments_ = splitPath(array_path);
  rule.source_path_ = std::move(array_path);
  rule.predicate_field_ = std::move(predicate_field);
  rule.match_values_.assign(match_values.begin(), match_values.end());
  rule.extract_subpath_segments_ = splitPath(extract_subpath);
  rule.extract_subpath_ = std::move(extract_subpath);
  rule.target_segments_ = splitPath(target_path);
  rule.target_path_ = std::move(target_path);
  return rule;
}

TranscodeRule TranscodeRule::prependToArray(std::string source_path, std::string array_path,
                                            std::string key_field, std::string key_value,
                                            std::string value_subpath) {
  TranscodeRule rule(Op::PrependToArray);
  rule.source_segments_ = splitPath(source_path);
  rule.source_path_ = std::move(source_path);
  rule.target_segments_ = splitPath(array_path);
  rule.target_path_ = std::move(array_path);
  rule.predicate_field_ = std::move(key_field);
  rule.match_values_ = {std::move(key_value)};
  rule.extract_subpath_segments_ = splitPath(value_subpath);
  rule.extract_subpath_ = std::move(value_subpath);
  return rule;
}

TranscodeRule TranscodeRule::wrapInArrayObject(std::string from_path, std::string to_array_path,
                                               std::string element_key) {
  TranscodeRule rule(Op::WrapInArrayObject);
  rule.source_segments_ = splitPath(from_path);
  rule.source_path_ = std::move(from_path);
  rule.target_segments_ = splitPath(to_array_path);
  rule.target_path_ = std::move(to_array_path);
  rule.extract_subpath_ = std::move(element_key);
  return rule;
}

TranscodeRule TranscodeRule::unwrapArrayObject(std::string from_array_path, std::string element_key,
                                               std::string to_path) {
  TranscodeRule rule(Op::UnwrapArrayObject);
  rule.source_segments_ = splitPath(from_array_path);
  rule.source_path_ = std::move(from_array_path);
  rule.extract_subpath_segments_ = splitPath(element_key);
  rule.extract_subpath_ = std::move(element_key);
  rule.target_segments_ = splitPath(to_path);
  rule.target_path_ = std::move(to_path);
  return rule;
}

TranscodeRule TranscodeRule::mergeConsecutiveByKey(std::string array_path, std::string key_field,
                                                   std::string merge_field) {
  TranscodeRule rule(Op::MergeConsecutiveByKey);
  rule.target_segments_ = splitPath(array_path);
  rule.target_path_ = std::move(array_path);
  rule.predicate_field_ = std::move(key_field);
  rule.extract_subpath_ = std::move(merge_field);
  return rule;
}

TranscodeRule TranscodeRule::dropElements(std::string array_path, std::string predicate_field,
                                          std::vector<nlohmann::json> values) {
  TranscodeRule rule(Op::DropElements);
  rule.source_segments_ = splitPath(array_path);
  rule.source_path_ = std::move(array_path);
  rule.predicate_segments_ = splitPath(predicate_field);
  rule.predicate_field_ = std::move(predicate_field);
  rule.match_json_ = std::move(values);
  return rule;
}

TranscodeRule TranscodeRule::discardElements(std::string array_path, std::string predicate_field,
                                             std::vector<nlohmann::json> values) {
  TranscodeRule rule =
      dropElements(std::move(array_path), std::move(predicate_field), std::move(values));
  rule.op_ = Op::DiscardElements;
  return rule;
}

TranscodeRule TranscodeRule::when(TranscodeCondition condition, std::vector<TranscodeRule> rules) {
  TranscodeRule rule(Op::When);
  rule.condition_ = std::move(condition);
  rule.sub_rules_ = std::move(rules);
  return rule;
}

TranscodeRule TranscodeRule::fail(std::string message, std::string value_path) {
  TranscodeRule rule(Op::Fail);
  rule.message_ = std::move(message);
  rule.source_segments_ = splitPath(value_path);
  rule.source_path_ = std::move(value_path);
  return rule;
}

TranscodeRule TranscodeRule::keepOnly(std::vector<std::string> keys, std::string path) {
  TranscodeRule rule(Op::KeepOnly);
  rule.keys_ = std::move(keys);
  rule.target_segments_ = splitPath(path);
  rule.target_path_ = std::move(path);
  return rule;
}

absl::Status TranscodeRule::apply(nlohmann::json& json) const {
  return apply(json, defaultOptions(), nullptr);
}

absl::Status TranscodeRule::apply(nlohmann::json& json, const TranscodeOptions& options,
                                  TranscodeReport* report) const {
  return applyIn(json, Scope(options, report));
}

absl::Status TranscodeRule::applyIn(nlohmann::json& json, const Scope& scope) const {
  if (!json.is_object()) {
    return absl::InvalidArgumentError("transcoding target must be a JSON object");
  }

  switch (op_) {
  case Op::Move: {
    if (source_path_ == target_path_) {
      return absl::OkStatus();
    }
    if (std::optional<nlohmann::json> val = extractNodeByPath(json, source_segments_);
        val.has_value()) {
      setNodeByPath(json, target_segments_, std::move(*val));
    }
    return absl::OkStatus();
  }

  case Op::FirstOf: {
    std::optional<nlohmann::json> chosen;
    for (const std::vector<std::string>& candidate_segments : source_paths_segments_) {
      std::optional<nlohmann::json> extracted = extractNodeByPath(json, candidate_segments);
      if (!chosen.has_value() && extracted.has_value() && !extracted->is_null()) {
        chosen = std::move(extracted);
      }
    }
    if (chosen.has_value()) {
      setNodeByPath(json, target_segments_, std::move(*chosen));
    }
    return absl::OkStatus();
  }

  case Op::Drop: {
    std::optional<nlohmann::json> removed = extractNodeByPath(json, source_segments_);
    if (!removed.has_value()) {
      return absl::OkStatus();
    }
    if (removed->is_object()) {
      for (auto it = removed->begin(); it != removed->end(); ++it) {
        if (carriesValue(*it)) {
          scope.report(absl::StrCat(source_path_, ".", it.key()));
        }
      }
    } else if (carriesValue(*removed)) {
      scope.report(source_path_);
    }
    return absl::OkStatus();
  }

  case Op::Discard: {
    extractNodeByPath(json, source_segments_);
    return absl::OkStatus();
  }

  case Op::SetDefault: {
    const nlohmann::json* existing = findNodeByPath(json, target_segments_);
    if (existing != nullptr && !existing->is_null()) {
      return absl::OkStatus();
    }
    nlohmann::json value = default_value_;
    if (option_.has_value()) {
      switch (*option_) {
      case Option::MaxOutputTokens:
        value = scope.options().default_max_output_tokens;
        break;
      case Option::StreamUsage:
        if (!scope.options().request_stream_usage) {
          return absl::OkStatus();
        }
        value = true;
        break;
      }
    }
    setNodeByPath(json, target_segments_, std::move(value));
    return absl::OkStatus();
  }

  case Op::EnsureArray: {
    nlohmann::json* node = findNodeByPath(json, target_segments_);
    // An absent or null field has nothing to normalize, and wrapping it would invent a value the
    // client never sent. An array is already the shape the destination wants.
    if (node == nullptr || node->is_null() || node->is_array()) {
      return absl::OkStatus();
    }
    nlohmann::json wrapped = nlohmann::json::array();
    // Moved, not copied, so an `ExternalRef` node survives the wrap without materializing.
    wrapped.push_back(std::move(*node));
    *node = std::move(wrapped);
    return absl::OkStatus();
  }

  case Op::EnsureObject: {
    nlohmann::json* node = findNodeByPath(json, target_segments_);
    if (node == nullptr || node->is_null() || node->is_object()) {
      return absl::OkStatus();
    }
    nlohmann::json wrapped = nlohmann::json::object();
    wrapped[extract_subpath_] = std::move(*node);
    *node = std::move(wrapped);
    return absl::OkStatus();
  }

  case Op::UnwrapSingleKeyObject: {
    nlohmann::json* node = findNodeByPath(json, target_segments_);
    // Anything carrying more than `extract_subpath_` is a structured value in its own right, so
    // collapsing it would discard the other members.
    if (node == nullptr || !node->is_object() || node->size() != 1) {
      return absl::OkStatus();
    }
    auto it = node->find(extract_subpath_);
    if (it == node->end()) {
      return absl::OkStatus();
    }
    nlohmann::json inner = std::move(*it);
    *node = std::move(inner);
    return absl::OkStatus();
  }

  case Op::CoerceNumeric: {
    nlohmann::json* node = findNodeByPath(json, target_segments_);
    // Only a genuine inline string needs converting. Anything else is either already a number or
    // an `ExternalRef` binary node, neither of which should be touched here.
    if (node == nullptr || !node->is_string()) {
      return absl::OkStatus();
    }
    const std::string& text = node->get_ref<const std::string&>();
    if (integral_) {
      int64_t parsed = 0;
      if (!absl::SimpleAtoi(text, &parsed)) {
        return absl::OkStatus();
      }
      *node = parsed;
      return absl::OkStatus();
    }
    double parsed = 0;
    // A non-finite number would serialize as null; left a string, the destination rejects it.
    if (!absl::SimpleAtod(text, &parsed) || !std::isfinite(parsed)) {
      return absl::OkStatus();
    }
    *node = parsed;
    return absl::OkStatus();
  }

  case Op::ValueMap: {
    nlohmann::json* node = findNodeByPath(json, target_segments_);
    if (node == nullptr || node->is_null()) {
      return absl::OkStatus();
    }
    if (JsonWithExtBuf::isExternalRef(*node)) {
      return absl::InvalidArgumentError(
          absl::StrCat("cannot apply value_map to offloaded ExternalRef at '", target_path_, "'"));
    }
    for (const ValueMapping& mapping : value_mappings_) {
      if (mapping.from != *node) {
        continue;
      }
      if (mapping.to.is_null()) {
        extractNodeByPath(json, target_segments_);
      } else {
        *node = mapping.to;
      }
      return absl::OkStatus();
    }
    switch (unknown_policy_) {
    case UnknownValuePolicy::Passthrough:
      return absl::OkStatus();
    case UnknownValuePolicy::Drop:
      if (carriesValue(*node)) {
        scope.report(target_path_);
      }
      extractNodeByPath(json, target_segments_);
      return absl::OkStatus();
    case UnknownValuePolicy::Reject:
      return absl::InvalidArgumentError(
          absl::StrCat("unmapped value '", renderValue(*node), "' at field '", target_path_, "'"));
    }
    return absl::OkStatus();
  }

  case Op::ForEach: {
    nlohmann::json* arr = findNodeByPath(json, target_segments_);
    if (arr == nullptr || !arr->is_array()) {
      return absl::OkStatus();
    }
    for (size_t i = 0; i < arr->size(); ++i) {
      nlohmann::json& item = (*arr)[i];
      if (!item.is_object()) {
        continue;
      }
      const Scope element_scope(scope, target_path_, i);
      for (const TranscodeRule& sub_rule : sub_rules_) {
        absl::Status status = sub_rule.applyIn(item, element_scope);
        if (!status.ok()) {
          return status;
        }
      }
    }
    return absl::OkStatus();
  }

  case Op::ExtractFromArray: {
    nlohmann::json* arr = findNodeByPath(json, source_segments_);
    if (arr == nullptr || !arr->is_array()) {
      return absl::OkStatus();
    }
    nlohmann::json remaining = nlohmann::json::array();
    // All matches are collected, not just the first. Keeping only the first would silently drop
    // the second and subsequent system prompts, which changes the model's behavior with no signal
    // to the client.
    nlohmann::json extracted = nlohmann::json::array();
    for (nlohmann::json& elem : *arr) {
      bool matched = false;
      if (elem.is_object()) {
        if (auto it = elem.find(predicate_field_); it != elem.end() && it->is_string()) {
          const std::string& val = it->get_ref<const std::string&>();
          matched =
              std::find(match_values_.begin(), match_values_.end(), val) != match_values_.end();
        }
      }
      if (matched) {
        // A null would become a block with null text once concatenated with other matches.
        if (std::optional<nlohmann::json> sub = extractNodeByPath(elem, extract_subpath_segments_);
            sub.has_value() && !sub->is_null()) {
          extracted.push_back(std::move(*sub));
        }
      } else {
        remaining.push_back(std::move(elem));
      }
    }
    *arr = std::move(remaining);
    if (extracted.empty()) {
      return absl::OkStatus();
    }
    if (extracted.size() == 1) {
      // A single match keeps its original scalar shape, which every dialect accepts.
      setNodeByPath(json, target_segments_, std::move(extracted[0]));
      return absl::OkStatus();
    }
    // Multiple matches are concatenated as content blocks so that no prompt is lost and no
    // offloadable `ExternalRef` node has to be stringified.
    nlohmann::json blocks = nlohmann::json::array();
    for (nlohmann::json& value : extracted) {
      for (nlohmann::json& block : toContentBlockArray(std::move(value))) {
        blocks.push_back(std::move(block));
      }
    }
    setNodeByPath(json, target_segments_, std::move(blocks));
    return absl::OkStatus();
  }

  case Op::PrependToArray: {
    std::optional<nlohmann::json> val = extractNodeByPath(json, source_segments_);
    if (!val.has_value() || val->is_null()) {
      return absl::OkStatus();
    }
    nlohmann::json elem = nlohmann::json::object();
    elem[predicate_field_] = match_values_.front();
    setNodeByPath(elem, extract_subpath_segments_, std::move(*val));

    nlohmann::json* arr = findNodeByPath(json, target_segments_);
    if (arr == nullptr || !arr->is_array()) {
      nlohmann::json new_arr = nlohmann::json::array();
      new_arr.push_back(std::move(elem));
      setNodeByPath(json, target_segments_, std::move(new_arr));
    } else {
      arr->insert(arr->begin(), std::move(elem));
    }
    return absl::OkStatus();
  }

  case Op::WrapInArrayObject: {
    std::optional<nlohmann::json> val = extractNodeByPath(json, source_segments_);
    if (!val.has_value() || val->is_null()) {
      return absl::OkStatus();
    }
    nlohmann::json arr = nlohmann::json::array();
    if (val->is_array()) {
      // Content that is already a block array fans out into one wrapper per block. Nesting the
      // whole array under a single key would produce e.g. a Gemini `part.text` holding an array,
      // which the dialect schema rejects.
      static const std::vector<std::string> kTextSegment = {"text"};
      for (nlohmann::json& block : *val) {
        nlohmann::json item = nlohmann::json::object();
        if (block.is_object()) {
          std::optional<nlohmann::json> text = extractNodeByPath(block, kTextSegment);
          if (!text.has_value()) {
            return absl::InvalidArgumentError(
                absl::StrCat("cannot transcode content block in '", source_path_,
                             "' without a 'text' field; multi-modal content is not supported yet"));
          }
          item[extract_subpath_] = std::move(*text);
        } else {
          item[extract_subpath_] = std::move(block);
        }
        arr.push_back(std::move(item));
      }
      setNodeByPath(json, target_segments_, std::move(arr));
      return absl::OkStatus();
    }
    nlohmann::json item = nlohmann::json::object();
    item[extract_subpath_] = std::move(*val);
    arr.push_back(std::move(item));
    setNodeByPath(json, target_segments_, std::move(arr));
    return absl::OkStatus();
  }

  case Op::UnwrapArrayObject: {
    std::optional<nlohmann::json> arr = extractNodeByPath(json, source_segments_);
    if (!arr.has_value() || !arr->is_array() || arr->empty()) {
      return absl::OkStatus();
    }
    // Every element must be unwrapped. Reading only the first one would silently delete the
    // remaining parts, which is how attached images disappear from a multi-modal request. An
    // element that does not carry `extract_subpath_` (an inline image blob, a function call, a
    // thought signature) has no text representation, so it is surfaced as an error rather than
    // dropped on the floor.
    nlohmann::json blocks = nlohmann::json::array();
    for (nlohmann::json& elem : *arr) {
      if (!elem.is_object()) {
        return absl::InvalidArgumentError(
            absl::StrCat("cannot transcode non-object element in '", source_path_, "'"));
      }
      std::optional<nlohmann::json> inner = extractNodeByPath(elem, extract_subpath_segments_);
      if (!inner.has_value()) {
        return absl::InvalidArgumentError(
            absl::StrCat("cannot transcode element in '", source_path_, "' without field '",
                         extract_subpath_, "'; multi-modal content is not supported yet"));
      }
      blocks.push_back(std::move(*inner));
    }
    if (blocks.size() == 1) {
      setNodeByPath(json, target_segments_, std::move(blocks[0]));
      return absl::OkStatus();
    }
    // Multiple parts collapse into the IR's array-of-content-blocks representation.
    nlohmann::json content = nlohmann::json::array();
    for (nlohmann::json& block : blocks) {
      nlohmann::json wrapper = nlohmann::json::object();
      wrapper["type"] = "text";
      wrapper["text"] = std::move(block);
      content.push_back(std::move(wrapper));
    }
    setNodeByPath(json, target_segments_, std::move(content));
    return absl::OkStatus();
  }

  case Op::MergeConsecutiveByKey: {
    nlohmann::json* arr = findNodeByPath(json, target_segments_);
    if (arr == nullptr || !arr->is_array() || arr->size() < 2) {
      return absl::OkStatus();
    }
    nlohmann::json merged = nlohmann::json::array();
    for (nlohmann::json& elem : *arr) {
      if (!merged.empty() && merged.back().is_object() && elem.is_object()) {
        auto prev_key_it = merged.back().find(predicate_field_);
        auto curr_key_it = elem.find(predicate_field_);
        if (prev_key_it != merged.back().end() && curr_key_it != elem.end() &&
            prev_key_it->is_string() && curr_key_it->is_string() && *prev_key_it == *curr_key_it) {
          // `operator[]` would insert a null member for an absent key, which would fabricate a
          // `{"type": "text", "text": null}` block. Only merge when both sides actually carry the
          // field; otherwise leave the elements separate so no content is invented or lost.
          auto prev_content_it = merged.back().find(extract_subpath_);
          auto curr_content_it = elem.find(extract_subpath_);
          if (prev_content_it != merged.back().end() && curr_content_it != elem.end()) {
            nlohmann::json prev_blocks = toContentBlockArray(std::move(*prev_content_it));
            nlohmann::json curr_blocks = toContentBlockArray(std::move(*curr_content_it));
            for (nlohmann::json& b : curr_blocks) {
              prev_blocks.push_back(std::move(b));
            }
            *prev_content_it = std::move(prev_blocks);
            continue;
          }
        }
      }
      merged.push_back(std::move(elem));
    }
    *arr = std::move(merged);
    return absl::OkStatus();
  }

  case Op::DropElements:
  case Op::DiscardElements: {
    nlohmann::json* arr = findNodeByPath(json, source_segments_);
    if (arr == nullptr || !arr->is_array()) {
      return absl::OkStatus();
    }
    nlohmann::json kept = nlohmann::json::array();
    for (nlohmann::json& elem : *arr) {
      const nlohmann::json* value =
          elem.is_object() ? findNodeByPath(elem, predicate_segments_) : nullptr;
      if (value == nullptr ||
          std::find(match_json_.begin(), match_json_.end(), *value) == match_json_.end()) {
        kept.push_back(std::move(elem));
        continue;
      }
      if (op_ == Op::DropElements && carriesValue(elem)) {
        scope.report(
            absl::StrCat(source_path_, "[", predicate_field_, "=", renderValue(*value), "]"));
      }
    }
    *arr = std::move(kept);
    return absl::OkStatus();
  }

  case Op::When: {
    if (!condition_->holds(json)) {
      return absl::OkStatus();
    }
    for (const TranscodeRule& sub_rule : sub_rules_) {
      absl::Status status = sub_rule.applyIn(json, scope);
      if (!status.ok()) {
        return status;
      }
    }
    return absl::OkStatus();
  }

  case Op::Fail: {
    std::string value = "(none)";
    if (const nlohmann::json* node = findNodeByPath(json, source_segments_);
        !source_segments_.empty() && node != nullptr && node->is_string()) {
      value = node->get<std::string>();
    }
    return absl::InvalidArgumentError(
        absl::StrReplaceAll(message_, {{"{path}", scope.location()}, {"{value}", value}}));
  }

  case Op::KeepOnly: {
    nlohmann::json* object = findNodeByPath(json, target_segments_);
    if (object == nullptr || !object->is_object()) {
      return absl::OkStatus();
    }
    for (auto it = object->begin(); it != object->end();) {
      if (std::find(keys_.begin(), keys_.end(), it.key()) != keys_.end()) {
        ++it;
        continue;
      }
      if (carriesValue(*it)) {
        scope.report(target_path_.empty() ? it.key() : absl::StrCat(target_path_, ".", it.key()));
      }
      it = object->erase(it);
    }
    return absl::OkStatus();
  }
  }
  return absl::OkStatus();
}

absl::Status TranscodeRuleSet::execute(nlohmann::json& json) const {
  return execute(json, defaultOptions(), nullptr);
}

absl::Status TranscodeRuleSet::execute(nlohmann::json& json, const TranscodeOptions& options,
                                       TranscodeReport* report) const {
  for (const TranscodeRule& rule : rules_) {
    absl::Status status = rule.apply(json, options, report);
    if (!status.ok()) {
      return status;
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<RequestEnvelope> TranscodingEngine::readRequestEnvelope(LLMProtocol protocol,
                                                                       const nlohmann::json& body,
                                                                       absl::string_view path) {
  switch (protocol) {
  case LLMProtocol::OpenAiChatCompletions:
  case LLMProtocol::AnthropicMessages:
    return readEnvelopeFromBody(protocol, body);
  case LLMProtocol::GeminiGenerateContent:
    return readEnvelopeFromGeminiPath(path);
  case LLMProtocol::OpenAiResponses:
  case LLMProtocol::Unspecified:
    break;
  }
  return absl::InvalidArgumentError(
      absl::StrCat("cannot read the model of a ", llmProtocolName(protocol), " request"));
}

absl::Status TranscodingEngine::validateRulesAgainstSchema(const TranscodeRuleSet& plan,
                                                           const PayloadSchema* source_schema) {
  if (source_schema == nullptr) {
    return absl::OkStatus();
  }
  const std::vector<std::string> offloadable_paths = source_schema->requestOffloadableFieldPaths();
  absl::flat_hash_set<std::string> offloadable_set(offloadable_paths.begin(),
                                                   offloadable_paths.end());
  return verifyRulesTrackProvenance(plan.rules(), "", offloadable_set);
}

absl::Status TranscodingEngine::registerPack(DialectTranscodePack pack,
                                             const PayloadSchema* dialect_schema,
                                             const PayloadSchema* ir_schema) {
  // Only override the pack's own schema pointers when the caller supplied one. A pack constructed
  // with pre-populated schemas keeps them if `nullptr` is passed here.
  if (dialect_schema != nullptr) {
    pack.dialect_schema = dialect_schema;
  }
  if (ir_schema != nullptr) {
    pack.ir_schema = ir_schema;
  }
  absl::Status to_ir_status = validateRulesAgainstSchema(pack.to_ir, pack.dialect_schema);
  if (!to_ir_status.ok()) {
    return to_ir_status;
  }
  absl::Status from_ir_status = validateRulesAgainstSchema(pack.from_ir, pack.ir_schema);
  if (!from_ir_status.ok()) {
    return from_ir_status;
  }
  const LLMProtocol protocol = pack.protocol;
  packs_.insert_or_assign(protocol, std::move(pack));
  return absl::OkStatus();
}

absl::StatusOr<TranscodingEngine> TranscodingEngine::createDefault() {
  TranscodingEngine engine;
  const PayloadSchema* ir_schema = AdapterRegistry::get(kIrProtocol).schema();

  for (DialectTranscodePack pack : {createOpenAiChatTranscodePack(), createAnthropicTranscodePack(),
                                    createGeminiTranscodePack()}) {
    const PayloadSchema* dialect_schema = AdapterRegistry::get(pack.protocol).schema();
    absl::Status status = engine.registerPack(std::move(pack), dialect_schema, ir_schema);
    if (!status.ok()) {
      return status;
    }
  }
  return engine;
}

absl::Status TranscodingEngine::transcodeToIr(LLMProtocol source_protocol,
                                              nlohmann::json& json) const {
  TranscodeReport report;
  return transcodeToIr(source_protocol, json, RequestEnvelope(), report);
}

absl::Status TranscodingEngine::transcodeToIr(LLMProtocol source_protocol, nlohmann::json& json,
                                              const RequestEnvelope& envelope,
                                              TranscodeReport& report) const {
  if (source_protocol == LLMProtocol::Unspecified) {
    return absl::OkStatus();
  }
  auto it = packs_.find(source_protocol);
  if (it == packs_.end()) {
    return absl::InvalidArgumentError(absl::StrCat("no transcoding pack registered for source ",
                                                   llmProtocolName(source_protocol)));
  }
  if (!json.is_object()) {
    return absl::InvalidArgumentError("request body is not a JSON object");
  }
  if (absl::Status status = it->second.to_ir.execute(json, defaultOptions(), &report);
      !status.ok()) {
    return status;
  }
  if (!envelope.model.empty()) {
    json["model"] = envelope.model;
  }
  if (envelope.stream) {
    json["stream"] = true;
  }
  return absl::OkStatus();
}

absl::Status TranscodingEngine::transcodeFromIr(LLMProtocol target_protocol,
                                                nlohmann::json& json) const {
  TranscodeReport report;
  return transcodeFromIr(target_protocol, json, defaultOptions(), report);
}

absl::Status TranscodingEngine::transcodeFromIr(LLMProtocol target_protocol, nlohmann::json& json,
                                                const TranscodeOptions& options,
                                                TranscodeReport& report) const {
  if (target_protocol == LLMProtocol::Unspecified) {
    return absl::OkStatus();
  }
  auto it = packs_.find(target_protocol);
  if (it == packs_.end()) {
    return absl::InvalidArgumentError(absl::StrCat("no transcoding pack registered for target ",
                                                   llmProtocolName(target_protocol)));
  }
  if (!json.is_object()) {
    return absl::InvalidArgumentError("request body is not a JSON object");
  }
  if (absl::Status status = it->second.from_ir.execute(json, options, &report); !status.ok()) {
    return status;
  }
  const PayloadSchema* schema = it->second.dialect_schema;
  if (schema != nullptr) {
    pruneToSchema(json, schema->requestSchema().rootSchema(), report);
  }
  if (options.unsupported_fields == UnsupportedFieldPolicy::Reject && !report.dropped.empty()) {
    return absl::InvalidArgumentError(
        absl::StrCat(llmProtocolName(target_protocol),
                     " cannot express request fields: ", absl::StrJoin(report.dropped, ", ")));
  }
  if (schema == nullptr) {
    return absl::OkStatus();
  }
  if (absl::Status status = schema->validateRequest(json); !status.ok()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "request is not valid ", llmProtocolName(target_protocol), ": ", status.message()));
  }
  return absl::OkStatus();
}

absl::Status TranscodingEngine::transcodeRequest(LLMProtocol from, LLMProtocol to,
                                                 nlohmann::json& json,
                                                 const RequestEnvelope& envelope,
                                                 const TranscodeOptions& options,
                                                 TranscodeReport& report) const {
  if (from == to) {
    return absl::InvalidArgumentError(
        absl::StrCat("a ", llmProtocolName(from), " request needs no conversion"));
  }
  if (!packs_.contains(to)) {
    return absl::InvalidArgumentError(
        absl::StrCat("cannot convert a request to ", llmProtocolName(to)));
  }
  if (!packs_.contains(from)) {
    return absl::InvalidArgumentError(
        absl::StrCat("cannot convert a ", llmProtocolName(from), " request"));
  }
  if (absl::Status status = transcodeToIr(from, json, envelope, report); !status.ok()) {
    return status;
  }
  return transcodeFromIr(to, json, options, report);
}

std::optional<const ResponseCodec*> TranscodingEngine::responseCodec(LLMProtocol protocol) const {
  if (protocol == kIrProtocol) {
    return nullptr;
  }
  auto it = packs_.find(protocol);
  if (it == packs_.end() || it->second.response_codec == nullptr) {
    return std::nullopt;
  }
  return it->second.response_codec;
}

bool TranscodingEngine::canTranscodeResponse(LLMProtocol from, LLMProtocol to) const {
  return from == to || (responseCodec(from).has_value() && responseCodec(to).has_value());
}

absl::StatusOr<ResponseStreamTranscoderPtr>
TranscodingEngine::createResponseStreamTranscoder(LLMProtocol from, LLMProtocol to,
                                                  const ResponseContext& context) const {
  if (from == to) {
    return nullptr;
  }
  const std::optional<const ResponseCodec*> from_codec = responseCodec(from);
  const std::optional<const ResponseCodec*> to_codec = responseCodec(to);
  if (!from_codec.has_value() || !to_codec.has_value()) {
    return unsupportedResponsePair(from, to);
  }
  return createResponseStreamTranscoderViaIr(*from_codec, *to_codec, context);
}

absl::StatusOr<nlohmann::json>
TranscodingEngine::transcodeUnaryResponse(LLMProtocol from, LLMProtocol to, nlohmann::json body,
                                          const ResponseContext& context) const {
  if (from == to) {
    return body;
  }
  const std::optional<const ResponseCodec*> from_codec = responseCodec(from);
  const std::optional<const ResponseCodec*> to_codec = responseCodec(to);
  if (!from_codec.has_value() || !to_codec.has_value()) {
    return unsupportedResponsePair(from, to);
  }
  return transcodeUnaryResponseViaIr(*from_codec, *to_codec, std::move(body), context);
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
