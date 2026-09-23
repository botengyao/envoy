#pragma once

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/filters/http/ai_protocol_manager/schema.h"
#include "source/extensions/filters/http/ai_protocol_manager/token_usage.h"
#include "source/extensions/filters/http/ai_protocol_manager/transcoding/response_transcoder.h"

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// What a request asks for that its protocol may keep outside the body.
struct RequestEnvelope {
  std::string model;
  bool stream{false};
  // OpenAI Chat Completions `stream_options.include_usage`.
  bool include_usage{false};
  // False when a stream is not SSE-framed: Gemini `streamGenerateContent` without `alt=sse`.
  bool sse{true};
};

// Request fields a conversion removed although they carried a value.
struct TranscodeReport {
  // Records `field` once, keeping the order in which fields were first dropped.
  void add(std::string field);

  std::vector<std::string> dropped;
};

enum class UnsupportedFieldPolicy { Drop, Reject };

struct TranscodeOptions {
  // Anthropic `max_tokens` when the request sets no output cap.
  uint32_t default_max_output_tokens{4096};
  UnsupportedFieldPolicy unsupported_fields{UnsupportedFieldPolicy::Drop};
  // Ask an OpenAI upstream to report usage on a stream.
  bool request_stream_usage{true};
};

// A predicate over the object a rule runs on, for `TranscodeRule::when`.
class TranscodeCondition {
public:
  // Present and carrying a value: not null, not false, not an empty array or object.
  static TranscodeCondition hasValue(std::string path);
  static TranscodeCondition noValue(std::string path);
  // Present and not null.
  static TranscodeCondition present(std::string path);
  // Present and equal to one of `values`.
  static TranscodeCondition in(std::string path, std::vector<nlohmann::json> values);
  // The negation of `in`, so it also holds when `path` is absent.
  static TranscodeCondition notIn(std::string path, std::vector<nlohmann::json> values);
  static TranscodeCondition isObject(std::string path);
  // Absent, or neither a string nor an `ExternalRef` standing in for one.
  static TranscodeCondition notString(std::string path);

  bool holds(const nlohmann::json& object) const;

  const std::string& path() const { return path_; }
  // True when evaluating compares the value at `path`, rather than only its presence or type.
  bool readsValue() const { return kind_ == Kind::In; }

private:
  enum class Kind { HasValue, Present, In, IsObject, IsString };

  TranscodeCondition(Kind kind, bool negated, std::string path);

  Kind kind_;
  bool negated_;
  std::string path_;
  std::vector<std::string> segments_;
  std::vector<nlohmann::json> values_;
};

// Declarative, schema-backed JSON transcoding rule specification.
//
// Styled after `Schema` (schema.h): each `TranscodeRule` describes a declarative
// field or structural transformation ("this field maps to that field", "this value
// maps to that value") without bespoke per-model C++ logic.
//
// All structural rules operate on `nlohmann::json` nodes via `std::move`, preserving
// `JsonWithExtBuf::ExternalRef` binary reference nodes in O(1) without materializing
// offloaded strings.
class TranscodeRule {
public:
  enum class Op {
    // Moves a field from `source_path` to `target_path` (if present).
    Move,
    // Moves the first present field in `source_paths` to `target_path`, discarding the other
    // candidates without reporting them.
    FirstOf,
    // Removes `source_path` from the JSON object if present, reporting what carried a value.
    Drop,
    // Removes `source_path` from the JSON object if present, without reporting it.
    Discard,
    // Sets `target_path` to `default_value` (or an option) if `target_path` is absent or null.
    SetDefault,
    // Wraps a scalar at `target_path` in a single-element array. A no-op when the field is
    // absent, null, or already an array.
    EnsureArray,
    // Wraps a scalar at `target_path` in an object keyed by `element_key`. A no-op when the
    // field is absent, null, or already an object.
    EnsureObject,
    // Replaces the object at `target_path` with the value it holds under `element_key`, but
    // only when that is its sole key. A no-op otherwise, which is what lets a rule set collapse
    // a degenerate wrapper without disturbing a genuinely structured value.
    UnwrapSingleKeyObject,
    // Parses a numeric string at `target_path` into a real JSON number, as an integer when
    // `integral` is set. A no-op when the field is absent, already numeric, or does not parse.
    CoerceNumeric,
    // Translates JSON values at `target_path` according to `value_map`.
    ValueMap,
    // Applies `sub_rules` to every object element of the array at `target_path`.
    ForEach,
    // Partition/extracts elements from array `source_path` where `predicate_field` is in
    // `match_values`, moving their `extract_subpath` into `target_path` and keeping
    // remaining elements in `source_path`.
    ExtractFromArray,
    // Prepends an object element into array `target_path` constructed from `source_path`
    // (removing `source_path`), setting `predicate_field` = `role_value` and
    // `extract_subpath` = moved value.
    PrependToArray,
    // Wraps a field `source_path` into a single-element object array `target_path`:
    // `[{element_key: <moved source_path>}]` (if `source_path` is already an array, moves it).
    WrapInArrayObject,
    // Unwraps the first element's `element_key` from object array `source_path` into
    // `target_path` (e.g., `parts[0].text` -> `content`).
    UnwrapArrayObject,
    // Merges consecutive elements in array `target_path` that share the same `key_field`
    // value, combining their `merge_field` values.
    MergeConsecutiveByKey,
    // Removes the elements of array `source_path` whose `predicate_field` equals one of the
    // rule's `values`, reporting each one that carried a value.
    DropElements,
    // As `DropElements`, without reporting.
    DiscardElements,
    // Applies `sub_rules` when `condition` holds.
    When,
    // Fails the conversion with `message`.
    Fail,
    // Removes the members of the object at `target_path` that are not in `keys`.
    KeepOnly,
  };

  enum class UnknownValuePolicy {
    Passthrough,
    Drop,
    Reject,
  };

  // A default that `setDefault` reads from `TranscodeOptions`.
  enum class Option {
    // `default_max_output_tokens`.
    MaxOutputTokens,
    // `true` when `request_stream_usage` is set; nothing otherwise.
    StreamUsage,
  };

  // Mapping `to` null removes the field without reporting it.
  struct ValueMapping {
    nlohmann::json from;
    nlohmann::json to;
  };

  // Static factory builders for declarative rule construction:

  // Moves `from_path` (dot-separated, e.g. "generationConfig.maxOutputTokens") to `to_path`.
  static TranscodeRule move(std::string from_path, std::string to_path);

  // Moves the first present field in `from_paths` to `to_path` and discards the other
  // candidates without reporting them.
  static TranscodeRule firstOf(std::initializer_list<std::string> from_paths, std::string to_path);

  // Removes `path` from the payload if present, reporting the loss: an object reports each of its
  // members that carried a value as `path.member`, anything else reports `path` if it carried a
  // value.
  static TranscodeRule drop(std::string path);

  // Removes `path` from the payload if present, for a field whose loss is not worth reporting.
  static TranscodeRule discard(std::string path);

  // Sets `path` to `default_value` if `path` is missing or null.
  static TranscodeRule setDefault(std::string path, nlohmann::json default_value);

  // As above, with the default taken from the `TranscodeOptions` the rule runs with.
  static TranscodeRule setDefault(std::string path, Option option);

  // Normalizes `path` to array shape by wrapping a scalar in a single-element array. Fields that
  // are absent, null, or already arrays are left untouched. Use this ahead of a mapping into a
  // destination that only accepts an array, where the source dialect also permits a bare scalar
  // (e.g. OpenAI `stop` -> Anthropic `stop_sequences`).
  static TranscodeRule ensureArray(std::string path);

  // Normalizes `path` to object shape by wrapping a scalar as `{key: <scalar>}`. Fields that are
  // absent, null, or already objects are left untouched. Pairs with `unwrapSingleKeyObject` to
  // move between a dialect that spells a choice as a bare string and one that spells it as a
  // tagged object (e.g. OpenAI `tool_choice: "auto"` -> Anthropic `{"type": "auto"}`).
  static TranscodeRule ensureObject(std::string path, std::string key);

  // Replaces the object at `path` with the value under `key`, but only when `key` is its only
  // member. An object carrying anything else is left alone, so a rule set can collapse the
  // degenerate `{"type": "auto"}` form while leaving `{"type": "function", "function": {...}}`
  // intact without needing conditional rules.
  static TranscodeRule unwrapSingleKeyObject(std::string path, std::string key);

  // Converts a numeric string at `path` into a real JSON number. Values that are absent, already
  // numeric, or not parseable are left untouched; an unparseable string is the source schema's
  // problem to reject, not this rule's. Use where a lenient source dialect permits a quoted
  // number (Gemini renders proto numbers as strings) and the destination requires a real one.
  static TranscodeRule toNumber(std::string path);

  // As `toNumber`, but yields an integer, for destinations that declare the field as such.
  static TranscodeRule toInteger(std::string path);

  // Maps the value at `path` using `mappings` ("this value should be interpreted as that").
  // `UnknownValuePolicy::Drop` removes and reports a value no mapping names.
  static TranscodeRule
  valueMap(std::string path, std::initializer_list<ValueMapping> mappings,
           UnknownValuePolicy unknown_policy = UnknownValuePolicy::Passthrough);

  // Runs `rules` on each element of the array at `array_path`.
  static TranscodeRule forEach(std::string array_path, std::vector<TranscodeRule> rules);

  // Extracts elements from `array_path` whose `predicate_field` matches any of `match_values`.
  // The matched element's `extract_subpath` is moved to `target_path` (removing the element
  // from `array_path`).
  static TranscodeRule extractFromArray(std::string array_path, std::string predicate_field,
                                        std::initializer_list<std::string> match_values,
                                        std::string extract_subpath, std::string target_path);

  // Moves `source_path` into a new element prepended to `array_path`. The new element maps
  // `key_field` to `key_value` and holds the moved node under `value_subpath`.
  static TranscodeRule prependToArray(std::string source_path, std::string array_path,
                                      std::string key_field, std::string key_value,
                                      std::string value_subpath);

  // Wraps `from_path` inside the current object into `to_array_path: [{element_key: <moved>}]`.
  static TranscodeRule wrapInArrayObject(std::string from_path, std::string to_array_path,
                                         std::string element_key);

  // Unwraps `from_array_path[0][element_key]` into `to_path` inside the current object.
  static TranscodeRule unwrapArrayObject(std::string from_array_path, std::string element_key,
                                         std::string to_path);

  // Merges consecutive array elements at `array_path` that have identical `key_field` values
  // by concatenating/merging their `merge_field` values into an array of blocks or string.
  static TranscodeRule mergeConsecutiveByKey(std::string array_path, std::string key_field,
                                             std::string merge_field);

  // Removes the elements of `array_path` whose `predicate_field` equals one of `values`,
  // reporting each removed element that carried a value as `array_path[predicate_field=value]`.
  static TranscodeRule dropElements(std::string array_path, std::string predicate_field,
                                    std::vector<nlohmann::json> values);

  // As `dropElements`, without reporting.
  static TranscodeRule discardElements(std::string array_path, std::string predicate_field,
                                       std::vector<nlohmann::json> values);

  // Runs `rules` on the current object when `condition` holds on it.
  static TranscodeRule when(TranscodeCondition condition, std::vector<TranscodeRule> rules);

  // Fails the conversion with InvalidArgument `message`, in which `{path}` names the array
  // element the rule runs on (e.g. `messages[1]`) and `{value}` is the string at `value_path`,
  // or `(none)`.
  static TranscodeRule fail(std::string message, std::string value_path = "");

  // Removes the members of the object at `path` (the current object when empty) that are not
  // in `keys`, reporting those that carried a value.
  static TranscodeRule keepOnly(std::vector<std::string> keys, std::string path = "");

  // Introspection accessors (used by the startup Verifier and Executor):
  Op op() const { return op_; }
  const std::string& sourcePath() const { return source_path_; }
  const std::vector<std::string>& sourcePaths() const { return source_paths_; }
  const std::string& targetPath() const { return target_path_; }
  const std::string& predicateField() const { return predicate_field_; }
  const std::string& extractSubpath() const { return extract_subpath_; }
  const std::vector<std::string>& matchValues() const { return match_values_; }
  const nlohmann::json& defaultValue() const { return default_value_; }
  const std::vector<ValueMapping>& valueMappings() const { return value_mappings_; }
  UnknownValuePolicy unknownValuePolicy() const { return unknown_policy_; }
  const std::vector<TranscodeRule>& subRules() const { return sub_rules_; }
  const std::optional<TranscodeCondition>& condition() const { return condition_; }
  const std::vector<std::string>& keys() const { return keys_; }

  // Executes this rule in-place on `json`, with default options and no report.
  absl::Status apply(nlohmann::json& json) const;
  // Executes this rule in-place on `json`, recording dropped fields in `report` when non-null.
  absl::Status apply(nlohmann::json& json, const TranscodeOptions& options,
                     TranscodeReport* report) const;

private:
  class Scope;

  explicit TranscodeRule(Op op) : op_(op) {}

  absl::Status applyIn(nlohmann::json& json, const Scope& scope) const;

  Op op_;
  std::string source_path_;
  std::vector<std::string> source_segments_;
  std::vector<std::string> source_paths_;
  std::vector<std::vector<std::string>> source_paths_segments_;
  std::string target_path_;
  std::vector<std::string> target_segments_;
  std::string predicate_field_;
  std::vector<std::string> predicate_segments_;
  std::string extract_subpath_;
  std::vector<std::string> extract_subpath_segments_;
  std::vector<std::string> match_values_;
  std::vector<nlohmann::json> match_json_;
  nlohmann::json default_value_;
  std::optional<Option> option_;
  std::vector<ValueMapping> value_mappings_;
  UnknownValuePolicy unknown_policy_{UnknownValuePolicy::Passthrough};
  bool integral_{false};
  std::vector<TranscodeRule> sub_rules_;
  std::optional<TranscodeCondition> condition_;
  std::vector<std::string> keys_;
  std::string message_;
};

// A compiled, immutable sequence of declarative `TranscodeRule`s that transforms a payload
// from `source_protocol` to `target_protocol`.
class TranscodeRuleSet {
public:
  TranscodeRuleSet() = default;
  TranscodeRuleSet(LLMProtocol source_protocol, LLMProtocol target_protocol,
                   std::initializer_list<TranscodeRule> rules)
      : source_protocol_(source_protocol), target_protocol_(target_protocol), rules_(rules) {}
  TranscodeRuleSet(LLMProtocol source_protocol, LLMProtocol target_protocol,
                   std::vector<TranscodeRule> rules)
      : source_protocol_(source_protocol), target_protocol_(target_protocol),
        rules_(std::move(rules)) {}

  LLMProtocol sourceProtocol() const { return source_protocol_; }
  LLMProtocol targetProtocol() const { return target_protocol_; }
  const std::vector<TranscodeRule>& rules() const { return rules_; }

  // Executes all rules in order on `payload`.
  absl::Status execute(JsonWithExtBuf& payload) const { return execute(payload.json()); }
  absl::Status execute(nlohmann::json& json) const;
  absl::Status execute(nlohmann::json& json, const TranscodeOptions& options,
                       TranscodeReport* report) const;

private:
  LLMProtocol source_protocol_{LLMProtocol::Unspecified};
  LLMProtocol target_protocol_{LLMProtocol::Unspecified};
  std::vector<TranscodeRule> rules_;
};

// Declarative dialect pack pairing a protocol's `to_ir` (Protocol -> OpenAiChatCompletions)
// and `from_ir` (OpenAiChatCompletions -> Protocol) rule sets.
//
// `dialect_schema` is the protocol's own `PayloadSchema`; a payload converted out of the IR is
// pruned to and validated against it before it is handed to the upstream. `ir_schema` is only
// used for static rule verification at registration time -- see
// `TranscodingEngine::transcodeToIr()` for why the IR document itself is not validated at runtime.
//
// `response_codec` transcodes the protocol's responses to and from the IR; without one, responses
// in the protocol cannot be transcoded (the IR protocol needs none).
struct DialectTranscodePack {
  LLMProtocol protocol{LLMProtocol::Unspecified};
  TranscodeRuleSet to_ir;
  TranscodeRuleSet from_ir;
  const PayloadSchema* dialect_schema{nullptr};
  const PayloadSchema* ir_schema{nullptr};
  const ResponseCodec* response_codec{nullptr};
};

// The Transcoding Engine: manages registered `DialectTranscodePack`s, verifies them against
// `PayloadSchema` definitions at startup, and converts payloads between any registered dialect
// and the intermediate representation, chaining `Dialect A -> IR -> Dialect B` for requests
// (`transcodeRequest`) and responses (`createResponseStreamTranscoder`, `transcodeUnaryResponse`).
//
// The engine does not infer target wire protocols from model names. Selecting target wire
// protocols from route/endpoint configuration, and bypassing request conversion when source and
// target protocols match, are the responsibility of the calling transcoding filter; the response
// API passes a same-protocol response through unchanged.
//
// TODO(ginama): Address the IR data-loss problem where dialect-specific fields not modeled by
// `OpenAiChatCompletions` (e.g. unmapped `generationConfig` fields) are dropped when converting
// to the IR.
class TranscodingEngine {
public:
  static constexpr LLMProtocol kIrProtocol = LLMProtocol::OpenAiChatCompletions;

  TranscodingEngine() = default;

  // Builds the default engine pre-loaded with OpenAI Chat Completions, Anthropic Messages,
  // and Gemini GenerateContent declarative transcoding packs.
  static absl::StatusOr<TranscodingEngine> createDefault();

  // Reads the model and streaming choice from the body for OpenAI Chat Completions and Anthropic
  // Messages, and from the path for Gemini: `.../models/{model}:generateContent` or
  // `...:streamGenerateContent`, Gemini API and Vertex AI paths alike, with a percent-encoded
  // model decoded. InvalidArgument when the model cannot be found.
  static absl::StatusOr<RequestEnvelope>
  readRequestEnvelope(LLMProtocol protocol, const nlohmann::json& body, absl::string_view path);

  // Statically verifies a rule set against `source_schema` at config load time.
  // Rejects any rule set where a value-reading rule (`ValueMap`, `DropElements`, a `When`
  // comparing values, a `Fail` quoting a value) reads a field declared `.offloadable()` in
  // `source_schema`, since such a field may arrive as an `ExternalRef` binary node rather than an
  // inline string. Provenance is tracked across structural rules (including content-block array
  // reshaping into `<field>[].text`) in execution order.
  static absl::Status validateRulesAgainstSchema(const TranscodeRuleSet& rules,
                                                 const PayloadSchema* source_schema = nullptr);

  // Registers a `DialectTranscodePack` after statically verifying its rule sets.
  //
  // `dialect_schema` and `ir_schema` override the corresponding fields on `pack` when
  // non-null; when null, whatever `pack` already carries is kept. This lets a caller either
  // pass the schemas here or set them directly on the struct, without one silently winning.
  absl::Status registerPack(DialectTranscodePack pack,
                            const PayloadSchema* dialect_schema = nullptr,
                            const PayloadSchema* ir_schema = nullptr);

  // Converts `json` from `source_protocol` into the intermediate representation
  // (`OpenAiChatCompletions`), then places the envelope's model (when it names one) and streaming
  // choice in the body. Fields the IR cannot hold are recorded in `report`.
  //
  // The result is deliberately NOT validated against the IR schema. Two reasons: the source
  // payload was already validated against its own schema by the AI Protocol Manager before the
  // filter chain ran, so re-validating is duplicated work on the hot path; and a Gemini request
  // legitimately carries its model outside its body.
  absl::Status transcodeToIr(LLMProtocol source_protocol, nlohmann::json& json,
                             const RequestEnvelope& envelope, TranscodeReport& report) const;
  absl::Status transcodeToIr(LLMProtocol source_protocol, JsonWithExtBuf& payload) const {
    return transcodeToIr(source_protocol, payload.json());
  }
  absl::Status transcodeToIr(LLMProtocol source_protocol, nlohmann::json& json) const;

  // Converts `json` out of the intermediate representation into `target_protocol`: runs the
  // target's rules, prunes what its schema does not declare at the root and in the elements of
  // every root array of objects (recording what carried a value in `report`), fails under
  // `UnsupportedFieldPolicy::Reject` when `report` holds anything, then validates the result
  // against the target's schema so a payload the upstream would reject is caught here instead
  // of over the network.
  absl::Status transcodeFromIr(LLMProtocol target_protocol, nlohmann::json& json,
                               const TranscodeOptions& options, TranscodeReport& report) const;
  absl::Status transcodeFromIr(LLMProtocol target_protocol, JsonWithExtBuf& payload) const {
    return transcodeFromIr(target_protocol, payload.json());
  }
  absl::Status transcodeFromIr(LLMProtocol target_protocol, nlohmann::json& json) const;

  // Converts a request from `from` to `to`, `from != to`: into the IR, then out of it.
  absl::Status transcodeRequest(LLMProtocol from, LLMProtocol to, nlohmann::json& json,
                                const RequestEnvelope& envelope, const TranscodeOptions& options,
                                TranscodeReport& report) const;

  // Whether a response in `from` can be transcoded to `to`: the same protocol, or each side the IR
  // or a protocol whose pack carries a response codec.
  bool canTranscodeResponse(LLMProtocol from, LLMProtocol to) const;

  // A stream transcoder from `from` to `to`, chaining through the IR when neither side is the IR;
  // nullptr when the protocols match. InvalidArgument for a pair `canTranscodeResponse` rejects.
  absl::StatusOr<ResponseStreamTranscoderPtr>
  createResponseStreamTranscoder(LLMProtocol from, LLMProtocol to,
                                 const ResponseContext& context) const;

  // Transcodes a whole unary response body from `from` to `to`, chaining as above. Returns `body`
  // unchanged when the protocols match.
  absl::StatusOr<nlohmann::json> transcodeUnaryResponse(LLMProtocol from, LLMProtocol to,
                                                        nlohmann::json body,
                                                        const ResponseContext& context) const;

private:
  // The codec for one side of a response transcoding: nullptr for the IR, nullopt when `protocol`
  // has no registered codec.
  std::optional<const ResponseCodec*> responseCodec(LLMProtocol protocol) const;

  absl::flat_hash_map<LLMProtocol, DialectTranscodePack> packs_;
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
