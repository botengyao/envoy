#include "source/extensions/filters/http/ai_protocol_manager/schema/gemini_interactions.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace GeminiInteractions {

// Written from Google's v1beta and v1 OpenAPI specs (https://ai.google.dev/api/interactions-api).
// One schema serves both versions, so it takes the fields of either: v1 drops `temperature` and
// `top_p`. Enum values go unchecked, since their lists grow with each model and tool.

namespace {

// An `input` list holds content or steps. The content kinds are fixed while the step kinds grow
// with the tools, so any other `type` names a step.
bool isContentType(absl::string_view type) {
  return type == "text" || type == "image" || type == "audio" || type == "video" ||
         type == "document";
}

absl::Status validateStepType(const nlohmann::json& value) {
  if (value.is_string() && isContentType(value.get_ref<const std::string&>())) {
    return absl::InvalidArgumentError(
        absl::StrCat("'", value.get_ref<const std::string&>(), "' is a content type"));
  }
  return absl::OkStatus();
}

// `atMostOneOf` rejects both being set; this rejects neither.
absl::Status requireModelOrAgent(const nlohmann::json& value) {
  const auto is_set = [&value](const char* key) {
    const auto it = value.find(key);
    return it != value.end() && !it->is_null();
  };
  if (!is_set("model") && !is_set("agent")) {
    return absl::InvalidArgumentError("missing required field: model or agent");
  }
  return absl::OkStatus();
}

const Schema& textContentSchema() {
  static const Schema schema = Schema::object({
      {"type", Schema::enumString({"text"}).required()},
      {"text", Schema::string().offloadable().required()},
  });
  return schema;
}

// `data` is base64, routinely megabytes, and `uri` can be a long pre-signed URL.
const Schema& mediaContentSchema() {
  static const Schema schema = Schema::object({
      {"type", Schema::enumString({"image", "audio", "video", "document"}).required()},
      {"data", Schema::string().offloadable().nullable()},
      {"uri", Schema::string().offloadable().nullable()},
      {"mime_type", Schema::string().nullable()},
  });
  return schema;
}

const Schema& safetySettingSchema() {
  static const Schema schema = Schema::object({
      {"type", Schema::string().required()},
      {"threshold", Schema::string().required()},
      {"method", Schema::string().nullable()},
  });
  return schema;
}

// A mode, or the tools the model may call.
const Schema& toolChoiceSchema() {
  static const Schema schema =
      Schema::oneOf(
          {
              Schema::string(),
              Schema::object({
                  {"allowed_tools",
                   Schema::object({
                                      {"mode", Schema::string().nullable()},
                                      {"tools", Schema::array(Schema::string()).nullable()},
                                  })
                       .nullable()},
              }),
          })
          .nullable();
  return schema;
}

} // namespace

const Schema& contentSchema() {
  static const Schema schema = Schema::oneOf({textContentSchema(), mediaContentSchema()});
  return schema;
}

// Every step kind's members in one flat object. Which ones apply depends on `type`, and Gemini
// rejects a bad combination.
const Schema& stepSchema() {
  static const Schema schema = Schema::object({
      {"type", Schema::string().required().customValidator(validateStepType)},
      {"content", Schema::array(contentSchema()).nullable()},
      {"summary", Schema::array(contentSchema()).nullable()},
      // An opaque signature, `bytes` on the wire, with no documented size bound.
      {"signature", Schema::string().offloadable().nullable()},
      {"id", Schema::string().nullable()},
      {"call_id", Schema::string().nullable()},
      {"name", Schema::string().nullable()},
      // Its members are the called tool's.
      {"arguments", Schema::object({}).nullable()},
      // A string, an object or a list, depending on the tool. List items are left opaque, and
      // `any` accepts an offloaded value at any depth.
      {"result", Schema::oneOf({
                                   Schema::string().offloadable(),
                                   Schema::object({}),
                                   Schema::array(Schema::any()),
                               })
                     .nullable()},
      {"is_error", Schema::boolean().nullable()},
  });
  return schema;
}

// Every tool kind's members in one flat object, as for steps. Only a function's are declared.
const Schema& toolSchema() {
  static const Schema schema = Schema::object({
      {"type", Schema::string().required()},
      {"name", Schema::string().nullable()},
      {"description", Schema::string().offloadable().nullable()},
      // A JSON Schema, left unchecked.
      {"parameters", Schema::any()},
  });
  return schema;
}

const Schema& generationConfigSchema() {
  static const Schema schema =
      Schema::object({
                         {"max_output_tokens", Schema::integer().nullable()},
                         {"seed", Schema::integer().nullable()},
                         {"stop_sequences", Schema::array(Schema::string()).nullable()},
                         // Deprecated on v1beta, and gone from v1.
                         {"temperature", Schema::number().nullable()},
                         {"top_p", Schema::number().nullable()},
                         {"thinking_level", Schema::string().nullable()},
                         {"thinking_summaries", Schema::string().nullable()},
                         {"tool_choice", toolChoiceSchema()},
                     })
          .nullable();
  return schema;
}

PayloadSchema createPayloadSchema() {
  return PayloadSchema{
      /*request_schema=*/RequestSchema{
          Schema::object(
              {
                  // Exactly one of the two, checked below.
                  {"model", Schema::string().nullable()},
                  {"agent", Schema::string().nullable()},
                  // Required on v1, not on v1beta.
                  {"input", Schema::oneOf({
                                              Schema::string().offloadable(),
                                              contentSchema(),
                                              Schema::array(contentSchema()),
                                              Schema::array(stepSchema()),
                                          })
                                .nullable()},
                  {"system_instruction", Schema::string().offloadable().nullable()},
                  {"tools", Schema::array(toolSchema()).nullable()},
                  {"response_format", Schema::oneOf({
                                                        Schema::object({}),
                                                        Schema::array(Schema::object({})),
                                                    })
                                          .nullable()},
                  {"stream", Schema::boolean().nullable()},
                  {"store", Schema::boolean().nullable()},
                  {"background", Schema::boolean().nullable()},
                  {"generation_config", generationConfigSchema()},
                  {"agent_config", Schema::object({
                                                      {"type", Schema::string().required()},
                                                  })
                                       .nullable()},
                  {"previous_interaction_id", Schema::string().nullable()},
                  {"safety_settings", Schema::array(safetySettingSchema()).nullable()},
                  {"service_tier", Schema::string().nullable()},
              })
              .atMostOneOf({"model", "agent"})
              .customValidator(requireModelOrAgent)
              .allowUnknownFields(true),
          /*streamable_field_order=*/
          {
              "input",
              "input.text",
              "input.data",
              "input.uri",
              "input[].text",
              "input[].data",
              "input[].uri",
              "input[].content[].text",
              "input[].content[].data",
              "input[].content[].uri",
              "input[].summary[].text",
              "input[].summary[].data",
              "input[].summary[].uri",
              "input[].signature",
              "input[].result",
              "system_instruction",
              "tools[].description",
          }},
      /*response_schema=*/ResponseSchema{}};
}

} // namespace GeminiInteractions
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
