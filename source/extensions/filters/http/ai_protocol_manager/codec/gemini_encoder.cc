#include "source/extensions/filters/http/ai_protocol_manager/codec/gemini_encoder.h"

#include <string>

#include "source/common/protobuf/utility.h"

#include "google/protobuf/struct.pb.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

namespace {

using google::protobuf::ListValue;
using google::protobuf::Struct;
using google::protobuf::Value;

Value stringValue(absl::string_view s) {
  Value v;
  v.set_string_value(std::string(s));
  return v;
}

Value numberValue(double d) {
  Value v;
  v.set_number_value(d);
  return v;
}

Value boolValue(bool b) {
  Value v;
  v.set_bool_value(b);
  return v;
}

Value structValue(Struct s) {
  Value v;
  *v.mutable_struct_value() = std::move(s);
  return v;
}

Value listValue(ListValue l) {
  Value v;
  *v.mutable_list_value() = std::move(l);
  return v;
}

// Build a { role, parts: [{text}] } Gemini Content.
Struct buildContent(absl::string_view role, absl::string_view text) {
  Struct content;
  (*content.mutable_fields())["role"] = stringValue(role);

  ListValue parts_list;
  Struct part;
  (*part.mutable_fields())["text"] = stringValue(text);
  *parts_list.add_values() = structValue(std::move(part));

  (*content.mutable_fields())["parts"] = listValue(std::move(parts_list));
  return content;
}

// OPENAI_VERTEX_SPEC.md §2.1 — OpenAI role → Gemini role for contents[].
// system / developer are handled separately (systemInstruction).
absl::string_view geminiRoleFor(absl::string_view openai_role) {
  if (openai_role == "assistant") {
    return "model";
  }
  // user, tool, anything else → user. Tool responses currently fold into
  // user turns; proper functionResponse parts land in Phase 3b alongside
  // functionCall.
  return "user";
}

} // namespace

absl::Status GeminiEncoder::encode(const AiRequest& req, Buffer::Instance& out) {
  const InferencePayload* payload = req.asInference();
  if (payload == nullptr) {
    return absl::InvalidArgumentError("GeminiEncoder expects an Inference payload");
  }

  Struct root;
  auto& fields = *root.mutable_fields();

  // contents[]
  if (!payload->chat.empty()) {
    ListValue contents;
    for (const auto& m : payload->chat) {
      *contents.add_values() = structValue(buildContent(geminiRoleFor(m.role), m.text));
    }
    fields["contents"] = listValue(std::move(contents));
  }

  // systemInstruction — merged from all system/developer messages.
  if (!payload->system_instructions.empty()) {
    std::string merged;
    for (const auto& s : payload->system_instructions) {
      if (!merged.empty()) {
        merged += "\n";
      }
      merged += s;
    }
    // systemInstruction in Gemini uses the Content shape (role + parts).
    // Role is typically "user" or omitted; matching the Go translator's use
    // of a Content-with-role-user body.
    fields["systemInstruction"] = structValue(buildContent("user", merged));
  }

  // generationConfig
  Struct gen_cfg;
  auto& gen_fields = *gen_cfg.mutable_fields();
  if (payload->sampling.temperature.has_value()) {
    gen_fields["temperature"] = numberValue(*payload->sampling.temperature);
  }
  if (payload->sampling.top_p.has_value()) {
    gen_fields["topP"] = numberValue(*payload->sampling.top_p);
  }
  if (payload->sampling.max_tokens.has_value()) {
    gen_fields["maxOutputTokens"] = numberValue(static_cast<double>(*payload->sampling.max_tokens));
  }
  if (payload->sampling.n.has_value()) {
    gen_fields["candidateCount"] = numberValue(static_cast<double>(*payload->sampling.n));
  }
  if (payload->sampling.seed.has_value()) {
    gen_fields["seed"] = numberValue(static_cast<double>(*payload->sampling.seed));
  }
  if (payload->sampling.frequency_penalty.has_value()) {
    gen_fields["frequencyPenalty"] = numberValue(*payload->sampling.frequency_penalty);
  }
  if (payload->sampling.presence_penalty.has_value()) {
    gen_fields["presencePenalty"] = numberValue(*payload->sampling.presence_penalty);
  }
  if (!payload->sampling.stop.empty()) {
    ListValue stops;
    for (const auto& s : payload->sampling.stop) {
      *stops.add_values() = stringValue(s);
    }
    gen_fields["stopSequences"] = listValue(std::move(stops));
  }
  if (!gen_fields.empty()) {
    fields["generationConfig"] = structValue(std::move(gen_cfg));
  }

  // Required but not-yet-implemented pieces (Phase 3b+): tools, toolConfig,
  // responseFormat, safetySettings, thinkingConfig. Flag silently by leaving
  // them off the output rather than erroring, to keep Phase 3a useful for
  // simple chat requests.
  (void)boolValue;

  const std::string json = MessageUtil::getJsonStringFromMessageOrError(
      root, /*pretty_print=*/false, /*always_print_primitive_fields=*/false);
  out.add(json);
  return absl::OkStatus();
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
