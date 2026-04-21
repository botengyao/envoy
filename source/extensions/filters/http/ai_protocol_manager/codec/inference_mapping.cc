#include "source/extensions/filters/http/ai_protocol_manager/codec/inference_mapping.h"

#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/json/json_loader.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

namespace {

// Drain the body into residual_params for OPENAI_PASSTHROUGH round-trip. Kept
// as a helper so both the fast-path parser and error-recovery paths share it.
absl::Status stashRawBody(absl::string_view body, AiRequest& req) {
  if (req.payload_store == nullptr) {
    return absl::FailedPreconditionError("AiRequest has no payload store");
  }
  auto buf = std::make_unique<Buffer::OwnedImpl>();
  buf->add(body);
  auto ref = req.payload_store->store(std::move(buf), PayloadKind::Other);
  auto* payload = req.asInference();
  if (payload == nullptr) {
    payload = &req.payload.emplace<InferencePayload>();
  }
  payload->residual_params = std::move(ref);
  return absl::OkStatus();
}

// Parse a single OpenAI "messages[i]" entry. Phase 3a: text content only.
// Returns a ChatMessage with role + flattened text. Non-text content parts
// (image_url, input_audio, ...) are dropped with a note in the text field;
// proper handling lands in Phase 3c.
ChatMessage parseMessageEntry(const Json::Object& msg) {
  ChatMessage out;
  out.role = msg.getString("role", "").value_or("");

  // content can be a string OR an array of content parts. We only inspect it
  // via the getString path first; if that fails we fall back to array form.
  auto content_str_or = msg.getString("content");
  if (content_str_or.ok()) {
    out.text = *content_str_or;
    return out;
  }

  // Array form: walk parts looking for type=="text".text.
  auto parts_or = msg.getObjectArray("content", /*allow_empty=*/true);
  if (!parts_or.ok()) {
    return out;
  }
  std::string combined;
  for (const auto& part : *parts_or) {
    const std::string type = part->getString("type", "").value_or("");
    if (type == "text") {
      const auto text_or = part->getString("text");
      if (text_or.ok()) {
        if (!combined.empty()) {
          combined += "\n";
        }
        combined += *text_or;
      }
    }
    // Phase 3c: image_url, input_audio. Today these fall through silently.
  }
  out.text = std::move(combined);
  return out;
}

} // namespace

absl::Status parseOpenAIInferenceRequest(absl::string_view body, InferenceInvocation invocation,
                                         AiRequest& req) {
  if (req.payload_store == nullptr) {
    return absl::FailedPreconditionError("AiRequest has no payload store");
  }

  // Initialize payload + stash raw body for the OPENAI_PASSTHROUGH round-trip
  // fallback.
  InferencePayload& payload = req.payload.emplace<InferencePayload>();
  payload.invocation = invocation;
  req.protocol = ProtocolKind::Inference;

  auto raw_st = stashRawBody(body, req);
  if (!raw_st.ok()) {
    return raw_st;
  }

  if (body.empty()) {
    return absl::OkStatus();
  }

  auto root_or = Json::Factory::loadFromString(std::string(body));
  if (!root_or.ok()) {
    // Leave payload parsed-empty; residual_params has the raw body for
    // pass-through. Gemini encoder will error out (it requires parsed fields).
    return root_or.status();
  }
  const auto& root = *root_or;

  payload.target.name = root->getString("model", "").value_or("");
  payload.streaming = root->getBoolean("stream", false).value_or(false);

  // Sampling — see OPENAI_VERTEX_SPEC.md §2.
  if (auto t = root->getDouble("temperature"); t.ok()) {
    payload.sampling.temperature = *t;
  }
  if (auto t = root->getDouble("top_p"); t.ok()) {
    payload.sampling.top_p = *t;
  }
  // max_completion_tokens wins over max_tokens when both present.
  if (auto mt = root->getInteger("max_completion_tokens"); mt.ok()) {
    payload.sampling.max_tokens = static_cast<int32_t>(*mt);
  } else if (auto mt2 = root->getInteger("max_tokens"); mt2.ok()) {
    payload.sampling.max_tokens = static_cast<int32_t>(*mt2);
  }
  if (auto n = root->getInteger("n"); n.ok()) {
    payload.sampling.n = static_cast<int32_t>(*n);
  }
  if (auto s = root->getInteger("seed"); s.ok()) {
    payload.sampling.seed = *s;
  }
  if (auto p = root->getDouble("frequency_penalty"); p.ok()) {
    payload.sampling.frequency_penalty = *p;
  }
  if (auto p = root->getDouble("presence_penalty"); p.ok()) {
    payload.sampling.presence_penalty = *p;
  }
  // stop: string or array-of-string.
  if (auto s = root->getString("stop"); s.ok()) {
    payload.sampling.stop.push_back(*s);
  } else if (auto arr = root->getStringArray("stop", /*allow_empty=*/true); arr.ok()) {
    payload.sampling.stop.assign(arr->begin(), arr->end());
  }

  // Messages. OPENAI_VERTEX_SPEC.md §2.1: system / developer roles merge into
  // systemInstruction; user / assistant / tool turns populate contents.
  auto messages_or = root->getObjectArray("messages", /*allow_empty=*/true);
  if (messages_or.ok()) {
    for (const auto& msg : *messages_or) {
      ChatMessage m = parseMessageEntry(*msg);
      if (m.role == "system" || m.role == "developer") {
        if (!m.text.empty()) {
          payload.system_instructions.push_back(std::move(m.text));
        }
      } else if (!m.role.empty()) {
        payload.chat.push_back(std::move(m));
      }
    }
  }

  return absl::OkStatus();
}

absl::Status OpenAiEncoder::encode(const AiRequest& req, Buffer::Instance& out) {
  const InferencePayload* payload = req.asInference();
  if (payload == nullptr) {
    return absl::InvalidArgumentError("OpenAiEncoder expects an Inference payload");
  }
  // Phase 3a: round-trip via residual_params (the raw OpenAI body the parser
  // stashed). Phase 3b+ will synthesize OpenAI-shape JSON from the parsed
  // fields once the parser covers tools / multimodal / etc.
  const PayloadRef& ref = payload->residual_params;
  switch (ref.storage()) {
  case PayloadRef::Storage::Inline:
    out.add(ref.inlineView());
    return absl::OkStatus();
  case PayloadRef::Storage::Buffered:
    out.add(ref.buffered());
    return absl::OkStatus();
  case PayloadRef::Storage::External:
    return absl::UnimplementedError("External payload resolution not yet implemented");
  }
  return absl::InternalError("unknown PayloadRef storage");
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
