#include "source/extensions/filters/http/ai_protocol_manager/codec/inference_mapping.h"

#include "source/common/buffer/buffer_impl.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

absl::Status parseOpenAIInferenceRequest(absl::string_view body, InferenceInvocation invocation,
                                         AiRequest& req) {
  // Phase 2a: pass-through. Stash the entire body into residual_params so the
  // encoder can round-trip it verbatim. Phase 3 introduces the real parser
  // per OPENAI_VERTEX_SPEC.md §2 (messages, tools, sampling, tool_choice,
  // thinking, ...).
  if (req.payload_store == nullptr) {
    return absl::FailedPreconditionError("AiRequest has no payload store");
  }
  auto buf = std::make_unique<Buffer::OwnedImpl>();
  buf->add(body);
  auto ref = req.payload_store->store(std::move(buf), PayloadKind::Other);

  InferencePayload& payload = req.payload.emplace<InferencePayload>();
  payload.invocation = invocation;
  payload.residual_params = std::move(ref);
  req.protocol = ProtocolKind::Inference;
  return absl::OkStatus();
}

absl::Status OpenAiEncoder::encode(const AiRequest& req, Buffer::Instance& out) {
  const InferencePayload* payload = req.asInference();
  if (payload == nullptr) {
    return absl::InvalidArgumentError("OpenAiEncoder expects an Inference payload");
  }
  // Phase 2a: the whole body lives in residual_params (stashed by the
  // decoder). Phase 3 will synthesize the body from typed fields (messages,
  // tools, sampling, ...) here instead.
  const PayloadRef& ref = payload->residual_params;
  switch (ref.storage()) {
  case PayloadRef::Storage::Inline:
    out.add(ref.inlineView());
    return absl::OkStatus();
  case PayloadRef::Storage::Buffered:
    out.add(ref.buffered());
    return absl::OkStatus();
  case PayloadRef::Storage::External:
    // Async resolution via PayloadStore::fetch(); not needed for Phase 2a
    // (InMemoryPayloadStore never produces External refs).
    return absl::UnimplementedError("External payload resolution not yet implemented");
  }
  return absl::InternalError("unknown PayloadRef storage");
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
