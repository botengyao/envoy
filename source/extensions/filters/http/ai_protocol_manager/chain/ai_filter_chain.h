#pragma once

#include <memory>
#include <string>
#include <vector>

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/chain/ai_filter.h"
#include "source/extensions/filters/http/ai_protocol_manager/chain/ai_filter_callbacks.h"
#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"

#include "absl/container/flat_hash_map.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Chain {

// DESIGN.md §4.5 — materialized per-item view. Lives only during one
// onRequestItem invocation; runtime owns copy-in / copy-out.

struct MessageItem {
  std::string role;
  std::string text;
  // Multimodal parts + attributes deferred; added alongside item-phase impl.
};

struct ToolItem {
  std::string name;
  std::string description;
  std::string schema_json;
};

struct AttachmentItem {
  std::string mime_type;
  std::string filename;
  std::string bytes;
};

class AiItem {
public:
  AiItem(AiItemKind kind, std::size_t index) : kind_(kind), index_(index) {}

  AiItemKind kind() const { return kind_; }
  std::size_t index() const { return index_; }

  bool dirty() const { return dirty_; }
  void markDirty() { dirty_ = true; }

  MessageItem* asMessage() { return kind_ == AiItemKind::Message ? &message_ : nullptr; }
  ToolItem* asTool() { return kind_ == AiItemKind::Tool ? &tool_ : nullptr; }
  AttachmentItem* asAttachment() {
    return kind_ == AiItemKind::Attachment ? &attachment_ : nullptr;
  }

private:
  AiItemKind kind_;
  std::size_t index_;
  bool dirty_{false};

  // Only the field matching kind_ is populated; the others are inert.
  MessageItem message_;
  ToolItem tool_;
  AttachmentItem attachment_;
};

struct AiEvent {
  std::string name;
};

// DESIGN.md §5.3 — ordered runner. Single implementation used by both
// InferenceChain and AgentChain; distinction is purely which filters are
// registered and which dispatch filter sits at the tail.
class AiFilterChain : public Logger::Loggable<Logger::Id::filter> {
public:
  explicit AiFilterChain(std::vector<AiFilterPtr> filters);

  // Compute the union of itemInterest() across member filters. Used by the
  // runtime to decide whether to materialize each item kind at all
  // (phase-skip optimization, DESIGN.md §5.3).
  AiItemKindSet itemInterestUnion() const;

  // Run the metadata phase across all filters. Returns the aggregate status:
  // Continue if every filter continued, StopIteration if any paused.
  AiFilterStatus runMetadata(Codec::AiRequest& req, AiFilterCallbacks& cb);

  // Per-item run: invoke only filters that declared interest in item.kind().
  AiFilterStatus runItem(AiItem& item, AiFilterCallbacks& cb);

  // Response phase (V0 pass-through until the response-side split lands).
  AiFilterStatus runResponse(Codec::AiResponse& res, AiFilterCallbacks& cb);

  void onDestroy();

private:
  std::vector<AiFilterPtr> filters_;
};

using AiFilterChainPtr = std::unique_ptr<AiFilterChain>;

} // namespace Chain
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
