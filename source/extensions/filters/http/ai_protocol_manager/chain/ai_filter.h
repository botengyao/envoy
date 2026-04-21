#pragma once

#include <memory>

#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Chain {

// DESIGN.md §5.1 — ergonomic, phased filter interface presented to operators
// writing sub-chain filters.

class AiFilterCallbacks; // fwd; chain/ai_filter_callbacks.h

enum class AiFilterStatus {
  Continue,       // advance to next filter (same phase)
  StopIteration,  // pause; resume via cb.continueRequest()
};

enum class AiItemKind { Message, Tool, Attachment };

// Bitset: which item kinds this filter wants onRequestItem callbacks for.
struct AiItemKindSet {
  bool messages{false};
  bool tools{false};
  bool attachments{false};

  static AiItemKindSet all() { return AiItemKindSet{true, true, true}; }
  static AiItemKindSet none() { return AiItemKindSet{false, false, false}; }

  bool any() const { return messages || tools || attachments; }
  AiItemKindSet unionWith(const AiItemKindSet& other) const {
    return AiItemKindSet{messages || other.messages, tools || other.tools,
                         attachments || other.attachments};
  }
};

// Runtime-side materialized item view. Filters see this during the per-item
// phase; they mutate it in place (and set dirty()) to trigger re-store. See
// DESIGN.md §4.5. Concrete struct defined in chain/ai_filter_chain.h so the
// interface here only forward-declares it.
class AiItem;

class AiFilter {
public:
  virtual ~AiFilter() = default;

  // Phase 1: scalars only. Always invoked. Does not trigger payload
  // materialization. Most cross-cutting filters stop here.
  virtual AiFilterStatus onRequestMetadata(Codec::AiRequest& /*req*/,
                                           AiFilterCallbacks& /*cb*/) {
    return AiFilterStatus::Continue;
  }

  // Phase 2+: per-item. Only invoked for kinds this filter declared interest
  // in via itemInterest(). Runtime materializes the item before the call and
  // re-stores on return if the filter marked it dirty.
  virtual AiItemKindSet itemInterest() const { return AiItemKindSet::none(); }
  virtual AiFilterStatus onRequestItem(AiItem& /*item*/, AiFilterCallbacks& /*cb*/) {
    return AiFilterStatus::Continue;
  }

  // Response path. V0: pass-through; a symmetric split lands alongside the
  // response-phase design.
  virtual AiFilterStatus onResponse(Codec::AiResponse& /*res*/, AiFilterCallbacks& /*cb*/) {
    return AiFilterStatus::Continue;
  }

  virtual void onDestroy() {}
};

using AiFilterPtr = std::unique_ptr<AiFilter>;

} // namespace Chain
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
