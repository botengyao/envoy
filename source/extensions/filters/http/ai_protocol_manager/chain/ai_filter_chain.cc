#include "source/extensions/filters/http/ai_protocol_manager/chain/ai_filter_chain.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Chain {

AiFilterChain::AiFilterChain(std::vector<AiFilterPtr> filters) : filters_(std::move(filters)) {}

AiItemKindSet AiFilterChain::itemInterestUnion() const {
  AiItemKindSet out = AiItemKindSet::none();
  for (const auto& f : filters_) {
    out = out.unionWith(f->itemInterest());
  }
  return out;
}

AiFilterStatus AiFilterChain::runMetadata(Codec::AiRequest& req, AiFilterCallbacks& cb) {
  for (auto& f : filters_) {
    const auto s = f->onRequestMetadata(req, cb);
    if (s == AiFilterStatus::StopIteration) {
      // V0: return immediately. Resume/continue machinery lands with the
      // per-item pause handling; for now the caller treats StopIteration as
      // "pipeline paused, wait for continueRequest()".
      return s;
    }
  }
  return AiFilterStatus::Continue;
}

AiFilterStatus AiFilterChain::runItem(AiItem& item, AiFilterCallbacks& cb) {
  for (auto& f : filters_) {
    const auto interest = f->itemInterest();
    const bool wants = (item.kind() == AiItemKind::Message && interest.messages) ||
                       (item.kind() == AiItemKind::Tool && interest.tools) ||
                       (item.kind() == AiItemKind::Attachment && interest.attachments);
    if (!wants) {
      continue;
    }
    const auto s = f->onRequestItem(item, cb);
    if (s == AiFilterStatus::StopIteration) {
      return s;
    }
  }
  return AiFilterStatus::Continue;
}

AiFilterStatus AiFilterChain::runResponse(Codec::AiResponse& res, AiFilterCallbacks& cb) {
  for (auto& f : filters_) {
    const auto s = f->onResponse(res, cb);
    if (s == AiFilterStatus::StopIteration) {
      return s;
    }
  }
  return AiFilterStatus::Continue;
}

void AiFilterChain::onDestroy() {
  for (auto& f : filters_) {
    f->onDestroy();
  }
}

} // namespace Chain
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
