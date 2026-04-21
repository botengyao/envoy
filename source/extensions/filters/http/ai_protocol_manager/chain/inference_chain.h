#pragma once

#include "source/extensions/filters/http/ai_protocol_manager/chain/ai_filter_chain.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Chain {

// DESIGN.md §5.4 — typed façade over AiFilterChain. Exists so inference-
// specific factories and helpers (e.g. modelTarget() accessor) have a natural
// home separate from the shared runner.
class InferenceChain {
public:
  explicit InferenceChain(AiFilterChainPtr chain) : chain_(std::move(chain)) {}

  AiFilterChain& chain() { return *chain_; }
  const AiFilterChain& chain() const { return *chain_; }

private:
  AiFilterChainPtr chain_;
};

using InferenceChainPtr = std::unique_ptr<InferenceChain>;

} // namespace Chain
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
