#pragma once

#include "source/extensions/filters/http/ai_protocol_manager/chain/ai_filter_chain.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Chain {

// DESIGN.md §5.4 — typed façade for the agent sub-chain.
class AgentChain {
public:
  explicit AgentChain(AiFilterChainPtr chain) : chain_(std::move(chain)) {}

  AiFilterChain& chain() { return *chain_; }
  const AiFilterChain& chain() const { return *chain_; }

private:
  AiFilterChainPtr chain_;
};

using AgentChainPtr = std::unique_ptr<AgentChain>;

} // namespace Chain
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
