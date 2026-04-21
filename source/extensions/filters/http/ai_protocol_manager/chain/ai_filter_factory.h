#pragma once

#include <memory>
#include <string>

#include "envoy/registry/registry.h"

#include "source/extensions/filters/http/ai_protocol_manager/chain/ai_filter.h"

#include "google/protobuf/any.pb.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Chain {

// DESIGN.md §5.4 / §5.5 — typed registration for sub-chain filters. Two
// categories (Inference, Agent) keep namespaces independent so factories can
// validate config against only their variant of AiRequest::payload.

enum class SubChainKind { Inference, Agent };

class AiFilterFactory {
public:
  virtual ~AiFilterFactory() = default;
  virtual std::string name() const = 0;
  virtual SubChainKind subChainKind() const = 0;
  virtual AiFilterPtr create(const google::protobuf::Any& typed_config) = 0;

  static std::string category() { return "envoy.ai_protocol_manager.filters"; }
};

} // namespace Chain
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
