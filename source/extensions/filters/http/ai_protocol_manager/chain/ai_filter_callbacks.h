#pragma once

#include "envoy/event/dispatcher.h"
#include "envoy/stream_info/stream_info.h"

#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_request.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Chain {

class AiItem; // chain/ai_filter_chain.h

// Forward-declared event type for recordEvent(). Kept opaque here; concrete
// enum defined alongside the chain implementation. Avoids a cyclic include.
struct AiEvent;

// DESIGN.md §5.2 — narrow interface through which an AiFilter interacts with
// the world. Intentionally does not expose HTTP primitives (RequestHeaderMap,
// Buffer, route config, ClusterManager). If a sub-chain filter needs one, the
// concern should be promoted into AiRequest instead.
class AiFilterCallbacks {
public:
  virtual ~AiFilterCallbacks() = default;

  virtual Event::Dispatcher& dispatcher() = 0;
  virtual StreamInfo::StreamInfo& streamInfo() = 0;

  // Resume after StopIteration. Valid at whatever granularity the pause
  // happened (metadata or per-item phase).
  virtual void continueRequest() = 0;
  virtual void continueResponse() = 0;

  // Short-circuit the chain and reply directly. Valid in any phase.
  virtual void sendLocalReply(Codec::AiResponse&& response) = 0;

  // Per-item callbacks (valid only inside onRequestItem).
  virtual void dropCurrentItem() = 0;
  virtual void insertAfter(AiItem&& item) = 0;

  // Observability entry point.
  virtual void recordEvent(const AiEvent& event) = 0;
};

} // namespace Chain
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
