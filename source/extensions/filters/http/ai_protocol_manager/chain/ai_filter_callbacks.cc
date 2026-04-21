#include "source/extensions/filters/http/ai_protocol_manager/chain/ai_filter_callbacks.h"

#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Chain {

#define AI_UNREACHABLE() PANIC("UnreachableCallbacks invoked — empty-chain invariant broken")

Event::Dispatcher& UnreachableCallbacks::dispatcher() { AI_UNREACHABLE(); }
StreamInfo::StreamInfo& UnreachableCallbacks::streamInfo() { AI_UNREACHABLE(); }
void UnreachableCallbacks::continueRequest() { AI_UNREACHABLE(); }
void UnreachableCallbacks::continueResponse() { AI_UNREACHABLE(); }
void UnreachableCallbacks::sendLocalReply(Codec::AiResponse&&) { AI_UNREACHABLE(); }
void UnreachableCallbacks::dropCurrentItem() { AI_UNREACHABLE(); }
void UnreachableCallbacks::insertAfter(AiItem&&) { AI_UNREACHABLE(); }
void UnreachableCallbacks::recordEvent(const AiEvent&) { AI_UNREACHABLE(); }

#undef AI_UNREACHABLE

} // namespace Chain
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
