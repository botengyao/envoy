#pragma once

#include <optional>
#include <string>

#include "envoy/stream_info/filter_state.h"

#include "source/extensions/filters/http/ai_protocol_manager/token_usage.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// The LLM wire protocol a request payload follows, named by a filter that knows
// the caller rather than by the route that matched. The AI Protocol Manager
// takes it ahead of the route's own declaration; see RouteConfig in filter.h.
//
// A factory is registered under kFilterStateKey that builds the object from an
// envoy.type.ai.v3.ApiProtocol enum-value name, so an extension that cannot link
// this one -- set_filter_state, Lua, ext_proc -- can still set it.
//
// Serializes as that same name: the object holds one enum, so a string says
// everything a proto would. Access logs therefore need ``:PLAIN`` or
// ``:FIELD:api_protocol``, since ``%FILTER_STATE(key)%`` defaults to TYPED.
class RequestLlmProtocol : public StreamInfo::FilterState::Object {
public:
  static constexpr absl::string_view kFilterStateKey = "envoy.ai.llm_protocol.request";

  explicit RequestLlmProtocol(ApiProtocol protocol) : protocol_(protocol) {}

  ApiProtocol protocol() const { return protocol_; }

  // StreamInfo::FilterState::Object
  std::optional<std::string> serializeAsString() const override;
  bool hasFieldSupport() const override { return true; }
  FieldType getField(absl::string_view field_name) const override;

private:
  const ApiProtocol protocol_;
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
