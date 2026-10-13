#pragma once

#include "absl/strings/string_view.h"
#include "nlohmann/json_fwd.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// The member a response document reserves for what AI filters hand down the chain. The AI Protocol
// Manager removes it as a response enters the AI filter chain, so an upstream cannot supply it,
// and again before the response leaves, so a client never sees it.
namespace ReservedMember {

constexpr absl::string_view Name = "_envoy";

// Under Name: the usage the provider reported, as the envoy.data.ai.v3.TokenUsage record that a
// transcoder leg writes when it converts the provider's response into the IR (usage_record.h).
constexpr absl::string_view TokenUsageRecord = "token_usage";

// Removes the member from `document`, if it is an object that has one.
void remove(nlohmann::json& document);

// Whether the member is all `document` carries: the document exists only to hand data down the
// chain, and has nothing for the client.
bool isOnlyMember(const nlohmann::json& document);

} // namespace ReservedMember

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
