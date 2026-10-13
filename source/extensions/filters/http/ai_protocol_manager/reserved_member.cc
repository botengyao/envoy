#include "source/extensions/filters/http/ai_protocol_manager/reserved_member.h"

#include <string>

#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace ReservedMember {

void remove(nlohmann::json& document) {
  if (document.is_object()) {
    document.erase(std::string(Name));
  }
}

bool isOnlyMember(const nlohmann::json& document) {
  return document.is_object() && document.size() == 1 && document.contains(Name);
}

} // namespace ReservedMember
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
