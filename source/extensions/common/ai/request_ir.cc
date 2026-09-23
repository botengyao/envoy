#include "source/extensions/common/ai/request_ir.h"

#include <utility>

#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Ai {

using HttpFilters::AiProtocolManager::JsonWithExtBuf;
using HttpFilters::AiProtocolManager::LLMProtocol;
using HttpFilters::AiProtocolManager::llmProtocolName;

RequestIr::RequestIr(LLMProtocol client_protocol, std::string model, std::optional<bool> stream,
                     std::optional<JsonWithExtBuf> document)
    : client_protocol_(client_protocol), model_(std::move(model)), stream_(stream),
      document_(std::move(document)) {}

std::optional<std::string> RequestIr::serializeAsString() const {
  nlohmann::json summary = nlohmann::json::object();
  summary["client_protocol"] = std::string(llmProtocolName(client_protocol_));
  summary["model"] = model_;
  if (stream_.has_value()) {
    summary["stream"] = stream_.value();
  }
  return summary.dump();
}

StreamInfo::FilterState::Object::FieldType RequestIr::getField(absl::string_view field_name) const {
  if (field_name == "model") {
    return absl::string_view(model_);
  }
  if (field_name == "client_protocol") {
    return llmProtocolName(client_protocol_);
  }
  if (field_name == "stream" && stream_.has_value()) {
    return absl::string_view(stream_.value() ? "true" : "false");
  }
  return absl::monostate{};
}

} // namespace Ai
} // namespace Common
} // namespace Extensions
} // namespace Envoy
