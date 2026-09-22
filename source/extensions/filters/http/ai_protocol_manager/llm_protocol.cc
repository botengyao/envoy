#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol.h"

#include <memory>
#include <string>

#include "envoy/data/ai/v3/llm_protocol.pb.h"
#include "envoy/registry/registry.h"

#include "source/extensions/filters/http/ai_protocol_manager/api_protocol_conversion.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

ProtobufTypes::MessagePtr RequestLlmProtocol::serializeAsProto() const {
  auto proto = std::make_unique<envoy::data::ai::v3::RequestLlmProtocol>();
  proto->set_api_protocol(protocolToProto(protocol_));
  return proto;
}

std::optional<std::string> RequestLlmProtocol::serializeAsString() const {
  return std::string(apiProtocolName(protocol_));
}

StreamInfo::FilterState::Object::FieldType
RequestLlmProtocol::getField(absl::string_view field_name) const {
  // Backed by a string literal, so the view outlives the call.
  if (field_name == "api_protocol") {
    return apiProtocolName(protocol_);
  }
  return absl::monostate{};
}

namespace {

class RequestLlmProtocolObjectFactory : public StreamInfo::FilterState::ObjectFactory {
public:
  std::string name() const override { return std::string(RequestLlmProtocol::kFilterStateKey); }

  // A name the enum does not define yields no object, rather than one silently
  // naming no protocol: a typo must not read as "I looked and did not know".
  std::unique_ptr<StreamInfo::FilterState::Object>
  createFromBytes(absl::string_view data) const override {
    envoy::type::ai::v3::ApiProtocol protocol;
    if (!envoy::type::ai::v3::ApiProtocol_Parse(std::string(data), &protocol)) {
      return nullptr;
    }
    return std::make_unique<RequestLlmProtocol>(protocolFromProto(protocol));
  }
};

REGISTER_FACTORY(RequestLlmProtocolObjectFactory, StreamInfo::FilterState::ObjectFactory);

} // namespace

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
