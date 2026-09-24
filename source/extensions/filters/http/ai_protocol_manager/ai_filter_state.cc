#include "source/extensions/filters/http/ai_protocol_manager/ai_filter_state.h"

#include <memory>
#include <string>

#include "envoy/registry/registry.h"
#include "envoy/type/ai/v3/downstream_api.pb.validate.h"
#include "envoy/type/ai/v3/upstream_target.pb.validate.h"

#include "source/common/common/logger.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_conversion.h"

#include "absl/status/status.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

// PGV only requires a defined llm_protocol, which protocolFromProto() relies on.
template <class Proto> bool parseJson(absl::string_view json, Proto& proto, absl::string_view key) {
  bool has_unknown_field = false;
  absl::Status status = MessageUtil::loadFromJsonNoThrow(json, proto, has_unknown_field);
  if (std::string error; status.ok() && !Validate(proto, &error)) {
    status = absl::InvalidArgumentError(error);
  }
  if (!status.ok()) {
    ENVOY_LOG_MISC(debug, "invalid {} filter state: {}", key, status.message());
  }
  return status.ok();
}

} // namespace

const DownstreamApiState*
DownstreamApiState::fromFilterState(const StreamInfo::FilterState& filter_state) {
  return filter_state.getDataReadOnly<DownstreamApiState>(kFilterStateKey);
}

LLMProtocol DownstreamApiState::protocol() const { return protocolFromProto(api_->llm_protocol()); }

ProtobufTypes::MessagePtr DownstreamApiState::serializeAsProto() const {
  return std::make_unique<envoy::type::ai::v3::DownstreamApi>(*api_);
}

std::optional<std::string> DownstreamApiState::serializeAsString() const {
  return MessageUtil::getJsonStringFromMessageOrError(*api_);
}

StreamInfo::FilterState::Object::FieldType
DownstreamApiState::getField(absl::string_view field_name) const {
  if (field_name == "llm_protocol") {
    return llmProtocolName(protocol());
  }
  return absl::monostate{};
}

const UpstreamTargetState*
UpstreamTargetState::fromFilterState(const StreamInfo::FilterState& filter_state) {
  return filter_state.getDataReadOnly<UpstreamTargetState>(kFilterStateKey);
}

LLMProtocol UpstreamTargetState::protocol() const {
  return protocolFromProto(target_->llm_protocol());
}

ProtobufTypes::MessagePtr UpstreamTargetState::serializeAsProto() const {
  return std::make_unique<envoy::type::ai::v3::UpstreamTarget>(*target_);
}

std::optional<std::string> UpstreamTargetState::serializeAsString() const {
  return MessageUtil::getJsonStringFromMessageOrError(*target_);
}

StreamInfo::FilterState::Object::FieldType
UpstreamTargetState::getField(absl::string_view field_name) const {
  // The views point into the held proto, which outlives the call.
  if (field_name == "llm_protocol") {
    return llmProtocolName(protocol());
  }
  if (field_name == "authority") {
    return absl::string_view(target_->authority());
  }
  if (field_name == "model") {
    return absl::string_view(target_->model());
  }
  if (field_name == "preset") {
    return absl::string_view(target_->endpoint().preset());
  }
  return absl::monostate{};
}

namespace {

class DownstreamApiObjectFactory : public StreamInfo::FilterState::ObjectFactory {
public:
  std::string name() const override { return std::string(DownstreamApiState::kFilterStateKey); }

  std::unique_ptr<StreamInfo::FilterState::Object>
  createFromBytes(absl::string_view data) const override {
    envoy::type::ai::v3::DownstreamApi api;
    envoy::type::ai::v3::LLMProtocol protocol;
    if (envoy::type::ai::v3::LLMProtocol_Parse(std::string(data), &protocol)) {
      api.set_llm_protocol(protocol);
    } else if (!parseJson(data, api, DownstreamApiState::kFilterStateKey)) {
      return nullptr;
    }
    return std::make_unique<DownstreamApiState>(
        std::make_shared<const envoy::type::ai::v3::DownstreamApi>(std::move(api)));
  }
};

class UpstreamTargetObjectFactory : public StreamInfo::FilterState::ObjectFactory {
public:
  std::string name() const override { return std::string(UpstreamTargetState::kFilterStateKey); }

  std::unique_ptr<StreamInfo::FilterState::Object>
  createFromBytes(absl::string_view data) const override {
    envoy::type::ai::v3::UpstreamTarget target;
    if (!parseJson(data, target, UpstreamTargetState::kFilterStateKey)) {
      return nullptr;
    }
    return std::make_unique<UpstreamTargetState>(
        std::make_shared<const envoy::type::ai::v3::UpstreamTarget>(std::move(target)));
  }
};

REGISTER_FACTORY(DownstreamApiObjectFactory, StreamInfo::FilterState::ObjectFactory);
REGISTER_FACTORY(UpstreamTargetObjectFactory, StreamInfo::FilterState::ObjectFactory);

} // namespace

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
