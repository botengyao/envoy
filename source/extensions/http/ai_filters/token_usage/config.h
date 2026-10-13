#pragma once

#include "envoy/extensions/http/ai_filters/token_usage/v3/token_usage.pb.h"
#include "envoy/extensions/http/ai_filters/token_usage/v3/token_usage.pb.validate.h"

#include "source/extensions/filters/http/ai_protocol_manager/ai_filter.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace TokenUsage {

class TokenUsageFilterConfigFactory : public HttpFilters::AiProtocolManager::AiFilterConfigFactory {
public:
  absl::StatusOr<HttpFilters::AiProtocolManager::AiFilterFactoryCb>
  createAiFilterFactory(const Protobuf::Message& config,
                        Server::Configuration::ServerFactoryContext& context,
                        Stats::Scope& scope) override;

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::http::ai_filters::token_usage::v3::TokenUsage>();
  }

  std::string name() const override { return "envoy.http.ai_filters.token_usage"; }
};

} // namespace TokenUsage
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
