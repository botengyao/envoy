#include "source/extensions/http/ai_filters/transcoder/config.h"

#include "envoy/registry/registry.h"

#include "source/common/protobuf/utility.h"
#include "source/extensions/http/ai_filters/transcoder/filter.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

absl::StatusOr<HttpFilters::AiProtocolManager::AiFilterFactoryCb>
TranscoderFilterConfigFactory::createAiFilterFactory(
    const Protobuf::Message& config, Server::Configuration::ServerFactoryContext& context,
    Stats::Scope& scope) {
  const auto& proto = MessageUtil::downcastAndValidate<
      const envoy::extensions::http::ai_filters::transcoder::v3::Transcoder&>(
      config, context.messageValidationVisitor());
  absl::StatusOr<TranscoderConfigSharedPtr> filter_config = TranscoderConfig::create(proto, scope);
  RETURN_IF_NOT_OK_REF(filter_config.status());
  return [filter_config = std::move(filter_config.value())](
             const HttpFilters::AiProtocolManager::AiFilterContext& stream_context)
             -> HttpFilters::AiProtocolManager::AiFilterSharedPtr {
    return std::make_shared<TranscoderFilter>(filter_config, stream_context);
  };
}

REGISTER_FACTORY(TranscoderFilterConfigFactory,
                 HttpFilters::AiProtocolManager::AiFilterConfigFactory);

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
