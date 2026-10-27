#include "source/extensions/http/ai_filters/schema_validation/filter.h"

#include <optional>
#include <string>
#include <utility>

#include "source/extensions/filters/http/ai_protocol_manager/ai_filter_state.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_readers.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_adapter.h"
#include "source/extensions/filters/http/ai_protocol_manager/llm_protocol_conversion.h"
#include "source/extensions/filters/http/ai_protocol_manager/schema.h"
#include "source/extensions/http/ai_filters/schema_validation/llm_protocol_detection.h"

#include "absl/status/statusor.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace SchemaValidation {

using HttpFilters::AiProtocolManager::AdapterRegistry;
using HttpFilters::AiProtocolManager::AiFilterContext;
using HttpFilters::AiProtocolManager::AiRequest;
using HttpFilters::AiProtocolManager::BuiltInBindings;
using HttpFilters::AiProtocolManager::builtInBindings;
using HttpFilters::AiProtocolManager::LlmBindingConstSharedPtr;
using HttpFilters::AiProtocolManager::LlmBindingObject;
using HttpFilters::AiProtocolManager::LlmBindingRead;
using HttpFilters::AiProtocolManager::LLMProtocol;
using HttpFilters::AiProtocolManager::llmProtocolName;
using HttpFilters::AiProtocolManager::LocalReplier;
using HttpFilters::AiProtocolManager::PayloadSchema;
namespace FilterStateKeys = HttpFilters::AiProtocolManager::FilterStateKeys;
namespace Keys = HttpFilters::AiProtocolManager::Keys;

namespace {

std::optional<nlohmann::json> copyField(const nlohmann::json& body, absl::string_view field) {
  const auto found = body.find(field);
  return found != body.end() ? std::make_optional(*found) : std::nullopt;
}

void restoreField(nlohmann::json& body, absl::string_view field,
                  std::optional<nlohmann::json>&& sent) {
  if (sent.has_value()) {
    body[field] = *std::move(sent);
  } else {
    body.erase(field);
  }
}

// The envoy.ai.binding.request object, else the route's binding. The transcoder reports one that
// does not parse.
LlmBindingConstSharedPtr requestBinding(const AiFilterContext& context) {
  absl::StatusOr<LlmBindingConstSharedPtr> binding = LlmBindingObject::fromFilterState(
      *context.stream_info.filterState(), FilterStateKeys::BindingRequest);
  return binding.ok() && *binding != nullptr ? *std::move(binding) : context.request_binding;
}

// Validates the payload with the client's path read into it under its binding, as the transcoder
// reads it, and restores the payload after.
absl::Status validate(const PayloadSchema& schema, AiRequest& request,
                      const AiFilterContext& context) {
  nlohmann::json& body = request.json();
  if (!body.is_object()) {
    return schema.validateRequest(request.request_index());
  }
  // The read replaces `model` and `stream` with the path's, and hands back the fields it takes out.
  std::optional<nlohmann::json> model = copyField(body, Keys::Model);
  std::optional<nlohmann::json> stream = copyField(body, Keys::Stream);
  const BuiltInBindings& built_in = builtInBindings(request.protocol());
  std::optional<LlmBindingRead> read =
      readClientPath(requestBinding(context), built_in.api, built_in.clients,
                     context.request_headers.getPathValue(), body);
  const absl::Status status = schema.validateRequest(request.request_index());
  if (read.has_value()) {
    for (auto& [field, value] : read->written_fields) {
      body[field] = std::move(value);
    }
    restoreField(body, Keys::Model, std::move(model));
    restoreField(body, Keys::Stream, std::move(stream));
  }
  return status;
}

} // namespace

SchemaValidationFilterConfig::SchemaValidationFilterConfig(
    const envoy::extensions::http::ai_filters::schema_validation::v3::SchemaValidation& proto,
    Stats::Scope& scope)
    : stats_(SchemaValidationFilterStats{ALL_SCHEMA_VALIDATION_FILTER_STATS(
          POOL_COUNTER_PREFIX(scope, "ai_protocol_manager.schema_validation."))}),
      default_llm_protocol_(
          HttpFilters::AiProtocolManager::protocolFromProto(proto.default_llm_protocol())),
      fail_open_(proto.fail_open()) {}

SchemaValidationFilter::SchemaValidationFilter(SchemaValidationFilterConfigSharedPtr config,
                                               const AiFilterContext& context)
    : config_(std::move(config)), context_(context) {}

absl::Status SchemaValidationFilter::decodeSync(AiRequest& request, LocalReplier reply_locally) {
  request.setProtocol(resolveLlmProtocol(request));
  const PayloadSchema* schema = AdapterRegistry::get(request.protocol()).schema();
  if (schema == nullptr) {
    config_->stats().skipped_.inc();
    return absl::OkStatus();
  }

  // TODO(penguingao): validate as the parser streams, rejecting an invalid field before the
  // payload ends.
  const absl::Status status = validate(*schema, request, context_);
  if (status.ok()) {
    config_->stats().valid_.inc();
    return absl::OkStatus();
  }
  config_->stats().invalid_.inc();
  ENVOY_LOG(debug, "schema_validation: invalid {} payload: {}", llmProtocolName(request.protocol()),
            status.message());
  if (!config_->failOpen()) {
    std::move(reply_locally)(Http::Code::BadRequest, std::string(status.message()));
  }
  return absl::OkStatus();
}

LLMProtocol SchemaValidationFilter::resolveLlmProtocol(const AiRequest& request) const {
  if (request.protocol() != LLMProtocol::Unspecified) {
    return request.protocol();
  }
  if (config_->defaultLlmProtocol() != LLMProtocol::Unspecified) {
    return config_->defaultLlmProtocol();
  }
  LLMProtocol detected = detectFromHeaders(context_.request_headers);
  if (detected == LLMProtocol::Unspecified) {
    detected = detectFromPayload(request.json());
  }
  if (detected != LLMProtocol::Unspecified) {
    config_->stats().llm_protocol_detected_.inc();
  }
  return detected;
}

} // namespace SchemaValidation
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
