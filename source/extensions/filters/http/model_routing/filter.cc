#include "source/extensions/filters/http/model_routing/filter.h"

#include <algorithm>

#include "envoy/http/codes.h"

#include "source/common/common/utility.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/headers.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/common/dynamic_forward_proxy/dynamic_host_candidates.h"
#include "source/extensions/filters/http/ai_protocol_manager/serializer.h"

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelRouting {

namespace {

using DynamicHostCandidates = Envoy::Extensions::Common::DynamicForwardProxy::DynamicHostCandidates;

constexpr absl::string_view DefaultPolicyNamespace = "envoy.ai.model_routing";
constexpr int MaxPolicyTargets = 16;
constexpr size_t MaxHostLength = 255;
constexpr size_t MaxIdLength = 128;
constexpr size_t MaxModelLength = 256;
constexpr size_t MaxPathLength = 1024;
constexpr uint32_t MaxPort = 65535;

constexpr ModelRoutingPolicy::FallbackCondition DefaultFallbackOn[] = {
    ModelRoutingPolicy::CONNECT_FAILURE, ModelRoutingPolicy::RATE_LIMITED,
    ModelRoutingPolicy::OVERLOADED, ModelRoutingPolicy::GATEWAY_ERROR};

bool validCondition(int condition) {
  return ModelRoutingPolicy::FallbackCondition_IsValid(condition) &&
         condition != ModelRoutingPolicy::FALLBACK_CONDITION_UNSPECIFIED;
}

// Metadata is not validated against the proto constraints, so the policy is checked here.
bool validTarget(const ModelRoutingPolicy::Target& target) {
  if (target.host().size() > MaxHostLength || !DynamicHostCandidates::validHost(target.host()) ||
      target.port() > MaxPort || target.id().size() > MaxIdLength || target.model().empty() ||
      target.model().size() > MaxModelLength || target.path().size() > MaxPathLength) {
    return false;
  }
  if (target.path().empty()) {
    return true;
  }
  return target.path().front() == '/' &&
         Envoy::Http::HeaderUtility::headerValueIsValid(
             absl::StrReplaceAll(target.path(), {{"{model}", target.model()}}));
}

bool validPolicy(const ModelRoutingPolicy& policy) {
  return !policy.targets().empty() && policy.targets_size() <= MaxPolicyTargets &&
         policy.decision_id().size() <= MaxIdLength &&
         std::all_of(policy.targets().begin(), policy.targets().end(), validTarget) &&
         std::all_of(policy.fallback_on().begin(), policy.fallback_on().end(), validCondition);
}

void addUnique(std::vector<absl::string_view>& values, absl::string_view value) {
  if (std::find(values.begin(), values.end(), value) == values.end()) {
    values.push_back(value);
  }
}

void addRetryCondition(ModelRoutingPolicy::FallbackCondition condition,
                       std::vector<absl::string_view>& retry_on,
                       std::vector<absl::string_view>& status_codes) {
  const auto& values = Envoy::Http::Headers::get().EnvoyRetryOnValues;
  switch (condition) {
  case ModelRoutingPolicy::CONNECT_FAILURE:
    addUnique(retry_on, values.ConnectFailure);
    break;
  case ModelRoutingPolicy::RESET:
    addUnique(retry_on, values.Reset);
    break;
  case ModelRoutingPolicy::RATE_LIMITED:
    addUnique(retry_on, values.RetriableStatusCodes);
    addUnique(status_codes, "429");
    break;
  case ModelRoutingPolicy::SERVER_ERROR:
    addUnique(retry_on, values._5xx);
    break;
  case ModelRoutingPolicy::OVERLOADED:
    addUnique(retry_on, values.RetriableStatusCodes);
    addUnique(status_codes, "503");
    addUnique(status_codes, "529");
    break;
  case ModelRoutingPolicy::GATEWAY_ERROR:
    addUnique(retry_on, values.GatewayError);
    break;
  default:
    break;
  }
}

void setRetryHeaders(Envoy::Http::RequestHeaderMap& headers, const ModelRoutingPolicy& policy,
                     size_t plan_size) {
  const auto& header_names = Envoy::Http::Headers::get();
  // Attempts share one request header map, so overlapping hedged attempts would overwrite each
  // other's target.
  headers.setCopy(header_names.EnvoyHedgeOnPerTryTimeout, "false");
  if (policy.has_per_try_timeout()) {
    if (auto timeout = DurationUtil::durationToMillisecondsNoThrow(policy.per_try_timeout());
        timeout.ok() && timeout.value() > 0) {
      headers.setCopy(header_names.EnvoyUpstreamRequestPerTryTimeoutMs,
                      std::to_string(timeout.value()));
    }
  }
  // Also set for a single target, since a route retry would find no candidate left.
  headers.setCopy(header_names.EnvoyMaxRetries, std::to_string(plan_size - 1));
  if (plan_size < 2) {
    return;
  }

  std::vector<absl::string_view> retry_on;
  std::vector<absl::string_view> status_codes;
  if (policy.fallback_on().empty()) {
    for (const auto condition : DefaultFallbackOn) {
      addRetryCondition(condition, retry_on, status_codes);
    }
  } else {
    for (const int condition : policy.fallback_on()) {
      addRetryCondition(static_cast<ModelRoutingPolicy::FallbackCondition>(condition), retry_on,
                        status_codes);
    }
  }
  headers.setCopy(header_names.EnvoyRetryOn, absl::StrJoin(retry_on, ","));
  if (!status_codes.empty()) {
    headers.setCopy(header_names.EnvoyRetriableStatusCodes, absl::StrJoin(status_codes, ","));
  }
}

// The upstream AI protocol manager can only rewrite the model of an uncompressed JSON body.
bool rewritableBody(const Envoy::Http::RequestHeaderMap& headers) {
  const absl::string_view content_type =
      StringUtil::trim(StringUtil::cropRight(headers.getContentTypeValue(), ";"));
  if (!absl::EqualsIgnoreCase(content_type, "application/json") &&
      !absl::EndsWithIgnoreCase(content_type, "+json")) {
    return false;
  }
  const auto encodings = headers.get(Envoy::Http::CustomHeaders::get().ContentEncoding);
  for (size_t i = 0; i < encodings.size(); ++i) {
    if (!absl::EqualsIgnoreCase(StringUtil::trim(encodings[i]->value().getStringView()),
                                "identity")) {
      return false;
    }
  }
  return true;
}

// The models a request body parsed by an AI protocol manager filter asks for.
std::vector<absl::string_view> requestModels(const StreamInfo::FilterState& filter_state) {
  std::vector<absl::string_view> models;
  const auto* payload = filter_state.getDataReadOnly<AiProtocolManager::APMRequestPayloadIndex>(
      AiProtocolManager::APMRequestPayloadIndex::kFilterStateKey);
  if (payload == nullptr || !payload->index().json().is_object()) {
    return models;
  }
  const nlohmann::json& body = payload->index().json();
  if (const auto list = body.find("models"); list != body.end() && list->is_array()) {
    for (const nlohmann::json& model : *list) {
      if (model.is_string()) {
        models.push_back(model.get_ref<const std::string&>());
      }
    }
  } else if (const auto model = body.find("model"); model != body.end() && model->is_string()) {
    models.push_back(model->get_ref<const std::string&>());
  }
  return models;
}

} // namespace

FilterConfig::FilterConfig(const ModelRoutingProto& proto, const std::string& stats_prefix,
                           Stats::Scope& scope)
    : policy_namespace_(proto.policy_metadata_namespace().empty()
                            ? std::string(DefaultPolicyNamespace)
                            : proto.policy_metadata_namespace()),
      continue_without_policy_(proto.continue_without_policy()),
      prefer_request_models_(proto.prefer_request_models()),
      stats_{ALL_MODEL_ROUTING_STATS(
          POOL_COUNTER_PREFIX(scope, absl::StrCat(stats_prefix, "model_routing.")))} {}

Envoy::Http::FilterHeadersStatus
ModelRoutingFilter::decodeHeaders(Envoy::Http::RequestHeaderMap& headers, bool end_stream) {
  ModelRoutingPolicy policy;
  switch (readPolicy(policy)) {
  case PolicyStatus::Missing:
    return onUnusablePolicy(config_->stats().no_policy_, "model_routing_no_policy");
  case PolicyStatus::Invalid:
    return onUnusablePolicy(config_->stats().invalid_policy_, "model_routing_invalid_policy");
  case PolicyStatus::Ok:
    break;
  }
  if (!end_stream && !rewritableBody(headers)) {
    return onUnusablePolicy(config_->stats().unsupported_body_, "model_routing_unsupported_body");
  }

  std::vector<AiCommon::ModelTarget> targets;
  targets.reserve(policy.targets_size());
  for (const auto& target : policy.targets()) {
    targets.push_back({target.id().empty() ? target.model() : target.id(), target.host(),
                       static_cast<uint16_t>(target.port()), target.model(), target.path()});
  }
  if (config_->preferRequestModels()) {
    targets = orderByRequestModels(std::move(targets));
  }

  const size_t plan_size = targets.size();
  auto plan = std::make_shared<AiCommon::ModelRoutePlan>(std::move(targets), policy.decision_id());
  StreamInfo::FilterState& filter_state = *decoder_callbacks_->streamInfo().filterState();
  filter_state.setData(AiCommon::ModelRoutePlan::key(), plan,
                       StreamInfo::FilterState::LifeSpan::FilterChain);
  filter_state.setData(DynamicHostCandidates::key(), plan,
                       StreamInfo::FilterState::LifeSpan::FilterChain);

  setRetryHeaders(headers, policy, plan_size);
  config_->stats().plan_created_.inc();
  return Envoy::Http::FilterHeadersStatus::Continue;
}

ModelRoutingFilter::PolicyStatus ModelRoutingFilter::readPolicy(ModelRoutingPolicy& policy) const {
  const auto& metadata = decoder_callbacks_->streamInfo().dynamicMetadata();
  if (const auto typed = metadata.typed_filter_metadata().find(config_->policyNamespace());
      typed != metadata.typed_filter_metadata().end()) {
    if (!MessageUtil::unpackTo(typed->second, policy).ok()) {
      return PolicyStatus::Invalid;
    }
  } else if (const auto untyped = metadata.filter_metadata().find(config_->policyNamespace());
             untyped != metadata.filter_metadata().end()) {
    const auto json = MessageUtil::getJsonStringFromMessage(untyped->second);
    if (!json.ok()) {
      return PolicyStatus::Invalid;
    }
    bool has_unknown_field = false;
    const absl::Status status =
        MessageUtil::loadFromJsonNoThrow(json.value(), policy, has_unknown_field);
    // Unknown fields are accepted, as they are in typed metadata.
    if (!status.ok() && !has_unknown_field) {
      return PolicyStatus::Invalid;
    }
  } else {
    return PolicyStatus::Missing;
  }
  return validPolicy(policy) ? PolicyStatus::Ok : PolicyStatus::Invalid;
}

Envoy::Http::FilterHeadersStatus ModelRoutingFilter::onUnusablePolicy(Stats::Counter& counter,
                                                                      absl::string_view details) {
  counter.inc();
  if (config_->continueWithoutPolicy()) {
    return Envoy::Http::FilterHeadersStatus::Continue;
  }
  decoder_callbacks_->sendLocalReply(Envoy::Http::Code::ServiceUnavailable, "", nullptr,
                                     std::nullopt, details);
  return Envoy::Http::FilterHeadersStatus::StopIteration;
}

std::vector<AiCommon::ModelTarget>
ModelRoutingFilter::orderByRequestModels(std::vector<AiCommon::ModelTarget> targets) const {
  const std::vector<absl::string_view> models =
      requestModels(*decoder_callbacks_->streamInfo().filterState());
  if (models.empty()) {
    return targets;
  }
  std::vector<AiCommon::ModelTarget> ordered;
  std::vector<bool> taken(targets.size());
  for (const absl::string_view model : models) {
    for (size_t i = 0; i < targets.size(); ++i) {
      if (!taken[i] && targets[i].model == model) {
        taken[i] = true;
        ordered.push_back(targets[i]);
      }
    }
  }
  if (ordered.empty()) {
    config_->stats().request_models_unmatched_.inc();
    return targets;
  }
  return ordered;
}

} // namespace ModelRouting
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
