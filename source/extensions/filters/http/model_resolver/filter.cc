#include "source/extensions/filters/http/model_resolver/filter.h"

#include <algorithm>

#include "envoy/http/codes.h"

#include "source/common/common/macros.h"
#include "source/common/common/utility.h"
#include "source/common/http/headers.h"
#include "source/common/protobuf/utility.h"
#include "source/common/secret/secret_provider_impl.h"

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelResolver {

namespace {

constexpr absl::string_view DefaultPolicyNamespace = "envoy.ai.model_routing";
constexpr uint32_t DefaultMaxRetries = 3;
constexpr int MaxPolicyTargets = 16;
constexpr size_t MaxDecisionIdLength = 128;
constexpr uint16_t PrewarmDefaultPort = 443;

class SdsCredentialSource : public AiCommon::CredentialSource {
public:
  explicit SdsCredentialSource(std::unique_ptr<Secret::ThreadLocalGenericSecretProvider> provider)
      : provider_(std::move(provider)) {}

  absl::string_view credential() const override { return provider_->secret(); }

private:
  const std::unique_ptr<Secret::ThreadLocalGenericSecretProvider> provider_;
};

absl::StatusOr<AiCommon::CredentialSourceSharedPtr>
createCredentialSource(const envoy::extensions::transport_sockets::tls::v3::SdsSecretConfig& config,
                       Server::Configuration::ServerFactoryContext& context,
                       Init::Manager& init_manager) {
  Secret::GenericSecretConfigProviderSharedPtr provider =
      config.has_sds_config()
          ? context.secretManager().findOrCreateGenericSecretProvider(
                config.sds_config(), config.name(), context, init_manager)
          : context.secretManager().findStaticGenericSecretProvider(config.name());
  if (provider == nullptr) {
    return absl::InvalidArgumentError(
        absl::StrCat("model_resolver: unknown generic secret '", config.name(), "'"));
  }
  auto thread_local_provider = Secret::ThreadLocalGenericSecretProvider::create(
      std::move(provider), context.threadLocal(), context.api());
  RETURN_IF_NOT_OK_REF(thread_local_provider.status());
  return std::make_shared<SdsCredentialSource>(std::move(thread_local_provider.value()));
}

bool validCondition(int condition) {
  return ModelRoutingPolicy::FallbackCondition_IsValid(condition) &&
         condition != ModelRoutingPolicy::FALLBACK_CONDITION_UNSPECIFIED;
}

bool validPolicy(const ModelRoutingPolicy& policy) {
  if (policy.target_ids().empty() || policy.target_ids().size() > MaxPolicyTargets ||
      policy.decision_id().size() > MaxDecisionIdLength) {
    return false;
  }
  if (std::any_of(policy.target_ids().begin(), policy.target_ids().end(),
                  [](const std::string& id) { return id.empty(); })) {
    return false;
  }
  return std::all_of(policy.fallback_on().begin(), policy.fallback_on().end(), validCondition);
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

class NoopLoadDnsCacheEntryCallbacks : public DfpCommon::DnsCache::LoadDnsCacheEntryCallbacks {
public:
  void onLoadDnsCacheComplete(const DfpCommon::DnsHostInfoSharedPtr&) override {}
};

DfpCommon::DnsCache::LoadDnsCacheEntryCallbacks& noopLoadDnsCacheEntryCallbacks() {
  MUTABLE_CONSTRUCT_ON_FIRST_USE(NoopLoadDnsCacheEntryCallbacks);
}

} // namespace

FilterConfig::FilterConfig(const ModelResolverProto& proto, const std::string& stats_prefix,
                           Stats::Scope& scope)
    : policy_namespace_(proto.policy_metadata_namespace().empty()
                            ? std::string(DefaultPolicyNamespace)
                            : proto.policy_metadata_namespace()),
      client_api_protocol_(proto.client_api_protocol()),
      max_retries_(PROTOBUF_GET_WRAPPED_OR_DEFAULT(proto, max_retries, DefaultMaxRetries)),
      continue_without_policy_(proto.continue_without_policy()),
      prewarm_fallback_targets_(proto.prewarm_fallback_targets()),
      stats_{ALL_MODEL_RESOLVER_STATS(
          POOL_COUNTER_PREFIX(scope, absl::StrCat(stats_prefix, "model_resolver.")))} {}

absl::StatusOr<FilterConfigConstSharedPtr>
FilterConfig::create(const ModelResolverProto& proto, const std::string& stats_prefix,
                     Stats::Scope& scope, Server::Configuration::ServerFactoryContext& context,
                     Init::Manager& init_manager,
                     DfpCommon::DnsCacheManagerFactory& dns_cache_manager_factory) {
  std::shared_ptr<FilterConfig> config(new FilterConfig(proto, stats_prefix, scope));

  for (const int condition : proto.default_fallback_on()) {
    if (!validCondition(condition)) {
      return absl::InvalidArgumentError("model_resolver: invalid default_fallback_on condition");
    }
    config->default_fallback_on_.push_back(
        static_cast<ModelRoutingPolicy::FallbackCondition>(condition));
  }
  if (config->default_fallback_on_.empty()) {
    config->default_fallback_on_ = {
        ModelRoutingPolicy::CONNECT_FAILURE, ModelRoutingPolicy::RATE_LIMITED,
        ModelRoutingPolicy::OVERLOADED, ModelRoutingPolicy::GATEWAY_ERROR};
  }
  if (proto.has_max_per_try_timeout()) {
    auto timeout = DurationUtil::durationToMillisecondsNoThrow(proto.max_per_try_timeout());
    RETURN_IF_NOT_OK_REF(timeout.status());
    config->max_per_try_timeout_ = std::chrono::milliseconds(timeout.value());
  }

  std::vector<AiCommon::ModelTarget> targets;
  targets.reserve(proto.targets().size());
  for (const auto& [id, target_proto] : proto.targets()) {
    if (!DfpCommon::DynamicHostCandidates::validHost(target_proto.host())) {
      return absl::InvalidArgumentError(
          absl::StrCat("model_resolver: target '", id,
                       "' host must be a DNS name or an IP address without a port"));
    }
    AiCommon::ModelTarget target;
    target.id = id;
    target.host = target_proto.host();
    target.port = static_cast<uint16_t>(target_proto.port());
    target.model = target_proto.model();
    target.path = target_proto.path();
    target.api_protocol = target_proto.api_protocol();
    if (target_proto.has_credential()) {
      const auto& credential = target_proto.credential();
      target.credential_header = Envoy::Http::LowerCaseString(credential.header_name());
      target.credential_prefix = credential.value_prefix();
      auto source = createCredentialSource(credential.generic_secret(), context, init_manager);
      RETURN_IF_NOT_OK_REF(source.status());
      target.credential = std::move(source.value());
    }
    targets.push_back(std::move(target));
  }
  config->registry_ = std::make_shared<const AiCommon::ModelTargetRegistry>(std::move(targets));

  if (proto.has_dns_cache_config()) {
    config->dns_cache_manager_ = dns_cache_manager_factory.get();
    auto cache = config->dns_cache_manager_->getCache(proto.dns_cache_config());
    RETURN_IF_NOT_OK_REF(cache.status());
    config->dns_cache_ = std::move(cache.value());
  }
  return config;
}

Envoy::Http::FilterHeadersStatus
ModelResolverFilter::decodeHeaders(Envoy::Http::RequestHeaderMap& headers, bool end_stream) {
  ModelRoutingPolicy policy;
  switch (readPolicy(policy)) {
  case PolicyStatus::Missing:
    return onUnusablePolicy(config_->stats().no_policy_, "model_resolver_no_policy");
  case PolicyStatus::Invalid:
    return onUnusablePolicy(config_->stats().invalid_policy_, "model_resolver_invalid_policy");
  case PolicyStatus::Ok:
    break;
  }
  if (!end_stream && !rewritableBody(headers)) {
    return onUnusablePolicy(config_->stats().unsupported_body_, "model_resolver_unsupported_body");
  }

  std::vector<const AiCommon::ModelTarget*> targets;
  for (const std::string& id : policy.target_ids()) {
    const AiCommon::ModelTarget* target = config_->registry()->find(id);
    if (target == nullptr) {
      ENVOY_STREAM_LOG(debug, "model_resolver: unknown target '{}'", *decoder_callbacks_, id);
      config_->stats().unknown_target_.inc();
      continue;
    }
    if (!compatible(*target)) {
      config_->stats().incompatible_target_.inc();
      continue;
    }
    targets.push_back(target);
  }
  if (targets.empty()) {
    return onUnusablePolicy(config_->stats().invalid_policy_, "model_resolver_invalid_policy");
  }

  const size_t plan_size = targets.size();
  auto plan = std::make_shared<AiCommon::ModelRoutePlan>(config_->registry(), std::move(targets),
                                                         policy.decision_id());
  StreamInfo::FilterState& filter_state = *decoder_callbacks_->streamInfo().filterState();
  filter_state.setData(AiCommon::ModelRoutePlan::key(), plan,
                       StreamInfo::FilterState::LifeSpan::FilterChain);
  filter_state.setData(DfpCommon::DynamicHostCandidates::key(), plan,
                       StreamInfo::FilterState::LifeSpan::FilterChain);

  setRetryHeaders(headers, policy, plan_size);
  prewarm(*plan);
  config_->stats().plan_created_.inc();
  return Envoy::Http::FilterHeadersStatus::Continue;
}

ModelResolverFilter::PolicyStatus
ModelResolverFilter::readPolicy(ModelRoutingPolicy& policy) const {
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

Envoy::Http::FilterHeadersStatus ModelResolverFilter::onUnusablePolicy(Stats::Counter& counter,
                                                                       absl::string_view details) {
  counter.inc();
  if (config_->continueWithoutPolicy()) {
    return Envoy::Http::FilterHeadersStatus::Continue;
  }
  decoder_callbacks_->sendLocalReply(Envoy::Http::Code::ServiceUnavailable, "", nullptr,
                                     std::nullopt, details);
  return Envoy::Http::FilterHeadersStatus::StopIteration;
}

bool ModelResolverFilter::compatible(const AiCommon::ModelTarget& target) const {
  return target.api_protocol == envoy::type::ai::v3::API_PROTOCOL_UNSPECIFIED ||
         config_->clientApiProtocol() == envoy::type::ai::v3::API_PROTOCOL_UNSPECIFIED ||
         target.api_protocol == config_->clientApiProtocol();
}

void ModelResolverFilter::setRetryHeaders(Envoy::Http::RequestHeaderMap& headers,
                                          const ModelRoutingPolicy& policy,
                                          size_t plan_size) const {
  const auto& header_names = Envoy::Http::Headers::get();
  // Attempts share one request header map, so overlapping hedged attempts would overwrite each
  // other's target and credential.
  headers.setCopy(header_names.EnvoyHedgeOnPerTryTimeout, "false");
  if (policy.has_per_try_timeout() && config_->maxPerTryTimeout().has_value()) {
    if (auto timeout = DurationUtil::durationToMillisecondsNoThrow(policy.per_try_timeout());
        timeout.ok() && timeout.value() > 0) {
      const uint64_t capped =
          std::min<uint64_t>(timeout.value(), config_->maxPerTryTimeout()->count());
      headers.setCopy(header_names.EnvoyUpstreamRequestPerTryTimeoutMs, std::to_string(capped));
    }
  }
  // Also set for a single target, since a route retry would find no candidate left.
  headers.setCopy(header_names.EnvoyMaxRetries,
                  std::to_string(std::min<uint64_t>(plan_size - 1, config_->maxRetries())));
  if (plan_size < 2) {
    return;
  }

  std::vector<absl::string_view> retry_on;
  std::vector<absl::string_view> status_codes;
  if (policy.fallback_on().empty()) {
    for (const auto condition : config_->defaultFallbackOn()) {
      addRetryCondition(condition, retry_on, status_codes);
    }
  } else {
    for (const int condition : policy.fallback_on()) {
      addRetryCondition(static_cast<ModelRoutingPolicy::FallbackCondition>(condition), retry_on,
                        status_codes);
    }
  }
  if (retry_on.empty()) {
    return;
  }
  headers.setCopy(header_names.EnvoyRetryOn, absl::StrJoin(retry_on, ","));
  if (!status_codes.empty()) {
    headers.setCopy(header_names.EnvoyRetriableStatusCodes, absl::StrJoin(status_codes, ","));
  }
}

void ModelResolverFilter::prewarm(const AiCommon::ModelRoutePlan& plan) const {
  const DfpCommon::DnsCacheSharedPtr& cache = config_->dnsCache();
  if (cache == nullptr || config_->prewarmFallbackTargets() == 0) {
    return;
  }
  const auto& candidates = plan.candidates();
  const size_t end = std::min<size_t>(candidates.size(),
                                      1 + static_cast<size_t>(config_->prewarmFallbackTargets()));
  for (size_t i = 1; i < end; ++i) {
    // Only an admission check: the lookup keeps running after the handle below is dropped.
    if (cache->canCreateDnsRequest() == nullptr) {
      config_->stats().prewarm_overflow_.inc();
      return;
    }
    const uint16_t port = candidates[i].port != 0 ? candidates[i].port : PrewarmDefaultPort;
    const auto result =
        cache->loadDnsCacheEntry(candidates[i].host, port,
                                 /*is_proxy_lookup=*/false, noopLoadDnsCacheEntryCallbacks());
    if (result.status_ == DfpCommon::DnsCache::LoadDnsCacheEntryStatus::Loading) {
      config_->stats().prewarm_started_.inc();
    }
  }
}

} // namespace ModelResolver
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
