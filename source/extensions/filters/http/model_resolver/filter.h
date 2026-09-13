#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "envoy/data/ai/v3/model_routing_policy.pb.h"
#include "envoy/extensions/filters/http/model_resolver/v3/model_resolver.pb.h"
#include "envoy/server/factory_context.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/extensions/common/ai/model_route_plan.h"
#include "source/extensions/common/dynamic_forward_proxy/dns_cache.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelResolver {

namespace AiCommon = Envoy::Extensions::Common::Ai;
namespace DfpCommon = Envoy::Extensions::Common::DynamicForwardProxy;

#define ALL_MODEL_RESOLVER_STATS(COUNTER)                                                          \
  COUNTER(plan_created)                                                                            \
  COUNTER(no_policy)                                                                               \
  COUNTER(invalid_policy)                                                                          \
  COUNTER(unknown_target)                                                                          \
  COUNTER(incompatible_target)                                                                     \
  COUNTER(unsupported_body)                                                                        \
  COUNTER(prewarm_started)                                                                         \
  COUNTER(prewarm_overflow)

struct ModelResolverStats {
  ALL_MODEL_RESOLVER_STATS(GENERATE_COUNTER_STRUCT)
};

using ModelResolverProto = envoy::extensions::filters::http::model_resolver::v3::ModelResolver;
using ModelRoutingPolicy = envoy::data::ai::v3::ModelRoutingPolicy;

class FilterConfig;
using FilterConfigConstSharedPtr = std::shared_ptr<const FilterConfig>;

class FilterConfig {
public:
  static absl::StatusOr<FilterConfigConstSharedPtr>
  create(const ModelResolverProto& proto, const std::string& stats_prefix, Stats::Scope& scope,
         Server::Configuration::ServerFactoryContext& context, Init::Manager& init_manager,
         DfpCommon::DnsCacheManagerFactory& dns_cache_manager_factory);

  const std::string& policyNamespace() const { return policy_namespace_; }
  const AiCommon::ModelTargetRegistrySharedPtr& registry() const { return registry_; }
  envoy::type::ai::v3::ApiProtocol clientApiProtocol() const { return client_api_protocol_; }
  uint32_t maxRetries() const { return max_retries_; }
  const std::vector<ModelRoutingPolicy::FallbackCondition>& defaultFallbackOn() const {
    return default_fallback_on_;
  }
  std::optional<std::chrono::milliseconds> maxPerTryTimeout() const { return max_per_try_timeout_; }
  bool continueWithoutPolicy() const { return continue_without_policy_; }
  const DfpCommon::DnsCacheSharedPtr& dnsCache() const { return dns_cache_; }
  uint32_t prewarmFallbackTargets() const { return prewarm_fallback_targets_; }
  ModelResolverStats& stats() const { return stats_; }

private:
  FilterConfig(const ModelResolverProto& proto, const std::string& stats_prefix,
               Stats::Scope& scope);

  const std::string policy_namespace_;
  AiCommon::ModelTargetRegistrySharedPtr registry_;
  const envoy::type::ai::v3::ApiProtocol client_api_protocol_;
  const uint32_t max_retries_;
  std::vector<ModelRoutingPolicy::FallbackCondition> default_fallback_on_;
  std::optional<std::chrono::milliseconds> max_per_try_timeout_;
  const bool continue_without_policy_;
  DfpCommon::DnsCacheManagerSharedPtr dns_cache_manager_;
  DfpCommon::DnsCacheSharedPtr dns_cache_;
  const uint32_t prewarm_fallback_targets_;
  mutable ModelResolverStats stats_;
};

/**
 * Turns the ordered model routing policy of a request into a ModelRoutePlan. The plan is the
 * dynamic forward proxy host candidate list of the request and the source of per-attempt request
 * rewrites, and the filter enables router retries so each fallback target gets an attempt.
 */
class ModelResolverFilter : public Envoy::Http::PassThroughDecoderFilter,
                            public Logger::Loggable<Logger::Id::filter> {
public:
  explicit ModelResolverFilter(FilterConfigConstSharedPtr config) : config_(std::move(config)) {}

  // Http::StreamDecoderFilter
  Envoy::Http::FilterHeadersStatus decodeHeaders(Envoy::Http::RequestHeaderMap& headers,
                                                 bool end_stream) override;

private:
  enum class PolicyStatus { Missing, Invalid, Ok };

  PolicyStatus readPolicy(ModelRoutingPolicy& policy) const;
  Envoy::Http::FilterHeadersStatus onUnusablePolicy(Stats::Counter& counter,
                                                    absl::string_view details);
  bool compatible(const AiCommon::ModelTarget& target) const;
  void setRetryHeaders(Envoy::Http::RequestHeaderMap& headers, const ModelRoutingPolicy& policy,
                       size_t plan_size) const;
  void prewarm(const AiCommon::ModelRoutePlan& plan) const;

  const FilterConfigConstSharedPtr config_;
};

} // namespace ModelResolver
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
