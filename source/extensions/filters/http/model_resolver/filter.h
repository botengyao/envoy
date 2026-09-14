#pragma once

#include <memory>
#include <string>
#include <vector>

#include "envoy/data/ai/v3/model_routing_policy.pb.h"
#include "envoy/extensions/filters/http/model_resolver/v3/model_resolver.pb.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/extensions/common/ai/model_route_plan.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModelResolver {

namespace AiCommon = Envoy::Extensions::Common::Ai;

#define ALL_MODEL_RESOLVER_STATS(COUNTER)                                                          \
  COUNTER(plan_created)                                                                            \
  COUNTER(no_policy)                                                                               \
  COUNTER(invalid_policy)                                                                          \
  COUNTER(unsupported_body)                                                                        \
  COUNTER(request_models_unmatched)

struct ModelResolverStats {
  ALL_MODEL_RESOLVER_STATS(GENERATE_COUNTER_STRUCT)
};

using ModelResolverProto = envoy::extensions::filters::http::model_resolver::v3::ModelResolver;
using ModelRoutingPolicy = envoy::data::ai::v3::ModelRoutingPolicy;

class FilterConfig {
public:
  FilterConfig(const ModelResolverProto& proto, const std::string& stats_prefix,
               Stats::Scope& scope);

  const std::string& policyNamespace() const { return policy_namespace_; }
  bool continueWithoutPolicy() const { return continue_without_policy_; }
  bool preferRequestModels() const { return prefer_request_models_; }
  ModelResolverStats& stats() const { return stats_; }

private:
  const std::string policy_namespace_;
  const bool continue_without_policy_;
  const bool prefer_request_models_;
  mutable ModelResolverStats stats_;
};

using FilterConfigConstSharedPtr = std::shared_ptr<const FilterConfig>;

/**
 * Turns the ordered model routing policy of a request into a ModelRoutePlan. The plan is the
 * dynamic forward proxy host candidate list of the request and the source of per-attempt request
 * rewrites, and the filter enables router retries so each target gets an attempt.
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
  std::vector<AiCommon::ModelTarget>
  orderByRequestModels(std::vector<AiCommon::ModelTarget> targets) const;

  const FilterConfigConstSharedPtr config_;
};

} // namespace ModelResolver
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
