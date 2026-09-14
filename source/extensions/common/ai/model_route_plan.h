#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "envoy/http/header_map.h"
#include "envoy/stream_info/filter_state.h"

#include "source/extensions/common/dynamic_forward_proxy/dynamic_host_candidates.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Ai {

struct ModelTarget {
  std::string id;
  std::string host;
  // Zero selects the cluster default port and leaves the port out of the authority.
  uint16_t port{};
  std::string model;
  // Empty keeps the request path. "{model}" is replaced with the model.
  std::string path;
};

/**
 * Ordered model targets for one request. It is also the dynamic forward proxy host candidate list
 * of the request, so each upstream attempt connects to the host of the target it uses.
 */
class ModelRoutePlan : public DynamicForwardProxy::DynamicHostCandidates {
public:
  static const std::string& key();

  ModelRoutePlan(std::vector<ModelTarget> targets, std::string decision_id);

  const ModelTarget& target(uint32_t index) const { return targets_[index]; }
  const std::vector<ModelTarget>& targets() const { return targets_; }
  const std::optional<std::string>& canonicalPath() const { return canonical_path_; }
  const std::string& decisionId() const { return decision_id_; }

  /**
   * Sets the request path and authority for the target at the index. The first call records the
   * request path, after any route rewrite, as the canonical path. The result then only depends on
   * the canonical request and the target, so it is safe on a header map earlier attempts modified.
   */
  void applyToHeaders(uint32_t index, Http::RequestHeaderMap& headers);

  // StreamInfo::FilterState::Object
  std::optional<std::string> serializeAsString() const override;
  FieldType getField(absl::string_view field_name) const override;

private:
  const std::vector<ModelTarget> targets_;
  const std::string decision_id_;
  std::optional<std::string> canonical_path_;
};

/**
 * The target one upstream attempt used, recorded on the attempt's StreamInfo for upstream logs.
 */
class ModelAttempt : public StreamInfo::FilterState::Object {
public:
  static const std::string& key();

  ModelAttempt(uint32_t attempt, const ModelTarget& target)
      : attempt_(attempt), target_id_(target.id), model_(target.model), host_(target.host) {}

  // StreamInfo::FilterState::Object
  std::optional<std::string> serializeAsString() const override { return target_id_; }
  bool hasFieldSupport() const override { return true; }
  FieldType getField(absl::string_view field_name) const override;

private:
  const uint32_t attempt_;
  const std::string target_id_;
  const std::string model_;
  const std::string host_;
};

} // namespace Ai
} // namespace Common
} // namespace Extensions
} // namespace Envoy
