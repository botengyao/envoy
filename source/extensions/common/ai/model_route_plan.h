#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "envoy/common/pure.h"
#include "envoy/http/header_map.h"
#include "envoy/stream_info/filter_state.h"
#include "envoy/type/ai/v3/api_protocol.pb.h"

#include "source/extensions/common/dynamic_forward_proxy/dynamic_host_candidates.h"

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Ai {

class CredentialSource {
public:
  virtual ~CredentialSource() = default;

  /**
   * @return the credential, or an empty value while it is unavailable.
   */
  virtual absl::string_view credential() const PURE;
};

using CredentialSourceSharedPtr = std::shared_ptr<const CredentialSource>;

struct ModelTarget {
  std::string id;
  std::string host;
  // Zero selects the cluster default port and leaves the port out of the authority.
  uint16_t port{};
  std::string model;
  // Empty keeps the client path. "{model}" is replaced with the model.
  std::string path;
  envoy::type::ai::v3::ApiProtocol api_protocol{};
  std::optional<Http::LowerCaseString> credential_header;
  std::string credential_prefix;
  CredentialSourceSharedPtr credential;
};

/**
 * Targets that model routing policies may name. Immutable once built and shared by every plan
 * created from one configuration.
 */
class ModelTargetRegistry {
public:
  explicit ModelTargetRegistry(std::vector<ModelTarget> targets);

  const ModelTarget* find(absl::string_view id) const;

  /**
   * @return the credential headers of all targets. Requests to a target must not carry another
   * target's credential.
   */
  const std::vector<Http::LowerCaseString>& credentialHeaders() const {
    return credential_headers_;
  }

private:
  absl::flat_hash_map<std::string, ModelTarget> targets_;
  std::vector<Http::LowerCaseString> credential_headers_;
};

using ModelTargetRegistrySharedPtr = std::shared_ptr<const ModelTargetRegistry>;

/**
 * Ordered model targets for one request. It is also the dynamic forward proxy host candidate list
 * of the request, so each upstream attempt connects to the host of the target it uses.
 */
class ModelRoutePlan : public DynamicForwardProxy::DynamicHostCandidates {
public:
  static const std::string& key();

  ModelRoutePlan(ModelTargetRegistrySharedPtr registry, std::vector<const ModelTarget*> targets,
                 std::string canonical_path, std::string decision_id);

  const ModelTarget& target(uint32_t index) const { return *targets_[index]; }
  const ModelTargetRegistry& registry() const { return *registry_; }
  const std::string& canonicalPath() const { return canonical_path_; }
  const std::string& decisionId() const { return decision_id_; }

  /**
   * Rewrites the request headers for the target at the index. The result only depends on the
   * canonical request and the target, so it is safe on a header map earlier attempts modified.
   */
  void applyToHeaders(uint32_t index, Http::RequestHeaderMap& headers) const;

  // StreamInfo::FilterState::Object
  std::optional<std::string> serializeAsString() const override;
  FieldType getField(absl::string_view field_name) const override;

private:
  const ModelTargetRegistrySharedPtr registry_;
  const std::vector<const ModelTarget*> targets_;
  const std::string canonical_path_;
  const std::string decision_id_;
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
