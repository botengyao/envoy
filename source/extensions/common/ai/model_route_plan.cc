#include "source/extensions/common/ai/model_route_plan.h"

#include "source/common/common/macros.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Ai {

namespace {

std::vector<DynamicForwardProxy::DynamicHostCandidates::Candidate>
toCandidates(const std::vector<const ModelTarget*>& targets) {
  std::vector<DynamicForwardProxy::DynamicHostCandidates::Candidate> candidates;
  candidates.reserve(targets.size());
  for (const ModelTarget* target : targets) {
    candidates.push_back({target->host, target->port});
  }
  return candidates;
}

} // namespace

ModelTargetRegistry::ModelTargetRegistry(std::vector<ModelTarget> targets) {
  for (ModelTarget& target : targets) {
    if (target.credential_header.has_value() &&
        std::find(credential_headers_.begin(), credential_headers_.end(),
                  target.credential_header.value()) == credential_headers_.end()) {
      credential_headers_.push_back(target.credential_header.value());
    }
    std::string id = target.id;
    targets_.emplace(std::move(id), std::move(target));
  }
}

const ModelTarget* ModelTargetRegistry::find(absl::string_view id) const {
  const auto it = targets_.find(id);
  return it == targets_.end() ? nullptr : &it->second;
}

const std::string& ModelRoutePlan::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.ai.model_route_plan");
}

ModelRoutePlan::ModelRoutePlan(ModelTargetRegistrySharedPtr registry,
                               std::vector<const ModelTarget*> targets, std::string decision_id)
    : DynamicHostCandidates(toCandidates(targets)), registry_(std::move(registry)),
      targets_(std::move(targets)), decision_id_(std::move(decision_id)) {}

void ModelRoutePlan::removeCredentials(Http::RequestHeaderMap& headers) const {
  for (const Http::LowerCaseString& header : registry_->credentialHeaders()) {
    headers.remove(header);
  }
}

void ModelRoutePlan::applyToHeaders(uint32_t index, Http::RequestHeaderMap& headers) {
  if (!canonical_path_.has_value()) {
    canonical_path_ = std::string(headers.getPathValue());
  }
  const ModelTarget& selected = target(index);
  removeCredentials(headers);
  headers.setPath(absl::StrReplaceAll(selected.path.empty() ? *canonical_path_ : selected.path,
                                      {{"{model}", selected.model}}));
  headers.setHost(selected.port == 0 ? selected.host
                                     : absl::StrCat(selected.host, ":", selected.port));
  if (!selected.credential_header.has_value() || selected.credential == nullptr) {
    return;
  }
  absl::string_view credential = selected.credential->credential();
  // Secret files commonly end with a newline, which is not valid in a header value.
  while (!credential.empty() && (credential.back() == '\n' || credential.back() == '\r')) {
    credential.remove_suffix(1);
  }
  if (!credential.empty()) {
    headers.setCopy(selected.credential_header.value(),
                    absl::StrCat(selected.credential_prefix, credential));
  }
}

std::optional<std::string> ModelRoutePlan::serializeAsString() const {
  return absl::StrJoin(targets_, ",", [](std::string* out, const ModelTarget* target) {
    absl::StrAppend(out, target->id);
  });
}

StreamInfo::FilterState::Object::FieldType
ModelRoutePlan::getField(absl::string_view field_name) const {
  if (field_name == "decision_id") {
    return absl::string_view(decision_id_);
  }
  if (field_name == "selected_target" || field_name == "selected_model") {
    const std::optional<uint32_t> index = latestSelection();
    if (!index.has_value()) {
      return absl::monostate{};
    }
    const ModelTarget& selected = target(index.value());
    return absl::string_view(field_name == "selected_target" ? selected.id : selected.model);
  }
  return DynamicHostCandidates::getField(field_name);
}

const std::string& ModelAttempt::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.ai.model_attempt");
}

StreamInfo::FilterState::Object::FieldType
ModelAttempt::getField(absl::string_view field_name) const {
  if (field_name == "target_id") {
    return absl::string_view(target_id_);
  }
  if (field_name == "model") {
    return absl::string_view(model_);
  }
  if (field_name == "host") {
    return absl::string_view(host_);
  }
  if (field_name == "attempt") {
    return static_cast<int64_t>(attempt_);
  }
  return absl::monostate{};
}

} // namespace Ai
} // namespace Common
} // namespace Extensions
} // namespace Envoy
