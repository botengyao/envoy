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
toCandidates(const std::vector<ModelTarget>& targets) {
  std::vector<DynamicForwardProxy::DynamicHostCandidates::Candidate> candidates;
  candidates.reserve(targets.size());
  for (const ModelTarget& target : targets) {
    candidates.push_back({target.host, target.port});
  }
  return candidates;
}

} // namespace

const std::string& ModelRoutePlan::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.ai.model_route_plan");
}

ModelRoutePlan::ModelRoutePlan(std::vector<ModelTarget> targets, std::string decision_id)
    : DynamicHostCandidates(toCandidates(targets)), targets_(std::move(targets)),
      decision_id_(std::move(decision_id)) {}

void ModelRoutePlan::applyToHeaders(uint32_t index, Http::RequestHeaderMap& headers) {
  if (!canonical_path_.has_value()) {
    canonical_path_ = std::string(headers.getPathValue());
  }
  const ModelTarget& selected = target(index);
  headers.setPath(absl::StrReplaceAll(selected.path.empty() ? *canonical_path_ : selected.path,
                                      {{"{model}", selected.model}}));
  headers.setHost(selected.port == 0 ? selected.host
                                     : absl::StrCat(selected.host, ":", selected.port));
}

std::optional<std::string> ModelRoutePlan::serializeAsString() const {
  return absl::StrJoin(targets_, ",", [](std::string* out, const ModelTarget& target) {
    absl::StrAppend(out, target.id);
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
