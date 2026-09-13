#include "source/extensions/common/dynamic_forward_proxy/dynamic_host_candidates.h"

#include "source/common/common/macros.h"
#include "source/common/http/utility.h"

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/strings/strip.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace DynamicForwardProxy {

namespace {

std::string candidateKey(const DynamicHostCandidates::Candidate& candidate) {
  return candidate.port == 0 ? candidate.host : absl::StrCat(candidate.host, ":", candidate.port);
}

} // namespace

const std::string& DynamicHostCandidates::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "envoy.upstream.dynamic_host_candidates");
}

DynamicHostCandidates::DynamicHostCandidates(std::vector<Candidate> candidates)
    : candidates_(std::move(candidates)) {}

std::unique_ptr<DynamicHostCandidates> DynamicHostCandidates::fromString(absl::string_view value) {
  std::vector<Candidate> candidates;
  for (absl::string_view entry : absl::StrSplit(value, ',')) {
    entry = absl::StripAsciiWhitespace(entry);
    if (entry.empty()) {
      return nullptr;
    }
    const auto authority = Http::Utility::parseAuthority(entry);
    if (authority.host_.empty() || (authority.port_.has_value() && authority.port_.value() == 0)) {
      return nullptr;
    }
    std::string host(authority.host_);
    // parseAuthority() strips IPv6 brackets, which the DFP host key keeps.
    if (authority.is_ip_address_ && absl::StrContains(host, ':')) {
      host = absl::StrCat("[", host, "]");
    }
    candidates.push_back({std::move(host), authority.port_.value_or(0)});
  }
  return std::make_unique<DynamicHostCandidates>(std::move(candidates));
}

std::optional<uint32_t> DynamicHostCandidates::selectForAttempt(uint32_t attempt) {
  attempt = std::max<uint32_t>(attempt, 1);
  while (selections_.size() < attempt) {
    std::optional<uint32_t> next;
    if (selections_.empty()) {
      next = nextUsable(0);
    } else if (selections_.back().has_value()) {
      next = nextUsable(selections_.back().value() + 1);
    }
    selections_.push_back(next);
    updateSelected(next);
  }
  return selections_[attempt - 1];
}

std::optional<uint32_t> DynamicHostCandidates::skipForAttempt(uint32_t attempt) {
  if (attempt == 0 || attempt > selections_.size() || !selections_[attempt - 1].has_value()) {
    return std::nullopt;
  }
  std::optional<uint32_t>& selection = selections_[attempt - 1];
  unusable_hosts_.insert(candidateKey(candidates_[selection.value()]));
  selection = nextUsable(selection.value() + 1);
  updateSelected(selection);
  return selection;
}

std::optional<uint32_t> DynamicHostCandidates::selectionForAttempt(uint32_t attempt) const {
  if (attempt == 0 || attempt > selections_.size()) {
    return std::nullopt;
  }
  return selections_[attempt - 1];
}

std::optional<uint32_t> DynamicHostCandidates::latestSelection() const {
  return selections_.empty() ? std::nullopt : selections_.back();
}

std::optional<std::string> DynamicHostCandidates::serializeAsString() const {
  return absl::StrJoin(candidates_, ",", [](std::string* out, const Candidate& candidate) {
    absl::StrAppend(out, candidateKey(candidate));
  });
}

StreamInfo::FilterState::Object::FieldType
DynamicHostCandidates::getField(absl::string_view field_name) const {
  if (field_name == "selected") {
    return absl::string_view(selected_);
  }
  if (field_name == "attempts") {
    return static_cast<int64_t>(selections_.size());
  }
  return absl::monostate{};
}

std::optional<uint32_t> DynamicHostCandidates::nextUsable(uint32_t from) const {
  for (uint32_t i = from; i < candidates_.size(); ++i) {
    if (!unusable_hosts_.contains(candidateKey(candidates_[i]))) {
      return i;
    }
  }
  return std::nullopt;
}

void DynamicHostCandidates::updateSelected(std::optional<uint32_t> index) {
  selected_ = index.has_value() ? candidateKey(candidates_[index.value()]) : "";
}

} // namespace DynamicForwardProxy
} // namespace Common
} // namespace Extensions
} // namespace Envoy
