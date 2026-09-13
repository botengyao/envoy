#include "source/extensions/common/dynamic_forward_proxy/dynamic_host_candidates.h"

#include <algorithm>

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

bool DynamicHostCandidates::validHost(absl::string_view host) {
  const auto authority = Http::Utility::parseAuthority(host);
  if (authority.host_.empty() || authority.port_.has_value()) {
    return false;
  }
  return !absl::StrContains(host, ':') || (authority.is_ip_address_ && host.front() == '[');
}

std::unique_ptr<DynamicHostCandidates> DynamicHostCandidates::fromString(absl::string_view value) {
  std::vector<Candidate> candidates;
  for (absl::string_view entry : absl::StrSplit(value, ',')) {
    entry = absl::StripAsciiWhitespace(entry);
    if (entry.empty()) {
      return nullptr;
    }
    const auto authority = Http::Utility::parseAuthority(entry);
    if (authority.port_.has_value() && authority.port_.value() == 0) {
      return nullptr;
    }
    // parseAuthority() strips IPv6 brackets, which the DFP host key keeps.
    std::string host = authority.is_ip_address_ && absl::StrContains(authority.host_, ':')
                           ? absl::StrCat("[", authority.host_, "]")
                           : std::string(authority.host_);
    if (!validHost(host) || (host.front() == '[' && entry.front() != '[')) {
      return nullptr;
    }
    candidates.push_back({std::move(host), authority.port_.value_or(0)});
  }
  return std::make_unique<DynamicHostCandidates>(std::move(candidates));
}

std::optional<uint32_t> DynamicHostCandidates::selectForAttempt(uint32_t attempt) {
  attempt = std::max<uint32_t>(attempt, 1);
  if (const auto it = selections_.find(attempt); it != selections_.end()) {
    return it->second;
  }
  std::optional<uint32_t> next;
  if (!exhausted_) {
    next = nextUsable(last_index_.has_value() ? last_index_.value() + 1 : 0);
  }
  recordSelection(attempt, next);
  return next;
}

std::optional<uint32_t> DynamicHostCandidates::skipForAttempt(uint32_t attempt) {
  const auto it = selections_.find(attempt);
  if (it == selections_.end() || !it->second.has_value()) {
    return std::nullopt;
  }
  const uint32_t current = it->second.value();
  unusable_hosts_.insert(candidateKey(candidates_[current]));
  // A concurrent later attempt may already hold a later candidate.
  const std::optional<uint32_t> next =
      nextUsable(std::max(current, last_index_.value_or(current)) + 1);
  recordSelection(attempt, next);
  return next;
}

std::optional<uint32_t> DynamicHostCandidates::selectionForAttempt(uint32_t attempt) const {
  const auto it = selections_.find(attempt);
  return it == selections_.end() ? std::nullopt : it->second;
}

std::optional<uint32_t> DynamicHostCandidates::latestSelection() const {
  return selectionForAttempt(latest_attempt_);
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

void DynamicHostCandidates::recordSelection(uint32_t attempt, std::optional<uint32_t> index) {
  selections_[attempt] = index;
  if (index.has_value()) {
    last_index_ = std::max(index.value(), last_index_.value_or(index.value()));
  } else {
    exhausted_ = true;
  }
  if (attempt >= latest_attempt_) {
    latest_attempt_ = attempt;
    selected_ = index.has_value() ? candidateKey(candidates_[index.value()]) : "";
  }
}

} // namespace DynamicForwardProxy
} // namespace Common
} // namespace Extensions
} // namespace Envoy
