#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "envoy/stream_info/filter_state.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace DynamicForwardProxy {

/**
 * Request-scoped ordered list of hosts for the dynamic forward proxy cluster. Each HTTP router
 * attempt that reaches the cluster uses the next usable candidate, so a router retry reaches the
 * next host in the list.
 */
class DynamicHostCandidates : public StreamInfo::FilterState::Object {
public:
  struct Candidate {
    std::string host;
    // Zero selects the cluster default port.
    uint16_t port{};
  };

  static const std::string& key();

  explicit DynamicHostCandidates(std::vector<Candidate> candidates);

  /**
   * Parses a comma separated "host[:port]" list. IPv6 addresses must be bracketed.
   * @return nullptr if the list is empty or an entry is malformed.
   */
  static std::unique_ptr<DynamicHostCandidates> fromString(absl::string_view value);

  /**
   * @return whether the value is a DNS name, an IPv4 address or a bracketed IPv6 address, with no
   * port.
   */
  static bool validHost(absl::string_view host);

  /**
   * @param attempt the 1-based upstream attempt.
   * @return the candidate index used by the attempt. The first call for an attempt takes the next
   * usable candidate after the most recently selected one; std::nullopt when none is left.
   */
  std::optional<uint32_t> selectForAttempt(uint32_t attempt);

  /**
   * Marks the host of the attempt's candidate as unusable for the rest of the request and moves the
   * attempt to the next usable candidate.
   * @return the new candidate index, or std::nullopt when none is left.
   */
  std::optional<uint32_t> skipForAttempt(uint32_t attempt);

  /**
   * @return the candidate index already selected for the attempt, if any.
   */
  std::optional<uint32_t> selectionForAttempt(uint32_t attempt) const;

  /**
   * @return the candidate index of the most recent attempt, if it has one.
   */
  std::optional<uint32_t> latestSelection() const;

  const std::vector<Candidate>& candidates() const { return candidates_; }

  // StreamInfo::FilterState::Object
  std::optional<std::string> serializeAsString() const override;
  bool hasFieldSupport() const override { return true; }
  FieldType getField(absl::string_view field_name) const override;

private:
  std::optional<uint32_t> nextUsable(uint32_t from) const;
  void recordSelection(uint32_t attempt, std::optional<uint32_t> index);

  const std::vector<Candidate> candidates_;
  absl::flat_hash_set<std::string> unusable_hosts_;
  // Attempts that never reached the cluster have no entry, so they do not consume a candidate.
  absl::flat_hash_map<uint32_t, std::optional<uint32_t>> selections_;
  std::optional<uint32_t> last_index_;
  uint32_t latest_attempt_{0};
  bool exhausted_{false};
  std::string selected_;
};

} // namespace DynamicForwardProxy
} // namespace Common
} // namespace Extensions
} // namespace Envoy
