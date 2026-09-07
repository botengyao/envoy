#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "source/common/json/wuffs_json/wuffs_json_cursor.h"
#include "source/extensions/filters/http/ai_protocol_manager/request_info.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Selectively extracts bounded request metadata from a JSON body as it arrives.
// It intentionally does not construct a DOM: only the top-level model string is
// captured, up to MaxModelBytes, while all prompt-bearing strings are discarded
// by Wuffs without being copied.
class RequestInfoExtractor : private Json::Wuffs::WuffsJsonCursor::Handler {
public:
  static constexpr size_t MaxModelBytes = 256;

  RequestInfoExtractor();

  // Feeds the next contiguous request-body region. `closed` means that no more
  // body bytes follow. JSON syntax errors, duplicate keys, excessive nesting,
  // and a closed-but-incomplete document are returned to the caller. Errors are
  // terminal and sticky.
  absl::Status feed(absl::string_view chunk, bool closed);

  // True as soon as the root JSON value is complete, independently of whether
  // the HTTP body has reached end-of-stream.
  bool rootClosed() const { return root_closed_; }

  // Conservative body-only protocol evidence. Conflicting markers return
  // Unspecified rather than choosing one dialect.
  ApiProtocol bodyDetectedProtocol() const;

  // Materializes provider-specific aliases only after the caller has resolved
  // the protocol. This makes precedence independent of JSON member order and
  // prevents a field belonging to another dialect from winning accidentally.
  RequestInfo finalizeForProtocol(ApiProtocol protocol) const;

private:
  enum class CountedArray { None, Messages, Input, Contents, Tools };

  // Json::Wuffs::WuffsJsonCursor::Handler
  bool openStringCapture(absl::string_view key, int depth, size_t token_start) override;
  bool onStringChunk(absl::string_view key, int depth, absl::string_view chunk) override;
  void closeStringCapture(absl::string_view key, int depth, size_t token_end) override;
  absl::Status onKey(absl::string_view key, int depth, size_t token_start) override;
  absl::Status onNumber(absl::string_view key, absl::string_view raw, int depth, size_t token_start,
                        size_t token_end) override;
  absl::Status onBoolean(absl::string_view key, bool value, int depth, size_t token_start,
                         size_t token_end) override;
  void onNull(absl::string_view key, int depth, size_t token_start, size_t token_end) override;
  void onContainerOpen(absl::string_view key, bool is_dict, int depth, size_t token_start) override;
  void onContainerClose(int depth, size_t token_end) override;

  void beginCountedArray(absl::string_view key);
  void completeCountedArray();
  void countArrayScalar(int depth, absl::string_view key);
  void incrementActiveArray();

  void recordTopLevelLimit(absl::string_view key, uint64_t value);
  void recordGeminiLimit(absl::string_view key, uint64_t value);

  RequestInfo request_info_;
  Json::Wuffs::WuffsJsonCursor cursor_;
  absl::Status status_;

  bool root_closed_{false};
  bool input_closed_{false};
  bool capturing_model_{false};
  bool observing_anthropic_marker_{false};
  bool model_over_limit_{false};
  std::string pending_model_;

  CountedArray active_array_{CountedArray::None};
  uint32_t active_array_count_{0};
  std::optional<uint32_t> messages_count_;
  std::optional<uint32_t> input_count_;
  std::optional<uint32_t> contents_count_;
  std::optional<uint32_t> tools_count_;

  bool in_generation_config_{false};
  std::optional<uint64_t> max_completion_tokens_;
  std::optional<uint64_t> top_level_max_output_tokens_;
  std::optional<uint64_t> max_tokens_;
  std::optional<uint64_t> gemini_max_output_tokens_camel_;
  std::optional<uint64_t> gemini_max_output_tokens_snake_;

  bool saw_anthropic_marker_{false};
  bool saw_gemini_marker_{false};
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
