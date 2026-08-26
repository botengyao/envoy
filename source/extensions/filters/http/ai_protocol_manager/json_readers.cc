#include "source/extensions/filters/http/ai_protocol_manager/json_readers.h"

#include <algorithm>
#include <cmath>
#include <limits>

#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"

#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

std::optional<uint64_t> readCount(const nlohmann::json& json, const std::string& key,
                                  bool& malformed) {
  const auto it = json.find(key);
  if (it == json.end()) {
    return std::nullopt;
  }
  const nlohmann::json& value = *it;
  // JsonWithExtBufParser stores any literal that fits int64 as a *signed*
  // integer (is_number_unsigned() is true only above INT64_MAX), so probe the
  // signed representation first.
  if (value.is_number_integer()) {
    if (value.is_number_unsigned()) {
      const uint64_t count = value.get<uint64_t>();
      if (count > MaxSafeCount) {
        malformed = true;
        return std::nullopt;
      }
      return count;
    }
    const int64_t count = value.get<int64_t>();
    if (count < 0 || static_cast<uint64_t>(count) > MaxSafeCount) {
      malformed = true;
      return std::nullopt;
    }
    return static_cast<uint64_t>(count);
  }
  if (value.is_number_float()) {
    const double as_double = value.get<double>();
    // Range-check before the float-to-integer cast: converting an
    // out-of-range double to uint64_t is undefined behavior.
    if (!std::isfinite(as_double) || as_double < 0 ||
        as_double > static_cast<double>(MaxSafeCount) || std::trunc(as_double) != as_double) {
      malformed = true;
      return std::nullopt;
    }
    return static_cast<uint64_t>(as_double);
  }
  malformed = true; // Present with a non-numeric value (string, bool, null, container).
  return std::nullopt;
}

std::optional<std::string> readString(const nlohmann::json& json, const std::string& key) {
  const auto it = json.find(key);
  if (it == json.end() || !it->is_string()) {
    return std::nullopt;
  }
  const auto& value = it->get_ref<const std::string&>();
  if (value.empty() || value.size() > MaxStringValueSize) {
    return std::nullopt;
  }
  return value;
}

const nlohmann::json* readObject(const nlohmann::json& json, const std::string& key,
                                 bool& malformed, NullPolicy null_policy) {
  const auto it = json.find(key);
  if (it == json.end()) {
    return nullptr;
  }
  if (it->is_object()) {
    return &*it;
  }
  if (!it->is_null() || null_policy == NullPolicy::NullIsMalformed) {
    malformed = true;
  }
  return nullptr;
}

std::optional<uint64_t> addCounts(std::optional<uint64_t> base,
                                  const std::optional<uint64_t>& extra, bool& overflow) {
  if (!base.has_value() || !extra.has_value()) {
    return base;
  }
  const uint64_t sum = base.value() + extra.value();
  if (sum > MaxSafeCount) {
    overflow = true;
    return std::nullopt;
  }
  return sum;
}

std::optional<uint64_t> readRequestCount(const nlohmann::json& json, const std::string& key) {
  bool ignored = false;
  return readCount(json, key, ignored);
}

bool readFlag(const nlohmann::json& json, const std::string& key) {
  const auto it = json.find(key);
  return it != json.end() && it->is_boolean() && it->get<bool>();
}

std::optional<uint32_t> countArray(const nlohmann::json& json, const std::string& key) {
  const auto it = json.find(key);
  if (it == json.end() || !it->is_array()) {
    return std::nullopt;
  }
  return static_cast<uint32_t>(std::min<size_t>(it->size(), std::numeric_limits<uint32_t>::max()));
}

uint64_t measureTextBytes(const nlohmann::json& node, int depth) {
  if (depth > MaxTextWalkDepth) {
    return 0;
  }
  if (node.is_string()) {
    return node.get_ref<const std::string&>().size();
  }
  // An offloaded string is not in the DOM: it rides as a reference carrying
  // the length of its raw (still-escaped) bytes in the request body. Counting
  // that length is what lets the estimate cover a multi-megabyte prompt
  // without reading a byte of it.
  if (JsonWithExtBuf::isExternalRef(node)) {
    const absl::StatusOr<JsonWithExtBuf::ExternalRef> ref = JsonWithExtBuf::externalRef(node);
    return ref.ok() ? ref->length : 0;
  }
  // Only containers are descended into: nlohmann gives a primitive a
  // single-element iteration range containing itself, so iterating one would
  // recurse to the depth cap for nothing.
  if (!node.is_array() && !node.is_object()) {
    return 0;
  }
  uint64_t bytes = 0;
  for (const auto& child : node) {
    const uint64_t child_bytes = measureTextBytes(child, depth + 1);
    // The sum runs over an attacker-influenced number of terms; saturate
    // rather than wrap, at the same bound the token counts use.
    if (bytes > MaxSafeCount - child_bytes) {
      return MaxSafeCount;
    }
    bytes += child_bytes;
  }
  return bytes;
}

uint64_t estimateInputTokens(uint64_t text_bytes, uint32_t message_count) {
  // Round up: a payload with any text at all costs at least one token.
  const uint64_t from_text = text_bytes == 0 ? 0 : (text_bytes - 1) / BytesPerTokenEstimate + 1;
  const uint64_t framing = uint64_t{message_count} * MessageFramingTokens;
  if (from_text > MaxSafeCount - framing) {
    return MaxSafeCount;
  }
  return from_text + framing;
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
