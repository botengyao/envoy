#include "source/extensions/filters/http/ai_protocol_manager/flattening_json_codec.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>
#include <utility>

#include "source/common/common/assert.h"
#include "source/common/coroutine/status_macros.h"
#include "source/extensions/filters/http/ai_protocol_manager/replay_awaitable.h"

#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

absl::StatusOr<std::string> dumpJson(const nlohmann::json& node) noexcept {
  TRY_NEEDS_AUDIT { return node.dump(); }
  END_TRY
  CATCH(const nlohmann::json::exception& e, {
    return absl::InvalidArgumentError(absl::StrCat("JSON serialization error: ", e.what()));
  })
  CATCH(const std::exception& e, {
    return absl::InvalidArgumentError(absl::StrCat("JSON serialization error: ", e.what()));
  })
  CATCH(..., { return absl::InvalidArgumentError("unknown error during JSON serialization"); })
  return absl::InternalError("unexpected flow in dumpJson");
}

nlohmann::json emptyContainerFor(const FieldPathSegment& child_segment) {
  return absl::holds_alternative<std::string>(child_segment) ? nlohmann::json::object()
                                                             : nlohmann::json::array();
}

// Adds a null child at `segment`, which must name a new key or the next index of `container`.
absl::StatusOr<nlohmann::json*> appendChild(nlohmann::json& container,
                                            const FieldPathSegment& segment, size_t field_index) {
  if (container.is_object()) {
    if (!absl::holds_alternative<std::string>(segment)) {
      return absl::InvalidArgumentError(
          absl::StrCat("ai json: field ", field_index, " indexes an object as an array"));
    }
    auto [it, inserted] =
        container.get_ref<nlohmann::json::object_t&>().try_emplace(absl::get<std::string>(segment));
    if (!inserted) {
      return absl::InvalidArgumentError(
          absl::StrCat("ai json: field ", field_index, " repeats an object key"));
    }
    return &it->second;
  }
  ASSERT(container.is_array());
  if (!absl::holds_alternative<size_t>(segment)) {
    return absl::InvalidArgumentError(
        absl::StrCat("ai json: field ", field_index, " keys into an array"));
  }
  nlohmann::json::array_t& array = container.get_ref<nlohmann::json::array_t&>();
  if (absl::get<size_t>(segment) != array.size()) {
    return absl::InvalidArgumentError(
        absl::StrCat("ai json: field ", field_index, " skips or revisits an array index"));
  }
  return &array.emplace_back();
}

void flattenInto(const nlohmann::json& node, std::vector<FieldPathSegment>& path,
                 std::vector<FlattenJsonField>& fields) {
  if (node.is_object() && !node.empty()) {
    for (const auto& [key, child] : node.get_ref<const nlohmann::json::object_t&>()) {
      path.emplace_back(key);
      flattenInto(child, path, fields);
      path.pop_back();
    }
    return;
  }
  if (node.is_array() && !node.empty()) {
    size_t index = 0;
    for (const nlohmann::json& child : node.get_ref<const nlohmann::json::array_t&>()) {
      path.emplace_back(index++);
      flattenInto(child, path, fields);
      path.pop_back();
    }
    return;
  }
  fields.emplace_back(path, node);
}

} // namespace

uint64_t FlattenJsonField::byteSize() const {
  uint64_t total = sizeof(FlattenJsonField);
  for (const FieldPathSegment& seg : path_) {
    if (absl::holds_alternative<std::string>(seg)) {
      total += absl::get<std::string>(seg).size();
    }
  }
  if (node_.is_string()) {
    total += node_.get_ref<const std::string&>().size();
  } else if (node_.is_binary()) {
    total += node_.get_binary().size();
  }
  return total;
}

FlatteningJsonDecoder::FlatteningJsonDecoder() : cursor_(*this) {}

absl::Status FlatteningJsonDecoder::feedCursor(absl::string_view data, bool closed) {
  const absl::Status status = cursor_.feed(data, closed);
  if (!status_.ok()) {
    finished_ = true;
    return status_;
  }
  if (!status.ok()) {
    finished_ = true;
    status_ = status;
    return status_;
  }
  return absl::OkStatus();
}

absl::StatusOr<std::vector<FlattenJsonField>>
FlatteningJsonDecoder::onData(const Buffer::Instance& data, bool end_stream) {
  if (!status_.ok()) {
    return status_;
  }
  if (finished_) {
    return absl::FailedPreconditionError("ai json: decoder called after the document completed");
  }

  current_fields_.clear();

  for (const Buffer::RawSlice& slice : data.getRawSlices()) {
    if (slice.len_ == 0) {
      continue;
    }
    const absl::string_view view(static_cast<const char*>(slice.mem_), slice.len_);
    if (absl::Status status = feedCursor(view, /*closed=*/false); !status.ok()) {
      return status;
    }
  }

  if (end_stream) {
    finished_ = true;
    if (absl::Status status = feedCursor("", /*closed=*/true); !status.ok()) {
      return status;
    }
    if (!root_seen_ || !container_stack_.empty() || in_string_) {
      status_ = absl::InvalidArgumentError("ai json: incomplete JSON document");
      return status_;
    }
  }

  return std::move(current_fields_);
}

void FlatteningJsonDecoder::setError(absl::Status status) {
  if (status_.ok()) {
    status_ = std::move(status);
  }
}

void FlatteningJsonDecoder::advanceChildSegment(absl::string_view key) {
  ASSERT(!container_stack_.empty());
  ContainerState& parent = container_stack_.back();
  if (parent.is_dict) {
    parent.segment = std::string(key);
  } else if (parent.has_children) {
    ++absl::get<size_t>(parent.segment);
  } else {
    parent.segment = size_t{0};
  }
  parent.has_children = true;
}

void FlatteningJsonDecoder::emitCurrentPathField(nlohmann::json value, bool is_partial) {
  std::vector<FieldPathSegment> path;
  path.reserve(container_stack_.size());
  for (const ContainerState& entry : container_stack_) {
    path.push_back(entry.segment);
  }
  current_fields_.emplace_back(std::move(path), std::move(value), is_partial);
}

absl::Status FlatteningJsonDecoder::emitLeafValue(absl::string_view key, nlohmann::json value) {
  if (container_stack_.empty()) {
    if (root_seen_) {
      return absl::InvalidArgumentError("ai json: more than one root value");
    }
    root_seen_ = true;
  } else {
    advanceChildSegment(key);
  }
  emitCurrentPathField(std::move(value));
  return absl::OkStatus();
}

bool FlatteningJsonDecoder::openStringCapture(absl::string_view key, int, size_t) {
  if (!status_.ok()) {
    return false;
  }
  if (container_stack_.empty()) {
    if (root_seen_) {
      setError(absl::InvalidArgumentError("ai json: more than one root value"));
      return false;
    }
    root_seen_ = true;
  } else {
    advanceChildSegment(key);
  }
  in_string_ = true;
  return true;
}

bool FlatteningJsonDecoder::onStringChunk(absl::string_view, int, absl::string_view chunk) {
  if (!status_.ok()) {
    return false;
  }
  if (current_fields_.empty() || !current_fields_.back().is_partial()) {
    emitCurrentPathField(nlohmann::json(std::string(chunk)), /*is_partial=*/true);
  } else {
    ASSERT(current_fields_.back().node().is_string());
    current_fields_.back().node().get_ref<std::string&>().append(chunk.data(), chunk.size());
  }
  return true;
}

void FlatteningJsonDecoder::closeStringCapture(absl::string_view, int, size_t) {
  if (!status_.ok()) {
    return;
  }
  if (!current_fields_.empty() && current_fields_.back().is_partial()) {
    current_fields_.back().set_is_partial(false);
  } else {
    emitCurrentPathField(nlohmann::json(""), /*is_partial=*/false);
  }
  in_string_ = false;
}

absl::Status FlatteningJsonDecoder::onKey(absl::string_view, int, size_t) {
  return absl::OkStatus();
}

absl::Status FlatteningJsonDecoder::onNumber(absl::string_view key, absl::string_view raw, int,
                                             size_t, size_t) {
  std::int64_t as_int = 0;
  if (absl::SimpleAtoi(raw, &as_int)) {
    return emitLeafValue(key, nlohmann::json(as_int));
  }
  std::uint64_t as_uint = 0;
  if (absl::SimpleAtoi(raw, &as_uint)) {
    return emitLeafValue(key, nlohmann::json(as_uint));
  }
  double as_double = 0;
  if (!absl::SimpleAtod(raw, &as_double) || !std::isfinite(as_double)) {
    return absl::InvalidArgumentError(
        absl::StrCat("ai json: unrepresentable number \"", raw, "\""));
  }
  return emitLeafValue(key, nlohmann::json(as_double));
}

absl::Status FlatteningJsonDecoder::onBoolean(absl::string_view key, bool value, int, size_t,
                                              size_t) {
  return emitLeafValue(key, nlohmann::json(value));
}

void FlatteningJsonDecoder::onNull(absl::string_view key, int, size_t, size_t) {
  if (!status_.ok()) {
    return;
  }
  setError(emitLeafValue(key, nlohmann::json(nullptr)));
}

void FlatteningJsonDecoder::onContainerOpen(absl::string_view key, bool is_dict, int, size_t) {
  if (!status_.ok()) {
    return;
  }
  if (container_stack_.empty()) {
    if (root_seen_) {
      setError(absl::InvalidArgumentError("ai json: more than one root value"));
      return;
    }
    root_seen_ = true;
  } else {
    advanceChildSegment(key);
  }
  container_stack_.push_back(ContainerState{{}, is_dict, /*has_children=*/false});
}

void FlatteningJsonDecoder::onContainerClose(int, size_t) {
  if (!status_.ok()) {
    return;
  }
  if (container_stack_.empty()) {
    setError(absl::InternalError("ai json: container closed with no container open"));
    return;
  }
  const ContainerState closed = std::move(container_stack_.back());
  container_stack_.pop_back();
  if (!closed.has_children) {
    emitCurrentPathField(closed.is_dict ? nlohmann::json::object() : nlohmann::json::array());
  }
}

FlatteningJsonSerializer::FlatteningJsonSerializer(BufferManager& out) : out_(out) {}

bool FlatteningJsonSerializer::pathMatchesOpenContainers(FieldPath path) const {
  if (path.size() != open_containers_.size()) {
    return false;
  }
  for (size_t i = 0; i < path.size(); ++i) {
    if (open_containers_[i].segment != path[i]) {
      return false;
    }
  }
  return true;
}

Coroutine::Task<absl::Status>
FlatteningJsonSerializer::serializeBatch(absl::Span<const FlattenJsonField> fields) {
  for (const FlattenJsonField& field : fields) {
    CO_RETURN_IF_ERROR(co_await serializeField(field));
  }
  co_return absl::OkStatus();
}

Coroutine::Task<absl::Status>
FlatteningJsonSerializer::serializeField(const FlattenJsonField& field) {
  const FieldPath path = field.field_path();

  // Subsequent chunks of an open partial string sharing the same path are appended directly into
  // the open JSON string literal; the final chunk (`!field.is_partial()`) also emits the closing
  // quote.
  if (string_open_ && field.node().is_string() && pathMatchesOpenContainers(path)) {
    ASSIGN_OR_CO_RETURN(const std::string dumped, dumpJson(field.node()));
    ASSERT(dumped.size() >= 2);
    if (field.is_partial()) {
      small_buf_.add(absl::string_view(dumped).substr(1, dumped.size() - 2));
    } else {
      small_buf_.add(absl::string_view(dumped).substr(1));
      string_open_ = false;
    }
    CO_RETURN_IF_ERROR(co_await maybeFlushBuffer());
    co_return absl::OkStatus();
  }

  if (string_open_) {
    small_buf_.add("\"");
    string_open_ = false;
  }

  if (root_emitted_ && (open_containers_.empty() || path.empty())) {
    co_return absl::InvalidArgumentError("ai json: multiple root values in field stream");
  }

  size_t common = 0;
  const size_t max_common = std::min(open_containers_.size(), path.size());
  while (common < max_common && open_containers_[common].segment == path[common]) {
    ++common;
  }
  if (common == open_containers_.size() && common > 0) {
    --common;
  }

  // Close deeper containers from the previous field path.
  while (open_containers_.size() > common + 1) {
    small_buf_.add(open_containers_.back().is_object ? "}" : "]");
    open_containers_.pop_back();
  }

  // Advance the shared ancestor container at `common`, or open the root container.
  size_t start_open_depth = 0;
  if (!open_containers_.empty()) {
    const bool is_object = absl::holds_alternative<std::string>(path[common]);
    if (open_containers_[common].is_object != is_object) {
      co_return absl::InvalidArgumentError(
          "ai json: conflicting container type at shared field path prefix");
    }
    open_containers_[common].segment = path[common];
    small_buf_.add(",");
    if (is_object) {
      ASSIGN_OR_CO_RETURN(const std::string dumped_key,
                          dumpJson(nlohmann::json(absl::get<std::string>(path[common]))));
      small_buf_.add(dumped_key);
      small_buf_.add(":");
    }
    start_open_depth = common + 1;
  }

  // Open any newly entered containers along `path`.
  for (size_t k = start_open_depth; k < path.size(); ++k) {
    const bool is_object = absl::holds_alternative<std::string>(path[k]);
    open_containers_.push_back(OpenContainer{is_object, path[k]});
    if (is_object) {
      small_buf_.add("{");
      ASSIGN_OR_CO_RETURN(const std::string dumped_key,
                          dumpJson(nlohmann::json(absl::get<std::string>(path[k]))));
      small_buf_.add(dumped_key);
      small_buf_.add(":");
    } else {
      small_buf_.add("[");
    }
  }

  root_emitted_ = true;

  // Emit the leaf value. Partial string chunks omit their closing quote (`string_open_ = true`)
  // so subsequent chunks can be concatenated into the same JSON string literal.
  ASSIGN_OR_CO_RETURN(const std::string dumped, dumpJson(field.node()));
  if (field.node().is_string() && field.is_partial()) {
    ASSERT(dumped.size() >= 2);
    small_buf_.add(absl::string_view(dumped).substr(0, dumped.size() - 1));
    string_open_ = true;
  } else {
    small_buf_.add(dumped);
  }

  CO_RETURN_IF_ERROR(co_await maybeFlushBuffer());
  co_return absl::OkStatus();
}

Coroutine::Task<absl::Status> FlatteningJsonSerializer::finish() {
  if (string_open_) {
    small_buf_.add("\"");
    string_open_ = false;
  }
  while (!open_containers_.empty()) {
    small_buf_.add(open_containers_.back().is_object ? "}" : "]");
    open_containers_.pop_back();
  }
  if (!root_emitted_) {
    small_buf_.add("{}");
    root_emitted_ = true;
  }
  co_return co_await flushBuffer();
}

Coroutine::Task<absl::Status> FlatteningJsonSerializer::maybeFlushBuffer() {
  if (small_buf_.length() >= kMaxSmallBufferSize) {
    co_return co_await flushBuffer();
  }
  co_return absl::OkStatus();
}

Coroutine::Task<absl::Status> FlatteningJsonSerializer::flushBuffer() {
  if (small_buf_.length() > 0) {
    CO_RETURN_IF_ERROR(co_await ReplayAwaitable(out_, small_buf_));
  }
  co_return absl::OkStatus();
}

absl::StatusOr<nlohmann::json> unflattenJson(absl::Span<const FlattenJsonField> fields) {
  if (fields.empty()) {
    return absl::InvalidArgumentError("ai json: no fields to unflatten");
  }
  nlohmann::json root;
  // containers[k] holds segment k of the previous field's path.
  std::vector<nlohmann::json*> containers;
  // The string a partial chunk left open for the next chunk.
  nlohmann::json* open_string = nullptr;

  for (size_t i = 0; i < fields.size(); ++i) {
    const FlattenJsonField& field = fields[i];
    const FieldPath path = field.field_path();
    const nlohmann::json& node = field.node();

    if (open_string != nullptr) {
      const FieldPath previous = fields[i - 1].field_path();
      if (!node.is_string() ||
          !std::equal(path.begin(), path.end(), previous.begin(), previous.end())) {
        return absl::InvalidArgumentError(
            absl::StrCat("ai json: field ", i, " interrupts a partial string"));
      }
      open_string->get_ref<std::string&>().append(node.get_ref<const std::string&>());
      if (!field.is_partial()) {
        open_string = nullptr;
      }
      continue;
    }
    if (node.is_structured() && !node.empty()) {
      return absl::InvalidArgumentError(
          absl::StrCat("ai json: field ", i, " is a non-empty container, not a leaf"));
    }
    if (field.is_partial() && !node.is_string()) {
      return absl::InvalidArgumentError(
          absl::StrCat("ai json: field ", i, " is a partial chunk of a non-string"));
    }

    size_t depth = 0;
    if (i == 0) {
      if (!path.empty()) {
        root = emptyContainerFor(path[0]);
        containers.push_back(&root);
      }
    } else {
      const FieldPath previous = fields[i - 1].field_path();
      const size_t max_common = std::min(path.size(), previous.size());
      while (depth < max_common && path[depth] == previous[depth]) {
        ++depth;
      }
      // Each leaf after the first branches off the previous one inside a container both share.
      if (depth == path.size() || depth == previous.size()) {
        return absl::InvalidArgumentError(
            absl::StrCat("ai json: field ", i, " overlaps the field before it"));
      }
      containers.resize(depth + 1);
    }

    nlohmann::json* leaf = &root;
    for (; depth < path.size(); ++depth) {
      absl::StatusOr<nlohmann::json*> child = appendChild(*containers[depth], path[depth], i);
      if (!child.ok()) {
        return child.status();
      }
      leaf = *child;
      if (depth + 1 < path.size()) {
        *leaf = emptyContainerFor(path[depth + 1]);
        containers.push_back(leaf);
      }
    }
    *leaf = node;
    if (field.is_partial()) {
      open_string = leaf;
    }
  }

  if (open_string != nullptr) {
    return absl::InvalidArgumentError("ai json: fields end inside a partial string");
  }
  return root;
}

std::vector<FlattenJsonField> flattenJson(const nlohmann::json& doc) {
  std::vector<FlattenJsonField> fields;
  std::vector<FieldPathSegment> path;
  flattenInto(doc, path, fields);
  return fields;
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
