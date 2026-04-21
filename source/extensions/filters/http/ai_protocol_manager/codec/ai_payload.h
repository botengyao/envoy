#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

// Tags the semantic kind of a payload so the store can apply kind-specific
// policies (size thresholds, TTLs, external URIs). Matches the item-kind
// split that the chain layer iterates in DESIGN.md §5.3.
enum class PayloadKind {
  Unknown,
  Message,     // chat turn / A2A part / MCP content
  Tool,        // tool or function definition
  Attachment,  // image, audio, file, blob
  Other,
};

// PayloadRef — the storage-side handle to a piece of payload data.
// See DESIGN.md §4.2. Three storage modes:
//   - Inline:   small chunk held directly in the ref (absl::string_view into
//               owner-held memory).
//   - Buffered: held in an Envoy Buffer::Instance owned by the ref.
//   - External: opaque URI resolved by the PayloadStore.
//
// V0 only wires up Inline and Buffered; External is a forward declaration for
// the offload path.
class PayloadRef {
public:
  enum class Storage { Inline, Buffered, External };

  PayloadRef() = default;

  static PayloadRef makeInline(absl::string_view view, PayloadKind kind = PayloadKind::Unknown);
  static PayloadRef makeBuffered(std::unique_ptr<Buffer::Instance> buffer,
                                 PayloadKind kind = PayloadKind::Unknown);
  static PayloadRef makeExternal(std::string handle, std::size_t size,
                                 PayloadKind kind = PayloadKind::Unknown);

  Storage storage() const { return storage_; }
  PayloadKind kind() const { return kind_; }
  std::size_t size() const { return size_; }

  // Valid only when storage() == Inline.
  absl::string_view inlineView() const { return inline_view_; }

  // Valid only when storage() == Buffered.
  const Buffer::Instance& buffered() const { return *buffered_; }
  Buffer::Instance& buffered() { return *buffered_; }

  // Valid only when storage() == External.
  absl::string_view externalHandle() const { return external_handle_; }

private:
  Storage storage_{Storage::Inline};
  PayloadKind kind_{PayloadKind::Unknown};
  std::size_t size_{0};
  absl::string_view inline_view_;
  std::unique_ptr<Buffer::Instance> buffered_;
  std::string external_handle_;
};

// PayloadStore — pluggable offload boundary. See DESIGN.md §4.2.
// V0 ships an in-memory impl; FileApi / object-store impls land later.
class PayloadStore {
public:
  using FetchCallback = std::function<void(const Buffer::Instance&)>;

  virtual ~PayloadStore() = default;

  // Stash raw bytes and return a ref the encoder can later resolve. The
  // implementation decides Inline vs Buffered vs External based on size and
  // configured thresholds.
  virtual PayloadRef store(std::unique_ptr<Buffer::Instance> data, PayloadKind kind) = 0;

  // Materialize a ref back into a buffer. May invoke the callback
  // asynchronously for External refs.
  virtual void fetch(const PayloadRef& ref, FetchCallback cb) = 0;
};

using PayloadStorePtr = std::unique_ptr<PayloadStore>;

// Simple in-memory implementation. Never offloads to External; every call is
// synchronous. Suitable for V0 and for tests.
class InMemoryPayloadStore : public PayloadStore {
public:
  PayloadRef store(std::unique_ptr<Buffer::Instance> data, PayloadKind kind) override;
  void fetch(const PayloadRef& ref, FetchCallback cb) override;
};

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
