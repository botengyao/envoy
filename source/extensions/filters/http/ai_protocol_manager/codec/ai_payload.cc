#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_payload.h"

#include "source/common/buffer/buffer_impl.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

PayloadRef PayloadRef::makeInline(absl::string_view view, PayloadKind kind) {
  PayloadRef ref;
  ref.storage_ = Storage::Inline;
  ref.kind_ = kind;
  ref.inline_view_ = view;
  ref.size_ = view.size();
  return ref;
}

PayloadRef PayloadRef::makeBuffered(std::unique_ptr<Buffer::Instance> buffer, PayloadKind kind) {
  PayloadRef ref;
  ref.storage_ = Storage::Buffered;
  ref.kind_ = kind;
  ref.size_ = buffer ? buffer->length() : 0;
  ref.buffered_ = std::move(buffer);
  return ref;
}

PayloadRef PayloadRef::makeExternal(std::string handle, std::size_t size, PayloadKind kind) {
  PayloadRef ref;
  ref.storage_ = Storage::External;
  ref.kind_ = kind;
  ref.size_ = size;
  ref.external_handle_ = std::move(handle);
  return ref;
}

PayloadRef InMemoryPayloadStore::store(std::unique_ptr<Buffer::Instance> data, PayloadKind kind) {
  return PayloadRef::makeBuffered(std::move(data), kind);
}

void InMemoryPayloadStore::fetch(const PayloadRef& ref, FetchCallback cb) {
  // Inline and Buffered refs are synchronous. External is not supported in
  // this impl (DESIGN.md §4.2 flags that as a later addition).
  if (ref.storage() == PayloadRef::Storage::Buffered) {
    cb(ref.buffered());
    return;
  }
  if (ref.storage() == PayloadRef::Storage::Inline) {
    Buffer::OwnedImpl temp;
    temp.add(ref.inlineView());
    cb(temp);
    return;
  }
  // External not implemented here; callers should check storage() first.
}

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
