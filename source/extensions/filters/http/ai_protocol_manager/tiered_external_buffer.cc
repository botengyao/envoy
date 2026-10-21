#include "source/extensions/filters/http/ai_protocol_manager/tiered_external_buffer.h"

#include <utility>

#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

TieredExternalBuffer::TieredExternalBuffer(Event::Dispatcher& dispatcher,
                                           ExternalBufferFactorySharedPtr backing,
                                           uint64_t memory_limit)
    : dispatcher_(dispatcher), backing_factory_(std::move(backing)), memory_limit_(memory_limit) {}

void TieredExternalBuffer::write(Buffer::InstancePtr data, bool end_stream, WriteCallback cb) {
  ASSERT(!spilling_);
  if (failed_) {
    cb(ExternalBufferStatus::Error);
    return;
  }
  if (spilled_) {
    backing_->write(std::move(data), end_stream, std::move(cb));
    return;
  }
  if (memory_length_ + data->length() <= memory_limit_) {
    // Acknowledged on a later pass, as the in-memory buffer does, so a caller never sees its own
    // write complete on-stack.
    dispatcher_.post([this, alive = alive_, data = std::move(data), cb = std::move(cb)]() mutable {
      if (!*alive) {
        return;
      }
      memory_length_ += data->length();
      memory_.move(*data);
      cb(ExternalBufferStatus::Ok);
    });
    return;
  }
  ENVOY_LOG(debug, "ai_protocol_manager: spilling {} bytes held in memory to the external buffer",
            memory_length_ + data->length());
  spilling_ = true;
  backing_ = backing_factory_->createBuffer(dispatcher_);
  auto spill = std::make_unique<Buffer::OwnedImpl>();
  spill->move(memory_);
  spill->move(*data);
  backing_->write(std::move(spill), end_stream,
                  [this, cb = std::move(cb)](ExternalBufferStatus status) mutable {
                    onSpilled(status, std::move(cb));
                  });
}

void TieredExternalBuffer::onSpilled(ExternalBufferStatus status, WriteCallback cb) {
  spilling_ = false;
  spilled_ = status == ExternalBufferStatus::Ok;
  failed_ = !spilled_;
  std::vector<DeferredRead> reads;
  reads.swap(deferred_reads_);
  // A reader may destroy this buffer from its callback.
  const std::shared_ptr<bool> alive = alive_;
  for (DeferredRead& read : reads) {
    if (!*alive) {
      return;
    }
    if (failed_) {
      read.cb(ExternalBufferStatus::Error, nullptr);
    } else {
      backing_->read(read.offset, read.length, std::move(read.cb));
    }
  }
  if (*alive) {
    cb(status);
  }
}

void TieredExternalBuffer::read(uint64_t offset, uint64_t length, ReadCallback cb) {
  if (failed_) {
    cb(ExternalBufferStatus::Error, nullptr);
    return;
  }
  if (spilled_) {
    backing_->read(offset, length, std::move(cb));
    return;
  }
  if (spilling_) {
    deferred_reads_.push_back({offset, length, std::move(cb)});
    return;
  }
  ASSERT(offset + length <= memory_length_);
  auto out = std::make_unique<Buffer::OwnedImpl>();
  if (length > 0) {
    auto bytes = std::make_unique<uint8_t[]>(length);
    memory_.copyOut(offset, length, bytes.get());
    out->add(bytes.get(), length);
  }
  cb(ExternalBufferStatus::Ok, std::move(out));
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
