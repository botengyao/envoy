#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "envoy/event/dispatcher.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// An ExternalBuffer that keeps its payload in memory while it fits in `memory_limit` bytes. The
// write that would pass the limit moves everything held, then its own bytes, into one write to a
// buffer from `backing`, which holds the payload from offset 0 on; later operations go straight to
// it. A payload that never passes the limit never creates the backing buffer.
class TieredExternalBuffer : public ExternalBuffer, Logger::Loggable<Logger::Id::filter> {
public:
  TieredExternalBuffer(Event::Dispatcher& dispatcher, ExternalBufferFactorySharedPtr backing,
                       uint64_t memory_limit);
  ~TieredExternalBuffer() override { *alive_ = false; }

  // ExternalBuffer
  void write(Buffer::InstancePtr data, bool end_stream, WriteCallback cb) override;
  void read(uint64_t offset, uint64_t length, ReadCallback cb) override;
  uint64_t length() const override { return spilled_ ? backing_->length() : memory_length_; }

private:
  struct DeferredRead {
    uint64_t offset;
    uint64_t length;
    ReadCallback cb;
  };

  void onSpilled(ExternalBufferStatus status, WriteCallback cb);

  Event::Dispatcher& dispatcher_;
  const ExternalBufferFactorySharedPtr backing_factory_;
  const uint64_t memory_limit_;
  Buffer::OwnedImpl memory_;
  uint64_t memory_length_{0};
  // Reads that arrive while the held bytes are on their way to the backing buffer.
  std::vector<DeferredRead> deferred_reads_;
  bool spilling_{false};
  bool spilled_{false};
  bool failed_{false};
  std::shared_ptr<bool> alive_{std::make_shared<bool>(true)};
  // Last, so it is destroyed first and cancels its own callbacks.
  ExternalBufferPtr backing_;
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
