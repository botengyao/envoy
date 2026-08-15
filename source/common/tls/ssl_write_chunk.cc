#include "source/common/tls/ssl_write_chunk.h"

#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

namespace {

uint64_t writesNeededFor(uint64_t bytes, uint64_t bytes_per_write) {
  return (bytes + bytes_per_write - 1) / bytes_per_write;
}

// Whether writing just the contiguous front slice earns a TLS record of its own. Two independent
// conditions:
//
// 1. The slice behind it must cover the following write alone, or nothing is re-aligned. Chains
//    fragmented more than one slice deep (HTTP/1 chunked framing, small HTTP/2 frames, buffer
//    fragments) would just pay an extra record and writev for the same bytes copied.
// 2. It must not increase the write count. Splitting the front slice off shifts every record
//    boundary behind it and can push the tail into one more record. Envoy issues one writev per
//    record, so requiring the count not to grow keeps this strictly fewer copies, never more
//    records.
bool shortRecordRealignsBuffer(Buffer::Instance& write_buffer, const Buffer::RawSlice& front_slice,
                               uint64_t bytes_to_write) {
  // getRawSlices() skips empty slices like frontSlice(), so index 1 becomes the front once the
  // short record is drained.
  const Buffer::RawSliceVector slices = write_buffer.getRawSlices(/*max_slices=*/2);
  if (slices.size() < 2 || slices[1].len_ < bytes_to_write) {
    return false;
  }

  const uint64_t queued = write_buffer.length();
  const uint64_t with_short_record = 1 + writesNeededFor(queued - front_slice.len_, bytes_to_write);
  return with_short_record <= writesNeededFor(queued, bytes_to_write);
}

} // namespace

SslWriteChunk selectSslWriteChunk(Buffer::Instance& write_buffer, uint64_t bytes_to_write,
                                  bool linearized_last_write, bool avoid_repeated_linearize) {
  ASSERT(bytes_to_write > 0 && bytes_to_write <= write_buffer.length());
  const Buffer::RawSlice front_slice = write_buffer.frontSlice();
  // Non-empty by the precondition above, since frontSlice() skips empty slices.
  ASSERT(front_slice.len_ > 0);

  if (front_slice.len_ >= bytes_to_write) {
    // linearize() would hand back this same pointer without copying.
    return {front_slice.mem_, bytes_to_write, false};
  }

  if (avoid_repeated_linearize && linearized_last_write &&
      shortRecordRealignsBuffer(write_buffer, front_slice, bytes_to_write)) {
    // Copied last time, about to copy again, and one short record breaks the cycle for free.
    return {front_slice.mem_, front_slice.len_, false};
  }

  return {write_buffer.linearize(bytes_to_write), bytes_to_write, true};
}

SslWriteChunk SslWriteChunkSelector::nextChunk(Buffer::Instance& write_buffer,
                                               uint64_t bytes_to_write) {
  if (pending_.has_value()) {
    // Repeat verbatim: nothing is drained while a write is outstanding and new data only appends at
    // the back, so the same bytes are still at the same address.
    ASSERT(write_buffer.frontSlice().len_ >= pending_->length_);
    return {write_buffer.frontSlice().mem_, pending_->length_, pending_->linearized_};
  }
  return selectSslWriteChunk(write_buffer, bytes_to_write, linearized_last_write_,
                             avoid_repeated_linearize_);
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
