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

// Whether writing just the contiguous front slice is worth a TLS record of its own.
//
// Two things have to hold, and neither implies the other:
//
// 1. The slice behind the front one must cover the following write on its own, so that the short
//    record actually leaves the buffer aligned. On a chain fragmented more than one slice deep -
//    HTTP/1 chunked framing, small HTTP/2 frames, buffer fragments - it re-aligns nothing, and the
//    short record is pure overhead: another TLS record and another writev for the same bytes.
//
// 2. It must not increase the number of writes. Splitting a short front slice off shifts every
//    record boundary behind it, which can push the tail over into one extra record - and Envoy
//    issues one writev syscall per record. Requiring the count not to grow keeps this change to
//    what it is meant to be: strictly fewer copies, never more records.
bool shortRecordRealignsBuffer(Buffer::Instance& write_buffer, const Buffer::RawSlice& front_slice,
                               uint64_t bytes_to_write) {
  // getRawSlices() skips empty slices, exactly as frontSlice() does, so index 1 is the slice that
  // becomes the front once the short record is written and drained.
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
  // Non-empty by the precondition: the buffer holds data, and frontSlice() skips empty slices.
  const Buffer::RawSlice front_slice = write_buffer.frontSlice();
  ASSERT(front_slice.len_ > 0);

  if (front_slice.len_ >= bytes_to_write) {
    // Already contiguous, so linearize() would hand back this same pointer without copying.
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
    // Repeat the pending write verbatim. Nothing is drained while a write is outstanding and new
    // data is only ever appended at the back, so the front of the buffer still holds exactly these
    // bytes at the same address.
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
