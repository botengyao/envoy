#include "source/common/tls/ssl_write_chunk.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

// The escape below only works because a write is capped at exactly the size of a read-path slice:
// linearize() copies bytes_to_write into a fresh slice and drains the same amount, so for a chain
// of full-size slices the next one is left holding exactly the offset the first one introduced.
static_assert(MaxSslWriteSize == Buffer::Slice::default_slice_size_,
              "the short-record escape assumes writes and buffer slices are the same size");

namespace {

// linearize() leaves the following slice short by exactly the offset the front one introduced, so
// a buffer holding a small header slice ahead of full-size body slices stays misaligned and every
// write repeats the allocation and the copy. Writing just the contiguous front slice breaks that,
// at the price of one short TLS record.
//
// The short record costs at most one extra TLS record, and Envoy issues one writev syscall per
// record, so it is only worth taking when it buys more than it costs. Three bounds, each measured:
//
// - The slice behind the front one must cover the following write alone, or nothing is realigned.
//   Chains fragmented more than one slice deep (HTTP/1 chunked framing, small HTTP/2 frames,
//   buffer fragments) would pay an extra record and writev for the same bytes copied.
// - The front slice must be a small fragment. Splitting off a large one is not cheap, and where
//   the chain behind is also fragmented it realigns nothing.
// - Enough must remain queued behind it. Without the escape every following full-size write
//   linearizes, so the copies saved grow with what is queued, while the cost stays one record.
constexpr uint64_t MaxShortRecordFraction = 4;
constexpr uint64_t MinQueuedRecords = 3;

bool shortRecordIsWorthwhile(Buffer::Instance& write_buffer, const Buffer::RawSlice& front_slice,
                             uint64_t bytes_to_write) {
  if (front_slice.len_ * MaxShortRecordFraction > bytes_to_write) {
    return false;
  }
  if (write_buffer.length() - front_slice.len_ < MinQueuedRecords * bytes_to_write) {
    return false;
  }
  // getRawSlices() skips empty slices like frontSlice(), so index 1 becomes the front once the
  // short record is drained.
  const Buffer::RawSliceVector slices = write_buffer.getRawSlices(/*max_slices=*/2);
  return slices.size() == 2 && slices[1].len_ >= bytes_to_write;
}

} // namespace

SslWriteChunk selectSslWriteChunk(Buffer::Instance& write_buffer, uint64_t bytes_to_write,
                                  bool linearized_last_write, bool avoid_repeated_linearize) {
  ASSERT(bytes_to_write > 0);
  ASSERT(bytes_to_write <= write_buffer.length());
  const Buffer::RawSlice front_slice = write_buffer.frontSlice();
  // Non-empty by the precondition above, since frontSlice() skips empty slices.
  ASSERT(front_slice.len_ > 0);

  if (front_slice.len_ >= bytes_to_write) {
    // linearize() would hand back this same pointer without copying.
    return {front_slice.mem_, bytes_to_write, false};
  }

  if (avoid_repeated_linearize && linearized_last_write &&
      shortRecordIsWorthwhile(write_buffer, front_slice, bytes_to_write)) {
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
    // Bounds check, not just an invariant: this pointer and length go straight to SSL_write().
    SECURITY_ASSERT(write_buffer.frontSlice().len_ >= pending_->length_,
                    "pending TLS write no longer fits the write buffer's front slice");
    return {write_buffer.frontSlice().mem_, pending_->length_, pending_->linearized_};
  }
  return selectSslWriteChunk(write_buffer, bytes_to_write, linearized_last_write_,
                             avoid_repeated_linearize_);
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
