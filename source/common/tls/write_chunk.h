#pragma once

#include <algorithm>
#include <cstdint>

#include "envoy/buffer/buffer.h"

#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

// The maximum amount of plaintext handed to a single SSL_write() call, matching the maximum TLS
// record payload size.
constexpr uint64_t MaxWriteChunkSize = 16384;

// The smallest amount of contiguous plaintext worth writing on its own. A front slice at least this
// large is written as-is; a shorter one is coalesced up to this size so that a fragmented buffer
// does not turn into a stream of tiny TLS records.
constexpr uint64_t MinWriteChunkSize = 4096;

// How many leading slices to consider coalescing whole. Bounds the scan below for a buffer made of
// many tiny slices, which falls back to coalescing MinWriteChunkSize anyway.
constexpr uint64_t MaxCoalescedSlices = 16;

/**
 * Select the plaintext for the next SSL_write() call from the front of `buffer`.
 *
 * `Buffer::Instance::linearize()` copies whenever the front slice holds less than the requested
 * size. A single short slice at the front of the buffer (response headers, an HTTP/2 frame header)
 * permanently misaligns the slice boundaries against the write chunks: every subsequent chunk then
 * straddles two slices, so effectively the whole egress stream is copied one extra time. Writing
 * the front slice as-is, and coalescing only up to MinWriteChunkSize when it is too short, restores
 * the alignment after at most one small copy.
 *
 * The returned chunk is stable across appends to `buffer`, which is what lets an
 * SSL_ERROR_WANT_WRITE retry re-run this and hand SSL_write() the same parameters: appending never
 * moves the front slice and can only grow it, so re-running with `max_bytes` capped at the
 * previously returned length yields the same pointer and the same length.
 *
 * @param buffer the buffer to write from, which must hold at least `max_bytes` bytes.
 * @param max_bytes the maximum number of bytes to write, at most MaxWriteChunkSize.
 * @return the contiguous chunk to hand to SSL_write().
 */
inline Buffer::RawSlice nextWriteChunk(Buffer::Instance& buffer, uint64_t max_bytes) {
  ASSERT(max_bytes > 0 && max_bytes <= MaxWriteChunkSize && max_bytes <= buffer.length());

  const Buffer::RawSlice front = buffer.frontSlice();
  if (front.len_ >= std::min(max_bytes, MinWriteChunkSize)) {
    return {front.mem_, static_cast<size_t>(std::min<uint64_t>(front.len_, max_bytes))};
  }

  // The front slice is too short to write on its own, so something has to be coalesced. Prefer
  // taking whole slices: ending the copy on a slice boundary leaves the rest of the buffer aligned
  // with the chunk size, so leading fragments that tile the chunk exactly still go out as one
  // record, exactly as linearizing the whole chunk would.
  uint64_t size = 0;
  for (const Buffer::RawSlice& slice : buffer.getRawSlices(MaxCoalescedSlices)) {
    if (size + slice.len_ > max_bytes) {
      break;
    }
    size += slice.len_;
  }

  // The fragments do not tile the chunk, so the slice behind them has to be split. Copy only up to
  // MinWriteChunkSize rather than the whole chunk: the remainder of that slice then stays big
  // enough to be written in place next time round, which is what stops the misalignment from
  // repeating for the rest of the stream.
  if (size < MinWriteChunkSize) {
    size = std::min(max_bytes, MinWriteChunkSize);
  }
  return {buffer.linearize(size), static_cast<size_t>(size)};
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
