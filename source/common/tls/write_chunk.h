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

  const uint64_t size = std::min(max_bytes, MinWriteChunkSize);
  return {buffer.linearize(size), static_cast<size_t>(size)};
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
