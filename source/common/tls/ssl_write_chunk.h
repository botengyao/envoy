#pragma once

#include <cstdint>
#include <optional>

#include "envoy/buffer/buffer.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

// The most plaintext a single TLS record can carry, and so the most that is ever handed to one
// SSL_write(). It is also Buffer::Slice::default_slice_size_, which is what makes a misaligned
// write buffer self-perpetuating; see selectSslWriteChunk().
constexpr uint64_t MaxSslWriteSize = 16384;

/**
 * The pointer and length to hand to the next SSL_write(), plus whether producing it required
 * linearizing the write buffer.
 */
struct SslWriteChunk {
  const void* data_;
  uint64_t length_;
  bool linearized_;
};

/**
 * Select the contiguous chunk for the next SSL_write().
 *
 * SSL_write() needs contiguous memory, which normally means linearize(). But linearize() copies
 * `bytes_to_write` into a freshly allocated slice and drains the same amount, which leaves the
 * following slice short. The read path reserves slices of MaxSslWriteSize, and that is also the
 * most we ever write at once, so for a chain of full-size slices the drain leaves the next one
 * holding exactly the offset the first one introduced. A write buffer that starts out misaligned -
 * as it does whenever a small header slice is moved in ahead of full body slices - therefore stays
 * misaligned, and every subsequent write repeats the allocation and the copy.
 *
 * The way out is to write just the contiguous front slice, as one short TLS record, after which the
 * chain is aligned and the writes that follow are copy-free. That is only taken when it is free:
 * see shortRecordRealignsBuffer() for the two conditions.
 *
 * @param write_buffer the buffer to write from; must not be empty. May be linearized in place.
 * @param bytes_to_write the number of bytes the caller wants to write.
 * @param linearized_last_write whether the previous successful write had to linearize.
 * @param avoid_repeated_linearize whether the short-record escape is enabled.
 * @return the chunk to write. The returned length is never larger than @param bytes_to_write, and
 *         is only smaller when the short-record escape is taken.
 */
SslWriteChunk selectSslWriteChunk(Buffer::Instance& write_buffer, uint64_t bytes_to_write,
                                  bool linearized_last_write, bool avoid_repeated_linearize);

/**
 * Drives selectSslWriteChunk() across a sequence of SSL_write() calls, holding the little state
 * those decisions need. Two pieces of history matter, and they are not the same:
 *
 * - A write that returned SSL_ERROR_WANT_WRITE must be repeated with identical bytes, and must not
 *   be decided again. Re-deciding would see the buffer as it is *after* a linearize and conclude
 *   nothing was copied, losing the very fact the next decision depends on. (BoringSSL is not
 *   configured with SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, so the pointer must match too.)
 * - Whether the previous *successful* write had to copy. That is what identifies a misaligned
 *   chain. It is deliberately connection-scoped rather than reset when the buffer drains: the
 *   misalignment is a property of how the connection assembles writes, not of one doWrite batch,
 *   and carrying it across a drained buffer is what keeps request/response connections in the
 *   copy-free steady state instead of paying a fresh linearize per response.
 *
 * One per SslSocket, used only from the connection's dispatcher thread.
 */
class SslWriteChunkSelector {
public:
  explicit SslWriteChunkSelector(bool avoid_repeated_linearize)
      : avoid_repeated_linearize_(avoid_repeated_linearize) {}

  /**
   * @return the length the pending write must be repeated with, or nullopt if none is outstanding.
   */
  std::optional<uint64_t> pendingLength() const {
    return pending_.has_value() ? std::make_optional(pending_->length_) : std::nullopt;
  }

  /**
   * @param write_buffer the buffer to write from; must not be empty. May be linearized in place.
   * @param bytes_to_write how much the caller wants to write. Ignored while a write is pending,
   *        since that one must be repeated exactly.
   * @return the chunk for the next SSL_write().
   */
  SslWriteChunk nextChunk(Buffer::Instance& write_buffer, uint64_t bytes_to_write);

  /**
   * Record that @param chunk was written in full.
   *
   * Must be called before the write buffer is drained: drain() can synchronously run low-watermark
   * callbacks and slice drain trackers, which may re-enter the connection, and a nested write must
   * not find this one still pending.
   */
  void onWriteSucceeded(const SslWriteChunk& chunk) {
    pending_.reset();
    linearized_last_write_ = chunk.linearized_;
  }

  /** Record that SSL_write() returned SSL_ERROR_WANT_WRITE for @param chunk. */
  void onWantWrite(const SslWriteChunk& chunk) {
    pending_ = PendingWrite{chunk.length_, chunk.linearized_};
  }

  bool avoidRepeatedLinearizeForTest() const { return avoid_repeated_linearize_; }

private:
  struct PendingWrite {
    uint64_t length_;
    bool linearized_;
  };

  const bool avoid_repeated_linearize_;
  std::optional<PendingWrite> pending_;
  bool linearized_last_write_{false};
};

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
