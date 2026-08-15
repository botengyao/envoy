#pragma once

#include <cstdint>
#include <optional>

#include "envoy/buffer/buffer.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

// The most plaintext one TLS record carries, so the most ever handed to a single SSL_write().
// Equal to Buffer::Slice::default_slice_size_, which is what makes misalignment self-perpetuating.
constexpr uint64_t MaxSslWriteSize = 16384;

/**
 * The pointer and length for the next SSL_write(), and whether producing it required a linearize.
 */
struct SslWriteChunk {
  const void* data_;
  uint64_t length_;
  bool linearized_;
};

/**
 * Select the contiguous chunk for the next SSL_write().
 *
 * linearize() copies `bytes_to_write` into a fresh slice and drains the same amount, leaving the
 * next slice short by exactly the offset the first one introduced - so a buffer holding a small
 * header slice ahead of full-size body slices stays misaligned, and every write repeats the
 * allocation and the copy. Writing just the contiguous front slice as one short TLS record breaks
 * that, when it is free to do so; see shortRecordRealignsBuffer().
 *
 * @param write_buffer the buffer to write from; must not be empty. May be linearized in place.
 * @param bytes_to_write the number of bytes the caller wants to write.
 * @param linearized_last_write whether the previous successful write had to linearize.
 * @param avoid_repeated_linearize whether the short-record escape is enabled.
 * @return the chunk to write, never longer than @param bytes_to_write.
 */
SslWriteChunk selectSslWriteChunk(Buffer::Instance& write_buffer, uint64_t bytes_to_write,
                                  bool linearized_last_write, bool avoid_repeated_linearize);

/**
 * Drives selectSslWriteChunk() across successive SSL_write() calls. Holds two distinct pieces of
 * history:
 *
 * - A write that returned SSL_ERROR_WANT_WRITE, repeated verbatim rather than decided again.
 *   Re-deciding would inspect the buffer *after* the linearize, conclude nothing was copied, and
 *   lose the fact the next decision needs.
 * - Whether the previous successful write copied, which is what identifies a misaligned chain.
 *   Deliberately connection-scoped: the misalignment belongs to the connection's write pattern, not
 *   to one doWrite batch, so carrying it across a drained buffer keeps request/response connections
 *   copy-free instead of re-linearizing per response.
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
   * @param bytes_to_write how much to write. Ignored while a write is pending, since that one must
   *        be repeated exactly.
   * @return the chunk for the next SSL_write().
   */
  SslWriteChunk nextChunk(Buffer::Instance& write_buffer, uint64_t bytes_to_write);

  /**
   * Record that @param chunk was written in full. Must be called before draining the write buffer:
   * drain() can run callbacks that re-enter the connection, and a nested write must not find this
   * one still pending.
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
