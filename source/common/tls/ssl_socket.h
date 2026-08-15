#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "envoy/network/connection.h"
#include "envoy/network/transport_socket.h"
#include "envoy/secret/secret_callbacks.h"
#include "envoy/ssl/handshaker.h"
#include "envoy/ssl/private_key/private_key_callbacks.h"
#include "envoy/ssl/ssl_socket_extended_info.h"
#include "envoy/ssl/ssl_socket_state.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/common/tls/context_impl.h"
#include "source/common/tls/ssl_handshaker.h"
#include "source/common/tls/utility.h"

#include "absl/container/node_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

#define ALL_SSL_SOCKET_FACTORY_STATS(COUNTER)                                                      \
  COUNTER(ssl_context_update_by_sds)                                                               \
  COUNTER(upstream_context_secrets_not_ready)                                                      \
  COUNTER(downstream_context_secrets_not_ready)

/**
 * Wrapper struct for SSL socket factory stats. @see stats_macros.h
 */
struct SslSocketFactoryStats {
  ALL_SSL_SOCKET_FACTORY_STATS(GENERATE_COUNTER_STRUCT)
};

enum class InitialState { Client, Server };

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
 * following slice short. The read path fills slices of Slice::default_slice_size_ (16KB), and that
 * is also the most we ever write at once; for that common chain the drain leaves the next slice
 * holding exactly the offset the first one introduced. So a write buffer that starts out
 * misaligned - as it does whenever a small header slice is moved in ahead of full body slices -
 * stays misaligned, and every subsequent write repeats the allocation and the copy. (Slices larger
 * than the write size are not affected: they self-heal, because the leftover then exceeds the write
 * size and the next write is contiguous.)
 *
 * So when the previous write already had to linearize and this one would too, write just the
 * contiguous front slice instead. That costs one short TLS record, and for the usual chain of
 * full-size slices it re-aligns the buffer so the writes that follow are copy-free. The escape is
 * skipped when this write would drain the buffer completely: no chain survives for it to re-align,
 * so linearizing is the better choice and keeps the batch to a single record.
 *
 * @param write_buffer the buffer to write from; must not be empty. May be linearized in place.
 * @param bytes_to_write the number of bytes the caller wants to write.
 * @param linearized_last_write whether the previous call to this function linearized.
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
   * Record that @param chunk was written in full and drained.
   * @param write_buffer the buffer, already drained.
   */
  void onWriteSucceeded(const SslWriteChunk& chunk) {
    pending_.reset();
    linearized_last_write_ = chunk.linearized_;
  }

  /** Record that SSL_write() returned SSL_ERROR_WANT_WRITE for @param chunk. */
  void onWantWrite(const SslWriteChunk& chunk) {
    pending_ = PendingWrite{chunk.length_, chunk.linearized_};
  }

private:
  struct PendingWrite {
    uint64_t length_;
    bool linearized_;
  };

  const bool avoid_repeated_linearize_;
  std::optional<PendingWrite> pending_;
  bool linearized_last_write_{false};
};

class SslSocket : public Network::TransportSocket,
                  public Envoy::Ssl::PrivateKeyConnectionCallbacks,
                  public Ssl::HandshakeCallbacks,
                  protected Logger::Loggable<Logger::Id::connection> {
public:
  static absl::StatusOr<std::unique_ptr<SslSocket>>
  create(Envoy::Ssl::ContextSharedPtr ctx, InitialState state,
         const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
         Ssl::HandshakerFactoryCb handshaker_factory_cb,
         Upstream::HostDescriptionConstSharedPtr host = {});

  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override;
  std::string protocol() const override;
  absl::string_view failureReason() const override;
  bool canFlushClose() override { return info_->state() == Ssl::SocketState::HandshakeComplete; }
  void closeSocket(Network::ConnectionEvent close_type, bool abort_reset) override;
  Network::IoResult doRead(Buffer::Instance& read_buffer) override;
  Network::IoResult doWrite(Buffer::Instance& write_buffer, bool end_stream) override;
  void onConnected() override;
  Ssl::ConnectionInfoConstSharedPtr ssl() const override;
  bool startSecureTransport() override { return false; }
  void configureInitialCongestionWindow(uint64_t, std::chrono::microseconds) override {}
  // Ssl::PrivateKeyConnectionCallbacks
  void onPrivateKeyMethodComplete() override;
  // Ssl::HandshakeCallbacks
  Network::Connection& connection() const override;
  void onSuccess(SSL* ssl) override;
  void onFailure() override;
  Network::TransportSocketCallbacks* transportSocketCallbacks() override { return callbacks_; }
  void onAsynchronousCertValidationComplete() override;
  void onAsynchronousCertificateSelectionComplete() override;

  SSL* rawSslForTest() const { return rawSsl(); }

protected:
  SSL* rawSsl() const { return info_->ssl(); }

private:
  friend class SslSocketPeer;

  SslSocket(Envoy::Ssl::ContextSharedPtr ctx,
            const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options);
  absl::Status initialize(InitialState state, Ssl::HandshakerFactoryCb handshaker_factory_cb,
                          Upstream::HostDescriptionConstSharedPtr host);

  struct ReadResult {
    uint64_t bytes_read_{0};
    std::optional<int> error_;
  };
  ReadResult sslReadIntoSlice(Buffer::RawSlice& slice);

  Network::PostIoAction doHandshake();
  void drainErrorQueue();
  void shutdownSsl();
  void shutdownBasic();
  void resumeHandshake();

  const Network::TransportSocketOptionsConstSharedPtr transport_socket_options_;
  Network::TransportSocketCallbacks* callbacks_{};
  ContextImplSharedPtr ctx_;
  SslWriteChunkSelector write_chunk_selector_;
  std::string failure_reason_;
  std::optional<Api::IoError::IoErrorCode> detected_io_error_;
  bool read_disabled_{false};

  SslHandshakerImplSharedPtr info_;
};

class InvalidSslSocket : public Network::TransportSocket {
public:
  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks&) override {}
  std::string protocol() const override { return EMPTY_STRING; }
  bool canFlushClose() override { return true; }
  void closeSocket(Network::ConnectionEvent, bool) override {}
  Network::IoResult doRead(Buffer::Instance&) override {
    return {Network::PostIoAction::Close, 0, false};
  }
  Network::IoResult doWrite(Buffer::Instance&, bool) override {
    return {Network::PostIoAction::Close, 0, false};
  }
  void onConnected() override {}
  Ssl::ConnectionInfoConstSharedPtr ssl() const override { return nullptr; }
  bool startSecureTransport() override { return false; }
  void configureInitialCongestionWindow(uint64_t, std::chrono::microseconds) override {}
};

// This SslSocket will be used when SSL secret is not fetched from SDS server.
class NotReadySslSocket : public InvalidSslSocket {
public:
  // Network::TransportSocket
  absl::string_view failureReason() const override;
};

class ErrorSslSocket : public InvalidSslSocket {
public:
  ErrorSslSocket(absl::string_view error) : error_(error) {}

  // Network::TransportSocket
  absl::string_view failureReason() const override { return error_; }

private:
  std::string error_;
};

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
