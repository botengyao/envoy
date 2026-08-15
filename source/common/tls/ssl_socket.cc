#include "source/common/tls/ssl_socket.h"

#include "envoy/stats/scope.h"

#include "source/common/common/assert.h"
#include "source/common/common/empty_string.h"
#include "source/common/common/hex.h"
#include "source/common/http/headers.h"
#include "source/common/runtime/runtime_features.h"
#include "source/common/tls/io_handle_bio.h"
#include "source/common/tls/ssl_handshaker.h"
#include "source/common/tls/utility.h"

#include "absl/strings/str_replace.h"
#include "openssl/err.h"
#include "openssl/x509v3.h"

using Envoy::Network::PostIoAction;

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

namespace {

constexpr absl::string_view NotReadyReason{"TLS error: Secret is not supplied by SDS"};

} // namespace

absl::string_view NotReadySslSocket::failureReason() const { return NotReadyReason; }

absl::StatusOr<std::unique_ptr<SslSocket>>
SslSocket::create(Envoy::Ssl::ContextSharedPtr ctx, InitialState state,
                  const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
                  Ssl::HandshakerFactoryCb handshaker_factory_cb,
                  Upstream::HostDescriptionConstSharedPtr host) {
  std::unique_ptr<SslSocket> socket(new SslSocket(ctx, transport_socket_options));
  auto status = socket->initialize(state, handshaker_factory_cb, host);
  if (status.ok()) {
    return socket;
  } else {
    return status;
  }
}

SslSocket::SslSocket(Envoy::Ssl::ContextSharedPtr ctx,
                     const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options)
    : transport_socket_options_(transport_socket_options),
      ctx_(std::dynamic_pointer_cast<ContextImpl>(ctx)),
      // Latched here rather than read per write: this is a per-connection object, matching how
      // other hot-path reloadable guards are handled (e.g. ConnectionManagerImpl), so a runtime
      // change takes effect on new connections.
      write_chunk_selector_(Runtime::runtimeFeatureEnabled(
          "envoy.reloadable_features.tls_avoid_repeated_linearize")) {}

absl::Status SslSocket::initialize(InitialState state,
                                   Ssl::HandshakerFactoryCb handshaker_factory_cb,
                                   Upstream::HostDescriptionConstSharedPtr host) {
  auto status_or_ssl = ctx_->newSsl(transport_socket_options_, host);
  if (!status_or_ssl.ok()) {
    return status_or_ssl.status();
  }

  info_ = std::dynamic_pointer_cast<SslHandshakerImpl>(handshaker_factory_cb(
      std::move(status_or_ssl.value()), ctx_->sslExtendedSocketInfoIndex(), this));

  if (state == InitialState::Client) {
    SSL_set_connect_state(rawSsl());
  } else {
    ASSERT(state == InitialState::Server);
    SSL_set_accept_state(rawSsl());
  }

  return absl::OkStatus();
}

void SslSocket::setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) {
  ASSERT(!callbacks_);
  callbacks_ = &callbacks;

  // Associate this SSL connection with all the certificates (with their potentially different
  // private key methods).
  for (auto const& provider : ctx_->getPrivateKeyMethodProviders()) {
    provider->registerPrivateKeyMethod(rawSsl(), *this, callbacks_->connection().dispatcher());
  }

  // Use custom BIO that reads from/writes to IoHandle
  BIO* bio = BIO_new_io_handle(&callbacks_->ioHandle());
  SSL_set_bio(rawSsl(), bio, bio);
  SSL_set_ex_data(rawSsl(), ContextImpl::sslSocketIndex(), static_cast<void*>(callbacks_));
}

SslSocket::ReadResult SslSocket::sslReadIntoSlice(Buffer::RawSlice& slice) {
  ReadResult result;
  uint8_t* mem = static_cast<uint8_t*>(slice.mem_);
  size_t remaining = slice.len_;
  while (remaining > 0) {
    int rc = SSL_read(rawSsl(), mem, remaining);
    ENVOY_CONN_LOG(trace, "ssl read returns: {}", callbacks_->connection(), rc);
    if (rc > 0) {
      ASSERT(static_cast<size_t>(rc) <= remaining);
      mem += rc;
      remaining -= rc;
      result.bytes_read_ += rc;
    } else {
      result.error_ = std::make_optional<int>(rc);
      break;
    }
  }

  return result;
}

Network::IoResult SslSocket::doRead(Buffer::Instance& read_buffer) {
  if (info_->state() != Ssl::SocketState::HandshakeComplete &&
      info_->state() != Ssl::SocketState::ShutdownSent) {
    PostIoAction action = doHandshake();
    if (action == PostIoAction::Close || info_->state() != Ssl::SocketState::HandshakeComplete) {
      // end_stream is false because either a hard error occurred (action == Close) or
      // the handshake isn't complete, so a half-close cannot occur yet.
      return {action, 0, false};
    }
  }

  bool keep_reading = true;
  bool end_stream = false;
  PostIoAction action = PostIoAction::KeepOpen;
  uint64_t bytes_read = 0;
  while (keep_reading) {
    uint64_t bytes_read_this_iteration = 0;
    Buffer::Reservation reservation = read_buffer.reserveForRead();
    for (uint64_t i = 0; i < reservation.numSlices(); i++) {
      auto result = sslReadIntoSlice(reservation.slices()[i]);
      bytes_read_this_iteration += result.bytes_read_;
      if (result.error_.has_value()) {
        keep_reading = false;
        int err = SSL_get_error(rawSsl(), result.error_.value());
        ENVOY_CONN_LOG(trace, "ssl error occurred while read: {}", callbacks_->connection(),
                       Utility::getErrorDescription(err));
        switch (err) {
        case SSL_ERROR_WANT_READ:
          break;
        case SSL_ERROR_ZERO_RETURN:
          // Graceful shutdown using close_notify TLS alert.
          end_stream = true;
          break;
        case SSL_ERROR_SYSCALL:
          if (result.error_.value() == 0) {
            // Non-graceful shutdown by closing the underlying socket.
            end_stream = true;
            break;
          }
          FALLTHRU;
        case SSL_ERROR_WANT_WRITE:
          // Renegotiation has started. We don't handle renegotiation so just fall through.
        default:
          drainErrorQueue();
          action = PostIoAction::Close;
          break;
        }

        break;
      }
    }

    reservation.commit(bytes_read_this_iteration);
    if (bytes_read_this_iteration > 0 && callbacks_->shouldDrainReadBuffer()) {
      callbacks_->setTransportSocketIsReadable();
      keep_reading = false;
    }

    bytes_read += bytes_read_this_iteration;
  }

  ENVOY_CONN_LOG(trace, "ssl read {} bytes", callbacks_->connection(), bytes_read);

  return {action, bytes_read, end_stream, detected_io_error_};
}

void SslSocket::onPrivateKeyMethodComplete() { resumeHandshake(); }

void SslSocket::resumeHandshake() {
  ASSERT(callbacks_ != nullptr && callbacks_->connection().dispatcher().isThreadSafe());
  ASSERT(info_->state() == Ssl::SocketState::HandshakeBlockedOnAsyncOperation);

  // Resume handshake.
  PostIoAction action = doHandshake();
  if (action == PostIoAction::Close) {
    ENVOY_CONN_LOG(debug, "async handshake completion error", callbacks_->connection());
    callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite,
                                   "failed_resuming_async_handshake");
  }
}

Network::Connection& SslSocket::connection() const { return callbacks_->connection(); }

void SslSocket::onSuccess(SSL* ssl) {
  ctx_->logHandshake(ssl);
  if (callbacks_->connection().streamInfo().upstreamInfo()) {
    callbacks_->connection()
        .streamInfo()
        .upstreamInfo()
        ->upstreamTiming()
        .onUpstreamHandshakeComplete(callbacks_->connection().dispatcher().timeSource());
  } else {
    callbacks_->connection().streamInfo().downstreamTiming().onDownstreamHandshakeComplete(
        callbacks_->connection().dispatcher().timeSource());
  }

  // There is at least one assertion that reads are enabled when the connected event is raised, so
  // ensure we are in the correct state. The same operation would happen in
  // `SslSocket::doHandshake()`, but it wouldn't happen until after the event was raised.
  if (read_disabled_) {
    read_disabled_ = false;
    callbacks_->connection().readDisable(false);
  }

  callbacks_->raiseEvent(Network::ConnectionEvent::Connected);
}

void SslSocket::onFailure() { drainErrorQueue(); }

PostIoAction SslSocket::doHandshake() {
  auto ret = info_->doHandshake();
  if (ret == PostIoAction::KeepOpen) {
    if (info_->state() == Ssl::SocketState::HandshakeBlockedOnAsyncOperation && !read_disabled_) {
      // Connection close events can only be detected if the connection has reading disabled.
      // If reading is disabled, the connection registers for close events directly.
      // If reading is enabled, the connection registers for read events, but `doRead()` doesn't
      // process any data (including an EOF) when the handshake is in this state, so the connection
      // close isn't detected.
      read_disabled_ = true;
      callbacks_->connection().readDisable(true);
    } else if (info_->state() != Ssl::SocketState::HandshakeBlockedOnAsyncOperation &&
               read_disabled_) {
      read_disabled_ = false;
      callbacks_->connection().readDisable(false);
    }
  }
  return ret;
}

void SslSocket::drainErrorQueue() {
  bool saw_error = false;
  bool saw_counted_error = false;
  bool saw_cert_verify_failed = false;
  bool saw_no_client_cert = false;
  bool saw_econnreset = false;
  bool saw_non_econnreset_error = false;
  while (uint64_t err = ERR_get_error()) {
    bool is_econnreset = false;
    if (ERR_GET_LIB(err) == ERR_LIB_SSL) {
      if (ERR_GET_REASON(err) == SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE) {
        ctx_->stats().fail_verify_no_cert_.inc();
        saw_counted_error = true;
        saw_no_client_cert = true;
      } else if (ERR_GET_REASON(err) == SSL_R_CERTIFICATE_VERIFY_FAILED) {
        saw_counted_error = true;
        saw_cert_verify_failed = true;
      }
    } else if (ERR_GET_LIB(err) == ERR_LIB_SYS) {
      if (ERR_GET_REASON(err) == ECONNRESET) {
        // Only a candidate: any other queued error (TLS protocol failure or
        // unrelated syscall error) is by definition the root cause, and the
        // trailing peer-originated RST is just the symptom. The final decision
        // is made after the loop has visited every queued error.
        saw_econnreset = true;
        is_econnreset = true;
      }
      // Any syscall errors that result in connection closure are already tracked in other
      // connection related stats. We will still retain the specific syscall failure for
      // transport failure reasons.
      saw_counted_error = true;
    }
    if (!is_econnreset) {
      saw_non_econnreset_error = true;
    }
    saw_error = true;

    if (failure_reason_.empty()) {
      failure_reason_ = "TLS_error:";
    }

    absl::StrAppend(&failure_reason_, "|", err, ":",
                    absl::NullSafeStringView(ERR_lib_error_string(err)), ":",
                    absl::NullSafeStringView(ERR_func_error_string(err)), ":",
                    absl::NullSafeStringView(ERR_reason_error_string(err)));
  }

  if (!saw_error) {
    return;
  }

  // Surface a peer-originated RST (pushed onto the queue by io_handle_bio's SO_ERROR probe)
  // only when no other error was queued. Any other queued error means the disconnect was
  // caused by that error and the trailing RST is just the peer's reaction; reporting the
  // RST as the transport error would clobber the more diagnostic
  // ``transport failure reason: TLS_error:...`` signal operators rely on (issue #45011).
  if (saw_econnreset && !saw_non_econnreset_error &&
      Runtime::runtimeFeatureEnabled(
          "envoy.reloadable_features.ssl_socket_report_connection_reset")) {
    detected_io_error_ = Api::IoError::IoErrorCode::ConnectionReset;
  }

  // Append detailed error info for certificate-related failures.
  bool added_detail = false;
  if (saw_cert_verify_failed) {
    auto* extended_socket_info = reinterpret_cast<Envoy::Ssl::SslExtendedSocketInfo*>(
        SSL_get_ex_data(rawSsl(), ContextImpl::sslExtendedSocketInfoIndex()));
    if (extended_socket_info != nullptr) {
      absl::string_view cert_validation_error = extended_socket_info->certificateValidationError();
      if (!cert_validation_error.empty()) {
        absl::StrAppend(&failure_reason_, ":", cert_validation_error);
        added_detail = true;
      }
    }
  }
  if (!added_detail && saw_no_client_cert) {
    absl::StrAppend(&failure_reason_, ":peer did not provide required client certificate");
  }

  if (!failure_reason_.empty()) {
    absl::StrAppend(&failure_reason_, ":TLS_error_end");
    ENVOY_CONN_LOG(debug, "remote address:{},{}", callbacks_->connection(),
                   callbacks_->connection().connectionInfoProvider().remoteAddress()->asString(),
                   failure_reason_);
  }

  if (!saw_counted_error) {
    ctx_->stats().connection_error_.inc();
  }
}

namespace {

// Whether the slice behind the front one is on its own big enough for the write that would follow
// a short record, i.e. whether writing just the front slice actually re-aligns the buffer.
bool nextSliceCoversWrite(Buffer::Instance& write_buffer, uint64_t bytes_to_write) {
  // getRawSlices() skips empty slices, exactly as frontSlice() does, so index 1 is the slice that
  // becomes the front once the short record is written and drained.
  const Buffer::RawSliceVector slices = write_buffer.getRawSlices(/*max_slices=*/2);
  return slices.size() == 2 && slices[1].len_ >= bytes_to_write;
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

  // Only worth a short record if it actually buys the copy-free steady state, which it does only
  // when the slice behind the front one can satisfy the next write by itself. If the chain is
  // fragmented more than one slice deep - HTTP/1 chunked framing, small HTTP/2 frames, buffer
  // fragments - writing the front slice re-aligns nothing, and the short record is pure overhead:
  // an extra TLS record and an extra writev syscall for the same bytes copied. This also implies
  // bytes_to_write < write_buffer.length(), so a write that drains the buffer never splits.
  if (avoid_repeated_linearize && linearized_last_write &&
      nextSliceCoversWrite(write_buffer, bytes_to_write)) {
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

Network::IoResult SslSocket::doWrite(Buffer::Instance& write_buffer, bool end_stream) {
  ASSERT(info_->state() != Ssl::SocketState::ShutdownSent || write_buffer.length() == 0);
  if (info_->state() != Ssl::SocketState::HandshakeComplete &&
      info_->state() != Ssl::SocketState::ShutdownSent) {
    PostIoAction action = doHandshake();
    if (action == PostIoAction::Close || info_->state() != Ssl::SocketState::HandshakeComplete) {
      return {action, 0, false};
    }
  }

  // A write that previously returned SSL_ERROR_WANT_WRITE has to be repeated exactly; otherwise
  // write as much as one TLS record can carry.
  const uint64_t bytes_wanted = std::min(write_buffer.length(), static_cast<uint64_t>(16384));
  uint64_t bytes_to_write = write_chunk_selector_.pendingLength().value_or(bytes_wanted);

  uint64_t total_bytes_written = 0;
  while (bytes_to_write > 0) {
    // TODO(mattklein123): As it relates to our fairness efforts, we might want to limit the number
    // of iterations of this loop, either by pure iterations, bytes written, etc.
    ASSERT(bytes_to_write <= write_buffer.length());
    const SslWriteChunk chunk = write_chunk_selector_.nextChunk(write_buffer, bytes_to_write);
    int rc = SSL_write(rawSsl(), chunk.data_, chunk.length_);
    ENVOY_CONN_LOG(trace, "ssl write returns: {}", callbacks_->connection(), rc);
    if (rc > 0) {
      ASSERT(rc == static_cast<int>(chunk.length_));
      total_bytes_written += rc;
      // Discharge the write before draining, not after. drain() is not a leaf call - it can run
      // low-watermark callbacks and slice drain trackers, which may close the connection and
      // re-enter doWrite() synchronously. A nested call must not find this write still pending.
      write_chunk_selector_.onWriteSucceeded(chunk);
      write_buffer.drain(rc);
      bytes_to_write = std::min(write_buffer.length(), static_cast<uint64_t>(16384));
    } else {
      int err = SSL_get_error(rawSsl(), rc);
      ENVOY_CONN_LOG(trace, "ssl error occurred while write: {}", callbacks_->connection(),
                     Utility::getErrorDescription(err));
      switch (err) {
      case SSL_ERROR_WANT_WRITE:
        write_chunk_selector_.onWantWrite(chunk);
        break;
      case SSL_ERROR_WANT_READ:
      // Renegotiation has started. We don't handle renegotiation so just fall through.
      default:
        drainErrorQueue();
        return {PostIoAction::Close, total_bytes_written, false, detected_io_error_};
      }

      break;
    }
  }

  if (write_buffer.length() == 0 && end_stream) {
    shutdownSsl();
  }

  return {PostIoAction::KeepOpen, total_bytes_written, false};
}

void SslSocket::onConnected() {
  ASSERT(info_->state() == Ssl::SocketState::HandshakeWaitingForConnectionData);
}

Ssl::ConnectionInfoConstSharedPtr SslSocket::ssl() const { return info_; }

void SslSocket::shutdownSsl() {
  ASSERT(info_->state() != Ssl::SocketState::HandshakeWaitingForConnectionData);
  if (info_->state() != Ssl::SocketState::ShutdownSent &&
      callbacks_->connection().state() != Network::Connection::State::Closed) {
    int rc = SSL_shutdown(rawSsl());
    if constexpr (Event::PlatformDefaultTriggerType == Event::FileTriggerType::EmulatedEdge) {
      // Windows operate under `EmulatedEdge`. These are level events that are artificially
      // made to behave like edge events. And if the rc is 0 then in that case we want read
      // activation resumption. This code is protected with an `constexpr` if, to minimize the tax
      // on POSIX systems that operate in Edge events.
      if (rc == 0) {
        // See https://www.openssl.org/docs/manmaster/man3/SSL_shutdown.html
        // if return value is 0,  Call SSL_read() to do a bidirectional shutdown.
        callbacks_->setTransportSocketIsReadable();
      }
    }
    ENVOY_CONN_LOG(debug, "SSL shutdown: rc={}", callbacks_->connection(), rc);
    drainErrorQueue();
    info_->setState(Ssl::SocketState::ShutdownSent);
  }
}

void SslSocket::shutdownBasic() {
  if (info_->state() != Ssl::SocketState::ShutdownSent &&
      callbacks_->connection().state() != Network::Connection::State::Closed) {
    callbacks_->ioHandle().shutdown(ENVOY_SHUT_WR);
    drainErrorQueue();
    info_->setState(Ssl::SocketState::ShutdownSent);
  }
}

void SslSocket::closeSocket(Network::ConnectionEvent, bool abort_reset) {
  // Unregister the SSL connection object from private key method providers.
  for (auto const& provider : ctx_->getPrivateKeyMethodProviders()) {
    provider->unregisterPrivateKeyMethod(rawSsl());
  }

  // When the connection is being torn down with a TCP RST, skip the TLS shutdown
  // (close_notify). Sending close_notify alongside a RST sends contradictory signals
  // to the peer (graceful close vs. reset) and races the alert against the RST,
  // making peer-side reset detection unreliable. Skipping close_notify ensures the
  // peer reliably observes a connection reset.
  if (abort_reset && Runtime::runtimeFeatureEnabled(
                         "envoy.reloadable_features.ssl_socket_report_connection_reset")) {
    return;
  }

  // Attempt to send a shutdown before closing the socket. It's possible this won't go out if
  // there is no room on the socket. We can extend the state machine to handle this at some point
  // if needed.
  if (info_->state() == Ssl::SocketState::HandshakeBlockedOnAsyncOperation ||
      info_->state() == Ssl::SocketState::HandshakeComplete) {
    shutdownSsl();
  } else {
    // We're not in a state to do the full SSL shutdown so perform a basic shutdown to flush any
    // outstanding alerts
    shutdownBasic();
  }
}

std::string SslSocket::protocol() const { return ssl()->alpn(); }

absl::string_view SslSocket::failureReason() const { return failure_reason_; }

void SslSocket::onAsynchronousCertValidationComplete() {
  ENVOY_CONN_LOG(debug, "Async cert validation completed", callbacks_->connection());
  if (info_->state() == Ssl::SocketState::HandshakeBlockedOnAsyncOperation) {
    resumeHandshake();
  }
}

void SslSocket::onAsynchronousCertificateSelectionComplete() {
  ENVOY_CONN_LOG(debug, "Async cert selection completed", callbacks_->connection());
  if (info_->state() != Ssl::SocketState::HandshakeBlockedOnAsyncOperation) {
    IS_ENVOY_BUG(fmt::format("unexpected handshake state: {}", static_cast<int>(info_->state())));
    return;
  }
  resumeHandshake();
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
