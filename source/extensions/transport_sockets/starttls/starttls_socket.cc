#include "source/extensions/transport_sockets/starttls/starttls_socket.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace StartTls {

Network::IoResult StartTlsSocket::doRead(Buffer::Instance& buffer) {
  if (using_tls_ || !remaining_cleartext_bytes_.has_value()) {
    return active_socket_->doRead(buffer);
  }

  // Bound the read so that a ClientHello coalesced with the last clear-text message stays in the
  // kernel for the TLS socket, instead of landing in the clear-text read buffer.
  if (*remaining_cleartext_bytes_ == 0) {
    return {Network::PostIoAction::KeepOpen, 0, false};
  }

  Api::IoCallUint64Result result = callbacks_.ioHandle().read(buffer, *remaining_cleartext_bytes_);
  if (!result.ok()) {
    ENVOY_CONN_LOG(trace, "cleartext read error: {}", callbacks_.connection(),
                   result.err_->getErrorDetails());
    if (result.err_->getErrorCode() == Api::IoError::IoErrorCode::Again) {
      return {Network::PostIoAction::KeepOpen, 0, false};
    }
    return {Network::PostIoAction::Close, 0, false, result.err_->getErrorCode()};
  }

  *remaining_cleartext_bytes_ -= result.return_value_;
  ENVOY_CONN_LOG(trace, "cleartext read: {}, remaining: {}", callbacks_.connection(),
                 result.return_value_, *remaining_cleartext_bytes_);
  if (result.return_value_ > 0 && *remaining_cleartext_bytes_ > 0) {
    // Only part of the budget was used, so more clear-text may still be pending.
    callbacks_.setTransportSocketIsReadable();
  }
  return {Network::PostIoAction::KeepOpen, result.return_value_, result.return_value_ == 0};
}

// Switch clear-text to secure transport.
bool StartTlsSocket::startSecureTransport() {
  if (!using_tls_) {
    tls_socket_->setTransportSocketCallbacks(callbacks_);
    tls_socket_->onConnected();
    // TODO(cpakulski): deleting active_socket_ assumes
    // that active_socket_ does not contain any buffered data.
    // Currently, active_socket_ is initialized to raw_buffer, which does not
    // buffer. If active_socket_ is initialized to a transport socket which
    // does buffering, it should be flushed before destroying or
    // flush should be called from destructor.
    active_socket_ = std::move(tls_socket_);
    callbacks_.connection().connectionInfoSetter().setSslConnection(active_socket_->ssl());
    using_tls_ = true;
    // A ClientHello may already be waiting in the kernel, and reads stop once the clear-text
    // boundary is reached, so re-arm reading now that TLS owns the connection.
    callbacks_.setTransportSocketIsReadable();
  }
  return true;
}

Network::TransportSocketPtr StartTlsSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsConstSharedPtr transport_socket_options,
    Upstream::HostDescriptionConstSharedPtr host) const {
  return std::make_unique<StartTlsSocket>(
      raw_socket_factory_->createTransportSocket(transport_socket_options, host),
      tls_socket_factory_->createTransportSocket(transport_socket_options, host),
      transport_socket_options);
}

Network::TransportSocketPtr
StartTlsDownstreamSocketFactory::createDownstreamTransportSocket() const {
  return std::make_unique<StartTlsSocket>(raw_socket_factory_->createDownstreamTransportSocket(),
                                          tls_socket_factory_->createDownstreamTransportSocket(),
                                          nullptr, max_cleartext_read_bytes_);
}

} // namespace StartTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
