#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/network/io_handle.h"

#include "openssl/bio.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

/**
 * Creates a custom BIO that can read from/write to an IoHandle. It's equivalent to a socket BIO
 * but instead of relying on access to an fd, it relies on IoHandle APIs for all interactions. The
 * IoHandle must remain valid for the lifetime of the BIO.
 */
// NOLINTNEXTLINE(readability-identifier-naming)
BIO* BIO_new_io_handle(Envoy::Network::IoHandle* io_handle);

/**
 * Queues data on the read side of a BIO created by BIO_new_io_handle(). Reads return it ahead of
 * anything read from the IoHandle, e.g. bytes a clear-text transport socket received before the
 * connection switched to TLS. The buffer is drained.
 */
// NOLINTNEXTLINE(readability-identifier-naming)
void BIO_io_handle_inject_read_data(BIO* bio, Envoy::Buffer::Instance& data);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
