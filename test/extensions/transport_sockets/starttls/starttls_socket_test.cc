#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "envoy/extensions/transport_sockets/starttls/v3/starttls.pb.h"
#include "envoy/extensions/transport_sockets/starttls/v3/starttls.pb.validate.h"
#include "envoy/network/connection.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/io_socket_error_impl.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/extensions/transport_sockets/starttls/starttls_socket.h"

#include "test/mocks/network/io_handle.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/network/transport_socket.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace StartTls {

using testing::_;
using testing::Invoke;
using testing::Optional;
using testing::Return;
using testing::ReturnRef;

class StartTlsTransportSocketMock : public Network::MockTransportSocket {
public:
  MOCK_METHOD(void, Die, ());
  ~StartTlsTransportSocketMock() override { Die(); }
};

TEST(StartTlsTest, BasicSwitch) {
  Network::TransportSocketOptionsConstSharedPtr options =
      std::make_shared<Network::TransportSocketOptionsImpl>();
  NiceMock<Network::MockTransportSocketCallbacks> transport_callbacks;
  NiceMock<StartTlsTransportSocketMock>* raw_socket = new NiceMock<StartTlsTransportSocketMock>;
  Network::MockTransportSocket* ssl_socket = new Network::MockTransportSocket;
  Buffer::OwnedImpl buf;

  std::unique_ptr<StartTlsSocket> socket = std::make_unique<StartTlsSocket>(
      Network::TransportSocketPtr(raw_socket), Network::TransportSocketPtr(ssl_socket), options);
  socket->setTransportSocketCallbacks(transport_callbacks);

  // StartTls socket is initial clear-text state. All calls should be forwarded to raw socket.
  ASSERT_THAT(socket->protocol(), "starttls");
  EXPECT_CALL(*raw_socket, onConnected());
  EXPECT_CALL(*ssl_socket, onConnected()).Times(0);
  socket->onConnected();

  EXPECT_CALL(*raw_socket, failureReason());
  EXPECT_CALL(*ssl_socket, failureReason()).Times(0);
  socket->failureReason();

  EXPECT_CALL(*raw_socket, canFlushClose());
  EXPECT_CALL(*ssl_socket, canFlushClose()).Times(0);
  socket->canFlushClose();

  EXPECT_CALL(*raw_socket, configureInitialCongestionWindow(100, std::chrono::microseconds(123)));
  EXPECT_CALL(*ssl_socket, configureInitialCongestionWindow(_, _)).Times(0);
  socket->configureInitialCongestionWindow(100, std::chrono::microseconds(123));

  EXPECT_CALL(*raw_socket, ssl());
  EXPECT_CALL(*ssl_socket, ssl()).Times(0);
  socket->ssl();

  EXPECT_CALL(*raw_socket, closeSocket(Network::ConnectionEvent::RemoteClose, false));
  EXPECT_CALL(*ssl_socket, closeSocket(Network::ConnectionEvent::RemoteClose, false)).Times(0);
  socket->closeSocket(Network::ConnectionEvent::RemoteClose, false);

  EXPECT_CALL(*raw_socket, doRead(_));
  EXPECT_CALL(*ssl_socket, doRead(_)).Times(0);
  socket->doRead(buf);

  EXPECT_CALL(*raw_socket, doWrite(_, true));
  EXPECT_CALL(*ssl_socket, doWrite(_, true)).Times(0);
  socket->doWrite(buf, true);

  // Now switch to Tls. During the switch, the new socket should register for callbacks
  // and connect.
  EXPECT_CALL(*ssl_socket, ssl());
  EXPECT_CALL(*ssl_socket, setTransportSocketCallbacks(_));
  EXPECT_CALL(*ssl_socket, onConnected);
  // Make sure that raw socket is destructed.
  EXPECT_CALL(*raw_socket, Die);
  socket->startSecureTransport();

  // Calling again should do nothing: No subsequent registration for callbacks
  // and no onConnected.
  socket->startSecureTransport();

  // Now calls to all methods should be forwarded to ssl_socket.
  // raw_socket has been destructed when switch to tls happened.
  ASSERT_THAT(socket->protocol(), "starttls");
  EXPECT_CALL(*ssl_socket, onConnected());
  socket->onConnected();

  EXPECT_CALL(*ssl_socket, failureReason());
  socket->failureReason();

  EXPECT_CALL(*ssl_socket, canFlushClose());
  socket->canFlushClose();

  EXPECT_CALL(*ssl_socket, configureInitialCongestionWindow(200, std::chrono::microseconds(223)));
  socket->configureInitialCongestionWindow(200, std::chrono::microseconds(223));

  EXPECT_CALL(*ssl_socket, ssl());
  socket->ssl();

  EXPECT_CALL(*ssl_socket, closeSocket(Network::ConnectionEvent::RemoteClose, false));
  socket->closeSocket(Network::ConnectionEvent::RemoteClose, false);

  EXPECT_CALL(*ssl_socket, doRead(_));
  socket->doRead(buf);

  EXPECT_CALL(*ssl_socket, doWrite(_, true));
  socket->doWrite(buf, true);
}

TEST(StartTlsTest, CallbackProxy) {

  Network::TransportSocketOptionsConstSharedPtr options =
      std::make_shared<Network::TransportSocketOptionsImpl>();
  Network::MockTransportSocketCallbacks transport_callbacks;
  NiceMock<Network::MockTransportSocket>* raw_socket = new NiceMock<Network::MockTransportSocket>;
  NiceMock<Network::MockTransportSocket>* ssl_socket = new NiceMock<Network::MockTransportSocket>;

  std::unique_ptr<StartTlsSocket> socket = std::make_unique<StartTlsSocket>(
      Network::TransportSocketPtr(raw_socket), Network::TransportSocketPtr(ssl_socket), options);
  socket->setTransportSocketCallbacks(transport_callbacks);

  // This is an instance of the StartTlsSocket::CallbackProxy which wraps the above
  // transport_callbacks
  Network::TransportSocketCallbacks* proxy = raw_socket->callbacks_;

  // Verify raiseEvent logic

  // Connected should only called once. When ssl_socket takes over it also raises Connected,
  // which we don't want to propagate.
  EXPECT_CALL(transport_callbacks, raiseEvent(Network::ConnectionEvent::Connected));
  EXPECT_CALL(transport_callbacks, flushWriteBuffer);
  proxy->raiseEvent(Network::ConnectionEvent::Connected);
  proxy->raiseEvent(Network::ConnectionEvent::Connected);

  // Should get multiples of other events
  EXPECT_CALL(transport_callbacks, raiseEvent(Network::ConnectionEvent::RemoteClose)).Times(2);
  proxy->raiseEvent(Network::ConnectionEvent::RemoteClose);
  proxy->raiseEvent(Network::ConnectionEvent::RemoteClose);

  // Connected should get raised again after !Connected but only once
  EXPECT_CALL(transport_callbacks, raiseEvent(Network::ConnectionEvent::Connected));
  EXPECT_CALL(transport_callbacks, flushWriteBuffer);
  proxy->raiseEvent(Network::ConnectionEvent::Connected);
  proxy->raiseEvent(Network::ConnectionEvent::Connected);

  // Verify all the passthrough functions work

  Network::MockIoHandle handle;
  EXPECT_CALL(transport_callbacks, ioHandle()).WillOnce(testing::ReturnRef(handle));
  proxy->ioHandle();

  // Check const version of ioHandle
  EXPECT_CALL(testing::Const(transport_callbacks), ioHandle()).WillOnce(testing::ReturnRef(handle));
  static_cast<const Network::TransportSocketCallbacks*>(proxy)->ioHandle();

  Network::MockConnection connection;
  EXPECT_CALL(transport_callbacks, connection()).WillOnce(testing::ReturnRef(connection));
  proxy->connection();

  EXPECT_CALL(transport_callbacks, shouldDrainReadBuffer()).WillOnce(testing::Return(true));
  proxy->shouldDrainReadBuffer();

  EXPECT_CALL(transport_callbacks, setTransportSocketIsReadable());
  proxy->setTransportSocketIsReadable();

  EXPECT_CALL(transport_callbacks, flushWriteBuffer());
  proxy->flushWriteBuffer();
}

// Factory test.
TEST(StartTls, BasicFactoryTest) {
  NiceMock<Network::MockTransportSocketFactory>* raw_buffer_factory =
      new NiceMock<Network::MockTransportSocketFactory>;
  NiceMock<Network::MockTransportSocketFactory>* ssl_factory =
      new NiceMock<Network::MockTransportSocketFactory>;
  std::unique_ptr<StartTlsSocketFactory> factory = std::make_unique<StartTlsSocketFactory>(
      Network::UpstreamTransportSocketFactoryPtr(raw_buffer_factory),
      Network::UpstreamTransportSocketFactoryPtr(ssl_factory));
  ASSERT_FALSE(factory->implementsSecureTransport());
  ASSERT_EQ(factory->sslCtx(), ssl_factory->sslCtx());
  ASSERT_EQ(factory->clientContextConfig().has_value(),
            ssl_factory->clientContextConfig().has_value());
  std::vector<uint8_t> key;
  factory->hashKey(key, nullptr);
  EXPECT_EQ(0, key.size());
}

// Fixture for the downstream clear-text read boundary. The socket reads directly from the io
// handle while the boundary is in force, so the raw socket only sees the other operations.
class StartTlsCleartextBoundaryTest : public testing::Test {
protected:
  void initialize(std::optional<uint64_t> max_cleartext_read_bytes) {
    ON_CALL(transport_callbacks_, ioHandle()).WillByDefault(ReturnRef(io_handle_));
    socket_ = std::make_unique<StartTlsSocket>(
        Network::TransportSocketPtr(raw_socket_), Network::TransportSocketPtr(tls_socket_),
        std::make_shared<Network::TransportSocketOptionsImpl>(), max_cleartext_read_bytes);
    socket_->setTransportSocketCallbacks(transport_callbacks_);
  }

  // Returns a read which appends `size` bytes and reports them as read.
  static auto readOf(uint64_t size) {
    return Invoke([size](Buffer::Instance& data, std::optional<uint64_t>) {
      data.add(std::string(size, 'a'));
      return Api::IoCallUint64Result(size, Api::IoError::none());
    });
  }

  NiceMock<Network::MockIoHandle> io_handle_;
  NiceMock<Network::MockTransportSocketCallbacks> transport_callbacks_;
  NiceMock<Network::MockTransportSocket>* raw_socket_{new NiceMock<Network::MockTransportSocket>};
  NiceMock<Network::MockTransportSocket>* tls_socket_{new NiceMock<Network::MockTransportSocket>};
  std::unique_ptr<StartTlsSocket> socket_;
  Buffer::OwnedImpl buffer_;
};

// Each read asks for the whole remaining budget, and the budget drops only by bytes actually read.
// A partly used budget re-arms reading, since more clear-text may still be pending.
TEST_F(StartTlsCleartextBoundaryTest, CapsReadsToRemainingBudget) {
  initialize(36);
  EXPECT_CALL(*raw_socket_, doRead(_)).Times(0);

  EXPECT_CALL(io_handle_, read(_, Optional(uint64_t{36}))).WillOnce(readOf(20));
  EXPECT_CALL(transport_callbacks_, setTransportSocketIsReadable());

  const Network::IoResult result = socket_->doRead(buffer_);
  EXPECT_EQ(Network::PostIoAction::KeepOpen, result.action_);
  EXPECT_EQ(20, result.bytes_processed_);
  EXPECT_FALSE(result.end_stream_read_);
  EXPECT_EQ(20, buffer_.length());

  EXPECT_CALL(io_handle_, read(_, Optional(uint64_t{16}))).WillOnce(readOf(16));
  EXPECT_EQ(16, socket_->doRead(buffer_).bytes_processed_);
}

// The boundary is permanent: once exhausted no further clear-text bytes are read, and reading is
// not re-armed, even though a network filter has drained the read buffer.
TEST_F(StartTlsCleartextBoundaryTest, StopsReadingOnceBoundaryReached) {
  initialize(36);

  EXPECT_CALL(io_handle_, read(_, Optional(uint64_t{36}))).WillOnce(readOf(36));
  EXPECT_CALL(transport_callbacks_, setTransportSocketIsReadable()).Times(0);
  EXPECT_EQ(36, socket_->doRead(buffer_).bytes_processed_);
  buffer_.drain(buffer_.length());

  EXPECT_CALL(io_handle_, read(_, _)).Times(0);
  const Network::IoResult result = socket_->doRead(buffer_);
  EXPECT_EQ(Network::PostIoAction::KeepOpen, result.action_);
  EXPECT_EQ(0, result.bytes_processed_);
  EXPECT_FALSE(result.end_stream_read_);
}

TEST_F(StartTlsCleartextBoundaryTest, PropagatesEndStream) {
  initialize(36);

  EXPECT_CALL(io_handle_, read(_, Optional(uint64_t{36})))
      .WillOnce(Return(testing::ByMove(Api::IoCallUint64Result(0, Api::IoError::none()))));
  EXPECT_CALL(transport_callbacks_, setTransportSocketIsReadable()).Times(0);

  const Network::IoResult result = socket_->doRead(buffer_);
  EXPECT_EQ(Network::PostIoAction::KeepOpen, result.action_);
  EXPECT_TRUE(result.end_stream_read_);
}

TEST_F(StartTlsCleartextBoundaryTest, KeepsConnectionOpenOnAgain) {
  initialize(36);

  EXPECT_CALL(io_handle_, read(_, Optional(uint64_t{36})))
      .WillOnce(Return(testing::ByMove(
          Api::IoCallUint64Result(0, Network::IoSocketError::getIoSocketEagainError()))));

  const Network::IoResult result = socket_->doRead(buffer_);
  EXPECT_EQ(Network::PostIoAction::KeepOpen, result.action_);
  EXPECT_EQ(0, result.bytes_processed_);
  EXPECT_FALSE(result.err_code_.has_value());
}

TEST_F(StartTlsCleartextBoundaryTest, ClosesOnReadError) {
  initialize(36);

  EXPECT_CALL(io_handle_, read(_, Optional(uint64_t{36})))
      .WillOnce(Return(testing::ByMove(
          Api::IoCallUint64Result(0, Network::IoSocketError::getIoSocketEbadfError()))));

  const Network::IoResult result = socket_->doRead(buffer_);
  EXPECT_EQ(Network::PostIoAction::Close, result.action_);
  EXPECT_EQ(Api::IoError::IoErrorCode::BadFd, result.err_code_);
}

// Without the option the read path is the wrapped raw buffer socket, unchanged.
TEST_F(StartTlsCleartextBoundaryTest, DelegatesToRawSocketWhenUnset) {
  initialize(std::nullopt);

  EXPECT_CALL(io_handle_, read(_, _)).Times(0);
  EXPECT_CALL(*raw_socket_, doRead(_));
  socket_->doRead(buffer_);
}

// Switching to TLS re-arms reading, so a ClientHello left in the kernel by the boundary is picked
// up by the TLS socket.
TEST_F(StartTlsCleartextBoundaryTest, SwitchToTlsRearmsReadAndTakesOverReads) {
  initialize(36);

  EXPECT_CALL(transport_callbacks_, setTransportSocketIsReadable());
  socket_->startSecureTransport();

  EXPECT_CALL(io_handle_, read(_, _)).Times(0);
  EXPECT_CALL(*tls_socket_, doRead(_));
  socket_->doRead(buffer_);
}

} // namespace StartTls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
