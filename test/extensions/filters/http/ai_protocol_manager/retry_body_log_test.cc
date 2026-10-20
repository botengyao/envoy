#include <deque>
#include <memory>
#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/retry_body_log.h"

#include "test/mocks/event/mocks.h"
#include "test/test_common/status_utility.h"

#include "absl/crc/crc32c.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Invoke;
using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

class FailingWriteBuffer : public ExternalBuffer {
public:
  explicit FailingWriteBuffer(Event::Dispatcher& dispatcher) : dispatcher_(dispatcher) {}
  void write(Buffer::InstancePtr, bool, WriteCallback cb) override {
    dispatcher_.post([cb = std::move(cb)]() mutable { cb(ExternalBufferStatus::Error); });
  }
  void read(uint64_t, uint64_t, ReadCallback cb) override {
    cb(ExternalBufferStatus::Error, nullptr);
  }
  uint64_t length() const override { return 0; }

private:
  Event::Dispatcher& dispatcher_;
};

class FailingWriteBufferFactory : public ExternalBufferFactory {
public:
  using ExternalBufferFactory::createBuffer;
  ExternalBufferPtr createBuffer(Event::Dispatcher& dispatcher) override {
    return std::make_unique<FailingWriteBuffer>(dispatcher);
  }
};

class TestWriter : public Http::RequestBodyLog::WriterCallbacks {
public:
  void onLogAboveHighWatermark() override { ++above_; }
  void onLogBelowLowWatermark() override { ++below_; }
  void onLogFailed() override { ++failed_; }
  int above_{0};
  int below_{0};
  int failed_{0};
};

class RequestBodyLogTest : public testing::Test {
public:
  RequestBodyLogTest() {
    ON_CALL(dispatcher_, post(testing::_)).WillByDefault(Invoke([this](Event::PostCb cb) {
      posted_.push_back(std::move(cb));
    }));
  }

  std::shared_ptr<ExternalBufferRequestBodyLog> makeLog(
      uint64_t high_watermark = 0,
      ExternalBufferFactorySharedPtr factory = std::make_shared<InMemoryExternalBufferFactory>(),
      uint64_t max_length = 0) {
    auto log = std::make_shared<ExternalBufferRequestBodyLog>(dispatcher_, std::move(factory),
                                                              high_watermark, max_length);
    handle_ = log->attachWriter(writer_);
    return log;
  }

  void append(absl::string_view bytes) {
    Buffer::OwnedImpl data(bytes);
    handle_->append(data);
  }

  void drain() {
    while (!posted_.empty()) {
      Event::PostCb cb = std::move(posted_.front());
      posted_.pop_front();
      cb();
    }
  }

  // Reads from `offset` and drains the dispatcher; returns what one read delivered, or "error".
  std::string readOnce(Http::RequestBodyLog& log, uint64_t offset, uint64_t max_length) {
    std::string out = "<pending>";
    auto handle = log.read(offset, max_length, [&out](absl::StatusOr<Buffer::InstancePtr> data) {
      out = data.ok() ? (*data)->toString() : "error";
    });
    drain();
    return out;
  }

  NiceMock<Event::MockDispatcher> dispatcher_;
  std::deque<Event::PostCb> posted_;
  TestWriter writer_;
  Http::RequestBodyLog::WriterPtr handle_;
};

// Bytes become readable once the store acknowledges them; a read for them waits until then.
TEST_F(RequestBodyLogTest, ReadsWaitForTheStoreToAcknowledge) {
  auto log = makeLog();
  EXPECT_TRUE(log->writing());
  EXPECT_EQ(log->attachWriter(writer_), nullptr);
  append("hello ");

  std::string out = "<pending>";
  auto handle = log->read(0, 100, [&out](absl::StatusOr<Buffer::InstancePtr> data) {
    ASSERT_OK(data.status());
    out = (*data)->toString();
  });
  EXPECT_EQ(out, "<pending>");
  drain();
  EXPECT_EQ(out, "hello ");

  append("world");
  handle_->end();
  EXPECT_EQ(readOnce(*log, 6, 100), "world");
  EXPECT_TRUE(log->ended());
  EXPECT_EQ(log->length(), 11);
  EXPECT_EQ(log->crc32c(), static_cast<uint32_t>(absl::ComputeCrc32c("hello world")));
}

// A read covering acknowledged and unacknowledged bytes delivers the acknowledged part.
TEST_F(RequestBodyLogTest, ReadDeliversTheAcknowledgedPrefix) {
  auto log = makeLog();
  append("abc");
  drain();
  append("def");
  EXPECT_EQ(readOnce(*log, 0, 100), "abc");
  EXPECT_EQ(readOnce(*log, 3, 100), "def");
}

// Destroying the handle of a waiting read cancels it.
TEST_F(RequestBodyLogTest, CancelledReadNeverCallsBack) {
  auto log = makeLog();
  append("abc");
  bool called = false;
  auto handle = log->read(0, 3, [&called](absl::StatusOr<Buffer::InstancePtr>) { called = true; });
  ASSERT_NE(handle, nullptr);
  handle.reset();
  drain();
  EXPECT_FALSE(called);
}

// The writer is paused while unacknowledged bytes exceed the high watermark, and resumed once the
// store catches up to half of it.
TEST_F(RequestBodyLogTest, BackPressuresTheWriter) {
  auto log = makeLog(/*high_watermark=*/4);
  append("12345678");
  EXPECT_EQ(writer_.above_, 1);
  EXPECT_EQ(writer_.below_, 0);
  drain();
  EXPECT_EQ(writer_.below_, 1);
}

// A failed write makes the log unreadable and releases the writer.
TEST_F(RequestBodyLogTest, WriteErrorFailsReadsAndReleasesTheWriter) {
  auto log = makeLog(/*high_watermark=*/4, std::make_shared<FailingWriteBufferFactory>());
  append("12345678");
  EXPECT_EQ(writer_.above_, 1);
  std::string out = "<pending>";
  auto handle = log->read(0, 8, [&out](absl::StatusOr<Buffer::InstancePtr> data) {
    out = data.ok() ? (*data)->toString() : "error";
  });
  drain();
  EXPECT_EQ(out, "error");
  EXPECT_EQ(writer_.below_, 1);
  EXPECT_EQ(writer_.failed_, 1);
  EXPECT_TRUE(log->failed());
  EXPECT_FALSE(log->writing());
  EXPECT_EQ(readOnce(*log, 0, 1), "error");
}

// A body past the log's limit fails it, so the writer gives up on retrying from it.
TEST_F(RequestBodyLogTest, BodyPastTheLimitFailsTheLog) {
  auto log = makeLog(0, std::make_shared<InMemoryExternalBufferFactory>(), /*max_length=*/8);
  append("12345");
  EXPECT_EQ(writer_.failed_, 0);
  append("6789");
  EXPECT_EQ(writer_.failed_, 1);
  EXPECT_TRUE(log->failed());
  EXPECT_EQ(log->length(), 5);
}

// Destroying the writer's handle detaches it, so no borrower relies on a log nobody writes.
TEST_F(RequestBodyLogTest, DestroyingTheWriterDetachesIt) {
  auto log = makeLog();
  EXPECT_TRUE(log->writing());
  handle_.reset();
  EXPECT_FALSE(log->writing());
}

// An upstream BufferManager's writes are checked against the log and its reads come from it.
TEST_F(RequestBodyLogTest, LogBackedBufferReadsTheLog) {
  auto log = makeLog();
  append("hello world");
  handle_->end();

  LogBackedExternalBuffer buffer(log);
  ExternalBufferStatus first = ExternalBufferStatus::Error;
  ExternalBufferStatus last = ExternalBufferStatus::Error;
  buffer.write(std::make_unique<Buffer::OwnedImpl>("hello "), false,
               [&first](ExternalBufferStatus status) { first = status; });
  buffer.write(std::make_unique<Buffer::OwnedImpl>("world"), true,
               [&last](ExternalBufferStatus status) { last = status; });
  EXPECT_EQ(first, ExternalBufferStatus::Ok);
  EXPECT_EQ(last, ExternalBufferStatus::Ok);
  EXPECT_EQ(buffer.length(), 11);

  std::string out;
  buffer.read(0, 11, [&out](ExternalBufferStatus status, Buffer::InstancePtr data) {
    ASSERT_EQ(status, ExternalBufferStatus::Ok);
    out = data->toString();
  });
  drain();
  EXPECT_EQ(out, "hello world");
}

// The final write fails for bytes the router did not send, as when a filter ahead of the
// ai_protocol_manager changed the body.
TEST_F(RequestBodyLogTest, LogBackedBufferRejectsBytesTheRouterDidNotSend) {
  auto log = makeLog();
  append("hello world");
  handle_->end();

  LogBackedExternalBuffer buffer(log);
  ExternalBufferStatus status = ExternalBufferStatus::Ok;
  buffer.write(std::make_unique<Buffer::OwnedImpl>("HELLO world"), true,
               [&status](ExternalBufferStatus s) { status = s; });
  EXPECT_EQ(status, ExternalBufferStatus::Error);
}

// Without a writer the log would never hold the body, so the filter keeps a copy of its own.
TEST_F(RequestBodyLogTest, BorrowsOnlyWhenTheRouterWritesTheLog) {
  auto unwritten = std::make_shared<ExternalBufferRequestBodyLog>(
      dispatcher_, std::make_shared<InMemoryExternalBufferFactory>(), 0, 0);
  InMemoryExternalBufferFactory fallback;
  BorrowingExternalBufferFactory without_writer(unwritten, fallback, std::nullopt);
  EXPECT_NE(dynamic_cast<InMemoryExternalBuffer*>(without_writer.createBuffer(dispatcher_).get()),
            nullptr);

  BorrowingExternalBufferFactory with_writer(makeLog(), fallback, std::nullopt);
  EXPECT_NE(dynamic_cast<LogBackedExternalBuffer*>(with_writer.createBuffer(dispatcher_).get()),
            nullptr);
}

// A bounded log is borrowed only for a body known to fit; anything else keeps its own copy.
TEST_F(RequestBodyLogTest, BorrowsABoundedLogOnlyForABodyThatFits) {
  auto log = makeLog(0, std::make_shared<InMemoryExternalBufferFactory>(), /*max_length=*/100);
  InMemoryExternalBufferFactory fallback;
  BorrowingExternalBufferFactory fits(log, fallback, 100);
  EXPECT_NE(dynamic_cast<LogBackedExternalBuffer*>(fits.createBuffer(dispatcher_).get()), nullptr);
  BorrowingExternalBufferFactory too_long(log, fallback, 101);
  EXPECT_NE(dynamic_cast<InMemoryExternalBuffer*>(too_long.createBuffer(dispatcher_).get()),
            nullptr);
  BorrowingExternalBufferFactory unknown(log, fallback, std::nullopt);
  EXPECT_NE(dynamic_cast<InMemoryExternalBuffer*>(unknown.createBuffer(dispatcher_).get()),
            nullptr);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
