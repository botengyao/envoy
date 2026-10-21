#include <deque>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/tiered_external_buffer.h"

#include "test/mocks/event/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Invoke;
using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

// A backing buffer that records its writes and acknowledges them on a later pass.
class FakeBacking : public ExternalBuffer {
public:
  FakeBacking(Event::Dispatcher& dispatcher, bool fail) : dispatcher_(dispatcher), fail_(fail) {}
  ~FakeBacking() override { *alive_ = false; }

  void write(Buffer::InstancePtr data, bool end_stream, WriteCallback cb) override {
    writes_.emplace_back(data->toString(), end_stream);
    dispatcher_.post([this, alive = alive_, data = std::move(data), cb = std::move(cb)]() mutable {
      if (!*alive) {
        return;
      }
      if (fail_) {
        cb(ExternalBufferStatus::Error);
        return;
      }
      data_.move(*data);
      cb(ExternalBufferStatus::Ok);
    });
  }
  void read(uint64_t offset, uint64_t length, ReadCallback cb) override {
    auto out = std::make_unique<Buffer::OwnedImpl>();
    out->add(data_.toString().substr(offset, length));
    cb(ExternalBufferStatus::Ok, std::move(out));
  }
  uint64_t length() const override { return data_.length(); }

  std::vector<std::pair<std::string, bool>> writes_;

private:
  Event::Dispatcher& dispatcher_;
  const bool fail_;
  Buffer::OwnedImpl data_;
  std::shared_ptr<bool> alive_{std::make_shared<bool>(true)};
};

class FakeBackingFactory : public ExternalBufferFactory {
public:
  explicit FakeBackingFactory(bool fail = false) : fail_(fail) {}
  using ExternalBufferFactory::createBuffer;
  ExternalBufferPtr createBuffer(Event::Dispatcher& dispatcher) override {
    auto buffer = std::make_unique<FakeBacking>(dispatcher, fail_);
    created_ = buffer.get();
    ++creations_;
    return buffer;
  }

  FakeBacking* created_{};
  int creations_{0};

private:
  const bool fail_;
};

class TieredExternalBufferTest : public testing::Test {
public:
  TieredExternalBufferTest() {
    ON_CALL(dispatcher_, post(testing::_)).WillByDefault(Invoke([this](Event::PostCb cb) {
      posted_.push_back(std::move(cb));
    }));
  }

  void makeBuffer(uint64_t limit, bool fail = false) {
    factory_ = std::make_shared<FakeBackingFactory>(fail);
    buffer_ = std::make_unique<TieredExternalBuffer>(dispatcher_, factory_, limit);
  }

  // Writes `bytes` and returns where its acknowledgment stands after draining the dispatcher.
  std::string writeAndDrain(absl::string_view bytes, bool end_stream = false) {
    std::string status = "<pending>";
    buffer_->write(std::make_unique<Buffer::OwnedImpl>(bytes), end_stream,
                   [&status](ExternalBufferStatus s) {
                     status = s == ExternalBufferStatus::Ok ? "ok" : "error";
                   });
    drain();
    return status;
  }

  std::string readNow(uint64_t offset, uint64_t length) {
    std::string out = "<pending>";
    buffer_->read(offset, length, [&out](ExternalBufferStatus s, Buffer::InstancePtr data) {
      out = s == ExternalBufferStatus::Ok ? data->toString() : "error";
    });
    return out;
  }

  void drain() {
    while (!posted_.empty()) {
      Event::PostCb cb = std::move(posted_.front());
      posted_.pop_front();
      cb();
    }
  }

  NiceMock<Event::MockDispatcher> dispatcher_;
  std::deque<Event::PostCb> posted_;
  std::shared_ptr<FakeBackingFactory> factory_;
  std::unique_ptr<TieredExternalBuffer> buffer_;
};

// Up to the limit the payload stays in memory: no backing buffer, acknowledged on a later pass,
// read on-stack.
TEST_F(TieredExternalBufferTest, StaysInMemoryUpToTheLimit) {
  makeBuffer(10);
  std::string status = "<pending>";
  buffer_->write(std::make_unique<Buffer::OwnedImpl>("hello"), false,
                 [&status](ExternalBufferStatus) { status = "ok"; });
  EXPECT_EQ(status, "<pending>");
  EXPECT_EQ(buffer_->length(), 0);
  drain();
  EXPECT_EQ(status, "ok");
  EXPECT_EQ(buffer_->length(), 5);
  EXPECT_EQ(readNow(1, 3), "ell");
  EXPECT_EQ(factory_->creations_, 0);
}

TEST_F(TieredExternalBufferTest, APayloadAtTheLimitStaysInMemory) {
  makeBuffer(10);
  EXPECT_EQ(writeAndDrain("hello"), "ok");
  EXPECT_EQ(writeAndDrain("world", true), "ok");
  EXPECT_EQ(factory_->creations_, 0);
  EXPECT_EQ(buffer_->length(), 10);
  EXPECT_EQ(readNow(3, 4), "lowo");
}

// The write that passes the limit sends the held bytes and its own as one write at offset 0;
// everything after goes straight through.
TEST_F(TieredExternalBufferTest, SpillsTheHeldBytesWithTheCrossingWrite) {
  makeBuffer(4);
  EXPECT_EQ(writeAndDrain("abc"), "ok");
  EXPECT_EQ(writeAndDrain("defg"), "ok");
  ASSERT_EQ(factory_->creations_, 1);
  ASSERT_EQ(factory_->created_->writes_.size(), 1);
  EXPECT_EQ(factory_->created_->writes_[0].first, "abcdefg");
  EXPECT_EQ(buffer_->length(), 7);
  EXPECT_EQ(writeAndDrain("h", true), "ok");
  ASSERT_EQ(factory_->created_->writes_.size(), 2);
  EXPECT_TRUE(factory_->created_->writes_[1].second);
  EXPECT_EQ(buffer_->length(), 8);
  EXPECT_EQ(readNow(2, 5), "cdefg");
}

TEST_F(TieredExternalBufferTest, ASpillCarriesTheEndOfStream) {
  makeBuffer(2);
  EXPECT_EQ(writeAndDrain("abc", true), "ok");
  ASSERT_EQ(factory_->created_->writes_.size(), 1);
  EXPECT_TRUE(factory_->created_->writes_[0].second);
}

// While the held bytes are on their way, reads wait for them.
TEST_F(TieredExternalBufferTest, ReadsDuringTheSpillWait) {
  makeBuffer(4);
  EXPECT_EQ(writeAndDrain("abc"), "ok");
  buffer_->write(std::make_unique<Buffer::OwnedImpl>("defg"), false, [](ExternalBufferStatus) {});
  EXPECT_EQ(buffer_->length(), 3);
  std::string out = readNow(0, 3);
  EXPECT_EQ(out, "<pending>");
  std::string deferred = "<pending>";
  buffer_->read(1, 2, [&deferred](ExternalBufferStatus s, Buffer::InstancePtr data) {
    deferred = s == ExternalBufferStatus::Ok ? data->toString() : "error";
  });
  drain();
  EXPECT_EQ(deferred, "bc");
}

// A spill that fails fails its write, the reads waiting on it, and everything after.
TEST_F(TieredExternalBufferTest, AFailedSpillFailsEverything) {
  makeBuffer(4, /*fail=*/true);
  EXPECT_EQ(writeAndDrain("abc"), "ok");
  std::string status = "<pending>";
  buffer_->write(std::make_unique<Buffer::OwnedImpl>("defg"), false,
                 [&status](ExternalBufferStatus s) {
                   status = s == ExternalBufferStatus::Ok ? "ok" : "error";
                 });
  std::string deferred = "<pending>";
  buffer_->read(0, 3, [&deferred](ExternalBufferStatus s, Buffer::InstancePtr) {
    deferred = s == ExternalBufferStatus::Ok ? "ok" : "error";
  });
  drain();
  EXPECT_EQ(status, "error");
  EXPECT_EQ(deferred, "error");
  EXPECT_EQ(writeAndDrain("h"), "error");
  EXPECT_EQ(readNow(0, 1), "error");
}

// Destroying the buffer cancels a pending acknowledgment.
TEST_F(TieredExternalBufferTest, DestructionCancelsPendingCallbacks) {
  makeBuffer(10);
  bool called = false;
  buffer_->write(std::make_unique<Buffer::OwnedImpl>("abc"), false,
                 [&called](ExternalBufferStatus) { called = true; });
  buffer_.reset();
  drain();
  EXPECT_FALSE(called);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
