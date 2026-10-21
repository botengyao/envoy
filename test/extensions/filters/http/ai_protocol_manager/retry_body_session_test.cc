#include <deque>
#include <memory>
#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/retry_body_session.h"

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

class FailingWriteBuffer : public ExternalBuffer {
public:
  void write(Buffer::InstancePtr, bool, WriteCallback cb) override {
    cb(ExternalBufferStatus::Error);
  }
  void read(uint64_t, uint64_t, ReadCallback cb) override {
    cb(ExternalBufferStatus::Error, nullptr);
  }
  uint64_t length() const override { return 0; }
};

class TestWriter : public Http::RetryBodySession::WriterCallbacks {
public:
  void onSessionAboveHighWatermark() override { ++above_; }
  void onSessionBelowLowWatermark() override { ++below_; }
  void onSessionFailed() override { ++failed_; }
  int above_{0};
  int below_{0};
  int failed_{0};
};

const RetryBodySessionImpl::ParseTag GeminiTag{LLMProtocol::GeminiGenerateContent, 1024};

class RetryBodySessionTest : public testing::Test {
public:
  RetryBodySessionTest() {
    ON_CALL(dispatcher_, post(testing::_)).WillByDefault(Invoke([this](Event::PostCb cb) {
      posted_.push_back(std::move(cb));
    }));
  }

  std::shared_ptr<RetryBodySessionImpl> makeSession(ExternalBufferPtr store = nullptr,
                                                    uint64_t high_watermark = 0) {
    if (store == nullptr) {
      store = InMemoryExternalBufferFactory().createBuffer(dispatcher_);
    }
    auto session =
        std::make_shared<RetryBodySessionImpl>(std::move(store), high_watermark, /*attempt=*/1);
    writer_ = session->attachWriter(callbacks_, 0);
    return session;
  }

  void append(absl::string_view bytes) {
    Buffer::OwnedImpl data(bytes);
    writer_->append(data);
  }

  void drain() {
    while (!posted_.empty()) {
      Event::PostCb cb = std::move(posted_.front());
      posted_.pop_front();
      cb();
    }
  }

  // Reads through `view` and drains the dispatcher; returns the bytes, "error" or "<pending>".
  std::string readOnce(ExternalBuffer& view, uint64_t offset, uint64_t length) {
    std::string out = "<pending>";
    view.read(offset, length, [&out](ExternalBufferStatus status, Buffer::InstancePtr data) {
      out = status == ExternalBufferStatus::Ok ? data->toString() : "error";
    });
    drain();
    return out;
  }

  NiceMock<Event::MockDispatcher> dispatcher_;
  std::deque<Event::PostCb> posted_;
  TestWriter callbacks_;
  Http::RetryBodySession::WriterPtr writer_;
};

TEST_F(RetryBodySessionTest, TakesTheBodyAndEnds) {
  auto session = makeSession();
  append("{}");
  EXPECT_EQ(session->length(), 2);
  EXPECT_FALSE(session->ended());
  writer_->end();
  EXPECT_TRUE(session->ended());
  EXPECT_FALSE(session->failed());
}

// The document is offered only to a filter that parses the same way.
TEST_F(RetryBodySessionTest, DocumentOnlyForTheSameParse) {
  auto session = makeSession();
  EXPECT_EQ(session->document(GeminiTag), nullptr);
  session->setDocument(GeminiTag, nlohmann::json{{"contents", nlohmann::json::array()}});
  ASSERT_NE(session->document(GeminiTag), nullptr);
  EXPECT_TRUE(session->document(GeminiTag)->contains("contents"));
  EXPECT_EQ(session->document({LLMProtocol::GeminiGenerateContent, 2048}), nullptr);
  EXPECT_EQ(session->document({LLMProtocol::OpenAiChatCompletions, 1024}), nullptr);
}

// An attempt's view is the session as it stands; it takes only the empty write ending the
// payload, and only once the session has ended.
TEST_F(RetryBodySessionTest, ViewTakesOnlyTheEndWrite) {
  auto session = makeSession();
  append("hello");
  ExternalBufferPtr view = session->view();
  EXPECT_EQ(view->length(), 5);

  ExternalBufferStatus status = ExternalBufferStatus::Ok;
  view->write(std::make_unique<Buffer::OwnedImpl>(), true,
              [&](ExternalBufferStatus s) { status = s; });
  EXPECT_EQ(status, ExternalBufferStatus::Error);
  writer_->end();
  view->write(std::make_unique<Buffer::OwnedImpl>(), true,
              [&](ExternalBufferStatus s) { status = s; });
  EXPECT_EQ(status, ExternalBufferStatus::Ok);
  view->write(std::make_unique<Buffer::OwnedImpl>("x"), true,
              [&](ExternalBufferStatus s) { status = s; });
  EXPECT_EQ(status, ExternalBufferStatus::Error);
}

// A read waits until the store holds every byte it covers.
TEST_F(RetryBodySessionTest, ReadsWaitForTheStore) {
  auto session = makeSession();
  ExternalBufferPtr view = session->view();
  append("hello");
  std::string out = "<pending>";
  view->read(1, 3, [&out](ExternalBufferStatus status, Buffer::InstancePtr data) {
    out = status == ExternalBufferStatus::Ok ? data->toString() : "error";
  });
  EXPECT_EQ(out, "<pending>");
  drain();
  EXPECT_EQ(out, "ell");
  EXPECT_EQ(readOnce(*view, 0, 5), "hello");
  // Past what the session has taken.
  EXPECT_EQ(readOnce(*view, 3, 5), "error");
}

TEST_F(RetryBodySessionTest, DestroyingTheViewCancelsItsReads) {
  auto session = makeSession();
  ExternalBufferPtr view = session->view();
  append("hello");
  bool called = false;
  view->read(0, 5, [&called](ExternalBufferStatus, Buffer::InstancePtr) { called = true; });
  view.reset();
  drain();
  EXPECT_FALSE(called);
}

// Bytes taken but not yet stored push back on the writer, and let it go once stored.
TEST_F(RetryBodySessionTest, BackPressuresTheWriter) {
  auto session = makeSession(nullptr, /*high_watermark=*/4);
  append("hello");
  EXPECT_EQ(callbacks_.above_, 1);
  drain();
  EXPECT_EQ(callbacks_.below_, 1);
}

// A store that fails fails the waiting reads and tells the writer, releasing its back-pressure
// first.
TEST_F(RetryBodySessionTest, StoreFailureFailsReadsAndTellsTheWriter) {
  auto session = makeSession(std::make_unique<FailingWriteBuffer>(), /*high_watermark=*/2);
  append("hello");
  EXPECT_TRUE(session->failed());
  EXPECT_EQ(callbacks_.failed_, 1);
  EXPECT_EQ(callbacks_.above_, callbacks_.below_);
  ExternalBufferPtr view = session->view();
  EXPECT_EQ(readOnce(*view, 0, 1), "error");
  EXPECT_EQ(session->attachWriter(callbacks_, session->length()), nullptr);
}

// One writer at a time; the next attaches where the last stopped, and is told at once when the
// session is still pushing back.
TEST_F(RetryBodySessionTest, WriterHandsOffAtTheSessionsLength) {
  auto session = makeSession(nullptr, /*high_watermark=*/4);
  TestWriter next;
  EXPECT_TRUE(session->hasWriter());
  EXPECT_EQ(session->attachWriter(next, 0), nullptr);
  append("hello");
  writer_.reset();
  EXPECT_FALSE(session->hasWriter());

  EXPECT_EQ(session->attachWriter(next, 4), nullptr);
  auto writer = session->attachWriter(next, 5);
  ASSERT_NE(writer, nullptr);
  EXPECT_EQ(next.above_, 1);
  drain();
  EXPECT_EQ(next.below_, 1);

  Buffer::OwnedImpl rest(" world");
  writer->append(rest);
  writer->end();
  drain();
  EXPECT_EQ(session->attachWriter(callbacks_, session->length()), nullptr);
  ExternalBufferPtr view = session->view();
  EXPECT_EQ(readOnce(*view, 0, 11), "hello world");
}

TEST_F(RetryBodySessionTest, AdoptStampsTheAttemptAndHandOverSticks) {
  auto session = makeSession();
  EXPECT_EQ(session->attempt(), 1);
  session->adopt(3);
  EXPECT_EQ(session->attempt(), 3);
  EXPECT_FALSE(session->handedOver());
  session->handOver();
  EXPECT_TRUE(session->handedOver());
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
