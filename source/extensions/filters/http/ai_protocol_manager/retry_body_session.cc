#include "source/extensions/filters/http/ai_protocol_manager/retry_body_session.h"

#include <utility>

#include "source/common/common/assert.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

class RetryBodySessionImpl::WriterImpl : public Writer {
public:
  explicit WriterImpl(std::shared_ptr<RetryBodySessionImpl> session)
      : session_(std::move(session)) {}
  ~WriterImpl() override { session_->detach(*this); }
  void append(Buffer::Instance& data) override { session_->append(data); }
  void end() override { session_->end(); }

private:
  const std::shared_ptr<RetryBodySessionImpl> session_;
};

class RetryBodySessionImpl::View : public ExternalBuffer {
public:
  explicit View(std::shared_ptr<RetryBodySessionImpl> session) : session_(std::move(session)) {}
  ~View() override {
    for (const PendingReadSharedPtr& read : reads_) {
      read->live = false;
    }
  }

  // ExternalBuffer
  void write(Buffer::InstancePtr data, bool end_stream, WriteCallback cb) override {
    cb(data->length() == 0 && end_stream && session_->ended_ && !session_->failed_
           ? ExternalBufferStatus::Ok
           : ExternalBufferStatus::Error);
  }
  void read(uint64_t offset, uint64_t length, ReadCallback cb) override {
    // Reads are few per attempt; the finished ones are dropped as new ones come.
    reads_.remove_if([](const PendingReadSharedPtr& read) { return !read->live; });
    auto read = std::make_shared<PendingRead>(PendingRead{offset, length, std::move(cb)});
    reads_.push_back(read);
    session_->read(read);
  }
  uint64_t length() const override { return session_->taken_; }

private:
  const std::shared_ptr<RetryBodySessionImpl> session_;
  std::list<PendingReadSharedPtr> reads_;
};

RetryBodySessionImpl::RetryBodySessionImpl(ExternalBufferPtr store, uint64_t high_watermark,
                                           uint32_t attempt)
    : store_(std::move(store)), high_watermark_(high_watermark), attempt_(attempt) {}

Http::RetryBodySession::WriterPtr RetryBodySessionImpl::attachWriter(WriterCallbacks& callbacks,
                                                                     uint64_t offset) {
  if (writer_ != nullptr || ended_ || failed_ || offset != taken_) {
    return nullptr;
  }
  auto writer = std::make_unique<WriterImpl>(shared_from_this());
  writer_ = writer.get();
  writer_callbacks_ = &callbacks;
  if (above_high_watermark_) {
    callbacks.onSessionAboveHighWatermark();
  }
  return writer;
}

void RetryBodySessionImpl::detach(WriterImpl& writer) {
  if (writer_ == &writer) {
    writer_ = nullptr;
    writer_callbacks_ = nullptr;
  }
}

void RetryBodySessionImpl::setDocument(const ParseTag& tag, const nlohmann::json& document) {
  if (document_ != nullptr) {
    return;
  }
  tag_ = tag;
  document_ = std::make_shared<const nlohmann::json>(document);
}

const nlohmann::json* RetryBodySessionImpl::document(const ParseTag& tag) const {
  return document_ != nullptr && tag == tag_ ? document_.get() : nullptr;
}

ExternalBufferPtr RetryBodySessionImpl::view() {
  return std::make_unique<View>(shared_from_this());
}

void RetryBodySessionImpl::append(Buffer::Instance& data) {
  ASSERT(!ended_);
  if (failed_) {
    data.drain(data.length());
    return;
  }
  taken_ += data.length();
  pending_.move(data);
  maybeWrite();
  updateWatermark();
}

void RetryBodySessionImpl::end() {
  ASSERT(!ended_);
  ended_ = true;
  maybeWrite();
}

void RetryBodySessionImpl::maybeWrite() {
  if (write_in_flight_ || failed_) {
    return;
  }
  const bool terminal = ended_ && !end_written_;
  if (pending_.length() == 0 && !terminal) {
    return;
  }
  // One write in flight at a time; whatever arrives meanwhile goes out as the next write.
  auto data = std::make_unique<Buffer::OwnedImpl>();
  in_flight_ = pending_.length();
  data->move(pending_);
  write_in_flight_ = true;
  end_written_ = ended_;
  store_->write(std::move(data), ended_,
                [this](ExternalBufferStatus status) { onWriteComplete(status); });
}

void RetryBodySessionImpl::onWriteComplete(ExternalBufferStatus status) {
  write_in_flight_ = false;
  in_flight_ = 0;
  if (status != ExternalBufferStatus::Ok) {
    fail();
    return;
  }
  updateWatermark();
  serviceWaitingReads();
  maybeWrite();
}

void RetryBodySessionImpl::fail() {
  if (failed_) {
    return;
  }
  ENVOY_LOG(warn, "ai_protocol_manager: retry session failed: its store failed a write");
  failed_ = true;
  pending_.drain(pending_.length());
  // Let a paused writer go before telling it, so it sees the session released.
  updateWatermark();
  std::list<PendingReadSharedPtr> reads;
  reads.swap(waiting_reads_);
  for (const PendingReadSharedPtr& read : reads) {
    if (read->live) {
      read->live = false;
      read->cb(ExternalBufferStatus::Error, nullptr);
    }
  }
  if (writer_callbacks_ != nullptr) {
    writer_callbacks_->onSessionFailed();
  }
}

void RetryBodySessionImpl::updateWatermark() {
  const uint64_t unstored = failed_ ? 0 : pending_.length() + in_flight_;
  if (!above_high_watermark_ && high_watermark_ != 0 && unstored > high_watermark_) {
    above_high_watermark_ = true;
    if (writer_callbacks_ != nullptr) {
      writer_callbacks_->onSessionAboveHighWatermark();
    }
  } else if (above_high_watermark_ && unstored <= high_watermark_ / 2) {
    above_high_watermark_ = false;
    if (writer_callbacks_ != nullptr) {
      writer_callbacks_->onSessionBelowLowWatermark();
    }
  }
}

void RetryBodySessionImpl::read(const PendingReadSharedPtr& read) {
  if (failed_ || read->offset + read->length > taken_) {
    read->live = false;
    read->cb(ExternalBufferStatus::Error, nullptr);
    return;
  }
  if (read->offset + read->length <= store_->length()) {
    issueRead(read);
  } else {
    waiting_reads_.push_back(read);
  }
}

void RetryBodySessionImpl::issueRead(const PendingReadSharedPtr& read) {
  store_->read(read->offset, read->length,
               [read](ExternalBufferStatus status, Buffer::InstancePtr data) {
                 if (!read->live) {
                   return;
                 }
                 read->live = false;
                 read->cb(status, std::move(data));
               });
}

void RetryBodySessionImpl::serviceWaitingReads() {
  const uint64_t stored = store_->length();
  std::list<PendingReadSharedPtr> ready;
  for (auto it = waiting_reads_.begin(); it != waiting_reads_.end();) {
    if (!(*it)->live || (*it)->offset + (*it)->length <= stored) {
      if ((*it)->live) {
        ready.push_back(*it);
      }
      it = waiting_reads_.erase(it);
    } else {
      ++it;
    }
  }
  for (const PendingReadSharedPtr& read : ready) {
    if (read->live) {
      issueRead(read);
    }
  }
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
