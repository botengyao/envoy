#include "source/extensions/filters/http/ai_protocol_manager/retry_body_log.h"

#include <algorithm>
#include <utility>

#include "source/common/common/assert.h"

#include "absl/status/status.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

absl::crc32c_t extendCrc(absl::crc32c_t crc, const Buffer::Instance& data) {
  for (const Buffer::RawSlice& slice : data.getRawSlices()) {
    crc = absl::ExtendCrc32c(crc,
                             absl::string_view(static_cast<const char*>(slice.mem_), slice.len_));
  }
  return crc;
}

template <class T> class LivenessHandle : public Http::RequestBodyLog::ReadHandle {
public:
  explicit LivenessHandle(std::shared_ptr<T> read) : read_(std::move(read)) {}
  ~LivenessHandle() override { read_->live = false; }

private:
  std::shared_ptr<T> read_;
};

} // namespace

ExternalBufferRequestBodyLog::ExternalBufferRequestBodyLog(Event::Dispatcher& dispatcher,
                                                           ExternalBufferFactorySharedPtr factory,
                                                           uint64_t high_watermark,
                                                           uint64_t max_length)
    : dispatcher_(dispatcher), factory_(std::move(factory)), high_watermark_(high_watermark),
      max_length_(max_length) {}

Http::RequestBodyLog::WriterPtr
ExternalBufferRequestBodyLog::attachWriter(WriterCallbacks& callbacks) {
  if (had_writer_ || appended_ != 0) {
    return nullptr;
  }
  had_writer_ = true;
  writer_ = &callbacks;
  return std::make_unique<WriterImpl>(shared_from_this());
}

void ExternalBufferRequestBodyLog::append(Buffer::Instance& data) {
  ASSERT(!ended_);
  if (failed_) {
    data.drain(data.length());
    return;
  }
  if (max_length_ != 0 && appended_ + data.length() > max_length_) {
    data.drain(data.length());
    fail("the body is longer than the log's limit");
    return;
  }
  crc_ = extendCrc(crc_, data);
  appended_ += data.length();
  pending_.move(data);
  if (store_ == nullptr) {
    store_ = factory_->createBuffer(dispatcher_);
  }
  maybeWrite();
  updateWatermark();
}

void ExternalBufferRequestBodyLog::end() {
  ASSERT(!ended_);
  ended_ = true;
  if (store_ == nullptr && !failed_) {
    store_ = factory_->createBuffer(dispatcher_);
  }
  maybeWrite();
}

void ExternalBufferRequestBodyLog::maybeWrite() {
  if (store_ == nullptr || write_in_flight_ || failed_) {
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

void ExternalBufferRequestBodyLog::onWriteComplete(ExternalBufferStatus status) {
  write_in_flight_ = false;
  in_flight_ = 0;
  if (status != ExternalBufferStatus::Ok) {
    fail("its store failed a write");
    return;
  }
  updateWatermark();
  serviceWaitingReads();
  maybeWrite();
}

void ExternalBufferRequestBodyLog::fail(absl::string_view reason) {
  if (failed_) {
    return;
  }
  ENVOY_LOG(warn, "ai_protocol_manager: request body log failed: {}", reason);
  failed_ = true;
  pending_.drain(pending_.length());
  // Let a paused writer go before telling it, so it sees the log released.
  updateWatermark();
  std::list<PendingReadSharedPtr> reads;
  reads.swap(waiting_reads_);
  for (const PendingReadSharedPtr& read : reads) {
    if (read->live) {
      read->live = false;
      read->cb(absl::UnavailableError("request body log failed"));
    }
  }
  if (writer_ != nullptr) {
    writer_->onLogFailed();
  }
}

void ExternalBufferRequestBodyLog::updateWatermark() {
  if (writer_ == nullptr || high_watermark_ == 0) {
    return;
  }
  const uint64_t unacked = failed_ ? 0 : pending_.length() + in_flight_;
  if (!above_high_watermark_ && unacked > high_watermark_) {
    above_high_watermark_ = true;
    writer_->onLogAboveHighWatermark();
  } else if (above_high_watermark_ && unacked <= high_watermark_ / 2) {
    above_high_watermark_ = false;
    writer_->onLogBelowLowWatermark();
  }
}

Http::RequestBodyLog::ReadHandlePtr
ExternalBufferRequestBodyLog::read(uint64_t offset, uint64_t max_length, ReadCallback cb) {
  if (failed_ || offset >= appended_ || max_length == 0) {
    cb(absl::FailedPreconditionError("request body log is not readable at this offset"));
    return nullptr;
  }
  auto read = std::make_shared<PendingRead>(PendingRead{offset, max_length, std::move(cb)});
  if (offset < durableLength()) {
    issueRead(read);
    if (!read->live) {
      return nullptr;
    }
  } else {
    waiting_reads_.push_back(read);
  }
  return std::make_unique<LivenessHandle<PendingRead>>(read);
}

void ExternalBufferRequestBodyLog::issueRead(const PendingReadSharedPtr& read) {
  const uint64_t length = std::min(read->max_length, durableLength() - read->offset);
  store_->read(read->offset, length, [read](ExternalBufferStatus status, Buffer::InstancePtr data) {
    if (!read->live) {
      return;
    }
    read->live = false;
    if (status != ExternalBufferStatus::Ok) {
      read->cb(absl::UnavailableError("request body log read failed"));
      return;
    }
    read->cb(std::move(data));
  });
}

void ExternalBufferRequestBodyLog::serviceWaitingReads() {
  const uint64_t durable = durableLength();
  std::list<PendingReadSharedPtr> ready;
  for (auto it = waiting_reads_.begin(); it != waiting_reads_.end();) {
    if (!(*it)->live || (*it)->offset < durable) {
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

void LogBackedExternalBuffer::write(Buffer::InstancePtr data, bool end_stream, WriteCallback cb) {
  crc_ = extendCrc(crc_, *data);
  written_ += data->length();
  // The router appends a frame before it forwards it, so every byte written here is already in
  // the log. A filter ahead of this one that changed the body shows up as a mismatch at the end.
  bool ok = !log_->failed() && log_->length() >= written_;
  if (ok && end_stream) {
    ok = log_->ended() && log_->length() == written_ &&
         log_->crc32c() == static_cast<uint32_t>(crc_);
    if (!ok) {
      ENVOY_LOG(warn, "ai_protocol_manager: the request body this filter received differs from "
                      "the router's request body log; place the filter first among the "
                      "cluster's http_filters that touch the body");
    }
  }
  cb(ok ? ExternalBufferStatus::Ok : ExternalBufferStatus::Error);
}

void LogBackedExternalBuffer::read(uint64_t offset, uint64_t length, ReadCallback cb) {
  auto gather = std::make_shared<Gather>();
  gather->offset = offset;
  gather->remaining = length;
  gather->cb = std::move(cb);
  readMore(gather);
}

void LogBackedExternalBuffer::readMore(const std::shared_ptr<Gather>& gather) {
  // The log may deliver a range in pieces as its store acknowledges it; the caller wants it whole.
  // The pending callback owns `gather`, so a cancelled read frees it.
  Http::RequestBodyLog::ReadHandlePtr handle = log_->read(
      gather->offset, gather->remaining, [this, gather](absl::StatusOr<Buffer::InstancePtr> data) {
        if (!data.ok()) {
          gather->cb(ExternalBufferStatus::Error, nullptr);
          return;
        }
        gather->offset += (*data)->length();
        gather->remaining -= (*data)->length();
        gather->out->move(**data);
        if (gather->remaining == 0) {
          gather->cb(ExternalBufferStatus::Ok, std::move(gather->out));
          return;
        }
        readMore(gather);
      });
  if (handle != nullptr) {
    reads_.push_back(std::move(handle));
  }
}

ExternalBufferPtr BorrowingExternalBufferFactory::createBuffer(Event::Dispatcher& dispatcher) {
  const bool fits = log_->maxLength() == 0 ||
                    (content_length_.has_value() && *content_length_ <= log_->maxLength());
  if (log_->writing() && fits) {
    ENVOY_LOG(debug, "ai_protocol_manager: reading the payload back from the router's request "
                     "body log instead of storing a copy");
    return std::make_unique<LogBackedExternalBuffer>(log_);
  }
  return fallback_.createBuffer(dispatcher);
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
