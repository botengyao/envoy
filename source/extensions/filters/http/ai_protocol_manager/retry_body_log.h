#pragma once

#include <cstdint>
#include <list>
#include <memory>
#include <optional>

#include "envoy/event/dispatcher.h"
#include "envoy/http/request_body_log.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer.h"

#include "absl/crc/crc32c.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// A request body log kept in an ExternalBuffer from the filter's configured factory. The router
// appends the body as it sends it; reads wait until the store has acknowledged the bytes they
// cover.
class ExternalBufferRequestBodyLog
    : public Http::RequestBodyLog,
      public std::enable_shared_from_this<ExternalBufferRequestBodyLog>,
      Logger::Loggable<Logger::Id::filter> {
public:
  // `high_watermark` bounds the bytes appended but not yet acknowledged before the writer is told
  // to pause; zero disables the back-pressure. `max_length` bounds the body; zero for no limit.
  ExternalBufferRequestBodyLog(Event::Dispatcher& dispatcher,
                               ExternalBufferFactorySharedPtr factory, uint64_t high_watermark,
                               uint64_t max_length);

  // Http::RequestBodyLog
  WriterPtr attachWriter(WriterCallbacks& callbacks) override;
  bool writing() const override { return writer_ != nullptr && !failed_; }
  bool failed() const override { return failed_; }
  uint64_t maxLength() const override { return max_length_; }
  uint64_t length() const override { return appended_; }
  bool ended() const override { return ended_; }
  uint32_t crc32c() const override { return static_cast<uint32_t>(crc_); }
  ReadHandlePtr read(uint64_t offset, uint64_t max_length, ReadCallback cb) override;

private:
  class WriterImpl : public Writer {
  public:
    explicit WriterImpl(std::shared_ptr<ExternalBufferRequestBodyLog> log) : log_(std::move(log)) {}
    ~WriterImpl() override { log_->writer_ = nullptr; }
    void append(Buffer::Instance& data) override { log_->append(data); }
    void end() override { log_->end(); }

  private:
    const std::shared_ptr<ExternalBufferRequestBodyLog> log_;
  };

  struct PendingRead {
    uint64_t offset;
    uint64_t max_length;
    ReadCallback cb;
    bool live{true};
  };
  using PendingReadSharedPtr = std::shared_ptr<PendingRead>;

  void append(Buffer::Instance& data);
  void end();
  uint64_t durableLength() const { return store_ == nullptr ? 0 : store_->length(); }
  void maybeWrite();
  void onWriteComplete(ExternalBufferStatus status);
  void fail(absl::string_view reason);
  void updateWatermark();
  void issueRead(const PendingReadSharedPtr& read);
  void serviceWaitingReads();

  Event::Dispatcher& dispatcher_;
  const ExternalBufferFactorySharedPtr factory_;
  const uint64_t high_watermark_;
  const uint64_t max_length_;
  WriterCallbacks* writer_{};
  bool had_writer_{false};
  ExternalBufferPtr store_;
  // Appended bytes not yet handed to the store; the store has one write in flight at a time.
  Buffer::OwnedImpl pending_;
  uint64_t in_flight_{0};
  uint64_t appended_{0};
  absl::crc32c_t crc_{0};
  std::list<PendingReadSharedPtr> waiting_reads_;
  bool write_in_flight_{false};
  bool ended_{false};
  bool end_written_{false};
  bool above_high_watermark_{false};
  bool failed_{false};
};

// An ExternalBuffer for an upstream BufferManager whose payload the router has already appended
// to a request body log. Writes keep nothing: they only check that the bytes are the log's, so
// the filter's frames must be the router's, unmodified. Reads come back from the log.
class LogBackedExternalBuffer : public ExternalBuffer, Logger::Loggable<Logger::Id::filter> {
public:
  explicit LogBackedExternalBuffer(std::shared_ptr<Http::RequestBodyLog> log)
      : log_(std::move(log)) {}

  // ExternalBuffer
  void write(Buffer::InstancePtr data, bool end_stream, WriteCallback cb) override;
  void read(uint64_t offset, uint64_t length, ReadCallback cb) override;
  uint64_t length() const override { return written_; }

private:
  struct Gather {
    uint64_t offset{0};
    uint64_t remaining{0};
    Buffer::InstancePtr out{std::make_unique<Buffer::OwnedImpl>()};
    ReadCallback cb;
  };
  void readMore(const std::shared_ptr<Gather>& gather);

  const std::shared_ptr<Http::RequestBodyLog> log_;
  uint64_t written_{0};
  absl::crc32c_t crc_{0};
  std::list<Http::RequestBodyLog::ReadHandlePtr> reads_;
};

// Creates log-backed buffers when the log is going to hold the whole body, and buffers from
// `fallback` otherwise, so a request the router does not log keeps a copy of its own.
class BorrowingExternalBufferFactory : public ExternalBufferFactory,
                                       Logger::Loggable<Logger::Id::filter> {
public:
  // `content_length` is the request's, when known; a bounded log is borrowed only for a body known
  // to fit.
  BorrowingExternalBufferFactory(std::shared_ptr<Http::RequestBodyLog> log,
                                 ExternalBufferFactory& fallback,
                                 std::optional<uint64_t> content_length)
      : log_(std::move(log)), fallback_(fallback), content_length_(content_length) {}

  using ExternalBufferFactory::createBuffer;
  ExternalBufferPtr createBuffer(Event::Dispatcher& dispatcher) override;

private:
  const std::shared_ptr<Http::RequestBodyLog> log_;
  ExternalBufferFactory& fallback_;
  const std::optional<uint64_t> content_length_;
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
