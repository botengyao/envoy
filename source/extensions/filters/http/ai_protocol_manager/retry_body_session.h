#pragma once

#include <cstdint>
#include <list>
#include <memory>

#include "envoy/http/retry_body_session.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer.h"
#include "source/extensions/filters/http/ai_protocol_manager/token_usage.h"

#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// The retry session an upstream installation keeps: the body the router forwarded to the attempt
// that wrote it, in an external buffer, and the document parsed from it before any AI filter edited
// it.
class RetryBodySessionImpl : public Http::RetryBodySession,
                             public std::enable_shared_from_this<RetryBodySessionImpl>,
                             Logger::Loggable<Logger::Id::filter> {
public:
  // How a document was parsed; a filter that parses differently cannot use it.
  struct ParseTag {
    LLMProtocol protocol{LLMProtocol::Unspecified};
    uint32_t inline_string_threshold_bytes{0};

    bool operator==(const ParseTag& other) const {
      return protocol == other.protocol &&
             inline_string_threshold_bytes == other.inline_string_threshold_bytes;
    }
  };

  // `store` keeps the body. `high_watermark` bounds the bytes taken but not yet stored before the
  // writer is told to pause; zero never pauses it.
  RetryBodySessionImpl(ExternalBufferPtr store, uint64_t high_watermark, uint32_t attempt);

  // Http::RetryBodySession
  uint32_t attempt() const override { return attempt_; }
  uint64_t length() const override { return taken_; }
  bool failed() const override { return failed_; }
  void handOver() override { handed_over_ = true; }
  bool hasWriter() const override { return writer_ != nullptr; }
  WriterPtr attachWriter(WriterCallbacks& callbacks, uint64_t offset) override;

  bool handedOver() const { return handed_over_; }
  bool ended() const { return ended_; }
  // Records that `attempt` takes its body from the session.
  void adopt(uint32_t attempt) { attempt_ = attempt; }
  // Keeps a copy of `document`, parsed as `tag`.
  void setDocument(const ParseTag& tag, const nlohmann::json& document);
  // The document, if it was parsed as `tag`; otherwise null.
  const nlohmann::json* document(const ParseTag& tag) const;
  // A buffer over the session's bytes for one attempt. Its reads wait until the bytes they cover
  // are stored; the empty write ending a payload succeeds once the session has ended. Destroying it
  // cancels its reads.
  ExternalBufferPtr view();

private:
  class WriterImpl;
  class View;
  struct PendingRead {
    uint64_t offset;
    uint64_t length;
    ReadCallback cb;
    bool live{true};
  };
  using PendingReadSharedPtr = std::shared_ptr<PendingRead>;

  void append(Buffer::Instance& data);
  void end();
  void detach(WriterImpl& writer);
  void maybeWrite();
  void onWriteComplete(ExternalBufferStatus status);
  void fail();
  void updateWatermark();
  void read(const PendingReadSharedPtr& read);
  void issueRead(const PendingReadSharedPtr& read);
  void serviceWaitingReads();

  const ExternalBufferPtr store_;
  const uint64_t high_watermark_;
  uint32_t attempt_;
  WriterImpl* writer_{};
  WriterCallbacks* writer_callbacks_{};
  // Taken bytes not yet handed to the store; the store has one write in flight at a time.
  Buffer::OwnedImpl pending_;
  uint64_t in_flight_{0};
  uint64_t taken_{0};
  std::list<PendingReadSharedPtr> waiting_reads_;
  std::shared_ptr<const nlohmann::json> document_;
  ParseTag tag_;
  bool write_in_flight_{false};
  bool ended_{false};
  bool end_written_{false};
  bool above_high_watermark_{false};
  bool failed_{false};
  bool handed_over_{false};
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
