#pragma once

#include <cstdint>
#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/common/pure.h"
#include "envoy/stream_info/filter_state.h"

#include "absl/functional/any_invocable.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Http {

/**
 * The request body as the router sent it on the first attempt, kept so that retries can be
 * replayed from it instead of from an in-memory copy. A filter that can store a body, for example
 * in an external buffer, creates one in the stream's filter state under key() before the router
 * receives the first body byte. The router then appends every body byte it receives before it
 * forwards it, so the log holds exactly what the router sent, whatever filters ahead of the router
 * did to the body.
 *
 * The router is the only writer. Any filter may read, including the upstream filters of every
 * attempt, which can read their payload back from the log instead of storing a copy of their own.
 */
class RequestBodyLog : public StreamInfo::FilterState::Object {
public:
  // Delivers between 1 and the requested number of bytes, or an error. An error is final: the
  // log can no longer be read.
  using ReadCallback = absl::AnyInvocable<void(absl::StatusOr<Buffer::InstancePtr>)>;

  // Destroying a handle cancels its read; the callback does not run afterwards.
  class ReadHandle {
  public:
    virtual ~ReadHandle() = default;
  };
  using ReadHandlePtr = std::unique_ptr<ReadHandle>;

  /**
   * Notifications to the writer.
   */
  class WriterCallbacks {
  public:
    virtual ~WriterCallbacks() = default;
    // The log holds more bytes than its store has acknowledged; pause, and resume on the low
    // watermark.
    virtual void onLogAboveHighWatermark() PURE;
    virtual void onLogBelowLowWatermark() PURE;
    // The log can no longer hold the whole body: its store failed, or the body went past
    // maxLength(). Anything appended afterwards is dropped and reads fail. May run inside append().
    virtual void onLogFailed() PURE;
  };

  /**
   * The writer's handle. Destroying it detaches the writer.
   */
  class Writer {
  public:
    virtual ~Writer() = default;
    // Appends the next bytes of the body. `data` is drained.
    virtual void append(Buffer::Instance& data) PURE;
    // Marks the end of the body. No append() follows.
    virtual void end() PURE;
  };
  using WriterPtr = std::unique_ptr<Writer>;

  static constexpr absl::string_view key() { return "envoy.http.request_body_log"; }

  /**
   * Makes the caller the log's only writer, before anything has been appended.
   * @return the writer's handle, or null if the log has had a writer already.
   */
  virtual WriterPtr attachWriter(WriterCallbacks& callbacks) PURE;

  /**
   * @return whether a writer is attached and the log has not failed, i.e. whether the log is going
   * to hold the whole body.
   */
  virtual bool writing() const PURE;

  /**
   * @return whether the log failed; it cannot be read any more.
   */
  virtual bool failed() const PURE;

  /**
   * @return the most bytes the log holds, or zero for no limit. A longer body fails the log.
   */
  virtual uint64_t maxLength() const PURE;

  /**
   * @return the number of bytes appended so far.
   */
  virtual uint64_t length() const PURE;

  /**
   * @return whether end() has been called.
   */
  virtual bool ended() const PURE;

  /**
   * @return the CRC32C of the bytes appended so far.
   */
  virtual uint32_t crc32c() const PURE;

  /**
   * Reads bytes starting at `offset`, which must be below length(). The callback runs once the
   * bytes are readable, which may be before read() returns; the returned handle is then null.
   */
  virtual ReadHandlePtr read(uint64_t offset, uint64_t max_length, ReadCallback cb) PURE;
};

} // namespace Http
} // namespace Envoy
