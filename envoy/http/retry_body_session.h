#pragma once

#include <cstdint>
#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/common/pure.h"
#include "envoy/stream_info/filter_state.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Http {

/**
 * The request body, kept by an upstream filter of the attempt the router sends it to, so that the
 * router keeps no copy of its own for retries. The filter creates the session in the stream's
 * filter state under key() before the router forwards the first body byte, and writes every byte
 * the router forwards to that attempt, in order and in the call that delivers it.
 *
 * The router hands the body over to the session at the point it would stop buffering it. From then
 * on the body has exactly one writer at a time: that attempt's filter while the attempt lives, and
 * the router itself for whatever arrives after it. A retry gets the request headers and, once the
 * session has the whole body, an empty end of stream or the trailers; its upstream filter adopts
 * the session and takes its body from it.
 */
class RetryBodySession : public StreamInfo::FilterState::Object {
public:
  class WriterCallbacks {
  public:
    virtual ~WriterCallbacks() = default;

    /**
     * The bytes taken but not yet stored passed the session's high watermark: stop sending more
     * until onSessionBelowLowWatermark().
     */
    virtual void onSessionAboveHighWatermark() PURE;
    virtual void onSessionBelowLowWatermark() PURE;

    /**
     * The session failed and will never hold the whole body. May be called from inside append() or
     * end().
     */
    virtual void onSessionFailed() PURE;
  };

  /**
   * The only way to add to a session. Destroying it detaches the writer.
   */
  class Writer {
  public:
    virtual ~Writer() = default;

    /**
     * Takes the next body bytes; `data` is drained.
     */
    virtual void append(Buffer::Instance& data) PURE;

    /**
     * Marks the end of the body.
     */
    virtual void end() PURE;
  };
  using WriterPtr = std::unique_ptr<Writer>;

  static constexpr absl::string_view key() { return "envoy.http.retry_body_session"; }

  /**
   * @return the attempt, as StreamInfo::attemptCount() numbers it, whose upstream filter last
   * wrote or adopted the session.
   */
  virtual uint32_t attempt() const PURE;

  /**
   * @return the body bytes the session has taken so far.
   */
  virtual uint64_t length() const PURE;

  /**
   * @return whether the session failed; it will never hold the whole body.
   */
  virtual bool failed() const PURE;

  /**
   * Called by the router when it stops keeping the body: later attempts must adopt the session.
   */
  virtual void handOver() PURE;

  /**
   * Makes the caller the session's only writer from `offset`, which must be length(). A writer
   * attached above the high watermark is told so at once.
   * @return null if the session has a writer, has ended or failed, or `offset` is not its length.
   */
  virtual WriterPtr attachWriter(WriterCallbacks& callbacks, uint64_t offset) PURE;
};

} // namespace Http
} // namespace Envoy
