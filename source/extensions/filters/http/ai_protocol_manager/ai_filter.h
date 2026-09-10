#pragma once

#include <memory>
#include <utility>

#include "envoy/http/codes.h"

#include "source/common/common/assert.h"
#include "source/common/coroutine/task.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_request.h"

#include "absl/functional/any_invocable.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Callable awaitable that delivers the `AiRequest` to a filter. Callable on r-value only.
//
// One-shot: `co_await std::move(receive_request)()` suspends until the previous stage hands the
// request off, then yields exclusive ownership of it. Not invoking it bypasses the filter; a
// second invocation is a bug and returns FailedPrecondition. Yields CancelledError if the stream
// was reset or the manager destroyed while suspended, which should be returned out of `decode()`
// rather than treated as a filter failure.
class AiRequestReceiver {
public:
  using Impl = absl::AnyInvocable<Coroutine::Task<absl::StatusOr<AiRequestPtr>>() &&>;

  explicit AiRequestReceiver(Impl impl) : impl_(std::move(impl)) {}

  Coroutine::Task<absl::StatusOr<AiRequestPtr>> operator()() && {
    if (!valid()) {
      IS_ENVOY_BUG("AiRequestReceiver invoked on an invalid or already moved instance");
      co_return absl::FailedPreconditionError(
          "AiRequestReceiver invoked on an invalid or already moved instance");
    }
    Impl impl = std::move(impl_);
    co_return co_await std::move(impl)();
  }

  bool valid() const { return impl_ != nullptr; }

private:
  Impl impl_;
};

// Callable awaitable that forwards the `AiRequest` to the next filter in the chain. Callable on
// r-value only.
//
// One-shot: `co_await std::move(propagate_request)(std::move(req))` hands ownership to the next
// stage, or to the serializing sink for the last filter. Until then the filter owns the request
// and may mutate `req->request_index()` or await unrelated work; the rest of the chain stays
// suspended. Propagating a null request, or invoking the propagator twice, is a bug and returns
// InvalidArgument or FailedPrecondition respectively.
class AiRequestPropagator {
public:
  using Impl = absl::AnyInvocable<Coroutine::Task<absl::Status>(AiRequestPtr) &&>;

  explicit AiRequestPropagator(Impl impl) : impl_(std::move(impl)) {}

  // Forwards the request index without requesting field streaming.
  Coroutine::Task<absl::Status> operator()(AiRequestPtr req) && {
    if (!valid()) {
      IS_ENVOY_BUG("AiRequestPropagator invoked on an invalid or already moved instance");
      co_return absl::FailedPreconditionError(
          "AiRequestPropagator invoked on an invalid or already moved instance");
    }
    Impl impl = std::move(impl_);
    co_return co_await std::move(impl)(std::move(req));
  }

  // TODO(penguingao): Add overload accepting FieldStreamInterest when field streaming is
  // introduced.

  bool valid() const { return impl_ != nullptr; }

private:
  Impl impl_;
};

// Callable callback to send an immediate HTTP local reply and abort processing. Callable on
// r-value only.
//
// Cancels the whole chain: the request is never forwarded upstream and the remaining filters stop
// where they are. `decode()` should return absl::OkStatus() afterwards. No-op once the chain has
// already terminated.
using LocalReplier = absl::AnyInvocable<void(Http::Code code, std::string details) &&>;

// Abstract interface implemented by AI filter instances.
class AiFilter {
public:
  virtual ~AiFilter() = default;

  // Decodes one AI request. Every filter's `decode()` is launched as its own coroutine when the
  // chain starts, so it runs before the request reaches this filter; `receive_request` is the
  // suspension point that waits for it. All three callbacks run on the stream's dispatcher thread.
  //
  // A filter terminates in exactly one of these ways:
  // 1. Receives the request, optionally mutates it, and propagates it (the common path):
  //      ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
  //      req->request_index().json()["model"] = "gpt-4";
  //      co_return co_await std::move(propagate_request)(std::move(req));
  // 2. Ends the stream with a local reply, leaving `propagate_request` unused:
  //      std::move(reply_locally)(Http::Code::Unauthorized, "access denied");
  //      co_return absl::OkStatus();
  // 3. Returns without ever invoking `receive_request`, which bypasses the filter: the manager
  //    forwards the request to the next stage unchanged.
  //
  // Returns absl::OkStatus() on normal completion, or an error status on failure. An error cancels
  // the chain and triggers a 502 local reply; so does consuming the request and returning without
  // either propagating it or replying locally.
  virtual Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                               AiRequestPropagator propagate_request,
                                               LocalReplier reply_locally) = 0;
};

using AiFilterPtr = std::unique_ptr<AiFilter>;

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
