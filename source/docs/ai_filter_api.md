# The AI filter decode API

This describes a proposed replacement for the `AiFilter` interface in
[ai_filter.h](../extensions/filters/http/ai_protocol_manager/ai_filter.h).

`AiFilter` and `FilterManager` are in main; the configuration surface that exposes them
(`RequestHandling.filters`, extension category `envoy.filters.ai`, `ai_filter_factory.h`) and the
first filter written against them (`envoy.filters.ai.request_info`) are in flight. This proposal
covers both, and says which side each change lands on.

It is deliverable in two independent stages. The first is an adapter base class that removes the
ceremony from filter code without touching `AiFilter` or `FilterManager`; the second replaces the
producer/consumer chain with a sequential loop. See [An incremental path](#an-incremental-path).

## Goal

Almost every AI filter that will be written against this chain does one of four things:

* read the request payload and publish something derived from it (`envoy.filters.ai.request_info`),
* mutate a field (model rewriting, parameter clamping, prompt injection),
* call an external service and then either continue or reject the request (auth, quota,
  guardrails, semantic cache),
* transcode the payload from one wire API to another (OpenAI chat completions to Anthropic
  messages).

The first two should be as short as a plain C++ function. The third should be possible without
writing the filter in a different style. The fourth needs the request object to carry state that it
does not carry today. Deciding when the request moves to the next filter is the manager's job in
all four cases, and should not appear in filter code at all.

## The current design

```cpp
virtual Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                             AiRequestPropagator propagate_request,
                                             LocalReplier reply_locally) = 0;
```

Every filter's `decode()` is launched as its own coroutine when the chain starts, before the
request exists. The `N` filters and the serializing sink are connected by `N + 1`
`AsyncQueue<AiRequestPtr>` handoffs. A filter awaits `receive_request` to take ownership of the
request, and awaits `propagate_request` to hand it to the next stage. All three callables are
one-shot and r-value-only, so invoking one means moving from it.

The first filter written against it, `request_info`, has one line of actual work:

```cpp
Coroutine::Task<absl::Status> RequestInfoFilter::decode(AiRequestReceiver receive_request,
                                                        AiRequestPropagator propagate_request,
                                                        LocalReplier) {
  ASSIGN_OR_CO_RETURN(AiRequestPtr request, co_await std::move(receive_request)());
  publish(request->request_index().json());
  co_return co_await std::move(propagate_request)(std::move(request));
}
```

Three parameters (one unused), three `std::move`s, two `co_await`s, a `co_return` and an
`ASSIGN_OR_CO_RETURN`, wrapped around `publish()`.

### Problem 1: ownership transfer is delegated to filters

`AiRequest`'s class comment states the intent directly: *"ownership transfer across the filter
pipeline is expressed via `std::unique_ptr<AiRequest>`"*. But the only participant that has to hold
the request for the whole chain is the manager, which holds it until the sink serializes it.
Handing ownership to each filter and taking it back is what forces the one-shot receiver and
propagator into existence, and with them every `std::move` in filter code.

The `std::move`s are a symptom. The cause is that filters were made responsible for ownership they
do not need.

### Problem 2: chain orchestration leaks into every filter

To write a correct filter today an author has to know that `decode()` starts before the request
arrives, that they must receive before acting, that they must propagate afterwards or the chain
stalls, and that each callable may be used once. None of that describes what a filter does.

The manager already tracks the same protocol independently, in
`FilterManager::AsyncState::FilterContext{received, propagated}`. The state machine exists twice,
in two places that must agree.

### Problem 3: two protocol violations are only visible at runtime

* Receiving the request and returning without propagating or replying: the manager notices in
  `onFilterCompletion` and synthesizes a 502.
* Returning without ever receiving: an implicit bypass. This one is silent, so a filter that
  returns early because of a configuration problem becomes a no-op instead of a loud failure.

Neither is expressible as a compile error, because the interface has no return value that carries
the filter's decision.

### Problem 4: `propagate_request` has accidental semantics

`AsyncState::propagateRequest` is `co_await handoff->push(...)`, and `AsyncQueue::push()` returns
`absl::OkStatus()` as soon as `tryHandoff()` finds a waiting popper. Three consequences:

* The returned status reports whether the handoff happened, not whether the downstream succeeded.
* Because `tryHandoff()` resumes the popper inline, an all-synchronous chain runs the entire
  downstream, including the sink's serialization, inside that `push()` call. So `propagate_request`
  looks like it awaits the downstream, and stops doing so as soon as one downstream filter awaits
  real I/O.
* When a downstream filter fails, `onFilterError` calls `cancel()`, which cancels the awaiting
  filter's own handle. Code after `co_await propagate_request(...)` may never run at all.

Code placed after propagation therefore has no defined behavior, and the interface comment does not
say so. This matters for the cost/benefit argument: the one thing that would justify a
producer/consumer pipeline is an "around" hook that observes downstream completion, and that is
exactly what the design does not provide.

### Problem 5: the payload's wire API is not request state

`AiRequest` holds a payload and nothing else. The dialect that payload is written in lives outside
it: the in-flight extension point hands filters an `AiFilterContext::request_protocol`, which is
`route_request_protocol_`, read from route configuration and fixed for the stream before any filter
is constructed. `request_info` extracts with it:

```cpp
extractRequestAttributes(context_.request_protocol, json, context_.request_headers.getPathValue());
```

A transcoding filter changes the dialect the payload is written in, and has no way to say so. Every
filter after it keeps extracting with the route-declared protocol, against a payload that no longer
matches. This is a gap in the design as it stands, and moving an `AiRequestPtr` down the chain does
not close it: ownership transfer carries the DOM, not the fact that its shape changed.

### Problem 6: per-stream cost

Each of the `N + 1` stages allocates an `AsyncQueue`, which is four `make_shared` calls (the queue,
its `Core`, its `Semaphore`, and its `alive_` flag), plus one coroutine frame and one
`DetachedHandle`. Each filter also gets three `absl::AnyInvocable`s, each capturing a `weak_ptr`
and an index. A five-filter chain is roughly two dozen allocations of pure plumbing per request.

`AsyncQueue`'s own documentation notes that the call stack "can be as deep as the chain of queues
that are connected by pop-push operations", so an all-synchronous chain of `N` filters nests `N`
frames before reaching the serializer.

All of it buys concurrency the chain never uses: the handoff is strictly sequential, one stage at a
time.

## Proposed design

Four changes:

1. The manager owns the request for the whole chain and hands filters an `AiRequest&`. No transfer,
   therefore no moves.
2. A filter returns its decision as a value instead of invoking one of several callbacks. Continue
   and local reply become mutually exclusive by construction.
3. The manager drives the chain sequentially, in one coroutine.
4. `AiRequest` carries the wire API its payload conforms to, and transcoding replaces both together.

### `DecodeAction`

```cpp
// What a filter decided: exactly one of continue or local reply.
class DecodeAction {
public:
  static DecodeAction continueChain() { return DecodeAction{}; }
  static DecodeAction localReply(Http::Code code, std::string details) {
    return DecodeAction{LocalReply{code, std::move(details)}};
  }

  bool isLocalReply() const { return local_reply_.has_value(); }
  Http::Code code() const { return local_reply_->code; }
  absl::string_view details() const { return local_reply_->details; }

private:
  struct LocalReply {
    Http::Code code;
    std::string details;
  };

  DecodeAction() = default;
  explicit DecodeAction(LocalReply reply) : local_reply_(std::move(reply)) {}

  std::optional<LocalReply> local_reply_;
};
```

### `AiRequest`

```cpp
class AiRequest {
public:
  AiRequest(ApiProtocol protocol, JsonWithExtBuf index);

  // The payload, for the common case. `request_index()` stays available for callers that need the
  // external buffer.
  nlohmann::json& json() { return request_index_.json(); }
  const nlohmann::json& json() const { return request_index_.json(); }

  // The wire API the payload currently conforms to. Starts as the route-declared request protocol
  // and follows the payload through transcoding, so a filter reads the dialect it is actually
  // looking at rather than the one the route declared.
  ApiProtocol protocol() const { return protocol_; }

  // Replaces the payload and the API it conforms to. The two cannot be changed separately: a
  // payload in a new dialect without the matching protocol is the bug this prevents. Marks the
  // request for full re-serialization.
  void transcode(ApiProtocol protocol, JsonWithExtBuf index);

  // True once a filter has transcoded the payload.
  bool transcoded() const { return transcoded_; }

private:
  ApiProtocol protocol_;
  JsonWithExtBuf request_index_;
  bool transcoded_{false};
};
```

`JsonWithExtBuf` is already move-only and move-assignable, so `transcode()` is a move-assign plus
two scalar writes.

### The filter interfaces

```cpp
// The interface the manager drives. Implement this directly when the filter must await external
// work.
class AiFilter {
public:
  virtual ~AiFilter() = default;

  // Called once, in configuration order, on the stream's dispatcher, after every preceding filter
  // continued. `request` is owned by the manager and outlives the call. A non-OK status cancels
  // the chain and sends a 502.
  virtual Coroutine::Task<absl::StatusOr<DecodeAction>> decode(AiRequest& request) PURE;
};

// Base for filters that never await; they implement a plain function instead.
class SyncAiFilter : public AiFilter {
public:
  virtual absl::StatusOr<DecodeAction> onRequest(AiRequest& request) PURE;

private:
  Coroutine::Task<absl::StatusOr<DecodeAction>> decode(AiRequest& request) final {
    co_return onRequest(request);
  }
};
```

An adapter, rather than two interfaces the manager selects between, because it keeps exactly one
call site and no branch in the manager while giving authors two minimal shapes to choose from. The
choice is compiler-enforced: `onRequest` is pure virtual and `decode` is `final`, so a
`SyncAiFilter` cannot be half-implemented.

A `SyncAiFilter` still allocates one coroutine frame per call. If that ever shows up in a profile,
a ready-value fast path can be added inside the adapter without touching a single filter.

`AiFilterPtr` stays `std::unique_ptr<AiFilter>`, so the in-flight `AiFilterConfigFactory` and
`AiFilterFactoryCb` need no change.

### The manager

```cpp
Coroutine::Task<absl::Status> FilterManager::runChain() {
  for (const AiFilterPtr& filter : filters_) {
    ASSIGN_OR_CO_RETURN(DecodeAction action, co_await filter->decode(*request_));
    if (action.isLocalReply()) {
      local_reply_fn_(action.code(), std::string(action.details()));
      co_return absl::CancelledError("local reply sent");
    }
  }
  co_return co_await serialize(*request_);
}
```

One coroutine per stream, one handle to cancel, no queues, and no `received`/`propagated`
bookkeeping. `receiveRequest`, `bypassFilter`, `propagateRequest` and `onFilterCompletion` all
leave `FilterManager::AsyncState`.

## Examples

### Mutating a field

```cpp
class ModelRewriteFilter : public SyncAiFilter {
public:
  explicit ModelRewriteFilter(std::string model) : model_(std::move(model)) {}

  absl::StatusOr<DecodeAction> onRequest(AiRequest& request) override {
    request.json()["model"] = model_;
    return DecodeAction::continueChain();
  }

private:
  const std::string model_;
};
```

The same filter today:

```cpp
Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                     AiRequestPropagator propagate_request, LocalReplier) override {
  ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
  req->request_index().json()["model"] = model_;
  co_return co_await std::move(propagate_request)(std::move(req));
}
```

### Publishing derived data

`request_info` becomes:

```cpp
absl::StatusOr<DecodeAction> RequestInfoFilter::onRequest(AiRequest& request) {
  publish(request);
  return DecodeAction::continueChain();
}
```

with `publish()` extracting against `request.protocol()` rather than
`context_.request_protocol`, so it reads the payload in whatever dialect it is now in.

### Transcoding between wire APIs

```cpp
class OpenAiToAnthropicFilter : public SyncAiFilter {
public:
  absl::StatusOr<DecodeAction> onRequest(AiRequest& request) override {
    if (request.protocol() != ApiProtocol::OpenAiChatCompletions) {
      return DecodeAction::continueChain();
    }

    absl::StatusOr<JsonWithExtBuf> messages = toAnthropicMessages(request.json());
    if (!messages.ok()) {
      return DecodeAction::localReply(Http::Code::BadRequest, std::string(messages.status().message()));
    }

    request.transcode(ApiProtocol::AnthropicMessages, std::move(*messages));
    return DecodeAction::continueChain();
  }
};
```

Three things fall out of this that neither the current design nor a move-based redesign gives:

* **Downstream filters see the new dialect.** They read `request.protocol()`, which is now
  `AnthropicMessages`. Under `AiFilterContext::request_protocol` they would keep reading the
  route-declared `OpenAiChatCompletions` and misparse the payload.
* **Request identity survives.** Constructing a fresh `AiRequest` to replace the old one, which is
  what a move-based chain would do, silently drops anything else accumulated on the request. That
  is empty today and will not stay empty once field streaming lands.
* **The sink learns it must re-serialize.** A transcoded payload has no external-buffer backing, so
  passthrough of the original body is not an option. `transcoded()` is the definite signal for the
  existing `TODO(penguingao)` in `runSink` about conditioning serialization on config: transcoded
  always re-serializes, untouched payloads can still pass through.

A rejection inside a transcoder is a plain `localReply`, on the same path as any other filter's
rejection, so an unconvertible request produces a 400 rather than the chain's generic 502.

### Awaiting an external service

```cpp
class TokenAuthFilter : public AiFilter {
public:
  Coroutine::Task<absl::StatusOr<DecodeAction>> decode(AiRequest& request) override {
    ASSIGN_OR_CO_RETURN(AuthDecision decision, co_await authorize(request.json()));
    if (!decision.allowed) {
      co_return DecodeAction::localReply(Http::Code::Unauthorized, decision.reason);
    }
    request.json()["user"] = decision.subject;
    co_return DecodeAction::continueChain();
  }

private:
  Coroutine::Task<absl::StatusOr<AuthDecision>> authorize(const nlohmann::json& payload);
};
```

The filter awaits whatever it needs to; the rest of the chain simply has not been called yet. There
is no rule to remember about replying locally and then also returning `absl::OkStatus()`, because
the reply is the return value.

### Skipping the filter

```cpp
absl::StatusOr<DecodeAction> onRequest(AiRequest& request) override {
  if (request.protocol() != ApiProtocol::OpenAiChatCompletions) {
    return DecodeAction::continueChain();
  }
  ...
}
```

Skipping is the same statement as finishing normally, so the implicit "never received the request,
therefore bypassed" rule disappears. Declaring that a filter does not apply to a protocol at all
belongs in the separately proposed `supportedProtocols()` hook on the factory, where the manager
can skip the filter without constructing it. Note that with transcoding in the chain that hook can
only be a construction-time optimization: the authoritative check is `request.protocol()`, because
the dialect can change between filters.

### Failing

```cpp
return absl::InvalidArgumentError("request payload is not a JSON object");
```

The manager cancels the chain and sends a 502, as it does today.

## Open questions for transcoding

Transcoding the payload is the part this design settles. Two neighbouring pieces are not settled,
and are called out here rather than assumed away:

* **Request headers.** OpenAI's `/v1/chat/completions` and Anthropic's `/v1/messages` differ in
  path and in required headers. `AiFilterContext` exposes `const Http::RequestHeaderMap&`, and the
  chain runs after the route has been resolved (`route_request_protocol_` is read from route
  configuration in `decodeHeaders`), so rewriting `:path` would also mean deciding whether the
  route cache is cleared. Options are a mutable header accessor on `AiRequest`, or header
  mutations carried on `DecodeAction` so the manager applies them at a defined point. The latter
  keeps the "filters return decisions, the manager acts" property, and is the one worth prototyping
  first.
* **Response symmetry.** A request-side transcoder implies a response-side one. The route already
  models these separately (`requestProtocol()` and `effectiveResponseProtocol()`), so the encode
  path should get the matching `AiResponse::protocol()` / `transcode()` pair rather than inferring
  the response dialect from the request. Out of scope here; the request-side shape should not
  foreclose it, and it does not.

## Companion changes

* Remove `AiRequest`'s "ownership transfer across the filter pipeline" comment, which describes the
  model being replaced. Left in place, it invites the propagator to be rebuilt.
* `AiFilterContext::request_protocol` becomes the route-declared seed for `AiRequest::protocol()`
  and should be removed from the context, so there is one place to read the dialect from and it is
  the one that stays correct.

## What this gives up

| Capability | Today | Proposed | How to add it back |
| --- | --- | --- | --- |
| Work before the request arrives | Yes, via eager launch | No | A separate `onStreamStart()` hook defaulting to a no-op, so only filters that want it pay for it |
| Observing downstream completion | No, see Problem 4 | No | The response path, which is where it belongs |
| Filters running concurrently | No, strictly sequential | No | An explicit parallel group in configuration, if it is ever wanted |
| Field-level streaming (the `FieldStreamInterest` TODO) | No | No | A separate streaming interface. This is where `AsyncQueue` genuinely fits; the request chain should not be shaped around it in advance |

Unchanged: `Coroutine::Task`, `ASSIGN_OR_CO_RETURN`, `DispatcherExecutor`, cancellation through
handles, and the sink/serializer split.

## Ceremony, before and after

Measured on `request_info`, which has one line of real work.

| | Parameters | `std::move` | `co_await` / `co_return` | `ASSIGN_OR_CO_RETURN` |
| --- | --- | --- | --- | --- |
| Today | 3, one unused | 3 | 3 | 1 |
| Adapter only, manager unchanged | 1 | 0 | 0 | 0 |
| Proposed, async filter | 1 | 0 | 1 | 0 |
| Proposed, sync filter | 1 | 0 | 0 | 0 |

## An incremental path

The ergonomics and the manager rewrite are separable. `DecodeAction` plus an adapter base class
delivers the entire ceremony reduction without touching `AiFilter` or `FilterManager` at all, which
means it can land and be reviewed on its own.

### The adapter

This is the same `SyncAiFilter` as above, with its private `decode()` written against today's
three-callable interface instead of the proposed one:

```cpp
// Base for filters with the receive-act-propagate shape. The adapter owns the protocol; the
// filter only decides.
class SyncAiFilter : public AiFilter {
public:
  virtual absl::StatusOr<DecodeAction> onRequest(AiRequest& request) PURE;

private:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier reply_locally) final {
    ASSIGN_OR_CO_RETURN(AiRequestPtr request, co_await std::move(receive_request)());
    ASSIGN_OR_CO_RETURN(DecodeAction action, onRequest(*request));
    if (action.isLocalReply()) {
      std::move(reply_locally)(action.code(), std::string(action.details()));
      co_return absl::OkStatus();
    }
    co_return co_await std::move(propagate_request)(std::move(request));
  }
};
```

`AwaitingAiFilter` is the same body with `onRequest` returning
`Coroutine::Task<absl::StatusOr<DecodeAction>>` and one `co_await` added.

Every `std::move`, `co_await`, `co_return` and `ASSIGN_OR_CO_RETURN` the chain protocol requires now
exists once, in one file, reviewed once. A filter is a plain function again:

```cpp
absl::StatusOr<DecodeAction> RequestInfoFilter::onRequest(AiRequest& request) {
  publish(request.json());
  return DecodeAction::continueChain();
}
```

The adapter is correct against the manager as it stands. `DetachedHandle::cancel()` fires the
pending leaf's cancel callback, and a running frame has no pending leaf, so invoking
`reply_locally` and then returning does not destroy the frame underneath itself. `triggerLocalReply`
sets `terminated_` before `onFilterCompletion` runs, so a filter that replies without propagating is
not misread as the "consumed the request but did not propagate" error. `TestLocalReplyFilter` and
`TestImmediateLocalReplyFilter` already cover that path.

### The names match on purpose

`SyncAiFilter::onRequest(AiRequest&) -> absl::StatusOr<DecodeAction>` is deliberately identical to
the interface proposed above. Under the adapter, `decode()` runs the receive/propagate protocol;
after the manager rewrite it collapses to `co_return onRequest(request);`. Synchronous filters and
the tests written against them do not change at all.

Awaiting filters are not quite free: at stage 2 they drop `AwaitingAiFilter` and implement
`AiFilter::decode(AiRequest&)` directly, which is a base-class and method-name change on an
otherwise identical body. There are no awaiting filters yet, so the cost of that is currently zero.

So this is a stepping stone, not a fork in the road. Stage 1 is not thrown away by stage 2, and
choosing stage 1 does not commit to stage 2.

### What the adapter does not fix

Worth stating plainly, because the adapter is tempting enough to stop at:

* **Cost is unchanged.** Still `N + 1` `AsyncQueue`s, four allocations per stage, `N + 1` coroutine
  frames, and three `absl::AnyInvocable`s per filter. The adapter hides the plumbing; it does not
  remove it.
* **Problem 4 gets quieter, not fixed.** `propagate_request`'s accidental semantics move inside the
  adapter, where nobody reads them. That is arguably worse than leaving them in view: surprising
  behavior stops being in front of the person who has to reason about it.
* **Transcoding stays blocked.** `AiRequest` carries no protocol regardless of which interface sits
  on top of it, so a transcoder still cannot tell downstream filters that the dialect changed.

The adapter buys ergonomics. The manager rewrite buys cost and correctness. They are worth having
in that order, not instead of each other.

### Why not a macro

Packaging the same three lines as `AI_CO_RETURN_PROPAGATE(propagate_request, request)` would follow
the existing `ASSIGN_OR_CO_RETURN` naming convention, so it is not unthinkable. But it hides a
`co_return` behind a name, it cannot remove the unused third parameter from the signature, and it
cannot enforce that a filter propagates exactly once. The adapter gets all three for the same
effort, and a base class is the more conventional tool for "this protocol is boilerplate".

## Delivery

### Stage 1: `DecodeAction` and the adapter

* `ai_filter.h`: add `DecodeAction`, `SyncAiFilter`, `AwaitingAiFilter`. `AiFilter`,
  `AiRequestReceiver`, `AiRequestPropagator` and `LocalReplier` are untouched.
* `ai_request.h`: add `json()`.
* Tests: adapter coverage for continue, local reply and error. The existing twelve fakes stay as
  they are; they exercise the raw `AiFilter` contract, which still exists.

Nothing in this stage presumes the second.

### Stage 2: the manager

* `ai_filter.h`: `AiFilter::decode(AiRequest&)`; `SyncAiFilter::decode` collapses to
  `co_return onRequest(request);`; delete `AiRequestReceiver`, `AiRequestPropagator` and
  `LocalReplier`.
* `ai_request.h`: `protocol()`, `transcode()`, `transcoded()`.
* `filter_manager.cc`: replace the eager launch, the handoff queues and the completion bookkeeping
  with `runChain()`. Net reduction of roughly 120 lines.
* Test fakes: twelve in `filter_manager_test.cc`. Filters already written against `SyncAiFilter`
  need no change.

On the in-flight side: drop `request_protocol` from `AiFilterContext`, and land `request_info` as a
`SyncAiFilter` extracting against `request.protocol()`. No proto or configuration change either
way.

### Worth doing regardless

* `AiRequest::json()`, which deletes `->request_index().json()` from every filter and every test.
  One accessor, no interface change, useful whichever way the rest goes.
* A test filter factory. The twelve fakes in `filter_manager_test.cc` are the same shape declared
  twelve times:

  ```cpp
  AiFilterPtr makeAiFilter(absl::AnyInvocable<absl::StatusOr<DecodeAction>(AiRequest&)> fn);
  ```

  Each collapses to a lambda, and the test file stops being a migration cost every time the
  interface moves.
