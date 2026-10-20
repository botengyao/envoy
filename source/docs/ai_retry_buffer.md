# Retry buffer for AI fallback

Status: proposal, not implemented. Code references are at upstream/main `d7b74bd624`.

This doc covers three questions:

1. How to use the `priority_group` cluster specifier (#46640) with the router's retry buffer.
2. How to use the AI protocol manager's (APM) external buffer for the retry buffer when the APM
   runs in the upstream filter chain.
3. Whether either needs a custom retry policy.

## Summary

- **#46640 works today with the stock retry policy.** `priority_group` picks a group by attempt
  index. `refresh_cluster_on_retry` re-runs it on every retry. The router replays the body it
  retained. Section 2 has the configuration.
- **The upstream APM's external buffer cannot be the retry buffer as it is.** An upstream filter
  instance lives for one attempt, and it receives the retried body from the router rather than
  supplying it. The router also needs the body when no attempt exists (backoff, async host
  selection). The router has to own the per-request copy.
- **What can be shared is the storage extension and the bytes.**
  - Promote the APM's `ExternalBuffer` interface to core.
  - The router spills its retry buffer into an external buffer when the body outgrows the
    in-memory limit, instead of giving up on retries.
  - The upstream APM then reads the router's copy instead of offloading its own per attempt, so
    the body is stored once per request.
- **No custom retry policy.** Each concern already has a home:
  - target order: the cluster specifier;
  - the retry decision: `retry_on` and `retriable_status_codes`;
  - body retention: the router;
  - per-attempt rewrites: upstream filters.

## 1. What main does today

### 1.1 priority_group (#46640)

- The group is `priority_groups[min(attempt_count - 1, len - 1)]`, and the weights pick a cluster
  inside it. The random value is computed once per request
  (`source/extensions/router/cluster_specifiers/priority_group/priority_group_cluster_specifier.cc:288`).
- It needs `RetryPolicy.refresh_cluster_on_retry`. `doRetry` bumps the attempt count, then calls
  `refreshRouteCluster()`, so the specifier sees the new attempt
  (`source/common/router/router.cc:2435-2457`).
- Per-request groups come from `override_metadata_namespace`. The filter that writes them must
  clear the route cache.
- Cross-cluster retry is off while hedging is on (`router.cc:861`).

### 1.2 The router's retry buffer

- **Retention.** The router forwards a copy of each body frame to the live attempt
  (`router.cc:1195`). It then keeps the frame in the HCM decoding buffer with `addDecodedData`
  (`router.cc:1204`).
- **Limit.** The limit is the first of these that is set:
  1. the route's or virtual host's `request_body_buffer_limit`;
  2. the legacy `per_request_buffer_limit_bytes`;
  3. the stream's buffer limit (`router.cc:1097`).

  When the route sets a limit, the router raises the stream's buffer limit to it
  (`router.cc:640-646`).
- **Overflow.** The router drops retries (`retry_or_shadow_abandoned`). If no attempt is live, the
  request fails with a 507 (`router.cc:1147-1180`). Internal redirects are skipped too
  (`router.cc:2247`).
- **Replay.** Each retry copies the whole buffer into the new attempt (`router.cc:2558`).
  `Buffer::OwnedImpl(const Instance&)` copies the bytes rather than sharing slices.

### 1.3 The APM in an upstream chain

- **Per-attempt chain.** Every attempt builds a new upstream filter chain from that attempt's
  cluster (`source/common/router/upstream_request.cc:175`). The APM instance, its `BufferManager`
  and its `ExternalBuffer` therefore last one attempt.
- **Shared request state.** Upstream filters see the downstream `StreamInfo`
  (`upstream_request.cc:56-60`) and the router's request header map (`upstream_request.cc:497`).
  Header edits made during one attempt are still there on the next.
- **In-memory tier.** The upstream filter manager takes the stream's buffer limit when the attempt
  is created (`upstream_request.cc:173`), after the router has raised it. The APM's in-memory tier
  is that limit (`source/extensions/filters/http/ai_protocol_manager/filter.cc:342`). With a route
  limit set, the APM holds the whole body in heap and never writes the external buffer.
- **Back-pressure.** Only the HCM's filter manager forwards upstream back-pressure to
  `addUpstreamWatermarkCallbacks` subscribers (`source/common/http/conn_manager_impl.cc:2339`,
  `:2348`). The upstream filter manager does not; that is the open follow-up from #46385. The
  router is a downstream filter, so it does get these signals.
- **Local replies.** A local reply from an upstream filter goes straight to the client. The retry
  state is not consulted.

### 1.4 What it costs

Take a body of size B, a route limit L ≥ B, and an upstream APM on every cluster:

| Copy | Where | Size | Held for |
|---|---|---|---|
| Router retry copy | HCM heap | B | the request |
| Attempt copy (`router.cc:2558`), held by the APM in-memory tier | heap | B | the attempt, until the APM finishes replaying |

The peak is about 2B of heap per request. A body larger than L gets no retries at all, so the
external buffer is only ever used for bodies the router could not retry anyway.

With the APM downstream instead, the APM does offload. Its tier is the unraised limit, because it
holds the headers and the router has not run yet. But the router then buffers all of B in heap.

Either way, enabling retries puts the whole body back in the HCM buffers, which is what the
external buffer is there to avoid.

## 2. Configuration that works today

```yaml
routes:
- match: {prefix: "/v1/chat/completions"}
  route:
    inline_cluster_specifier_plugin:
      extension:
        name: envoy.router.cluster_specifier_plugin.priority_group
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.router.cluster_specifiers.priority_group.v3.PriorityGroupClusterSpecifier
          priority_groups:
          - name: local
            clusters:
            - {cluster_name: vllm_a, weight: 80}
            - {cluster_name: vllm_b, weight: 20}
          - name: primary
            clusters: [{cluster_name: openai, weight: 100}]
          - name: secondary
            clusters: [{cluster_name: azure_openai, weight: 100}]
    retry_policy:
      retry_on: "5xx,reset,connect-failure,retriable-status-codes"
      retriable_status_codes: [429]
      num_retries: 2
      refresh_cluster_on_retry: true
      per_try_timeout: 120s
      retry_back_off: {base_interval: 0.01s, max_interval: 0.05s}
  request_body_buffer_limit: 8388608
```

Each cluster carries its own upstream chain:

```yaml
- name: openai
  typed_extension_protocol_options:
    envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
      "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
      explicit_http_config: {http2_protocol_options: {}}
      http_filters:
      - name: envoy.filters.http.credential_injector   # overwrite: true
        typed_config: {...}
      - name: envoy.filters.http.ai_protocol_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
          request_handling: {}
      - name: envoy.filters.http.upstream_codec
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec
```

- **`num_retries`.** Set it to at least the number of groups minus one. The retry circuit breaker
  belongs to the first attempt's cluster (`router.cc:851`) and governs every retry, so use a fixed
  `num_retries` rather than a retry budget.
- **Backoff.** Leave `rate_limited_retry_back_off` unset. Otherwise provider A's `Retry-After`
  delays the move to provider B. Keep `retry_back_off` short.
- **Buffer limit.** `request_body_buffer_limit` caps the bodies that can be retried. A larger body
  gets a single attempt.
- **Providers.** Without the fixes in section 5, this configuration is only safe when every
  provider speaks the same API with the same model name.

## 3. Why the upstream APM's buffer can't be the retry buffer

1. **Lifetime.** The buffer is deleted together with its attempt.
2. **Direction.** The router replays the body into the upstream chain. The APM receives that
   replay; it does not produce it.
3. **Gaps between attempts.** No attempt exists during backoff or async host selection, or after an
   attempt resets mid-upload. Downstream bytes keep arriving, and the router has to keep them.
4. **Mixed chains.** The next attempt's cluster may not run an APM at all.
5. **Single writer.** `ExternalBuffer` allows one writer at a time. The router and every attempt's
   APM would all be writers.

Moving the APM's buffer into filter state when the filter is destroyed solves only the first
problem. So ownership flips: the router owns the per-request copy, built from the same
external-buffer extension, and the upstream APM borrows it.

## 4. Proposal

### 4.1 One external-buffer interface in core

- Move `ExternalBuffer`, `ExternalBufferFactory` and `ExternalBufferConfigFactory` out of
  `source/extensions/filters/http/ai_protocol_manager/external_buffer.h` into
  `envoy/buffer/external_buffer.h`, under a core extension category (D4).
- Move the in-memory implementation out of the APM. The APM is alpha, so its
  `external_buffer_config` can take the new category directly.
- Split `BufferManager` along the line its TODO already draws (`buffer_manager.h:208`):
  - The passive spool moves to `source/common/buffer/`: the memory tier, single-writer batching,
    the durable length and ranged reads.
  - The replay driver stays with each consumer.

  The router and the APM then share one spool and one set of flow-control rules.

These moves change nothing for the APM.

### 4.2 Router: spill the retry buffer

```proto
// envoy.extensions.filters.http.router.v3.Router
message Router {
  // Keeps the request body retained for retries once it outgrows the route's in-memory request
  // body buffer limit, instead of giving up on retrying the request.
  RetryBodySpool retry_body_spool = <next>;
}

message RetryBodySpool {
  // [#extension-category: <D4>]
  config.core.v3.TypedExtensionConfig external_buffer = 1
      [(validate.rules).message = {required: true}];

  // A body larger than this is not retried, as with an in-memory overflow today.
  google.protobuf.UInt64Value max_bytes = 2 [(validate.rules).message = {required: true}];
}
```

- **Small bodies.** A body within the in-memory limit behaves exactly as it does today.
- **Crossing the limit.** The router moves the decoding buffer into the spool and appends every
  later frame there. It pauses the downstream while the spool's unacknowledged bytes exceed the
  stream limit, the same rule the APM's bridge applies.
- **Past `max_bytes`.** The router falls back to today's overflow handling.
- **Replaying a spilled body.**
  - Headers go out at once.
  - The body is read back from the spool in chunks, paced by the attempt's write watermarks.
  - If the downstream has not finished, v1 holds the body replay until end of stream (D3). Live
    frames go only to the spool.
- **Spool errors.** A failed read or write ends the request with a local 500 and
  `retry_body_spool_error`, as the APM does for its own buffer errors.
- **Internal redirects** are off for a spilled body, as they are for an overflowed one. Mirrors are
  unchanged, because they stream live copies.
- **Configuration.** With a spool, operators leave `request_body_buffer_limit` unset or small. The
  router then stops raising the stream limit to fit the largest prompt, and an upstream APM's
  in-memory tier stays small too.

### 4.3 The upstream APM borrows the router's body

- **Accessor.** Add an upstream-only accessor, `Http::UpstreamStreamFilterCallbacks::retainedRequestBody()`
  (D6). It returns a read-only view of what the router retains for this request, whether in memory
  or spilled: length, completeness, and async ranged reads with cancellation. It returns null when
  the router retains nothing.
- **Retain before forward.** The router retains each frame before forwarding it. Any byte an
  upstream filter has seen can then be read from the view. Today it is the other way round
  (`router.cc:1195` runs before `:1204`).
- **Borrow mode.** Add `RequestHandling.use_router_retained_body` (opt-in, D5). In an upstream
  chain with a non-null view, the `BufferManager` feeds each frame to the parser, counts it and
  drops it. Replay reads ranges from the view. Parser offsets stay valid because the frames are the
  retained bytes, starting at offset 0.
- **Integrity.** An upstream filter ahead of the APM that edits the body would break that
  assumption. The flag documents the requirement. At end of stream, the APM fails closed with a 500
  if the byte count it saw differs from the view's length.
- **Later, optional.** Cache the unmodified parse per request so attempts 2..N skip re-parsing.
  AI filters would then edit a per-attempt clone.

### 4.4 Memory per request

Take a body B larger than the in-memory limit, with one live attempt:

| | Router | Live attempt (APM) | Retries above the limit |
|---|---|---|---|
| Today | heap B, only if B ≤ L | heap B | no |
| 4.2, in-memory backend | heap B | heap B (own in-memory buffer) | yes |
| 4.2, disk/remote backend | heap O(chunk), store B | heap O(limit), store B | yes |
| 4.2 + 4.3, in-memory backend | heap B | heap O(frame) | yes |
| 4.2 + 4.3, disk/remote backend | heap O(chunk), store B | heap O(frame) | yes |

The in-memory implementation is the only backend in tree. So 4.2 alone makes large bodies
retriable but saves no heap. 4.3 is what halves it.

## 5. Prerequisites for cross-provider fallback

These are not buffer work, but retained bodies are no use without them when the providers differ.

1. **Header restore per attempt (router).** Upstream filters edit the router's header map: `:path`,
   `content-length` and credentials. The router should snapshot the headers before the first
   attempt and restore them at the top of `doRetry` on cross-cluster retries. This was proposed in
   the model-failover design.
2. **Per-attempt AI target (APM).** `envoy.ai.llm_protocol.response`, `envoy.ai.binding.response`
   and `envoy.ai.model.resolved` are request filter state
   (`ai_protocol_manager/ai_filter_state.h:30-41`), and the route's per-filter config is the same
   on every attempt. Every attempt therefore gets the same backend API, binding and model.
   Proposal: the upstream APM's own config declares its cluster's backend (`llm_protocol`,
   `binding`, `model`), and in an upstream chain that declaration wins over the request filter
   state (D7).
3. **Credentials.** Run `credential_injector` per cluster with `overwrite: true`. This is safe only
   once item 1 lands; until then attempt 1's header survives under a name attempt 2 does not
   overwrite.
4. **Terminal local replies.** A transcode or schema rejection at attempt k ends the request
   without trying attempt k+1. v1 accepts this: a payload one provider rejects locally is usually
   malformed for all of them.

## 6. Do we need a custom retry policy?

No:

| Need | Existing mechanism |
|---|---|
| Ordered targets per attempt | `priority_group` + `refresh_cluster_on_retry` |
| Per-request order | `override_metadata_namespace` |
| Retry on 429, 5xx (529 included) and resets | `retry_on` + `retriable_status_codes` |
| Keep A's `Retry-After` from delaying B | leave `rate_limited_retry_back_off` unset |
| Attempt count | `num_retries` |
| Retain and replay the body | router (+ spool, 4.2) |
| Per-attempt rewrites | the attempt cluster's upstream filters |

The one need it would serve is classifying error *bodies*. For example, OpenAI returns 429 both for
`insufficient_quota` and for rate limits, and 400 for `context_length_exceeded`. Even then, an
upstream filter can read the small error body and set a response header before the router sees the
headers, and `retriable_headers` matches that header. That is an APM response feature for later,
not a new retry extension point.

## 7. PR plan

1. router: restore request headers per attempt on cross-cluster retry.
2. buffer: promote `ExternalBuffer` and the in-memory factory to core. No functional change.
3. ai_protocol_manager: split the passive spool out of `BufferManager` into common. No functional
   change.
4. router: spill the retry buffer into an external buffer: config, chunked paced replay, stats,
   docs and a release note.
5. router: expose `retainedRequestBody()` to upstream filters, and retain each frame before
   forwarding it.
6. ai_protocol_manager: borrow the router's retained body.
7. ai_protocol_manager: let an upstream chain declare its cluster's backend.

PRs 1 and 7 unblock cross-provider fallback whether or not any buffering lands. PRs 2 → 3 → 4 are
the buffer MVP. PRs 5 → 6 get to a single copy.

## 8. Decisions

- **D1. Where the spool is configured.** Recommended: the router filter config, since the storage
  backend is infrastructure. The alternative is per-route config on `RetryPolicy`.
- **D2. When to spill.** Recommended: only past the in-memory limit, which leaves today's behavior
  unchanged below it. The alternative is to spool from the first byte.
- **D3. Retries that start mid-upload.** Recommended: hold the spilled-body replay until downstream
  end of stream. The alternative is a replay that follows the live tail.
- **D4. Name of the core extension category** for external buffers.
- **D5. Borrow mode.** Recommended: an opt-in flag plus the length check. The alternative is to
  borrow automatically.
- **D6. How upstream filters reach the retained body.** Recommended: an
  `UpstreamStreamFilterCallbacks` accessor, which ties lifetime to the router and keeps the view out
  of downstream filters' reach. The alternative is filter state.
- **D7. Where an attempt's AI target comes from.** Recommended: the per-cluster APM config. The
  alternatives are cluster metadata or attributes on `priority_group` cluster entries.

## 9. Out of scope

- A disk or remote `ExternalBuffer` implementation.
- Replay that follows the live tail for retries that start mid-upload.
- Hedging combined with cross-cluster retry.
- Sharing with a downstream APM. The router needs the bytes after the AI filters have run, and the
  APM's buffer holds them as they arrived.
- Fanning out upstream-chain watermarks (the #46385 follow-up). The APM's own replay pacing needs
  it; the router's spool replay does not.
