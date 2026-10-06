# OpenTelemetry GenAI semantic conventions in the AI Protocol Manager

Phase 1 covers metrics. Spans and events follow (section 10).

Spec: [open-telemetry/semantic-conventions-genai](https://github.com/open-telemetry/semantic-conventions-genai)
pinned at `cb10b70c15` (2026-10-05), schema `gen-ai-dev/1.42.0-dev`. Every GenAI convention is
**Development** stability and the repo has no release yet. It is still making breaking changes:
#374 replaced the `gen_ai.client.token.usage` histogram and its `gen_ai.token.type` attribute with
the `inference.usage.*` counters and `inference.operation.*` histograms below. Two consequences:

- Keep the whole vocabulary (metric names, attribute keys, enum values) in one file, so a spec
  change touches one file.
- Ship behind `work_in_progress` and document the pinned spec revision.

## 1. Envoy emits client metrics

The spec defines a client family (`gen_ai.client.*`: the caller of a provider) and a model-server
family (`gen_ai.server.*`: the process that generates tokens). Envoy calls the provider on the
application's behalf and generates no tokens, so it emits the **client** family. The client family
now covers streaming latency (`time_to_first_chunk`, `time_per_output_chunk`), which removes the
reason to borrow `gen_ai.server.time_to_first_token`.

envoyproxy/ai-gateway emits `gen_ai.client.token.usage` (removed by #374) plus
`gen_ai.server.request.duration`, `time_to_first_token` and `time_per_output_token`, so dashboards
built for it will not carry over. We do not add a compatibility mode in phase 1.

## 2. Metric set

| Metric | Instrument | Envoy stat | Recorded |
|---|---|---|---|
| `gen_ai.client.operation.duration` | histogram, `s` | histogram, ms | every operation, errors included |
| `gen_ai.client.operation.time_to_first_chunk` | histogram, `s` | histogram, ms | SSE responses only |
| `gen_ai.client.operation.time_per_output_chunk` | histogram, `s` | histogram, us | once per SSE event after the first (opt-in) |
| `gen_ai.client.inference.usage.input_tokens` | counter, `{token}` | counter | usage extracted |
| `gen_ai.client.inference.usage.output_tokens` | counter | counter | usage extracted |
| `gen_ai.client.inference.usage.cache_read.input_tokens` | counter | counter | provider reported it |
| `gen_ai.client.inference.usage.cache_write.input_tokens` | counter | counter | provider reported it |
| `gen_ai.client.inference.usage.reasoning.output_tokens` | counter | counter | provider reported it |
| `gen_ai.client.inference.operation.input_tokens` | histogram, `{token}` | histogram, unspecified | usage extracted |
| `gen_ai.client.inference.operation.output_tokens` | histogram, `{token}` | histogram, unspecified | usage extracted |

`TokenUsage` already matches the spec's definitions, so the counters need no new extraction:

| Spec | `TokenUsage` field (after `finalize()`) |
|---|---|
| input tokens, cached included | `input_tokens` (inclusive) |
| output tokens, reasoning included | `output_tokens` (inclusive) |
| cache read | `cached_input_tokens` |
| cache write | `cache_creation_input_tokens` |
| reasoning | `reasoning_tokens` |
| (no counter) | `tool_use_input_tokens`, `provider_total_tokens`: not emitted |

Rules:

- **Extraction status.** Token metrics are emitted for `COMPLETE` and `PARTIAL` records and
  skipped for `FAILED` or missing usage. A `PARTIAL` count is a lower bound, and dropping it would
  undercount spend by more. `token_usage_partial` already counts these records.
- **Estimates are excluded.** `RequestInfo.estimated_input_tokens` is a byte heuristic, and the
  spec forbids reporting usage that was not counted.
- **Modality.** `gen_ai.token.modality` is required on the counters. Phase 1 always reports
  `unknown`, which the spec defines as "the provider gave no modality breakdown." A later PR
  splits by modality where the provider reports one (Gemini `promptTokensDetails`, OpenAI
  `audio_tokens`).
- **What counts as a chunk.** One chunk is one dispatched SSE event, matching what SDK
  instrumentation sees when it iterates a stream. Comments, heartbeats (Anthropic `ping`) and the
  OpenAI `[DONE]` sentinel are excluded. Events decoded from the same `encodeData()` buffer share
  one timestamp, so their deltas are 0, as a client reading that buffer would also see.

## 3. Attributes

| Attribute | Level | Source |
|---|---|---|
| `gen_ai.operation.name` | Required | upstream `LLMProtocol`: chat completions, responses, messages → `chat`; Gemini → `generate_content` |
| `gen_ai.provider.name` | Required | in order: upstream cluster metadata, the filter's default, the value inferred from the protocol (`openai`, `anthropic`, `gcp.gen_ai`) |
| `gen_ai.request.model` | Cond. required | `envoy.ai.model.request` filter state (written by the `request_info` AI filter) |
| `gen_ai.response.model` | Recommended | `TokenUsage.model` |
| `server.address` / `server.port` | Recommended / Cond. | upstream host `hostname()` and port; omitted when the hostname is empty, so a pool of IP endpoints does not create one series per IP |
| `error.type` | Cond. required | section 5 |
| `gen_ai.token.modality` | Required, counters only | `unknown` (phase 1) |

On the provider fallback: the spec calls `gen_ai.provider.name` "the instrumentation's best
knowledge" and a "discriminator ... of the telemetry format flavor". That makes inferring it from
the wire protocol legitimate as a last resort. Cluster metadata is still the primary source,
because a cluster is what represents a provider (an OpenAI-compatible vLLM pool is not `openai`).

If the operation name cannot be resolved (protocol unspecified and not auto-detected), nothing is
emitted for that stream.

## 4. Operation boundary and timing anchors

A spec "operation" is one model API call. In Envoy terms that is one upstream attempt.

- **Upstream placement** (the filter in the router's upstream HTTP filter chain) gives one
  operation per attempt. Retries and model fallback across providers each record their own
  operation with their own provider, model and `error.type`. This is the recommended deployment
  for metrics.
- **Downstream placement** records the attempt that produced the response. Retried attempts are
  invisible.
- **Both placements**: use the same first-writer-wins guard that token publication uses, so a
  response is never counted twice.

Anchors, all read from `StreamInfo` monotonic timing so both placements work the same way:

| Value | Start | End |
|---|---|---|
| duration | `first_upstream_tx_byte_sent_`; when no attempt was made, `lastDownstreamRxByteReceived` | `last_upstream_rx_byte_received_`, else completion time |
| time to first chunk | same start | first SSE event seen by the response handler |
| time per output chunk | previous event | current event |

Recording happens once, in `onStreamComplete()`, which runs for every stream before access
logging, including error responses and local replies. The three timing metrics then share one
resolved attribute set, which matters because `response.model` is only known late.
Per-chunk deltas are buffered per stream as `uint32` microseconds, capped at
`max_parsed_sse_events`.

## 5. `error.type`

The spec asks for a low-cardinality, documented list. In order:

1. The upstream returned a status of 400 or higher: the status code (`"429"`, `"500"`).
2. Envoy ended the attempt: the response flag, with `UT` mapped to `timeout` and every other
   flag reported by its Envoy long name (`UpstreamConnectionFailure`, `UpstreamOverflow`,
   `DownstreamConnectionTermination`, ...).
3. A 2xx stream that carried an in-band error (`ExtractionResult::stream_error`, for example
   Anthropic `event: error`): `stream_error` in phase 1. A follow-up reports the provider's own
   error type (for example `overloaded_error`).

Local replies sent before any upstream attempt (schema rejection, local rate limit) are gateway
decisions, not provider calls, and are not recorded. Envoy's own filter stats already count them.

## 6. Cardinality and untrusted input

`gen_ai.request.model` comes from the request body, so a client can make it unbounded. Envoy stats
are not freed until their scope is released, which makes an unbounded tag value a memory DoS
vector. Defenses, from most to least specific:

1. **Model values are trusted only after the provider accepts them.** On a non-2xx response,
   `gen_ai.request.model` is reported as `_OTHER`; the provider rejecting an unknown model with a
   4xx is what keeps junk out. `gen_ai.response.model` comes from the upstream and is not
   affected.
2. **Values are sanitized.** Each value is length-capped, and control characters are stripped.
3. **The scope is bounded as a backstop.** The stats live in a scope built from
   `envoy.type.v3.Scope` (`max_counters`, `max_histograms`, `enable_eviction`), as the stats
   access logger does. Past the limit, Envoy hands back a null stat and increments its overflow
   counter, so data is dropped, never memory.

## 7. Export path

The metrics are emitted as ordinary Envoy stats; no OTLP code is added to the filter.

- **Names.** Stats are created with `counterFromTaggedName()` / `histogramFromTaggedName()`. The
  base name is the spec metric name, the tags are the spec attributes, and the scope prefix is
  empty. The OTel stat sink's defaults (`use_tag_extracted_name: true`,
  `emit_tags_as_attributes: true`) then export exactly `gen_ai.client.operation.duration{gen_ai.provider.name=...}`.
  Prometheus and the admin endpoint get the sanitized form for free.
- **Buckets.** Envoy histogram buckets come from bootstrap
  `stats_config.histogram_bucket_settings`. The docs ship the spec's boundaries, converted to the
  recording unit:
  - duration and time to first chunk: 10, 20, 40, ... 81920 ms
  - time per output chunk: 10000 ... 81920000 us
  - token histograms: 1, 4, 16, ... 67108864
- **Seconds.** The OTel sink does not set `unit` and does not rescale values. Phase 1 documents an
  OTel Collector `transform` processor `scale_metric(0.001, "s")` (to be verified against the
  current OTTL). A separate PR teaches the sink to emit `unit` from `Histogram::Unit` and to
  optionally convert ms/us histograms to seconds by scaling the bounds and the sum. That change is
  useful outside AI traffic as well.
- **Statsd cost.** A sink that forwards every histogram value (statsd) sends one packet per
  recorded chunk. This is why `time_per_output_chunk` is opt-in.

## 8. Where the code lives

The recorder goes in the AI Protocol Manager core, beside token usage. It does not become a new
`envoy.http.ai_filters.*` extension, for these reasons:

- **Observe-only.** It needs SSE event timing from the observe-only `ResponseHandler`. An AI filter
  only sees frames through `encodeSSE()`, which pushes the response through the buffer and replay
  pipeline. An observer should not change how the response is delivered.
- **Non-2xx coverage.** It must see error responses and failed attempts. AI filters only run on
  2xx SSE/JSON bodies and have no completion hook.
- **Data ownership.** It consumes the finalized `TokenUsage`, which the core owns today.

This lines up with the deferred item "move token-usage publication into an AI filter": when
response-path AI filters gain completion and observer hooks, publication and metrics can move out
together.

Files:

- `gen_ai_semconv.h`: the vocabulary from the pinned revision: names, attribute keys,
  `LLMProtocol` → operation name, `LLMProtocol` → provider fallback.
- `gen_ai_metrics.{h,cc}`:
  - `GenAiMetricsConfig`: scope, a `StatNamePool` of the fixed names, the default provider.
  - `GenAiMetricsRecorder`: per stream; holds the anchors and chunk deltas, and does
    `record(StreamInfo, const TokenUsage*)`.
- `response_handler.{h,cc}`: `onData()` reports how many SSE events it dispatched, so the filter
  can timestamp them with the dispatcher's time source. Event boundaries come from the scanner,
  so chunk timing does not depend on the JSON parse budget.
- `filter.{h,cc}`: create the recorder in `encodeHeaders()` for in-scope routes regardless of
  status, and call `record()` from `onStreamComplete()`.

## 9. API sketch

```proto
message ResponseHandling {
  TokenUsageExtraction token_usage = 1;

  // OpenTelemetry GenAI semantic-convention metrics. Requires ``token_usage``.
  GenAiMetrics gen_ai_metrics = 2;
}

message GenAiMetrics {
  // Scope for the metrics. Leave ``prefix`` empty so stat names are the convention's metric
  // names; the limits bound attribute cardinality.
  type.v3.Scope stats_scope = 1;

  // gen_ai.provider.name when the upstream cluster's metadata names none.
  string default_provider_name = 2;

  // Records gen_ai.client.operation.time_per_output_chunk, one observation per SSE event.
  bool record_output_chunk_timing = 3;
}
```

The cluster-level provider is read from
`filter_metadata["envoy.filters.http.ai_protocol_manager"]["provider_name"]` on the upstream
cluster.

## 10. PR sequence

1. **Token metrics.** API (`GenAiMetrics`), vocabulary header, recorder for the five counters and
   two histograms. Attributes: operation, provider, request/response model, server.*, modality.
   Includes unit tests (attribute mapping, cardinality rules), filter tests on a
   `TestUtility` store asserting tag sets, an integration test, docs and a changelog. Smallest
   useful slice: the data already exists.
2. **Duration and `error.type`.** The `onStreamComplete()` path, timing anchors, the error mapping
   and the both-placement guard.
3. **Streaming latency.** The `ResponseHandler` event hook, time to first chunk, and opt-in time
   per output chunk.
4. **OTel stat sink.** Emit `unit` and optionally convert time histograms to seconds. Not AI
   specific.
5. **Modality split and provider error types.** Gemini/OpenAI modality details, and in-band error
   types reported as `error.type`.

Later phases, for scope only:

- **Spans.** Set inference span attributes (`gen_ai.operation.name`, `gen_ai.request.*`,
  `gen_ai.response.*`, `gen_ai.usage.*`) and the span name `{operation} {model}` on the active
  tracing span. The upstream span maps naturally to one operation.
- **Events.** Opt-in content capture (input and output messages). This needs a privacy design
  first and is off by default.

## 11. Open decisions

1. **Client family only (section 1).** No `gen_ai.server.*` compatibility mode for ai-gateway
   dashboards.
2. **Core recorder, not an AI filter (section 8).**
3. **Request model is `_OTHER` on non-2xx (section 6).** The alternative is an explicit model
   allowlist, which is safer but means an operator edit for every new model.
4. **Provider inferred from the protocol as the last fallback (section 3).** The alternative is
   to emit nothing when no provider is configured.
5. **Per-chunk metric opt-in (section 7).** The spec marks it Recommended; it is gated on cost.
6. **Local replies with no upstream attempt are not recorded (section 5).**
7. **Model under rewrite.** With model fallback or transcoding, `gen_ai.request.model` should be
   the model sent upstream for that attempt. Phase 1 reads `envoy.ai.model.request`, the model the
   client asked for. It switches to the per-attempt model once the upstream-target filter state
   lands.
