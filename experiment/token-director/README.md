# AI Protocol Manager → Token Director demo

An end-to-end run of the AI Protocol Manager filter against the real OpenAI,
Anthropic and Gemini APIs, with an ext_proc "Token Director" that admits each
request against a token budget and settles it against the usage Envoy
extracted from the response.

The point of the demo is the **hand-off**: what the filter has to publish, when
it has to publish it, and how the external processor gets it without the proxy
shipping payload bytes over gRPC.

## Topologies

```
1)  client ──▶ DFP proxy :10000 ──▶ api.openai.com / api.anthropic.com / generativelanguage…
                  │
                  └─ mcp → [registry] → aipm(request) → ext_proc → dynamic_forward_proxy → router
                                                            │
                                        upstream chain:  aipm(response) → upstream_codec
                                                            │
                                                     Token Director :9000

2)  client ──▶ tunnel proxy :10010 ──▶ DFP proxy :10000 ──▶ providers
                  │
                  └─ mcp → [registry] → aipm(request) → ext_proc → router
                                                            │
                                        upstream chain:  aipm(response) → upstream_codec
```

`[registry]` is the slot for the model/provider registry filter. Until it
lands, the route table plays its part: it picks the provider host and declares
which AI wire API each endpoint speaks.

Topology 2 is an **HTTP forward-proxy hop, not a CONNECT tunnel**. A CONNECT
tunnel carries opaque TLS, so no filter above the transport could see a model
id or a usage record and neither hop could account for anything. Cleartext HTTP
between the two proxies is what keeps the payload visible at both.

## Why the filter is installed twice

Envoy runs decode filters in chain order and encode filters in reverse. That
single fact decides the whole design:

**Request path.** `aipm` sits ahead of `ext_proc`, and it holds the request
headers (`StopIteration`) until the payload has been offloaded, parsed and
validated — only then does it replay, and the first
`injectDecodedDataToFilterChain()` releases the held headers ahead of the body.
So by the time `ext_proc::decodeHeaders()` runs, the payload is already parsed
and `envoy.ai.request_info` is already published. ext_proc's **first** message
carries the model id and the pre-flight estimate in `metadata_context`, and
`request_body_mode: NONE` is enough.

**Response path.** A downstream `aipm` would run *after* `ext_proc` on encode —
too late to tell it anything. Response extraction therefore runs in the
cluster's **upstream** filter chain, which precedes the downstream encoder
chain. The record is published before ext_proc's message is built.

This is the PR's dual-filter placement doing real work: identical extraction in
either chain, first publication owns the namespace.

## The metadata contract

Two typed records, one per direction, both `google.protobuf.Any` in
`ProcessingRequest.metadata_context.typed_filter_metadata`:

| namespace | message | published | carried on |
|---|---|---|---|
| `envoy.ai.request_info` | `envoy.data.ai.v3.RequestInfo` | end of request payload parse, before replay | `request_headers` |
| `envoy.ai.token_usage` | `envoy.data.ai.v3.TokenUsage` | clean end of response stream | `response_trailers` |

`RequestInfo` carries the model, whether the client asked to stream, the
declared output cap (`max_tokens` / `max_output_tokens` /
`generationConfig.maxOutputTokens` — exact, and free), a pre-flight
`estimated_input_tokens` with the `estimation_method` that produced it, and the
turn and tool counts.

The estimate is deliberately crude — bytes of prompt-bearing text over a fixed
bytes-per-token ratio, plus a per-turn framing allowance. A real tokenizer is
model-specific and far too expensive for a hot path; the estimate is an
**admission bound**, and the Director settles it against the provider's own
counts the moment the response ends.

One detail worth calling out: the estimator measures *lengths*, never content.
A prompt large enough to be offloaded is not in the DOM at all — it rides as an
external reference carrying its length — so a multi-megabyte prompt is measured
without reading a byte of it.

## Declared routes vs. a true DFP catch-all

The four provider routes declare their wire API, which is what lets the filter
read a request payload at all. But a real DFP egress listener has no such
routes — the provider comes from the Host header, not from configuration. The
`dfp_passthrough` route is that shape: `prefix: "/"`, no `typed_per_filter_config`
of any kind.

`request_info.include_unconfigured_routes: true` brings that route into scope,
and the wire API then resolves the same way the response side resolves it —
per-route declaration, then `default_api_protocol`, then detection from the
request. Here nothing is declared, so detection decides. Verified live:

```bash
curl http://127.0.0.1:10000/v1/chat/completions \
  -H "Host: api.openai.com" -H "authorization: Bearer $OPENAI_API_KEY" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4o-mini","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}'

[   dfp] #1 admit   gpt-4o-mini  reserved 43 (est_in=11, max_out=32)
[   dfp] #1 settle  gpt-4o-mini  in=12 out=2 total=14 (complete)

ai_protocol_manager.request_info_protocol_detected: 1
```

The same undeclared route handles Gemini too — `:generateContent` in the
target, model read out of the path:

```
[   dfp] #2 admit   gemini-3.6-flash  reserved 43 (est_in=11, max_out=32)
[   dfp] #2 settle  gemini-3.6-flash  in=6 out=0 total=6 (complete)
```

Detection only fills a gap: run the declared routes afterwards and
`request_info_published` climbs while `request_info_protocol_detected` stays
put. And it can only name a record, never reject a request — an unconfigured
route is parsed best-effort, and schema validation still runs solely against a
wire API the route itself declared.

## Getting the record to ext_proc

`ext_proc` rebuilds `metadata_context` on **every** message it sends
(`addDynamicMetadata()` runs in `buildHeaderRequest`, `setupBodyChunk` and
`sendTrailers`). So a record published late still arrives — as long as some
message is sent *after* publication. The request side gets this for free. The
response side needs a message at end of stream, and the options are:

1. **A synthesized trailer** — what this demo uses. `usage_signal:
   SYNTHESIZE_TRAILERS` makes the filter add response trailers at a clean end
   of stream *when the response carries none of its own*, purely so ext_proc's
   `response_trailer_mode: SEND` fires. Cost: one small gRPC message. No body
   bytes cross the boundary in either direction.
   - If the response already has trailers, nothing is synthesized — publication
     in `encodeTrailers()` already precedes ext_proc's trailer message.
   - HTTP/1.1 downstreams drop the synthesized trailers at the codec unless
     `enable_trailers` is set, so clients never see them. HTTP/2/3 clients see
     an empty trailer frame, which every SDK in this demo ignores.
2. **The last `STREAMED` body chunk** — works with no new code, but ships
   *every response byte* over gRPC (`setupBodyChunk` copies the body into the
   message). For SSE that is the entire generation, chunk by chunk. This is the
   cost the trailer signal exists to avoid; flip `response_body_mode: STREAMED`
   in the config to measure it.
3. **A gRPC access-log sink** — the natural home for pure accounting, but it
   cannot see this record today: `%DYNAMIC_METADATA%` and
   `METADATA(DYNAMIC:…)` read **untyped** metadata only, and there is no typed
   formatter in Envoy. The filter publishes typed metadata exclusively.
4. **A "stream complete" `ProcessingRequest`** — doesn't exist in the ext_proc
   API. It would be the cleanest answer and is worth proposing upstream.

Because of (3), the access-log lines in both configs deliberately show
`ai_request_info_typed` and `ai_token_usage_typed` rendering **empty**. The
`ledger` field next to them is the Director's reconciled record, written back
as *untyped* metadata over ext_proc (`receiving_namespaces.untyped`) — which is
how the data becomes loggable at all.

## What a run actually shows

Measured on this branch against the live APIs (`./run.sh demo`, then
`./run.sh ledger`):

```
#       hop model                        fr       in    out  total    est  drift status
----------------------------------------------------------------------------------------
3       dfp gemini-3.6-flash             json     11     60     71     81    +10 complete
4       dfp gemini-3.6-flash             sse      11      0     11     81    +70 complete
5       dfp gpt-4o-mini-2024-07-18       json     17     12     29     81    +52 complete
6       dfp gpt-4o-mini-2024-07-18       sse      17     12     29     81    +52 complete
7       dfp gpt-4o-mini-2024-07-18       json     17     13     30     76    +46 complete
8       dfp gpt-4o-mini-2024-07-18       sse      17      8     25     76    +51 complete
```

The estimate is dominated by `max_tokens`, which is what makes it a usable
admission *bound*: `est` is the worst case the request could cost, `total` is
what it did cost, and `drift` is the headroom the Director hands back at
settlement. The input half of the estimate was exact (17) on every OpenAI row.

Cost on the wire, per accounted request: **two gRPC messages, zero body bytes.**
Over the run above, `stream_msgs_sent: 14` for 8 admissions and 6 settlements.

The two-hop topology nests as you would expect, each hop accounting
independently off the same response:

```
[tunnel] #14   admit    gpt-4o-mini   reserved 81 (est_in=17, max_out=64)
[   dfp] #15   admit    gpt-4o-mini   reserved 81 (est_in=17, max_out=64)
[   dfp] #15   settle   gpt-4o-mini   in=17 out=12 total=29 (complete)
[tunnel] #14   settle   gpt-4o-mini   in=17 out=12 total=29 (complete)
```

And the policy path denies before the request ever reaches the provider:

```
[   dfp] #6    deny     gpt-4o-mini   estimate 81 exceeds headroom 55
→ 429 {"error":{"type":"token_budget_exceeded", ...}}
```

## Two things the demo turned up

**1. A compressed response is an uncountable response.** Every provider SDK
advertises `gzip, deflate, br` (or zstd) by default, and the filter refuses to
inspect a body it cannot read — the run just increments
`unsupported_content_encoding` and publishes nothing. The `decompressor` filter
is registered for downstream chains only, so it cannot be placed ahead of an
upstream-installed `aipm`; and in the downstream chain it would run *after*
ext_proc on the encode path anyway. Both configs therefore overwrite
`accept-encoding: identity` on the way out. Any deployment doing token
accounting on an egress hop has to make the same choice, and it is worth
saying so in the filter's docs.

**2. Streaming clients that hang up on `[DONE]` cost the outer hop its record.**
Through the two-hop topology, SSE settles at the DFP hop but *not* at the
tunnel hop. The access log shows `flags: "DC"` — the OpenAI SDK closes the
connection the moment it reads `data: [DONE]`, without draining the
terminating chunk. The tunnel proxy sees a downstream disconnect, resets its
upstream stream, and its observe-only filter never reaches the clean end of
stream that publication requires. Replaying the identical request with `curl`,
which drains fully, settles at both hops
(`cluster.next_hop_dfp.ai_protocol_manager.token_usage_found: 0 → 1`).

That is exactly the case for **usage-on-abort publication**, which the PR
lists as deferred. The inner hop is unaffected because it terminates the
provider connection itself, so the deferral is safe for a single gateway — but
in a chain, the hop closest to the client is the one that loses the record, and
that is often the hop that owns the customer's budget. A partial record
published on abort (with `extraction_status: PARTIAL`) would close the gap.

## Running it

Prerequisites: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` and `GEMINI_API_KEY` in
the environment, and an `envoy-static` built from this branch.

```bash
python3 -m venv .venv && .venv/bin/pip install grpcio grpcio-tools protobuf openai anthropic google-genai
./gen_protos.sh          # Python stubs, generated from this checkout's api/ tree
./run.sh up              # Director + both proxies
./run.sh demo            # all four dialects, JSON and SSE, through the DFP hop
./run.sh tunnel          # the same, through the extra hop
./run.sh report          # everything below in one pass
./run.sh down
```

Useful variations:

```bash
./run.sh demo --provider anthropic --framing sse
./run.sh demo --provider openai --max-tokens 2000 --repeat 5   # walk into the budget
BUDGET=500 ./run.sh up                                         # make denials easy to trigger
```

### Reading the results

| command | shows |
|---|---|
| `./run.sh ledger` | per-request accounting, per-model and per-hop totals, and how the admission estimate scored against actual usage |
| `./run.sh access` | Envoy's access logs from both proxies — and, deliberately, the two typed fields that render `null` next to the ledger that doesn't |
| `./run.sh stats` | filter counters split by instance (downstream request side vs. upstream response side) and the ext_proc traffic to the Director |
| `./run.sh report` | all three |
| `./run.sh director [n]` | tail the Director's admit/settle log |
| `./run.sh logs [n]` | tail every process log |

`stats` is where the design claim gets checked. The request-side counters only
ever move on the downstream instance and the response-side ones only on the
upstream (`cluster.*`) instance — which is the ordering argument, visible as
numbers. And the last line reports bytes-per-request to the Director:

```
dfp: 1396 bytes per request to the Director -- flat, no body in either direction
```

Flat is the point. It does not grow with prompt or generation size, because
neither ever crosses the gRPC boundary. Switch `response_body_mode` to
`STREAMED` and watch that number track the size of the response instead.

Logs land in `/tmp/token-director/`: `director.log`, `envoy-dfp.log`,
`envoy-tunnel.log`, the two access logs, and `ledger.jsonl`.

## Caveats

- The price table in `token_director.py` is illustrative, not authoritative.
- Anthropic is wired up and exercised, but the `ANTHROPIC_API_KEY` in this
  environment is rejected (`401 authentication_error`) by the API directly,
  not just through the proxy — so no Anthropic rows appear in the ledger
  above. Supply a working key and the route works like the others.
- Gemini's `generateContent` can spend the whole `max_output_tokens` budget on
  reasoning and return no text; row 4 above (`out=0`) is that, not a
  extraction failure.
- The budget lives in the Director process and resets when it restarts.
- `failure_mode_allow: false` on ext_proc is deliberate: admission is a policy
  decision, so a Director outage fails requests closed rather than silently
  admitting unbudgeted traffic.
- Both hops in topology 2 account independently. They are told apart at the
  Director by the `x-hop` gRPC initial metadata each proxy sends.
