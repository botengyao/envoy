# Per-tenant buffer & CPU accounting for water-fill load shedding

Status: design + prototype (L4/L7 filters implemented; core CPU hook design-only)
Branch: `water_fill_management`. Companion docs: `source/extensions/filters/http/ip_load_shed/DESIGN.md`
(water-fill algorithm, threading overview), `experiments/ip_load_shed/` (experiment harness + results).

This document answers one question: **how do buffer bytes and CPU time actually get attributed
to a tenant (source IP)** without slowing down the data path — the accounting problem. All
file/line references were verified against `main` (6806efb84e).

## 1. The shape of the problem

Envoy shares one heap and N worker event loops among all tenants. Neither memory nor CPU carries
a tenant label:

* The allocator cannot tag an allocation with the connection it serves; buffers move between
  codec, filter-manager, and connection buffers, and slices even migrate between buffers without
  copying (`OwnedImpl::coalesceOrAddSlice` keeps the *original* account on moved slices).
* A worker thread interleaves callbacks for hundreds of connections per event-loop iteration;
  CPU time exists only as "this thread was busy", never "this stream cost 40µs".

So both dimensions need *attribution machinery*, and it must obey Envoy's threading contract:
no locks or atomics on the per-request path, thread-confined writes, main-thread aggregation.
Everything below is organized as: what exists today (facts), what to build (design), and what
each layer (L4 vs L7) can and cannot see.

## 2. Buffer accounting

### 2.1 What exists today: `BufferMemoryAccount` (facts)

* One account **per downstream HTTP stream**, created in `ConnectionManagerImpl::newStream`
  (`conn_manager_impl.cc:419-431`) from the **per-worker-dispatcher** `WatermarkBufferFactory`
  (`dispatcher_impl.cc:61-64`) — all account state is worker-local by construction, no locks.
* Accounts exist **only when** bootstrap `overload_manager.buffer_factory_config.
  minimum_account_to_track_power_of_two` (range [10,56]) is set; otherwise `createAccount`
  returns nullptr and all wiring is a no-op.
* Coverage is effectively **HTTP/2 only**: the H2 codec binds `pending_recv_data_`/
  `pending_send_data_` (`http2/codec_impl.cc:979-983`), and the router re-attaches the
  downstream account to H2 upstream streams (`upstream_request.cc:646`) and shadow requests.
  HTTP/1 and HTTP/3 store the pointer solely for reset notification (explicit TODO in
  `http1/codec_impl.h:79-85`). Connection read/write buffers, filter-manager buffered
  request/response data (`filter_manager.cc:406,1873`), headers, TLS and codec-internal memory
  are **never charged**.
* The account interface has **no balance getter** (`envoy/buffer/buffer.h:107-140` — only
  `charge/credit/clearDownstream/resetDownstream`); `balance()` exists only on the impl
  (`watermark_buffer.h:119`). A filter can reach the account via
  `StreamDecoderFilterCallbacks::account()` (`filter.h:866-869`) but cannot read it.
* Accounting granularity is slice **capacity**, not bytes used; charge/credit fire on every
  slice allocate/release — the hot-path budget precedent already exists.
* The existing consumer, `envoy.overload_actions.reset_high_memory_stream`, runs per worker
  (`worker_impl.cc:206-210`) and resets the largest accounts bucket-first — the closest
  in-tree analogue to a shedding actuator.

### 2.2 The design: three accounting tiers

The water-fill solver only needs a per-tenant scalar, so the buffer dimension is built as three
tiers of increasing fidelity, each swappable behind `WaterFillController::addUsage()`:

**Tier 1 — filter-observed bytes (implemented, both layers).**
The L7 filter charges `stream_cost_bytes` + every body byte seen in `decodeData`/`encodeData`;
the L4 filter charges `connection_cost_bytes` + every byte seen in `onData`/`onWrite`. Released
in one lump on stream/connection destruction. This is an *upper bound proxy* (bytes seen, not
bytes currently buffered): cheap, protocol-agnostic, worker-thread-only — but it overstates
long-lived streams (a 1-hour gRPC stream keeps its cumulative count) and understates nothing.

**Tier 2 — real buffered bytes via a tenant ledger charged from account call sites (core
change, the production path).** Two small upstream changes make the existing machinery
tenant-aware:

1. Add `virtual uint64_t balance() const` to `BufferMemoryAccount` (trivial; impl already has
   it) — this alone lets a periodic sampler read true per-stream buffered bytes.
2. Give `WatermarkBufferFactory` an optional **tenant ledger**: `createAccount()` grows a
   variant that takes the connection's `ConnectionInfoProvider` (available at the single
   choke point, `newStream`), and `BufferMemoryAccountImpl::charge/credit` additionally
   update `ledger_[tenant_key] += / -= amount`. Because the factory is per-dispatcher, the
   ledger is a plain (unlocked) `flat_hash_map<string, int64_t>` — the same structural
   thread-safety the bucket sets rely on today. The water-fill harvest (§4) then reads each
   worker's ledger instead of (or in addition to) the filter-observed shards.

   This measures *actually buffered* bytes — charged as buffers fill, credited as they drain —
   fixing the long-lived-stream overcount. Its blind spots are inherited from account
   coverage: H2-only today. Extending H1 (the codec TODO) and H3 (QUICHE buffer simulation
   already computes buffered-byte deltas in `envoy_quic_stream.h:112-134` — route them to
   `charge/credit`) closes the gap incrementally, and every improvement to account coverage
   automatically improves tenant attribution.

**Tier 3 — L4 connection buffers (only visible at L4).** Connection read/write buffers are
account-less watermark buffers, but an L4 filter is in the right position to observe them:
`onData` hands the filter the connection read buffer itself (its `length()` is the current
read-side depth), and the mutable `Connection&` allows `addConnectionCallbacks` for
write-buffer high/low watermark events plus `addBytesSentCallback` for drain observation.
Sampling read-buffer depth + a watermark-derived write-side estimate gives a per-tenant
connection-buffered-bytes signal. (The prototype L4 filter uses Tier 1 counting; Tier 3
sampling is an incremental follow-up.)

**Why keep Tier 1 at all once Tier 2 exists:** Tier 1 charges the *flow* (bytes moved), Tier 2
the *stock* (bytes parked). Under memory pressure the stock is what kills you, but the flow is
what predicts who is about to park more. Weighted sum `u = stock + λ·flow_ewma` (λ small) is
the practical blend; the solver is agnostic.

### 2.3 What each layer can see (buffer)

| signal | L7 filter | L4 filter | core change needed |
| --- | --- | --- | --- |
| body bytes in flight (Tier 1) | ✅ decode/encodeData | ✅ onData/onWrite | none (implemented) |
| per-stream buffered bytes (Tier 2) | via account, needs `balance()` | ❌ (no accounts at L4) | small |
| connection read/write buffer depth | ❌ (const `Connection`) | ✅ direct | none |
| wire/header bytes (`BytesMeter`) | ✅ `streamInfo().getDownstreamBytesMeter()` — free to diff | ❌ | none |
| request-less idle connections | ❌ invisible | ✅ connection_cost at accept | none (implemented) |

## 3. CPU accounting

### 3.1 What exists today (facts)

* **No per-thread CPU clock anywhere in the tree** (grep: zero hits for
  `CLOCK_THREAD_CPUTIME_ID`/`thread_info`/`RUSAGE_THREAD` outside vendored code), and no
  per-callback duration measurement — dispatcher stats are per-loop-iteration wall clock
  (`loop_duration_us`, off by default), and the watchdog touch is a boolean.
* **The attribution hook already exists**: every data-path callback brackets itself with
  `ScopeTrackerScopeState`, pushing a `ScopeTrackedObject` onto a per-dispatcher stack
  (`dispatcher_impl.cc:415-431`). The outermost frame is `ConnectionImpl::onFileEvent`
  (`connection_impl.cc:720`); HCM streams, codec dispatch, timers with a tracked object, and
  the QUIC context listener all push nested frames. `trackedStream()` on the tracked object
  returns the `StreamInfo`, whose `downstreamAddressProvider()` is the tenant key.
* `ExecutionContext` (`envoy/common/execution_context.h`) is architecturally the same hook with
  activate/deactivate callbacks, but it is compiled out by default (`--define
  execution_context=enabled`), nothing installs its FilterState object in production, and each
  activation does a FilterState hash lookup — **not viable as-is**.
* Global CPU pressure for the overload manager exists: `envoy.resource_monitors.
  cpu_utilization` (HOST = /proc/stat deltas; CONTAINER = cgroup v2/v1; Linux-only; EWMA
  α=0.05 → ~20 refresh-interval time constant). An overload action may combine multiple
  triggers with max-wins semantics (`overload_manager_impl.cc:326-336`), so one
  `shed_tenant_load` action can ramp on *either* heap or CPU pressure.

### 3.2 The design: scope-transition CPU attribution (core change)

The sound signal is **thread-CPU time per outermost tracked scope**, attributed to the tracked
stream's tenant:

1. **A portable `Thread::currentThreadCpuTime()`** (new, ~30 lines beside
   `source/common/common/thread.h`): `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` on both Linux
   and macOS (measured 105ns/read on Apple Silicon — 5× cheaper than mach `thread_info` at
   532ns, see E3; note the Linux vDSO fast path covers only the wall clocks, so
   `CLOCK_THREAD_CPUTIME_ID` is a real syscall there too, order ~100-300ns), and
   `GetThreadTimes` on Windows (`QueryThreadCycleTime` returns cycles, not time).
2. **Instrument the stack transitions, not every push.** In `DispatcherImpl::
   pushTrackedObject`: if the stack was empty, read the CPU clock and remember the top-level
   object. In `popTrackedObject`: if the stack becomes empty, read again and charge
   `delta` to the tenant resolved **once** from `object->trackedStream()
   ->downstreamAddressProvider()` (cache the resolved key on the transition, not per pop).
   Nested pushes (codec → stream → filter-manager) cost nothing — only the empty↔non-empty
   transitions pay, i.e. exactly two clock reads per dispatcher callback that touches a
   connection. Timers armed with a tracked object and the QUIC context listener are covered
   for free; `post()` callbacks and deferred deletion are not attributed (they run with an
   empty stack) — acceptable: that work is proxy overhead, not tenant work.
3. **Charge into the per-worker ledger** (§4) as an EWMA *rate*: unlike buffer bytes (a level
   that credits back), CPU is a flow, so the ledger keeps
   `cpu_ewma = α·delta/interval + (1-α)·cpu_ewma` folded at harvest time; a tenant that stops
   burning CPU decays out of the shed set within a few intervals. Deltas are plain thread-local
   integer adds — no atomics.
4. **Sampling knob.** The thread-CPU read is a syscall on every platform (~100-500ns), so at
   very high callback rates attribute every Nth transition scaled by N (per-worker counter, no
   randomness needed — callback interleaving decorrelates). A wall-clock substitute via
   `approximateMonotonicTime()` does **not** work: that value is refreshed once per event-loop
   iteration, so intra-iteration deltas are zero by construction; a real wall-clock read
   (`steady_clock`, ~12ns) is the only cheap fallback, at the cost of counting blocking time
   as CPU. Measured numbers in `experiments/ip_load_shed/RESULTS.md`.

This is a small core change (dispatcher + a thread util), gated by a bootstrap flag so the
default build pays only the `tracked_object_stack_.empty()` check it already performs. The
extension-only fallback — filters timing their own callbacks — was rejected: it misses codec
parsing, TLS, and connection-level work, which is precisely where an abusive tenant burns CPU.

### 3.3 Per-dimension severity and multi-resource fairness

* **Severity**: configure the `shed_tenant_load` action with two scaled triggers —
  `fixed_heap` (0.80→0.90) and `cpu_utilization` (e.g. 0.85→0.95). Action state is the max of
  the two ramps; the controller consumes it unchanged via `registerForAction`. (Tune the
  overload `refresh_interval` down from 1s and remember the cpu monitor's own α=0.05 EWMA
  makes it slow; for a fast CPU dimension a leaner monitor or a smaller dampening constant is
  a follow-up.)
* **Who to shed** when the two dimensions disagree: dominant-resource fairness (DRF).
  Normalize per tenant: `share_mem = u_mem / heap_capacity`, `share_cpu = cpu_ewma /
  (workers × 1s)`; feed the solver `u_i = max(share_mem, share_cpu)` (scaled to integers).
  Properties inherited from DRF: a tenant heavy in *either* dimension surfaces; a tenant light
  in both is untouched for any severity < 1. The solver (`water_fill.cc`) needs no change —
  it already takes opaque scalars.

## 4. The accounting plane: threading (the tricky part)

The prototype ships with 64 striped `absl::Mutex` shards — correct, contention-negligible at
10k tenants, and easy to reason about. The production plane removes even that, copying the two
proven Envoy patterns verbatim:

* **Harvest (workers → main): the stats-histogram merge choreography**
  (`thread_local_store.cc:272-296`). Per worker, the tenant ledger is double-buffered exactly
  like `ThreadLocalHistogramImpl::histograms_[2]`: hot-path writes go to `active`;
  `runOnAllThreads(swap_cb, completion_cb)` flips each worker's buffers on its own dispatcher;
  the completion (guaranteed to run on main after every worker flipped) folds the inactive
  buffers into the global per-tenant table. Workers never see a lock; main never reads a
  buffer a worker is writing. Rules copied with the pattern: never capture the slot or its
  owner in the closures (capture `shared_ptr` snapshots), enforce a single in-flight merge and
  re-arm the timer only from the completion path, and guard every publish with
  `tls_->isShutdown()` since completions may never fire during shutdown.
* **Publish (main → workers): the overload-manager flush** (`overload_manager_impl.cc:
  721-739`): swap the decision into a `shared_ptr<const ShedSnapshot>`, one
  `runOnAllThreads` without completion, workers overwrite their TLS pointer. Already
  implemented in `water_fill_controller.cc`.

Cadence: 100ms evaluation (vs 1s overload refresh, 5s stats flush) — staleness of one interval
is the price of a lock-free data path, and the scaled severity ramp gives hysteresis.

Budget per data-path operation (targets; measured numbers in `RESULTS.md`):
Tier-1 accounting = one striped-mutex add today (21-35ns measured), one thread-local add in
the TLS design; shed check = one TLS shared_ptr read + one hash lookup; CPU attribution = two
thread-CPU clock reads per dispatcher callback (~105ns each measured on macOS, similar order
on Linux), amortized over every stream touched in that callback.

## 5. The L4/L7 split

Both filters share one `WaterFillController` (`filters/common/ip_load_shed`), one usage map,
one shed snapshot — a tenant's usage is the sum of what both layers observe, and a shed
decision binds both layers on the next tick.

| | L7 `envoy.filters.http.ip_load_shed` | L4 `envoy.filters.network.ip_load_shed` |
| --- | --- | --- |
| shed unit | new stream → 503 + `x-envoy-ip-load-shed` (retriable, per-request granularity, works mid-connection on H2/H3 multiplexed conns) | new connection → close at accept (cheapest possible rejection: no codec, no TLS for plaintext; protects even the accept path) |
| accounts | stream cost + body bytes; Tier 2 account balance (production) | connection cost + bytes both directions; Tier 3 buffer depth (follow-up) |
| sees | per-stream fairness inside a shared connection; response bodies | raw TCP; request-less/idle connections; bytes before HTTP parsing |
| blind to | tenants that never send a request; non-HTTP listeners | which stream on a multiplexed connection is heavy; can't send an HTTP error |
| ambient role | waypoint / L7 node proxy | ztunnel-style L4 node proxy |
| CPU attribution (§3.2) | covered — HCM/codec scopes carry `trackedStream()` | covered — `onFileEvent` scope carries the connection's stream info |

Deployment on one listener chain (L4 filter before HCM) composes: the L4 filter sheds
connection floods and accounts connection overhead; the L7 filter sheds per-stream and
accounts bodies. Double counting is by design, not a bug: the two layers charge different cost
components (connection overhead vs stream payload) into the same ledger.

Deciding *which* to reject at a given severity is the same water level — a tenant above `L`
gets neither new connections (L4) nor new streams on existing connections (L7), so a heavy
tenant cannot dodge the L4 gate by multiplexing harder.

## 6. Experiments

Harness, configs, and traffic generators live in `experiments/ip_load_shed/`; measured results
in `RESULTS.md` there. Summary of method:

* **E1 (L7)** and **E2 (L4)**: 40 tenants (8 heavy, 32 light) simulated from one host via the
  PROXY protocol listener filter (`tenant_key_source: REMOTE_ADDRESS`); severity driven
  deterministically by the `injected_resource` monitor through the
  `envoy.overload_actions.shed_tenant_load` scaled trigger (0.80→0.90) while pressure sweeps
  0.70 → 0.95. Assert: light-tenant success rate stays ~100% until deep in the ramp, heavy
  tenants shed progressively, everything sheds ≥0.90, and recovery is clean when pressure
  drops.
* **E3 (accounting microbench)**: water-fill solve latency at 1k/10k/100k tenants, striped-map
  `addUsage` throughput under 1/4/8 threads, and thread-CPU clock read cost (the §3.2 budget)
  on this platform.
