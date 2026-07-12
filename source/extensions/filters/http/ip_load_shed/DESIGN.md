# IP-based water-fill load shedding for multi-tenant ambient Envoy

Status: prototype / design proposal
Branch: `water_fill_management`

## 1. Problem

An ambient-mode Envoy (node proxy / waypoint) terminates traffic from ~10,000 micro-VMs on
the same node. Each micro-VM is a tenant, identified by its source IP. All tenants share one
Envoy process and therefore one heap: connection buffers, codec buffers, buffered request and
response bodies, filter state.

Today the overload manager protects the *process* (e.g. `stop_accepting_requests` at 90% of
`max_heap_size_bytes`), but it is tenant-blind: when a handful of micro-VMs pin gigabytes of
buffered data, the overload actions punish all 10,000 tenants equally — or worse, the process
is OOM-killed and everyone loses.

Goal: **weighted fairness under memory pressure**.

* Heap < 80%: no interference; tenants can burst freely (work-conserving).
* Heap in [80%, 90%): shed *new* work from the heaviest tenants only, just enough to bring
  usage back under control. Light tenants must not notice.
* Heap >= 90%: shed all new work (existing overload behavior, kept as the backstop).

## 2. Water-filling theory

Let `u_1 … u_n` be the current per-tenant resource usage and `U = Σ u_i`. Given a shed
severity `s ∈ [0, 1]` derived from memory pressure, we want a **water level** `L` such that

```
Σ min(u_i, L)  <=  (1 - s) · U
```

Tenants with `u_i <= L` are below the water line and are never shed. Tenants with `u_i > L`
have their *new* work (new streams) rejected until their in-flight usage drains down to `L`.
As `s → 1`, `L → 0` and everything is shed.

This is the classic max-min-fairness water-fill: the shedding burden falls exclusively on the
heaviest users, in usage order. A tenant using less than the fair share is mathematically
guaranteed to be untouched for any `s < 1`.

Severity is the standard scaled-trigger ramp used by the overload manager:

```
s = clamp((pressure - 0.80) / (0.90 - 0.80), 0, 1)
```

so at 80% heap we shed nothing, at 85% we target shedding the heaviest half of in-flight
usage, at 90% we shed everything (and the overload manager's own `stop_accepting_requests`
action is expected to be configured at 0.9 as the process-wide backstop).

### Computing L — O(n log n)

Sort usages descending `u(1) >= u(2) >= … >= u(n)`, target `T = (1 - s) · U`, and walk the
prefix: after capping the top `k` tenants at level `L`, total usage is
`k·L + suffix_sum(k)`. Solve `L = (T - suffix_sum(k)) / k` and accept the first `k` where
`u(k+1) <= L <= u(k)`. With n = 10,000 and a 100 ms cadence this is microseconds of work on
the main thread. See `water_fill.cc`.

## 3. Threading model (the careful part)

Envoy is thread-per-worker: N workers each own an event loop; cross-thread data sharing on
the data path is forbidden by convention (no locks in per-request code, TLS + main-thread
aggregation everywhere else — same pattern as the stats store and the overload manager
itself).

The design splits into three planes:

```
            ┌────────────────────────── main thread ──────────────────────────┐
            │  WaterFillController (server singleton)                          │
            │  every evaluation_interval (default 100 ms):                     │
            │    1. read heap pressure (overload action state / Memory::Stats) │
            │    2. merge per-worker usage into global per-IP usage            │
            │    3. severity s → water level L → shed set {heavy IPs}          │
            │    4. publish immutable ShedSnapshot to all workers (TLS)        │
            └───────▲──────────────────────────────────────────┬──────────────┘
       usage deltas │                                          │ snapshot (RCU)
            ┌───────┴──────────┐                     ┌─────────▼─────────┐
            │ worker 0..N      │                     │ worker 0..N       │
            │ accounting plane │                     │ decision plane    │
            │ (writes, hot)    │                     │ (reads, hot)      │
            └──────────────────┘                     └───────────────────┘
```

### 3.1 Accounting plane (workers, per-request, write path)

#### Two resources, two roles

The design deliberately uses **two different resource measurements**:

* **The trigger resource — real process heap — decides *how much* to shed.** Severity `s`
  comes from actual allocator-reported memory (the `fixed_heap` monitor's
  `allocated / max_heap`, or `Memory::Stats::totalCurrentlyAllocated()` in self-contained
  mode). This is ground truth: it covers buffers, codec state, filter state, everything. The
  decision "we are at 84%, shed 40% of tenant load" is anchored to reality even though the
  per-tenant numbers below are estimates.
* **The per-tenant usage `u_i` — a cost proxy — decides *who* gets shed.** True heap
  attribution per source IP is impossible: the heap is one shared arena and the allocator
  cannot tag an allocation with the tenant it serves. So each tenant is charged an estimated
  cost per active stream instead.

#### What is charged to a tenant

```
u_ip = Σ_active_streams (stream_cost_bytes + bytes_seen_both_directions)
```

| component | charged | released | approximates |
| --- | --- | --- | --- |
| `stream_cost_bytes` (default 64 KiB) | stream admitted (`decodeHeaders`) | stream destroyed (`onDestroy`) | fixed per-stream overhead: connection/codec buffers, header maps, filter state, socket buffers |
| request body bytes | each `decodeData` chunk | stream destroyed | request data potentially buffered while an upstream is slow / backed up |
| response body bytes | each `encodeData` chunk | stream destroyed | response data potentially buffered for a slow-reading downstream (the classic slow-consumer memory attack) |

Aggregated across all of the tenant's streams on all workers. A micro-VM holding 200 open
streams while POSTing large bodies to a slow upstream accumulates a large `u_i`; a VM doing
quick small request/responses stays near zero because everything is released at stream end.

Properties of this proxy:

* **Upper bound, not a measurement.** Bytes are counted when *seen*, never decremented when
  the buffer actually drains (the filter cannot observe draining). A healthy fast stream may
  have megabytes "on the books" with ~0 actually buffered. The error is in the conservative
  direction: heavy movers look heavy.
* **Known weakness: long-lived streams.** A well-behaved gRPC stream that has been up for an
  hour keeps its cumulative byte count until destroy, overstating its buffered footprint.
  Acceptable for a prototype (it biases toward shedding the busiest tenants); first thing to
  fix for production — see below.
* **The solver doesn't care what "usage" is.** `computeWaterLevel()` takes a vector of
  scalars; any cost function works — bytes, streams, weighted blends
  (`α·streams + β·buffered_bytes`), request rate. Accounting sits behind
  `WaterFillController::addUsage()` precisely so the cost model can be swapped without
  touching the algorithm or the threading.

#### Prototype data structure

A single `TenantUsageMap` sharded 64 ways by IP hash, each shard a
`absl::Mutex + absl::flat_hash_map`. A request touches its shard 2–3 times over its lifetime
with a few-instruction critical section; at 10k tenants spread over 64 shards, contention is
negligible and correctness is easy to see.

#### Production follow-ups (noted, not prototyped)

1. **Real buffer accounting via `Buffer::BufferMemoryAccount`.** Envoy already tracks
   *actually buffered* bytes per stream (this powers
   `envoy.overload_actions.reset_high_memory_stream`): accounts are charged as buffers fill
   and credited as they drain. Aggregating stream accounts per source IP replaces the
   in-flight upper bound with a real measurement and fixes the long-lived-stream overcount.
2. **Connection-level costs.** An HTTP filter never sees tenants that open connections but
   send no requests, nor TLS handshake / socket buffer memory — that needs the L4 companion
   filter sharing the same controller.
3. **Thread-local shards.** Make the shard truly thread-local per worker and have the
   controller *harvest* by posting to each worker dispatcher and merging the returned copies
   (identical to `ThreadLocalStoreImpl` stats merging), removing even the striped mutex from
   the data path.
4. **Optional decay.** An EWMA or windowed decay on `u_i` so idle-but-open streams gradually
   stop counting.

### 3.2 Decision plane (main thread, periodic)

The `WaterFillController` is a server-scoped singleton created by the first filter config; it
runs a timer on the **main** dispatcher (`evaluation_interval`, default 100 ms):

1. **Pressure**: preferred source is the overload manager — a `fixed_heap` resource monitor
   with a scaled trigger `{scaling_threshold: 0.80, saturation_threshold: 0.90}` driving the
   new action `envoy.overload_actions.shed_tenant_load`; its `OverloadActionState` value *is*
   the severity `s`. Overload action names are allowlisted in core
   (`OverloadActionNameValues::WellKnownActions`), so this prototype adds the new name there —
   a two-line core change; the overload manager takes no direct action for it, extensions
   consume the state. The controller subscribes via
   `overloadManager().registerForAction(name, mainThreadDispatcher(), cb)` (the designed API:
   registration happens at filter-config load, before the overload manager starts; it returns
   `false` gracefully if the action is not configured). The prototype also supports a
   self-contained mode (`max_heap_size_bytes` in filter config) that computes pressure from
   `Memory::Stats::totalCurrentlyAllocated()` directly, so the filter works without overload
   manager config changes.
2. **Merge + solve**: snapshot the usage map, run the water-fill solve above.
3. **Publish**: build an immutable `ShedSnapshot{severity, water_level, shed_ips}` and
   post it to every worker through a `ThreadLocal` slot (RCU-style shared_ptr swap; same
   publication mechanism the overload manager uses for action state).

Staleness is bounded by one evaluation interval (100 ms) plus the TLS post latency, which is
the same order as the overload manager's own `refresh_interval` (250 ms default). Memory
pressure moves on a much slower timescale, and the scaled ramp gives natural hysteresis: as
shedding drains heavy tenants, pressure falls, severity falls, and the water level rises
smoothly instead of flapping.

### 3.3 Enforcement plane (workers, per-request, read path)

`IpLoadShedFilter::decodeHeaders`:

1. `key = downstreamAddressProvider().directRemoteAddress()` (the micro-VM's own IP; the
   *direct* remote, deliberately not XFF-derived, so tenants cannot spoof their identity).
2. One TLS load of the current `ShedSnapshot` + one hash-set lookup.
3. If shed: `sendLocalReply(503, "tenant over water level")` with
   `x-envoy-ip-load-shed: true` (503 is retriable-after-backoff by well-behaved clients;
   configurable to 429).
4. Otherwise: register an RAII accounting handle (increments usage now, decrements in
   `onDestroy`) and continue.

Cost per request on the hot path: one shared_ptr TLS read, one or two hash lookups, no locks
held across any callback. Unknown/new tenants are never shed at `s < 1` (they have no usage
yet, hence are below any positive water level).

## 4. Overload manager integration

The component is deliberately shaped as an overload-manager satellite:

* **Pressure source**: reuses the existing `fixed_heap` resource monitor — no new monitor.
* **Severity**: `OverloadActionState` from a scaled trigger already encodes the
  80→90% ramp as a `UnitFloat`; the controller just reads it via
  `overloadManager().getThreadLocalOverloadState().getState(action_name)`.
* **Backstop**: `envoy.overload_actions.stop_accepting_requests` at 0.9 remains configured;
  water-fill only makes the 80–90% band tenant-aware. At `s = 1` the filter also rejects
  everything, so behavior is correct even if the backstop action is absent.
* Longer term this generalizes to an `envoy.load_shed_points`-style hook where the shed
  decision callback receives connection/stream context (source IP) — today load-shed points
  only expose a context-free `shouldShedLoad()`, which cannot do tenant-aware shedding;
  that gap is exactly what this filter fills.

Example overload manager config (see `example_config.yaml` for the full bootstrap):

```yaml
overload_manager:
  refresh_interval: 0.25s
  resource_monitors:
  - name: envoy.resource_monitors.fixed_heap
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.resource_monitors.fixed_heap.v3.FixedHeapConfig
      max_heap_size_bytes: 2147483648   # 2 GiB
  actions:
  - name: envoy.overload_actions.shed_tenant_load          # 80%..90%: severity ramps 0 -> 1
    triggers:
    - name: envoy.resource_monitors.fixed_heap
      scaled: { scaling_threshold: 0.80, saturation_threshold: 0.90 }
  - name: envoy.overload_actions.stop_accepting_requests   # >= 90%: reject all (backstop)
    triggers:
    - name: envoy.resource_monitors.fixed_heap
      threshold: { value: 0.90 }
```

Filter config:

```yaml
http_filters:
- name: envoy.filters.http.ip_load_shed
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ip_load_shed.v3.IpLoadShed
    overload_action_name: envoy.overload_actions.shed_tenant_load
    # Self-contained fallback if the action is not configured:
    max_heap_size_bytes: 2147483648
    shed_start_threshold:  { value: 80 }   # type.v3.Percent
    reject_all_threshold:  { value: 90 }
    evaluation_interval: 0.1s
    stream_cost_bytes: 65536
```

## 5. Observability

Per-filter-scope stats:

| stat | type | meaning |
| --- | --- | --- |
| `ip_load_shed.shed_total` | counter | streams rejected by water-fill |
| `ip_load_shed.severity` | gauge (‰) | current shed severity s × 1000 |
| `ip_load_shed.water_level_bytes` | gauge | current water level L |
| `ip_load_shed.tenants_tracked` | gauge | tenants with non-zero usage |
| `ip_load_shed.tenants_shed` | gauge | tenants above the water line |
| `ip_load_shed.total_usage_bytes` | gauge | Σ u_i |

## 6. Failure modes & limits

* **IPv6 / many IPs**: tenant key is the raw IP bytes; 10k entries ≈ hundreds of KB — the
  tracker itself must never become the memory problem. Map capacity is bounded
  (`max_tracked_tenants`, default 100k); beyond it, new tenants fall into an "overflow"
  bucket that is treated as one (heavy) tenant.
* **Connection-level bypass**: an HTTP filter only sheds streams. A tenant opening raw
  connections without requests still costs memory; the same controller is designed to back
  an L4 (network) filter variant sharing the `TenantUsageMap` — noted as follow-up, and the
  proactive `global_downstream_max_connections` limit remains the L4 backstop.
* **Retry amplification**: shed responses are 503 with no retry-after by default; clients
  are expected to back off. Optionally emit `Retry-After` (config).
* **Fairness vs. priority**: pure water-fill treats all tenants equally. Weighted water-fill
  (per-tenant weight `w_i`, cap at `w_i · L`) is a straightforward extension once tenant
  metadata (e.g. from ambient workload identity rather than raw IP) is plumbed in.
