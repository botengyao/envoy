# Experiment results

Platform: Apple Silicon macOS (Darwin 25.5), envoy built from `water_fill_management`,
`--concurrency 4`. Tenants: 8 heavy + 32 light source IPs via PROXY protocol; severity from
the `injected_resource` monitor through `envoy.overload_actions.shed_tenant_load`
(scaled 0.80 → 0.90); water-fill evaluation every 100ms.

## E3 — accounting microbenchmarks (`bench_accounting.cc`)

Measured (2M+ iterations each):

| benchmark | result | budget implication |
| --- | --- | --- |
| water-fill solve, 1k tenants | 4.9 µs/solve | negligible |
| water-fill solve, 10k tenants | 61.3 µs/solve | 0.06% of one core at 100ms cadence |
| water-fill solve, 100k tenants | 1.22 ms/solve | still fine at 100ms; use 250ms+ cadence beyond 100k |
| striped-map addUsage, 1 thread | 21.2 ns/op | ~3 ops per stream (admit, bytes, release) |
| striped-map addUsage, 4 threads | 28.4 ns/op | contention barely visible |
| striped-map addUsage, 8 threads | 35.0 ns/op | 64 shards absorb 8 workers |
| `steady_clock::now` | 12.4 ns/read | wall-clock fallback cost |
| `CLOCK_MONOTONIC` | 16.8 ns/read | |
| `CLOCK_THREAD_CPUTIME_ID` (macOS) | 104.9 ns/read | 2 reads/callback ≈ 210ns — sampling unneeded |
| mach `thread_info` (macOS) | 532.3 ns/read | rejected; use clock_gettime on macOS too |

Conclusions: even the earlier striped-shard accounting plane (since replaced by lock-free
thread-local delta ledgers — a plain map update on the hot path) cost tens of nanoseconds per
operation even under all-worker contention — the design's "negligible at 10k tenants" claim
holds with a 3× margin. The main-thread solve is microseconds at the 10k-tenant design point.
CPU attribution at two thread-CPU clock reads per dispatcher callback costs ~0.2µs/callback on
macOS (similar order on Linux — `CLOCK_THREAD_CPUTIME_ID` is not vDSO-serviced, it is a real
syscall on both platforms), i.e. well under 1% of a callback that does any real work.

## E1 — L7 water-fill shedding (`results_l7.json`)

8 heavy tenants (6 concurrent 256 KiB POSTs each into a 64 KiB/s-draining upstream, ~1.9 MB
sustained usage per tenant) vs 32 light tenants (2 GETs/s each, transient usage). Per 15s
step, request outcomes by class:

| pressure | severity | water level | heavy shed rate | light shed rate | tenants shed |
| --- | --- | --- | --- | --- | --- |
| 0.70 | 0 | — | 0 | **0** | 0 |
| 0.82 | 0.20 | 1.57 MB | 0.90 | **0** | 8 (all heavy) |
| 0.85 | 0.50 | 983 KB | 0.92 | **0** | 8 |
| 0.88 | 0.80 | 393 KB | 0.86 | **0** | 8 |
| 0.92 | 1.00 | 0 | 1.00 | 1.00 | reject-all |
| 0.70 (recovery) | 0 | — | 0 | 0 | 0 |

Every water-fill property holds end to end: light tenants saw **zero** 503s through the entire
80–90% ramp while heavy tenants shed at 86–92%; at saturation everything sheds (the
`stop_accepting_requests`-equivalent backstop); recovery is immediate and clean when pressure
drops. Heavy tenants are not starved below saturation (~192 requests/step still complete):
shed tenants drain, dip below the water level, and are re-admitted — the duty-cycle predicted
in the design (an EWMA on usage would smooth it; see ACCOUNTING.md follow-ups).

## E2 — L4 water-fill shedding (`results_l4.json`)

Same tenant split; heavy = 6 long-lived connections each writing 64 KiB/s into an 8 KiB/s
sink (buffers fill, watermarks throttle), light = one 1 KiB/s connection. Measured signal:
1/s **new-connection probes** per tenant (shed = closed at accept).

| pressure | severity | water level | heavy probe shed rate | light probe shed rate |
| --- | --- | --- | --- | --- |
| 0.70 | 0 | — | 0 | **0** |
| 0.82 | 0.20 | 6.5 MB | 1.00 | **0** |
| 0.85 | 0.50 | 5.8 MB | 1.00 | **0** |
| 0.88 | 0.80 | 1.96 MB | 1.00 | **0** |
| 0.92 | 1.00 | 0 | 1.00 | 1.00 |
| 0.70 (recovery) | 0 | — | 0 | 0 |

The L4 gate is binary rather than duty-cycled: existing heavy connections are never closed, so
their accounted usage never drains and heavy tenants stay above the water line for the whole
ramp — new heavy connections are rejected 100% while all 32 light tenants connect freely.
Two documented Tier-1 limitations are directly visible in the data: total usage grows
monotonically across steps (67 MB → 148 MB; cumulative bytes-seen never decays while
connections stay open), and at recovery heavy tenants are admitted again purely because
severity is 0, not because their booked usage dropped. Both are what the Tier-2
buffered-bytes ledger / EWMA decay in ACCOUNTING.md §2.2 fix.
