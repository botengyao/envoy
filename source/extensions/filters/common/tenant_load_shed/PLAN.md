# Water-fill tenant load shedding — design & plan

One page tying the whole effort together. Deep dives:
[DESIGN.md](../../http/tenant_load_shed/DESIGN.md) (algorithm + threading),
[ACCOUNTING.md](ACCOUNTING.md) (buffer/CPU resource counting — the hard part),
[experiments](../../../../../experiments/tenant_load_shed/README.md) /
[RESULTS.md](../../../../../experiments/tenant_load_shed/RESULTS.md) (measured data).

## Problem

An ambient node Envoy fronts ~10k micro-VM tenants (tenant = source IP) on one shared heap
and one set of worker threads. Overload actions today are tenant-blind: a handful of abusive
tenants push heap past the limit and *everyone* gets shed (or the process is OOM-killed).

Goal: **< 80% heap — no interference; 80–90% — shed the heaviest tenants only, water-fill
fair; ≥ 90% — reject all (existing backstop).**

## Design in five sentences

1. **Water-fill fairness**: given per-tenant usage `u_i` and severity `s ∈ [0,1]`, solve the
   level `L` with `Σ min(u_i, L) ≤ (1−s)·Σu_i`; tenants above `L` are shed, tenants at or
   below are mathematically untouched for any `s < 1` (O(n log n), 61µs at 10k tenants).
2. **Severity comes from the overload manager**: a new well-known action
   `envoy.overload_actions.shed_tenant_load` driven by scaled triggers (`fixed_heap`
   0.80→0.90; `cpu_utilization` addable, max-wins), consumed via `registerForAction`; a
   self-contained `Memory::Stats` fallback needs no overload config.
3. **Resource counting is layered** (ACCOUNTING.md): Tier-1 filter-observed bytes
   (implemented) → Tier-2 real buffered bytes via a per-tenant ledger in the per-worker
   `WatermarkBufferFactory` plus a `BufferMemoryAccount::balance()` accessor → CPU via
   thread-CPU deltas at ScopeTracker stack transitions, composed with memory by
   dominant-resource fairness.
4. **Threading**: workers write per-tenant deltas into thread-local ledgers (lock-free); a
   main-thread 100ms timer aggregates, solves `L`, and publishes an immutable `ShedSnapshot`
   to every worker via a ThreadLocal slot (RCU); the per-request hot path is one TLS read +
   one hash lookup.
5. **Enforcement is split L7/L4 over one shared controller**: the HTTP filter sheds new
   *streams* (503 + `x-envoy-tenant-load-shed`, per-stream fairness on multiplexed connections);
   the network filter sheds new *connections* at accept and catches request-less
   connection-holders — one water level binds both, so multiplexing cannot dodge the gate.

## Implemented on this branch

| piece | where |
| --- | --- |
| solver + shared controller (singleton, pinned; TLS publish; overload/self-contained severity) | `source/extensions/filters/common/tenant_load_shed/` |
| shared config proto (`WaterFillConfig`, `tenant_key_source`) | `api/envoy/extensions/filters/common/tenant_load_shed/v3/` |
| L7 filter `envoy.filters.http.tenant_load_shed` | `source/extensions/filters/http/tenant_load_shed/` |
| L4 filter `envoy.filters.network.tenant_load_shed` | `source/extensions/filters/network/tenant_load_shed/` |
| core: `shed_tenant_load` well-known overload action | `envoy/server/overload/overload_manager.h` |
| tests: solver properties, both factories, HTTP data path | `test/extensions/filters/{common,http,network}/tenant_load_shed/` |
| experiment harness + measured data | `experiments/tenant_load_shed/` |

## Measured results (details in RESULTS.md)

* **E1 (L7)**: through the whole 80–90% ramp, 32 light tenants saw **zero** 503s while 8
  heavy tenants shed at 86–92%; reject-all at ≥90%; clean recovery.
* **E2 (L4)**: heavy tenants' new connections rejected 100% across the ramp, light tenants
  **0%**; existing connections untouched; reject-all and recovery clean.
* **E3 (overhead)**: solve 61µs @10k tenants per 100ms tick; accounting 21–35ns/op under
  8-thread contention; thread-CPU clock 105ns/read (macOS) — every hot-path budget holds.

## Plan forward (phased)

1. **Accounting fidelity** — Tier-2 buffered-bytes ledger (`balance()` accessor + tenant
   ledger charged from existing account call sites; H2 complete, then H1/H3), EWMA decay so
   lifetime bytes stop standing in for current footprint (the one distortion E2 makes
   visible), L4 connection-buffer sampling.
2. **CPU dimension** — `Thread::currentThreadCpuTime()` + ScopeTracker transition hook
   (bootstrap-gated core change), per-tenant CPU EWMA, DRF composition, `cpu_utilization`
   as a second trigger on the same action.
3. **Productionization** — weighted water-fill (per-tenant-class weights), LDS-safe
   overload registration, docs + changelog + integration tests for upstreaming.
