# tenant_load_shed experiments

Reproducible experiments for the water-fill load-shedding filters (L7 + L4) and the
accounting design (`source/extensions/filters/common/tenant_load_shed/ACCOUNTING.md`).
Results: `RESULTS.md`.

## Setup

```
bazel build //source/exe:envoy-static
```

Tenants are simulated from one host with PROXY protocol v1 headers (the configs set
`tenant_key_source: REMOTE_ADDRESS`); shed severity is driven deterministically by writing
`[0,1]` to `/tmp/tenant_load_shed_exp/pressure` (the `injected_resource` overload monitor), so no
real memory pressure is needed and runs are repeatable.

## E1 / E2 — shedding behavior (L7 / L4)

```
python3 run_experiment.py --mode l7 --envoy ../../bazel-bin/source/exe/envoy-static
python3 run_experiment.py --mode l4 --envoy ../../bazel-bin/source/exe/envoy-static
```

8 heavy tenants (concurrent 256 KiB POSTs into a slow-draining upstream / long-lived
fast-writing TCP connections into a slow sink) and 32 light tenants (small periodic GETs /
1 KiB/s connections + 1/s connection probes). Pressure sweeps
0.70 → 0.82 → 0.85 → 0.88 → 0.92 → 0.70, 15s per step; per-step per-class outcome counts and
`tenant_load_shed.*` admin stats land in `results_<mode>.json`.

Expected: light tenants unaffected through the ramp (their usage is below every water level);
heavy tenants shed progressively as severity rises; everything sheds at ≥0.90 (severity 1);
full recovery after pressure drops.

## E3 — accounting microbenchmarks

```
clang++ -O2 -std=c++17 bench_accounting.cc \
    ../../source/extensions/filters/common/tenant_load_shed/water_fill.cc -I../../ \
    -o bench_accounting && ./bench_accounting
```
