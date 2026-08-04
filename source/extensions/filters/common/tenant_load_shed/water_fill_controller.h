#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/event/timer.h"
#include "envoy/extensions/filters/common/tenant_load_shed/v3/water_fill.pb.h"
#include "envoy/network/socket.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/common/tenant_load_shed/water_fill.h"

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace TenantLoadShed {

/**
 * Immutable shedding decision computed on the main thread each evaluation interval and
 * published to all workers (RCU-style: workers hold a shared_ptr to the current snapshot and
 * never mutate it).
 */
struct ShedSnapshot {
  double severity{0.0};
  uint64_t water_level{NoWaterLevel};
  // Tenants whose aggregated usage is above the water level.
  absl::flat_hash_set<std::string> shed_tenants;

  bool shouldShed(absl::string_view tenant) const {
    if (severity >= 1.0) {
      return true;
    }
    if (severity <= 0.0) {
      return false;
    }
    return shed_tenants.contains(tenant);
  }
};
using ShedSnapshotConstSharedPtr = std::shared_ptr<const ShedSnapshot>;

/**
 * All tenant_load_shed stats, shared by the HTTP and network filters. @see stats_macros.h
 */
#define ALL_TENANT_LOAD_SHED_STATS(COUNTER, GAUGE)                                                 \
  COUNTER(shed_total)                                                                              \
  GAUGE(severity_permille, NeverImport)                                                            \
  GAUGE(water_level_bytes, NeverImport)                                                            \
  GAUGE(tenants_tracked, NeverImport)                                                              \
  GAUGE(tenants_shed, NeverImport)                                                                 \
  GAUGE(total_usage_bytes, NeverImport)

struct TenantLoadShedStats {
  ALL_TENANT_LOAD_SHED_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT)
};

/**
 * Server-wide singleton shared by all tenant_load_shed filter instances (HTTP and network).
 *
 * Threading model — the accounting hot path is lock-free (same choreography as the stats
 * store's histogram merge):
 *  - Each worker owns a thread-local delta ledger; addUsage() is a plain map update on the
 *    calling thread. No locks, no atomics.
 *  - A main-thread timer every evaluation_interval runs a harvest: a closure posted to every
 *    worker moves that worker's delta ledger into a shared accumulator (one short mutex
 *    acquisition per worker per tick, never on the data path), and the completion callback —
 *    guaranteed to run on the main thread after all workers finished — folds the deltas into
 *    the main-thread-owned usage map, derives severity, solves the water level, and
 *    publishes an immutable ShedSnapshot back to every worker through the same ThreadLocal
 *    slot.
 *  - The per-request hot path is one TLS read plus one hash lookup (shed check) and one
 *    thread-local map update (accounting).
 */
class WaterFillController : public Singleton::Instance,
                            public Logger::Loggable<Logger::Id::filter> {
public:
  using WaterFillConfig = envoy::extensions::filters::common::tenant_load_shed::v3::WaterFillConfig;

  WaterFillController(Server::Configuration::ServerFactoryContext& context,
                      const WaterFillConfig& config);
  ~WaterFillController() override;

  // Returns an error when the config has no usable pressure source or inverted thresholds.
  static absl::Status validateConfig(const WaterFillConfig& config);

  // Returns the process-wide controller, creating it from this config on first use. Filter
  // config factories call this on the main thread during listener configuration.
  static std::shared_ptr<WaterFillController>
  getOrCreate(Server::Configuration::ServerFactoryContext& context, const WaterFillConfig& config);

  // Worker-thread API ---------------------------------------------------------------------

  // The current shedding decision for the calling thread. May be nullptr on threads without
  // TLS (treated as "do not shed").
  ShedSnapshotConstSharedPtr snapshot();

  // Adjusts a tenant's usage by delta bytes (positive on admission and observed data,
  // negative when the stream or connection is destroyed). Lock-free: writes only the calling
  // thread's delta ledger; the change becomes globally visible at the next harvest tick.
  void addUsage(absl::string_view tenant, int64_t delta);

  // The tenant key for a downstream connection per the configured TenantKeySource; empty
  // when the address is not an IP (e.g. unix domain sockets).
  std::string tenantKey(const Network::ConnectionInfoProvider& info) const;

  TenantLoadShedStats& stats() { return stats_; }

private:
  // Per-thread state: the worker's published shed snapshot (read path) and its delta ledger
  // (write path). Both are only ever touched from the owning thread; the harvest closure
  // runs on that thread too and moves the ledger out.
  struct ThreadLocalLedger : public ThreadLocal::ThreadLocalObject {
    ShedSnapshotConstSharedPtr snapshot_{std::make_shared<const ShedSnapshot>()};
    absl::flat_hash_map<std::string, int64_t> deltas_;
  };

  // Per-tick accumulator shared by the harvest closures; the mutex is taken once per worker
  // per evaluation interval, never on the request path.
  struct Harvest {
    absl::Mutex mutex;
    std::vector<absl::flat_hash_map<std::string, int64_t>> maps ABSL_GUARDED_BY(mutex);
  };

  // Main-thread timer callback: kicks the harvest fan-out.
  void evaluate();
  // Main-thread completion: folds harvested deltas, solves the water level, publishes the
  // snapshot, re-arms the timer.
  void finishEvaluate(const std::shared_ptr<Harvest>& harvest);
  // Applies one tenant delta to the main-thread usage map, enforcing the tenant cap.
  void foldDelta(const std::string& tenant, int64_t delta);
  // Current shed severity in [0, 1]. Main thread only.
  double shedSeverity() const;

  const WaterFillConfig config_;
  const std::string overload_action_name_;
  const uint64_t max_heap_size_bytes_;
  const double shed_start_;
  const double reject_all_;
  const std::chrono::milliseconds evaluation_interval_;
  const uint32_t max_tracked_tenants_;
  const bool use_remote_address_;

  TenantLoadShedStats stats_;
  // Aggregated per-tenant usage. Main thread only; updated exclusively in finishEvaluate().
  absl::flat_hash_map<std::string, int64_t> usage_;
  ThreadLocal::TypedSlotPtr<ThreadLocalLedger> tls_;
  Event::TimerPtr timer_;

  // Latest severity delivered by the overload manager action callback (main thread only).
  bool use_overload_action_{false};
  double overload_severity_{0.0};
  // Liveness sentinel for closures that outlive ordinary ownership (the overload-action
  // callback held by the overload manager, and harvest completions in flight at shutdown).
  // All guarded paths run on the main thread, as does the destructor, so a weak_ptr lock is
  // a race-free liveness check.
  const std::shared_ptr<bool> alive_{std::make_shared<bool>(true)};
};

using WaterFillControllerSharedPtr = std::shared_ptr<WaterFillController>;

} // namespace TenantLoadShed
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
