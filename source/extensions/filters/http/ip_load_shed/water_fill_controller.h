#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include "envoy/event/timer.h"
#include "envoy/extensions/filters/http/ip_load_shed/v3/ip_load_shed.pb.h"
#include "envoy/http/codes.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/ip_load_shed/water_fill.h"

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {

/**
 * Immutable shedding decision computed on the main thread each evaluation interval and
 * published to all workers (RCU-style: workers hold a shared_ptr to the current snapshot and
 * never mutate it).
 */
struct ShedSnapshot {
  double severity{0.0};
  uint64_t water_level{NoWaterLevel};
  // Tenants whose aggregated usage is above the water level.
  absl::flat_hash_set<std::string> shed_ips;

  bool shouldShed(absl::string_view ip) const {
    if (severity >= 1.0) {
      return true;
    }
    if (severity <= 0.0) {
      return false;
    }
    return shed_ips.contains(ip);
  }
};
using ShedSnapshotConstSharedPtr = std::shared_ptr<const ShedSnapshot>;

/**
 * All ip_load_shed stats. @see stats_macros.h
 */
#define ALL_IP_LOAD_SHED_STATS(COUNTER, GAUGE)                                                     \
  COUNTER(shed_total)                                                                              \
  GAUGE(severity_permille, NeverImport)                                                            \
  GAUGE(water_level_bytes, NeverImport)                                                            \
  GAUGE(tenants_tracked, NeverImport)                                                              \
  GAUGE(tenants_shed, NeverImport)                                                                 \
  GAUGE(total_usage_bytes, NeverImport)

struct IpLoadShedStats {
  ALL_IP_LOAD_SHED_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT)
};

/**
 * Server-wide singleton shared by all ip_load_shed filter instances.
 *
 * Threading model:
 *  - Workers account per-tenant usage into 64 striped shards (short critical sections on a
 *    sharded absl::Mutex; at ~10k tenants contention is negligible).
 *  - A main-thread timer periodically aggregates the shards, derives the shed severity from
 *    the overload manager action state (or directly from heap usage in self-contained mode),
 *    solves the water-fill level, and publishes an immutable ShedSnapshot to every worker
 *    through a ThreadLocal slot.
 *  - The per-request hot path is one TLS read plus one hash-set lookup; no locks are held
 *    across filter callbacks.
 */
class WaterFillController : public Singleton::Instance,
                            public Logger::Loggable<Logger::Id::filter> {
public:
  WaterFillController(
      Server::Configuration::ServerFactoryContext& context,
      const envoy::extensions::filters::http::ip_load_shed::v3::IpLoadShed& config);
  ~WaterFillController() override;

  // Worker-thread API ---------------------------------------------------------------------

  // The current shedding decision for the calling thread. May be nullptr on threads without
  // TLS (treated as "do not shed").
  ShedSnapshotConstSharedPtr snapshot();

  // Adjusts a tenant's aggregated usage by delta bytes (positive on stream admission and
  // buffered data, negative when a stream is destroyed).
  void addUsage(absl::string_view ip, int64_t delta);

  IpLoadShedStats& stats() { return stats_; }
  uint64_t streamCostBytes() const { return stream_cost_bytes_; }
  Http::Code rejectionStatusCode() const { return rejection_status_code_; }

private:
  struct ThreadLocalSnapshot : public ThreadLocal::ThreadLocalObject {
    ShedSnapshotConstSharedPtr snapshot_{std::make_shared<const ShedSnapshot>()};
  };

  static constexpr size_t NumShards = 64;
  struct Shard {
    absl::Mutex mutex;
    absl::flat_hash_map<std::string, int64_t> usage ABSL_GUARDED_BY(mutex);
  };

  // Main-thread timer callback: aggregate usage, solve the water level, publish the snapshot.
  void evaluate();
  // Current shed severity in [0, 1]. Main thread only.
  double shedSeverity() const;

  const std::string overload_action_name_;
  const uint64_t max_heap_size_bytes_;
  const double shed_start_;
  const double reject_all_;
  const std::chrono::milliseconds evaluation_interval_;
  const uint64_t stream_cost_bytes_;
  const Http::Code rejection_status_code_;
  const uint32_t max_tenants_per_shard_;

  IpLoadShedStats stats_;
  std::array<Shard, NumShards> shards_;
  ThreadLocal::TypedSlotPtr<ThreadLocalSnapshot> tls_;
  Event::TimerPtr timer_;

  // Latest severity delivered by the overload manager action callback (main thread only).
  bool use_overload_action_{false};
  double overload_severity_{0.0};
};

using WaterFillControllerSharedPtr = std::shared_ptr<WaterFillController>;

} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
