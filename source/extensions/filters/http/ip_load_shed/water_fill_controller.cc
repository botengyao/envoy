#include "source/extensions/filters/http/ip_load_shed/water_fill_controller.h"

#include <utility>
#include <vector>

#include "source/common/memory/stats.h"
#include "source/common/protobuf/utility.h"

#include "absl/hash/hash.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {

namespace {

constexpr uint64_t DefaultStreamCostBytes = 64 * 1024;
constexpr uint32_t DefaultMaxTrackedTenants = 100000;
constexpr uint64_t DefaultEvaluationIntervalMs = 100;
// Per-shard aggregation bucket for tenants beyond max_tracked_tenants. It counts toward total
// usage (and thus lowers the water level for everyone else) but is not individually sheddable
// below the reject-all threshold, keeping the tracker's own memory bounded.
constexpr absl::string_view OverflowTenantKey = "overflow";

IpLoadShedStats generateStats(Stats::Scope& scope) {
  return IpLoadShedStats{ALL_IP_LOAD_SHED_STATS(POOL_COUNTER_PREFIX(scope, "ip_load_shed."),
                                                POOL_GAUGE_PREFIX(scope, "ip_load_shed."))};
}

} // namespace

WaterFillController::WaterFillController(
    Server::Configuration::ServerFactoryContext& context,
    const envoy::extensions::filters::http::ip_load_shed::v3::IpLoadShed& config)
    : overload_action_name_(config.overload_action_name()),
      max_heap_size_bytes_(config.max_heap_size_bytes()),
      shed_start_(config.has_shed_start_threshold()
                      ? config.shed_start_threshold().value() / 100.0
                      : 0.8),
      reject_all_(config.has_reject_all_threshold()
                      ? config.reject_all_threshold().value() / 100.0
                      : 0.9),
      evaluation_interval_(
          PROTOBUF_GET_MS_OR_DEFAULT(config, evaluation_interval, DefaultEvaluationIntervalMs)),
      stream_cost_bytes_(config.stream_cost_bytes() != 0 ? config.stream_cost_bytes()
                                                         : DefaultStreamCostBytes),
      rejection_status_code_(config.rejection_status_code() != 0
                                 ? static_cast<Http::Code>(config.rejection_status_code())
                                 : Http::Code::ServiceUnavailable),
      max_tenants_per_shard_(
          std::max<uint32_t>(1, (config.max_tracked_tenants() != 0 ? config.max_tracked_tenants()
                                                                   : DefaultMaxTrackedTenants) /
                                    NumShards)),
      stats_(generateStats(context.serverScope())),
      tls_(ThreadLocal::TypedSlot<ThreadLocalSnapshot>::makeUnique(context.threadLocal())),
      timer_(context.mainThreadDispatcher().createTimer([this] { evaluate(); })) {
  tls_->set([](Event::Dispatcher&) { return std::make_shared<ThreadLocalSnapshot>(); });

  if (!overload_action_name_.empty()) {
    // Preferred pressure source: the overload manager posts the action state (the scaled
    // trigger's 0..1 value, i.e. the shed severity) to the main dispatcher. Registration must
    // happen before the overload manager starts, which holds for bootstrap-configured filters.
    use_overload_action_ = context.overloadManager().registerForAction(
        overload_action_name_, context.mainThreadDispatcher(),
        [this](Server::OverloadActionState state) {
          overload_severity_ = state.value().value();
        });
    if (!use_overload_action_) {
      ENVOY_LOG(warn,
                "ip_load_shed: overload action {} is not configured in the overload manager; "
                "falling back to self-contained heap pressure ({} bytes max heap)",
                overload_action_name_, max_heap_size_bytes_);
    }
  }
  if (!use_overload_action_ && max_heap_size_bytes_ == 0) {
    ENVOY_LOG(warn, "ip_load_shed: no usable pressure source configured; the filter will track "
                    "usage but never shed");
  }

  timer_->enableTimer(evaluation_interval_);
}

WaterFillController::~WaterFillController() {
  if (timer_ != nullptr) {
    timer_->disableTimer();
  }
}

ShedSnapshotConstSharedPtr WaterFillController::snapshot() {
  const OptRef<ThreadLocalSnapshot> tls = tls_->get();
  if (!tls.has_value()) {
    return nullptr;
  }
  return tls->snapshot_;
}

void WaterFillController::addUsage(absl::string_view ip, int64_t delta) {
  Shard& shard = shards_[absl::HashOf(ip) % NumShards];
  absl::MutexLock lock(&shard.mutex);
  auto it = shard.usage.find(ip);
  if (it == shard.usage.end()) {
    if (delta <= 0) {
      // A release for a tenant folded into the overflow bucket (or already erased).
      it = shard.usage.find(OverflowTenantKey);
      if (it == shard.usage.end()) {
        return;
      }
    } else if (shard.usage.size() >= max_tenants_per_shard_) {
      it = shard.usage.try_emplace(std::string(OverflowTenantKey), 0).first;
    } else {
      it = shard.usage.try_emplace(std::string(ip), 0).first;
    }
  }
  it->second += delta;
  if (it->second <= 0) {
    shard.usage.erase(it);
  }
}

double WaterFillController::shedSeverity() const {
  if (use_overload_action_) {
    return overload_severity_;
  }
  if (max_heap_size_bytes_ == 0) {
    return 0.0;
  }
  const double pressure = static_cast<double>(Memory::Stats::totalCurrentlyAllocated()) /
                          static_cast<double>(max_heap_size_bytes_);
  if (pressure <= shed_start_) {
    return 0.0;
  }
  if (pressure >= reject_all_) {
    return 1.0;
  }
  return (pressure - shed_start_) / (reject_all_ - shed_start_);
}

void WaterFillController::evaluate() {
  const double severity = shedSeverity();

  std::vector<std::pair<std::string, uint64_t>> tenants;
  uint64_t total = 0;
  for (Shard& shard : shards_) {
    absl::MutexLock lock(&shard.mutex);
    tenants.reserve(tenants.size() + shard.usage.size());
    for (const auto& [ip, usage] : shard.usage) {
      if (usage > 0) {
        tenants.emplace_back(ip, static_cast<uint64_t>(usage));
        total += static_cast<uint64_t>(usage);
      }
    }
  }

  auto snapshot = std::make_shared<ShedSnapshot>();
  snapshot->severity = severity;
  if (severity >= 1.0) {
    snapshot->water_level = 0;
  } else if (severity > 0.0 && !tenants.empty()) {
    std::vector<uint64_t> usages;
    usages.reserve(tenants.size());
    for (const auto& [ip, usage] : tenants) {
      usages.push_back(usage);
    }
    snapshot->water_level = computeWaterLevel(usages, severity);
    for (const auto& [ip, usage] : tenants) {
      if (usage > snapshot->water_level && ip != OverflowTenantKey) {
        snapshot->shed_ips.insert(ip);
      }
    }
  }

  stats_.severity_permille_.set(static_cast<uint64_t>(severity * 1000.0));
  stats_.water_level_bytes_.set(snapshot->water_level == NoWaterLevel ? 0
                                                                      : snapshot->water_level);
  stats_.tenants_tracked_.set(tenants.size());
  stats_.tenants_shed_.set(snapshot->shed_ips.size());
  stats_.total_usage_bytes_.set(total);

  // Publish RCU-style: workers atomically pick up the new immutable snapshot; in-flight reads
  // keep the old one alive through their shared_ptr. Per the TypedSlot contract the callback
  // captures only the snapshot, never this.
  const ShedSnapshotConstSharedPtr to_publish = std::move(snapshot);
  tls_->runOnAllThreads([to_publish](OptRef<ThreadLocalSnapshot> tls) {
    if (tls.has_value()) {
      tls->snapshot_ = to_publish;
    }
  });

  timer_->enableTimer(evaluation_interval_);
}

} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
