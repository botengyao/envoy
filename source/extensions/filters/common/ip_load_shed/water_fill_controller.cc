#include "source/extensions/filters/common/ip_load_shed/water_fill_controller.h"

#include <utility>
#include <vector>

#include "envoy/network/address.h"
#include "envoy/singleton/manager.h"

#include "source/common/memory/stats.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "absl/hash/hash.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace IpLoadShed {

namespace {

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

SINGLETON_MANAGER_REGISTRATION(water_fill_controller);

absl::Status WaterFillController::validateConfig(const WaterFillConfig& config) {
  if (config.overload_action_name().empty() && config.max_heap_size_bytes() == 0) {
    return absl::InvalidArgumentError(
        "ip_load_shed: one of overload_action_name or max_heap_size_bytes must be set");
  }
  // Compare effective values so a single explicit threshold crossing the other's default is
  // rejected too.
  const double shed_start =
      config.has_shed_start_threshold() ? config.shed_start_threshold().value() : 80.0;
  const double reject_all =
      config.has_reject_all_threshold() ? config.reject_all_threshold().value() : 90.0;
  if (shed_start >= reject_all) {
    return absl::InvalidArgumentError(
        "ip_load_shed: shed_start_threshold must be less than reject_all_threshold");
  }
  return absl::OkStatus();
}

std::shared_ptr<WaterFillController>
WaterFillController::getOrCreate(Server::Configuration::ServerFactoryContext& context,
                                 const WaterFillConfig& config) {
  // Pinned: the controller registers a process-lifetime overload-action callback, so it must
  // live for the server's lifetime rather than die with the last filter config.
  std::shared_ptr<WaterFillController> controller =
      context.singletonManager().getTyped<WaterFillController>(
          SINGLETON_MANAGER_REGISTERED_NAME(water_fill_controller),
          [&context, &config] { return std::make_shared<WaterFillController>(context, config); },
          /*pin=*/true);
  // Later filter instances do not reconfigure the controller; surface silent mismatches.
  if (!Protobuf::util::MessageDifferencer::Equals(config, controller->config_)) {
    ENVOY_LOG_MISC(warn,
                   "ip_load_shed: water_fill config differs from the controller's (first "
                   "instantiated filter wins); got: {}, using: {}",
                   config.ShortDebugString(), controller->config_.ShortDebugString());
  }
  return controller;
}

WaterFillController::WaterFillController(Server::Configuration::ServerFactoryContext& context,
                                         const WaterFillConfig& config)
    : config_(config), overload_action_name_(config.overload_action_name()),
      max_heap_size_bytes_(config.max_heap_size_bytes()),
      shed_start_(config.has_shed_start_threshold() ? config.shed_start_threshold().value() / 100.0
                                                    : 0.8),
      reject_all_(config.has_reject_all_threshold() ? config.reject_all_threshold().value() / 100.0
                                                    : 0.9),
      evaluation_interval_(
          PROTOBUF_GET_MS_OR_DEFAULT(config, evaluation_interval, DefaultEvaluationIntervalMs)),
      max_tenants_per_shard_(
          std::max<uint32_t>(1, (config.max_tracked_tenants() != 0 ? config.max_tracked_tenants()
                                                                   : DefaultMaxTrackedTenants) /
                                    NumShards)),
      use_remote_address_(config.tenant_key_source() ==
                          WaterFillConfig::REMOTE_ADDRESS),
      stats_(generateStats(context.serverScope())),
      tls_(ThreadLocal::TypedSlot<ThreadLocalSnapshot>::makeUnique(context.threadLocal())),
      timer_(context.mainThreadDispatcher().createTimer([this] { evaluate(); })) {
  tls_->set([](Event::Dispatcher&) { return std::make_shared<ThreadLocalSnapshot>(); });

  if (!overload_action_name_.empty()) {
    // Preferred pressure source: the overload manager posts the action state (the scaled
    // trigger's 0..1 value, i.e. the shed severity) to the main dispatcher. Registration must
    // happen before the overload manager starts, which holds for bootstrap-configured filters
    // (known limitation: filters first delivered via LDS after startup must use the
    // self-contained mode). The overload manager keeps the callback for the process lifetime,
    // so it guards `this` with a liveness sentinel; both callback and destructor run on the
    // main thread, making the check race-free.
    use_overload_action_ = context.overloadManager().registerForAction(
        overload_action_name_, context.mainThreadDispatcher(),
        [this, alive = std::weak_ptr<bool>(alive_)](Server::OverloadActionState state) {
          if (alive.lock() != nullptr) {
            overload_severity_ = state.value().value();
          }
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

std::string WaterFillController::tenantKey(const Network::ConnectionInfoProvider& info) const {
  const Network::Address::InstanceConstSharedPtr& address =
      use_remote_address_ ? info.remoteAddress() : info.directRemoteAddress();
  if (address == nullptr || address->type() != Network::Address::Type::Ip) {
    return "";
  }
  return address->ip()->addressAsString();
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
    // Conservation: a tenant admitted while the shard was at capacity had its early charges
    // folded into the overflow bucket, but later charges may have landed in an own entry
    // created after churn freed space. Its lump-sum release then over-draws the own entry;
    // route the residual back to the overflow bucket instead of discarding it, so phantom
    // usage cannot accumulate there.
    const int64_t residual = it->second;
    const bool was_overflow_entry = (it->first == OverflowTenantKey);
    shard.usage.erase(it);
    if (residual < 0 && !was_overflow_entry) {
      const auto overflow_it = shard.usage.find(OverflowTenantKey);
      if (overflow_it != shard.usage.end()) {
        overflow_it->second += residual;
        if (overflow_it->second <= 0) {
          shard.usage.erase(overflow_it);
        }
      }
    }
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
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
