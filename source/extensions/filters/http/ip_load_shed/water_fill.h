#pragma once

#include <cstdint>
#include <limits>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {

// Water level meaning "nothing is shed".
constexpr uint64_t NoWaterLevel = std::numeric_limits<uint64_t>::max();

/**
 * Computes the water-fill level ``L`` for max-min fair load shedding: the largest ``L`` such
 * that ``sum(min(u_i, L)) <= (1 - severity) * sum(u_i)``. Tenants with usage at or below ``L``
 * are never shed; tenants above ``L`` are shed until their usage drains to ``L``. The shedding
 * burden therefore falls exclusively on the heaviest tenants, in usage order.
 *
 * @param usages per-tenant usage values. Reordered (sorted descending) in place.
 * @param severity fraction of total usage to shed, in [0, 1].
 * @return the water level: NoWaterLevel when severity <= 0 or there is nothing to shed, 0 when
 *         severity >= 1.
 */
uint64_t computeWaterLevel(std::vector<uint64_t>& usages, double severity);

} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
