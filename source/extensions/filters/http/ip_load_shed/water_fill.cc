#include "source/extensions/filters/http/ip_load_shed/water_fill.h"

#include <algorithm>
#include <functional>
#include <numeric>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {

uint64_t computeWaterLevel(std::vector<uint64_t>& usages, double severity) {
  if (severity <= 0.0 || usages.empty()) {
    return NoWaterLevel;
  }
  if (severity >= 1.0) {
    return 0;
  }

  std::sort(usages.begin(), usages.end(), std::greater<>());
  const uint64_t total = std::accumulate(usages.begin(), usages.end(), uint64_t{0});
  if (total == 0) {
    return NoWaterLevel;
  }
  const double target = (1.0 - severity) * static_cast<double>(total);

  // Capping the top k tenants at level L yields a total of k * L + suffix_sum(k), where
  // suffix_sum(k) is the usage of the n - k tenants below the cap. Solve for the L that hits
  // the target and accept the first k for which L lies between the k-th and (k+1)-th largest
  // usage, i.e. capping exactly the top k tenants is self-consistent.
  double suffix = static_cast<double>(total);
  for (size_t k = 1; k <= usages.size(); ++k) {
    suffix -= static_cast<double>(usages[k - 1]);
    const double level = (target - suffix) / static_cast<double>(k);
    const double lower = (k < usages.size()) ? static_cast<double>(usages[k]) : 0.0;
    if (level >= lower && level <= static_cast<double>(usages[k - 1])) {
      return level <= 0.0 ? 0 : static_cast<uint64_t>(level);
    }
  }
  return 0;
}

} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
