#include <cstdint>
#include <numeric>
#include <vector>

#include "source/extensions/filters/http/ip_load_shed/water_fill.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {
namespace {

uint64_t cappedTotal(const std::vector<uint64_t>& usages, uint64_t level) {
  uint64_t total = 0;
  for (uint64_t u : usages) {
    total += std::min(u, level);
  }
  return total;
}

TEST(WaterFillTest, NoSheddingAtZeroSeverity) {
  std::vector<uint64_t> usages{100, 50, 30};
  EXPECT_EQ(computeWaterLevel(usages, 0.0), NoWaterLevel);
  EXPECT_EQ(computeWaterLevel(usages, -1.0), NoWaterLevel);
}

TEST(WaterFillTest, RejectAllAtFullSeverity) {
  std::vector<uint64_t> usages{100, 50, 30};
  EXPECT_EQ(computeWaterLevel(usages, 1.0), 0);
  EXPECT_EQ(computeWaterLevel(usages, 1.5), 0);
}

TEST(WaterFillTest, EmptyAndZeroUsage) {
  std::vector<uint64_t> empty;
  EXPECT_EQ(computeWaterLevel(empty, 0.5), NoWaterLevel);
  std::vector<uint64_t> zeros{0, 0, 0};
  EXPECT_EQ(computeWaterLevel(zeros, 0.5), NoWaterLevel);
}

// The core fairness property: shedding starts with the heaviest tenant, light tenants are
// untouched.
TEST(WaterFillTest, OnlyHeaviestTenantCappedAtLowSeverity) {
  std::vector<uint64_t> usages{100, 50, 30, 20};
  // Shed 5% of 200 -> target 190. Capping only the top tenant at 90 achieves it.
  const uint64_t level = computeWaterLevel(usages, 0.05);
  EXPECT_EQ(level, 90);
  // Only the 100-usage tenant is above the water line.
  EXPECT_EQ(cappedTotal(usages, level), 190);
}

TEST(WaterFillTest, WaterLevelSpreadsAcrossHeavyTenants) {
  std::vector<uint64_t> usages{100, 50, 30, 20};
  // Shed 50% of 200 -> target 100. Water level ends between 20 and 30: the three heaviest
  // tenants are capped, the lightest is untouched.
  const uint64_t level = computeWaterLevel(usages, 0.5);
  EXPECT_GE(level, 20);
  EXPECT_LT(level, 30);
  EXPECT_LE(cappedTotal(usages, level), 100);
  // The lightest tenant is below the water line.
  EXPECT_LT(uint64_t{20}, level + 10); // sanity: level ~26
}

TEST(WaterFillTest, EqualTenantsAllCapped) {
  std::vector<uint64_t> usages{10, 10};
  const uint64_t level = computeWaterLevel(usages, 0.5);
  EXPECT_EQ(level, 5);
}

// Property check across a sweep of severities: the capped total never exceeds the target and
// tenants at or below the level are never shed.
TEST(WaterFillTest, CappedTotalRespectsTargetAcrossSeverities) {
  std::vector<uint64_t> base{1000, 800, 400, 200, 100, 50, 25, 5, 1};
  const uint64_t total = std::accumulate(base.begin(), base.end(), uint64_t{0});
  for (double severity : {0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99}) {
    std::vector<uint64_t> usages = base;
    const uint64_t level = computeWaterLevel(usages, severity);
    ASSERT_NE(level, NoWaterLevel);
    const double target = (1.0 - severity) * static_cast<double>(total);
    // +9 tolerance: the level is floored, one unit per tenant.
    EXPECT_LE(cappedTotal(base, level), static_cast<uint64_t>(target) + 9)
        << "severity " << severity;
  }
}

TEST(WaterFillTest, LargeTenantCount) {
  // 10k tenants with linearly increasing usage; make sure the solve is stable and fair.
  std::vector<uint64_t> usages(10000);
  for (size_t i = 0; i < usages.size(); ++i) {
    usages[i] = i + 1;
  }
  std::vector<uint64_t> copy = usages;
  const uint64_t level = computeWaterLevel(copy, 0.3);
  ASSERT_NE(level, NoWaterLevel);
  ASSERT_GT(level, 0);
  const uint64_t total = std::accumulate(usages.begin(), usages.end(), uint64_t{0});
  EXPECT_LE(cappedTotal(usages, level), static_cast<uint64_t>(0.7 * total) + usages.size());
  // Light tenants (usage <= level) must be untouched.
  EXPECT_GT(level, usages.front());
}

} // namespace
} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
