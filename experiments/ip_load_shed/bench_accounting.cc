// E3: accounting microbenchmarks (standalone; no Envoy deps).
//   clang++ -O2 -std=c++17 bench_accounting.cc \
//       ../../source/extensions/filters/common/ip_load_shed/water_fill.cc \
//       -I../../ -o bench_accounting && ./bench_accounting
//
// Measures:
//   1. computeWaterLevel() solve latency at 1k / 10k / 100k tenants (the main-thread cost of
//      each 100ms evaluation tick).
//   2. Striped-mutex tenant-map add/remove throughput, 1 and 8 threads (the Tier-1 hot-path
//      accounting cost; std::mutex/std::unordered_map stand in for absl -- slightly
//      pessimistic vs absl::Mutex/flat_hash_map).
//   3. Clock read costs for the CPU-attribution budget (steady_clock,
//      CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC; plus mach thread_info on macOS).

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "source/extensions/filters/common/ip_load_shed/water_fill.h"

#ifdef __APPLE__
#include <mach/mach.h>
#endif

using Clock = std::chrono::steady_clock;
using Envoy::Extensions::Filters::Common::IpLoadShed::computeWaterLevel;

static double ns_per_op(Clock::time_point start, Clock::time_point end, uint64_t ops) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count() /
         static_cast<double>(ops);
}

static void benchSolve() {
  std::printf("-- water-fill solve (per evaluation tick, main thread)\n");
  std::mt19937_64 rng(42);
  for (size_t n : {1000, 10000, 100000}) {
    std::vector<uint64_t> base(n);
    for (auto& u : base) {
      u = 1 + rng() % (1 << 20); // up to 1 MiB usage per tenant
    }
    constexpr int iters = 200;
    uint64_t sink = 0;
    const auto start = Clock::now();
    for (int i = 0; i < iters; ++i) {
      std::vector<uint64_t> usages = base; // controller copies out of the shards each tick
      sink += computeWaterLevel(usages, 0.4);
    }
    const auto end = Clock::now();
    std::printf("   %6zu tenants: %8.1f us/solve (copy+sort+solve, sink=%" PRIu64 ")\n", n,
                ns_per_op(start, end, iters) / 1000.0, sink % 2);
  }
}

struct ShardedMap {
  static constexpr size_t NumShards = 64;
  struct Shard {
    std::mutex mu;
    std::unordered_map<std::string, int64_t> usage;
  };
  Shard shards[NumShards];
  std::hash<std::string> hasher;

  void add(const std::string& ip, int64_t delta) {
    Shard& s = shards[hasher(ip) % NumShards];
    std::lock_guard<std::mutex> lock(s.mu);
    auto [it, _] = s.usage.try_emplace(ip, 0);
    it->second += delta;
    if (it->second <= 0) {
      s.usage.erase(it);
    }
  }
};

static void benchShardedMap() {
  std::printf("-- striped tenant map addUsage (Tier-1 hot path)\n");
  constexpr uint64_t ops_per_thread = 2'000'000;
  std::vector<std::string> ips;
  for (int i = 0; i < 10000; ++i) {
    ips.push_back("10." + std::to_string(i / 65536) + "." + std::to_string((i / 256) % 256) +
                  "." + std::to_string(i % 256));
  }
  for (int threads : {1, 4, 8}) {
    ShardedMap map;
    const auto start = Clock::now();
    std::vector<std::thread> ts;
    for (int t = 0; t < threads; ++t) {
      ts.emplace_back([&map, &ips, t] {
        std::mt19937_64 rng(t);
        for (uint64_t i = 0; i < ops_per_thread; ++i) {
          const std::string& ip = ips[rng() % ips.size()];
          map.add(ip, 4096);
          map.add(ip, -4096);
        }
      });
    }
    for (auto& t : ts) {
      t.join();
    }
    const auto end = Clock::now();
    std::printf("   %d thread(s): %6.1f ns/op (%" PRIu64 " ops)\n", threads,
                ns_per_op(start, end, 2 * ops_per_thread * threads),
                2 * ops_per_thread * threads);
  }
}

template <typename F> static void benchClock(const char* name, F read) {
  constexpr uint64_t iters = 2'000'000;
  uint64_t sink = 0;
  const auto start = Clock::now();
  for (uint64_t i = 0; i < iters; ++i) {
    sink += read();
  }
  const auto end = Clock::now();
  std::printf("   %-28s %8.1f ns/read (sink=%" PRIu64 ")\n", name, ns_per_op(start, end, iters),
              sink % 2);
}

static void benchClocks() {
  std::printf("-- clock read cost (CPU attribution budget: 2 reads per dispatcher callback)\n");
  benchClock("steady_clock::now", [] {
    return static_cast<uint64_t>(Clock::now().time_since_epoch().count());
  });
  benchClock("CLOCK_MONOTONIC", [] {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_nsec);
  });
  benchClock("CLOCK_THREAD_CPUTIME_ID", [] {
    timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return static_cast<uint64_t>(ts.tv_nsec);
  });
#ifdef __APPLE__
  benchClock("mach thread_info", [] {
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    thread_info(mach_thread_self(), THREAD_BASIC_INFO,
                reinterpret_cast<thread_info_t>(&info), &count);
    return static_cast<uint64_t>(info.user_time.microseconds);
  });
#endif
}

int main() {
  benchSolve();
  benchShardedMap();
  benchClocks();
  return 0;
}
