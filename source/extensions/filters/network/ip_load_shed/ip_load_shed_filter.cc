#include "source/extensions/filters/network/ip_load_shed/ip_load_shed_filter.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace IpLoadShed {

IpLoadShedFilter::~IpLoadShedFilter() {
  // The filter is destroyed with its connection on the owning worker thread; release all
  // accounted usage for this connection.
  if (accounted_bytes_ > 0 && !ip_key_.empty()) {
    controller_->addUsage(ip_key_, -accounted_bytes_);
    accounted_bytes_ = 0;
  }
}

Network::FilterStatus IpLoadShedFilter::onNewConnection() {
  Network::Connection& connection = read_callbacks_->connection();
  ip_key_ = controller_->tenantKey(connection.connectionInfoProvider());

  if (!ip_key_.empty()) {
    const ShedSnapshotConstSharedPtr snapshot = controller_->snapshot();
    if (snapshot != nullptr && snapshot->shouldShed(ip_key_)) {
      controller_->stats().shed_total_.inc();
      ip_key_.clear(); // Nothing was accounted; the destructor must not release.
      connection.close(Network::ConnectionCloseType::NoFlush, "ip_load_shed");
      return Network::FilterStatus::StopIteration;
    }
    // Admitted: account the fixed per-connection cost now; bytes accrue as they are seen.
    account(connection_cost_bytes_);
  }
  return Network::FilterStatus::Continue;
}

Network::FilterStatus IpLoadShedFilter::onData(Buffer::Instance& data, bool) {
  account(data.length());
  return Network::FilterStatus::Continue;
}

Network::FilterStatus IpLoadShedFilter::onWrite(Buffer::Instance& data, bool) {
  account(data.length());
  return Network::FilterStatus::Continue;
}

void IpLoadShedFilter::account(uint64_t bytes) {
  if (bytes == 0 || ip_key_.empty()) {
    return;
  }
  accounted_bytes_ += static_cast<int64_t>(bytes);
  controller_->addUsage(ip_key_, static_cast<int64_t>(bytes));
}

} // namespace IpLoadShed
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
