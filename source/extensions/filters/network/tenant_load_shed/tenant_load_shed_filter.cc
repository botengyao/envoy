#include "source/extensions/filters/network/tenant_load_shed/tenant_load_shed_filter.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace TenantLoadShed {

TenantLoadShedFilter::~TenantLoadShedFilter() {
  // The filter is destroyed with its connection on the owning worker thread; release all
  // accounted usage for this connection.
  if (accounted_bytes_ > 0 && !tenant_key_.empty()) {
    controller_->addUsage(tenant_key_, -accounted_bytes_);
    accounted_bytes_ = 0;
  }
}

Network::FilterStatus TenantLoadShedFilter::onNewConnection() {
  Network::Connection& connection = read_callbacks_->connection();
  tenant_key_ = controller_->tenantKey(connection.connectionInfoProvider());

  if (!tenant_key_.empty()) {
    const ShedSnapshotConstSharedPtr snapshot = controller_->snapshot();
    if (snapshot != nullptr && snapshot->shouldShed(tenant_key_)) {
      controller_->stats().shed_total_.inc();
      tenant_key_.clear(); // Nothing was accounted; the destructor must not release.
      connection.close(Network::ConnectionCloseType::NoFlush, "tenant_load_shed");
      return Network::FilterStatus::StopIteration;
    }
    // Admitted: account the fixed per-connection cost now; bytes accrue as they are seen.
    account(connection_cost_bytes_);
  }
  return Network::FilterStatus::Continue;
}

Network::FilterStatus TenantLoadShedFilter::onData(Buffer::Instance& data, bool) {
  account(data.length());
  return Network::FilterStatus::Continue;
}

Network::FilterStatus TenantLoadShedFilter::onWrite(Buffer::Instance& data, bool) {
  account(data.length());
  return Network::FilterStatus::Continue;
}

void TenantLoadShedFilter::account(uint64_t bytes) {
  if (bytes == 0 || tenant_key_.empty()) {
    return;
  }
  accounted_bytes_ += static_cast<int64_t>(bytes);
  controller_->addUsage(tenant_key_, static_cast<int64_t>(bytes));
}

} // namespace TenantLoadShed
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
