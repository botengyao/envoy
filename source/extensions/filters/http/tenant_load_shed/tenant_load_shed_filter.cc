#include "source/extensions/filters/http/tenant_load_shed/tenant_load_shed_filter.h"

#include "source/common/common/macros.h"
#include "source/common/http/header_map_impl.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TenantLoadShed {

namespace {
const Http::LowerCaseString& shedHeader() {
  CONSTRUCT_ON_FIRST_USE(Http::LowerCaseString, "x-envoy-tenant-load-shed");
}
} // namespace

Http::FilterHeadersStatus TenantLoadShedFilter::decodeHeaders(Http::RequestHeaderMap&, bool) {
  tenant_key_ = config_->controller_->tenantKey(
      decoder_callbacks_->streamInfo().downstreamAddressProvider());

  if (!tenant_key_.empty()) {
    const ShedSnapshotConstSharedPtr snapshot = config_->controller_->snapshot();
    if (snapshot != nullptr && snapshot->shouldShed(tenant_key_)) {
      config_->controller_->stats().shed_total_.inc();
      // Nothing was accounted for this stream; clear the key so the local reply's own
      // encodeData bytes are not charged to the tenant either.
      tenant_key_.clear();
      decoder_callbacks_->sendLocalReply(
          config_->rejection_status_code_, "tenant usage over water level\n",
          [](Http::ResponseHeaderMap& headers) { headers.setReference(shedHeader(), "true"); },
          std::nullopt, "tenant_load_shed");
      return Http::FilterHeadersStatus::StopIteration;
    }
    // Admitted: account the fixed per-stream cost now; body bytes accrue as they are seen.
    account(config_->stream_cost_bytes_);
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus TenantLoadShedFilter::decodeData(Buffer::Instance& data, bool) {
  account(data.length());
  return Http::FilterDataStatus::Continue;
}

Http::FilterDataStatus TenantLoadShedFilter::encodeData(Buffer::Instance& data, bool) {
  account(data.length());
  return Http::FilterDataStatus::Continue;
}

void TenantLoadShedFilter::onDestroy() {
  if (accounted_bytes_ > 0 && !tenant_key_.empty()) {
    config_->controller_->addUsage(tenant_key_, -accounted_bytes_);
    accounted_bytes_ = 0;
  }
}

void TenantLoadShedFilter::account(uint64_t bytes) {
  if (bytes == 0 || tenant_key_.empty()) {
    return;
  }
  accounted_bytes_ += static_cast<int64_t>(bytes);
  config_->controller_->addUsage(tenant_key_, static_cast<int64_t>(bytes));
}

} // namespace TenantLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
