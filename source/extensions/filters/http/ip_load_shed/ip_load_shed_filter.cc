#include "source/extensions/filters/http/ip_load_shed/ip_load_shed_filter.h"

#include "envoy/network/address.h"

#include "source/common/common/macros.h"
#include "source/common/http/header_map_impl.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace IpLoadShed {

namespace {
const Http::LowerCaseString& shedHeader() {
  CONSTRUCT_ON_FIRST_USE(Http::LowerCaseString, "x-envoy-ip-load-shed");
}
} // namespace

Http::FilterHeadersStatus IpLoadShedFilter::decodeHeaders(Http::RequestHeaderMap&, bool) {
  // The tenant identity is the *direct* remote address (the micro-VM's own IP), deliberately
  // not the XFF-restored address, so a tenant cannot shift its usage onto another tenant.
  const Network::Address::InstanceConstSharedPtr& address =
      decoder_callbacks_->streamInfo().downstreamAddressProvider().directRemoteAddress();
  if (address != nullptr && address->type() == Network::Address::Type::Ip) {
    ip_key_ = address->ip()->addressAsString();
  }

  if (!ip_key_.empty()) {
    const ShedSnapshotConstSharedPtr snapshot = controller_->snapshot();
    if (snapshot != nullptr && snapshot->shouldShed(ip_key_)) {
      controller_->stats().shed_total_.inc();
      decoder_callbacks_->sendLocalReply(
          controller_->rejectionStatusCode(), "tenant usage over water level\n",
          [](Http::ResponseHeaderMap& headers) { headers.setReference(shedHeader(), "true"); },
          std::nullopt, "ip_load_shed");
      return Http::FilterHeadersStatus::StopIteration;
    }
    // Admitted: account the fixed per-stream cost now; body bytes accrue as they are seen.
    account(controller_->streamCostBytes());
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus IpLoadShedFilter::decodeData(Buffer::Instance& data, bool) {
  account(data.length());
  return Http::FilterDataStatus::Continue;
}

Http::FilterDataStatus IpLoadShedFilter::encodeData(Buffer::Instance& data, bool) {
  account(data.length());
  return Http::FilterDataStatus::Continue;
}

void IpLoadShedFilter::onDestroy() {
  if (accounted_bytes_ > 0 && !ip_key_.empty()) {
    controller_->addUsage(ip_key_, -accounted_bytes_);
    accounted_bytes_ = 0;
  }
}

void IpLoadShedFilter::account(uint64_t bytes) {
  if (bytes == 0 || ip_key_.empty()) {
    return;
  }
  accounted_bytes_ += static_cast<int64_t>(bytes);
  controller_->addUsage(ip_key_, static_cast<int64_t>(bytes));
}

} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
