#include <memory>
#include <string>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/utility.h"
#include "source/extensions/filters/http/tenant_load_shed/tenant_load_shed_filter.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TenantLoadShed {
namespace {

using Filters::Common::TenantLoadShed::WaterFillController;

class TenantLoadShedFilterTest : public testing::Test {
protected:
  TenantLoadShedFilterTest() {
    // The controller's evaluation timer is created on the (mock) main dispatcher.
    timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
    EXPECT_CALL(context_.overload_manager_, registerForAction(_, _, _))
        .WillOnce(DoAll(SaveArg<2>(&action_cb_), Return(true)));

    WaterFillController::WaterFillConfig config;
    config.set_overload_action_name("envoy.overload_actions.shed_tenant_load");
    controller_ = std::make_shared<WaterFillController>(context_, config);
    filter_config_ = std::make_shared<const FilterConfig>(
        FilterConfig{controller_, StreamCost, Http::Code::ServiceUnavailable});
  }

  std::unique_ptr<TenantLoadShedFilter>
  makeFilter(NiceMock<Http::MockStreamDecoderFilterCallbacks>& callbacks, const std::string& ip) {
    callbacks.stream_info_.downstream_connection_info_provider_->setDirectRemoteAddressForTest(
        Network::Utility::parseInternetAddressNoThrow(ip));
    auto filter = std::make_unique<TenantLoadShedFilter>(filter_config_);
    filter->setDecoderFilterCallbacks(callbacks);
    return filter;
  }

  uint64_t totalUsage() {
    return TestUtility::findGauge(context_.store_, "tenant_load_shed.total_usage_bytes")->value();
  }

  static constexpr uint64_t StreamCost = 1000;

  NiceMock<Server::Configuration::MockServerFactoryContext> context_;
  NiceMock<Event::MockTimer>* timer_{};
  Server::OverloadActionCb action_cb_;
  std::shared_ptr<WaterFillController> controller_;
  FilterConfigSharedPtr filter_config_;
  Http::TestRequestHeaderMapImpl headers_{
      {":method", "POST"}, {":path", "/"}, {":authority", "host"}};
};

// Severity 1 (saturated action) rejects every stream with 503 and the shed header, and does
// not account anything for the rejected stream.
TEST_F(TenantLoadShedFilterTest, RejectAllAtSaturation) {
  action_cb_(Server::OverloadActionState::saturated());
  timer_->invokeCallback(); // Publish the reject-all snapshot.

  NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks;
  auto filter = makeFilter(callbacks, "10.0.0.1");
  EXPECT_CALL(callbacks, sendLocalReply(Http::Code::ServiceUnavailable, _, _, _, "tenant_load_shed"));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter->decodeHeaders(headers_, false));

  filter->onDestroy();
  timer_->invokeCallback();
  EXPECT_EQ(0, totalUsage());
}

// Admitted streams account stream cost plus body bytes and release everything exactly once on
// destruction.
TEST_F(TenantLoadShedFilterTest, AdmitAccountAndReleaseLifecycle) {
  NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks;
  auto filter = makeFilter(callbacks, "10.0.0.1");
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter->decodeHeaders(headers_, false));

  Buffer::OwnedImpl body(std::string(4096, 'x'));
  EXPECT_EQ(Http::FilterDataStatus::Continue, filter->decodeData(body, true));

  timer_->invokeCallback();
  EXPECT_EQ(StreamCost + 4096, totalUsage());

  filter->onDestroy();
  filter->onDestroy(); // Idempotent: the release must happen exactly once.
  timer_->invokeCallback();
  EXPECT_EQ(0, totalUsage());
}

// At partial severity only the tenant above the water level is shed; the light tenant is
// untouched (the max-min fairness property, end to end through the filter).
TEST_F(TenantLoadShedFilterTest, WaterFillShedsHeavyTenantOnly) {
  NiceMock<Http::MockStreamDecoderFilterCallbacks> heavy_callbacks;
  auto heavy = makeFilter(heavy_callbacks, "10.0.0.1");
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, heavy->decodeHeaders(headers_, false));
  Buffer::OwnedImpl body(std::string(102400, 'x'));
  EXPECT_EQ(Http::FilterDataStatus::Continue, heavy->decodeData(body, false));

  NiceMock<Http::MockStreamDecoderFilterCallbacks> light_callbacks;
  auto light = makeFilter(light_callbacks, "10.0.0.2");
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, light->decodeHeaders(headers_, false));

  action_cb_(Server::OverloadActionState(UnitFloat(0.5f)));
  timer_->invokeCallback(); // usages {heavy: 103400, light: 1000} -> level between them.

  NiceMock<Http::MockStreamDecoderFilterCallbacks> heavy_retry_callbacks;
  auto heavy_retry = makeFilter(heavy_retry_callbacks, "10.0.0.1");
  EXPECT_CALL(heavy_retry_callbacks,
              sendLocalReply(Http::Code::ServiceUnavailable, _, _, _, "tenant_load_shed"));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration,
            heavy_retry->decodeHeaders(headers_, false));

  NiceMock<Http::MockStreamDecoderFilterCallbacks> light_retry_callbacks;
  auto light_retry = makeFilter(light_retry_callbacks, "10.0.0.2");
  EXPECT_CALL(light_retry_callbacks, sendLocalReply(_, _, _, _, _)).Times(0);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, light_retry->decodeHeaders(headers_, false));

  EXPECT_EQ(1, TestUtility::findGauge(context_.store_, "tenant_load_shed.tenants_shed")->value());
}

} // namespace
} // namespace TenantLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
