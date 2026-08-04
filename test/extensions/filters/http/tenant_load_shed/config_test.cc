#include "envoy/extensions/filters/http/tenant_load_shed/v3/tenant_load_shed.pb.h"

#include "source/extensions/filters/http/tenant_load_shed/config.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/server/factory_context.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TenantLoadShed {
namespace {

TEST(TenantLoadShedConfigTest, SelfContainedModeCreatesFilter) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  // The controller schedules its evaluation timer on the main dispatcher at construction.
  new NiceMock<Event::MockTimer>(&context.server_factory_context_.dispatcher_);

  envoy::extensions::filters::http::tenant_load_shed::v3::TenantLoadShed proto_config;
  proto_config.mutable_water_fill()->set_max_heap_size_bytes(2ULL * 1024 * 1024 * 1024);

  TenantLoadShedFilterFactory factory;
  auto cb = factory.createFilterFactoryFromProto(proto_config, "stats", context);
  ASSERT_TRUE(cb.ok());

  Http::MockFilterChainFactoryCallbacks filter_callbacks;
  EXPECT_CALL(filter_callbacks, addStreamFilter(_));
  cb.value()(filter_callbacks);
}

TEST(TenantLoadShedConfigTest, MissingPressureSourceRejected) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  envoy::extensions::filters::http::tenant_load_shed::v3::TenantLoadShed proto_config;
  proto_config.mutable_water_fill();

  TenantLoadShedFilterFactory factory;
  auto cb = factory.createFilterFactoryFromProto(proto_config, "stats", context);
  EXPECT_FALSE(cb.ok());
}

TEST(TenantLoadShedConfigTest, InvertedThresholdsRejected) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  envoy::extensions::filters::http::tenant_load_shed::v3::TenantLoadShed proto_config;
  auto* water_fill = proto_config.mutable_water_fill();
  water_fill->set_max_heap_size_bytes(1024);
  water_fill->mutable_shed_start_threshold()->set_value(95.0);
  water_fill->mutable_reject_all_threshold()->set_value(90.0);

  TenantLoadShedFilterFactory factory;
  auto cb = factory.createFilterFactoryFromProto(proto_config, "stats", context);
  EXPECT_FALSE(cb.ok());
}

} // namespace
} // namespace TenantLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
