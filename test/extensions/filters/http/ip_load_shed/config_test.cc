#include "envoy/extensions/filters/http/ip_load_shed/v3/ip_load_shed.pb.h"

#include "source/extensions/filters/http/ip_load_shed/config.h"

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
namespace IpLoadShed {
namespace {

TEST(IpLoadShedConfigTest, SelfContainedModeCreatesFilter) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  // The controller schedules its evaluation timer on the main dispatcher at construction.
  new NiceMock<Event::MockTimer>(&context.server_factory_context_.dispatcher_);

  envoy::extensions::filters::http::ip_load_shed::v3::IpLoadShed proto_config;
  proto_config.set_max_heap_size_bytes(2ULL * 1024 * 1024 * 1024);

  IpLoadShedFilterFactory factory;
  auto cb = factory.createFilterFactoryFromProto(proto_config, "stats", context);
  ASSERT_TRUE(cb.ok());

  Http::MockFilterChainFactoryCallbacks filter_callbacks;
  EXPECT_CALL(filter_callbacks, addStreamFilter(_));
  cb.value()(filter_callbacks);
}

TEST(IpLoadShedConfigTest, MissingPressureSourceRejected) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  envoy::extensions::filters::http::ip_load_shed::v3::IpLoadShed proto_config;

  IpLoadShedFilterFactory factory;
  auto cb = factory.createFilterFactoryFromProto(proto_config, "stats", context);
  EXPECT_FALSE(cb.ok());
}

TEST(IpLoadShedConfigTest, InvertedThresholdsRejected) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  envoy::extensions::filters::http::ip_load_shed::v3::IpLoadShed proto_config;
  proto_config.set_max_heap_size_bytes(1024);
  proto_config.mutable_shed_start_threshold()->set_value(95.0);
  proto_config.mutable_reject_all_threshold()->set_value(90.0);

  IpLoadShedFilterFactory factory;
  auto cb = factory.createFilterFactoryFromProto(proto_config, "stats", context);
  EXPECT_FALSE(cb.ok());
}

} // namespace
} // namespace IpLoadShed
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
