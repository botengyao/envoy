#include "envoy/extensions/filters/network/ip_load_shed/v3/ip_load_shed.pb.h"

#include "source/extensions/filters/network/ip_load_shed/config.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/factory_context.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace IpLoadShed {
namespace {

TEST(IpLoadShedNetworkConfigTest, SelfContainedModeCreatesFilter) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  // The controller schedules its evaluation timer on the main dispatcher at construction.
  new NiceMock<Event::MockTimer>(&context.server_factory_context_.dispatcher_);

  envoy::extensions::filters::network::ip_load_shed::v3::IpLoadShed proto_config;
  proto_config.mutable_water_fill()->set_max_heap_size_bytes(2ULL * 1024 * 1024 * 1024);

  IpLoadShedConfigFactory factory;
  auto cb = factory.createFilterFactoryFromProto(proto_config, context);
  ASSERT_TRUE(cb.ok());

  NiceMock<Network::MockFilterManager> filter_manager;
  EXPECT_CALL(filter_manager, addFilter(_));
  cb.value()(filter_manager);
}

TEST(IpLoadShedNetworkConfigTest, MissingPressureSourceRejected) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  envoy::extensions::filters::network::ip_load_shed::v3::IpLoadShed proto_config;
  proto_config.mutable_water_fill();

  IpLoadShedConfigFactory factory;
  auto cb = factory.createFilterFactoryFromProto(proto_config, context);
  EXPECT_FALSE(cb.ok());
}

} // namespace
} // namespace IpLoadShed
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
