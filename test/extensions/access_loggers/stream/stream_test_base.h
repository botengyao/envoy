#pragma once

#include "envoy/access_log/access_log.h"
#include "envoy/config/accesslog/v3/accesslog.pb.validate.h"
#include "envoy/extensions/access_loggers/stream/v3/stream.pb.h"
#include "envoy/registry/registry.h"

#include "source/common/access_log/access_log_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/extensions/access_loggers/common/file_access_log_impl.h"
#include "source/extensions/access_loggers/stream/config.h"

#include "test/mocks/server/factory_context.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::Return;

namespace Envoy {
namespace Extensions {
namespace AccessLoggers {
namespace File {
namespace {

template <class T, Filesystem::DestinationType destination_type>
class StreamAccessLogTest : public testing::Test {
public:
  StreamAccessLogTest() = default;

protected:
  void runTest(const std::string& yaml, absl::string_view expected, bool is_json) {
    T fal_config;
    TestUtility::loadFromYaml(yaml, fal_config);

    envoy::config::accesslog::v3::AccessLog config;
    config.mutable_typed_config()->PackFrom(fal_config);

    auto file = std::make_shared<AccessLog::MockAccessLogFile>();
    Filesystem::FilePathAndType file_info{destination_type, ""};
    EXPECT_CALL(context_.server_factory_context_.access_log_manager_, createAccessLog(file_info))
        .WillOnce(Return(file));

    AccessLog::InstanceSharedPtr logger = AccessLog::AccessLogFactory::fromProto(config, context_);

    absl::Time abslStartTime =
        TestUtility::parseTime("Dec 18 01:50:34 2018 GMT", "%b %e %H:%M:%S %Y GMT");
    stream_info_.start_time_ = absl::ToChronoTime(abslStartTime);
    stream_info_.upstreamInfo()->setUpstreamHost(nullptr);
    stream_info_.setResponseCode(200);

    EXPECT_CALL(*file, write(_)).WillOnce(Invoke([expected, is_json](absl::string_view got) {
      if (is_json) {
        EXPECT_TRUE(TestUtility::jsonStringEqual(std::string(got), std::string(expected)));
      } else {
        EXPECT_EQ(got, expected);
      }
    }));
    logger->log({&request_headers_, &response_headers_, &response_trailers_}, stream_info_);
  }

  Http::TestRequestHeaderMapImpl request_headers_{{":method", "GET"}, {":path", "/bar/foo"}};
  Http::TestResponseHeaderMapImpl response_headers_;
  Http::TestResponseTrailerMapImpl response_trailers_;
  NiceMock<StreamInfo::MockStreamInfo> stream_info_;

  NiceMock<Server::Configuration::MockFactoryContext> context_;
};

class StreamAccessLogExtensionConfigYamlTest : public testing::Test {
public:
  void runTest(std::string yaml, Filesystem::DestinationType expected_file_type) {
    ON_CALL(context_.server_factory_context_, runtime()).WillByDefault(ReturnRef(runtime_));
    ON_CALL(context_.server_factory_context_, accessLogManager())
        .WillByDefault(ReturnRef(log_manager_));
    EXPECT_CALL(log_manager_, createAccessLog(_))
        .WillOnce(
            Invoke([this, expected_file_type](const Envoy::Filesystem::FilePathAndType& file_info)
                       -> absl::StatusOr<AccessLog::AccessLogFileSharedPtr> {
              EXPECT_EQ(file_info.path_, "");
              EXPECT_EQ(file_info.file_type_, expected_file_type);
              return file_;
            }));
    envoy::config::accesslog::v3::AccessLog access_log;
    TestUtility::loadFromYamlAndValidate(yaml, access_log);
    EXPECT_NO_THROW(AccessLog::AccessLogFactory::fromProto(access_log, context_));
  }

private:
  NiceMock<Envoy::AccessLog::MockAccessLogManager> log_manager_;
  NiceMock<Server::Configuration::MockFactoryContext> context_;
  NiceMock<Runtime::MockLoader> runtime_;
  std::shared_ptr<AccessLog::MockAccessLogFile> file_;
};

} // namespace
} // namespace File
} // namespace AccessLoggers
} // namespace Extensions
} // namespace Envoy
