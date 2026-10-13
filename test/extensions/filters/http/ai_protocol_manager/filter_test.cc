#include <deque>
#include <memory>
#include <optional>
#include <string>

#include "envoy/extensions/filters/http/ai_protocol_manager/v3/ai_protocol_manager.pb.h"
#include "envoy/http/codes.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/coroutine/status_macros.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter_state.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/filter.h"
#include "source/extensions/filters/http/ai_protocol_manager/serializer.h"

#include "test/mocks/event/mocks.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/stats/mocks.h"
#include "test/test_common/logging.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

using testing::Invoke;
using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

class AiProtocolManagerFilterTest : public testing::Test {
public:
  AiProtocolManagerFilterTest() {
    // Capture the upstream watermark callbacks the filter registers so tests can
    // simulate upstream back-pressure.
    ON_CALL(callbacks_, addUpstreamWatermarkCallbacks(testing::_))
        .WillByDefault(
            Invoke([this](Http::UpstreamWatermarkCallbacks& cb) { watermark_cb_ = &cb; }));
    ON_CALL(callbacks_, removeUpstreamWatermarkCallbacks(testing::_))
        .WillByDefault(
            Invoke([this](Http::UpstreamWatermarkCallbacks&) { watermark_cb_ = nullptr; }));
    createFilter();
    // The in-memory buffer delivers completions via dispatcher.post(). Capture
    // those callbacks so the test can run the event loop deterministically.
    ON_CALL(callbacks_.dispatcher_, post(testing::_))
        .WillByDefault(Invoke([this](Event::PostCb cb) { posted_.push_back(std::move(cb)); }));
    ON_CALL(callbacks_, injectDecodedDataToFilterChain(testing::_, testing::_))
        .WillByDefault(Invoke([this](Buffer::Instance& data, bool end_stream) {
          injected_.add(data);
          injected_end_stream_ = end_stream;
          ++inject_calls_;
          // Simulate upstream back-pressure arising mid-replay: when configured,
          // raise the watermark right after the Nth injected chunk.
          if (watermark_cb_ != nullptr && inject_calls_ == raise_watermark_at_inject_) {
            watermark_cb_->onAboveWriteBufferHighWatermark();
          }
        }));
    // Capture continueDecoding() so trailer-terminated streams can assert the
    // held trailers are released after the replayed body.
    ON_CALL(callbacks_, continueDecoding()).WillByDefault(Invoke([this]() { ++continue_calls_; }));
    // Capture local replies so rejection tests can assert code and details.
    ON_CALL(callbacks_, sendLocalReply(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillByDefault(Invoke([this](Http::Code code, absl::string_view,
                                     std::function<void(Http::ResponseHeaderMap&)>,
                                     const std::optional<Grpc::Status::GrpcStatus>,
                                     absl::string_view details) {
          local_reply_code_ = code;
          local_reply_details_ = std::string(details);
          ++local_reply_calls_;
        }));
    // The BufferManager creates its replay callback on its first replay, so the mock is
    // manufactured on demand rather than armed up front. replay_cb_ stays null for a stream that
    // never replays.
    ON_CALL(callbacks_.dispatcher_, createSchedulableCallback_(testing::_))
        .WillByDefault(Invoke([this](std::function<void()> cb) -> Event::SchedulableCallback* {
          replay_cb_ = new NiceMock<Event::MockSchedulableCallback>(&callbacks_.dispatcher_, cb);
          return replay_cb_;
        }));
    ON_CALL(encoder_callbacks_.dispatcher_, post(testing::_))
        .WillByDefault(Invoke([this](Event::PostCb cb) { posted_.push_back(std::move(cb)); }));
    ON_CALL(encoder_callbacks_.dispatcher_, createSchedulableCallback_(testing::_))
        .WillByDefault(Invoke([this](std::function<void()> cb) -> Event::SchedulableCallback* {
          auto* scb =
              new NiceMock<Event::MockSchedulableCallback>(&encoder_callbacks_.dispatcher_, cb);
          ON_CALL(*scb, scheduleCallbackCurrentIteration()).WillByDefault(Invoke([this, scb, cb]() {
            scb->enabled_ = true;
            posted_.push_back([scb, cb]() {
              if (scb->enabled_) {
                scb->enabled_ = false;
                cb();
              }
            });
          }));
          ON_CALL(*scb, scheduleCallbackNextIteration()).WillByDefault(Invoke([this, scb, cb]() {
            scb->enabled_ = true;
            posted_.push_back([scb, cb]() {
              if (scb->enabled_) {
                scb->enabled_ = false;
                cb();
              }
            });
          }));
          return scb;
        }));
    ON_CALL(encoder_callbacks_, injectEncodedDataToFilterChain(testing::_, testing::_))
        .WillByDefault(Invoke([this](Buffer::Instance& data, bool end_stream) {
          encoded_injected_.add(data);
          encoded_injected_end_stream_ = end_stream;
          ++encoded_inject_calls_;
        }));
    ON_CALL(encoder_callbacks_, continueEncoding()).WillByDefault(Invoke([this]() {
      ++encode_continue_calls_;
    }));
    ON_CALL(encoder_callbacks_,
            sendLocalReply(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillByDefault(
            Invoke([this](Http::Code code, absl::string_view,
                          std::function<void(Http::ResponseHeaderMap&)>,
                          const std::optional<Grpc::Status::GrpcStatus>, absl::string_view) {
              encode_local_reply_code_ = code;
              ++encode_local_reply_calls_;
            }));
  }

  // Run at trace so debug/trace-log argument expressions execute too.
  LogLevelSetter log_level_setter_{spdlog::level::trace};

  // A test wanting a different filter-level config calls this again first. A
  // zero threshold leaves the field unset, so the default applies.
  void createFilter(bool parse_unconfigured_routes = false,
                    uint32_t inline_string_threshold_bytes = 0) {
    if (filter_ != nullptr) {
      filter_->onDestroy();
    }
    envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager proto;
    proto.mutable_request_handling()->set_parse_unconfigured_routes(parse_unconfigured_routes);
    if (inline_string_threshold_bytes != 0) {
      proto.mutable_request_handling()
          ->mutable_limits()
          ->mutable_inline_string_threshold_bytes()
          ->set_value(inline_string_threshold_bytes);
    }
    filter_ = std::make_unique<AiProtocolManagerFilter>(
        factory_, std::make_shared<const FilterConfig>(proto, *stats_store_.rootScope(),
                                                       AiFilterFactories{}));
    filter_->setDecoderFilterCallbacks(callbacks_);
    filter_->setEncoderFilterCallbacks(encoder_callbacks_);
  }

  // Parses unconfigured routes too, so a test can show the chain is not run there.
  void createFilterWithAiFilters(
      AiFilterFactories ai_filter_factories,
      envoy::extensions::filters::http::ai_protocol_manager::v3::RequestHandling::
          BodyReserialization reserialize_body =
              envoy::extensions::filters::http::ai_protocol_manager::v3::RequestHandling::ALWAYS) {
    if (filter_ != nullptr) {
      filter_->onDestroy();
    }
    envoy::extensions::filters::http::ai_protocol_manager::v3::AiProtocolManager proto;
    proto.mutable_request_handling()->set_parse_unconfigured_routes(true);
    proto.mutable_request_handling()->set_reserialize_body(reserialize_body);
    filter_ = std::make_unique<AiProtocolManagerFilter>(
        factory_, std::make_shared<const FilterConfig>(proto, *stats_store_.rootScope(),
                                                       std::move(ai_filter_factories)));
    filter_->setDecoderFilterCallbacks(callbacks_);
    filter_->setEncoderFilterCallbacks(encoder_callbacks_);
  }

  // decodeHeaders() for a stream the filter is expected to engage on.
  Http::FilterHeadersStatus decodeHeadersEngaging() {
    request_headers_ = requestHeaders();
    return filter_->decodeHeaders(request_headers_, /*end_stream=*/false);
  }

  // Engages the filter where the payload is not what the test is about:
  // parse_unconfigured_routes offloads and replays whether or not the body
  // parses.
  void engageIgnoringPayload() {
    createFilter(/*parse_unconfigured_routes=*/true);
    ASSERT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);
  }

  Http::FilterHeadersStatus decodeHeadersUnconfigured(Http::TestRequestHeaderMapImpl headers) {
    createFilter(/*parse_unconfigured_routes=*/true);
    return filter_->decodeHeaders(headers, /*end_stream=*/false);
  }

  // Attaches a per-route config declaring the route an AI endpoint with a
  // request payload for the filter to hold.
  void setRouteConfig() {
    PerRouteProto proto;
    proto.mutable_request()->set_llm_protocol(envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS);
    route_config_ = std::make_unique<RouteConfig>(proto);
    ON_CALL(callbacks_, mostSpecificPerFilterConfig())
        .WillByDefault(testing::Return(route_config_.get()));
    ON_CALL(encoder_callbacks_, mostSpecificPerFilterConfig())
        .WillByDefault(testing::Return(route_config_.get()));
  }

  // A valid chat-completions payload whose `model` sits between the default
  // 1KiB inline-string threshold and 4KiB, so which side of the threshold it
  // lands on is the configured value's doing.
  static std::string oversizedModelPayload() {
    return R"({"model":")" + std::string(2000, 'm') +
           R"(","messages":[{"role":"user","content":"hi"}]})";
  }

  static Http::TestRequestHeaderMapImpl requestHeaders() {
    // Best-effort parsing gates on a JSON content type.
    return Http::TestRequestHeaderMapImpl{
        {":method", "POST"}, {":path", "/chat/completions"}, {"content-type", "application/json"}};
  }

  // The manager the filter owns requires onDestroy() before destruction (see
  // buffer_manager.h); Envoy guarantees that in production, so drive it here to
  // detach decode_manager_ before ~filter_ frees it. Idempotent, so tests that
  // already called onDestroy() are fine.
  void TearDown() override { filter_->onDestroy(); }

  // Run all posted callbacks, including ones enqueued while draining.
  void drain() {
    while (!posted_.empty()) {
      Event::PostCb cb = std::move(posted_.front());
      posted_.pop_front();
      cb();
    }
  }

  uint64_t counterValue(const std::string& name) {
    const auto counter = TestUtility::findCounter(stats_store_, "ai_protocol_manager." + name);
    return counter != nullptr ? counter->value() : 0;
  }

  std::deque<Event::PostCb> posted_;
  NiceMock<Stats::MockIsolatedStatsStore> stats_store_;
  InMemoryExternalBufferFactory factory_;
  FilterConfigSharedPtr config_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks_;
  NiceMock<Http::MockStreamEncoderFilterCallbacks> encoder_callbacks_;
  Http::UpstreamWatermarkCallbacks* watermark_cb_{};
  // Owned by the manager the filter builds; present so createSchedulableCallback()
  // returns a usable callback during construction.
  NiceMock<Event::MockSchedulableCallback>* replay_cb_{nullptr};
  std::unique_ptr<RouteConfig> route_config_;
  std::unique_ptr<AiProtocolManagerFilter> filter_;
  Http::TestRequestHeaderMapImpl request_headers_;

  Buffer::OwnedImpl injected_;
  bool injected_end_stream_{false};
  int inject_calls_{0};
  int continue_calls_{0};
  int raise_watermark_at_inject_{0}; // 0 = never.
  int local_reply_calls_{0};
  std::optional<Http::Code> local_reply_code_;
  std::string local_reply_details_;

  Buffer::OwnedImpl encoded_injected_;
  bool encoded_injected_end_stream_{false};
  int encoded_inject_calls_{0};
  int encode_continue_calls_{0};
  int encode_local_reply_calls_{0};
  std::optional<Http::Code> encode_local_reply_code_;
};

// With a payload to inspect, iteration pauses so the rest of the chain does not
// see the headers until it is offloaded.
TEST_F(AiProtocolManagerFilterTest, HoldsHeadersWhenBodyFollows) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);
}

// A headers-only request has no payload to inspect, so the headers flow
// immediately; holding them would deadlock since no body drives the release.
TEST_F(AiProtocolManagerFilterTest, PassesHeadersOnlyRequest) {
  Http::TestRequestHeaderMapImpl headers{{":method", "GET"}, {":path", "/healthz"}};
  EXPECT_EQ(filter_->decodeHeaders(headers, true), Http::FilterHeadersStatus::Continue);
}

// Headers held during decodeHeaders() are released when replay begins: the body
// is offloaded while iteration is paused, then injected back to the chain.
TEST_F(AiProtocolManagerFilterTest, ReleasesHeldHeadersOnReplay) {
  engageIgnoringPayload();

  Buffer::OwnedImpl body("{\"messages\":[\"hi\"]}");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_GE(inject_calls_, 1);
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.toString(), "{\"messages\":[\"hi\"]}");
}

// The body is offloaded chunk-by-chunk and replayed verbatim once end_stream is
// seen, with end_stream propagated on the final injected frame.
TEST_F(AiProtocolManagerFilterTest, OffloadsAndReplaysBody) {
  engageIgnoringPayload();
  Buffer::OwnedImpl chunk1("{\"messages\":");
  EXPECT_EQ(filter_->decodeData(chunk1, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Buffer::OwnedImpl chunk2("[\"hi\"]}");
  EXPECT_EQ(filter_->decodeData(chunk2, true), Http::FilterDataStatus::StopIterationNoBuffer);

  // Nothing has been replayed yet: writes and replay are all asynchronous.
  EXPECT_EQ(inject_calls_, 0);

  drain();

  EXPECT_GE(inject_calls_, 1);
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.toString(), "{\"messages\":[\"hi\"]}");
}

// A body that arrives in a single end_stream frame is still round-tripped.
TEST_F(AiProtocolManagerFilterTest, SingleFrameBody) {
  engageIgnoringPayload();
  Buffer::OwnedImpl body("{}");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.toString(), "{}");
}

// An empty terminal frame produces an empty end_stream marker downstream. It
// issues no write, so replay is scheduled (not started reentrantly from
// decodeData) and runs on the next event-loop iteration.
TEST_F(AiProtocolManagerFilterTest, EmptyBody) {
  engageIgnoringPayload();
  Buffer::OwnedImpl empty;
  EXPECT_EQ(filter_->decodeData(empty, true), Http::FilterDataStatus::StopIterationNoBuffer);

  EXPECT_EQ(inject_calls_, 0);
  ASSERT_TRUE(replay_cb_->enabled());
  replay_cb_->invokeCallback();

  EXPECT_EQ(inject_calls_, 1);
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.length(), 0);
}

// A payload larger than the replay chunk size is streamed back in multiple
// bounded frames and reassembles to the original bytes.
TEST_F(AiProtocolManagerFilterTest, LargePayloadReplayedInChunks) {
  engageIgnoringPayload();
  const std::string big(200 * 1024, 'x'); // > ReadChunkSize (64KiB)
  Buffer::OwnedImpl body(big);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_GT(inject_calls_, 1);
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.length(), big.size());
  EXPECT_EQ(injected_.toString(), big);
}

// Destroying the filter mid-flight cancels pending callbacks; no replay occurs.
TEST_F(AiProtocolManagerFilterTest, DestroyBeforeReplay) {
  engageIgnoringPayload();
  Buffer::OwnedImpl body("payload");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  filter_->onDestroy();
  drain();

  EXPECT_EQ(inject_calls_, 0);
}

// The filter registers for upstream watermark callbacks so it can observe
// upstream back-pressure during replay.
TEST_F(AiProtocolManagerFilterTest, RegistersUpstreamWatermarkCallbacks) {
  engageIgnoringPayload();
  EXPECT_NE(watermark_cb_, nullptr);
}

// When the downstream chain (toward upstream) is backed up before replay starts,
// no data is injected until the back-pressure is released.
TEST_F(AiProtocolManagerFilterTest, ReplayPausesUnderUpstreamBackPressure) {
  engageIgnoringPayload();
  const std::string big(200 * 1024, 'x'); // > ReadChunkSize, multiple chunks.
  Buffer::OwnedImpl body(big);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);

  // Upstream signals back-pressure before replay begins.
  ASSERT_NE(watermark_cb_, nullptr);
  watermark_cb_->onAboveWriteBufferHighWatermark();

  // Draining completes the write and starts replay, but replay is paused: no
  // chunk is read or injected while the high watermark is held.
  drain();
  EXPECT_EQ(inject_calls_, 0);
  EXPECT_FALSE(injected_end_stream_);

  // Releasing back-pressure schedules the resume off the watermark callback stack
  // (deferred so we never read/inject reentrantly from within it); firing the
  // continuation runs replay to completion.
  watermark_cb_->onBelowWriteBufferLowWatermark();
  ASSERT_TRUE(replay_cb_->enabled());
  replay_cb_->invokeCallback();
  drain();
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.length(), big.size());
  EXPECT_EQ(injected_.toString(), big);
}

// Back-pressure arising mid-replay (the upstream fills as we inject) halts the
// synchronous read loop, and replay resumes when it clears.
TEST_F(AiProtocolManagerFilterTest, ReplayResumesMidStream) {
  engageIgnoringPayload();
  const std::string big(200 * 1024, 'x'); // 4 chunks of 64KiB + remainder.
  // Upstream backs up right after the first replayed chunk; the loop must then
  // stop until it is released.
  raise_watermark_at_inject_ = 1;
  Buffer::OwnedImpl body(big);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);

  // Append completes, replay injects one chunk, then pauses on the watermark
  // raised during that inject.
  drain();
  EXPECT_EQ(inject_calls_, 1);
  EXPECT_FALSE(injected_end_stream_);
  EXPECT_LT(injected_.length(), big.size());

  // Release back-pressure; the resume is scheduled off the watermark callback
  // stack (deferred to avoid reentrant read/inject) and the continuation runs
  // replay to completion.
  ASSERT_NE(watermark_cb_, nullptr);
  watermark_cb_->onBelowWriteBufferLowWatermark();
  ASSERT_TRUE(replay_cb_->enabled());
  replay_cb_->invokeCallback();
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.toString(), big);
}

// High watermark callbacks can nest (stream + connection); replay resumes only
// after a matching number of low-watermark callbacks.
TEST_F(AiProtocolManagerFilterTest, NestedWatermarksRequireBalancedRelease) {
  engageIgnoringPayload();
  const std::string big(200 * 1024, 'x');
  Buffer::OwnedImpl body(big);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);

  ASSERT_NE(watermark_cb_, nullptr);
  watermark_cb_->onAboveWriteBufferHighWatermark();
  watermark_cb_->onAboveWriteBufferHighWatermark();
  drain();
  EXPECT_EQ(inject_calls_, 0);

  // One release is not enough to resume.
  watermark_cb_->onBelowWriteBufferLowWatermark();
  drain();
  EXPECT_EQ(inject_calls_, 0);
  EXPECT_FALSE(injected_end_stream_);

  // Balanced release schedules the resume off the watermark callback stack; the
  // continuation runs replay to completion.
  watermark_cb_->onBelowWriteBufferLowWatermark();
  ASSERT_TRUE(replay_cb_->enabled());
  replay_cb_->invokeCallback();
  drain();
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.toString(), big);
}

// A request whose body is terminated by trailers (last data frame has
// end_stream=false; the trailers carry END_STREAM) is not stuck: the body is
// replayed (final frame end_stream=false) and the held trailers are released
// via continueDecoding() once the body has been injected.
TEST_F(AiProtocolManagerFilterTest, TrailerTerminatedStream) {
  engageIgnoringPayload();
  Buffer::OwnedImpl body("{\"messages\":[\"hi\"]}");
  EXPECT_EQ(filter_->decodeData(body, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Http::TestRequestTrailerMapImpl trailers{{"x-trailer", "1"}};
  EXPECT_EQ(filter_->decodeTrailers(trailers), Http::FilterTrailersStatus::StopIteration);

  EXPECT_EQ(inject_calls_, 0);
  EXPECT_EQ(continue_calls_, 0);

  drain();

  EXPECT_GE(inject_calls_, 1);
  EXPECT_FALSE(injected_end_stream_);
  EXPECT_EQ(injected_.toString(), "{\"messages\":[\"hi\"]}");
  EXPECT_EQ(continue_calls_, 1);
}

// A trailer-only request (headers + trailers, no body) has nothing to offload, so
// the trailers flow immediately (Continue) and nothing is injected or held.
TEST_F(AiProtocolManagerFilterTest, TrailersWithoutBody) {
  engageIgnoringPayload();

  Http::TestRequestTrailerMapImpl trailers{{"x-trailer", "1"}};
  EXPECT_EQ(filter_->decodeTrailers(trailers), Http::FilterTrailersStatus::Continue);
  drain();

  EXPECT_EQ(inject_calls_, 0);
  EXPECT_EQ(continue_calls_, 0);
}

// A declared endpoint's payload is parsed as it is offloaded and still replayed
// downstream byte for byte: parsing observes the payload, it does not rewrite it.
TEST_F(AiProtocolManagerFilterTest, ParsesDeclaredEndpointPayloadAndReplaysItVerbatim) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  const std::string payload =
      R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true,"max_tokens":256})";
  Buffer::OwnedImpl body(payload);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(nlohmann::json::parse(injected_.toString()), nlohmann::json::parse(payload));
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(counterValue("request_parsed"), 1);
  EXPECT_EQ(counterValue("request_parse_error"), 0);
}

// Rewrites `model` so a test can tell the chain ran ahead of replay.
class ContextRecordingAiFilter : public AiFilter {
public:
  struct Seen {
    LLMProtocol protocol;
    LLMProtocol request_protocol;
    std::string path;
    const StreamInfo::StreamInfo* stream_info;
    uint64_t payload_bytes;
  };

  ContextRecordingAiFilter(const AiFilterContext& context, std::vector<Seen>& seen)
      : context_(context), seen_(seen) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr request, co_await std::move(receive_request)());
    seen_.push_back({context_.request_protocol, request->protocol(),
                     std::string(context_.request_headers.getPathValue()), &context_.stream_info,
                     context_.request_payload_bytes});
    request->json()["model"] = "rewritten";
    co_return co_await std::move(propagate_request)(std::move(request));
  }

private:
  const AiFilterContext context_;
  std::vector<Seen>& seen_;
};

// Receives the request and passes it on without editing it.
class PassThroughAiFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr request, co_await std::move(receive_request)());
    co_return co_await std::move(propagate_request)(std::move(request));
  }
};

TEST_F(AiProtocolManagerFilterTest, ForwardsTheReceivedBodyWhenReserializationIsDisabled) {
  createFilterWithAiFilters(
      {[](const AiFilterContext&) -> AiFilterSharedPtr {
        return std::make_unique<PassThroughAiFilter>();
      }},
      envoy::extensions::filters::http::ai_protocol_manager::v3::RequestHandling::DISABLE);
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  const std::string payload =
      "{ \"model\": \"gpt-4\",  \"messages\": [ {\"role\": \"user\", \"content\": \"hi\"} ] }";
  Buffer::OwnedImpl body(payload);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(injected_.toString(), payload);
  EXPECT_TRUE(injected_end_stream_);
}

TEST_F(AiProtocolManagerFilterTest, RunsConfiguredAiFiltersOverDeclaredPayload) {
  std::vector<ContextRecordingAiFilter::Seen> seen;
  int built = 0;
  createFilterWithAiFilters({[&](const AiFilterContext& context) -> AiFilterSharedPtr {
    ++built;
    return std::make_unique<ContextRecordingAiFilter>(context, seen);
  }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(built, 1);
  ASSERT_EQ(seen.size(), 1);
  EXPECT_EQ(seen[0].protocol, LLMProtocol::OpenAiChatCompletions);
  EXPECT_EQ(seen[0].request_protocol, LLMProtocol::OpenAiChatCompletions);
  EXPECT_EQ(seen[0].path, "/chat/completions");
  EXPECT_EQ(seen[0].stream_info, &callbacks_.stream_info_);
  EXPECT_EQ(nlohmann::json::parse(injected_.toString())["model"], "rewritten");
  EXPECT_TRUE(injected_end_stream_);
}

// The payload byte count a filter sees spans the whole body, not the frame that closed it.
TEST_F(AiProtocolManagerFilterTest, AiFilterContextCarriesTotalPayloadBytes) {
  std::vector<ContextRecordingAiFilter::Seen> seen;
  createFilterWithAiFilters({[&](const AiFilterContext& context) -> AiFilterSharedPtr {
    return std::make_unique<ContextRecordingAiFilter>(context, seen);
  }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  const std::string first = R"({"model":"gpt-4","messages":)";
  const std::string second = R"([{"role":"user","content":"hi"}]})";
  Buffer::OwnedImpl head(first);
  EXPECT_EQ(filter_->decodeData(head, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Buffer::OwnedImpl tail(second);
  EXPECT_EQ(filter_->decodeData(tail, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  ASSERT_EQ(seen.size(), 1);
  EXPECT_EQ(seen[0].payload_bytes, first.size() + second.size());
}

class AiProtocolManagerFilterStateTest : public AiProtocolManagerFilterTest {
public:
  // What the AI filters see on a Chat Completions route when filter state names `named`.
  std::vector<ContextRecordingAiFilter::Seen> runWithFilterState(LLMProtocol named) {
    std::vector<ContextRecordingAiFilter::Seen> seen;
    createFilterWithAiFilters({[&seen](const AiFilterContext& context) -> AiFilterSharedPtr {
      return std::make_unique<ContextRecordingAiFilter>(context, seen);
    }});
    setRouteConfig();
    callbacks_.stream_info_.filterState()->setData(FilterStateKeys::LlmProtocolRequest,
                                                   std::make_shared<RequestLlmProtocol>(named),
                                                   StreamInfo::FilterState::LifeSpan::FilterChain);
    EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);
    Buffer::OwnedImpl body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
    EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
    drain();
    return seen;
  }
};

TEST_F(AiProtocolManagerFilterStateTest, FilterStateOutranksTheRoute) {
  const auto seen = runWithFilterState(LLMProtocol::AnthropicMessages);
  ASSERT_EQ(seen.size(), 1);
  EXPECT_EQ(seen[0].protocol, LLMProtocol::AnthropicMessages);
  EXPECT_EQ(seen[0].request_protocol, LLMProtocol::AnthropicMessages);
}

TEST_F(AiProtocolManagerFilterStateTest, UnspecifiedFilterStateLeavesTheRoute) {
  const auto seen = runWithFilterState(LLMProtocol::Unspecified);
  ASSERT_EQ(seen.size(), 1);
  EXPECT_EQ(seen[0].protocol, LLMProtocol::OpenAiChatCompletions);
  EXPECT_EQ(seen[0].request_protocol, LLMProtocol::OpenAiChatCompletions);
}

TEST_F(AiProtocolManagerFilterTest, DoesNotRunAiFiltersOnUnconfiguredRoute) {
  std::vector<ContextRecordingAiFilter::Seen> seen;
  int built = 0;
  createFilterWithAiFilters({[&](const AiFilterContext& context) -> AiFilterSharedPtr {
    ++built;
    return std::make_unique<ContextRecordingAiFilter>(context, seen);
  }});
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"gpt-4"})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(built, 0);
  EXPECT_TRUE(seen.empty());
  EXPECT_EQ(nlohmann::json::parse(injected_.toString())["model"], "gpt-4");
  EXPECT_TRUE(injected_end_stream_);
}

TEST_F(AiProtocolManagerFilterTest, NullAiFilterIsSkipped) {
  createFilterWithAiFilters({[](const AiFilterContext&) -> AiFilterSharedPtr { return nullptr; }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  const std::string payload = R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})";
  Buffer::OwnedImpl body(payload);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(nlohmann::json::parse(injected_.toString()), nlohmann::json::parse(payload));
  EXPECT_TRUE(injected_end_stream_);
}

// Content-Length header is set to the recalculated length when the filter manager serializes the
// payload.
TEST_F(AiProtocolManagerFilterTest, SetsContentLengthOnReplay) {
  setRouteConfig();
  request_headers_ = Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                                    {":path", "/chat/completions"},
                                                    {"content-type", "application/json"},
                                                    {"content-length", "999"}};
  ASSERT_EQ(filter_->decodeHeaders(request_headers_, /*end_stream=*/false),
            Http::FilterHeadersStatus::StopIteration);
  EXPECT_EQ(request_headers_.getContentLengthValue(), "999");

  const std::string payload = R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})";
  Buffer::OwnedImpl body(payload);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_NE(request_headers_.ContentLength(), nullptr);
  EXPECT_EQ(request_headers_.getContentLengthValue(), absl::StrCat(injected_.length()));
}

// Content-Length header is not added if it was not previously present on request headers.
TEST_F(AiProtocolManagerFilterTest, DoesNotSetContentLengthOnReplayWhenAbsent) {
  setRouteConfig();
  request_headers_ = Http::TestRequestHeaderMapImpl{
      {":method", "POST"}, {":path", "/chat/completions"}, {"content-type", "application/json"}};
  ASSERT_EQ(filter_->decodeHeaders(request_headers_, /*end_stream=*/false),
            Http::FilterHeadersStatus::StopIteration);
  EXPECT_EQ(request_headers_.ContentLength(), nullptr);

  const std::string payload = R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})";
  Buffer::OwnedImpl body(payload);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(request_headers_.ContentLength(), nullptr);
}

// A payload whose `model` is larger than the default 1KiB inline-string
// threshold: the parser leaves the value in the external buffer.
TEST_F(AiProtocolManagerFilterTest, ModelOverInlineStringThresholdIsOffloaded) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(oversizedModelPayload());
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  const auto* index =
      callbacks_.stream_info_.filterState()->getDataReadOnly<APMRequestPayloadIndex>(
          APMRequestPayloadIndex::kFilterStateKey);
  ASSERT_NE(index, nullptr);
  EXPECT_TRUE(JsonWithExtBuf::isExternalRef(index->index().json().at("model")));
}

// The same payload is accepted once the configured threshold is raised above
// the value: the configured threshold, not the default, reaches the parser.
TEST_F(AiProtocolManagerFilterTest, RaisedInlineStringThresholdKeepsLargeValuesInline) {
  createFilter(/*parse_unconfigured_routes=*/false, /*inline_string_threshold_bytes=*/4096);
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  const std::string payload = oversizedModelPayload();
  Buffer::OwnedImpl body(payload);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  // The DOM stores object members in a std::map, so re-serialization does not
  // preserve key order; compare the parsed JSON rather than the raw bytes.
  EXPECT_EQ(nlohmann::json::parse(injected_.toString()), nlohmann::json::parse(payload));
  EXPECT_TRUE(injected_end_stream_);
  const auto* index =
      callbacks_.stream_info_.filterState()->getDataReadOnly<APMRequestPayloadIndex>(
          APMRequestPayloadIndex::kFilterStateKey);
  ASSERT_NE(index, nullptr);
  EXPECT_TRUE(index->index().json().at("model").is_string());
}

// Malformed JSON is answered with a 400 and never reaches the upstream.
TEST_F(AiProtocolManagerFilterTest, RejectsMalformedJson) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model" "gpt-4"})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 1);
  EXPECT_EQ(local_reply_code_, Http::Code::BadRequest);
  EXPECT_EQ(local_reply_details_, "ai_protocol_manager_invalid_json");
  EXPECT_EQ(inject_calls_, 0);
  EXPECT_EQ(counterValue("request_parse_error"), 1);
  EXPECT_EQ(counterValue("request_parsed"), 0);
}

// Where Envoy and the backend could otherwise read the same body differently.
TEST_F(AiProtocolManagerFilterTest, RejectsDuplicateKeys) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"a","model":"b"})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 1);
  EXPECT_EQ(local_reply_code_, Http::Code::BadRequest);
  EXPECT_EQ(inject_calls_, 0);
}

// Incomplete rather than malformed; caught when the terminal frame closes.
TEST_F(AiProtocolManagerFilterTest, RejectsTruncatedJson) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"gpt-4")");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 1);
  EXPECT_EQ(local_reply_code_, Http::Code::BadRequest);
  EXPECT_EQ(inject_calls_, 0);
}

// A stream whose framing promised a body but delivered none -- a chunked request
// with only the terminating chunk, or an empty terminal DATA frame -- carries no
// payload to validate, so it passes through just like a request that ended on
// its headers. A GET reaches the filter this way.
TEST_F(AiProtocolManagerFilterTest, EmptyBodyOnDeclaredEndpointIsPassedThrough) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl empty;
  EXPECT_EQ(filter_->decodeData(empty, true), Http::FilterDataStatus::StopIterationNoBuffer);
  ASSERT_TRUE(replay_cb_->enabled());
  replay_cb_->invokeCallback();
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.length(), 0);
  // No payload arrived, so there is no document and nothing to count parsed.
  EXPECT_EQ(counterValue("request_parsed"), 0);
  EXPECT_EQ(counterValue("request_parse_error"), 0);
}

// Only a stream with no body at all is exempt. Once bytes have arrived they are
// a payload, and an empty terminal frame closes it rather than excusing it.
TEST_F(AiProtocolManagerFilterTest, RejectsTruncatedJsonEndedByEmptyTerminalFrame) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"gpt-4")");
  EXPECT_EQ(filter_->decodeData(body, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Buffer::OwnedImpl terminal;
  EXPECT_EQ(filter_->decodeData(terminal, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 1);
  EXPECT_EQ(local_reply_code_, Http::Code::BadRequest);
  EXPECT_EQ(inject_calls_, 0);
}

// Parsing before offloading means a bad byte early in a large upload fails the
// request immediately, and the rest of the client's data is dropped.
TEST_F(AiProtocolManagerFilterTest, RejectsMalformedJsonMidUpload) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl bad_chunk(R"({"model" "gpt-4",)");
  EXPECT_EQ(filter_->decodeData(bad_chunk, false), Http::FilterDataStatus::StopIterationNoBuffer);
  EXPECT_EQ(local_reply_calls_, 1);

  // What was in flight is discarded, and nothing is replayed.
  Buffer::OwnedImpl trailing_chunk(std::string(64 * 1024, 'x'));
  EXPECT_EQ(filter_->decodeData(trailing_chunk, true),
            Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 1);
  EXPECT_EQ(inject_calls_, 0);
}

// Schema validation is an AI filter's job: without one, a well-formed payload
// the declared API would reject is forwarded.
TEST_F(AiProtocolManagerFilterTest, ForwardsSchemaInvalidPayloadWithoutValidationFilter) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  // Missing required "messages" field.
  Buffer::OwnedImpl body(R"({"model":"gpt-4"})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(nlohmann::json::parse(injected_.toString()),
            nlohmann::json::parse(R"({"model":"gpt-4"})"));
  EXPECT_EQ(counterValue("request_parsed"), 1);
}

// Unknown fields are permitted and pass through untouched.
TEST_F(AiProtocolManagerFilterTest, PassesThroughUnknownFields) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  const std::string payload =
      R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"custom_tag":"blue"})";
  Buffer::OwnedImpl body(payload);
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(nlohmann::json::parse(injected_.toString()), nlohmann::json::parse(payload));
  EXPECT_TRUE(injected_end_stream_);
}

// A body ending on an empty terminal frame still gets its document closed, so a
// complete payload split that way is not mistaken for a truncated one.
TEST_F(AiProtocolManagerFilterTest, ChunkedBodyWithEmptyTerminalFrame) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl chunk1(R"({"model":"gpt-4","messages":[{"role":")");
  EXPECT_EQ(filter_->decodeData(chunk1, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Buffer::OwnedImpl chunk2(R"(user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(chunk2, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Buffer::OwnedImpl terminal;
  EXPECT_EQ(filter_->decodeData(terminal, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(
      nlohmann::json::parse(injected_.toString()),
      nlohmann::json::parse(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})"));
}

// With trailers, no data frame carries end_stream, so the trailers close it.
TEST_F(AiProtocolManagerFilterTest, TrailerTerminatedJsonIsParsed) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(body, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Http::TestRequestTrailerMapImpl trailers{{"x-trailer", "1"}};
  EXPECT_EQ(filter_->decodeTrailers(trailers), Http::FilterTrailersStatus::StopIteration);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(
      nlohmann::json::parse(injected_.toString()),
      nlohmann::json::parse(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})"));
  EXPECT_EQ(continue_calls_, 1);
}

// The same path catches a truncated body that would otherwise be forwarded.
TEST_F(AiProtocolManagerFilterTest, RejectsTruncatedJsonTerminatedByTrailers) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"gpt-4")");
  EXPECT_EQ(filter_->decodeData(body, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Http::TestRequestTrailerMapImpl trailers{{"x-trailer", "1"}};
  EXPECT_EQ(filter_->decodeTrailers(trailers), Http::FilterTrailersStatus::StopIteration);
  drain();

  EXPECT_EQ(local_reply_calls_, 1);
  EXPECT_EQ(local_reply_code_, Http::Code::BadRequest);
  EXPECT_EQ(inject_calls_, 0);
  EXPECT_EQ(continue_calls_, 0);
}

// An undeclared route gives the filter nothing to look at: headers are not held,
// the body is not offloaded, nothing is replayed.
TEST_F(AiProtocolManagerFilterTest, PassesThroughUndeclaredRoute) {
  Http::TestRequestHeaderMapImpl headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);

  Buffer::OwnedImpl body(R"({"model":"gpt-4"})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::Continue);
  drain();

  // Left in the chain's own buffer rather than round-tripped.
  EXPECT_EQ(body.toString(), R"({"model":"gpt-4"})");
  EXPECT_EQ(inject_calls_, 0);
  EXPECT_EQ(local_reply_calls_, 0);
  // A stream the filter never engages on touches none of the request counters.
  EXPECT_EQ(counterValue("request_parsed"), 0);
  EXPECT_EQ(counterValue("request_passthrough"), 0);
}

// Nor does it subscribe to watermarks or claim any replay machinery.
TEST_F(AiProtocolManagerFilterTest, PassThroughStreamCostsNothing) {
  Http::TestRequestHeaderMapImpl headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);

  EXPECT_EQ(watermark_cb_, nullptr);
  EXPECT_EQ(replay_cb_, nullptr);
}

// Trailers on a pass-through stream flow like everything else.
TEST_F(AiProtocolManagerFilterTest, PassesThroughTrailersOnUndeclaredRoute) {
  Http::TestRequestHeaderMapImpl headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);

  Buffer::OwnedImpl body(R"({"model":"gpt-4"})");
  EXPECT_EQ(filter_->decodeData(body, false), Http::FilterDataStatus::Continue);
  Http::TestRequestTrailerMapImpl trailers{{"x-trailer", "1"}};
  EXPECT_EQ(filter_->decodeTrailers(trailers), Http::FilterTrailersStatus::Continue);
  drain();

  EXPECT_EQ(inject_calls_, 0);
  EXPECT_EQ(continue_calls_, 0);
}

// A malformed payload there is forwarded untouched -- nothing is looking at it.
TEST_F(AiProtocolManagerFilterTest, PassesThroughMalformedPayloadOnUndeclaredRoute) {
  Http::TestRequestHeaderMapImpl headers = requestHeaders();
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);

  Buffer::OwnedImpl body(R"({"model" "gpt-4"})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::Continue);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(inject_calls_, 0);
}

// Best-effort parsing runs on an undeclared route and leaves a valid payload
// untouched.
TEST_F(AiProtocolManagerFilterTest, BestEffortParsingAcceptsValidPayload) {
  createFilter(/*parse_unconfigured_routes=*/true);
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"gpt-4"})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(injected_.toString(), R"({"model":"gpt-4"})");
  // An unconfigured route has no schema to check, but the document is still
  // there for later filters, so it counts as parsed.
  EXPECT_EQ(counterValue("request_parsed"), 1);
  EXPECT_EQ(counterValue("request_passthrough"), 0);
}

// Best effort means exactly that: a payload that does not parse is forwarded
// unchanged rather than rejected.
TEST_F(AiProtocolManagerFilterTest, BestEffortParsingForwardsMalformedPayload) {
  createFilter(/*parse_unconfigured_routes=*/true);
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model" "gpt-4"})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(injected_.toString(), R"({"model" "gpt-4"})");
  EXPECT_TRUE(injected_end_stream_);
  // Forwarded, not failed -- so it is counted apart from the rejecting paths.
  EXPECT_EQ(counterValue("request_passthrough"), 1);
  EXPECT_EQ(counterValue("request_parse_error"), 0);
  EXPECT_EQ(counterValue("request_parsed"), 0);
}

// A payload abandoned mid-upload is still offloaded and replayed in full.
TEST_F(AiProtocolManagerFilterTest, BestEffortParsingForwardsRestOfAbandonedPayload) {
  createFilter(/*parse_unconfigured_routes=*/true);
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl chunk1(R"({"model" "gpt-4",)");
  EXPECT_EQ(filter_->decodeData(chunk1, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Buffer::OwnedImpl chunk2(R"("stream":true})");
  EXPECT_EQ(filter_->decodeData(chunk2, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(injected_.toString(), R"({"model" "gpt-4","stream":true})");
}

// Best effort also tolerates an empty body, where a declared endpoint rejects it.
TEST_F(AiProtocolManagerFilterTest, BestEffortParsingForwardsEmptyBody) {
  createFilter(/*parse_unconfigured_routes=*/true);
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl empty;
  EXPECT_EQ(filter_->decodeData(empty, true), Http::FilterDataStatus::StopIterationNoBuffer);
  ASSERT_TRUE(replay_cb_->enabled());
  replay_cb_->invokeCallback();
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_TRUE(injected_end_stream_);
  EXPECT_EQ(injected_.length(), 0);
}

// The one shape best effort can hold: the whole request arrives before a response
// is wanted, so pinning the headers cannot stall it.
TEST_F(AiProtocolManagerFilterTest, BestEffortEngagesOnJsonContentType) {
  EXPECT_EQ(decodeHeadersUnconfigured(Http::TestRequestHeaderMapImpl{
                {":method", "POST"}, {":path", "/v1/chat"}, {"content-type", "application/json"}}),
            Http::FilterHeadersStatus::StopIteration);
}

// Media type parameters are not part of the type, and the type is case-insensitive.
TEST_F(AiProtocolManagerFilterTest, BestEffortEngagesOnJsonContentTypeWithParameters) {
  EXPECT_EQ(decodeHeadersUnconfigured(Http::TestRequestHeaderMapImpl{
                {":method", "POST"},
                {":path", "/v1/chat"},
                {"content-type", "Application/JSON; charset=utf-8"}}),
            Http::FilterHeadersStatus::StopIteration);
}

// A "+json" structured suffix names a JSON payload just as "application/json" does.
TEST_F(AiProtocolManagerFilterTest, BestEffortEngagesOnJsonStructuredSuffix) {
  EXPECT_EQ(decodeHeadersUnconfigured(
                Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                               {":path", "/v1/chat"},
                                               {"content-type", "application/vnd.openai+json"}}),
            Http::FilterHeadersStatus::StopIteration);
}

// The stall this gate exists for. The content type carries a JSON suffix, so
// only the protocol check catches it.
TEST_F(AiProtocolManagerFilterTest, BestEffortSkipsGrpcRequest) {
  EXPECT_EQ(decodeHeadersUnconfigured(
                Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                               {":path", "/Chat/Complete"},
                                               {"content-type", "application/grpc+json"}}),
            Http::FilterHeadersStatus::Continue);
}

// Connect's streaming framing carries a JSON suffix too. (Unary Connect sends
// plain "application/json" and stays eligible.)
TEST_F(AiProtocolManagerFilterTest, BestEffortSkipsConnectStreamingRequest) {
  EXPECT_EQ(decodeHeadersUnconfigured(
                Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                               {":path", "/Chat/Complete"},
                                               {"content-type", "application/connect+json"}}),
            Http::FilterHeadersStatus::Continue);
}

// An upgraded connection is full-duplex whatever content type it carries.
TEST_F(AiProtocolManagerFilterTest, BestEffortSkipsUpgrade) {
  EXPECT_EQ(decodeHeadersUnconfigured(
                Http::TestRequestHeaderMapImpl{{":method", "GET"},
                                               {":path", "/ws"},
                                               {"content-type", "application/json"},
                                               {"connection", "keep-alive, Upgrade"},
                                               {"upgrade", "websocket"}}),
            Http::FilterHeadersStatus::Continue);
}

// So is a CONNECT tunnel, extended or not.
TEST_F(AiProtocolManagerFilterTest, BestEffortSkipsConnect) {
  EXPECT_EQ(decodeHeadersUnconfigured(Http::TestRequestHeaderMapImpl{
                {":method", "CONNECT"}, {":path", "/"}, {"content-type", "application/json"}}),
            Http::FilterHeadersStatus::Continue);
}

// A body the parser could make nothing of is not worth holding the headers for.
TEST_F(AiProtocolManagerFilterTest, BestEffortSkipsNonJsonContentType) {
  EXPECT_EQ(
      decodeHeadersUnconfigured(Http::TestRequestHeaderMapImpl{
          {":method", "POST"}, {":path", "/upload"}, {"content-type", "application/octet-stream"}}),
      Http::FilterHeadersStatus::Continue);
}

// An absent content type says nothing about the payload, so best effort declines it.
TEST_F(AiProtocolManagerFilterTest, BestEffortSkipsMissingContentType) {
  EXPECT_EQ(decodeHeadersUnconfigured(
                Http::TestRequestHeaderMapImpl{{":method", "POST"}, {":path", "/upload"}}),
            Http::FilterHeadersStatus::Continue);
}

// The gate belongs to best effort alone; a declared endpoint is managed whatever
// the content type says.
TEST_F(AiProtocolManagerFilterTest, DeclaredEndpointIgnoresGate) {
  setRouteConfig();
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"}, {":path", "/chat/completions"}, {"content-type", "text/plain"}};
  EXPECT_EQ(filter_->decodeHeaders(headers, /*end_stream=*/false),
            Http::FilterHeadersStatus::StopIteration);
}

// A declared endpoint is strict regardless of the filter-level
// parse_unconfigured_routes setting: the request declaration is what says
// this payload has to be well formed.
TEST_F(AiProtocolManagerFilterTest, RouteConfigIsStrictEvenWithBestEffortConfigured) {
  createFilter(/*parse_unconfigured_routes=*/true);
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model" "gpt-4"})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 1);
  EXPECT_EQ(local_reply_code_, Http::Code::BadRequest);
  EXPECT_EQ(inject_calls_, 0);
}

// A declared endpoint's valid payload is parsed and forwarded unchanged.
TEST_F(AiProtocolManagerFilterTest, PassThroughEndpointIsParsedAndForwarded) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  EXPECT_EQ(
      nlohmann::json::parse(injected_.toString()),
      nlohmann::json::parse(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})"));
}

TEST_F(AiProtocolManagerFilterTest, SetsFilterStateObjectOnParsedPayload) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(local_reply_calls_, 0);
  auto* fs = callbacks_.stream_info_.filterState()->getDataReadOnly<APMRequestPayloadIndex>(
      APMRequestPayloadIndex::kFilterStateKey);
  ASSERT_NE(fs, nullptr);
  EXPECT_EQ(fs->index().json()["model"], "gpt-4");
}

// Trailers arriving after a stream was rejected are dropped with StopIteration.
TEST_F(AiProtocolManagerFilterTest, TrailersDroppedAfterPayloadRejection) {
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  // Send malformed payload chunk that fails the stream.
  Buffer::OwnedImpl bad_chunk(R"({"model" "gpt-4"})");
  EXPECT_EQ(filter_->decodeData(bad_chunk, false), Http::FilterDataStatus::StopIterationNoBuffer);

  // Send trailers on the dying stream.
  Http::TestRequestTrailerMapImpl trailers;
  EXPECT_EQ(filter_->decodeTrailers(trailers), Http::FilterTrailersStatus::StopIteration);
}

class SseTaggingAiFilter : public AiFilter {
public:
  explicit SseTaggingAiFilter(std::string tag, bool fail = false)
      : tag_(std::move(tag)), fail_(fail) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr request, co_await std::move(receive_request)());
    co_return co_await std::move(propagate_request)(std::move(request));
  }

  Coroutine::Task<absl::Status> encodeSSE(SseStreamReceiver receive_event,
                                          SseStreamPropagator propagate_event) override {
    while (true) {
      ASSIGN_OR_CO_RETURN(auto event, co_await receive_event());
      if (!event.has_value()) {
        co_return absl::OkStatus();
      }
      if (fail_) {
        co_return absl::InternalError("sse filter error");
      }
      if ((*event)->is_json()) {
        (*event)->json().json()[tag_] = true;
      }
      CO_RETURN_IF_ERROR(co_await propagate_event(std::move(*event)));
    }
  }

private:
  std::string tag_;
  bool fail_;
};

TEST_F(AiProtocolManagerFilterTest, RunsConfiguredAiFiltersOverSseResponse) {
  createFilterWithAiFilters({[](const AiFilterContext&) -> AiFilterSharedPtr {
                               return std::make_shared<SseTaggingAiFilter>("first");
                             },
                             [](const AiFilterContext&) -> AiFilterSharedPtr {
                               return std::make_shared<SseTaggingAiFilter>("second");
                             }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl req_body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(req_body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();
  ASSERT_TRUE(injected_end_stream_);

  Http::TestResponseHeaderMapImpl resp_headers{
      {":status", "200"}, {"content-type", "text/event-stream"}, {"content-length", "100"}};
  EXPECT_EQ(filter_->encodeHeaders(resp_headers, false), Http::FilterHeadersStatus::Continue);
  EXPECT_TRUE(resp_headers.getContentLengthValue().empty());

  Buffer::OwnedImpl sse_chunk("data: {\"a\":1}\n\ndata: [DONE]\n\n");
  EXPECT_EQ(filter_->encodeData(sse_chunk, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(encode_local_reply_calls_, 0);
  EXPECT_TRUE(encoded_injected_end_stream_);
  EXPECT_EQ(encoded_injected_.toString(),
            "data: {\"a\":1,\"first\":true,\"second\":true}\n\ndata: [DONE]\n\n");
}

TEST_F(AiProtocolManagerFilterTest, SseResponseEndedByTrailersContinuesEncoding) {
  createFilterWithAiFilters({[](const AiFilterContext&) -> AiFilterSharedPtr {
    return std::make_shared<SseTaggingAiFilter>("tagged");
  }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl req_body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(req_body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();
  ASSERT_TRUE(injected_end_stream_);

  Http::TestResponseHeaderMapImpl resp_headers{{":status", "200"},
                                               {"content-type", "text/event-stream"}};
  EXPECT_EQ(filter_->encodeHeaders(resp_headers, false), Http::FilterHeadersStatus::Continue);

  Buffer::OwnedImpl sse_chunk("data: {\"a\":1}\n\n");
  EXPECT_EQ(filter_->encodeData(sse_chunk, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Http::TestResponseTrailerMapImpl resp_trailers{{"x-trailer", "1"}};
  EXPECT_EQ(filter_->encodeTrailers(resp_trailers), Http::FilterTrailersStatus::StopIteration);
  drain();

  EXPECT_EQ(encode_local_reply_calls_, 0);
  EXPECT_EQ(encode_continue_calls_, 1);
  EXPECT_EQ(encoded_injected_.toString(), "data: {\"a\":1,\"tagged\":true}\n\n");
}

TEST_F(AiProtocolManagerFilterTest, SseResponseFilterErrorSendsBadGatewayLocalReply) {
  createFilterWithAiFilters({[](const AiFilterContext&) -> AiFilterSharedPtr {
    return std::make_shared<SseTaggingAiFilter>("tagged", /*fail=*/true);
  }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl req_body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(req_body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();
  ASSERT_TRUE(injected_end_stream_);

  Http::TestResponseHeaderMapImpl resp_headers{{":status", "200"},
                                               {"content-type", "text/event-stream"}};
  EXPECT_EQ(filter_->encodeHeaders(resp_headers, false), Http::FilterHeadersStatus::Continue);

  Buffer::OwnedImpl sse_chunk("data: {\"a\":1}\n\n");
  EXPECT_EQ(filter_->encodeData(sse_chunk, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(encode_local_reply_calls_, 1);
  EXPECT_EQ(encode_local_reply_code_, Http::Code::BadGateway);
}

class UnaryTaggingAiFilter : public AiFilter {
public:
  explicit UnaryTaggingAiFilter(std::string tag, std::vector<std::string>* order = nullptr,
                                bool fail = false)
      : tag_(std::move(tag)), order_(order), fail_(fail) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr request, co_await std::move(receive_request)());
    co_return co_await std::move(propagate_request)(std::move(request));
  }

  Coroutine::Task<absl::Status> encodeUnary(AiResponseStreamReceiver receive,
                                            AiResponseStreamPropagator propagate) override {
    if (order_ != nullptr) {
      order_->push_back(tag_);
    }
    while (true) {
      ASSIGN_OR_CO_RETURN(std::vector<FlattenJsonField> fields, co_await receive());
      if (fields.empty()) {
        break;
      }
      if (fail_) {
        co_return absl::InternalError("unary filter error");
      }
      CO_RETURN_IF_ERROR(co_await propagate(std::move(fields)));
    }
    std::vector<FlattenJsonField> tag_batch;
    tag_batch.emplace_back(std::vector<FieldPathSegment>{tag_}, nlohmann::json(true));
    CO_RETURN_IF_ERROR(co_await propagate(std::move(tag_batch)));
    co_return absl::OkStatus();
  }

private:
  std::string tag_;
  std::vector<std::string>* order_;
  bool fail_;
};

TEST_F(AiProtocolManagerFilterTest, RunsConfiguredAiFiltersOverUnaryJsonResponse) {
  std::vector<std::string> encode_order;
  createFilterWithAiFilters(
      {[&](const AiFilterContext&) -> AiFilterSharedPtr {
         return std::make_shared<UnaryTaggingAiFilter>("first", &encode_order);
       },
       [&](const AiFilterContext&) -> AiFilterSharedPtr {
         return std::make_shared<UnaryTaggingAiFilter>("second", &encode_order);
       }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl req_body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(req_body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();
  ASSERT_TRUE(injected_end_stream_);

  Http::TestResponseHeaderMapImpl resp_headers{
      {":status", "200"}, {"content-type", "application/json"}, {"content-length", "100"}};
  EXPECT_EQ(filter_->encodeHeaders(resp_headers, false), Http::FilterHeadersStatus::Continue);
  EXPECT_TRUE(resp_headers.getContentLengthValue().empty());

  Buffer::OwnedImpl json_chunk(R"({"id":"chatcmpl-1","a":1})");
  EXPECT_EQ(filter_->encodeData(json_chunk, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(encode_local_reply_calls_, 0);
  EXPECT_TRUE(encoded_injected_end_stream_);
  // Filters run in reverse order on the response path: "second" (N-1) before "first" (0).
  EXPECT_EQ(encode_order, (std::vector<std::string>{"second", "first"}));
  EXPECT_EQ(encoded_injected_.toString(),
            R"({"id":"chatcmpl-1","a":1,"second":true,"first":true})");
}

TEST_F(AiProtocolManagerFilterTest, UnaryJsonResponseEndedByTrailersContinuesEncoding) {
  createFilterWithAiFilters({[](const AiFilterContext&) -> AiFilterSharedPtr {
    return std::make_shared<UnaryTaggingAiFilter>("tagged");
  }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl req_body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(req_body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();
  ASSERT_TRUE(injected_end_stream_);

  Http::TestResponseHeaderMapImpl resp_headers{{":status", "200"},
                                               {"content-type", "application/json"}};
  EXPECT_EQ(filter_->encodeHeaders(resp_headers, false), Http::FilterHeadersStatus::Continue);

  Buffer::OwnedImpl json_chunk(R"({"a":1})");
  EXPECT_EQ(filter_->encodeData(json_chunk, false), Http::FilterDataStatus::StopIterationNoBuffer);
  Http::TestResponseTrailerMapImpl resp_trailers{{"x-trailer", "1"}};
  EXPECT_EQ(filter_->encodeTrailers(resp_trailers), Http::FilterTrailersStatus::StopIteration);
  drain();

  EXPECT_EQ(encode_local_reply_calls_, 0);
  EXPECT_EQ(encode_continue_calls_, 1);
  EXPECT_EQ(encoded_injected_.toString(), R"({"a":1,"tagged":true})");
}

TEST_F(AiProtocolManagerFilterTest, UnaryJsonResponseFilterErrorSendsBadGatewayLocalReply) {
  createFilterWithAiFilters({[](const AiFilterContext&) -> AiFilterSharedPtr {
    return std::make_shared<UnaryTaggingAiFilter>("tagged", /*order=*/nullptr, /*fail=*/true);
  }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl req_body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(req_body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();
  ASSERT_TRUE(injected_end_stream_);

  Http::TestResponseHeaderMapImpl resp_headers{{":status", "200"},
                                               {"content-type", "application/json"}};
  EXPECT_EQ(filter_->encodeHeaders(resp_headers, false), Http::FilterHeadersStatus::Continue);

  Buffer::OwnedImpl json_chunk(R"({"a":1})");
  EXPECT_EQ(filter_->encodeData(json_chunk, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(encode_local_reply_calls_, 1);
  EXPECT_EQ(encode_local_reply_code_, Http::Code::BadGateway);
}

TEST_F(AiProtocolManagerFilterTest, UnaryJsonResponseEngagesOnStructuredSuffixAndSkipsFramedRpc) {
  createFilterWithAiFilters({[](const AiFilterContext&) -> AiFilterSharedPtr {
    return std::make_shared<UnaryTaggingAiFilter>("tagged");
  }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl req_body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(req_body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();
  ASSERT_TRUE(injected_end_stream_);

  // Framed RPC responses (`application/grpc+json`, `application/connect+json`) carry a 5-byte
  // binary envelope and must pass through without starting the unary JSON pipeline.
  Http::TestResponseHeaderMapImpl grpc_json_headers{
      {":status", "200"}, {"content-type", "application/grpc+json"}, {"content-length", "50"}};
  EXPECT_EQ(filter_->encodeHeaders(grpc_json_headers, false), Http::FilterHeadersStatus::Continue);
  EXPECT_EQ(grpc_json_headers.getContentLengthValue(), "50");

  Http::TestResponseHeaderMapImpl connect_json_headers{
      {":status", "200"}, {"content-type", "application/connect+json"}, {"content-length", "50"}};
  EXPECT_EQ(filter_->encodeHeaders(connect_json_headers, false),
            Http::FilterHeadersStatus::Continue);
  EXPECT_EQ(connect_json_headers.getContentLengthValue(), "50");

  // A structured `+json` response suffix engages unary JSON filtering.
  Http::TestResponseHeaderMapImpl vendor_json_headers{
      {":status", "200"},
      {"content-type", "application/vnd.openai+json"},
      {"content-length", "50"}};
  EXPECT_EQ(filter_->encodeHeaders(vendor_json_headers, false),
            Http::FilterHeadersStatus::Continue);
  EXPECT_TRUE(vendor_json_headers.getContentLengthValue().empty());

  Buffer::OwnedImpl json_chunk(R"({"a":1})");
  EXPECT_EQ(filter_->encodeData(json_chunk, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(encoded_injected_.toString(), R"({"a":1,"tagged":true})");
}

// Content-Encoding is list-valued and repeatable: a non-identity coding anywhere keeps the
// response away from the AI filters, and only a response they would otherwise see counts it.
TEST_F(AiProtocolManagerFilterTest, EncodedResponseSkipsResponseFilters) {
  createFilterWithAiFilters({[](const AiFilterContext&) -> AiFilterSharedPtr {
    return std::make_shared<UnaryTaggingAiFilter>("tagged");
  }});
  setRouteConfig();
  EXPECT_EQ(decodeHeadersEngaging(), Http::FilterHeadersStatus::StopIteration);

  Buffer::OwnedImpl req_body(R"({"model":"gpt-4","messages":[{"role":"user","content":"hi"}]})");
  EXPECT_EQ(filter_->decodeData(req_body, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();
  ASSERT_TRUE(injected_end_stream_);

  const auto skipped = [this](Http::TestResponseHeaderMapImpl headers) {
    headers.setContentLength(50);
    EXPECT_EQ(filter_->encodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);
    EXPECT_EQ(headers.getContentLengthValue(), "50");
  };
  skipped({{":status", "200"},
           {"content-type", "application/json"},
           {"content-encoding", "identity"},
           {"content-encoding", "gzip"}});
  skipped({{":status", "200"},
           {"content-type", "application/json"},
           {"content-encoding", "identity, gzip"}});
  skipped({{":status", "200"},
           {"content-type", "text/event-stream"},
           {"content-encoding", "identity,,identity"}});
  EXPECT_EQ(counterValue("unsupported_content_encoding"), 3);
  skipped({{":status", "200"}, {"content-type", "text/plain"}, {"content-encoding", "gzip"}});
  EXPECT_EQ(counterValue("unsupported_content_encoding"), 3);

  Http::TestResponseHeaderMapImpl identity_headers{{":status", "200"},
                                                   {"content-type", "application/json"},
                                                   {"content-encoding", " identity , identity "},
                                                   {"content-encoding", "identity"}};
  EXPECT_EQ(filter_->encodeHeaders(identity_headers, false), Http::FilterHeadersStatus::Continue);
  Buffer::OwnedImpl json_chunk(R"({"a":1})");
  EXPECT_EQ(filter_->encodeData(json_chunk, true), Http::FilterDataStatus::StopIterationNoBuffer);
  drain();

  EXPECT_EQ(encoded_injected_.toString(), R"({"a":1,"tagged":true})");
  EXPECT_EQ(counterValue("unsupported_content_encoding"), 3);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
