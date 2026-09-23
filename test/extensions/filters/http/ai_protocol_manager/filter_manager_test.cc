#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/coroutine/async_queue.h"
#include "source/common/coroutine/dispatcher_executor.h"
#include "source/common/coroutine/launch.h"
#include "source/common/coroutine/status_macros.h"
#include "source/common/stream_info/stream_info_impl.h"
#include "source/extensions/common/ai/request_ir.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_filter.h"
#include "source/extensions/filters/http/ai_protocol_manager/ai_request.h"
#include "source/extensions/filters/http/ai_protocol_manager/buffer_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/filter_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf_parser.h"
#include "source/extensions/filters/http/ai_protocol_manager/serializer.h"

#include "test/extensions/filters/http/ai_protocol_manager/fake_bridge.h"
#include "test/test_common/status_utility.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

using ::Envoy::StatusHelpers::HasStatusCode;

class FilterManagerTest : public testing::Test {
public:
  FilterManagerTest()
      : api_(Api::createApiForTest()), dispatcher_(api_->allocateDispatcher("test")), factory_(),
        bridge_(*dispatcher_), buffer_manager_(BufferManager::Config{}, factory_, bridge_),
        stream_info_(api_->timeSource(), nullptr, StreamInfo::FilterState::LifeSpan::FilterChain) {}

  void drain() {
    for (int i = 0; i < 20; ++i) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }
  }

  // Stores `body` as the received request, as the filter does, and returns its parsed index.
  JsonWithExtBuf receive(absl::string_view body,
                         uint32_t inline_string_threshold_bytes =
                             JsonWithExtBufParser::kDefaultInlineStringThresholdBytes) {
    Buffer::OwnedImpl data(body);
    buffer_manager_.onData(data);
    buffer_manager_.endStream();
    JsonWithExtBufParser parser(JsonWithExtBufParser::Config{inline_string_threshold_bytes});
    EXPECT_OK(parser.feed(body, /*end_stream=*/true));
    return parser.takeDocument();
  }

  const APMRequestPayloadIndex* publishedIndex() {
    return stream_info_.filterState()->getDataReadOnly<APMRequestPayloadIndex>(
        APMRequestPayloadIndex::kFilterStateKey);
  }

  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;
  InMemoryExternalBufferFactory factory_;
  // Declared before buffer_manager_ so it outlives the manager that references it.
  FakeBridge bridge_;
  BufferManager buffer_manager_;
  StreamInfo::StreamInfoImpl stream_info_;
};

class TestMutationFilter : public AiFilter {
public:
  explicit TestMutationFilter(std::string target_model) : target_model_(std::move(target_model)) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    req->mutableJson()["model"] = target_model_;
    co_return co_await std::move(propagate_request)(std::move(req));
  }

private:
  std::string target_model_;
};

// Attaches an IR, as the transcoder's internal leg does.
class TestIrAttachingFilter : public AiFilter {
public:
  explicit TestIrAttachingFilter(std::string model) : model_(std::move(model)) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    req->setIr(std::make_shared<RequestIr>(LLMProtocol::OpenAiChatCompletions, model_, std::nullopt,
                                           std::nullopt));
    co_return co_await std::move(propagate_request)(std::move(req));
  }

private:
  const std::string model_;
};

class FilterManagerSinkOptionsTest : public FilterManagerTest {
protected:
  // Runs `filters` over `body` and returns what was forwarded.
  std::string run(std::vector<AiFilterSharedPtr> filters, RequestFilterManager::SinkOptions options,
                  absl::string_view body = R"({ "model" : "gpt-4" })") {
    FilterManager manager(std::move(filters));
    headers_ = Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                              {":path", "/v1/chat/completions"},
                                              {"content-length", absl::StrCat(body.size())}};
    absl::Status status = absl::UnknownError("never completed");
    manager.startRequest(
        receive(body), &buffer_manager_, *dispatcher_, stream_info_,
        [&status](absl::Status s) { status = std::move(s); }, &headers_, nullptr, options);
    drain();
    EXPECT_OK(status);
    return bridge_.injected_.toString();
  }

  const RequestIr* publishedIr() {
    return stream_info_.filterState()->getDataReadOnly<RequestIr>(RequestIr::FilterStateKey);
  }

  static std::vector<AiFilterSharedPtr> attaching(std::string model) {
    return {std::make_shared<TestIrAttachingFilter>(std::move(model))};
  }

  Http::TestRequestHeaderMapImpl headers_;
};

TEST_F(FilterManagerSinkOptionsTest, PublishesTheAttachedIrWhenConfigured) {
  run(attaching("m1"), {.publish_request_ir = true});
  ASSERT_NE(publishedIr(), nullptr);
  EXPECT_EQ(publishedIr()->model(), "m1");
}

TEST_F(FilterManagerSinkOptionsTest, DoesNotPublishUnlessConfigured) {
  run(attaching("m1"), {.publish_request_ir = false});
  EXPECT_EQ(publishedIr(), nullptr);
}

TEST_F(FilterManagerSinkOptionsTest, HasNothingToPublishWithoutAnIr) {
  run({}, {.publish_request_ir = true});
  EXPECT_EQ(publishedIr(), nullptr);
}

TEST_F(FilterManagerSinkOptionsTest, KeepsAnEarlierPublication) {
  stream_info_.filterState()->setData(RequestIr::FilterStateKey,
                                      std::make_shared<RequestIr>(LLMProtocol::AnthropicMessages,
                                                                  "first", std::nullopt,
                                                                  std::nullopt),
                                      StreamInfo::FilterState::LifeSpan::FilterChain);
  run(attaching("second"), {.publish_request_ir = true});
  EXPECT_EQ(publishedIr()->model(), "first");
}

TEST_F(FilterManagerSinkOptionsTest, AnEditAfterTheIrDropsIt) {
  std::vector<AiFilterSharedPtr> filters = attaching("m1");
  filters.push_back(std::make_shared<TestMutationFilter>("gpt-5"));
  run(std::move(filters), {.publish_request_ir = true});
  EXPECT_EQ(publishedIr(), nullptr);
}

TEST_F(FilterManagerSinkOptionsTest, ForwardsTheReceivedBodyByDefault) {
  const std::string body = R"({ "model" : "gpt-4" })";
  EXPECT_EQ(run({}, {}, body), body);
}

TEST_F(FilterManagerSinkOptionsTest, AlwaysSerializeRewritesAnUnmodifiedBody) {
  const std::string forwarded = run({}, {.always_serialize = true}, R"({ "model" : "gpt-4" })");
  EXPECT_EQ(forwarded, R"({"model":"gpt-4"})");
  EXPECT_EQ(headers_.getContentLengthValue(), absl::StrCat(forwarded.size()));
}

// 0-filter pass-through
TEST_F(FilterManagerTest, ZeroFilterPassThrough) {
  const std::string body = R"({ "model": "gpt-4" })";

  std::vector<AiFilterSharedPtr> filters;
  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;

  manager.startRequest(receive(body), &buffer_manager_, *dispatcher_, stream_info_,
                       [&status, &completed](absl::Status s) {
                         status = std::move(s);
                         completed = true;
                       });

  drain();
  EXPECT_TRUE(completed);
  ASSERT_OK(status);

  EXPECT_EQ(bridge_.injected_.toString(), body);

  auto* fs = publishedIndex();
  ASSERT_NE(fs, nullptr);
  EXPECT_EQ(fs->index().json()["model"], "gpt-4");
}

class TestReadOnlyFilter : public AiFilter {
public:
  explicit TestReadOnlyFilter(std::string& seen_model) : seen_model_(seen_model) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    seen_model_ = req->json().value("model", "");
    co_return co_await std::move(propagate_request)(std::move(req));
  }

private:
  std::string& seen_model_;
};

// Whitespace, key order and escapes that any re-serialization would normalize, around a value
// large enough to be offloaded.
std::string unnormalizedBody(const std::string& content) {
  return absl::StrCat("{\n  \"stream\" : false,\n  \"model\":\"gpt-4\",\n",
                      "  \"messages\": [ { \"role\": \"user\", \"content\": \"", content,
                      "\" } ],\n  \"note\": \"caf\\u00e9\"\n}\n");
}

TEST_F(FilterManagerTest, UnmodifiedRequestIsForwardedAsReceived) {
  const std::string content(64, 'c');
  const std::string body = unnormalizedBody(content);
  ASSERT_NE(body, nlohmann::json::parse(body).dump());

  std::string seen_model;
  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_shared<TestReadOnlyFilter>(seen_model));
  FilterManager manager(std::move(filters));

  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/v1/chat/completions"},
                                         {"content-length", absl::StrCat(body.size())}};
  absl::Status status;
  bool completed = false;
  manager.startRequest(
      receive(body, /*inline_string_threshold_bytes=*/16), &buffer_manager_, *dispatcher_,
      stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      &headers);
  drain();

  EXPECT_TRUE(completed);
  ASSERT_OK(status);
  EXPECT_EQ(seen_model, "gpt-4");
  const std::string output = bridge_.injected_.toString();
  EXPECT_EQ(output, body);
  EXPECT_EQ(headers.getContentLengthValue(), absl::StrCat(body.size()));

  // The published index is the request's own: its reference locates the value in these bytes.
  const APMRequestPayloadIndex* published = publishedIndex();
  ASSERT_NE(published, nullptr);
  const nlohmann::json& index = published->index().json();
  EXPECT_EQ(index.value("model", ""), "gpt-4");
  ASSERT_TRUE(index.contains("messages"));
  const nlohmann::json& message = index.at("messages").at(0);
  ASSERT_TRUE(JsonWithExtBuf::isExternalRef(message.at("content")));
  const absl::StatusOr<JsonWithExtBuf::ExternalRef> ref =
      JsonWithExtBuf::externalRef(message.at("content"));
  ASSERT_OK(ref);
  EXPECT_EQ(output.substr(ref->offset, ref->length), content);
}

TEST_F(FilterManagerTest, ModifiedRequestIsSerializedWithUpdatedContentLength) {
  const std::string content(64, 'c');
  const std::string body = unnormalizedBody(content);

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_shared<TestMutationFilter>("gpt-4o"));
  FilterManager manager(std::move(filters));

  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/v1/chat/completions"},
                                         {"content-length", absl::StrCat(body.size())}};
  absl::Status status;
  bool completed = false;
  manager.startRequest(
      receive(body, /*inline_string_threshold_bytes=*/16), &buffer_manager_, *dispatcher_,
      stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      &headers);
  drain();

  EXPECT_TRUE(completed);
  ASSERT_OK(status);
  nlohmann::json expected = nlohmann::json::parse(body);
  expected["model"] = "gpt-4o";
  const std::string output = bridge_.injected_.toString();
  EXPECT_EQ(output, expected.dump());
  EXPECT_EQ(headers.getContentLengthValue(), absl::StrCat(output.size()));

  // The published index is re-based onto the serialized output.
  const APMRequestPayloadIndex* published = publishedIndex();
  ASSERT_NE(published, nullptr);
  const nlohmann::json& message = published->index().json().at("messages").at(0);
  const absl::StatusOr<JsonWithExtBuf::ExternalRef> ref =
      JsonWithExtBuf::externalRef(message.at("content"));
  ASSERT_OK(ref);
  EXPECT_EQ(output.substr(ref->offset, ref->length), content);
}

// Replaces the request with one it builds instead of editing the one it received.
class TestRequestBuildingFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr received, co_await std::move(receive_request)());
    JsonWithExtBuf index;
    index.setJson(nlohmann::json{{"model", "built"}});
    auto built = std::make_unique<AiRequest>(std::move(index));
    built->headerEdits() = received->headerEdits();
    co_return co_await std::move(propagate_request)(std::move(built));
  }
};

TEST_F(FilterManagerTest, RequestBuiltByAFilterIsSerialized) {
  const std::string body = unnormalizedBody("hi");

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_shared<TestRequestBuildingFilter>());
  FilterManager manager(std::move(filters));

  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/v1/chat/completions"},
                                         {"content-length", absl::StrCat(body.size())}};
  absl::Status status;
  bool completed = false;
  manager.startRequest(
      receive(body), &buffer_manager_, *dispatcher_, stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      &headers);
  drain();

  EXPECT_TRUE(completed);
  ASSERT_OK(status);
  EXPECT_EQ(bridge_.injected_.toString(), R"({"model":"built"})");
  EXPECT_EQ(headers.getContentLengthValue(), absl::StrCat(bridge_.injected_.length()));
}

TEST_F(FilterManagerTest, MissingBufferManagerFailsTheRequest) {
  std::vector<AiFilterSharedPtr> filters;
  FilterManager manager(std::move(filters));

  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});
  absl::Status status;
  bool completed = false;
  manager.startRequest(std::move(doc), /*buffer_manager=*/nullptr, *dispatcher_, stream_info_,
                       [&status, &completed](absl::Status s) {
                         status = std::move(s);
                         completed = true;
                       });
  drain();

  EXPECT_TRUE(completed);
  EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kInvalidArgument));
}

TEST_F(FilterManagerTest, CancelStopsForwardingTheReceivedBody) {
  std::vector<AiFilterSharedPtr> filters;
  auto manager = std::make_unique<FilterManager>(std::move(filters));
  bool completed = false;
  manager->startRequest(receive(R"({"model":"gpt-4"})"), &buffer_manager_, *dispatcher_,
                        stream_info_, [&completed](absl::Status) { completed = true; });

  manager->cancel();
  drain();

  EXPECT_FALSE(completed);
  EXPECT_EQ(bridge_.injected_.length(), 0);
}

TEST_F(FilterManagerTest, SingleFilterMutation) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-3.5"}});

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestMutationFilter>("gpt-4-turbo"));

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                       [&status, &completed](absl::Status s) {
                         status = std::move(s);
                         completed = true;
                       });

  drain();
  EXPECT_TRUE(completed);
  ASSERT_OK(status);

  auto parsed = nlohmann::json::parse(bridge_.injected_.toString());
  EXPECT_EQ(parsed["model"], "gpt-4-turbo");
}

class TestFieldAdderFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    req->mutableJson()["temperature"] = 0.5;
    co_return co_await std::move(propagate_request)(std::move(req));
  }
};

class TestFieldModifierFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    nlohmann::json& json = req->mutableJson();
    EXPECT_DOUBLE_EQ(json["temperature"].get<double>(), 0.5);
    json["temperature"] = 0.9;
    co_return co_await std::move(propagate_request)(std::move(req));
  }
};

TEST_F(FilterManagerTest, MultiFilterPipeline) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestFieldAdderFilter>());
  filters.push_back(std::make_unique<TestFieldModifierFilter>());

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                       [&status, &completed](absl::Status s) {
                         status = std::move(s);
                         completed = true;
                       });

  drain();
  EXPECT_TRUE(completed);
  ASSERT_OK(status);

  auto parsed = nlohmann::json::parse(bridge_.injected_.toString());
  EXPECT_EQ(parsed["model"], "gpt-4");
  EXPECT_DOUBLE_EQ(parsed["temperature"].get<double>(), 0.9);
}

class TestErrorFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request, AiRequestPropagator,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    co_return absl::InternalError("intentional filter error");
  }
};

TEST_F(FilterManagerTest, FilterErrorPropagation) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestErrorFilter>());

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                       [&status, &completed](absl::Status s) {
                         status = std::move(s);
                         completed = true;
                       });

  drain();
  EXPECT_TRUE(completed);
  EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kInternal));
}

class TestBypassFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver, AiRequestPropagator,
                                       LocalReplier) override {
    // Early returns without calling receive_request or propagate_request or reply_locally
    co_return absl::OkStatus();
  }
};

TEST_F(FilterManagerTest, FilterBypassEarlyReturnPassesThrough) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-3.5"}});

  std::vector<AiFilterSharedPtr> filters;
  // Filter 0 bypasses itself
  filters.push_back(std::make_unique<TestBypassFilter>());
  // Filter 1 still receives and modifies the request
  filters.push_back(std::make_unique<TestMutationFilter>("gpt-4-turbo"));

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                       [&status, &completed](absl::Status s) {
                         status = std::move(s);
                         completed = true;
                       });

  drain();
  EXPECT_TRUE(completed);
  ASSERT_OK(status);

  auto parsed = nlohmann::json::parse(bridge_.injected_.toString());
  EXPECT_EQ(parsed["model"], "gpt-4-turbo");
}

class TestDropFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request, AiRequestPropagator,
                                       LocalReplier) override {
    // Receives request but never propagates or sends local reply
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    co_return absl::OkStatus();
  }
};

TEST_F(FilterManagerTest, FilterConsumedWithoutPropagationFails) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestDropFilter>());

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                       [&status, &completed](absl::Status s) {
                         status = std::move(s);
                         completed = true;
                       });

  drain();
  EXPECT_TRUE(completed);
  EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kInternal));
}

class TestLocalReplyFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request, AiRequestPropagator,
                                       LocalReplier reply_locally) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    std::move(reply_locally)(Http::Code::Unauthorized, "access denied by auth filter");
    co_return absl::OkStatus();
  }
};

TEST_F(FilterManagerTest, FilterLocalReply) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  Http::Code local_reply_code = Http::Code::OK;
  std::string local_reply_details;

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestLocalReplyFilter>());

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(
      std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      /*request_headers=*/nullptr,
      [&local_reply_code, &local_reply_details](Http::Code code, std::string details) {
        local_reply_code = code;
        local_reply_details = std::move(details);
      });

  drain();
  EXPECT_TRUE(completed);
  EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kCancelled));
  EXPECT_EQ(local_reply_code, Http::Code::Unauthorized);
  EXPECT_EQ(local_reply_details, "access denied by auth filter");
}

TEST_F(FilterManagerTest, FilterErrorTriggersLocalReply) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  Http::Code local_reply_code = Http::Code::OK;
  std::string local_reply_details;

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestErrorFilter>());

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(
      std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      /*request_headers=*/nullptr,
      [&local_reply_code, &local_reply_details](Http::Code code, std::string details) {
        local_reply_code = code;
        local_reply_details = std::move(details);
      });

  drain();
  EXPECT_TRUE(completed);
  EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kInternal));
  EXPECT_EQ(local_reply_code, Http::Code::BadGateway);
  EXPECT_EQ(local_reply_details, "intentional filter error");
}

TEST_F(FilterManagerTest, FilterLocalReplyWithoutLocalReplyFnInvokesCompletionWithCancelled) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestLocalReplyFilter>());

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(
      std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      /*request_headers=*/nullptr, /*local_reply_fn=*/nullptr);

  drain();
  EXPECT_TRUE(completed);
  EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kCancelled));
}

class TestImmediateErrorFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver, AiRequestPropagator,
                                       LocalReplier) override {
    co_return absl::InternalError("synchronous filter startup error");
  }
};

class TestCountingFilter : public AiFilter {
public:
  explicit TestCountingFilter(int& start_count) : start_count_(start_count) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ++start_count_;
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    co_return co_await std::move(propagate_request)(std::move(req));
  }

private:
  int& start_count_;
};

class TestImmediateLocalReplyFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver, AiRequestPropagator,
                                       LocalReplier reply_locally) override {
    std::move(reply_locally)(Http::Code::Unauthorized, "synchronous auth rejection");
    co_return absl::OkStatus();
  }
};

TEST_F(FilterManagerTest, SynchronousFilterErrorStopsSubsequentFilterLaunches) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  int filter2_started = 0;
  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestImmediateErrorFilter>());
  filters.push_back(std::make_unique<TestCountingFilter>(filter2_started));

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                       [&status, &completed](absl::Status s) {
                         status = std::move(s);
                         completed = true;
                       });

  drain();
  EXPECT_TRUE(completed);
  EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kInternal));
  EXPECT_EQ(filter2_started, 0);
}

TEST_F(FilterManagerTest, SynchronousFilterLocalReplyStopsSubsequentFilterLaunches) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  Http::Code local_reply_code = Http::Code::OK;
  std::string local_reply_details;
  int filter2_started = 0;

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestImmediateLocalReplyFilter>());
  filters.push_back(std::make_unique<TestCountingFilter>(filter2_started));

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(
      std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      /*request_headers=*/nullptr,
      [&local_reply_code, &local_reply_details](Http::Code code, std::string details) {
        local_reply_code = code;
        local_reply_details = std::move(details);
      });

  drain();
  EXPECT_TRUE(completed);
  EXPECT_EQ(local_reply_code, Http::Code::Unauthorized);
  EXPECT_EQ(local_reply_details, "synchronous auth rejection");
  EXPECT_EQ(filter2_started, 0);
}

TEST_F(FilterManagerTest, CancelCancelsCoroutines) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestFieldAdderFilter>());

  auto manager = std::make_unique<FilterManager>(std::move(filters));
  manager->startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                        [](absl::Status) {});

  manager->cancel();
  manager.reset();
}

TEST_F(FilterManagerTest, DestructWhileSuspendedIsSafe) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  class SuspendingFilter : public AiFilter {
  public:
    explicit SuspendingFilter(std::shared_ptr<Coroutine::AsyncQueue<bool>> queue)
        : queue_(std::move(queue)) {}

    Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                         AiRequestPropagator propagate_request,
                                         LocalReplier reply_locally) override {
      // Wait on an external suspension point (e.g. async gRPC / queue).
      std::ignore = co_await queue_->pop();

      // Manager is destructed during the above suspension point.
      // Calling receive_request should now safely return CancelledError without UAF.
      auto req_or = co_await std::move(receive_request)();
      EXPECT_THAT(req_or.status(), HasStatusCode(absl::StatusCode::kCancelled));

      // Calling propagate_request should also safely return CancelledError.
      auto status =
          co_await std::move(propagate_request)(std::make_unique<AiRequest>(JsonWithExtBuf()));
      EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kCancelled));

      // Calling reply_locally should safely no-op without crashing.
      std::move(reply_locally)(Http::Code::Unauthorized, "too late");

      co_return absl::OkStatus();
    }

  private:
    std::shared_ptr<Coroutine::AsyncQueue<bool>> queue_;
  };

  auto queue = std::make_shared<Coroutine::AsyncQueue<bool>>(1);
  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<SuspendingFilter>(queue));

  auto manager = std::make_unique<FilterManager>(std::move(filters));

  bool completed = false;
  manager->startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                        [&completed](absl::Status) { completed = true; });
  drain();

  // Destruct the manager while the filter is still suspended in queue_->pop().
  manager.reset();

  // Now resume the suspended filter coroutine.
  queue->tryPush(true);
  drain();
}

TEST_F(FilterManagerTest, InvalidReceiverAndPropagatorInvocation) {
  AiRequestReceiver empty_receiver(nullptr);
  EXPECT_FALSE(empty_receiver.valid());

  AiRequestPropagator empty_propagator(nullptr);
  EXPECT_FALSE(empty_propagator.valid());

  auto executor = std::make_shared<Coroutine::DispatcherExecutor>(*dispatcher_);

  EXPECT_ENVOY_BUG(
      {
        auto test_coro = []() -> Coroutine::Task<absl::Status> {
          AiRequestReceiver r(nullptr);
          std::ignore = co_await std::move(r)();
          co_return absl::OkStatus();
        };
        auto handle =
            Coroutine::launch(test_coro(), executor, [](auto) {}, Coroutine::StartMode::Inline);
      },
      "AiRequestReceiver invoked on an invalid or already moved instance");

  EXPECT_ENVOY_BUG(
      {
        auto test_coro = []() -> Coroutine::Task<absl::Status> {
          AiRequestPropagator p(nullptr);
          std::ignore = co_await std::move(p)(nullptr);
          co_return absl::OkStatus();
        };
        auto handle =
            Coroutine::launch(test_coro(), executor, [](auto) {}, Coroutine::StartMode::Inline);
      },
      "AiRequestPropagator invoked on an invalid or already moved instance");

  EXPECT_ENVOY_BUG(
      {
        auto test_coro = []() -> Coroutine::Task<absl::Status> {
          AiRequestReceiver r2([]() -> Coroutine::Task<absl::StatusOr<AiRequestPtr>> {
            co_return std::make_unique<AiRequest>(JsonWithExtBuf());
          });
          EXPECT_TRUE(r2.valid());
          auto res2 = co_await std::move(r2)();
          EXPECT_TRUE(res2.ok());
          EXPECT_FALSE(r2.valid());
          std::ignore = co_await std::move(r2)();
          co_return absl::OkStatus();
        };
        auto handle =
            Coroutine::launch(test_coro(), executor, [](auto) {}, Coroutine::StartMode::Inline);
      },
      "AiRequestReceiver invoked on an invalid or already moved instance");

  EXPECT_ENVOY_BUG(
      {
        auto test_coro = []() -> Coroutine::Task<absl::Status> {
          AiRequestPropagator p2(
              [](AiRequestPtr) -> Coroutine::Task<absl::Status> { co_return absl::OkStatus(); });
          EXPECT_TRUE(p2.valid());
          auto status2 = co_await std::move(p2)(std::make_unique<AiRequest>(JsonWithExtBuf()));
          EXPECT_TRUE(status2.ok());
          EXPECT_FALSE(p2.valid());
          std::ignore = co_await std::move(p2)(std::make_unique<AiRequest>(JsonWithExtBuf()));
          co_return absl::OkStatus();
        };
        auto handle =
            Coroutine::launch(test_coro(), executor, [](auto) {}, Coroutine::StartMode::Inline);
      },
      "AiRequestPropagator invoked on an invalid or already moved instance");
}

class TestNullPropagatorFilter : public AiFilter {
public:
  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    co_return co_await std::move(propagate_request)(nullptr);
  }
};

TEST_F(FilterManagerTest, FilterNullPropagationFails) {
  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestNullPropagatorFilter>());

  FilterManager manager(std::move(filters));

  EXPECT_ENVOY_BUG(
      {
        absl::Status status;
        bool completed = false;
        manager.startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                             [&status, &completed](absl::Status s) {
                               status = std::move(s);
                               completed = true;
                             });
        drain();
        EXPECT_TRUE(completed);
        EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kInvalidArgument));
      },
      "cannot propagate null AiRequestPtr");
}

TEST_F(FilterManagerTest, SetsContentLengthOnRequestHeadersAfterMutation) {
  Http::TestRequestHeaderMapImpl headers{
      {":method", "POST"}, {":path", "/chat/completions"}, {"content-length", "19"}};

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestMutationFilter>("gpt-4-turbo-extra-long"));

  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(
      receive(R"({"model":"gpt-3.5"})"), &buffer_manager_, *dispatcher_, stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      &headers);

  drain();
  EXPECT_TRUE(completed);
  ASSERT_OK(status);

  std::string output = bridge_.injected_.toString();
  EXPECT_EQ(output, R"({"model":"gpt-4-turbo-extra-long"})");
  EXPECT_EQ(headers.getContentLengthValue(), absl::StrCat(output.size()));
}

TEST_F(FilterManagerTest, DoesNotSetContentLengthWhenNotPreviouslyPresent) {
  Http::TestRequestHeaderMapImpl headers{{":method", "POST"}, {":path", "/chat/completions"}};

  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_unique<TestMutationFilter>("gpt-4-turbo"));
  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(
      receive(R"({"model":"gpt-4"})"), &buffer_manager_, *dispatcher_, stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      &headers);

  drain();
  EXPECT_TRUE(completed);
  ASSERT_OK(status);

  EXPECT_EQ(bridge_.injected_.toString(), R"({"model":"gpt-4-turbo"})");
  EXPECT_EQ(headers.ContentLength(), nullptr);
}

// Stages header edits and optionally modifies the body.
class TestHeaderEditingFilter : public AiFilter {
public:
  TestHeaderEditingFilter(bool modify_body, RequestHeaderEdits edits)
      : modify_body_(modify_body), edits_(std::move(edits)) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    if (modify_body_) {
      req->mutableJson()["model"] = "gpt-4o";
    }
    req->headerEdits() = edits_;
    co_return co_await std::move(propagate_request)(std::move(req));
  }

private:
  const bool modify_body_;
  const RequestHeaderEdits edits_;
};

RequestHeaderEdits providerEdits() {
  RequestHeaderEdits edits;
  edits.path = "/v1/projects/p/locations/global/publishers/google/models/m:generateContent";
  edits.set = {{Http::LowerCaseString("x-provider"), "vertex"}};
  edits.remove = {Http::LowerCaseString("accept-encoding")};
  return edits;
}

class FilterManagerHeaderEditsTest : public FilterManagerTest,
                                     public testing::WithParamInterface<bool> {
public:
  // Runs one TestHeaderEditingFilter and returns the headers as they were when the first body
  // bytes reached the chain, which is what releases them.
  Http::TestRequestHeaderMapImpl run(absl::string_view body, bool modify_body,
                                     RequestHeaderEdits edits) {
    std::vector<AiFilterSharedPtr> filters;
    filters.push_back(std::make_shared<TestHeaderEditingFilter>(modify_body, std::move(edits)));
    FilterManager manager(std::move(filters));

    std::optional<Http::TestRequestHeaderMapImpl> at_first_byte;
    bridge_.on_inject_ = [this, &at_first_byte]() {
      if (!at_first_byte.has_value()) {
        at_first_byte = headers_;
      }
    };
    absl::Status status;
    bool completed = false;
    manager.startRequest(
        receive(body), &buffer_manager_, *dispatcher_, stream_info_,
        [&status, &completed](absl::Status s) {
          status = std::move(s);
          completed = true;
        },
        &headers_);
    drain();
    bridge_.on_inject_ = nullptr;

    EXPECT_TRUE(completed);
    EXPECT_OK(status);
    EXPECT_TRUE(at_first_byte.has_value());
    return at_first_byte.value_or(Http::TestRequestHeaderMapImpl{});
  }

  Http::TestRequestHeaderMapImpl headers_{{":method", "POST"},
                                          {":path", "/v1/chat/completions"},
                                          {"accept-encoding", "gzip, deflate"},
                                          {"x-provider", "stale"},
                                          {"content-length", "19"}};
};

INSTANTIATE_TEST_SUITE_P(BodyModified, FilterManagerHeaderEditsTest, testing::Bool());

TEST_P(FilterManagerHeaderEditsTest, AppliedBeforeTheFirstBodyByte) {
  const bool modify_body = GetParam();
  const std::string body = R"({"model": "gpt-4"})";
  headers_.setContentLength(body.size());

  const Http::TestRequestHeaderMapImpl seen = run(body, modify_body, providerEdits());

  EXPECT_EQ(seen.getPathValue(),
            "/v1/projects/p/locations/global/publishers/google/models/m:generateContent");
  EXPECT_EQ(seen.get_("x-provider"), "vertex");
  EXPECT_FALSE(seen.has("accept-encoding"));
  const std::string output = bridge_.injected_.toString();
  EXPECT_EQ(output, modify_body ? R"({"model":"gpt-4o"})" : body);
  EXPECT_EQ(seen.getContentLengthValue(), absl::StrCat(output.size()));
}

// An edit that drops content-length is honored even when the body is re-serialized.
TEST_P(FilterManagerHeaderEditsTest, RemovedContentLengthStaysRemoved) {
  RequestHeaderEdits edits;
  edits.remove = {Http::LowerCaseString("content-length")};

  const Http::TestRequestHeaderMapImpl seen = run(R"({"model":"gpt-4"})", GetParam(), edits);

  EXPECT_EQ(seen.ContentLength(), nullptr);
  EXPECT_EQ(headers_.ContentLength(), nullptr);
}

TEST_P(FilterManagerHeaderEditsTest, EditsWithoutHeadersAreDropped) {
  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_shared<TestHeaderEditingFilter>(GetParam(), providerEdits()));
  FilterManager manager(std::move(filters));

  absl::Status status;
  bool completed = false;
  manager.startRequest(receive(R"({"model":"gpt-4"})"), &buffer_manager_, *dispatcher_,
                       stream_info_, [&status, &completed](absl::Status s) {
                         status = std::move(s);
                         completed = true;
                       });
  drain();

  EXPECT_TRUE(completed);
  ASSERT_OK(status);
  EXPECT_FALSE(bridge_.injected_.toString().empty());
}

// An edit cannot leave a content-length that disagrees with the body sent.
TEST_P(FilterManagerHeaderEditsTest, ContentLengthAlwaysStatesTheBodySent) {
  RequestHeaderEdits edits;
  edits.set = {{Http::LowerCaseString("content-length"), "1"}};
  const std::string body = R"({"model": "gpt-4"})";
  headers_.setContentLength(body.size());

  const Http::TestRequestHeaderMapImpl seen = run(body, GetParam(), edits);

  EXPECT_EQ(seen.getContentLengthValue(), absl::StrCat(bridge_.injected_.length()));
}

class FilterManagerInvalidHeaderEditsTest
    : public FilterManagerTest,
      public testing::WithParamInterface<std::tuple<bool, std::string>> {};

RequestHeaderEdits invalidEdits(absl::string_view name) {
  RequestHeaderEdits edits;
  if (name == "path_with_space") {
    edits.path = "/v1/models/a b:generateContent";
  } else if (name == "path_with_crlf") {
    edits.path = "/v1\r\nx-injected: 1";
  } else if (name == "relative_path") {
    edits.path = "v1/models";
  } else if (name == "empty_path") {
    edits.path = "";
  } else if (name == "value_with_crlf") {
    edits.set = {{Http::LowerCaseString("x-provider"), "vertex\r\nx-injected: 1"}};
  } else if (name == "value_with_nul") {
    edits.set = {{Http::LowerCaseString("x-provider"), std::string("a\0b", 3)}};
  } else if (name == "name_with_space") {
    edits.set = {{Http::LowerCaseString("x provider"), "v"}};
  } else if (name == "empty_name") {
    edits.set = {{Http::LowerCaseString(""), "v"}};
  } else if (name == "set_pseudo_header") {
    edits.set = {{Http::LowerCaseString(":authority"), "evil.example.com"}};
  } else if (name == "set_host") {
    edits.set = {{Http::LowerCaseString("host"), "evil.example.com"}};
  } else if (name == "remove_pseudo_header") {
    edits.remove = {Http::LowerCaseString(":method")};
  } else if (name == "remove_empty_name") {
    edits.remove = {Http::LowerCaseString("")};
  }
  return edits;
}

INSTANTIATE_TEST_SUITE_P(
    Edits, FilterManagerInvalidHeaderEditsTest,
    testing::Combine(testing::Bool(),
                     testing::Values("path_with_space", "path_with_crlf", "relative_path",
                                     "empty_path", "value_with_crlf", "value_with_nul",
                                     "name_with_space", "empty_name", "set_pseudo_header",
                                     "set_host", "remove_pseudo_header", "remove_empty_name")),
    [](const testing::TestParamInfo<std::tuple<bool, std::string>>& info) {
      return absl::StrCat(std::get<1>(info.param), std::get<0>(info.param) ? "_modified" : "");
    });

// Nothing reaches the chain and the held headers are left as received.
TEST_P(FilterManagerInvalidHeaderEditsTest, FailsTheRequest) {
  const auto& [modify_body, name] = GetParam();
  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_shared<TestHeaderEditingFilter>(modify_body, invalidEdits(name)));
  FilterManager manager(std::move(filters));

  Http::TestRequestHeaderMapImpl headers{{":method", "POST"},
                                         {":path", "/v1/chat/completions"},
                                         {":authority", "api.example.com"},
                                         {"content-length", "17"}};
  const Http::TestRequestHeaderMapImpl original = headers;
  absl::Status status;
  bool completed = false;
  std::optional<Http::Code> local_reply;
  manager.startRequest(
      receive(R"({"model":"gpt-4"})"), &buffer_manager_, *dispatcher_, stream_info_,
      [&status, &completed](absl::Status s) {
        status = std::move(s);
        completed = true;
      },
      &headers, [&local_reply](Http::Code code, std::string) { local_reply = code; });
  drain();

  EXPECT_TRUE(completed);
  EXPECT_THAT(status, HasStatusCode(absl::StatusCode::kInvalidArgument));
  EXPECT_EQ(local_reply, Http::Code::BadGateway);
  EXPECT_EQ(bridge_.injected_.length(), 0);
  EXPECT_EQ(headers, original);
}

// Suspends after propagating, so its coroutine resumes only after the manager is gone.
class OutlivingFilter : public AiFilter {
public:
  OutlivingFilter(std::shared_ptr<Coroutine::AsyncQueue<int>> queue, int& seen, bool& destroyed)
      : queue_(std::move(queue)), seen_(seen), destroyed_(destroyed) {}
  ~OutlivingFilter() override { destroyed_ = true; }

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    CO_RETURN_IF_ERROR(co_await std::move(propagate_request)(std::move(req)));
    ASSIGN_OR_CO_RETURN(std::optional<int> value, co_await queue_->pop());
    seen_ = value.value_or(-1);
    co_return absl::OkStatus();
  }

private:
  std::shared_ptr<Coroutine::AsyncQueue<int>> queue_;
  int& seen_;
  bool& destroyed_;
};

TEST_F(FilterManagerTest, FilterOutlivesManagerUntilItsCoroutineCompletes) {
  auto queue = std::make_shared<Coroutine::AsyncQueue<int>>(/*max_size=*/1);
  int seen = 0;
  bool destroyed = false;

  JsonWithExtBuf doc;
  doc.setJson(nlohmann::json{{"model", "gpt-4"}});
  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_shared<OutlivingFilter>(queue, seen, destroyed));
  auto manager = std::make_unique<FilterManager>(std::move(filters));
  bool completed = false;
  manager->startRequest(std::move(doc), &buffer_manager_, *dispatcher_, stream_info_,
                        [&completed](absl::Status s) { completed = s.ok(); });
  drain();
  ASSERT_TRUE(completed);

  manager.reset();
  EXPECT_FALSE(destroyed);

  ASSERT_TRUE(queue->tryPush(7));
  drain();
  EXPECT_EQ(seen, 7);
  EXPECT_TRUE(destroyed);
}

class BidirectionalTracingFilter : public AiFilter {
public:
  BidirectionalTracingFilter(std::string name, std::vector<std::string>& trace)
      : name_(std::move(name)), trace_(trace) {}

  Coroutine::Task<absl::Status> decode(AiRequestReceiver receive_request,
                                       AiRequestPropagator propagate_request,
                                       LocalReplier) override {
    ASSIGN_OR_CO_RETURN(AiRequestPtr req, co_await std::move(receive_request)());
    trace_.push_back("decode:" + name_);
    seen_request_model_ = req->json().value("model", "");
    co_return co_await std::move(propagate_request)(std::move(req));
  }

  Coroutine::Task<absl::Status> encodeSSE(SseStreamReceiver receive,
                                          SseStreamPropagator propagate) override {
    while (true) {
      ASSIGN_OR_CO_RETURN(auto event, co_await receive());
      if (!event.has_value()) {
        co_return absl::OkStatus();
      }
      trace_.push_back("encode:" + name_);
      if ((*event)->is_json()) {
        (*event)->json().json()[name_ + "_saw_model"] = seen_request_model_;
      }
      CO_RETURN_IF_ERROR(co_await propagate(std::move(*event)));
    }
  }

private:
  std::string name_;
  std::vector<std::string>& trace_;
  std::string seen_request_model_;
};

TEST_F(FilterManagerTest, RequestAndResponseShareFilterInstancesInReverseOrder) {
  std::vector<std::string> trace;
  std::vector<AiFilterSharedPtr> filters;
  filters.push_back(std::make_shared<BidirectionalTracingFilter>("A", trace));
  filters.push_back(std::make_shared<BidirectionalTracingFilter>("B", trace));

  FilterManager manager(std::move(filters));

  JsonWithExtBuf req_doc;
  req_doc.setJson(nlohmann::json{{"model", "gpt-4"}});
  bool req_completed = false;
  manager.startRequest(std::move(req_doc), &buffer_manager_, *dispatcher_, stream_info_,
                       [&req_completed](absl::Status s) { req_completed = s.ok(); });
  drain();
  ASSERT_TRUE(req_completed);
  EXPECT_EQ(trace, (std::vector<std::string>{"decode:A", "decode:B"}));

  FakeBridge resp_bridge(*dispatcher_);
  BufferManager resp_out_manager(BufferManager::Config{}, factory_, resp_bridge);
  bool resp_completed = false;
  manager.startSseResponse(factory_, resp_bridge, resp_out_manager,
                           [&resp_completed](absl::Status s) { resp_completed = s.ok(); });

  Buffer::OwnedImpl sse_input;
  sse_input.add("data: {\"ok\":true}\n\n");
  manager.onResponseData(sse_input, /*end_stream=*/true);
  drain();
  ASSERT_TRUE(resp_completed);

  EXPECT_EQ(trace, (std::vector<std::string>{"decode:A", "decode:B", "encode:B", "encode:A"}));
  const std::string resp_output = resp_bridge.injected_.toString();
  const nlohmann::json parsed_resp =
      nlohmann::json::parse(resp_output.substr(6, resp_output.size() - 8));
  EXPECT_EQ(parsed_resp["A_saw_model"], "gpt-4");
  EXPECT_EQ(parsed_resp["B_saw_model"], "gpt-4");

  resp_out_manager.onDestroy();
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
