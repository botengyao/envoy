#include <tuple>
#include <type_traits>
#include <utility>

#include "source/extensions/filters/http/ai_protocol_manager/ai_request.h"

#include "test/test_common/status_utility.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

// The single-ownership contract the handoff queues rely on.
static_assert(!std::is_copy_constructible_v<AiRequest>);
static_assert(!std::is_copy_assignable_v<AiRequest>);
static_assert(!std::is_move_constructible_v<AiRequest>);
static_assert(!std::is_move_assignable_v<AiRequest>);

// Reading must never be what makes the manager re-serialize a request.
static_assert(std::is_same_v<decltype(std::declval<AiRequest&>().json()), const nlohmann::json&>);

JsonWithExtBuf makeIndex(nlohmann::json json) {
  JsonWithExtBuf index;
  index.setJson(std::move(json));
  return index;
}

AiRequestPtr makeRequest(nlohmann::json json) {
  return AiRequest::received(makeIndex(std::move(json)));
}

// A filter that propagates a request it built must not have the received body forwarded instead.
TEST(AiRequestTest, RequestBuiltByAFilterStartsModified) {
  AiRequest request(makeIndex(nlohmann::json{{"model", "gpt-4"}}));

  EXPECT_TRUE(request.modified());
  EXPECT_EQ(request.json().value("model", ""), "gpt-4");
}

TEST(AiRequestTest, ReadingLeavesTheRequestUnmodified) {
  AiRequestPtr request = makeRequest(nlohmann::json{{"model", "gpt-4"}});

  EXPECT_EQ(request->json().value("model", ""), "gpt-4");
  EXPECT_EQ(request->request_index().json().value("model", ""), "gpt-4");
  EXPECT_FALSE(request->modified());
}

// mutableJson() hands out the stored document itself, so a filter's edit is what serialization
// later reads.
TEST(AiRequestTest, MutableJsonAliasesTheIndexAndMarksModified) {
  AiRequestPtr request = makeRequest(nlohmann::json{{"model", "gpt-4"}});

  request->mutableJson()["model"] = "gpt-4-turbo";

  EXPECT_TRUE(request->modified());
  EXPECT_EQ(request->request_index().json().value("model", ""), "gpt-4-turbo");
  EXPECT_EQ(&request->mutableJson(), &request->request_index().json());
  EXPECT_EQ(&request->json(), &request->request_index().json());
}

// Asking for the mutable document is enough: the manager cannot tell an edit from a no-op.
TEST(AiRequestTest, MutableJsonMarksModifiedWithoutAChange) {
  AiRequestPtr request = makeRequest(nlohmann::json{{"model", "gpt-4"}});

  std::ignore = request->mutableJson();

  EXPECT_TRUE(request->modified());
  EXPECT_EQ(request->json(), (nlohmann::json{{"model", "gpt-4"}}));
}

// A transcoding filter swaps the payload wholesale rather than editing fields.
TEST(AiRequestTest, AssigningMutableJsonReplacesTheDocument) {
  AiRequestPtr request = makeRequest(nlohmann::json{{"model", "gpt-4"}, {"temperature", 0.5}});

  request->mutableJson() = nlohmann::json{{"model", "claude-opus-4"}};

  EXPECT_TRUE(request->modified());
  EXPECT_EQ(request->json().value("model", ""), "claude-opus-4");
  EXPECT_FALSE(request->request_index().json().contains("temperature"));
}

TEST(AiRequestTest, TakeRequestIndexMovesTheDocumentOut) {
  AiRequestPtr request = makeRequest(nlohmann::json{{"model", "gpt-4"}});

  JsonWithExtBuf taken = request->takeRequestIndex();

  EXPECT_EQ(taken.json(), (nlohmann::json{{"model", "gpt-4"}}));
  EXPECT_FALSE(request->json().contains("model"));
  EXPECT_TRUE(request->modified());
}

// Offloaded values reach a filter as reference nodes, not as bytes.
TEST(AiRequestTest, ExternalRefsSurviveTheWrapper) {
  const JsonWithExtBuf::ExternalRef ref{/*offset=*/64, /*length=*/4096};
  AiRequestPtr request =
      makeRequest(nlohmann::json{{"prompt", JsonWithExtBuf::makeExternalRef(ref)}});

  const auto prompt = request->json().find("prompt");
  ASSERT_NE(prompt, request->json().end());
  ASSERT_TRUE(JsonWithExtBuf::isExternalRef(*prompt));
  const absl::StatusOr<JsonWithExtBuf::ExternalRef> decoded = JsonWithExtBuf::externalRef(*prompt);
  ASSERT_OK(decoded);
  EXPECT_EQ(*decoded, ref);
}

TEST(AiRequestTest, HeaderEditsStartEmptyAndDoNotMarkModified) {
  AiRequestPtr request = makeRequest(nlohmann::json{{"model", "gpt-4"}});
  EXPECT_TRUE(request->headerEdits().empty());

  request->headerEdits().path = "/v1/other";
  request->headerEdits().set.emplace_back(Http::LowerCaseString("x-set"), "v");
  request->headerEdits().remove.emplace_back("x-gone");

  const AiRequest& const_request = *request;
  EXPECT_EQ(&const_request.headerEdits(), &request->headerEdits());
  EXPECT_FALSE(const_request.headerEdits().empty());
  EXPECT_FALSE(request->modified());
}

TEST(AiRequestTest, CarriesTheIrUntilTheDocumentIsEdited) {
  AiRequestPtr request = makeRequest(nlohmann::json{{"model", "gpt-4"}});
  EXPECT_EQ(request->ir(), nullptr);

  auto ir = std::make_shared<RequestIr>(LLMProtocol::OpenAiChatCompletions, "gpt-4", std::nullopt,
                                        std::nullopt);
  request->setIr(ir);
  EXPECT_EQ(request->ir(), ir.get());
  EXPECT_EQ(request->sharedIr(), ir);
  EXPECT_FALSE(request->modified());

  request->mutableJson()["model"] = "gpt-5";
  EXPECT_EQ(request->ir(), nullptr);
}

TEST(RequestHeaderEditsTest, EachKindOfEditMakesItNonEmpty) {
  RequestHeaderEdits path_only;
  path_only.path = "/";
  EXPECT_FALSE(path_only.empty());

  RequestHeaderEdits set_only;
  set_only.set.emplace_back(Http::LowerCaseString("x-a"), "1");
  EXPECT_FALSE(set_only.empty());

  RequestHeaderEdits remove_only;
  remove_only.remove.emplace_back("x-a");
  EXPECT_FALSE(remove_only.empty());
}

// Removal runs first, so a header both removed and set ends up with the new value only.
TEST(RequestHeaderEditsTest, ApplyRemovesThenSetsThenRewritesPath) {
  Http::TestRequestHeaderMapImpl headers{{":method", "POST"}, {":path", "/v1/chat/completions"},
                                         {"x-multi", "1"},    {"x-multi", "2"},
                                         {"x-gone", "v"},     {"x-both", "old"},
                                         {"x-kept", "k"}};
  RequestHeaderEdits edits;
  edits.remove = {Http::LowerCaseString("x-gone"), Http::LowerCaseString("x-both"),
                  Http::LowerCaseString("x-absent")};
  edits.set = {{Http::LowerCaseString("x-multi"), "3"},
               {Http::LowerCaseString("x-both"), "new"},
               {Http::LowerCaseString("x-added"), "a"}};
  edits.path = "/v1/projects/p/locations/l/publishers/google/models/m:generateContent";

  edits.apply(headers);

  EXPECT_EQ(headers.getPathValue(),
            "/v1/projects/p/locations/l/publishers/google/models/m:generateContent");
  EXPECT_EQ(headers.get(Http::LowerCaseString("x-multi")).size(), 1);
  EXPECT_EQ(headers.get_("x-multi"), "3");
  EXPECT_FALSE(headers.has("x-gone"));
  EXPECT_EQ(headers.get_("x-both"), "new");
  EXPECT_EQ(headers.get_("x-added"), "a");
  EXPECT_EQ(headers.get_("x-kept"), "k");
  EXPECT_EQ(headers.getMethodValue(), "POST");
}

TEST(RequestHeaderEditsTest, EmptyEditsLeaveHeadersAlone) {
  Http::TestRequestHeaderMapImpl headers{{":method", "POST"}, {":path", "/v1/messages"}};
  const Http::TestRequestHeaderMapImpl original = headers;

  RequestHeaderEdits().apply(headers);

  EXPECT_EQ(headers, original);
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
