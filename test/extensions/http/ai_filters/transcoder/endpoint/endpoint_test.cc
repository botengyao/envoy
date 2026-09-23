#include <string>
#include <utility>
#include <vector>

#include "envoy/extensions/http/ai_filters/transcoder/v3/transcoder.pb.h"

#include "source/extensions/http/ai_filters/transcoder/endpoint/endpoint.h"

#include "test/test_common/utility.h"

#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {
namespace {

using envoy::extensions::http::ai_filters::transcoder::v3::Upstream;
using testing::ElementsAre;
using testing::HasSubstr;
using testing::IsEmpty;
using testing::Pair;

using HeaderList = std::vector<std::pair<std::string, std::string>>;

Upstream parseUpstream(const std::string& yaml) {
  Upstream config;
  TestUtility::loadFromYaml(yaml, config);
  return config;
}

EndpointConstPtr create(const std::string& yaml) {
  absl::StatusOr<EndpointConstPtr> endpoint = createEndpoint(parseUpstream(yaml));
  EXPECT_TRUE(endpoint.ok()) << endpoint.status();
  return endpoint.ok() ? std::move(*endpoint) : nullptr;
}

absl::Status createError(const std::string& yaml) {
  absl::StatusOr<EndpointConstPtr> endpoint = createEndpoint(parseUpstream(yaml));
  EXPECT_FALSE(endpoint.ok());
  return endpoint.status();
}

nlohmann::json parseJson(absl::string_view text) {
  nlohmann::json json = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
  EXPECT_FALSE(json.is_discarded()) << text;
  return json;
}

std::vector<std::string> names(const std::vector<Http::LowerCaseString>& headers) {
  std::vector<std::string> out;
  for (const Http::LowerCaseString& header : headers) {
    out.push_back(header.get());
  }
  return out;
}

HeaderList values(const std::vector<std::pair<Http::LowerCaseString, std::string>>& headers) {
  HeaderList out;
  for (const auto& [name, value] : headers) {
    out.emplace_back(name.get(), value);
  }
  return out;
}

struct Expected {
  std::string path;
  std::string body;
  bool body_changed;
};

void expectApply(const Endpoint& endpoint, absl::string_view input, absl::string_view model,
                 bool stream, const Expected& expected) {
  nlohmann::json body = parseJson(input);
  absl::StatusOr<UpstreamEnvelope> envelope = endpoint.apply(body, model, stream);
  ASSERT_TRUE(envelope.ok()) << envelope.status();
  EXPECT_EQ(envelope->path, expected.path);
  EXPECT_EQ(body, parseJson(expected.body));
  EXPECT_EQ(envelope->body_changed, expected.body_changed);
}

void expectRemovesBothHeaders(const Endpoint& endpoint) {
  nlohmann::json body = nlohmann::json::object();
  absl::StatusOr<UpstreamEnvelope> envelope = endpoint.apply(body, "m", false);
  ASSERT_TRUE(envelope.ok()) << envelope.status();
  EXPECT_THAT(values(envelope->set_headers), IsEmpty());
  EXPECT_THAT(names(envelope->remove_headers), ElementsAre("accept-encoding", "anthropic-version"));
}

void expectApplyError(const Endpoint& endpoint, absl::string_view input, absl::string_view model,
                      absl::string_view message) {
  nlohmann::json body = parseJson(input);
  const nlohmann::json original = body;
  absl::StatusOr<UpstreamEnvelope> envelope = endpoint.apply(body, model, false);
  ASSERT_FALSE(envelope.ok());
  EXPECT_EQ(envelope.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(envelope.status().message(), HasSubstr(message));
  EXPECT_EQ(body, original);
}

constexpr absl::string_view VertexGemini = R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: my-project, location: us-central1}
)EOF";

constexpr absl::string_view VertexAnthropic = R"EOF(
llm_protocol: ANTHROPIC_MESSAGES
vertex_ai: {project: my-project, location: global}
)EOF";

constexpr absl::string_view VertexOpenAi = R"EOF(
llm_protocol: OPENAI_CHAT_COMPLETIONS
vertex_ai: {project: my-project, location: us-central1}
)EOF";

constexpr absl::string_view NativeOpenAi = R"EOF(
llm_protocol: OPENAI_CHAT_COMPLETIONS
native: {}
)EOF";

constexpr absl::string_view NativeAnthropic = R"EOF(
llm_protocol: ANTHROPIC_MESSAGES
native: {}
)EOF";

constexpr absl::string_view NativeGemini = R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
native: {}
)EOF";

TEST(EncodeModelPathSegmentTest, KeepsUnreservedAndEncodesTheRest) {
  std::string encoded_ats;
  for (int i = 0; i < 256; ++i) {
    encoded_ats += "%40";
  }
  const std::vector<std::pair<std::string, std::string>> cases = {
      {"gemini-2.5-flash", "gemini-2.5-flash"},
      {"claude-sonnet-4-5@20250929", "claude-sonnet-4-5%4020250929"},
      {"a:b", "a%3Ab"},
      {"ABCXYZabcxyz0189-._~", "ABCXYZabcxyz0189-._~"},
      {"a+b=c&d", "a%2Bb%3Dc%26d"},
      {"!$'()*,;[]", "%21%24%27%28%29%2A%2C%3B%5B%5D"},
      {"\"<>\\^`{|}", "%22%3C%3E%5C%5E%60%7B%7C%7D"},
      {"...", "..."},
      {std::string(256, 'a'), std::string(256, 'a')},
      {std::string(256, '@'), encoded_ats},
  };
  for (const auto& [model, encoded] : cases) {
    SCOPED_TRACE(model);
    absl::StatusOr<std::string> result = encodeModelPathSegment(model);
    ASSERT_TRUE(result.ok()) << result.status();
    EXPECT_EQ(*result, encoded);
  }
}

TEST(EncodeModelPathSegmentTest, RejectsNamesThatCannotBeASegment) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {"", "1 to 256 bytes"},   {std::string(257, 'a'), "1 to 256 bytes"},
      {".", "dot segment"},     {"..", "dot segment"},
      {"../x", "not allowed"},  {"a/b", "not allowed"},
      {"a?b", "not allowed"},   {"a#b", "not allowed"},
      {"a%20b", "not allowed"}, {"a b", "not allowed"},
      {"a\tb", "not allowed"},  {"a\nb", "not allowed"},
      {"a\rb", "not allowed"},  {std::string("a\0b", 3), "not allowed"},
      {"a\x7f", "not allowed"}, {"caf\xc3\xa9", "not allowed"},
      {"\xff", "not allowed"},
  };
  for (const auto& [model, message] : cases) {
    SCOPED_TRACE(model);
    absl::StatusOr<std::string> result = encodeModelPathSegment(model);
    ASSERT_FALSE(result.ok());
    EXPECT_EQ(result.status().code(), absl::StatusCode::kInvalidArgument);
    EXPECT_THAT(result.status().message(), HasSubstr(message));
  }
}

TEST(VertexAiEndpointTest, GeminiUnary) {
  EndpointConstPtr endpoint = create(std::string(VertexGemini));
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint,
              R"({"model":"gemini","stream":false,"stream_options":{"include_usage":true},
                  "contents":[{"role":"user","parts":[{"text":"hi"}]}]})",
              "gemini-2.5-flash", false,
              {"/v1/projects/my-project/locations/us-central1/publishers/google/models/"
               "gemini-2.5-flash:generateContent",
               R"({"contents":[{"role":"user","parts":[{"text":"hi"}]}]})", true});
  expectRemovesBothHeaders(*endpoint);
}

TEST(VertexAiEndpointTest, GeminiStream) {
  EndpointConstPtr endpoint = create(std::string(VertexGemini));
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({"stream":true,"contents":[]})", "gemini-2.5-flash", true,
              {"/v1/projects/my-project/locations/us-central1/publishers/google/models/"
               "gemini-2.5-flash:streamGenerateContent?alt=sse",
               R"({"contents":[]})", true});
}

TEST(VertexAiEndpointTest, GeminiBodyWithoutEnvelopeFieldsIsUnchanged) {
  EndpointConstPtr endpoint = create(std::string(VertexGemini));
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({"contents":[],"generationConfig":{"maxOutputTokens":8}})",
              "gemini-2.5-flash", true,
              {"/v1/projects/my-project/locations/us-central1/publishers/google/models/"
               "gemini-2.5-flash:streamGenerateContent?alt=sse",
               R"({"contents":[],"generationConfig":{"maxOutputTokens":8}})", false});
  expectApply(*endpoint, R"({"stream_options":{}})", "gemini-2.5-flash", false,
              {"/v1/projects/my-project/locations/us-central1/publishers/google/models/"
               "gemini-2.5-flash:generateContent",
               "{}", true});
}

TEST(VertexAiEndpointTest, GeminiExpressMode) {
  EndpointConstPtr endpoint = create(R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {}
)EOF");
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({"contents":[]})", "gemini-2.5-flash", false,
              {"/v1/publishers/google/models/gemini-2.5-flash:generateContent",
               R"({"contents":[]})", false});
  expectApply(*endpoint, R"({"contents":[]})", "gemini-2.5-flash", true,
              {"/v1/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
               R"({"contents":[]})", false});
  expectRemovesBothHeaders(*endpoint);
}

TEST(VertexAiEndpointTest, AnthropicUnary) {
  EndpointConstPtr endpoint = create(std::string(VertexAnthropic));
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint,
              R"({"model":"claude","max_tokens":16,"messages":[{"role":"user","content":"hi"}]})",
              "claude-sonnet-4-5@20250929", false,
              {"/v1/projects/my-project/locations/global/publishers/anthropic/models/"
               "claude-sonnet-4-5%4020250929:rawPredict",
               R"({"anthropic_version":"vertex-2023-10-16","max_tokens":16,
                   "messages":[{"role":"user","content":"hi"}]})",
               true});
  expectRemovesBothHeaders(*endpoint);
}

TEST(VertexAiEndpointTest, AnthropicStreamKeepsStream) {
  EndpointConstPtr endpoint = create(std::string(VertexAnthropic));
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({"model":"claude","max_tokens":16,"messages":[],"stream":true})",
              "claude-sonnet-4-5@20250929", true,
              {"/v1/projects/my-project/locations/global/publishers/anthropic/models/"
               "claude-sonnet-4-5%4020250929:streamRawPredict",
               R"({"anthropic_version":"vertex-2023-10-16","max_tokens":16,"messages":[],
                   "stream":true})",
               true});
}

TEST(VertexAiEndpointTest, AnthropicBodyChangedTracksEachField) {
  EndpointConstPtr endpoint = create(std::string(VertexAnthropic));
  ASSERT_NE(endpoint, nullptr);
  const std::string path = "/v1/projects/my-project/locations/global/publishers/anthropic/models/"
                           "claude-haiku-4-5:rawPredict";
  expectApply(*endpoint, R"({"anthropic_version":"vertex-2023-10-16","messages":[]})",
              "claude-haiku-4-5", false,
              {path, R"({"anthropic_version":"vertex-2023-10-16","messages":[]})", false});
  expectApply(*endpoint, R"({"model":"x","anthropic_version":"vertex-2023-10-16"})",
              "claude-haiku-4-5", false,
              {path, R"({"anthropic_version":"vertex-2023-10-16"})", true});
  expectApply(*endpoint, R"({"anthropic_version":"bedrock-2023-05-31"})", "claude-haiku-4-5", false,
              {path, R"({"anthropic_version":"vertex-2023-10-16"})", true});
  expectApply(*endpoint, R"({"anthropic_version":1})", "claude-haiku-4-5", false,
              {path, R"({"anthropic_version":"vertex-2023-10-16"})", true});
}

TEST(VertexAiEndpointTest, AnthropicCustomVersion) {
  EndpointConstPtr endpoint = create(R"EOF(
llm_protocol: ANTHROPIC_MESSAGES
vertex_ai: {project: my-project, location: global, anthropic_version: vertex-2099-01-01}
)EOF");
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({"model":"claude","messages":[]})", "claude-opus-4-1@20250805", false,
              {"/v1/projects/my-project/locations/global/publishers/anthropic/models/"
               "claude-opus-4-1%4020250805:rawPredict",
               R"({"anthropic_version":"vertex-2099-01-01","messages":[]})", true});
}

TEST(VertexAiEndpointTest, OpenAiCompatible) {
  EndpointConstPtr endpoint = create(std::string(VertexOpenAi));
  ASSERT_NE(endpoint, nullptr);
  const std::string path =
      "/v1/projects/my-project/locations/us-central1/endpoints/openapi/chat/completions";
  expectApply(*endpoint, R"({"model":"gpt-4o","messages":[]})", "google/gemini-2.5-flash", false,
              {path, R"({"model":"google/gemini-2.5-flash","messages":[]})", true});
  expectApply(*endpoint,
              R"({"model":"google/gemini-2.5-flash","messages":[],"stream":true,
                  "stream_options":{"include_usage":true}})",
              "google/gemini-2.5-flash", true,
              {path,
               R"({"model":"google/gemini-2.5-flash","messages":[],"stream":true,
                   "stream_options":{"include_usage":true}})",
               false});
  expectRemovesBothHeaders(*endpoint);
}

TEST(VertexAiEndpointTest, InvalidConfigs) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: my-project}
)EOF",
       "both project and location"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {location: us-central1}
)EOF",
       "both project and location"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: my/project, location: us-central1}
)EOF",
       "vertex_ai.project must not contain"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: "my?project", location: us-central1}
)EOF",
       "vertex_ai.project must not contain"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: "my#project", location: us-central1}
)EOF",
       "vertex_ai.project must not contain"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: my-project, location: "us central1"}
)EOF",
       "vertex_ai.location must not contain"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: my-project, location: "us-central1\n"}
)EOF",
       "vertex_ai.location must not contain"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: "my-proj\xc3\xa9ct", location: us-central1}
)EOF",
       "vertex_ai.project must not contain"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: "my\x01project", location: us-central1}
)EOF",
       "vertex_ai.project must not contain"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: "..", location: us-central1}
)EOF",
       "vertex_ai.project must not be a dot segment"},
      {R"EOF(
llm_protocol: ANTHROPIC_MESSAGES
vertex_ai: {project: my-project, location: "."}
)EOF",
       "vertex_ai.location must not be a dot segment"},
      {R"EOF(
llm_protocol: OPENAI_CHAT_COMPLETIONS
vertex_ai: {}
)EOF",
       "express mode does not serve OPENAI_CHAT_COMPLETIONS"},
      {R"EOF(
llm_protocol: ANTHROPIC_MESSAGES
vertex_ai: {}
)EOF",
       "express mode does not serve ANTHROPIC_MESSAGES"},
      {R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
vertex_ai: {project: my-project, location: us-central1}
model: models/gemini-2.5-flash
)EOF",
       "model: model name holds a character not allowed"},
      {R"EOF(
llm_protocol: ANTHROPIC_MESSAGES
vertex_ai: {project: my-project, location: global}
model: "claude sonnet"
)EOF",
       "model: model name holds a character not allowed"},
      {R"EOF(
llm_protocol: OPENAI_RESPONSES
vertex_ai: {project: my-project, location: us-central1}
)EOF",
       "vertex_ai endpoint does not serve OPENAI_RESPONSES"},
      {R"EOF(
vertex_ai: {project: my-project, location: us-central1}
)EOF",
       "vertex_ai endpoint does not serve LLM_PROTOCOL_UNSPECIFIED"},
  };
  for (const auto& [yaml, message] : cases) {
    SCOPED_TRACE(yaml);
    const absl::Status status = createError(yaml);
    EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
    EXPECT_THAT(status.message(), HasSubstr(message));
  }
}

TEST(NativeEndpointTest, OpenAi) {
  EndpointConstPtr endpoint = create(std::string(NativeOpenAi));
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({"messages":[]})", "gpt-4o", false,
              {"/v1/chat/completions", R"({"model":"gpt-4o","messages":[]})", true});
  expectApply(*endpoint, R"({"model":"gpt-4o","messages":[],"stream":true})", "gpt-4o", true,
              {"/v1/chat/completions", R"({"model":"gpt-4o","messages":[],"stream":true})", false});
  expectApply(*endpoint, R"({"model":7})", "gpt-4o", false,
              {"/v1/chat/completions", R"({"model":"gpt-4o"})", true});
  expectRemovesBothHeaders(*endpoint);
}

TEST(NativeEndpointTest, OpenAiPathPrefix) {
  EndpointConstPtr endpoint = create(R"EOF(
llm_protocol: OPENAI_CHAT_COMPLETIONS
native: {path_prefix: /openai/v1}
)EOF");
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({"model":"gpt-4o"})", "gpt-4o", false,
              {"/openai/v1/chat/completions", R"({"model":"gpt-4o"})", false});
}

TEST(NativeEndpointTest, Anthropic) {
  EndpointConstPtr endpoint = create(std::string(NativeAnthropic));
  ASSERT_NE(endpoint, nullptr);
  expectApply(
      *endpoint, R"({"model":"claude","max_tokens":16,"messages":[]})", "claude-sonnet-4-5", false,
      {"/v1/messages", R"({"model":"claude-sonnet-4-5","max_tokens":16,"messages":[]})", true});
  expectApply(
      *endpoint, R"({"model":"claude-sonnet-4-5","messages":[],"stream":true})",
      "claude-sonnet-4-5", true,
      {"/v1/messages", R"({"model":"claude-sonnet-4-5","messages":[],"stream":true})", false});
  expectApply(*endpoint,
              R"({"model":"claude-sonnet-4-5","anthropic_version":"vertex-2023-10-16",)"
              R"("messages":[]})",
              "claude-sonnet-4-5", false,
              {"/v1/messages", R"({"model":"claude-sonnet-4-5","messages":[]})", true});

  nlohmann::json body = nlohmann::json::object();
  absl::StatusOr<UpstreamEnvelope> envelope = endpoint->apply(body, "claude-sonnet-4-5", false);
  ASSERT_TRUE(envelope.ok()) << envelope.status();
  EXPECT_THAT(values(envelope->set_headers), ElementsAre(Pair("anthropic-version", "2023-06-01")));
  EXPECT_THAT(names(envelope->remove_headers), ElementsAre("accept-encoding"));
}

TEST(NativeEndpointTest, AnthropicPathPrefix) {
  EndpointConstPtr endpoint = create(R"EOF(
llm_protocol: ANTHROPIC_MESSAGES
native: {path_prefix: /anthropic/v1}
)EOF");
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({})", "claude-sonnet-4-5", false,
              {"/anthropic/v1/messages", R"({"model":"claude-sonnet-4-5"})", true});
}

TEST(NativeEndpointTest, Gemini) {
  EndpointConstPtr endpoint = create(std::string(NativeGemini));
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({"model":"g","stream":false,"contents":[]})", "gemini-2.5-flash", false,
              {"/v1beta/models/gemini-2.5-flash:generateContent", R"({"contents":[]})", true});
  expectApply(*endpoint, R"({"contents":[]})", "gemini-2.5-flash", true,
              {"/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
               R"({"contents":[]})", false});
  expectRemovesBothHeaders(*endpoint);
}

TEST(NativeEndpointTest, GeminiPathPrefix) {
  EndpointConstPtr endpoint = create(R"EOF(
llm_protocol: GEMINI_GENERATE_CONTENT
native: {path_prefix: /v1}
)EOF");
  ASSERT_NE(endpoint, nullptr);
  expectApply(*endpoint, R"({"contents":[]})", "gemini-2.5-pro", false,
              {"/v1/models/gemini-2.5-pro:generateContent", R"({"contents":[]})", false});
}

TEST(NativeEndpointTest, InvalidConfigs) {
  const std::vector<std::pair<std::string, std::string>> cases = {
      {"llm_protocol: OPENAI_RESPONSES\nnative: {}",
       "native endpoint does not serve OPENAI_RESPONSES"},
      {"native: {}", "native endpoint does not serve LLM_PROTOCOL_UNSPECIFIED"},
      {"llm_protocol: OPENAI_CHAT_COMPLETIONS\nnative: {path_prefix: v1}", "native.path_prefix"},
      {"llm_protocol: OPENAI_CHAT_COMPLETIONS\nnative: {path_prefix: /}", "native.path_prefix"},
      {"llm_protocol: OPENAI_CHAT_COMPLETIONS\nnative: {path_prefix: /v1/}", "native.path_prefix"},
      {"llm_protocol: OPENAI_CHAT_COMPLETIONS\nnative: {path_prefix: //v1}", "native.path_prefix"},
      {"llm_protocol: OPENAI_CHAT_COMPLETIONS\nnative: {path_prefix: \"/v1?x=1\"}",
       "native.path_prefix"},
      {"llm_protocol: OPENAI_CHAT_COMPLETIONS\nnative: {path_prefix: \"/v1#x\"}",
       "native.path_prefix"},
      {"llm_protocol: OPENAI_CHAT_COMPLETIONS\nnative: {path_prefix: \"/v 1\"}",
       "native.path_prefix"},
      {"llm_protocol: OPENAI_CHAT_COMPLETIONS\nnative: {path_prefix: /v1/..}",
       "native.path_prefix"},
      {"llm_protocol: ANTHROPIC_MESSAGES\nnative: {path_prefix: /./v1}", "native.path_prefix"},
      {"llm_protocol: GEMINI_GENERATE_CONTENT\nnative: {}\nmodel: \"..\"",
       "model: model name must not be a dot segment"},
  };
  for (const auto& [yaml, message] : cases) {
    SCOPED_TRACE(yaml);
    const absl::Status status = createError(yaml);
    EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
    EXPECT_THAT(status.message(), HasSubstr(message));
  }
}

TEST(EndpointTest, ConfiguredModelIsCheckedOnlyWhereThePathCarriesIt) {
  for (absl::string_view yaml : {VertexOpenAi, NativeOpenAi, NativeAnthropic}) {
    SCOPED_TRACE(yaml);
    EndpointConstPtr endpoint =
        create(absl::StrCat(yaml, "model: \"google/gemini-2.5-flash@001\"\n"));
    EXPECT_NE(endpoint, nullptr);
  }
  for (absl::string_view yaml : {VertexGemini, VertexAnthropic, NativeGemini}) {
    SCOPED_TRACE(yaml);
    EXPECT_NE(create(absl::StrCat(yaml, "model: claude-sonnet-4-5@20250929\n")), nullptr);
    const absl::Status status = createError(absl::StrCat(yaml, "model: google/gemini\n"));
    EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
    EXPECT_THAT(status.message(), HasSubstr("model: model name holds a character"));
  }
}

TEST(EndpointTest, BodyStreamFollowsTheRequestedMode) {
  EndpointConstPtr vertex_anthropic = create(std::string(VertexAnthropic));
  ASSERT_NE(vertex_anthropic, nullptr);
  const std::string models =
      "/v1/projects/my-project/locations/global/publishers/anthropic/models/claude-haiku-4-5";
  expectApply(*vertex_anthropic, R"({"anthropic_version":"vertex-2023-10-16","messages":[]})",
              "claude-haiku-4-5", true,
              {models + ":streamRawPredict",
               R"({"anthropic_version":"vertex-2023-10-16","messages":[],"stream":true})", true});
  expectApply(*vertex_anthropic, R"({"anthropic_version":"vertex-2023-10-16","stream":true})",
              "claude-haiku-4-5", false,
              {models + ":rawPredict",
               R"({"anthropic_version":"vertex-2023-10-16","stream":false})", true});
  expectApply(*vertex_anthropic, R"({"anthropic_version":"vertex-2023-10-16","stream":false})",
              "claude-haiku-4-5", false,
              {models + ":rawPredict",
               R"({"anthropic_version":"vertex-2023-10-16","stream":false})", false});
  expectApply(*vertex_anthropic, R"({"anthropic_version":"vertex-2023-10-16","stream":null})",
              "claude-haiku-4-5", false,
              {models + ":rawPredict", R"({"anthropic_version":"vertex-2023-10-16","stream":null})",
               false});

  for (const auto& [yaml, path] : std::vector<std::pair<absl::string_view, std::string>>{
           {VertexOpenAi,
            "/v1/projects/my-project/locations/us-central1/endpoints/openapi/chat/completions"},
           {NativeOpenAi, "/v1/chat/completions"},
           {NativeAnthropic, "/v1/messages"}}) {
    SCOPED_TRACE(yaml);
    EndpointConstPtr endpoint = create(std::string(yaml));
    ASSERT_NE(endpoint, nullptr);
    expectApply(*endpoint, R"({"model":"m"})", "m", true,
                {path, R"({"model":"m","stream":true})", true});
    expectApply(*endpoint, R"({"model":"m","stream":"yes"})", "m", true,
                {path, R"({"model":"m","stream":true})", true});
    expectApply(*endpoint, R"({"model":"m","stream":true})", "m", false,
                {path, R"({"model":"m","stream":false})", true});
    expectApply(*endpoint, R"({"model":"m","stream":false})", "m", false,
                {path, R"({"model":"m","stream":false})", false});
  }
}

TEST(EndpointTest, NoEndpoint) {
  const absl::Status status = createError("llm_protocol: OPENAI_CHAT_COMPLETIONS");
  EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(status.message(), HasSubstr("no endpoint"));
}

TEST(EndpointTest, ApplyRejectsBadBodiesAndModelsWithoutChangingTheBody) {
  for (absl::string_view yaml :
       {VertexGemini, VertexAnthropic, VertexOpenAi, NativeOpenAi, NativeAnthropic, NativeGemini}) {
    SCOPED_TRACE(yaml);
    EndpointConstPtr endpoint = create(std::string(yaml));
    ASSERT_NE(endpoint, nullptr);
    expectApplyError(*endpoint, "[]", "m", "must be a JSON object");
    expectApplyError(*endpoint, R"("text")", "m", "must be a JSON object");
    expectApplyError(*endpoint, "null", "m", "must be a JSON object");
    expectApplyError(*endpoint, R"({"model":"m"})", "", "has no model");
  }
  for (absl::string_view yaml : {VertexGemini, VertexAnthropic, NativeGemini}) {
    SCOPED_TRACE(yaml);
    EndpointConstPtr endpoint = create(std::string(yaml));
    ASSERT_NE(endpoint, nullptr);
    expectApplyError(*endpoint, R"({"model":"m","stream":true})", "../x", "not allowed");
    expectApplyError(*endpoint, R"({"model":"m","stream":true})", "a%2Fb", "not allowed");
    expectApplyError(*endpoint, R"({"model":"m","stream":true})", std::string(257, 'a'),
                     "1 to 256 bytes");
  }
}

} // namespace
} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
