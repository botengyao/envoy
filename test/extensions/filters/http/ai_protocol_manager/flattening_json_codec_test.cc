#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/coroutine/dispatcher_executor.h"
#include "source/common/coroutine/launch.h"
#include "source/common/coroutine/status_macros.h"
#include "source/extensions/filters/http/ai_protocol_manager/buffer_manager.h"
#include "source/extensions/filters/http/ai_protocol_manager/external_buffer_impl.h"
#include "source/extensions/filters/http/ai_protocol_manager/flattening_json_codec.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"

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
using ::Envoy::StatusHelpers::IsOk;

class FlatteningJsonCodecTest : public testing::Test {
public:
  FlatteningJsonCodecTest()
      : api_(Api::createApiForTest()), dispatcher_(api_->allocateDispatcher("test")),
        executor_(std::make_shared<Coroutine::DispatcherExecutor>(*dispatcher_)),
        bridge_(*dispatcher_), out_buffer_manager_(BufferManager::Config{}, factory_, bridge_) {}

  ~FlatteningJsonCodecTest() override { out_buffer_manager_.onDestroy(); }

  void drain() {
    for (int i = 0; i < 40; ++i) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }
  }

  absl::Status serializeBatches(const std::vector<std::vector<FlattenJsonField>>& batches) {
    absl::Status result = absl::UnknownError("not finished");
    FlatteningJsonSerializer serializer(out_buffer_manager_);
    auto task = [&serializer, &batches]() -> Coroutine::Task<absl::Status> {
      for (const auto& batch : batches) {
        CO_RETURN_IF_ERROR(co_await serializer.serializeBatch(batch));
      }
      co_return co_await serializer.finish();
    };
    auto handle = Coroutine::launch(
        task(), executor_, [&result](absl::Status status) { result = std::move(status); },
        Coroutine::StartMode::Inline);
    drain();
    return result;
  }

  absl::StatusOr<std::string> roundTrip(absl::string_view input, size_t chunk_size = 0) {
    bridge_.injected_.drain(bridge_.injected_.length());
    FlatteningJsonDecoder decoder;
    std::vector<std::vector<FlattenJsonField>> batches;
    if (chunk_size == 0) {
      Buffer::OwnedImpl buf(input);
      auto batch_or = decoder.onData(buf, /*end_stream=*/true);
      RETURN_IF_NOT_OK(batch_or.status());
      if (!batch_or->empty()) {
        batches.push_back(std::move(*batch_or));
      }
    } else {
      for (size_t offset = 0; offset < input.size(); offset += chunk_size) {
        const bool is_last = (offset + chunk_size >= input.size());
        Buffer::OwnedImpl buf(input.substr(offset, chunk_size));
        auto batch_or = decoder.onData(buf, /*end_stream=*/is_last);
        RETURN_IF_NOT_OK(batch_or.status());
        if (!batch_or->empty()) {
          batches.push_back(std::move(*batch_or));
        }
      }
      if (input.empty()) {
        Buffer::OwnedImpl empty;
        auto batch_or = decoder.onData(empty, /*end_stream=*/true);
        RETURN_IF_NOT_OK(batch_or.status());
      }
    }
    RETURN_IF_NOT_OK(serializeBatches(batches));
    return bridge_.injected_.toString();
  }

  // Decodes `input` in `chunk_size` pieces (0 for one piece) into one sequence of fields.
  static absl::StatusOr<std::vector<FlattenJsonField>> decodeFields(absl::string_view input,
                                                                    size_t chunk_size) {
    FlatteningJsonDecoder decoder;
    std::vector<FlattenJsonField> fields;
    const size_t step = chunk_size == 0 ? input.size() : chunk_size;
    for (size_t offset = 0; offset < input.size(); offset += step) {
      Buffer::OwnedImpl buf(input.substr(offset, step));
      auto batch_or = decoder.onData(buf, /*end_stream=*/offset + step >= input.size());
      RETURN_IF_NOT_OK(batch_or.status());
      for (FlattenJsonField& field : *batch_or) {
        fields.push_back(std::move(field));
      }
    }
    return fields;
  }

  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;
  std::shared_ptr<Coroutine::DispatcherExecutor> executor_;
  InMemoryExternalBufferFactory factory_;
  FakeBridge bridge_;
  BufferManager out_buffer_manager_;
};

TEST_F(FlatteningJsonCodecTest, FlattenJsonFieldCopyMoveAndMutationPreservePath) {
  FlattenJsonField original({FieldPathSegment{"choices"}, FieldPathSegment{size_t{0}},
                             FieldPathSegment{"message"}, FieldPathSegment{"content"}},
                            nlohmann::json("hello world"));

  ASSERT_EQ(original.field_path().size(), 4);
  EXPECT_EQ(absl::get<std::string>(original.field_path()[0]), "choices");
  EXPECT_EQ(absl::get<size_t>(original.field_path()[1]), 0u);
  EXPECT_EQ(absl::get<std::string>(original.field_path()[2]), "message");
  EXPECT_EQ(absl::get<std::string>(original.field_path()[3]), "content");
  EXPECT_EQ(original.node(), "hello world");
  EXPECT_GT(original.byteSize(), sizeof(FlattenJsonField));

  // Copy construction and copy assignment.
  FlattenJsonField copied(original);
  EXPECT_EQ(copied, original);
  EXPECT_EQ(absl::get<std::string>(copied.field_path()[3]), "content");

  FlattenJsonField copy_assigned;
  copy_assigned = copied;
  EXPECT_EQ(copy_assigned, original);

  // Mutate via FieldPath span view.
  FlattenJsonField from_span({}, nlohmann::json(42));
  from_span.set_field_path(original.field_path());
  EXPECT_EQ(from_span.field_path().size(), 4);
  EXPECT_EQ(absl::get<std::string>(from_span.field_path()[0]), "choices");
  EXPECT_EQ(from_span.node(), 42);

  // Move construction and move assignment.
  FlattenJsonField moved(std::move(copied));
  EXPECT_EQ(moved, original);
  EXPECT_EQ(absl::get<std::string>(moved.field_path()[2]), "message");

  FlattenJsonField move_assigned;
  move_assigned = std::move(moved);
  EXPECT_EQ(move_assigned, original);
  EXPECT_EQ(absl::get<std::string>(move_assigned.field_path()[3]), "content");
}

TEST_F(FlatteningJsonCodecTest, TransformsAndInjectsFlattenedFieldsBeforeSerializing) {
  FlatteningJsonDecoder decoder;
  Buffer::OwnedImpl buf(R"({"id":"chatcmpl-1","model":"gpt-4","usage":{"total_tokens":12}})");
  auto decoded_or = decoder.onData(buf, /*end_stream=*/true);
  ASSERT_THAT(decoded_or.status(), IsOk());
  std::vector<FlattenJsonField> decoded = std::move(*decoded_or);

  for (FlattenJsonField& field : decoded) {
    if (field.field_path().size() == 1 &&
        absl::holds_alternative<std::string>(field.field_path()[0]) &&
        absl::get<std::string>(field.field_path()[0]) == "model") {
      field.node() = "gpt-4o-rewritten";
    }
  }
  decoded.emplace_back(
      std::vector<FieldPathSegment>{FieldPathSegment{"usage"}, FieldPathSegment{"cached_tokens"}},
      nlohmann::json(4));

  ASSERT_THAT(serializeBatches({decoded}), IsOk());
  const nlohmann::json output_json = nlohmann::json::parse(bridge_.injected_.toString());
  EXPECT_EQ(output_json["model"], "gpt-4o-rewritten");
  EXPECT_EQ(output_json["id"], "chatcmpl-1");
  EXPECT_EQ(output_json["usage"]["total_tokens"], 12);
  EXPECT_EQ(output_json["usage"]["cached_tokens"], 4);
}

TEST_F(FlatteningJsonCodecTest, RoundTripsComplexOpenAiChatCompletion) {
  const std::string payload = R"({
    "id": "chatcmpl-123",
    "object": "chat.completion",
    "created": 1677652288,
    "model": "gpt-4o-mini",
    "choices": [
      {
        "index": 0,
        "message": {
          "role": "assistant",
          "content": "Hello!\nHow can I assist you today?",
          "refusal": null,
          "annotations": []
        },
        "logprobs": null,
        "finish_reason": "stop"
      }
    ],
    "usage": {
      "prompt_tokens": 9,
      "completion_tokens": 12,
      "total_tokens": 21,
      "completion_tokens_details": {
        "reasoning_tokens": 0,
        "accepted_prediction_tokens": 0
      }
    },
    "service_tier": "default"
  })";

  auto out = roundTrip(payload);
  ASSERT_THAT(out.status(), IsOk());
  EXPECT_EQ(nlohmann::json::parse(*out), nlohmann::json::parse(payload));

  // Also verify 1-byte-at-a-time streaming across arbitrary token boundaries.
  auto byte_by_byte = roundTrip(payload, /*chunk_size=*/1);
  ASSERT_THAT(byte_by_byte.status(), IsOk());
  EXPECT_EQ(nlohmann::json::parse(*byte_by_byte), nlohmann::json::parse(payload));
}

TEST_F(FlatteningJsonCodecTest, RoundTripsEmptyContainersAndScalars) {
  for (absl::string_view doc : {
           "{}",
           "[]",
           "[[]]",
           "[[],{},[{}]]",
           R"({"a":[],"b":{},"c":[{},[]],"d":true,"e":false,"f":null,"g":-42,"h":3.5})",
           R"("root string")",
           "12345",
           "true",
           "null",
       }) {
    auto out = roundTrip(doc);
    ASSERT_THAT(out.status(), IsOk()) << "Failed on document: " << doc;
    EXPECT_EQ(nlohmann::json::parse(*out), nlohmann::json::parse(doc))
        << "Mismatch on document: " << doc << ", serialized: " << *out;
  }
}

TEST_F(FlatteningJsonCodecTest, StreamsStringsAcrossOnDataChunksAndCoalescesOnSerialize) {
  FlatteningJsonDecoder decoder;
  std::vector<FlattenJsonField> fields;

  // Split a string value across three onData calls (including one where only the closing quote
  // arrives), followed by an empty string in a single onData call.
  const std::vector<absl::string_view> parts = {
      absl::string_view(R"({"long":"01234567)"),
      absl::string_view(R"(89abcdef\nmore)"),
      absl::string_view(R"(","empty":""})"),
  };
  for (size_t i = 0; i < parts.size(); ++i) {
    Buffer::OwnedImpl buf(parts[i]);
    auto batch_or = decoder.onData(buf, /*end_stream=*/(i + 1 == parts.size()));
    ASSERT_THAT(batch_or.status(), IsOk());
    for (FlattenJsonField& f : *batch_or) {
      fields.push_back(std::move(f));
    }
  }

  // Expect 3 chunks for "long" (partial, partial, final empty closing chunk) + 1 chunk for "empty"
  // = 4 FlattenJsonFields.
  ASSERT_EQ(fields.size(), 4);
  for (size_t i = 0; i < 3; ++i) {
    ASSERT_EQ(fields[i].field_path().size(), 1);
    EXPECT_EQ(absl::get<std::string>(fields[i].field_path()[0]), "long");
  }
  EXPECT_EQ(fields[0].node(), "01234567");
  EXPECT_TRUE(fields[0].is_partial());
  EXPECT_EQ(fields[1].node(), "89abcdef\nmore");
  EXPECT_TRUE(fields[1].is_partial());
  EXPECT_EQ(fields[2].node(), "");
  EXPECT_FALSE(fields[2].is_partial());

  EXPECT_EQ(absl::get<std::string>(fields[3].field_path()[0]), "empty");
  EXPECT_EQ(fields[3].node(), "");
  EXPECT_FALSE(fields[3].is_partial());

  // Serializing those chunked fields coalesces them back into the original strings.
  ASSERT_THAT(serializeBatches({fields}), IsOk());
  EXPECT_EQ(nlohmann::json::parse(bridge_.injected_.toString()),
            nlohmann::json::parse(R"({"long":"0123456789abcdef\nmore","empty":""})"));
}

TEST_F(FlatteningJsonCodecTest, RejectsInvalidAndTruncatedJson) {
  // Malformed syntax.
  EXPECT_THAT(roundTrip(R"({"a": })").status(), HasStatusCode(absl::StatusCode::kInvalidArgument));
  // Duplicate keys.
  EXPECT_THAT(roundTrip(R"({"a": 1, "a": 2})").status(),
              HasStatusCode(absl::StatusCode::kInvalidArgument));
  // Truncated JSON object.
  EXPECT_THAT(roundTrip(R"({"a": 1)").status(), HasStatusCode(absl::StatusCode::kInvalidArgument));
  // Empty document.
  EXPECT_THAT(roundTrip("").status(), HasStatusCode(absl::StatusCode::kInvalidArgument));
  // Unrepresentable float overflow.
  EXPECT_THAT(roundTrip(R"({"a": 1e400})").status(),
              HasStatusCode(absl::StatusCode::kInvalidArgument));
}

TEST_F(FlatteningJsonCodecTest, SerializerHandlesEmptyStreamAndRejectsConflictingPaths) {
  // Empty batch stream emits "{}" on finish().
  ASSERT_THAT(serializeBatches({}), IsOk());
  EXPECT_EQ(bridge_.injected_.toString(), "{}");

  // Conflicting container type at shared prefix ("a" used as object then as array).
  bridge_.injected_.drain(bridge_.injected_.length());
  std::vector<FlattenJsonField> conflicting = {
      FlattenJsonField({FieldPathSegment{"a"}, FieldPathSegment{"key"}}, nlohmann::json(1)),
      FlattenJsonField({FieldPathSegment{"a"}, FieldPathSegment{size_t{0}}}, nlohmann::json(2)),
  };
  EXPECT_THAT(serializeBatches({conflicting}), HasStatusCode(absl::StatusCode::kInvalidArgument));
}

FlattenJsonField field(std::vector<FieldPathSegment> path, nlohmann::json node,
                       bool is_partial = false) {
  return FlattenJsonField(std::move(path), std::move(node), is_partial);
}

// Documents covering nesting, empty containers at every depth, root scalars, unicode and number
// edge cases, plus a trimmed Vertex AI Gemini response.
std::vector<std::string> codecDocuments() {
  return {
      R"({"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}]},"finishReason":"STOP","avgLogprobs":-0.013967220485210419}],"usageMetadata":{"promptTokenCount":19,"candidatesTokenCount":5,"totalTokenCount":24,"promptTokensDetails":[{"modality":"TEXT","tokenCount":19}]},"modelVersion":"gemini-2.5-flash","responseId":"OBm0atnIFMuSsbwPiefy0Qk"})",
      R"({"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!\nHow can I help?","tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{\"a\":1}"}}]},"finish_reason":"stop"}]})",
      "[[1,2],[3,[4,[]]],[]]",
      R"({"a":[{"b":[{}]},[[{"c":null}]]],"d":{"e":{"f":[]}},"g":[[],{}]})",
      "{}",
      "[]",
      "[[]]",
      "[{}]",
      R"("root string")",
      "12345",
      "-3.25",
      "true",
      "null",
      R"({"text":"caf\u00e9 \ud83d\ude00 \u4e2d\u6587 ok","raw":"déjà vu 😀","esc":"line\nbreak\t\"q\" \\ /"})",
      R"({"big":18446744073709551615,"neg":-9223372036854775808,"f":1.5e10,"g":0.1,"z":0})",
  };
}

TEST_F(FlatteningJsonCodecTest, UnflattenRebuildsDecodedDocuments) {
  for (const std::string& doc : codecDocuments()) {
    for (size_t chunk_size : {size_t{0}, size_t{1}, size_t{7}}) {
      auto fields = decodeFields(doc, chunk_size);
      ASSERT_THAT(fields.status(), IsOk()) << doc;
      auto rebuilt = unflattenJson(*fields);
      ASSERT_THAT(rebuilt.status(), IsOk()) << doc << " in chunks of " << chunk_size;
      EXPECT_EQ(*rebuilt, nlohmann::json::parse(doc)) << doc << " in chunks of " << chunk_size;
    }
  }
}

// Chunk boundaries can fall inside an escape or a multi-byte character.
TEST_F(FlatteningJsonCodecTest, DecodedChunksReserializeToTheSameDocument) {
  for (const std::string& doc : codecDocuments()) {
    for (size_t chunk_size : {size_t{1}, size_t{7}}) {
      auto out = roundTrip(doc, chunk_size);
      ASSERT_THAT(out.status(), IsOk()) << doc << " in chunks of " << chunk_size;
      EXPECT_EQ(nlohmann::json::parse(*out), nlohmann::json::parse(doc))
          << doc << " in chunks of " << chunk_size;
    }
  }
}

TEST_F(FlatteningJsonCodecTest, FlattenedDocumentsSerializeToTheirCompactDump) {
  for (const std::string& doc : codecDocuments()) {
    const nlohmann::json parsed = nlohmann::json::parse(doc);
    bridge_.injected_.drain(bridge_.injected_.length());
    ASSERT_THAT(serializeBatches({flattenJson(parsed)}), IsOk()) << doc;
    EXPECT_EQ(bridge_.injected_.toString(), parsed.dump()) << doc;
  }
}

TEST_F(FlatteningJsonCodecTest, FlattenAndUnflattenAreInverses) {
  for (const std::string& doc : codecDocuments()) {
    const nlohmann::json parsed = nlohmann::json::parse(doc);
    auto rebuilt = unflattenJson(flattenJson(parsed));
    ASSERT_THAT(rebuilt.status(), IsOk()) << doc;
    EXPECT_EQ(*rebuilt, parsed) << doc;
  }

  // External references are leaves like any other and survive the trip.
  const nlohmann::json with_ref = {
      {"prompt", JsonWithExtBuf::makeExternalRef({/*offset=*/3, /*length=*/9})}};
  auto rebuilt = unflattenJson(flattenJson(with_ref));
  ASSERT_THAT(rebuilt.status(), IsOk());
  EXPECT_EQ(*rebuilt, with_ref);
}

TEST_F(FlatteningJsonCodecTest, FlattenEmitsLeavesInDocumentOrder) {
  const nlohmann::json doc = nlohmann::json::parse(R"({"b":[[],{"c":1}],"a":{},"d":[["x"]]})");
  const std::vector<FlattenJsonField> expected = {
      field({"a"}, nlohmann::json::object()),
      field({"b", size_t{0}}, nlohmann::json::array()),
      field({"b", size_t{1}, "c"}, 1),
      field({"d", size_t{0}, size_t{0}}, "x"),
  };
  EXPECT_EQ(flattenJson(doc), expected);

  EXPECT_EQ(flattenJson(nlohmann::json(42)), std::vector<FlattenJsonField>{field({}, 42)});
  EXPECT_EQ(flattenJson(nlohmann::json::object()),
            std::vector<FlattenJsonField>{field({}, nlohmann::json::object())});
}

TEST_F(FlatteningJsonCodecTest, UnflattenConcatenatesPartialStringChunks) {
  const std::vector<FlattenJsonField> fields = {
      field({"a", size_t{0}}, "caf", /*is_partial=*/true),
      field({"a", size_t{0}}, "\xc3", /*is_partial=*/true),
      field({"a", size_t{0}}, "\xa9!", /*is_partial=*/true),
      field({"a", size_t{0}}, ""),
      field({"a", size_t{1}}, "whole"),
      field({"b"}, "x", /*is_partial=*/true),
      field({"b"}, "y"),
  };
  auto rebuilt = unflattenJson(fields);
  ASSERT_THAT(rebuilt.status(), IsOk());
  EXPECT_EQ(*rebuilt, nlohmann::json::parse(R"({"a":["café!","whole"],"b":"xy"})"));

  auto root = unflattenJson(
      std::vector<FlattenJsonField>{field({}, "ro", /*is_partial=*/true), field({}, "ot")});
  ASSERT_THAT(root.status(), IsOk());
  EXPECT_EQ(*root, "root");
}

TEST_F(FlatteningJsonCodecTest, UnflattenRejectsInconsistentSequences) {
  const nlohmann::json empty_object = nlohmann::json::object();
  const std::vector<std::pair<std::string, std::vector<FlattenJsonField>>> cases = {
      {"no fields", {}},
      {"two roots", {field({}, 1), field({}, 2)}},
      {"field after a root scalar", {field({}, 1), field({"a"}, 2)}},
      {"repeated leaf", {field({"a"}, 1), field({"a"}, 2)}},
      {"repeated key", {field({"a"}, 1), field({"b"}, 2), field({"a"}, 3)}},
      {"child of a leaf", {field({"a"}, 1), field({"a", "b"}, 2)}},
      {"child of an empty container", {field({"a"}, empty_object), field({"a", "b"}, 2)}},
      {"leaf over a container", {field({"a", "b"}, 1), field({"a"}, 2)}},
      {"array not starting at 0", {field({size_t{1}}, 1)}},
      {"skipped index", {field({size_t{0}}, 1), field({size_t{2}}, 2)}},
      {"revisited index",
       {field({size_t{0}, "x"}, 1), field({size_t{1}}, 2), field({size_t{0}, "y"}, 3)}},
      {"key into an array", {field({size_t{0}}, 1), field({"a"}, 2)}},
      {"index into an object", {field({"a"}, 1), field({size_t{0}}, 2)}},
      {"non-empty container leaf", {field({"a"}, nlohmann::json{{"b", 1}})}},
      {"partial non-string", {field({"a"}, 1, /*is_partial=*/true), field({"a"}, "x")}},
      {"partial interrupted by another path",
       {field({"a"}, "x", /*is_partial=*/true), field({"b"}, "y")}},
      {"partial interrupted by a non-string",
       {field({"a"}, "x", /*is_partial=*/true), field({"a"}, 1)}},
      {"trailing partial", {field({"a"}, "x", /*is_partial=*/true)}},
  };
  for (const auto& [name, fields] : cases) {
    EXPECT_THAT(unflattenJson(fields).status(), HasStatusCode(absl::StatusCode::kInvalidArgument))
        << name;
  }
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
