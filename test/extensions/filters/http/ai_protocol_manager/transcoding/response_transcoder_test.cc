#include <memory>
#include <utility>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/transcoding/anthropic_messages.h"
#include "source/extensions/filters/http/ai_protocol_manager/transcoding/gemini_generate_content.h"
#include "source/extensions/filters/http/ai_protocol_manager/transcoding/response_transcoder.h"

#include "absl/status/status.h"
#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace {

using nlohmann::json;

ResponseContext context() {
  ResponseContext c;
  c.model = "requested-model";
  c.created = 1700000000;
  return c;
}

class ScriptedTranscoder : public ResponseStreamTranscoder {
public:
  ScriptedTranscoder(bool fail_frame, bool fail_end)
      : fail_frame_(fail_frame), fail_end_(fail_end) {}

  absl::Status onFrame(SseFrame frame, std::vector<SseFrame>& out) override {
    if (fail_frame_) {
      return absl::InvalidArgumentError("frame");
    }
    out.push_back(std::move(frame));
    return absl::OkStatus();
  }

  absl::Status onEnd(std::vector<SseFrame>& out) override {
    if (fail_end_) {
      return absl::InvalidArgumentError("end");
    }
    out.push_back(SseFrame::ofData("end"));
    return absl::OkStatus();
  }

private:
  const bool fail_frame_;
  const bool fail_end_;
};

template <bool FailFrame, bool FailEnd>
ResponseStreamTranscoderPtr scripted(const ResponseContext&) {
  return std::make_unique<ScriptedTranscoder>(FailFrame, FailEnd);
}

const ResponseCodec Echo{scripted<false, false>, scripted<false, false>, nullptr, nullptr};
const ResponseCodec FailsOnFrame{scripted<true, false>, scripted<true, false>, nullptr, nullptr};
const ResponseCodec FailsOnEnd{scripted<false, true>, scripted<false, true>, nullptr, nullptr};

TEST(ResponseTranscoderTest, ViaIrBetweenIrAndIrIsIdentity) {
  EXPECT_EQ(createResponseStreamTranscoderViaIr(nullptr, nullptr, context()), nullptr);
  auto body = transcodeUnaryResponseViaIr(nullptr, nullptr, json{{"a", 1}}, context());
  ASSERT_TRUE(body.ok());
  EXPECT_EQ(*body, (json{{"a", 1}}));
}

TEST(ResponseTranscoderTest, ChainedUnaryStopsAtTheFirstError) {
  EXPECT_FALSE(transcodeUnaryResponseViaIr(&anthropicMessagesResponseCodec(),
                                           &geminiGenerateContentResponseCodec(), json::array(),
                                           context())
                   .ok());
}

TEST(ResponseTranscoderTest, ChainedStreamStopsAtTheFirstError) {
  std::vector<SseFrame> out;
  EXPECT_FALSE(createResponseStreamTranscoderViaIr(&FailsOnFrame, &Echo, context())
                   ->onFrame(SseFrame::ofData("x"), out)
                   .ok());
  EXPECT_FALSE(createResponseStreamTranscoderViaIr(&FailsOnEnd, &Echo, context())->onEnd(out).ok());
  ResponseStreamTranscoderPtr second_fails =
      createResponseStreamTranscoderViaIr(&Echo, &FailsOnFrame, context());
  EXPECT_FALSE(second_fails->onFrame(SseFrame::ofData("x"), out).ok());
  EXPECT_FALSE(second_fails->onEnd(out).ok());
  EXPECT_TRUE(out.empty());
}

} // namespace
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
