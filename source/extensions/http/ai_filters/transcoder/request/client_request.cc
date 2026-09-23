#include "source/extensions/http/ai_filters/transcoder/request/client_request.h"

#include "source/common/http/utility.h"

#include "absl/strings/str_cat.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

namespace {

constexpr absl::string_view kModelsSegment = "/models/";

bool isTrue(const nlohmann::json& object, const char* key) {
  auto it = object.find(key);
  return it != object.end() && it->is_boolean() && it->get<bool>();
}

absl::StatusOr<ClientRequest> readFromBody(LLMProtocol protocol, const nlohmann::json& body) {
  if (!body.is_object()) {
    return absl::InvalidArgumentError("request body is not a JSON object");
  }
  auto model = body.find("model");
  if (model == body.end() || !model->is_string() || model->get_ref<const std::string&>().empty()) {
    return absl::InvalidArgumentError("request has no model: 'model' must be a non-empty string");
  }
  ClientRequest client;
  client.model = model->get<std::string>();
  client.stream = isTrue(body, "stream");
  if (protocol == LLMProtocol::OpenAiChatCompletions) {
    auto options = body.find("stream_options");
    client.include_usage =
        options != body.end() && options->is_object() && isTrue(*options, "include_usage");
  }
  return client;
}

// Gemini API and Vertex AI paths alike end in `/models/{model}:{method}`.
absl::StatusOr<ClientRequest> readFromGeminiPath(absl::string_view path) {
  path = Http::Utility::stripQueryStringView(path);
  const size_t models = path.rfind(kModelsSegment);
  if (models == absl::string_view::npos) {
    return absl::InvalidArgumentError(absl::StrCat(
        "request path '", path, "' names no model: expected '.../models/{model}:...'"));
  }
  const absl::string_view resource = path.substr(models + kModelsSegment.size());
  const size_t colon = resource.rfind(':');
  if (colon == absl::string_view::npos || colon == 0) {
    return absl::InvalidArgumentError(absl::StrCat(
        "request path '", path, "' names no model: expected '.../models/{model}:{method}'"));
  }
  ClientRequest client;
  const absl::string_view method = resource.substr(colon + 1);
  if (method == "generateContent") {
    client.stream = false;
  } else if (method == "streamGenerateContent") {
    client.stream = true;
  } else {
    return absl::InvalidArgumentError(
        absl::StrCat("unsupported Gemini method '", method,
                     "': expected 'generateContent' or 'streamGenerateContent'"));
  }
  client.model = Http::Utility::PercentEncoding::decode(resource.substr(0, colon));
  return client;
}

} // namespace

absl::StatusOr<ClientRequest> readClientRequest(LLMProtocol protocol, const nlohmann::json& body,
                                                absl::string_view path) {
  switch (protocol) {
  case LLMProtocol::OpenAiChatCompletions:
  case LLMProtocol::AnthropicMessages:
    return readFromBody(protocol, body);
  case LLMProtocol::GeminiGenerateContent:
    return readFromGeminiPath(path);
  case LLMProtocol::OpenAiResponses:
  case LLMProtocol::Unspecified:
    break;
  }
  return absl::InvalidArgumentError(
      absl::StrCat("cannot read the model of a ",
                   HttpFilters::AiProtocolManager::llmProtocolName(protocol), " request"));
}

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
