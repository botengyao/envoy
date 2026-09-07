#include "source/extensions/filters/http/ai_protocol_manager/request_protocol_classifier.h"

#include <cstddef>
#include <string>
#include <utility>

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

namespace {

constexpr absl::string_view GeminiModelsMarker{"/models/"};
constexpr absl::string_view GeminiGenerateContentSuffix{":generateContent"};
constexpr absl::string_view GeminiStreamGenerateContentSuffix{":streamGenerateContent"};
constexpr absl::string_view BedrockModelPrefix{"/model/"};
constexpr absl::string_view BedrockInvokeSuffix{"/invoke"};
constexpr absl::string_view BedrockStreamInvokeSuffix{"/invoke-with-response-stream"};
constexpr absl::string_view BedrockAuthorityPrefix{"bedrock-runtime."};
constexpr size_t MaxPathModelSize = 256;

enum class AuthorityKind { Unknown, OpenAi, Anthropic, Gemini, Bedrock };

absl::string_view pathWithoutQuery(absl::string_view path) {
  return path.substr(0, path.find('?'));
}

RequestProtocolClassification classification(ApiProtocol protocol) {
  return {protocol, DetectionSource::AuthorityPath, std::nullopt, std::nullopt};
}

AuthorityKind classifyAuthority(absl::string_view authority) {
  std::string host = absl::AsciiStrToLower(authority);
  // Direct-provider names are DNS authorities. Bracketed IPv6 and authorities
  // with userinfo are necessarily custom/unknown here.
  if (host.empty() || host.front() == '[' || host.find('@') != std::string::npos ||
      host.find('/') != std::string::npos) {
    return AuthorityKind::Unknown;
  }
  const size_t colon = host.find(':');
  if (colon != std::string::npos) {
    // More than one colon is not a DNS host plus port.
    const absl::string_view port(host.data() + colon + 1, host.size() - colon - 1);
    if (colon == 0 || port.empty() ||
        port.find_first_not_of("0123456789") != absl::string_view::npos ||
        host.find(':', colon + 1) != std::string::npos) {
      return AuthorityKind::Unknown;
    }
    host.resize(colon);
  }
  if (!host.empty() && host.back() == '.') {
    host.pop_back();
  }
  if (host == "api.openai.com") {
    return AuthorityKind::OpenAi;
  }
  if (host == "api.anthropic.com") {
    return AuthorityKind::Anthropic;
  }
  if (host == "generativelanguage.googleapis.com") {
    return AuthorityKind::Gemini;
  }
  if (absl::StartsWith(host, BedrockAuthorityPrefix) &&
      host.size() > BedrockAuthorityPrefix.size()) {
    return AuthorityKind::Bedrock;
  }
  return AuthorityKind::Unknown;
}

bool authorityAllows(AuthorityKind authority, ApiProtocol protocol) {
  switch (authority) {
  case AuthorityKind::OpenAi:
    return protocol == ApiProtocol::OpenAiChatCompletions ||
           protocol == ApiProtocol::OpenAiResponses;
  case AuthorityKind::Anthropic:
    return protocol == ApiProtocol::AnthropicMessages;
  case AuthorityKind::Gemini:
    return protocol == ApiProtocol::GeminiGenerateContent;
  case AuthorityKind::Bedrock:
    return false;
  case AuthorityKind::Unknown:
    return false;
  }
  return false;
}

RequestProtocolClassification classifyGeminiPath(absl::string_view path) {
  bool streaming = false;
  size_t operation_start = absl::string_view::npos;
  if (absl::EndsWith(path, GeminiStreamGenerateContentSuffix)) {
    streaming = true;
    operation_start = path.size() - GeminiStreamGenerateContentSuffix.size();
  } else if (absl::EndsWith(path, GeminiGenerateContentSuffix)) {
    operation_start = path.size() - GeminiGenerateContentSuffix.size();
  } else {
    return {};
  }

  const size_t marker = path.rfind(GeminiModelsMarker, operation_start);
  if (marker == absl::string_view::npos) {
    return {};
  }
  const size_t model_start = marker + GeminiModelsMarker.size();
  if (model_start >= operation_start) {
    return {};
  }
  const absl::string_view model = path.substr(model_start, operation_start - model_start);
  if (model.size() > MaxPathModelSize || model.find('/') != absl::string_view::npos ||
      model.find(':') != absl::string_view::npos) {
    return {};
  }

  RequestProtocolClassification result = classification(ApiProtocol::GeminiGenerateContent);
  result.model = std::string(model);
  result.streaming = streaming;
  return result;
}

RequestProtocolClassification classifyOperationPath(absl::string_view path) {
  const absl::string_view operation_path = pathWithoutQuery(path);
  if (!absl::StartsWith(operation_path, "/")) {
    return {};
  }

  RequestProtocolClassification result = classifyGeminiPath(operation_path);
  if (result.matched()) {
    return result;
  }
  if (absl::EndsWith(operation_path, "/chat/completions")) {
    return classification(ApiProtocol::OpenAiChatCompletions);
  }
  if (absl::EndsWith(operation_path, "/responses")) {
    return classification(ApiProtocol::OpenAiResponses);
  }
  if (absl::EndsWith(operation_path, "/messages")) {
    return classification(ApiProtocol::AnthropicMessages);
  }
  return {};
}

RequestProtocolClassification
selectKnownProtocol(ApiProtocol protocol, DetectionSource source,
                    const RequestProtocolClassification& path_classification) {
  RequestProtocolClassification result = classification(protocol);
  result.detection_source = source;
  if (path_classification.api_protocol == protocol) {
    result.model = path_classification.model;
    result.streaming = path_classification.streaming;
  }
  return result;
}

bool readBedrockTarget(absl::string_view path, std::string& model, bool& streaming) {
  if (!absl::StartsWith(path, BedrockModelPrefix)) {
    return false;
  }
  size_t operation_start = absl::string_view::npos;
  if (absl::EndsWith(path, BedrockStreamInvokeSuffix)) {
    streaming = true;
    operation_start = path.size() - BedrockStreamInvokeSuffix.size();
  } else if (absl::EndsWith(path, BedrockInvokeSuffix)) {
    streaming = false;
    operation_start = path.size() - BedrockInvokeSuffix.size();
  } else {
    return false;
  }
  const size_t model_start = BedrockModelPrefix.size();
  if (model_start >= operation_start) {
    return false;
  }
  const absl::string_view candidate = path.substr(model_start, operation_start - model_start);
  if (candidate.size() > MaxPathModelSize || candidate.find('/') != absl::string_view::npos) {
    return false;
  }
  model = std::string(candidate);
  return true;
}

} // namespace

RequestProtocolClassification detectRequestProtocol(absl::string_view authority,
                                                    absl::string_view path) {
  const RequestProtocolClassification result = classifyOperationPath(path);
  return result.matched() && authorityAllows(classifyAuthority(authority), result.api_protocol)
             ? result
             : RequestProtocolClassification{};
}

RequestProtocolClassification classifyRequestPath(absl::string_view path) {
  return classifyOperationPath(path);
}

void applyRequestTarget(absl::string_view path, ApiProtocol protocol, RequestInfo& info) {
  const absl::string_view operation_path = pathWithoutQuery(path);
  if (protocol == ApiProtocol::GeminiGenerateContent) {
    const RequestProtocolClassification gemini = classifyGeminiPath(operation_path);
    if (gemini.matched()) {
      info.model = gemini.model;
      info.streaming = gemini.streaming;
    }
    return;
  }
  if (protocol == ApiProtocol::AnthropicMessages) {
    std::string model;
    bool streaming = false;
    if (readBedrockTarget(operation_path, model, streaming)) {
      info.model = std::move(model);
      info.streaming = streaming;
    }
  }
}

RequestProtocolClassification selectRequestProtocol(ApiProtocol route_protocol,
                                                    ApiProtocol config_default_protocol,
                                                    absl::string_view authority,
                                                    absl::string_view path,
                                                    ApiProtocol body_protocol) {
  const RequestProtocolClassification path_classification = detectRequestProtocol(authority, path);
  if (route_protocol != ApiProtocol::Unspecified) {
    RequestProtocolClassification result =
        selectKnownProtocol(route_protocol, DetectionSource::Route, path_classification);
    RequestInfo target_info;
    applyRequestTarget(path, route_protocol, target_info);
    result.model = std::move(target_info.model);
    result.streaming = target_info.streaming;
    return result;
  }
  if (config_default_protocol != ApiProtocol::Unspecified) {
    RequestProtocolClassification result = selectKnownProtocol(
        config_default_protocol, DetectionSource::ConfigDefault, path_classification);
    RequestInfo target_info;
    applyRequestTarget(path, config_default_protocol, target_info);
    result.model = std::move(target_info.model);
    result.streaming = target_info.streaming;
    return result;
  }
  if (path_classification.matched()) {
    return path_classification;
  }
  if (body_protocol != ApiProtocol::Unspecified) {
    RequestProtocolClassification result =
        selectKnownProtocol(body_protocol, DetectionSource::Body, path_classification);
    RequestInfo target_info;
    applyRequestTarget(path, body_protocol, target_info);
    result.model = std::move(target_info.model);
    result.streaming = target_info.streaming;
    return result;
  }
  return {};
}

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
