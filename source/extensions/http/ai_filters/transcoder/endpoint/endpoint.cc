#include "source/extensions/http/ai_filters/transcoder/endpoint/endpoint.h"

#include <initializer_list>

#include "source/common/common/macros.h"
#include "source/common/http/headers.h"

#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/strip.h"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

namespace {

using envoy::extensions::http::ai_filters::transcoder::v3::Native;
using envoy::extensions::http::ai_filters::transcoder::v3::Upstream;
using envoy::extensions::http::ai_filters::transcoder::v3::VertexAi;
using envoy::type::ai::v3::LLMProtocol;

constexpr size_t MaxModelNameLength = 256;
constexpr absl::string_view DefaultVertexAnthropicVersion = "vertex-2023-10-16";
constexpr absl::string_view NativeAnthropicVersion = "2023-06-01";

const Http::LowerCaseString& anthropicVersionHeader() {
  CONSTRUCT_ON_FIRST_USE(Http::LowerCaseString, "anthropic-version");
}

// Characters that would end the path segment they sit in, or that no path may carry raw.
bool isSegmentBreaking(char c) {
  return c == '/' || c == '?' || c == '#' || absl::ascii_isspace(c) || absl::ascii_iscntrl(c) ||
         !absl::ascii_isascii(c);
}

bool isUnreserved(char c) {
  return absl::ascii_isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

absl::Status validateConfigSegment(absl::string_view field, absl::string_view value) {
  if (value == "." || value == "..") {
    return absl::InvalidArgumentError(absl::StrCat(field, " must not be a dot segment"));
  }
  for (const char c : value) {
    if (isSegmentBreaking(c)) {
      return absl::InvalidArgumentError(
          absl::StrCat(field, " must not contain '/', '?', '#', whitespace, control, or non-ASCII "
                              "characters"));
    }
  }
  return absl::OkStatus();
}

absl::Status validatePathPrefix(absl::string_view prefix) {
  if (prefix.empty()) {
    return absl::OkStatus();
  }
  const absl::Status invalid = absl::InvalidArgumentError(
      absl::StrCat("native.path_prefix '", prefix, "' must be a sequence of '/segment'"));
  if (!absl::ConsumePrefix(&prefix, "/")) {
    return invalid;
  }
  for (const absl::string_view segment : absl::StrSplit(prefix, '/')) {
    if (segment.empty() || !validateConfigSegment("native.path_prefix", segment).ok()) {
      return invalid;
    }
  }
  return absl::OkStatus();
}

absl::Status validateRequest(const nlohmann::json& body, absl::string_view model) {
  if (!body.is_object()) {
    return absl::InvalidArgumentError("upstream request body must be a JSON object");
  }
  if (model.empty()) {
    return absl::InvalidArgumentError("upstream request has no model");
  }
  return absl::OkStatus();
}

UpstreamEnvelope newEnvelope(std::string path, bool sets_version_header = false) {
  UpstreamEnvelope envelope;
  envelope.path = std::move(path);
  envelope.remove_headers.push_back(Http::CustomHeaders::get().AcceptEncoding);
  if (sets_version_header) {
    envelope.set_headers.emplace_back(anthropicVersionHeader(),
                                      std::string(NativeAnthropicVersion));
  } else {
    envelope.remove_headers.push_back(anthropicVersionHeader());
  }
  return envelope;
}

// Returns whether any of `fields` was present.
bool eraseFields(nlohmann::json& body, std::initializer_list<const char*> fields) {
  bool erased = false;
  for (const char* field : fields) {
    if (body.erase(field) > 0) {
      erased = true;
    }
  }
  return erased;
}

// Returns whether `body[field]` differed from `value`.
bool setStringField(nlohmann::json& body, const char* field, absl::string_view value) {
  const auto it = body.find(field);
  if (it != body.end() && it->is_string() && it->get_ref<const std::string&>() == value) {
    return false;
  }
  body[field] = std::string(value);
  return true;
}

// Returns whether `body.stream` had to change. A converted body can carry a stray `stream` (a
// Gemini client's mode is in its path, not its body), and the upstream must stream as asked.
bool alignStream(nlohmann::json& body, bool stream) {
  const auto it = body.find("stream");
  const bool streaming = it != body.end() && it->is_boolean() && it->get<bool>();
  if (streaming == stream) {
    return false;
  }
  body["stream"] = stream;
  return true;
}

absl::Status validateConfiguredModel(absl::string_view model) {
  if (model.empty()) {
    return absl::OkStatus();
  }
  if (absl::StatusOr<std::string> segment = encodeModelPathSegment(model); !segment.ok()) {
    return absl::InvalidArgumentError(absl::StrCat("model: ", segment.status().message()));
  }
  return absl::OkStatus();
}

// Gemini on Vertex AI or the Gemini API, where the path carries the model and the streaming mode.
class GeminiEndpoint : public Endpoint {
public:
  explicit GeminiEndpoint(std::string models_path) : models_path_(std::move(models_path)) {}

  absl::StatusOr<UpstreamEnvelope> apply(nlohmann::json& body, absl::string_view model,
                                         bool stream) const override {
    if (absl::Status status = validateRequest(body, model); !status.ok()) {
      return status;
    }
    absl::StatusOr<std::string> segment = encodeModelPathSegment(model);
    if (!segment.ok()) {
      return segment.status();
    }
    UpstreamEnvelope envelope = newEnvelope(absl::StrCat(
        models_path_, *segment, stream ? ":streamGenerateContent?alt=sse" : ":generateContent"));
    envelope.body_changed = eraseFields(body, {"model", "stream", "stream_options"});
    return envelope;
  }

private:
  const std::string models_path_;
};

// Anthropic Messages on Vertex AI: the path carries the model, and the body keeps `stream`, which
// must agree with the path.
class VertexAnthropicEndpoint : public Endpoint {
public:
  VertexAnthropicEndpoint(std::string models_path, std::string anthropic_version)
      : models_path_(std::move(models_path)), anthropic_version_(std::move(anthropic_version)) {}

  absl::StatusOr<UpstreamEnvelope> apply(nlohmann::json& body, absl::string_view model,
                                         bool stream) const override {
    if (absl::Status status = validateRequest(body, model); !status.ok()) {
      return status;
    }
    absl::StatusOr<std::string> segment = encodeModelPathSegment(model);
    if (!segment.ok()) {
      return segment.status();
    }
    UpstreamEnvelope envelope = newEnvelope(
        absl::StrCat(models_path_, *segment, stream ? ":streamRawPredict" : ":rawPredict"));
    const bool erased = eraseFields(body, {"model"});
    const bool versioned = setStringField(body, "anthropic_version", anthropic_version_);
    const bool aligned = alignStream(body, stream);
    envelope.body_changed = erased || versioned || aligned;
    return envelope;
  }

private:
  const std::string models_path_;
  const std::string anthropic_version_;
};

// An endpoint with one path for every model, which the body names.
class ModelInBodyEndpoint : public Endpoint {
public:
  ModelInBodyEndpoint(std::string path, bool sets_version_header)
      : path_(std::move(path)), sets_version_header_(sets_version_header) {}

  absl::StatusOr<UpstreamEnvelope> apply(nlohmann::json& body, absl::string_view model,
                                         bool stream) const override {
    if (absl::Status status = validateRequest(body, model); !status.ok()) {
      return status;
    }
    UpstreamEnvelope envelope = newEnvelope(path_, sets_version_header_);
    const bool renamed = setStringField(body, "model", model);
    const bool aligned = alignStream(body, stream);
    // A Vertex or Bedrock envelope field, which the native API rejects.
    const bool unwrapped = sets_version_header_ && body.erase("anthropic_version") > 0;
    envelope.body_changed = renamed || aligned || unwrapped;
    return envelope;
  }

private:
  const std::string path_;
  const bool sets_version_header_;
};

absl::Status unsupportedProtocol(absl::string_view endpoint, LLMProtocol protocol) {
  return absl::InvalidArgumentError(absl::StrCat(endpoint, " endpoint does not serve ",
                                                 envoy::type::ai::v3::LLMProtocol_Name(protocol)));
}

absl::StatusOr<EndpointConstPtr>
createVertexAiEndpoint(LLMProtocol protocol, const VertexAi& config, absl::string_view model) {
  if (config.project().empty() != config.location().empty()) {
    return absl::InvalidArgumentError(
        "vertex_ai needs both project and location, or neither for express mode");
  }
  if (absl::Status status = validateConfigSegment("vertex_ai.project", config.project());
      !status.ok()) {
    return status;
  }
  if (absl::Status status = validateConfigSegment("vertex_ai.location", config.location());
      !status.ok()) {
    return status;
  }
  const bool express = config.project().empty();
  const std::string base =
      express ? "/v1"
              : absl::StrCat("/v1/projects/", config.project(), "/locations/", config.location());
  switch (protocol) {
  case envoy::type::ai::v3::GEMINI_GENERATE_CONTENT:
    if (absl::Status status = validateConfiguredModel(model); !status.ok()) {
      return status;
    }
    return std::make_unique<GeminiEndpoint>(absl::StrCat(base, "/publishers/google/models/"));
  case envoy::type::ai::v3::ANTHROPIC_MESSAGES:
    // Express mode authenticates with API keys, which Vertex's Claude models do not accept.
    if (express) {
      return absl::InvalidArgumentError("vertex_ai express mode does not serve "
                                        "ANTHROPIC_MESSAGES; set project and location");
    }
    if (absl::Status status = validateConfiguredModel(model); !status.ok()) {
      return status;
    }
    return std::make_unique<VertexAnthropicEndpoint>(
        absl::StrCat(base, "/publishers/anthropic/models/"),
        config.anthropic_version().empty() ? std::string(DefaultVertexAnthropicVersion)
                                           : config.anthropic_version());
  case envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS:
    if (express) {
      return absl::InvalidArgumentError("vertex_ai express mode does not serve "
                                        "OPENAI_CHAT_COMPLETIONS; set project and location");
    }
    return std::make_unique<ModelInBodyEndpoint>(
        absl::StrCat(base, "/endpoints/openapi/chat/completions"), /*sets_version_header=*/false);
  default:
    return unsupportedProtocol("vertex_ai", protocol);
  }
}

absl::StatusOr<EndpointConstPtr> createNativeEndpoint(LLMProtocol protocol, const Native& config,
                                                      absl::string_view model) {
  if (absl::Status status = validatePathPrefix(config.path_prefix()); !status.ok()) {
    return status;
  }
  const auto prefix = [&config](absl::string_view default_prefix) -> absl::string_view {
    return config.path_prefix().empty() ? default_prefix : config.path_prefix();
  };
  switch (protocol) {
  case envoy::type::ai::v3::OPENAI_CHAT_COMPLETIONS:
    return std::make_unique<ModelInBodyEndpoint>(absl::StrCat(prefix("/v1"), "/chat/completions"),
                                                 /*sets_version_header=*/false);
  case envoy::type::ai::v3::ANTHROPIC_MESSAGES:
    return std::make_unique<ModelInBodyEndpoint>(absl::StrCat(prefix("/v1"), "/messages"),
                                                 /*sets_version_header=*/true);
  case envoy::type::ai::v3::GEMINI_GENERATE_CONTENT:
    if (absl::Status status = validateConfiguredModel(model); !status.ok()) {
      return status;
    }
    return std::make_unique<GeminiEndpoint>(absl::StrCat(prefix("/v1beta"), "/models/"));
  default:
    return unsupportedProtocol("native", protocol);
  }
}

} // namespace

absl::StatusOr<EndpointConstPtr> createEndpoint(const Upstream& config) {
  if (config.has_vertex_ai()) {
    return createVertexAiEndpoint(config.llm_protocol(), config.vertex_ai(), config.model());
  }
  if (config.has_native()) {
    return createNativeEndpoint(config.llm_protocol(), config.native(), config.model());
  }
  return absl::InvalidArgumentError("upstream has no endpoint");
}

absl::StatusOr<std::string> encodeModelPathSegment(absl::string_view model) {
  if (model.empty() || model.size() > MaxModelNameLength) {
    return absl::InvalidArgumentError(
        absl::StrCat("model name must be 1 to ", MaxModelNameLength, " bytes"));
  }
  // Dot segments are resolved away by path normalization, percent-encoded or not.
  if (model == "." || model == "..") {
    return absl::InvalidArgumentError("model name must not be a dot segment");
  }
  constexpr absl::string_view HexDigits = "0123456789ABCDEF";
  std::string encoded;
  encoded.reserve(model.size());
  for (const char c : model) {
    if (c == '%' || isSegmentBreaking(c)) {
      return absl::InvalidArgumentError(
          "model name holds a character not allowed in a URL path segment");
    }
    if (isUnreserved(c)) {
      encoded.push_back(c);
      continue;
    }
    const auto byte = static_cast<unsigned char>(c);
    encoded.push_back('%');
    encoded.push_back(HexDigits[byte >> 4]);
    encoded.push_back(HexDigits[byte & 0xF]);
  }
  return encoded;
}

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
