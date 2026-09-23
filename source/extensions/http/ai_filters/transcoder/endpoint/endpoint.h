#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/pure.h"
#include "envoy/extensions/http/ai_filters/transcoder/v3/transcoder.pb.h"
#include "envoy/http/header_map.h"

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace AiFilters {
namespace Transcoder {

// How the upstream request differs from the client's, beyond the body's protocol.
struct UpstreamEnvelope {
  // The request path, query included.
  std::string path;
  // Headers to set, replacing any value already present.
  std::vector<std::pair<Http::LowerCaseString, std::string>> set_headers;
  // Headers to remove.
  std::vector<Http::LowerCaseString> remove_headers;
  // Whether apply() changed the body.
  bool body_changed{false};
};

// Where an upstream serves its protocol: the request path, and the envelope fields the endpoint
// adds to or takes out of the protocol's body. Vertex AI, for example, carries the model in the
// path and wants `anthropic_version` in an Anthropic body.
class Endpoint {
public:
  virtual ~Endpoint() = default;

  // `body` is already in the upstream's protocol. Moves endpoint-carried fields out of it, adds
  // the endpoint's own fields, and returns the envelope. `model` is the model to call; `stream`
  // whether the client asked for a streamed response.
  virtual absl::StatusOr<UpstreamEnvelope> apply(nlohmann::json& body, absl::string_view model,
                                                 bool stream) const PURE;
};

using EndpointConstPtr = std::unique_ptr<const Endpoint>;

// The endpoint an upstream leg is configured with.
absl::StatusOr<EndpointConstPtr>
createEndpoint(const envoy::extensions::http::ai_filters::transcoder::v3::Upstream& config);

// Percent-encodes `model` as a single path segment. Google's front end rejects a literal `@`, as
// in Vertex's `claude-sonnet-4-5@20250929`. InvalidArgument for an empty or over-long name, or one
// holding a character no model name has (`/`, `?`, `#`, `%`, whitespace, controls).
absl::StatusOr<std::string> encodeModelPathSegment(absl::string_view model);

} // namespace Transcoder
} // namespace AiFilters
} // namespace Extensions
} // namespace Envoy
