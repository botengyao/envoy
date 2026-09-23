#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "envoy/http/header_map.h"

#include "source/extensions/common/ai/request_ir.h"
#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"

#include "nlohmann/json.hpp"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

using RequestIr = ::Envoy::Extensions::Common::Ai::RequestIr;

// Request header changes an AI filter asks for. The manager applies them right before it
// releases the held request headers, so they travel with the body they describe.
// The manager fails the request on an invalid :path or header, or on a set or remove naming a
// pseudo-header or host. A content-length left after the edits is reset to the body it sends.
struct RequestHeaderEdits {
  std::optional<std::string> path;
  std::vector<std::pair<Http::LowerCaseString, std::string>> set;
  std::vector<Http::LowerCaseString> remove;

  bool empty() const { return !path.has_value() && set.empty() && remove.empty(); }

  // Removes, then sets (replacing any existing values), then rewrites :path.
  void apply(Http::RequestHeaderMap& headers) const {
    for (const Http::LowerCaseString& name : remove) {
      headers.remove(name);
    }
    for (const auto& [name, value] : set) {
      headers.setCopy(name, value);
    }
    if (path.has_value()) {
      headers.setPath(*path);
    }
  }
};

// AiRequest represents the structured request payload presented to an AiFilter.
// It wraps a JsonWithExtBuf document as the request payload index.
// AiRequest is non-copyable and non-movable to ensure strict single-ownership semantics;
// ownership transfer across the filter pipeline is expressed via std::unique_ptr<AiRequest>.
//
// The manager forwards the body it received unless a filter edits the document through
// mutableJson() or propagates a request it built itself, in which case it serializes the
// document instead.
class AiRequest {
public:
  // A request built this way is not the received body, so it starts out modified.
  explicit AiRequest(JsonWithExtBuf request_index) : request_index_(std::move(request_index)) {}

  // The request as the manager received it: unmodified until mutableJson() is called.
  static std::unique_ptr<AiRequest> received(JsonWithExtBuf request_index) {
    auto request = std::make_unique<AiRequest>(std::move(request_index));
    request->modified_ = false;
    return request;
  }

  ~AiRequest() = default;

  AiRequest(const AiRequest&) = delete;
  AiRequest& operator=(const AiRequest&) = delete;
  AiRequest(AiRequest&&) = delete;
  AiRequest& operator=(AiRequest&&) = delete;

  // The payload DOM.
  const nlohmann::json& json() const { return request_index_.json(); }

  // The payload DOM for editing. Marks the request modified even if the caller changes nothing,
  // and drops the IR, which would no longer describe the request sent.
  nlohmann::json& mutableJson() {
    modified_ = true;
    ir_.reset();
    return request_index_.json();
  }

  bool modified() const { return modified_; }

  // The whole index, external-buffer references included; only serialization needs it.
  const JsonWithExtBuf& request_index() const { return request_index_; }

  // Moves the index out, leaving an empty document. This counts as a modification.
  JsonWithExtBuf takeRequestIndex() {
    modified_ = true;
    return std::move(request_index_);
  }

  // Header edits never mark the body modified.
  RequestHeaderEdits& headerEdits() { return header_edits_; }
  const RequestHeaderEdits& headerEdits() const { return header_edits_; }

  // The request's internal representation, set by the AI filter that normalizes it (the
  // transcoder's internal leg) for the filters after it; nullptr when none has. The manager
  // publishes this same object to filter state when configured to.
  const RequestIr* ir() const { return ir_.get(); }
  const std::shared_ptr<RequestIr>& sharedIr() const { return ir_; }
  void setIr(std::shared_ptr<RequestIr> ir) { ir_ = std::move(ir); }

  // TODO(penguingao): Implement field streaming (AiRequest::stream, FieldStreamingSpec,
  // and FieldStreamingSession).

private:
  JsonWithExtBuf request_index_;
  RequestHeaderEdits header_edits_;
  std::shared_ptr<RequestIr> ir_;
  bool modified_{true};
};

using AiRequestPtr = std::unique_ptr<AiRequest>;

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
