#pragma once

#include <optional>
#include <string>

#include "envoy/stream_info/filter_state.h"

#include "source/extensions/filters/http/ai_protocol_manager/json_with_ext_buf.h"
#include "source/extensions/filters/http/ai_protocol_manager/token_usage.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Ai {

// Filter state key of the model an upstream transcoder sends in place of the request's.
inline constexpr absl::string_view UpstreamModelFilterStateKey = "envoy.ai.upstream_model";

// The request's internal representation (IR): a read-only, normalized view of an AI request for
// routing and policy, whatever protocol the client spoke. Nothing is ever sent from it; the
// client's request stays the source of truth. The document's ExternalRef nodes index the
// downstream request body, so a reader outside that buffer sees sizes, not bytes.
class RequestIr : public StreamInfo::FilterState::Object {
public:
  static constexpr absl::string_view FilterStateKey = "envoy.ai.request_ir";

  RequestIr(HttpFilters::AiProtocolManager::LLMProtocol client_protocol, std::string model,
            std::optional<bool> stream,
            std::optional<HttpFilters::AiProtocolManager::JsonWithExtBuf> document);

  HttpFilters::AiProtocolManager::LLMProtocol clientProtocol() const { return client_protocol_; }
  const std::string& model() const { return model_; }
  std::optional<bool> stream() const { return stream_; }

  // The IR document, or nullptr when the request could not be converted to the IR.
  const HttpFilters::AiProtocolManager::JsonWithExtBuf* document() const {
    return document_.has_value() ? &document_.value() : nullptr;
  }

  // StreamInfo::FilterState::Object
  std::optional<std::string> serializeAsString() const override;
  bool hasFieldSupport() const override { return true; }
  FieldType getField(absl::string_view field_name) const override;

private:
  const HttpFilters::AiProtocolManager::LLMProtocol client_protocol_;
  const std::string model_;
  const std::optional<bool> stream_;
  const std::optional<HttpFilters::AiProtocolManager::JsonWithExtBuf> document_;
};

} // namespace Ai
} // namespace Common
} // namespace Extensions
} // namespace Envoy
