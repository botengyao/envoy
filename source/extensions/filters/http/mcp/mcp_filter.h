#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"

#include "envoy/extensions/filters/http/mcp/v3/mcp.pb.h"
#include "envoy/http/async_client.h"
#include "envoy/http/filter.h"
#include "envoy/server/filter_config.h"
#include "envoy/upstream/cluster_manager.h"

#include "google/protobuf/struct.pb.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/http/message_impl.h"
#include "source/common/json/json_loader.h"
#include "source/common/protobuf/protobuf.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Mcp {

namespace MetadataKeys {
// Core MCP fields
constexpr absl::string_view FilterName = "mcp_proxy";
} // namespace MetadataKeys

// MCP protocol constants
namespace McpConstants {
constexpr absl::string_view kJsonRpcVersion = "2.0";
constexpr absl::string_view kSessionIdHeader = "mcp-session-id";
constexpr absl::string_view kDefaultPrefixSeparator = "__";
constexpr absl::string_view kDefaultMcpPath = "/mcp";
constexpr uint32_t kDefaultPbkdf2Iterations = 100000;
constexpr uint32_t kDefaultBackendTimeoutMs = 30000;
constexpr uint32_t kDefaultInitTimeoutMs = 60000;

// JSON-RPC error codes
constexpr int kJsonRpcParseError = -32700;
constexpr int kJsonRpcInvalidRequest = -32600;
constexpr int kJsonRpcMethodNotFound = -32601;
constexpr int kJsonRpcInvalidParams = -32602;
constexpr int kJsonRpcInternalError = -32603;
} // namespace McpConstants

// Forward declarations
class SessionManager;
class ResponseMerger;

/**
 * Parsed JSON-RPC request.
 */
struct JsonRpcRequest {
  std::string jsonrpc;
  std::string method;
  absl::optional<std::string> id;
  absl::optional<std::string> id_raw;  // Raw ID for type preservation
  std::string params_raw;              // Raw params JSON string
  bool is_notification{false};

  // Helper to check method type
  bool isInitialize() const { return method == "initialize"; }
  bool isToolsList() const { return method == "tools/list"; }
  bool isToolsCall() const { return method == "tools/call"; }
  bool isPromptsList() const { return method == "prompts/list"; }
  bool isPromptsGet() const { return method == "prompts/get"; }
  bool isResourcesList() const { return method == "resources/list"; }
  bool isResourcesRead() const { return method == "resources/read"; }
  bool isPing() const { return method == "ping"; }
  bool isNotification() const { return absl::StartsWith(method, "notifications/"); }

  // Methods that require fanout to all backends
  bool requiresFanout() const {
    return isInitialize() || isToolsList() || isPromptsList() ||
           isResourcesList() || method == "resources/templates/list" ||
           method == "logging/setLevel";
  }

  // Methods that route to a single backend based on name prefix
  bool requiresRouting() const {
    return isToolsCall() || isPromptsGet() || isResourcesRead() ||
           method == "resources/subscribe" || method == "resources/unsubscribe" ||
           method == "completion/complete";
  }
};

/**
 * JSON-RPC response structure.
 */
struct JsonRpcResponse {
  std::string jsonrpc{"2.0"};
  absl::optional<std::string> id;
  std::string result_raw;  // Raw result JSON string
  std::string error_raw;   // Raw error JSON string

  bool isError() const { return !error_raw.empty(); }
};

/**
 * Session data stored in encrypted session ID.
 */
struct SessionData {
  std::string subject;      // OAuth subject or client identifier
  std::string route_name;   // MCPRoute name
  // Map of backend name -> backend-specific session ID
  absl::flat_hash_map<std::string, std::string> backend_sessions;
};

/**
 * Result from backend initialization.
 */
struct BackendInitResult {
  std::string backend_name;
  std::string session_id;      // Backend's mcp-session-id
  std::string capabilities;    // Raw capabilities JSON
  bool success{false};
  std::string error_message;
};

/**
 * Response from a backend request.
 */
struct BackendResponse {
  std::string backend_name;
  bool is_sse{false};
  JsonRpcResponse response;
  Http::Code status_code{Http::Code::OK};
  bool success{false};
  std::string error_message;
  std::string session_id;  // Backend's mcp-session-id from response
};

/**
 * Backend configuration parsed from proto.
 */
struct BackendConfig {
  std::string name;
  std::string cluster;
  std::string path;
  absl::optional<std::string> api_key;
  absl::optional<std::string> api_key_header;
  absl::optional<std::string> bearer_token;
  std::chrono::milliseconds timeout;

  // Tool selector
  std::vector<std::string> include_tools;
  std::vector<std::string> exclude_tools;
};

/**
 * Session manager for creating and validating encrypted session IDs.
 * Uses AES-256-GCM with PBKDF2 key derivation.
 */
class SessionManager {
public:
  SessionManager(const std::string& encryption_seed,
                 const std::string& fallback_seed,
                 uint32_t pbkdf2_iterations);

  /**
   * Create a composite session ID from multiple backend sessions.
   * Format: Encrypted(base64(subject|route|backend1:sid1,backend2:sid2,...))
   */
  absl::StatusOr<std::string> createCompositeSession(
      const std::string& subject,
      const std::string& route_name,
      const std::vector<BackendInitResult>& init_results);

  /**
   * Parse and decrypt a session ID.
   */
  absl::StatusOr<SessionData> parseSession(const std::string& encrypted_session_id);

  /**
   * Get the session ID for a specific backend.
   */
  absl::StatusOr<std::string> getBackendSession(
      const SessionData& session,
      const std::string& backend_name);

private:
  absl::StatusOr<std::string> encrypt(absl::string_view plaintext);
  absl::StatusOr<std::string> decrypt(absl::string_view ciphertext);
  void deriveKey(const std::string& seed, std::string& out_key);

  std::string primary_key_;
  std::string fallback_key_;
  uint32_t pbkdf2_iterations_;
};

using SessionManagerPtr = std::unique_ptr<SessionManager>;

/**
 * JSON-RPC parser for MCP messages.
 */
class JsonRpcParser {
public:
  /**
   * Parse a JSON-RPC request from raw bytes.
   */
  static absl::StatusOr<JsonRpcRequest> parseRequest(absl::string_view body);

  /**
   * Parse a JSON-RPC response from raw bytes.
   */
  static absl::StatusOr<JsonRpcResponse> parseResponse(absl::string_view body);

  /**
   * Serialize a JSON-RPC response to string.
   */
  static std::string serializeResponse(const JsonRpcResponse& response);

  /**
   * Create a JSON-RPC error response.
   */
  static std::string serializeError(const std::string& id, int code, const std::string& message);

  /**
   * Extract a string field from params JSON.
   */
  static absl::optional<std::string> extractParamString(const std::string& params_raw,
                                                        const std::string& field);
};

/**
 * Response merger for combining responses from multiple backends.
 */
class ResponseMerger {
public:
  explicit ResponseMerger(const std::string& prefix_separator);

  /**
   * Merge initialize responses from all backends.
   * Combines capabilities.
   */
  JsonRpcResponse mergeInitialize(
      const std::vector<BackendResponse>& responses,
      const JsonRpcRequest& original_request);

  /**
   * Merge tools/list responses with name prefixing.
   */
  JsonRpcResponse mergeToolsList(
      const std::vector<BackendResponse>& responses,
      const JsonRpcRequest& original_request);

  /**
   * Merge prompts/list responses with name prefixing.
   */
  JsonRpcResponse mergePromptsList(
      const std::vector<BackendResponse>& responses,
      const JsonRpcRequest& original_request);

  /**
   * Merge resources/list responses with name and URI prefixing.
   */
  JsonRpcResponse mergeResourcesList(
      const std::vector<BackendResponse>& responses,
      const JsonRpcRequest& original_request);

  /**
   * Add backend prefix to a name.
   */
  std::string addPrefix(const std::string& backend_name, const std::string& name) const;

  /**
   * Remove backend prefix from a name.
   * Returns pair of (backend_name, original_name).
   */
  absl::optional<std::pair<std::string, std::string>>
  removePrefix(const std::string& prefixed_name) const;

private:
  std::string separator_;
};

using ResponseMergerPtr = std::unique_ptr<ResponseMerger>;

/**
 * MCP filter configuration.
 */
class McpFilterConfig {
public:
  explicit McpFilterConfig(const envoy::extensions::filters::http::mcp::v3::Mcp& proto_config);

  envoy::extensions::filters::http::mcp::v3::Mcp::TrafficMode trafficMode() const {
    return traffic_mode_;
  }

  bool shouldRejectNonMcp() const {
    return traffic_mode_ == envoy::extensions::filters::http::mcp::v3::Mcp::REJECT_NO_MCP;
  }

  bool clearRouteCache() const { return clear_route_cache_; }
  uint32_t maxRequestBodySize() const { return max_request_body_size_; }

  // Proxy mode accessors
  bool proxyEnabled() const { return proxy_enabled_; }
  const std::string& routeName() const { return route_name_; }
  const std::string& prefixSeparator() const { return prefix_separator_; }
  const std::vector<BackendConfig>& backends() const { return backends_; }
  std::chrono::milliseconds backendTimeout() const { return backend_timeout_; }
  std::chrono::milliseconds initializationTimeout() const { return initialization_timeout_; }

  // Session crypto accessors
  const std::string& encryptionSeed() const { return encryption_seed_; }
  const std::string& fallbackSeed() const { return fallback_seed_; }
  uint32_t pbkdf2Iterations() const { return pbkdf2_iterations_; }

  /**
   * Get backend config by name.
   */
  const BackendConfig* getBackend(const std::string& name) const;

  /**
   * Extract backend name from a prefixed tool/resource name.
   * Returns nullopt if the name doesn't contain the prefix separator.
   */
  absl::optional<std::pair<std::string, std::string>>
  extractBackendFromName(const std::string& prefixed_name) const;

private:
  void initProxyConfig(const envoy::extensions::filters::http::mcp::v3::McpProxyConfig& config);

  const envoy::extensions::filters::http::mcp::v3::Mcp::TrafficMode traffic_mode_;
  const bool clear_route_cache_;
  const uint32_t max_request_body_size_;

  // Proxy mode configuration
  bool proxy_enabled_{false};
  std::string route_name_;
  std::string prefix_separator_{std::string(McpConstants::kDefaultPrefixSeparator)};
  std::vector<BackendConfig> backends_;
  absl::flat_hash_map<std::string, size_t> backend_map_;  // name -> index
  std::chrono::milliseconds backend_timeout_{McpConstants::kDefaultBackendTimeoutMs};
  std::chrono::milliseconds initialization_timeout_{McpConstants::kDefaultInitTimeoutMs};

  // Session crypto
  std::string encryption_seed_;
  std::string fallback_seed_;
  uint32_t pbkdf2_iterations_{McpConstants::kDefaultPbkdf2Iterations};
};

/**
 * Per-route configuration for the MCP filter.
 */
class McpOverrideConfig : public Router::RouteSpecificFilterConfig {
public:
  explicit McpOverrideConfig(
      const envoy::extensions::filters::http::mcp::v3::McpOverride& proto_config)
      : traffic_mode_(proto_config.traffic_mode()) {}

  envoy::extensions::filters::http::mcp::v3::Mcp::TrafficMode trafficMode() const {
    return traffic_mode_;
  }

private:
  const envoy::extensions::filters::http::mcp::v3::Mcp::TrafficMode traffic_mode_;
};

using McpFilterConfigSharedPtr = std::shared_ptr<McpFilterConfig>;

/**
 * MCP proxy filter implementation.
 *
 * In pass-through mode, validates MCP requests and sets dynamic metadata.
 * In proxy mode, handles multi-backend aggregation with:
 * - Session management (encrypted composite session IDs)
 * - Request routing (fanout for list operations, targeted for calls)
 * - Response merging (tool/prompt/resource name prefixing)
 */
class McpFilter : public Http::StreamFilter,
                  public Logger::Loggable<Logger::Id::filter> {
public:
  McpFilter(McpFilterConfigSharedPtr config,
            Upstream::ClusterManager& cluster_manager);

  // Http::StreamFilterBase
  void onDestroy() override {}

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override {
    decoder_callbacks_ = &callbacks;
  }

  // Http::StreamEncoderFilter
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers, bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  Http::Filter1xxHeadersStatus encode1xxHeaders(Http::ResponseHeaderMap&) override {
    return Http::Filter1xxHeadersStatus::Continue;
  }
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap&) override {
    return Http::FilterMetadataStatus::Continue;
  }
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override {
    encoder_callbacks_ = &callbacks;
  }

private:
  // Request type detection
  bool isValidMcpSseRequest(const Http::RequestHeaderMap& headers) const;
  bool isValidMcpPostRequest(const Http::RequestHeaderMap& headers) const;
  bool isDeleteRequest(const Http::RequestHeaderMap& headers) const;
  bool shouldRejectRequest() const;

  // Pass-through mode handlers
  void handlePassThroughRequest();

  // Proxy mode handlers
  void handleProxyRequest(const JsonRpcRequest& request);
  void handleInitialize(const JsonRpcRequest& request);
  void handleFanoutRequest(const JsonRpcRequest& request);
  void handleRoutedRequest(const JsonRpcRequest& request);
  void handleDelete();

  // Response helpers
  void sendJsonRpcResponse(const JsonRpcResponse& response);
  void sendJsonRpcError(const std::string& id, int code, const std::string& message);
  void sendLocalError(Http::Code code, const std::string& message);

  // Dynamic metadata
  void finalizeDynamicMetadata();

  McpFilterConfigSharedPtr config_;
  Upstream::ClusterManager& cluster_manager_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_{};
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_{};

  // Request state
  Http::RequestHeaderMap* request_headers_{};
  bool is_mcp_request_{false};
  bool is_json_post_request_{false};
  bool is_proxy_mode_{false};
  bool response_sent_{false};

  // Session state (proxy mode)
  SessionManagerPtr session_manager_;
  ResponseMergerPtr response_merger_;
  absl::optional<SessionData> current_session_;
  std::string current_session_id_;

  // Buffered request body
  Buffer::OwnedImpl request_body_;

  // Parsed request
  absl::optional<JsonRpcRequest> parsed_request_;

  // Metadata for pass-through mode
  std::unique_ptr<Protobuf::Struct> metadata_;
};

} // namespace Mcp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
