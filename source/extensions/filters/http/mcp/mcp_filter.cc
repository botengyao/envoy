#include "source/extensions/filters/http/mcp/mcp_filter.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"

#include "google/protobuf/struct.pb.h"

#include "source/common/common/utility.h"
#include "source/common/http/headers.h"
#include "source/common/http/utility.h"
#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Mcp {

namespace {
// AES-GCM constants
constexpr size_t kAesKeySize = 32;      // AES-256
constexpr size_t kAesGcmNonceSize = 12;
constexpr size_t kAesGcmTagSize = 16;
} // namespace

//==============================================================================
// SessionManager Implementation
//==============================================================================

SessionManager::SessionManager(const std::string& encryption_seed,
                               const std::string& fallback_seed,
                               uint32_t pbkdf2_iterations)
    : pbkdf2_iterations_(pbkdf2_iterations) {
  deriveKey(encryption_seed, primary_key_);
  if (!fallback_seed.empty()) {
    deriveKey(fallback_seed, fallback_key_);
  }
}

void SessionManager::deriveKey(const std::string& seed, std::string& out_key) {
  // Use a fixed salt derived from the seed for deterministic key derivation
  std::vector<uint8_t> salt(16);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx != nullptr) {
    unsigned int salt_len = 16;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx, seed.data(), seed.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, salt.data(), &salt_len) == 1) {
      // Derive key using PBKDF2
      std::vector<uint8_t> key(kAesKeySize);
      if (PKCS5_PBKDF2_HMAC(seed.c_str(), seed.size(),
                            salt.data(), salt.size(),
                            pbkdf2_iterations_,
                            EVP_sha256(),
                            kAesKeySize, key.data()) == 1) {
        out_key.assign(reinterpret_cast<char*>(key.data()), key.size());
      }
    }
    EVP_MD_CTX_free(ctx);
  }
}

absl::StatusOr<std::string> SessionManager::encrypt(absl::string_view plaintext) {
  if (primary_key_.empty()) {
    return absl::FailedPreconditionError("Encryption key not initialized");
  }

  // Generate random nonce
  std::vector<uint8_t> nonce(kAesGcmNonceSize);
  if (RAND_bytes(nonce.data(), kAesGcmNonceSize) != 1) {
    return absl::InternalError("Failed to generate nonce");
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return absl::InternalError("Failed to create cipher context");
  }

  std::vector<uint8_t> ciphertext(plaintext.size() + kAesGcmTagSize);
  int len = 0;
  int ciphertext_len = 0;

  bool success = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                    reinterpret_cast<const uint8_t*>(primary_key_.data()),
                                    nonce.data()) == 1;
  if (success) {
    success = EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                                reinterpret_cast<const uint8_t*>(plaintext.data()),
                                plaintext.size()) == 1;
    ciphertext_len = len;
  }

  if (success) {
    success = EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) == 1;
    ciphertext_len += len;
  }

  std::vector<uint8_t> tag(kAesGcmTagSize);
  if (success) {
    success = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kAesGcmTagSize, tag.data()) == 1;
  }

  EVP_CIPHER_CTX_free(ctx);

  if (!success) {
    return absl::InternalError("Encryption failed");
  }

  // Combine: nonce || ciphertext || tag
  std::string result;
  result.reserve(nonce.size() + ciphertext_len + tag.size());
  result.append(reinterpret_cast<char*>(nonce.data()), nonce.size());
  result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
  result.append(reinterpret_cast<char*>(tag.data()), tag.size());

  return absl::Base64Escape(result);
}

absl::StatusOr<std::string> SessionManager::decrypt(absl::string_view ciphertext_b64) {
  std::string ciphertext;
  if (!absl::Base64Unescape(ciphertext_b64, &ciphertext)) {
    return absl::InvalidArgumentError("Invalid base64 encoding");
  }

  if (ciphertext.size() < kAesGcmNonceSize + kAesGcmTagSize) {
    return absl::InvalidArgumentError("Ciphertext too short");
  }

  absl::string_view nonce_view(ciphertext.data(), kAesGcmNonceSize);
  size_t ct_len = ciphertext.size() - kAesGcmNonceSize - kAesGcmTagSize;
  absl::string_view ct_view(ciphertext.data() + kAesGcmNonceSize, ct_len);
  absl::string_view tag_view(ciphertext.data() + kAesGcmNonceSize + ct_len, kAesGcmTagSize);

  auto tryDecrypt = [&](const std::string& key) -> absl::StatusOr<std::string> {
    if (key.empty()) {
      return absl::FailedPreconditionError("Key not initialized");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
      return absl::InternalError("Failed to create cipher context");
    }

    std::vector<uint8_t> plaintext(ct_len);
    int len = 0;
    int plaintext_len = 0;

    bool success = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                      reinterpret_cast<const uint8_t*>(key.data()),
                                      reinterpret_cast<const uint8_t*>(nonce_view.data())) == 1;

    if (success) {
      success = EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                  reinterpret_cast<const uint8_t*>(ct_view.data()),
                                  ct_len) == 1;
      plaintext_len = len;
    }

    if (success) {
      success = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kAesGcmTagSize,
                                    const_cast<char*>(tag_view.data())) == 1;
    }

    if (success) {
      success = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) == 1;
      plaintext_len += len;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!success) {
      return absl::UnauthenticatedError("Decryption failed");
    }

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
  };

  // Try primary key
  auto result = tryDecrypt(primary_key_);
  if (result.ok()) {
    return result;
  }

  // Try fallback key if available
  if (!fallback_key_.empty()) {
    result = tryDecrypt(fallback_key_);
    if (result.ok()) {
      return result;
    }
  }

  return absl::UnauthenticatedError("Decryption failed with all available keys");
}

absl::StatusOr<std::string> SessionManager::createCompositeSession(
    const std::string& subject,
    const std::string& route_name,
    const std::vector<BackendInitResult>& init_results) {

  std::vector<std::string> backend_parts;
  for (const auto& result : init_results) {
    if (result.success) {
      backend_parts.push_back(absl::StrCat(result.backend_name, ":", result.session_id));
    }
  }

  if (backend_parts.empty()) {
    return absl::FailedPreconditionError("No successful backend initializations");
  }

  std::string plaintext = absl::StrCat(
      subject, "|",
      route_name, "|",
      absl::StrJoin(backend_parts, ","));

  return encrypt(plaintext);
}

absl::StatusOr<SessionData> SessionManager::parseSession(const std::string& encrypted_session_id) {
  auto decrypt_result = decrypt(encrypted_session_id);
  if (!decrypt_result.ok()) {
    return decrypt_result.status();
  }

  // Parse: subject|route|backend1:sid1,backend2:sid2,...
  std::vector<std::string> parts = absl::StrSplit(*decrypt_result, '|');
  if (parts.size() != 3) {
    return absl::InvalidArgumentError("Invalid session format");
  }

  SessionData session;
  session.subject = std::string(parts[0]);
  session.route_name = std::string(parts[1]);

  std::vector<std::string> backend_parts = absl::StrSplit(parts[2], ',');
  for (const auto& bp : backend_parts) {
    std::vector<std::string> kv = absl::StrSplit(bp, absl::MaxSplits(':', 1));
    if (kv.size() == 2) {
      session.backend_sessions[std::string(kv[0])] = std::string(kv[1]);
    }
  }

  return session;
}

absl::StatusOr<std::string> SessionManager::getBackendSession(
    const SessionData& session,
    const std::string& backend_name) {
  auto it = session.backend_sessions.find(backend_name);
  if (it == session.backend_sessions.end()) {
    return absl::NotFoundError(absl::StrCat("No session for backend: ", backend_name));
  }
  return it->second;
}

//==============================================================================
// JsonRpcParser Implementation
//==============================================================================

absl::StatusOr<JsonRpcRequest> JsonRpcParser::parseRequest(absl::string_view body) {
  auto json_or = Json::Factory::loadFromString(std::string(body));
  if (!json_or.ok()) {
    return absl::InvalidArgumentError("Invalid JSON");
  }

  auto& json = *json_or;
  if (!json->isObject()) {
    return absl::InvalidArgumentError("Expected JSON object");
  }

  JsonRpcRequest request;

  // Parse jsonrpc version
  auto jsonrpc = json->getString("jsonrpc");
  if (!jsonrpc.ok() || *jsonrpc != McpConstants::kJsonRpcVersion) {
    return absl::InvalidArgumentError("Invalid or missing jsonrpc version");
  }
  request.jsonrpc = std::string(*jsonrpc);

  // Parse method
  auto method = json->getString("method");
  if (!method.ok()) {
    return absl::InvalidArgumentError("Missing method");
  }
  request.method = std::string(*method);

  // Parse id (optional - if missing, it's a notification)
  if (json->hasObject("id")) {
    auto id_value = json->getValue("id");
    if (id_value.ok()) {
      if ((*id_value)->isString()) {
        auto id_str = (*id_value)->getString("");
        if (id_str.ok()) {
          request.id = std::string(*id_str);
          request.id_raw = request.id;
        }
      } else if ((*id_value)->isNumber()) {
        auto id_num = (*id_value)->getDouble("");
        if (id_num.ok()) {
          // Check if it's an integer
          if (*id_num == static_cast<int64_t>(*id_num)) {
            request.id = std::to_string(static_cast<int64_t>(*id_num));
          } else {
            request.id = std::to_string(*id_num);
          }
          request.id_raw = request.id;
        }
      }
    }
  } else {
    request.is_notification = true;
  }

  // Parse params (optional) - store as raw JSON string
  if (json->hasObject("params")) {
    auto params = json->getObject("params");
    if (params.ok()) {
      request.params_raw = (*params)->asJsonString();
    }
  }

  return request;
}

absl::StatusOr<JsonRpcResponse> JsonRpcParser::parseResponse(absl::string_view body) {
  auto json_or = Json::Factory::loadFromString(std::string(body));
  if (!json_or.ok()) {
    return absl::InvalidArgumentError("Invalid JSON");
  }

  auto& json = *json_or;
  if (!json->isObject()) {
    return absl::InvalidArgumentError("Expected JSON object");
  }

  JsonRpcResponse response;

  // Parse id
  if (json->hasObject("id")) {
    auto id_value = json->getValue("id");
    if (id_value.ok()) {
      if ((*id_value)->isString()) {
        auto id_str = (*id_value)->getString("");
        if (id_str.ok()) {
          response.id = std::string(*id_str);
        }
      } else if ((*id_value)->isNumber()) {
        auto id_num = (*id_value)->getDouble("");
        if (id_num.ok()) {
          if (*id_num == static_cast<int64_t>(*id_num)) {
            response.id = std::to_string(static_cast<int64_t>(*id_num));
          } else {
            response.id = std::to_string(*id_num);
          }
        }
      }
    }
  }

  // Parse result or error
  if (json->hasObject("result")) {
    auto result = json->getObject("result");
    if (result.ok()) {
      response.result_raw = (*result)->asJsonString();
    }
  }

  if (json->hasObject("error")) {
    auto error = json->getObject("error");
    if (error.ok()) {
      response.error_raw = (*error)->asJsonString();
    }
  }

  return response;
}

std::string JsonRpcParser::serializeResponse(const JsonRpcResponse& response) {
  std::string result = R"({"jsonrpc":"2.0")";

  if (response.id) {
    // Check if ID looks like a number
    bool is_numeric = !response.id->empty();
    for (char c : *response.id) {
      if (!std::isdigit(c) && c != '-' && c != '.') {
        is_numeric = false;
        break;
      }
    }
    if (is_numeric) {
      result += R"(,"id":)" + *response.id;
    } else {
      result += R"(,"id":")" + *response.id + "\"";
    }
  } else {
    result += R"(,"id":null)";
  }

  if (!response.error_raw.empty()) {
    result += R"(,"error":)" + response.error_raw;
  } else if (!response.result_raw.empty()) {
    result += R"(,"result":)" + response.result_raw;
  } else {
    result += R"(,"result":{})";
  }

  result += "}";
  return result;
}

std::string JsonRpcParser::serializeError(const std::string& id, int code, const std::string& message) {
  std::string id_str = id.empty() || id == "null" ? "null" : "\"" + id + "\"";

  // Check if ID looks like a number
  if (!id.empty() && id != "null") {
    bool is_numeric = true;
    for (char c : id) {
      if (!std::isdigit(c) && c != '-' && c != '.') {
        is_numeric = false;
        break;
      }
    }
    if (is_numeric) {
      id_str = id;
    }
  }

  return absl::StrCat(
      R"({"jsonrpc":"2.0","id":)", id_str,
      R"(,"error":{"code":)", std::to_string(code),
      R"(,"message":")", message, R"("}})");
}

absl::optional<std::string> JsonRpcParser::extractParamString(const std::string& params_raw,
                                                               const std::string& field) {
  if (params_raw.empty()) {
    return absl::nullopt;
  }

  auto json_or = Json::Factory::loadFromString(params_raw);
  if (!json_or.ok()) {
    return absl::nullopt;
  }

  auto str = (*json_or)->getString(field);
  if (str.ok()) {
    return std::string(*str);
  }
  return absl::nullopt;
}

//==============================================================================
// ResponseMerger Implementation
//==============================================================================

ResponseMerger::ResponseMerger(const std::string& prefix_separator)
    : separator_(prefix_separator.empty() ?
                 std::string(McpConstants::kDefaultPrefixSeparator) : prefix_separator) {}

std::string ResponseMerger::addPrefix(const std::string& backend_name,
                                      const std::string& name) const {
  return absl::StrCat(backend_name, separator_, name);
}

absl::optional<std::pair<std::string, std::string>>
ResponseMerger::removePrefix(const std::string& prefixed_name) const {
  size_t pos = prefixed_name.find(separator_);
  if (pos == std::string::npos) {
    return absl::nullopt;
  }
  return std::make_pair(
      prefixed_name.substr(0, pos),
      prefixed_name.substr(pos + separator_.size()));
}

JsonRpcResponse ResponseMerger::mergeInitialize(
    const std::vector<BackendResponse>& /*responses*/,
    const JsonRpcRequest& original_request) {

  JsonRpcResponse merged;
  merged.id = original_request.id;

  // Build merged result with gateway capabilities using proper JSON construction
  ProtobufWkt::Struct result;
  auto& fields = *result.mutable_fields();

  fields["protocolVersion"].set_string_value("2025-06-18");

  // serverInfo
  auto& server_info = *fields["serverInfo"].mutable_struct_value()->mutable_fields();
  server_info["name"].set_string_value("envoy-mcp-gateway");
  server_info["version"].set_string_value("1.0.0");

  // capabilities
  auto& capabilities = *fields["capabilities"].mutable_struct_value()->mutable_fields();

  auto& tools_cap = *capabilities["tools"].mutable_struct_value()->mutable_fields();
  tools_cap["listChanged"].set_bool_value(true);

  auto& prompts_cap = *capabilities["prompts"].mutable_struct_value()->mutable_fields();
  prompts_cap["listChanged"].set_bool_value(true);

  auto& resources_cap = *capabilities["resources"].mutable_struct_value()->mutable_fields();
  resources_cap["listChanged"].set_bool_value(true);
  resources_cap["subscribe"].set_bool_value(true);

  // Empty logging object
  capabilities["logging"].mutable_struct_value();

  merged.result_raw = MessageUtil::getJsonStringFromMessageOrError(result, false, true);

  return merged;
}

JsonRpcResponse ResponseMerger::mergeToolsList(
    const std::vector<BackendResponse>& responses,
    const JsonRpcRequest& original_request) {

  JsonRpcResponse merged;
  merged.id = original_request.id;

  // Build result using protobuf Struct for proper JSON serialization
  ProtobufWkt::Struct result;
  auto& tools_list = *result.mutable_fields()["tools"].mutable_list_value();

  for (const auto& resp : responses) {
    if (!resp.success || resp.response.result_raw.empty()) {
      continue;
    }

    // Parse backend response
    ProtobufWkt::Struct backend_result;
    auto status = MessageUtil::loadFromJson(resp.response.result_raw, backend_result);
    if (!status.ok()) {
      continue;
    }

    // Get tools array from backend response
    auto tools_it = backend_result.fields().find("tools");
    if (tools_it == backend_result.fields().end() ||
        !tools_it->second.has_list_value()) {
      continue;
    }

    // Process each tool
    for (const auto& tool_value : tools_it->second.list_value().values()) {
      if (!tool_value.has_struct_value()) {
        continue;
      }

      const auto& tool_struct = tool_value.struct_value();
      auto name_it = tool_struct.fields().find("name");
      if (name_it == tool_struct.fields().end() ||
          name_it->second.kind_case() != ProtobufWkt::Value::kStringValue) {
        continue;
      }

      // Create new tool with prefixed name
      ProtobufWkt::Value new_tool;
      auto& new_tool_struct = *new_tool.mutable_struct_value();

      // Copy all fields from original tool
      for (const auto& field : tool_struct.fields()) {
        if (field.first == "name") {
          // Prefix the name
          std::string prefixed_name = addPrefix(resp.backend_name, field.second.string_value());
          (*new_tool_struct.mutable_fields())["name"].set_string_value(prefixed_name);
        } else {
          // Copy other fields as-is
          (*new_tool_struct.mutable_fields())[field.first] = field.second;
        }
      }

      *tools_list.add_values() = std::move(new_tool);
    }
  }

  merged.result_raw = MessageUtil::getJsonStringFromMessageOrError(result, false, true);

  return merged;
}

JsonRpcResponse ResponseMerger::mergePromptsList(
    const std::vector<BackendResponse>& responses,
    const JsonRpcRequest& original_request) {

  JsonRpcResponse merged;
  merged.id = original_request.id;

  ProtobufWkt::Struct result;
  auto& prompts_list = *result.mutable_fields()["prompts"].mutable_list_value();

  for (const auto& resp : responses) {
    if (!resp.success || resp.response.result_raw.empty()) {
      continue;
    }

    ProtobufWkt::Struct backend_result;
    auto status = MessageUtil::loadFromJson(resp.response.result_raw, backend_result);
    if (!status.ok()) {
      continue;
    }

    auto prompts_it = backend_result.fields().find("prompts");
    if (prompts_it == backend_result.fields().end() ||
        !prompts_it->second.has_list_value()) {
      continue;
    }

    for (const auto& prompt_value : prompts_it->second.list_value().values()) {
      if (!prompt_value.has_struct_value()) {
        continue;
      }

      const auto& prompt_struct = prompt_value.struct_value();
      auto name_it = prompt_struct.fields().find("name");
      if (name_it == prompt_struct.fields().end() ||
          name_it->second.kind_case() != ProtobufWkt::Value::kStringValue) {
        continue;
      }

      ProtobufWkt::Value new_prompt;
      auto& new_prompt_struct = *new_prompt.mutable_struct_value();

      for (const auto& field : prompt_struct.fields()) {
        if (field.first == "name") {
          std::string prefixed_name = addPrefix(resp.backend_name, field.second.string_value());
          (*new_prompt_struct.mutable_fields())["name"].set_string_value(prefixed_name);
        } else {
          (*new_prompt_struct.mutable_fields())[field.first] = field.second;
        }
      }

      *prompts_list.add_values() = std::move(new_prompt);
    }
  }

  merged.result_raw = MessageUtil::getJsonStringFromMessageOrError(result, false, true);

  return merged;
}

JsonRpcResponse ResponseMerger::mergeResourcesList(
    const std::vector<BackendResponse>& responses,
    const JsonRpcRequest& original_request) {

  JsonRpcResponse merged;
  merged.id = original_request.id;

  ProtobufWkt::Struct result;
  auto& resources_list = *result.mutable_fields()["resources"].mutable_list_value();

  for (const auto& resp : responses) {
    if (!resp.success || resp.response.result_raw.empty()) {
      continue;
    }

    ProtobufWkt::Struct backend_result;
    auto status = MessageUtil::loadFromJson(resp.response.result_raw, backend_result);
    if (!status.ok()) {
      continue;
    }

    auto resources_it = backend_result.fields().find("resources");
    if (resources_it == backend_result.fields().end() ||
        !resources_it->second.has_list_value()) {
      continue;
    }

    for (const auto& resource_value : resources_it->second.list_value().values()) {
      if (!resource_value.has_struct_value()) {
        continue;
      }

      const auto& resource_struct = resource_value.struct_value();

      ProtobufWkt::Value new_resource;
      auto& new_resource_struct = *new_resource.mutable_struct_value();

      for (const auto& field : resource_struct.fields()) {
        if (field.first == "name" &&
            field.second.kind_case() == ProtobufWkt::Value::kStringValue) {
          // Prefix the name
          std::string prefixed_name = addPrefix(resp.backend_name, field.second.string_value());
          (*new_resource_struct.mutable_fields())["name"].set_string_value(prefixed_name);
        } else if (field.first == "uri" &&
                   field.second.kind_case() == ProtobufWkt::Value::kStringValue) {
          // Prefix the URI: backend+originaluri
          std::string prefixed_uri = absl::StrCat(resp.backend_name, "+", field.second.string_value());
          (*new_resource_struct.mutable_fields())["uri"].set_string_value(prefixed_uri);
        } else {
          // Copy other fields as-is
          (*new_resource_struct.mutable_fields())[field.first] = field.second;
        }
      }

      *resources_list.add_values() = std::move(new_resource);
    }
  }

  merged.result_raw = MessageUtil::getJsonStringFromMessageOrError(result, false, true);

  return merged;
}

//==============================================================================
// McpFilterConfig Implementation
//==============================================================================

McpFilterConfig::McpFilterConfig(const envoy::extensions::filters::http::mcp::v3::Mcp& proto_config)
    : traffic_mode_(proto_config.traffic_mode()),
      clear_route_cache_(proto_config.clear_route_cache()),
      max_request_body_size_(proto_config.has_max_request_body_size()
                             ? proto_config.max_request_body_size().value()
                             : 8192),
      proxy_enabled_(proto_config.has_proxy_config() &&
                     proto_config.proxy_config().enabled()) {
  if (proxy_enabled_) {
    initProxyConfig(proto_config.proxy_config());
  }
}

void McpFilterConfig::initProxyConfig(
    const envoy::extensions::filters::http::mcp::v3::McpProxyConfig& config) {

  route_name_ = config.route_name();

  if (!config.prefix_separator().empty()) {
    prefix_separator_ = config.prefix_separator();
  }

  // Parse timeouts
  if (config.has_backend_timeout()) {
    backend_timeout_ = std::chrono::milliseconds(
        DurationUtil::durationToMilliseconds(config.backend_timeout()));
  }

  if (config.has_initialization_timeout()) {
    initialization_timeout_ = std::chrono::milliseconds(
        DurationUtil::durationToMilliseconds(config.initialization_timeout()));
  }

  // Parse session crypto
  if (config.has_session_crypto()) {
    const auto& crypto = config.session_crypto();
    encryption_seed_ = crypto.encryption_seed();
    fallback_seed_ = crypto.fallback_seed();
    if (crypto.pbkdf2_iterations() > 0) {
      pbkdf2_iterations_ = crypto.pbkdf2_iterations();
    }
  }

  // Parse backends
  for (const auto& backend_config : config.backends()) {
    BackendConfig backend;
    backend.name = backend_config.name();
    backend.cluster = backend_config.cluster();
    backend.path = backend_config.path().empty() ?
                   std::string(McpConstants::kDefaultMcpPath) : backend_config.path();

    if (backend_config.has_timeout()) {
      backend.timeout = std::chrono::milliseconds(
          DurationUtil::durationToMilliseconds(backend_config.timeout()));
    } else {
      backend.timeout = backend_timeout_;
    }

    // Parse auth
    if (backend_config.has_auth()) {
      const auto& auth = backend_config.auth();
      if (auth.has_api_key()) {
        backend.api_key = auth.api_key().key();
        backend.api_key_header = auth.api_key().header_name().empty() ?
                                 "x-api-key" : auth.api_key().header_name();
      } else if (auth.has_bearer()) {
        backend.bearer_token = auth.bearer().token();
      }
    }

    // Parse tool selector
    if (backend_config.has_tool_selector()) {
      const auto& selector = backend_config.tool_selector();
      for (const auto& inc : selector.include()) {
        backend.include_tools.push_back(inc);
      }
      for (const auto& exc : selector.exclude()) {
        backend.exclude_tools.push_back(exc);
      }
    }

    backend_map_[backend.name] = backends_.size();
    backends_.push_back(std::move(backend));
  }
}

const BackendConfig* McpFilterConfig::getBackend(const std::string& name) const {
  auto it = backend_map_.find(name);
  return it != backend_map_.end() ? &backends_[it->second] : nullptr;
}

absl::optional<std::pair<std::string, std::string>>
McpFilterConfig::extractBackendFromName(const std::string& prefixed_name) const {
  size_t pos = prefixed_name.find(prefix_separator_);
  if (pos == std::string::npos) {
    return absl::nullopt;
  }
  return std::make_pair(
      prefixed_name.substr(0, pos),
      prefixed_name.substr(pos + prefix_separator_.size()));
}

//==============================================================================
// McpFilter Implementation
//==============================================================================

McpFilter::McpFilter(McpFilterConfigSharedPtr config,
                     Upstream::ClusterManager& cluster_manager)
    : config_(config), cluster_manager_(cluster_manager) {

  if (config_->proxyEnabled()) {
    session_manager_ = std::make_unique<SessionManager>(
        config_->encryptionSeed(),
        config_->fallbackSeed(),
        config_->pbkdf2Iterations());

    response_merger_ = std::make_unique<ResponseMerger>(config_->prefixSeparator());
  }
}

bool McpFilter::isValidMcpSseRequest(const Http::RequestHeaderMap& headers) const {
  if (headers.getMethodValue() != Http::Headers::get().MethodValues.Get) {
    return false;
  }

  const auto& accepts = headers.get(Http::CustomHeaders::get().Accept);
  if (accepts.empty()) {
    return false;
  }

  for (size_t i = 0; i < accepts.size(); ++i) {
    if (absl::StrContains(accepts[i]->value().getStringView(),
                          Http::Headers::get().ContentTypeValues.TextEventStream)) {
      return true;
    }
  }

  return false;
}

bool McpFilter::isValidMcpPostRequest(const Http::RequestHeaderMap& headers) const {
  bool is_post_request =
      headers.getMethodValue() == Http::Headers::get().MethodValues.Post &&
      headers.getContentTypeValue() == Http::Headers::get().ContentTypeValues.Json;

  if (!is_post_request) {
    return false;
  }

  const auto& accepts = headers.get(Http::CustomHeaders::get().Accept);
  if (accepts.empty()) {
    return false;
  }

  bool has_sse = false;
  bool has_json = false;

  for (size_t i = 0; i < accepts.size(); ++i) {
    const absl::string_view value = accepts[i]->value().getStringView();
    if (!has_sse &&
        absl::StrContains(value, Http::Headers::get().ContentTypeValues.TextEventStream)) {
      has_sse = true;
    }
    if (!has_json && absl::StrContains(value, Http::Headers::get().ContentTypeValues.Json)) {
      has_json = true;
    }
    if (has_sse && has_json) {
      return true;
    }
  }

  return false;
}

bool McpFilter::isDeleteRequest(const Http::RequestHeaderMap& headers) const {
  return headers.getMethodValue() == Http::Headers::get().MethodValues.Delete;
}

bool McpFilter::shouldRejectRequest() const {
  const auto* override_config =
      Http::Utility::resolveMostSpecificPerFilterConfig<McpOverrideConfig>(decoder_callbacks_);

  if (override_config) {
    return override_config->trafficMode() ==
           envoy::extensions::filters::http::mcp::v3::Mcp::REJECT_NO_MCP;
  }

  return config_->shouldRejectNonMcp();
}

Http::FilterHeadersStatus McpFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                   bool end_stream) {
  request_headers_ = &headers;

  if (isValidMcpSseRequest(headers)) {
    is_mcp_request_ = true;
    ENVOY_LOG(debug, "valid MCP SSE request, passing through");
    return Http::FilterHeadersStatus::Continue;
  }

  if (isValidMcpPostRequest(headers)) {
    is_json_post_request_ = true;
    ENVOY_LOG(debug, "valid MCP Post request");
    if (end_stream) {
      is_mcp_request_ = false;
      if (shouldRejectRequest()) {
        sendLocalError(Http::Code::BadRequest, "Empty request body");
        return Http::FilterHeadersStatus::StopIteration;
      }
    } else {
      is_mcp_request_ = true;

      const uint32_t max_size = config_->maxRequestBodySize();
      if (max_size > 0) {
        decoder_callbacks_->setDecoderBufferLimit(max_size);
        ENVOY_LOG(debug, "set decoder buffer limit to {} bytes", max_size);
      }

      return Http::FilterHeadersStatus::StopIteration;
    }
  }

  // Handle DELETE for session termination in proxy mode
  if (isDeleteRequest(headers) && config_->proxyEnabled()) {
    is_mcp_request_ = true;
    is_proxy_mode_ = true;
    if (end_stream) {
      handleDelete();
    }
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (!is_mcp_request_ && shouldRejectRequest()) {
    ENVOY_LOG(debug, "rejecting non-MCP traffic");
    decoder_callbacks_->sendLocalReply(Http::Code::BadRequest, "Only MCP traffic is allowed",
                                       nullptr, absl::nullopt, "mcp_filter_reject_no_mcp");
    return Http::FilterHeadersStatus::StopIteration;
  }

  ENVOY_LOG(debug, "MCP filter passing through during decoding headers");
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus McpFilter::decodeData(Buffer::Instance& data, bool end_stream) {
  if (!is_json_post_request_ || !is_mcp_request_) {
    return Http::FilterDataStatus::Continue;
  }

  // Buffer the data
  request_body_.add(data);

  if (!end_stream) {
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }

  // Check size limit
  const uint32_t max_size = config_->maxRequestBodySize();
  if (max_size > 0 && request_body_.length() > max_size) {
    ENVOY_LOG(debug, "request body size {} exceeds maximum {}", request_body_.length(), max_size);
    sendLocalError(Http::Code::PayloadTooLarge,
                   absl::StrCat("Request body size exceeds maximum allowed size of ",
                                max_size, " bytes"));
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }

  // Parse the JSON-RPC request
  std::string body = request_body_.toString();
  auto request_or = JsonRpcParser::parseRequest(body);

  if (!request_or.ok()) {
    ENVOY_LOG(debug, "invalid JSON-RPC request: {}", request_or.status().message());
    if (shouldRejectRequest()) {
      sendJsonRpcError("null", McpConstants::kJsonRpcParseError, "Parse error");
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
    return Http::FilterDataStatus::Continue;
  }

  parsed_request_ = std::move(*request_or);

  // Validate JSON-RPC structure
  if (parsed_request_->jsonrpc != McpConstants::kJsonRpcVersion) {
    if (shouldRejectRequest()) {
      sendJsonRpcError(parsed_request_->id.value_or("null"),
                       McpConstants::kJsonRpcInvalidRequest, "Invalid Request");
      return Http::FilterDataStatus::StopIterationNoBuffer;
    }
    return Http::FilterDataStatus::Continue;
  }

  ENVOY_LOG(debug, "parsed MCP request: method={}", parsed_request_->method);

  // If proxy mode is enabled, handle the request
  if (config_->proxyEnabled()) {
    is_proxy_mode_ = true;
    handleProxyRequest(*parsed_request_);
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }

  // Pass-through mode: set dynamic metadata
  handlePassThroughRequest();

  return Http::FilterDataStatus::Continue;
}

Http::FilterHeadersStatus McpFilter::encodeHeaders(Http::ResponseHeaderMap&, bool) {
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus McpFilter::encodeData(Buffer::Instance&, bool) {
  return Http::FilterDataStatus::Continue;
}

void McpFilter::handlePassThroughRequest() {
  // Set dynamic metadata for routing
  finalizeDynamicMetadata();

  if (config_->clearRouteCache()) {
    ENVOY_LOG(debug, "clearing route cache after MCP validation");
    if (auto cb = decoder_callbacks_->downstreamCallbacks(); cb.has_value()) {
      cb->clearRouteCache();
    }
  }
}

void McpFilter::handleProxyRequest(const JsonRpcRequest& request) {
  ENVOY_LOG(debug, "handling proxy request: method={}", request.method);

  if (request.isInitialize()) {
    handleInitialize(request);
  } else if (request.requiresFanout()) {
    handleFanoutRequest(request);
  } else if (request.requiresRouting()) {
    handleRoutedRequest(request);
  } else if (request.isPing()) {
    // Respond to ping directly
    JsonRpcResponse response;
    response.id = request.id;
    response.result_raw = "{}";
    sendJsonRpcResponse(response);
  } else if (request.isNotification()) {
    // Notifications don't expect a response - just accept
    decoder_callbacks_->sendLocalReply(Http::Code::Accepted, "", nullptr,
                                       absl::nullopt, "notification_accepted");
  } else {
    sendJsonRpcError(request.id.value_or("null"),
                     McpConstants::kJsonRpcMethodNotFound, "Method not found");
  }
}

void McpFilter::handleInitialize(const JsonRpcRequest& request) {
  ENVOY_LOG(debug, "handling initialize request");

  // TODO: Implement full initialization with fanout to all backends
  // For now, create a session with placeholder backend sessions

  std::vector<BackendInitResult> init_results;
  for (const auto& backend : config_->backends()) {
    BackendInitResult result;
    result.backend_name = backend.name;
    result.session_id = absl::StrCat("session-", backend.name, "-",
                                     std::to_string(std::chrono::system_clock::now()
                                         .time_since_epoch().count()));
    result.success = true;
    init_results.push_back(result);
  }

  // Create composite session
  auto session_or = session_manager_->createCompositeSession(
      "",  // subject - TODO: extract from auth
      config_->routeName(),
      init_results);

  if (!session_or.ok()) {
    sendJsonRpcError(request.id.value_or("null"),
                     McpConstants::kJsonRpcInternalError, "Session creation failed");
    return;
  }

  current_session_id_ = *session_or;

  // Build response
  JsonRpcResponse response = response_merger_->mergeInitialize({}, request);
  sendJsonRpcResponse(response);
}

void McpFilter::handleFanoutRequest(const JsonRpcRequest& request) {
  ENVOY_LOG(debug, "handling fanout request: method={}", request.method);

  // TODO: Implement actual fanout to backends using AsyncClient
  // For now, return empty result

  JsonRpcResponse response;
  response.id = request.id;

  if (request.isToolsList()) {
    response = response_merger_->mergeToolsList({}, request);
  } else if (request.isPromptsList()) {
    response = response_merger_->mergePromptsList({}, request);
  } else if (request.isResourcesList()) {
    response = response_merger_->mergeResourcesList({}, request);
  } else {
    response.result_raw = "{}";
  }

  sendJsonRpcResponse(response);
}

void McpFilter::handleRoutedRequest(const JsonRpcRequest& request) {
  ENVOY_LOG(debug, "handling routed request: method={}", request.method);

  // Extract tool/resource name from params
  std::string name;
  if (request.isToolsCall()) {
    auto name_opt = JsonRpcParser::extractParamString(request.params_raw, "name");
    if (name_opt) {
      name = *name_opt;
    }
  } else if (request.isPromptsGet()) {
    auto name_opt = JsonRpcParser::extractParamString(request.params_raw, "name");
    if (name_opt) {
      name = *name_opt;
    }
  } else if (request.isResourcesRead()) {
    auto uri_opt = JsonRpcParser::extractParamString(request.params_raw, "uri");
    if (uri_opt) {
      // Parse backend from URI: backend+originaluri
      std::string uri = *uri_opt;
      size_t pos = uri.find('+');
      if (pos != std::string::npos) {
        name = uri.substr(0, pos) + config_->prefixSeparator() + "placeholder";
      }
    }
  }

  if (name.empty()) {
    sendJsonRpcError(request.id.value_or("null"),
                     McpConstants::kJsonRpcInvalidParams, "Missing name in params");
    return;
  }

  // Extract backend from name
  auto backend_or = config_->extractBackendFromName(name);
  if (!backend_or) {
    sendJsonRpcError(request.id.value_or("null"),
                     McpConstants::kJsonRpcInvalidParams, "Invalid tool/resource name format");
    return;
  }

  const auto& [backend_name, original_name] = *backend_or;

  const BackendConfig* backend = config_->getBackend(backend_name);
  if (backend == nullptr) {
    sendJsonRpcError(request.id.value_or("null"),
                     McpConstants::kJsonRpcMethodNotFound,
                     absl::StrCat("Unknown backend: ", backend_name));
    return;
  }

  ENVOY_LOG(debug, "routing to backend: {} with original name: {}", backend_name, original_name);

  // TODO: Route request to specific backend using AsyncClient
  // For now, return an error indicating not yet implemented
  sendJsonRpcError(request.id.value_or("null"),
                   McpConstants::kJsonRpcInternalError, "Backend routing not yet implemented");
}

void McpFilter::handleDelete() {
  ENVOY_LOG(debug, "handling DELETE request for session termination");

  // Get session ID from header
  auto session_header = request_headers_->get(
      Http::LowerCaseString(std::string(McpConstants::kSessionIdHeader)));

  if (session_header.empty()) {
    sendLocalError(Http::Code::BadRequest, "Missing session ID");
    return;
  }

  // TODO: Fanout DELETE to all backends
  // For now, just return success
  decoder_callbacks_->sendLocalReply(Http::Code::OK, "", nullptr,
                                     absl::nullopt, "session_terminated");
}

void McpFilter::sendJsonRpcResponse(const JsonRpcResponse& response) {
  if (response_sent_) {
    return;
  }
  response_sent_ = true;

  std::string body = JsonRpcParser::serializeResponse(response);

  decoder_callbacks_->sendLocalReply(
      Http::Code::OK, body,
      [this](Http::ResponseHeaderMap& headers) {
        headers.setContentType("application/json");
        if (!current_session_id_.empty()) {
          headers.addCopy(Http::LowerCaseString(std::string(McpConstants::kSessionIdHeader)),
                          current_session_id_);
        }
      },
      absl::nullopt, "mcp_response");
}

void McpFilter::sendJsonRpcError(const std::string& id, int code, const std::string& message) {
  if (response_sent_) {
    return;
  }
  response_sent_ = true;

  std::string body = JsonRpcParser::serializeError(id, code, message);

  decoder_callbacks_->sendLocalReply(
      Http::Code::OK, body,  // JSON-RPC errors use 200 status
      [](Http::ResponseHeaderMap& headers) {
        headers.setContentType("application/json");
      },
      absl::nullopt, "mcp_error");
}

void McpFilter::sendLocalError(Http::Code code, const std::string& message) {
  if (response_sent_) {
    return;
  }
  response_sent_ = true;

  decoder_callbacks_->sendLocalReply(code, message, nullptr, absl::nullopt, "mcp_error");
}

void McpFilter::finalizeDynamicMetadata() {
  if (!parsed_request_) {
    return;
  }

  ProtobufWkt::Struct metadata;
  auto& fields = *metadata.mutable_fields();

  fields["method"].set_string_value(parsed_request_->method);

  if (parsed_request_->id) {
    fields["id"].set_string_value(*parsed_request_->id);
  }

  fields["jsonrpc"].set_string_value(parsed_request_->jsonrpc);

  decoder_callbacks_->streamInfo().setDynamicMetadata(
      std::string(MetadataKeys::FilterName), metadata);

  ENVOY_LOG(debug, "MCP filter set dynamic metadata for method: {}", parsed_request_->method);
}

} // namespace Mcp
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
