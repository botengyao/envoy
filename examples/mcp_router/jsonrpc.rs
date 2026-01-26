//! JSON-RPC 2.0 Types for MCP
//!
//! Provides serialization/deserialization for JSON-RPC messages used in MCP.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// JSON-RPC Request
// ============================================================================

/// JSON-RPC 2.0 Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version (always "2.0")
    pub jsonrpc: String,
    
    /// Method name
    pub method: String,
    
    /// Request ID (optional for notifications)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<JsonRpcId>,
    
    /// Method parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Create a new JSON-RPC request
    pub fn new(method: &str, id: Option<JsonRpcId>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            id,
            params,
        }
    }
    
    /// Create a notification (no ID, no response expected)
    pub fn notification(method: &str, params: Option<Value>) -> Self {
        Self::new(method, None, params)
    }
    
    /// Check if this is a notification (no ID)
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
    
    /// Get the tool name from params (for tools/call)
    pub fn get_tool_name(&self) -> Option<&str> {
        self.params.as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
    }
    
    /// Get the resource URI from params (for resources/read, etc.)
    pub fn get_resource_uri(&self) -> Option<&str> {
        self.params.as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(|v| v.as_str())
    }
    
    /// Get the prompt name from params (for prompts/get)
    pub fn get_prompt_name(&self) -> Option<&str> {
        self.params.as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
    }
    
    /// Get the completion ref from params (for completion/complete)
    pub fn get_completion_ref(&self) -> Option<&Value> {
        self.params.as_ref()
            .and_then(|p| p.get("ref"))
    }
    
    /// Get the logging level from params (for logging/setLevel)
    pub fn get_logging_level(&self) -> Option<&str> {
        self.params.as_ref()
            .and_then(|p| p.get("level"))
            .and_then(|v| v.as_str())
    }
}

// ============================================================================
// JSON-RPC Response
// ============================================================================

/// JSON-RPC 2.0 Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version (always "2.0")
    pub jsonrpc: String,
    
    /// Request ID (matches the request)
    pub id: JsonRpcId,
    
    /// Result (present on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    
    /// Error (present on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Create a success response
    pub fn success(id: JsonRpcId, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }
    
    /// Create an error response
    pub fn error(id: JsonRpcId, code: i32, message: &str) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        }
    }
    
    /// Check if this response is an error
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
    
    /// Check if this response is successful
    pub fn is_success(&self) -> bool {
        self.result.is_some() && self.error.is_none()
    }
}

// ============================================================================
// JSON-RPC Error
// ============================================================================

/// JSON-RPC 2.0 Error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    
    /// Error message
    pub message: String,
    
    /// Additional error data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// Standard JSON-RPC error codes
impl JsonRpcError {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

// ============================================================================
// JSON-RPC ID
// ============================================================================

/// JSON-RPC ID (can be string, number, or null)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum JsonRpcId {
    String(String),
    Number(i64),
    Null,
}

impl Default for JsonRpcId {
    fn default() -> Self {
        JsonRpcId::Null
    }
}

impl From<i64> for JsonRpcId {
    fn from(n: i64) -> Self {
        JsonRpcId::Number(n)
    }
}

impl From<&str> for JsonRpcId {
    fn from(s: &str) -> Self {
        JsonRpcId::String(s.to_string())
    }
}

impl From<String> for JsonRpcId {
    fn from(s: String) -> Self {
        JsonRpcId::String(s)
    }
}

impl std::fmt::Display for JsonRpcId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonRpcId::String(s) => write!(f, "{}", s),
            JsonRpcId::Number(n) => write!(f, "{}", n),
            JsonRpcId::Null => write!(f, "null"),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse a JSON-RPC request from bytes
pub fn parse_request(body: &[u8]) -> Result<JsonRpcRequest, String> {
    serde_json::from_slice(body)
        .map_err(|e| format!("JSON-RPC parse error: {}", e))
}

/// Serialize a JSON-RPC response to bytes
pub fn serialize_response(response: &JsonRpcResponse) -> Vec<u8> {
    serde_json::to_vec(response).unwrap_or_default()
}

/// Create a simple error response body
pub fn error_response_body(id: JsonRpcId, code: i32, message: &str) -> Vec<u8> {
    serialize_response(&JsonRpcResponse::error(id, code, message))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request() {
        let json = r#"{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"test_tool"}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.id, Some(JsonRpcId::Number(1)));
        assert_eq!(req.get_tool_name(), Some("test_tool"));
    }

    #[test]
    fn test_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        
        assert!(req.is_notification());
        assert_eq!(req.method, "notifications/initialized");
    }

    #[test]
    fn test_response_serialization() {
        let resp = JsonRpcResponse::success(
            JsonRpcId::Number(1),
            serde_json::json!({"tools": []})
        );
        
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"result\""));
        assert!(!json.contains("\"error\""));
    }

    #[test]
    fn test_error_response() {
        let resp = JsonRpcResponse::error(
            JsonRpcId::Number(1),
            JsonRpcError::METHOD_NOT_FOUND,
            "Method not found"
        );
        
        assert!(resp.is_error());
        assert!(!resp.is_success());
    }
}
