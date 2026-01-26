//! Response Aggregation for Fanout Methods
//!
//! Merges responses from multiple backends for list operations like
//! tools/list, resources/list, prompts/list, etc.

use crate::method::{prefix_tool_name, prefix_prompt_name, prefix_resource_uri};
use crate::config::{PROTOCOL_VERSION, GATEWAY_NAME, GATEWAY_VERSION};
use serde_json::{json, Value};

// ============================================================================
// Backend Response
// ============================================================================

/// Content type of backend response
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResponseContentType {
    #[default]
    Unknown,
    Json,
    Sse,
}

impl ResponseContentType {
    /// Detect content type from Content-Type header value
    pub fn from_header(content_type: &str) -> Self {
        let media_type = content_type.split(';').next().unwrap_or("").trim();
        match media_type.to_lowercase().as_str() {
            "application/json" => ResponseContentType::Json,
            "text/event-stream" => ResponseContentType::Sse,
            _ => ResponseContentType::Unknown,
        }
    }
}

/// Response from a single backend
#[derive(Debug, Clone, Default)]
pub struct BackendResponse {
    /// Backend name
    pub backend_name: String,
    
    /// HTTP status code
    pub status_code: u32,
    
    /// Whether the request was successful
    pub success: bool,
    
    /// Response body (JSON string or SSE data)
    pub body: String,
    
    /// Session ID returned by backend
    pub session_id: String,
    
    /// Error message if failed
    pub error: String,
    
    /// Content type of the response
    pub content_type: ResponseContentType,
    
    /// Cached extracted JSON-RPC body (populated for SSE responses)
    pub extracted_jsonrpc: String,
}

impl BackendResponse {
    /// Parse the response body as JSON
    pub fn parse_body(&self) -> Option<Value> {
        let json_body = self.get_jsonrpc();
        if json_body.is_empty() {
            return None;
        }
        serde_json::from_str(json_body).ok()
    }
    
    /// Get the result field from a JSON-RPC response
    pub fn get_result(&self) -> Option<Value> {
        self.parse_body()
            .and_then(|v| v.get("result").cloned())
    }
    
    /// Get the error field from a JSON-RPC response
    pub fn get_error(&self) -> Option<Value> {
        self.parse_body()
            .and_then(|v| v.get("error").cloned())
    }
    
    /// Check if response is SSE
    pub fn is_sse(&self) -> bool {
        self.content_type == ResponseContentType::Sse
    }
    
    /// Check if response is JSON
    pub fn is_json(&self) -> bool {
        self.content_type == ResponseContentType::Json
    }
    
    /// Get the JSON-RPC body: extracted_jsonrpc if SSE, otherwise body
    pub fn get_jsonrpc(&self) -> &str {
        if !self.extracted_jsonrpc.is_empty() {
            &self.extracted_jsonrpc
        } else {
            &self.body
        }
    }
}

// ============================================================================
// Initialize Aggregation
// ============================================================================

/// Aggregate initialize responses from all backends
///
/// Returns gateway capabilities with all backend sessions collected
pub fn aggregate_initialize(
    responses: &[BackendResponse],
    request_id: i64,
) -> (Value, bool) {
    let mut any_success = false;
    
    // Check for any successful responses
    for resp in responses {
        if resp.success {
            any_success = true;
            break;
        }
    }
    
    // Build gateway capabilities response
    let result = json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": true },
            "resources": { "subscribe": true, "listChanged": true },
            "prompts": { "listChanged": true },
            "logging": {}
        },
        "serverInfo": {
            "name": GATEWAY_NAME,
            "version": GATEWAY_VERSION
        }
    });
    
    let response = json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result
    });
    
    (response, any_success)
}

// ============================================================================
// Tools List Aggregation
// ============================================================================

/// Aggregate tools/list responses from all backends
///
/// Merges tools from all backends, prefixing names with backend identifier
pub fn aggregate_tools_list(
    responses: &[BackendResponse],
    request_id: i64,
    multiplexing: bool,
) -> Value {
    let mut all_tools = Vec::new();
    
    for resp in responses {
        if !resp.success {
            continue;
        }
        
        if let Some(result) = resp.get_result() {
            if let Some(tools) = result.get("tools").and_then(|t| t.as_array()) {
                for tool in tools {
                    let mut tool = tool.clone();
                    
                    // Prefix the tool name with backend name
                    if multiplexing {
                        if let Some(name) = tool.get("name").and_then(|n| n.as_str()) {
                            let prefixed = prefix_tool_name(&resp.backend_name, name);
                            tool["name"] = json!(prefixed);
                        }
                    }
                    
                    all_tools.push(tool);
                }
            }
        }
    }
    
    json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "tools": all_tools
        }
    })
}

// ============================================================================
// Resources List Aggregation
// ============================================================================

/// Aggregate resources/list responses from all backends
///
/// Merges resources from all backends, prefixing URIs and names
pub fn aggregate_resources_list(
    responses: &[BackendResponse],
    request_id: i64,
    multiplexing: bool,
) -> Value {
    let mut all_resources = Vec::new();
    
    for resp in responses {
        if !resp.success {
            continue;
        }
        
        if let Some(result) = resp.get_result() {
            if let Some(resources) = result.get("resources").and_then(|r| r.as_array()) {
                for resource in resources {
                    let mut resource = resource.clone();
                    
                    if multiplexing {
                        // Prefix the resource URI
                        if let Some(uri) = resource.get("uri").and_then(|u| u.as_str()) {
                            let prefixed = prefix_resource_uri(&resp.backend_name, uri);
                            resource["uri"] = json!(prefixed);
                        }
                        
                        // Prefix the resource name
                        if let Some(name) = resource.get("name").and_then(|n| n.as_str()) {
                            let prefixed = prefix_tool_name(&resp.backend_name, name);
                            resource["name"] = json!(prefixed);
                        }
                    }
                    
                    all_resources.push(resource);
                }
            }
        }
    }
    
    json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "resources": all_resources
        }
    })
}

// ============================================================================
// Resource Templates List Aggregation
// ============================================================================

/// Aggregate resources/templates/list responses from all backends
pub fn aggregate_resource_templates_list(
    responses: &[BackendResponse],
    request_id: i64,
    multiplexing: bool,
) -> Value {
    let mut all_templates = Vec::new();
    
    for resp in responses {
        if !resp.success {
            continue;
        }
        
        if let Some(result) = resp.get_result() {
            if let Some(templates) = result.get("resourceTemplates").and_then(|r| r.as_array()) {
                for template in templates {
                    let mut template = template.clone();
                    
                    if multiplexing {
                        // Prefix the URI template
                        if let Some(uri) = template.get("uriTemplate").and_then(|u| u.as_str()) {
                            let prefixed = prefix_resource_uri(&resp.backend_name, uri);
                            template["uriTemplate"] = json!(prefixed);
                        }
                        
                        // Prefix the name
                        if let Some(name) = template.get("name").and_then(|n| n.as_str()) {
                            let prefixed = prefix_tool_name(&resp.backend_name, name);
                            template["name"] = json!(prefixed);
                        }
                    }
                    
                    all_templates.push(template);
                }
            }
        }
    }
    
    json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "resourceTemplates": all_templates
        }
    })
}

// ============================================================================
// Prompts List Aggregation
// ============================================================================

/// Aggregate prompts/list responses from all backends
///
/// Merges prompts from all backends, prefixing names
pub fn aggregate_prompts_list(
    responses: &[BackendResponse],
    request_id: i64,
    multiplexing: bool,
) -> Value {
    let mut all_prompts = Vec::new();
    
    for resp in responses {
        if !resp.success {
            continue;
        }
        
        if let Some(result) = resp.get_result() {
            if let Some(prompts) = result.get("prompts").and_then(|p| p.as_array()) {
                for prompt in prompts {
                    let mut prompt = prompt.clone();
                    
                    if multiplexing {
                        // Prefix the prompt name
                        if let Some(name) = prompt.get("name").and_then(|n| n.as_str()) {
                            let prefixed = prefix_prompt_name(&resp.backend_name, name);
                            prompt["name"] = json!(prefixed);
                        }
                    }
                    
                    all_prompts.push(prompt);
                }
            }
        }
    }
    
    json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "prompts": all_prompts
        }
    })
}

// ============================================================================
// Broadcast Response (for notifications and logging)
// ============================================================================

/// Create a response for broadcast methods (logging/setLevel)
///
/// Returns empty result if any backend succeeded
pub fn aggregate_broadcast(
    responses: &[BackendResponse],
    request_id: i64,
) -> Value {
    let any_success = responses.iter().any(|r| r.success);
    
    if any_success {
        json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {}
        })
    } else {
        json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32603,
                "message": "All backends failed"
            }
        })
    }
}

// ============================================================================
// Error Response
// ============================================================================

/// Create a JSON-RPC error response
pub fn error_response(request_id: i64, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

/// Create a JSON-RPC error response for backend not found
pub fn backend_not_found_response(request_id: i64, backend: &str) -> Value {
    error_response(request_id, -32602, &format!("Backend not found: {}", backend))
}

/// Create a JSON-RPC error response for session not found
pub fn session_not_found_response(request_id: i64, backend: &str) -> Value {
    error_response(request_id, -32602, &format!("No session for backend: {}", backend))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response(backend: &str, body: &str, success: bool) -> BackendResponse {
        BackendResponse {
            backend_name: backend.to_string(),
            status_code: if success { 200 } else { 500 },
            success,
            body: body.to_string(),
            session_id: String::new(),
            error: String::new(),
        }
    }

    #[test]
    fn test_aggregate_tools_list() {
        let responses = vec![
            make_response("time", r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_time","description":"Get current time"}]}}"#, true),
            make_response("files", r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"Read a file"}]}}"#, true),
        ];
        
        let result = aggregate_tools_list(&responses, 1, true);
        let tools = result["result"]["tools"].as_array().unwrap();
        
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "time__get_time");
        assert_eq!(tools[1]["name"], "files__read_file");
    }

    #[test]
    fn test_aggregate_resources_list() {
        let responses = vec![
            make_response("backend1", r#"{"jsonrpc":"2.0","id":1,"result":{"resources":[{"uri":"file:///test.txt","name":"test"}]}}"#, true),
        ];
        
        let result = aggregate_resources_list(&responses, 1, true);
        let resources = result["result"]["resources"].as_array().unwrap();
        
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "backend1+file:///test.txt");
        assert_eq!(resources[0]["name"], "backend1__test");
    }

    #[test]
    fn test_aggregate_prompts_list() {
        let responses = vec![
            make_response("ai", r#"{"jsonrpc":"2.0","id":1,"result":{"prompts":[{"name":"summarize","description":"Summarize text"}]}}"#, true),
        ];
        
        let result = aggregate_prompts_list(&responses, 1, true);
        let prompts = result["result"]["prompts"].as_array().unwrap();
        
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["name"], "ai__summarize");
    }

    #[test]
    fn test_aggregate_with_failures() {
        let responses = vec![
            make_response("good", r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"tool1"}]}}"#, true),
            make_response("bad", "", false),
        ];
        
        let result = aggregate_tools_list(&responses, 1, true);
        let tools = result["result"]["tools"].as_array().unwrap();
        
        // Should only include tools from successful response
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "good__tool1");
    }

    #[test]
    fn test_aggregate_initialize() {
        let responses = vec![
            make_response("backend1", r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#, true),
        ];
        
        let (result, success) = aggregate_initialize(&responses, 1);
        
        assert!(success);
        assert_eq!(result["result"]["serverInfo"]["name"], GATEWAY_NAME);
    }
}
