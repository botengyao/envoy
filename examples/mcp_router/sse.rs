//! SSE (Server-Sent Events) Streaming Support
//!
//! Handles bidirectional streaming for MCP:
//! - GET requests: Long-lived SSE stream for server→client notifications
//! - POST responses: SSE stream for streaming tool results
//!
//! ## Stream Merging Architecture
//!
//! For multiplexing, we need to merge SSE streams from multiple backends:
//!
//! ```text
//! Backend A ──SSE──┐
//!                  ├──► Gateway ──SSE──► Client
//! Backend B ──SSE──┘
//! ```
//!
//! ## Event ID Management
//!
//! Composite event IDs allow reconnection with Last-Event-ID:
//! ```text
//! {backend1}:{base64(eventId1)},{backend2}:{base64(eventId2)}
//! ```

use crate::session::SessionCodec;
use crate::method::prefix_resource_uri;
use std::collections::HashMap;
use serde_json::Value;

// ============================================================================
// SSE Event
// ============================================================================

/// SSE Event structure
#[derive(Debug, Clone, Default)]
pub struct SseEvent {
    /// Event ID (optional)
    pub id: Option<String>,
    /// Event type (optional, defaults to "message")
    pub event: Option<String>,
    /// Event data (required)
    pub data: String,
    /// Retry interval in ms (optional)
    pub retry: Option<u32>,
}

impl SseEvent {
    /// Create a new SSE event with just data
    pub fn new(data: impl Into<String>) -> Self {
        Self {
            id: None,
            event: None,
            data: data.into(),
            retry: None,
        }
    }

    /// Set the event ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the event type
    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Set retry interval
    pub fn with_retry(mut self, retry: u32) -> Self {
        self.retry = Some(retry);
        self
    }

    /// Format as SSE wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = String::new();
        
        if let Some(ref id) = self.id {
            output.push_str(&format!("id: {}\n", id));
        }
        if let Some(ref event) = self.event {
            output.push_str(&format!("event: {}\n", event));
        }
        if let Some(retry) = self.retry {
            output.push_str(&format!("retry: {}\n", retry));
        }
        
        // Data can be multi-line, each line prefixed with "data: "
        for line in self.data.lines() {
            output.push_str(&format!("data: {}\n", line));
        }
        
        // Empty line terminates the event
        output.push('\n');
        
        output.into_bytes()
    }

    /// Parse SSE event from wire format
    pub fn parse(input: &str) -> Option<Self> {
        let mut event = SseEvent::default();
        let mut data_lines = Vec::new();
        
        for line in input.lines() {
            if line.is_empty() {
                // End of event
                break;
            }
            
            if let Some(value) = line.strip_prefix("id: ") {
                event.id = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("id:") {
                event.id = Some(value.trim_start().to_string());
            } else if let Some(value) = line.strip_prefix("event: ") {
                event.event = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("event:") {
                event.event = Some(value.trim_start().to_string());
            } else if let Some(value) = line.strip_prefix("data: ") {
                data_lines.push(value.to_string());
            } else if let Some(value) = line.strip_prefix("data:") {
                data_lines.push(value.trim_start().to_string());
            } else if let Some(value) = line.strip_prefix("retry: ") {
                event.retry = value.parse().ok();
            } else if let Some(value) = line.strip_prefix("retry:") {
                event.retry = value.trim_start().parse().ok();
            }
            // Ignore comments (lines starting with ':')
        }
        
        if data_lines.is_empty() {
            return None;
        }
        
        event.data = data_lines.join("\n");
        Some(event)
    }

    /// Parse the data as JSON
    pub fn parse_json(&self) -> Option<Value> {
        serde_json::from_str(&self.data).ok()
    }
}

// ============================================================================
// Composite Event ID
// ============================================================================

/// Composite Event ID for multiplexed streams
/// 
/// Format: `{backend1}:{base64(eventId1)},{backend2}:{base64(eventId2)}`
/// 
/// This allows the client to reconnect with Last-Event-ID and the gateway
/// can route the reconnection to each backend with their respective event IDs.
#[derive(Debug, Clone, Default)]
pub struct CompositeEventId {
    pub backend_events: HashMap<String, String>,
}

impl CompositeEventId {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the event ID for a specific backend
    pub fn update(&mut self, backend: &str, event_id: &str) {
        self.backend_events.insert(backend.to_string(), event_id.to_string());
    }

    /// Encode to wire format
    pub fn encode(&self) -> String {
        if self.backend_events.is_empty() {
            return String::new();
        }
        
        self.backend_events
            .iter()
            .map(|(backend, event_id)| {
                format!("{}:{}", backend, SessionCodec::encode(event_id))
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Parse from Last-Event-ID header
    pub fn parse(encoded: &str) -> Result<Self, String> {
        let mut result = Self::new();
        
        if encoded.is_empty() {
            return Ok(result);
        }
        
        for part in encoded.split(',') {
            if let Some(colon_pos) = part.find(':') {
                let backend = &part[..colon_pos];
                let encoded_id = &part[colon_pos + 1..];
                
                if !backend.is_empty() && !encoded_id.is_empty() {
                    let event_id = SessionCodec::decode(encoded_id)?;
                    result.backend_events.insert(backend.to_string(), event_id);
                }
            }
        }
        
        Ok(result)
    }

    /// Get the event ID for a specific backend
    pub fn get(&self, backend: &str) -> Option<&str> {
        self.backend_events.get(backend).map(|s| s.as_str())
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.backend_events.is_empty()
    }
}

// ============================================================================
// SSE Stream State
// ============================================================================

/// SSE Stream state for a single backend
#[derive(Debug)]
pub struct BackendSseStream {
    pub backend_name: String,
    pub stream_id: u64,
    pub last_event_id: Option<String>,
    pub connected: bool,
}

/// SSE Stream manager for multiplexing
#[derive(Debug, Default)]
pub struct SseStreamManager {
    /// Active backend streams (stream_id -> stream info)
    pub streams: HashMap<u64, BackendSseStream>,
    /// Composite event ID tracking
    pub composite_event_id: CompositeEventId,
    /// Whether we're in SSE mode
    pub sse_mode: bool,
    /// Buffer for partial event data
    pub partial_buffers: HashMap<u64, String>,
}

impl SseStreamManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable SSE mode
    pub fn enable_sse(&mut self) {
        self.sse_mode = true;
    }

    /// Register a new backend stream
    pub fn add_stream(&mut self, stream_id: u64, backend_name: &str) {
        self.streams.insert(stream_id, BackendSseStream {
            backend_name: backend_name.to_string(),
            stream_id,
            last_event_id: None,
            connected: true,
        });
        self.partial_buffers.insert(stream_id, String::new());
    }

    /// Get backend name for a stream
    pub fn get_backend_name(&self, stream_id: u64) -> Option<&str> {
        self.streams.get(&stream_id).map(|s| s.backend_name.as_str())
    }

    /// Update event ID for a backend
    pub fn update_event_id(&mut self, stream_id: u64, event_id: &str) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.last_event_id = Some(event_id.to_string());
            self.composite_event_id.update(&stream.backend_name, event_id);
        }
    }

    /// Mark a stream as disconnected
    pub fn mark_disconnected(&mut self, stream_id: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.connected = false;
        }
    }

    /// Check if all streams are disconnected
    pub fn all_disconnected(&self) -> bool {
        self.streams.is_empty() || self.streams.values().all(|s| !s.connected)
    }

    /// Get the current composite event ID
    pub fn get_composite_event_id(&self) -> String {
        self.composite_event_id.encode()
    }

    /// Get number of active streams
    pub fn active_stream_count(&self) -> usize {
        self.streams.values().filter(|s| s.connected).count()
    }

    /// Append data to partial buffer and extract complete events
    pub fn append_data(&mut self, stream_id: u64, data: &str) -> Vec<SseEvent> {
        let buffer = self.partial_buffers.entry(stream_id).or_default();
        buffer.push_str(data);
        
        let mut events = Vec::new();
        
        // Split on double newlines (SSE event separator)
        while let Some(pos) = buffer.find("\n\n") {
            let event_str = buffer[..pos + 2].to_string();
            *buffer = buffer[pos + 2..].to_string();
            
            if let Some(event) = SseEvent::parse(&event_str) {
                events.push(event);
            }
        }
        
        events
    }
}

// ============================================================================
// Server-to-Client Request ID Encoding
// ============================================================================

/// Server-to-client request ID encoding for bidirectional JSON-RPC
/// 
/// When a backend sends a request to the client (e.g., sampling/createMessage),
/// we need to encode the backend info into the request ID so we can route
/// the client's response back to the correct backend.
/// 
/// Format: `{originalId}__{type}__{backend}`
/// Where type is: i (int), f (float), s (string), n (null)
pub mod request_id_encoding {
    use super::*;

    const ID_SEPARATOR: &str = "__";

    /// Encode a server-to-client request ID with backend info
    pub fn encode_request_id(original_id: &Value, backend: &str) -> String {
        match original_id {
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    format!("{}{}i{}{}", i, ID_SEPARATOR, ID_SEPARATOR, backend)
                } else if let Some(f) = n.as_f64() {
                    // Encode float as hex for safe string representation
                    format!("{:016x}{}f{}{}", f.to_bits(), ID_SEPARATOR, ID_SEPARATOR, backend)
                } else {
                    format!("{}{}n{}{}", n, ID_SEPARATOR, ID_SEPARATOR, backend)
                }
            }
            Value::String(s) => {
                let encoded = SessionCodec::encode(s);
                format!("{}{}s{}{}", encoded, ID_SEPARATOR, ID_SEPARATOR, backend)
            }
            Value::Null => {
                format!("null{}n{}{}", ID_SEPARATOR, ID_SEPARATOR, backend)
            }
            _ => {
                // For other types, convert to string
                let s = original_id.to_string();
                let encoded = SessionCodec::encode(&s);
                format!("{}{}s{}{}", encoded, ID_SEPARATOR, ID_SEPARATOR, backend)
            }
        }
    }

    /// Decode a client response ID to find the target backend
    pub fn decode_request_id(encoded_id: &str) -> Option<(Value, String)> {
        // Split from the right to handle IDs that might contain "__"
        let parts: Vec<&str> = encoded_id.rsplitn(3, ID_SEPARATOR).collect();
        if parts.len() != 3 {
            return None;
        }

        let backend = parts[0].to_string();
        let id_type = parts[1];
        let id_value = parts[2];

        let original_id = match id_type {
            "i" => {
                let i: i64 = id_value.parse().ok()?;
                Value::Number(i.into())
            }
            "f" => {
                let bits: u64 = u64::from_str_radix(id_value, 16).ok()?;
                let f = f64::from_bits(bits);
                serde_json::Number::from_f64(f).map(Value::Number)?
            }
            "s" => {
                let decoded = SessionCodec::decode(id_value).ok()?;
                Value::String(decoded)
            }
            "n" => Value::Null,
            _ => return None,
        };

        Some((original_id, backend))
    }
}

// ============================================================================
// Server-to-Client Message Transformation
// ============================================================================

/// Transform a server-to-client message for multiplexing
/// 
/// This handles:
/// - Encoding request IDs so responses route back correctly
/// - Prefixing resource URIs in notifications
pub fn transform_server_to_client_message(
    msg: &mut Value,
    backend: &str,
    multiplexing: bool,
) -> bool {
    // Extract method as owned String to avoid borrow conflicts
    let method = msg.get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    
    // If this is a request (has method and id), encode the ID
    if msg.get("id").is_some() && !method.is_empty() {
        if let Some(id) = msg.get("id").cloned() {
            let encoded_id = request_id_encoding::encode_request_id(&id, backend);
            msg["id"] = Value::String(encoded_id);
        }
    }
    
    // Transform notifications that need URI prefixing
    if multiplexing && method == "notifications/resources/updated" {
        if let Some(params) = msg.get_mut("params") {
            if let Some(uri) = params.get("uri").and_then(|u| u.as_str()).map(|s| s.to_string()) {
                let prefixed = prefix_resource_uri(backend, &uri);
                params["uri"] = Value::String(prefixed);
            }
        }
    }
    
    true
}

// ============================================================================
// SSE Message Classification
// ============================================================================

/// Message type classification for SSE events
/// Used during aggregation to identify different JSON-RPC message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SseMessageType {
    /// Notification - method with no id (notifications/*)
    Notification,
    /// ServerRequest - method with id (sampling/createMessage, roots/list)
    ServerRequest,
    /// Response - has result or error with matching id
    Response,
    /// Unknown message type
    Unknown,
}

/// Classifies a JSON-RPC message from SSE event data
/// 
/// Classification logic:
/// - Has `result` or `error` with matching ID → Response
/// - Has `method` but no `id` → Notification
/// - Has `method` AND `id` → ServerRequest
/// - Otherwise → Unknown
pub fn classify_message(json_data: &str, request_id: i64) -> SseMessageType {
    let parsed: Value = match serde_json::from_str(json_data) {
        Ok(v) => v,
        Err(_) => return SseMessageType::Unknown,
    };

    let has_id = parsed.get("id").is_some();
    let has_method = parsed.get("method").is_some();
    let has_result = parsed.get("result").is_some();
    let has_error = parsed.get("error").is_some();

    // Has result or error with matching ID -> Response
    if has_result || has_error {
        if let Some(id) = parsed.get("id").and_then(|v| v.as_i64()) {
            if request_id == 0 || id == request_id {
                return SseMessageType::Response;
            }
        }
    }

    // Has method but no id -> Notification
    if has_method && !has_id {
        return SseMessageType::Notification;
    }

    // Has method AND id -> ServerRequest
    if has_method && has_id {
        return SseMessageType::ServerRequest;
    }

    SseMessageType::Unknown
}

/// Extract JSON-RPC response body from SSE data
/// Returns the first Response event's data field, or None if not found
pub fn extract_jsonrpc_from_sse(body: &str, request_id: i64) -> Option<String> {
    let mut pos = 0;
    while pos < body.len() {
        let remaining = &body[pos..];
        // Find next double newline (SSE event separator)
        if let Some(end) = remaining.find("\n\n") {
            let event_str = &remaining[..end + 2];
            if let Some(event) = SseEvent::parse(event_str) {
                if !event.data.is_empty() {
                    let msg_type = classify_message(&event.data, request_id);
                    if msg_type == SseMessageType::Response {
                        return Some(event.data);
                    }
                }
            }
            pos += end + 2;
        } else {
            // Try parsing remaining as last event (no trailing newlines)
            if let Some(event) = SseEvent::parse(remaining) {
                if !event.data.is_empty() {
                    let msg_type = classify_message(&event.data, request_id);
                    if msg_type == SseMessageType::Response {
                        return Some(event.data);
                    }
                }
            }
            break;
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_event_format() {
        let event = SseEvent::new(r#"{"jsonrpc":"2.0","method":"test"}"#)
            .with_id("123")
            .with_event("message");
        
        let bytes = event.to_bytes();
        let formatted = String::from_utf8(bytes).unwrap();
        
        assert!(formatted.contains("id: 123\n"));
        assert!(formatted.contains("event: message\n"));
        assert!(formatted.contains("data: {"));
        assert!(formatted.ends_with("\n\n"));
    }

    #[test]
    fn test_sse_event_parse() {
        let input = "id: 123\nevent: message\ndata: hello\ndata: world\n\n";
        let event = SseEvent::parse(input).unwrap();
        
        assert_eq!(event.id, Some("123".to_string()));
        assert_eq!(event.event, Some("message".to_string()));
        assert_eq!(event.data, "hello\nworld");
    }

    #[test]
    fn test_composite_event_id() {
        let mut composite = CompositeEventId::new();
        composite.update("time", "event-123");
        composite.update("files", "event-456");
        
        let encoded = composite.encode();
        let parsed = CompositeEventId::parse(&encoded).unwrap();
        
        assert_eq!(parsed.get("time"), Some("event-123"));
        assert_eq!(parsed.get("files"), Some("event-456"));
    }

    #[test]
    fn test_request_id_encoding_int() {
        use request_id_encoding::*;
        
        let id = serde_json::json!(42);
        let encoded = encode_request_id(&id, "backend1");
        let (decoded_id, backend) = decode_request_id(&encoded).unwrap();
        
        assert_eq!(decoded_id, id);
        assert_eq!(backend, "backend1");
    }

    #[test]
    fn test_request_id_encoding_string() {
        use request_id_encoding::*;
        
        let id = serde_json::json!("my-request-id");
        let encoded = encode_request_id(&id, "backend2");
        let (decoded_id, backend) = decode_request_id(&encoded).unwrap();
        
        assert_eq!(decoded_id, id);
        assert_eq!(backend, "backend2");
    }

    #[test]
    fn test_sse_stream_manager() {
        let mut manager = SseStreamManager::new();
        manager.enable_sse();
        manager.add_stream(1, "backend1");
        manager.add_stream(2, "backend2");
        
        assert_eq!(manager.active_stream_count(), 2);
        assert_eq!(manager.get_backend_name(1), Some("backend1"));
        
        manager.mark_disconnected(1);
        assert_eq!(manager.active_stream_count(), 1);
        assert!(!manager.all_disconnected());
        
        manager.mark_disconnected(2);
        assert!(manager.all_disconnected());
    }

    #[test]
    fn test_partial_event_buffering() {
        let mut manager = SseStreamManager::new();
        manager.add_stream(1, "test");
        
        // First chunk - incomplete
        let events = manager.append_data(1, "id: 1\ndata: hello");
        assert!(events.is_empty());
        
        // Second chunk - completes first event, starts second
        let events = manager.append_data(1, "\n\nid: 2\ndata: world\n\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "hello");
        assert_eq!(events[1].data, "world");
    }

    #[test]
    fn test_classify_message_response() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        assert_eq!(classify_message(json, 1), SseMessageType::Response);
        assert_eq!(classify_message(json, 0), SseMessageType::Response); // 0 matches any
    }

    #[test]
    fn test_classify_message_error_response() {
        let json = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"error"}}"#;
        assert_eq!(classify_message(json, 1), SseMessageType::Response);
    }

    #[test]
    fn test_classify_message_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":50}}"#;
        assert_eq!(classify_message(json, 1), SseMessageType::Notification);
    }

    #[test]
    fn test_classify_message_server_request() {
        let json = r#"{"jsonrpc":"2.0","id":99,"method":"roots/list","params":{}}"#;
        assert_eq!(classify_message(json, 1), SseMessageType::ServerRequest);
    }

    #[test]
    fn test_classify_message_unknown() {
        let json = r#"{"invalid":"json"}"#;
        assert_eq!(classify_message(json, 1), SseMessageType::Unknown);
    }

    #[test]
    fn test_extract_jsonrpc_from_sse() {
        // SSE with notification then response
        let sse_body = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":50}}\n\n\
                        data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n";
        
        let extracted = extract_jsonrpc_from_sse(sse_body, 1);
        assert!(extracted.is_some());
        let result: serde_json::Value = serde_json::from_str(&extracted.unwrap()).unwrap();
        assert!(result.get("result").is_some());
    }

    #[test]
    fn test_extract_jsonrpc_from_sse_no_response() {
        let sse_body = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n";
        let extracted = extract_jsonrpc_from_sse(sse_body, 1);
        assert!(extracted.is_none());
    }
}
