//! MCP Router - Envoy Rust Dynamic Module
//!
//! A terminal HTTP filter implementing MCP Gateway functionality:
//! - Multiplexing across multiple backend MCP servers
//! - Fanout for list operations (tools/list, resources/list, prompts/list)
//! - Targeted routing for call operations (tools/call, resources/read, prompts/get)
//! - Stateless session management via composite session IDs
//! - SSE streaming support for server→client notifications
//!
//! ## Filter Chain Architecture
//!
//! ```text
//! mcp_filter (C++)          mcp_router (Rust DM)
//!    │                            │
//!    │ Parse JSON-RPC             │ Read from dynamic metadata
//!    │ Store to dynamic metadata  │ (no re-parsing!)
//!    │ (namespace: mcp_proxy)     │
//!    │                            │
//!    ▼                            │
//! RBAC (optional)                 │ Policy already enforced
//!    │                            │
//!    ▼                            ▼
//!    └────────────────────────────┘
//! ```

pub mod config;
pub mod session;
pub mod jsonrpc;
pub mod method;
pub mod aggregation;
pub mod sse;

use std::collections::HashMap;
use std::sync::Arc;

use envoy_proxy_dynamic_modules_rust_sdk::*;

use config::{McpRouterConfig, McpBackendConfig, SESSION_ID_HEADER, MCP_METADATA_NAMESPACE};
use session::{CompositeSessionId, SessionBuilder};
use method::{McpMethod, RoutingBehavior, parse_tool_name, parse_resource_uri, parse_prompt_name};
use aggregation::{
    BackendResponse, ResponseContentType, aggregate_initialize, aggregate_tools_list, aggregate_resources_list,
    aggregate_resource_templates_list, aggregate_prompts_list, aggregate_broadcast,
    error_response, backend_not_found_response, session_not_found_response,
};
use sse::{SseEvent, SseStreamManager, CompositeEventId, extract_jsonrpc_from_sse};

// ============================================================================
// Module Entry Point
// ============================================================================

// Declare the init functions that Envoy will call when loading the module
declare_init_functions!(init, new_mcp_router_filter_config);

/// Program initialization function.
/// Called once when the dynamic module is loaded.
fn init() -> bool {
    true
}

/// Creates a new filter configuration.
/// Called when Envoy loads a filter config that references this module.
fn new_mcp_router_filter_config<EC: EnvoyHttpFilterConfig, EHF: EnvoyHttpFilter>(
    _envoy_filter_config: &mut EC,
    _name: &str,
    config: &[u8],
) -> Option<Box<dyn HttpFilterConfig<EHF>>> {
    let config_str = match std::str::from_utf8(config) {
        Ok(s) => s,
        Err(e) => {
            envoy_log_error!("MCP Router: invalid UTF-8 config: {}", e);
            return None;
        }
    };
    
    let router_config = match McpRouterConfig::from_json(config_str) {
        Ok(c) => c,
        Err(e) => {
            envoy_log_error!("MCP Router config error: {}", e);
            return None;
        }
    };
    
    envoy_log_info!(
        "MCP Router: {} backends, multiplexing={}",
        router_config.servers.len(),
        router_config.is_multiplexing()
    );
    
    Some(Box::new(McpRouterFilterConfig {
        config: Arc::new(router_config),
    }))
}

// ============================================================================
// Filter Config
// ============================================================================

pub struct McpRouterFilterConfig {
    config: Arc<McpRouterConfig>,
}

impl<EHF: EnvoyHttpFilter> HttpFilterConfig<EHF> for McpRouterFilterConfig {
    fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        Box::new(McpRouterFilter::new(self.config.clone()))
    }
}

// ============================================================================
// Filter State
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterState {
    Initial,
    ProcessingBody,
    WaitingForBackends,
    SendingResponse,
    Streaming,
    Complete,
}

// ============================================================================
// Main Filter
// ============================================================================

pub struct McpRouterFilter {
    config: Arc<McpRouterConfig>,
    state: FilterState,
    
    // Request info from mcp_filter metadata
    method: McpMethod,
    request_id: i64,
    
    // Method parameters
    tool_name: String,
    unprefixed_tool_name: String,
    target_backend: String,
    resource_uri: String,
    rewritten_uri: String,
    prompt_name: String,
    unprefixed_prompt_name: String,
    needs_body_rewrite: bool,
    
    // Session state
    route_name: String,
    session_subject: String,
    encoded_session_id: String,
    backend_sessions: HashMap<String, String>,
    
    // Callout tracking
    pending_callouts: HashMap<u64, String>,
    pending_responses: Vec<BackendResponse>,
    expected_responses: usize,
    
    // Body
    request_body: Vec<u8>,
    metadata_read: bool,
    
    // SSE state
    sse_manager: SseStreamManager,
    is_sse_request: bool,
    last_event_id: Option<CompositeEventId>,
    http_method: String,
    accept_header: String,
    
    // POST streaming state (for backend SSE pass-through)
    streaming_content_type: ResponseContentType,
    streaming_response_started: bool,
    streaming_body_buffer: String,
}

impl McpRouterFilter {
    pub fn new(config: Arc<McpRouterConfig>) -> Self {
        Self {
            config,
            state: FilterState::Initial,
            method: McpMethod::Unknown,
            request_id: 0,
            tool_name: String::new(),
            unprefixed_tool_name: String::new(),
            target_backend: String::new(),
            resource_uri: String::new(),
            rewritten_uri: String::new(),
            prompt_name: String::new(),
            unprefixed_prompt_name: String::new(),
            needs_body_rewrite: false,
            route_name: "default".to_string(),
            session_subject: String::new(),
            encoded_session_id: String::new(),
            backend_sessions: HashMap::new(),
            pending_callouts: HashMap::new(),
            pending_responses: Vec::new(),
            expected_responses: 0,
            request_body: Vec::new(),
            metadata_read: false,
            sse_manager: SseStreamManager::new(),
            is_sse_request: false,
            last_event_id: None,
            http_method: String::new(),
            accept_header: String::new(),
            streaming_content_type: ResponseContentType::Unknown,
            streaming_response_started: false,
            streaming_body_buffer: String::new(),
        }
    }

    /// Read MCP attributes from dynamic metadata (set by mcp_filter)
    fn read_metadata_from_mcp_filter<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) -> bool {
        // Get method
        if let Some(method_buf) = envoy.get_metadata_string(
            MetadataSource::Dynamic, MCP_METADATA_NAMESPACE, "method"
        ) {
            let method_str = std::str::from_utf8(method_buf.as_slice()).unwrap_or("");
            self.method = McpMethod::from_str(method_str);
            envoy_log_debug!(
                "read_metadata: method_str='{}', method={:?}, routing={:?}",
                method_str, self.method, self.method.routing_behavior()
            );
        }
        
        if self.method == McpMethod::Unknown {
            envoy_log_warn!("read_metadata: unknown method, returning false");
            return false;
        }

        // Get request ID
        if let Some(id_val) = envoy.get_metadata_number(
            MetadataSource::Dynamic, MCP_METADATA_NAMESPACE, "id"
        ) {
            self.request_id = id_val as i64;
        }

        // Log session state
        envoy_log_debug!(
            "read_metadata: request_id={}, backend_sessions_count={}, has_encoded_session={}",
            self.request_id, self.backend_sessions.len(), !self.encoded_session_id.is_empty()
        );

        // Extract method parameters
        self.extract_method_parameters(envoy);
        true
    }

    fn extract_method_parameters<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        let multiplexing = self.config.is_multiplexing();
        
        match self.method {
            McpMethod::ToolsCall => {
                if let Some(name_buf) = envoy.get_metadata_string(
                    MetadataSource::Dynamic, MCP_METADATA_NAMESPACE, "params.name"
                ) {
                    self.tool_name = std::str::from_utf8(name_buf.as_slice()).unwrap_or("").to_string();
                    let (backend, tool) = parse_tool_name(&self.tool_name, multiplexing);
                    self.target_backend = backend;
                    self.unprefixed_tool_name = tool;
                    self.needs_body_rewrite = !self.target_backend.is_empty();
                }
            }
            McpMethod::ResourcesRead | McpMethod::ResourcesSubscribe | McpMethod::ResourcesUnsubscribe => {
                if let Some(uri_buf) = envoy.get_metadata_string(
                    MetadataSource::Dynamic, MCP_METADATA_NAMESPACE, "params.uri"
                ) {
                    self.resource_uri = std::str::from_utf8(uri_buf.as_slice()).unwrap_or("").to_string();
                    let (backend, uri) = parse_resource_uri(&self.resource_uri, multiplexing);
                    self.target_backend = backend;
                    self.rewritten_uri = uri;
                    self.needs_body_rewrite = !self.target_backend.is_empty();
                }
            }
            McpMethod::PromptsGet => {
                if let Some(name_buf) = envoy.get_metadata_string(
                    MetadataSource::Dynamic, MCP_METADATA_NAMESPACE, "params.name"
                ) {
                    self.prompt_name = std::str::from_utf8(name_buf.as_slice()).unwrap_or("").to_string();
                    let (backend, prompt) = parse_prompt_name(&self.prompt_name, multiplexing);
                    self.target_backend = backend;
                    self.unprefixed_prompt_name = prompt;
                    self.needs_body_rewrite = !self.target_backend.is_empty();
                }
            }
            _ => {}
        }
    }

    fn parse_session_header(&mut self, header_value: &str) -> Result<(), String> {
        self.encoded_session_id = header_value.to_string();
        let session = CompositeSessionId::parse(header_value)?;
        self.route_name = session.route.clone();
        self.session_subject = session.subject.clone();
        self.backend_sessions = session.backend_sessions.clone();
        
        // Debug: log all parsed backend sessions
        let sessions_str: Vec<String> = self.backend_sessions
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        envoy_log_debug!(
            "parse_session_header: route={}, subject={}, backends=[{}]",
            self.route_name, self.session_subject, sessions_str.join(", ")
        );
        Ok(())
    }

    fn build_composite_session_id(&self) -> String {
        let mut builder = SessionBuilder::new(&self.route_name, &self.session_subject);
        let mut included_backends: Vec<String> = Vec::new();
        for resp in &self.pending_responses {
            if resp.success && !resp.session_id.is_empty() {
                builder.add_backend_session(&resp.backend_name, &resp.session_id);
                included_backends.push(format!("{}={}", resp.backend_name, resp.session_id));
            }
        }
        let composite = builder.encode();
        envoy_log_debug!(
            "build_composite_session_id: route={}, subject={}, backends=[{}], composite={}",
            self.route_name, self.session_subject, included_backends.join(", "), composite
        );
        composite
    }

    fn check_sse_request<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) -> bool {
        if let Some(accept) = envoy.get_request_header_value("accept") {
            let s = std::str::from_utf8(accept.as_slice()).unwrap_or("");
            if s.contains("text/event-stream") {
                self.is_sse_request = true;
                self.sse_manager.enable_sse();
                return true;
            }
        }
        false
    }

    fn parse_last_event_id<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        if let Some(id) = envoy.get_request_header_value("last-event-id") {
            if let Ok(s) = std::str::from_utf8(id.as_slice()) {
                if let Ok(composite) = CompositeEventId::parse(s) {
                    self.last_event_id = Some(composite);
                }
            }
        }
    }

    fn handle_method<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        match self.method.routing_behavior() {
            RoutingBehavior::Local => self.handle_local(envoy),
            RoutingBehavior::Fanout => self.handle_fanout(envoy),
            RoutingBehavior::Targeted => self.handle_targeted(envoy),
            RoutingBehavior::Broadcast => self.handle_broadcast(envoy),
            _ => self.send_error_response(envoy, 400, "Unsupported method"),
        }
    }

    fn handle_local<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": self.request_id,
            "result": {}
        });
        self.send_json_response(envoy, 200, &response);
        self.state = FilterState::Complete;
    }

    fn handle_fanout<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        let backends = self.config.backends();
        if backends.is_empty() {
            self.send_error_response(envoy, 500, "No backends configured");
            return;
        }
        
        envoy_log_debug!(
            "handle_fanout: method={:?}, num_backends={}, backend_sessions_count={}",
            self.method, backends.len(), self.backend_sessions.len()
        );
        
        self.state = FilterState::WaitingForBackends;
        self.expected_responses = backends.len();
        for backend in &backends {
            self.send_backend_request(envoy, backend);
        }
    }

    fn handle_targeted<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        if self.target_backend.is_empty() {
            let backends = self.config.backends();
            if backends.len() == 1 {
                self.target_backend = backends[0].name.clone();
            } else {
                let resp = backend_not_found_response(self.request_id, "no prefix");
                self.send_json_response(envoy, 400, &resp);
                return;
            }
        }

        let backend = match self.config.get_backend(&self.target_backend) {
            Some(b) => b,
            None => {
                let resp = backend_not_found_response(self.request_id, &self.target_backend);
                self.send_json_response(envoy, 404, &resp);
                return;
            }
        };

        if self.method != McpMethod::Initialize && 
           !self.backend_sessions.contains_key(&self.target_backend) {
            let resp = session_not_found_response(self.request_id, &self.target_backend);
            self.send_json_response(envoy, 400, &resp);
            return;
        }

        // Use streaming mode for targeted POST requests - backend decides SSE vs JSON response
        // For GET requests with Accept: text/event-stream, send SSE headers immediately
        if self.is_sse_request && self.http_method == "GET" {
            envoy_log_debug!("handle_targeted: using SSE streaming mode for GET request to backend {}", backend.name);
            self.state = FilterState::Streaming;
            envoy.send_response_headers(vec![
                (":status", b"200"),
                ("content-type", b"text/event-stream"),
                ("cache-control", b"no-cache"),
                ("connection", b"keep-alive"),
            ], false);
            self.start_backend_stream(envoy, &backend);
            return;
        }

        // For POST requests, use streaming so backend can respond with SSE or JSON
        // Response headers are sent in on_http_stream_headers after detecting content type
        envoy_log_debug!("handle_targeted: using streaming for POST to backend {}", backend.name);
        self.state = FilterState::Streaming;
        self.start_backend_stream_with_body(envoy, &backend);
    }

    fn handle_broadcast<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        let backends = self.config.backends();
        
        if self.method.is_notification() {
            self.send_accepted_response(envoy);
        }

        if backends.is_empty() {
            return;
        }

        self.state = FilterState::WaitingForBackends;
        self.expected_responses = backends.len();
        for backend in &backends {
            self.send_backend_request(envoy, backend);
        }
    }

    fn send_backend_request<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF, backend: &McpBackendConfig) {
        let host = backend.host_rewrite().unwrap_or(backend.cluster()).to_string();
        let path = backend.path().to_string();
        let cluster = backend.cluster().to_string();
        
        let body = if self.needs_body_rewrite {
            self.rewrite_request_body()
        } else {
            self.request_body.clone()
        };

        // Use the original Accept header from client if available, or default
        // Order matches C++ implementation: SSE first, then JSON
        let accept_header_val = if !self.accept_header.is_empty() {
            self.accept_header.clone()
        } else {
            "text/event-stream, application/json".to_string()
        };

        let mut headers: Vec<(&str, &[u8])> = vec![
            (":method", b"POST"),
            (":path", path.as_bytes()),
            (":authority", host.as_bytes()),
            ("content-type", b"application/json"),
            ("accept", accept_header_val.as_bytes()),
        ];

        let session_id_storage: String;
        let session_id_for_log: String;
        if let Some(sid) = self.backend_sessions.get(&backend.name) {
            session_id_storage = sid.clone();
            session_id_for_log = sid.clone();
            headers.push((SESSION_ID_HEADER, session_id_storage.as_bytes()));
        } else {
            session_id_for_log = "<none>".to_string();
        }

        let timeout_ms = backend.timeout().as_millis() as u64;

        envoy_log_debug!(
            "send_backend_request: cluster={}, host={}, path={}, accept={}, backend_name={}, session_id={}",
            cluster, host, path, accept_header_val, backend.name, session_id_for_log
        );

        let (result, callout_id) = envoy.send_http_callout(
            &cluster, headers, Some(&body), timeout_ms,
        );

        match result {
            HttpCalloutInitResult::Success => {
                self.pending_callouts.insert(callout_id, backend.name.clone());
            }
            _ => {
                self.pending_responses.push(BackendResponse {
                    backend_name: backend.name.clone(),
                    success: false,
                    error: format!("{:?}", result),
                    ..Default::default()
                });
                self.check_all_responses_received(envoy);
            }
        }
    }

    fn rewrite_request_body(&self) -> Vec<u8> {
        let body_str = match std::str::from_utf8(&self.request_body) {
            Ok(s) => s,
            Err(_) => return self.request_body.clone(),
        };

        let mut body: serde_json::Value = match serde_json::from_str(body_str) {
            Ok(v) => v,
            Err(_) => return self.request_body.clone(),
        };

        if let Some(params) = body.get_mut("params") {
            match self.method {
                McpMethod::ToolsCall => {
                    if !self.unprefixed_tool_name.is_empty() {
                        params["name"] = serde_json::json!(self.unprefixed_tool_name);
                    }
                }
                McpMethod::ResourcesRead | McpMethod::ResourcesSubscribe | McpMethod::ResourcesUnsubscribe => {
                    if !self.rewritten_uri.is_empty() {
                        params["uri"] = serde_json::json!(self.rewritten_uri);
                    }
                }
                McpMethod::PromptsGet => {
                    if !self.unprefixed_prompt_name.is_empty() {
                        params["name"] = serde_json::json!(self.unprefixed_prompt_name);
                    }
                }
                _ => {}
            }
        }

        serde_json::to_vec(&body).unwrap_or_else(|_| self.request_body.clone())
    }

    fn check_all_responses_received<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        if self.pending_responses.len() >= self.expected_responses {
            self.aggregate_and_respond(envoy);
        }
    }

    fn aggregate_and_respond<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        self.state = FilterState::SendingResponse;
        let multiplexing = self.config.is_multiplexing();
        
        let response = match self.method {
            McpMethod::Initialize => {
                let (resp, _) = aggregate_initialize(&self.pending_responses, self.request_id);
                let composite = self.build_composite_session_id();
                envoy.set_response_header(SESSION_ID_HEADER, composite.as_bytes());
                resp
            }
            McpMethod::ToolsList => aggregate_tools_list(&self.pending_responses, self.request_id, multiplexing),
            McpMethod::ResourcesList => aggregate_resources_list(&self.pending_responses, self.request_id, multiplexing),
            McpMethod::ResourcesTemplatesList => aggregate_resource_templates_list(&self.pending_responses, self.request_id, multiplexing),
            McpMethod::PromptsList => aggregate_prompts_list(&self.pending_responses, self.request_id, multiplexing),
            McpMethod::LoggingSetLevel => aggregate_broadcast(&self.pending_responses, self.request_id),
            McpMethod::ToolsCall | McpMethod::ResourcesRead | McpMethod::ResourcesSubscribe |
            McpMethod::ResourcesUnsubscribe | McpMethod::PromptsGet | McpMethod::CompletionComplete => {
                if let Some(resp) = self.pending_responses.first() {
                    if resp.success {
                        // For targeted methods, pass through backend's response format
                        if resp.is_sse() {
                            // Backend returned SSE - pass through with SSE content-type
                            self.send_sse_response(envoy, &resp.body);
                            self.state = FilterState::Complete;
                            return;
                        }
                        // JSON response - parse and send
                        serde_json::from_str(&resp.body).unwrap_or_else(|_| 
                            error_response(self.request_id, -32603, "Invalid response"))
                    } else {
                        error_response(self.request_id, -32603, &resp.error)
                    }
                } else {
                    error_response(self.request_id, -32603, "No response")
                }
            }
            _ => error_response(self.request_id, -32601, "Method not supported"),
        };

        self.send_json_response(envoy, 200, &response);
        self.state = FilterState::Complete;
    }

    fn send_json_response<EHF: EnvoyHttpFilter>(&self, envoy: &mut EHF, status: u32, body: &serde_json::Value) {
        let body_bytes = serde_json::to_vec(body).unwrap_or_default();
        let status_str = status.to_string();
        envoy.send_response(
            status,
            vec![
                (":status", status_str.as_bytes()),
                ("content-type", b"application/json"),
            ],
            Some(&body_bytes),
            None,
        );
    }

    fn send_error_response<EHF: EnvoyHttpFilter>(&self, envoy: &mut EHF, status: u32, message: &str) {
        let response = error_response(self.request_id, -(status as i32), message);
        self.send_json_response(envoy, status, &response);
    }

    /// Send SSE response - pass through SSE data from backend to client
    fn send_sse_response<EHF: EnvoyHttpFilter>(&self, envoy: &mut EHF, body: &str) {
        let mut headers = vec![
            (":status", b"200" as &[u8]),
            ("content-type", b"text/event-stream"),
            ("cache-control", b"no-cache"),
        ];
        
        // Include session ID if present
        let session_id_bytes: Vec<u8>;
        if !self.encoded_session_id.is_empty() {
            session_id_bytes = self.encoded_session_id.as_bytes().to_vec();
            headers.push((SESSION_ID_HEADER, &session_id_bytes));
        }
        
        envoy.send_response(
            200,
            headers,
            Some(body.as_bytes()),
            None,
        );
    }

    fn send_accepted_response<EHF: EnvoyHttpFilter>(&self, envoy: &mut EHF) {
        envoy.send_response(
            202,
            vec![
                (":status", b"202"),
                ("content-type", b"application/json"),
            ],
            None,
            None,
        );
    }

    fn start_sse_fanout<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        let backends = self.config.backends();
        if backends.is_empty() {
            self.send_error_response(envoy, 500, "No backends");
            return;
        }

        self.state = FilterState::Streaming;
        envoy.send_response_headers(vec![
            (":status", b"200"),
            ("content-type", b"text/event-stream"),
            ("cache-control", b"no-cache"),
            ("connection", b"keep-alive"),
        ], false);

        for backend in &backends {
            self.start_backend_stream(envoy, backend);
        }
    }

    fn start_backend_stream<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF, backend: &McpBackendConfig) {
        let host = backend.host_rewrite().unwrap_or(backend.cluster()).to_string();
        let path = backend.path().to_string();
        let cluster = backend.cluster().to_string();

        // For SSE streaming, use stored Accept header or default matching C++ implementation
        let accept_val = if !self.accept_header.is_empty() {
            self.accept_header.clone()
        } else {
            "text/event-stream, application/json".to_string()
        };

        let mut headers: Vec<(&str, &[u8])> = vec![
            (":method", self.http_method.as_bytes()),
            (":path", path.as_bytes()),
            (":authority", host.as_bytes()),
            ("content-type", b"application/json"),
            ("accept", accept_val.as_bytes()),
        ];

        let session_id_storage: String;
        if let Some(sid) = self.backend_sessions.get(&backend.name) {
            session_id_storage = sid.clone();
            headers.push((SESSION_ID_HEADER, session_id_storage.as_bytes()));
        }

        let last_event_storage: String;
        if let Some(ref composite) = self.last_event_id {
            if let Some(event_id) = composite.get(&backend.name) {
                last_event_storage = event_id.to_string();
                headers.push(("last-event-id", last_event_storage.as_bytes()));
            }
        }

        let (result, stream_id) = envoy.start_http_stream(
            &cluster, headers, None, true, backend.timeout().as_millis() as u64,
        );

        if result == abi::envoy_dynamic_module_type_http_callout_init_result::Success {
            self.sse_manager.add_stream(stream_id, &backend.name);
            self.pending_callouts.insert(stream_id, backend.name.clone());
        }
    }

    /// Start a backend stream with request body (for POST requests)
    /// Response headers are forwarded after detecting content-type
    fn start_backend_stream_with_body<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF, backend: &McpBackendConfig) {
        let host = backend.host_rewrite().unwrap_or(backend.cluster()).to_string();
        let path = backend.path().to_string();
        let cluster = backend.cluster().to_string();

        // Accept both SSE and JSON - backend decides
        let accept_val = "text/event-stream, application/json";

        let body = if self.needs_body_rewrite {
            self.rewrite_request_body()
        } else {
            self.request_body.clone()
        };

        let mut headers: Vec<(&str, &[u8])> = vec![
            (":method", b"POST"),
            (":path", path.as_bytes()),
            (":authority", host.as_bytes()),
            ("content-type", b"application/json"),
            ("accept", accept_val.as_bytes()),
        ];

        let session_id_storage: String;
        if let Some(sid) = self.backend_sessions.get(&backend.name) {
            session_id_storage = sid.clone();
            headers.push((SESSION_ID_HEADER, session_id_storage.as_bytes()));
        }

        let (result, stream_id) = envoy.start_http_stream(
            &cluster, headers, Some(&body), true, backend.timeout().as_millis() as u64,
        );

        if result == abi::envoy_dynamic_module_type_http_callout_init_result::Success {
            self.sse_manager.add_stream(stream_id, &backend.name);
            self.pending_callouts.insert(stream_id, backend.name.clone());
            envoy_log_debug!("start_backend_stream_with_body: started stream {} for backend {}", stream_id, backend.name);
        } else {
            envoy_log_warn!("start_backend_stream_with_body: failed to start stream for backend {}", backend.name);
            self.send_error_response(envoy, 500, "Failed to connect to backend");
        }
    }

    fn forward_sse_event<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF, stream_id: u64, event: &SseEvent) {
        if let Some(ref event_id) = event.id {
            self.sse_manager.update_event_id(stream_id, event_id);
        }

        let mut forwarded = event.clone();
        let composite_id = self.sse_manager.get_composite_event_id();
        if !composite_id.is_empty() {
            forwarded.id = Some(composite_id);
        }

        if let Some(mut msg) = event.parse_json() {
            if let Some(backend_name) = self.sse_manager.get_backend_name(stream_id) {
                sse::transform_server_to_client_message(&mut msg, backend_name, self.config.is_multiplexing());
                forwarded.data = msg.to_string();
            }
        }

        envoy.send_response_data(&forwarded.to_bytes(), false);
    }
}

// ============================================================================
// HttpFilter Implementation
// ============================================================================

impl<EHF: EnvoyHttpFilter> HttpFilter<EHF> for McpRouterFilter {
    fn on_request_headers(&mut self, envoy: &mut EHF, end_of_stream: bool) -> OnHttpFilterRequestHeadersStatus {
        if let Some(method) = envoy.get_request_header_value(":method") {
            self.http_method = std::str::from_utf8(method.as_slice()).unwrap_or("").to_string();
        }

        if let Some(hdr) = envoy.get_request_header_value(SESSION_ID_HEADER) {
            if let Ok(s) = std::str::from_utf8(hdr.as_slice()) {
                let _ = self.parse_session_header(s);
            }
        }

        // Capture the original Accept header from client request
        if let Some(accept) = envoy.get_request_header_value("accept") {
            self.accept_header = std::str::from_utf8(accept.as_slice()).unwrap_or("").to_string();
        }

        self.check_sse_request(envoy);
        if self.is_sse_request {
            self.parse_last_event_id(envoy);
        }

        if self.http_method == "GET" {
            if !self.is_sse_request {
                self.send_error_response(envoy, 400, "GET requires Accept: text/event-stream");
                return OnHttpFilterRequestHeadersStatus::StopIteration;
            }
            if self.backend_sessions.is_empty() {
                self.send_error_response(envoy, 400, "Session required");
                return OnHttpFilterRequestHeadersStatus::StopIteration;
            }
            self.start_sse_fanout(envoy);
            return OnHttpFilterRequestHeadersStatus::StopIteration;
        }

        if end_of_stream {
            self.send_error_response(envoy, 400, "Missing body");
            return OnHttpFilterRequestHeadersStatus::StopIteration;
        }

        self.state = FilterState::ProcessingBody;
        OnHttpFilterRequestHeadersStatus::StopIteration
    }

    fn on_request_body(&mut self, envoy: &mut EHF, end_of_stream: bool) -> OnHttpFilterRequestBodyStatus {
        if let Some(body_buffers) = envoy.get_received_request_body() {
            for buffer in body_buffers {
                self.request_body.extend_from_slice(buffer.as_slice());
            }
        }
        
        if !end_of_stream {
            return OnHttpFilterRequestBodyStatus::StopIterationAndBuffer;
        }

        if !self.metadata_read {
            if !self.read_metadata_from_mcp_filter(envoy) {
                self.send_error_response(envoy, 400, "Invalid MCP request");
                return OnHttpFilterRequestBodyStatus::StopIterationNoBuffer;
            }
            self.metadata_read = true;
        }

        self.handle_method(envoy);
        OnHttpFilterRequestBodyStatus::StopIterationNoBuffer
    }

    fn on_http_callout_done(&mut self, envoy: &mut EHF, callout_id: u64, result: HttpCalloutResult,
        headers: Option<&[(EnvoyBuffer, EnvoyBuffer)]>, body: Option<&[EnvoyBuffer]>) {
        let backend_name = match self.pending_callouts.remove(&callout_id) {
            Some(n) => n,
            None => return,
        };

        let mut resp = BackendResponse { backend_name: backend_name.clone(), ..Default::default() };

        if result == HttpCalloutResult::Success {
            if let Some(hdrs) = headers {
                for (k, v) in hdrs {
                    let ks = std::str::from_utf8(k.as_slice()).unwrap_or("");
                    let vs = std::str::from_utf8(v.as_slice()).unwrap_or("");
                    if ks == ":status" {
                        resp.status_code = vs.parse().unwrap_or(0);
                        resp.success = resp.status_code >= 200 && resp.status_code < 300;
                    } else if ks.eq_ignore_ascii_case(SESSION_ID_HEADER) {
                        resp.session_id = vs.to_string();
                    } else if ks.eq_ignore_ascii_case("content-type") {
                        resp.content_type = ResponseContentType::from_header(vs);
                    }
                }
            }
            if let Some(chunks) = body {
                for chunk in chunks {
                    if let Ok(s) = std::str::from_utf8(chunk.as_slice()) {
                        resp.body.push_str(s);
                    }
                }
            }
            
            // For SSE responses, extract the JSON-RPC body from SSE events
            if resp.is_sse() && resp.success {
                if let Some(jsonrpc) = extract_jsonrpc_from_sse(&resp.body, self.request_id) {
                    resp.extracted_jsonrpc = jsonrpc;
                    envoy_log_debug!(
                        "on_http_callout_done: extracted JSON-RPC from SSE for backend={}",
                        backend_name
                    );
                }
            }
            
            // Log response for debugging
            envoy_log_debug!(
                "on_http_callout_done: backend={}, status={}, content_type={:?}, body_len={}, extracted_len={}",
                backend_name, resp.status_code, resp.content_type, resp.body.len(), resp.extracted_jsonrpc.len()
            );
        } else {
            resp.error = format!("{:?}", result);
        }

        self.pending_responses.push(resp);
        self.check_all_responses_received(envoy);
    }

    fn on_http_stream_headers(&mut self, envoy: &mut EHF, stream_handle: u64, 
        headers: &[(EnvoyBuffer, EnvoyBuffer)], end_stream: bool) {
        let mut status_code = 0u32;
        let mut content_type = ResponseContentType::Unknown;
        
        for (k, v) in headers {
            let ks = std::str::from_utf8(k.as_slice()).unwrap_or("");
            let vs = std::str::from_utf8(v.as_slice()).unwrap_or("");
            if ks == ":status" {
                status_code = vs.parse().unwrap_or(0);
            } else if ks.eq_ignore_ascii_case(SESSION_ID_HEADER) {
                if let Some(backend) = self.sse_manager.get_backend_name(stream_handle) {
                    self.backend_sessions.insert(backend.to_string(), vs.to_string());
                }
            } else if ks.eq_ignore_ascii_case("content-type") {
                content_type = ResponseContentType::from_header(vs);
            }
        }
        
        envoy_log_debug!(
            "on_http_stream_headers: stream_handle={}, status={}, content_type={:?}, streaming_started={}",
            stream_handle, status_code, content_type, self.streaming_response_started
        );
        
        // Track content type for POST streaming
        self.streaming_content_type = content_type;
        
        // For POST streaming, forward headers to client based on content type
        if self.http_method == "POST" && !self.streaming_response_started {
            if status_code >= 200 && status_code < 300 {
                self.streaming_response_started = true;
                
                if content_type == ResponseContentType::Sse {
                    // Backend chose SSE - forward SSE headers to client
                    let status_bytes = status_code.to_string();
                    let mut response_headers = vec![
                        (":status", status_bytes.as_bytes()),
                        ("content-type", b"text/event-stream" as &[u8]),
                        ("cache-control", b"no-cache"),
                    ];
                    
                    // Include session ID
                    let session_id_bytes: Vec<u8>;
                    if !self.encoded_session_id.is_empty() {
                        session_id_bytes = self.encoded_session_id.as_bytes().to_vec();
                        response_headers.push((SESSION_ID_HEADER, &session_id_bytes));
                    }
                    
                    envoy.send_response_headers(response_headers, false);
                } else {
                    // Backend chose JSON - we'll buffer and send when complete
                    envoy_log_debug!("on_http_stream_headers: JSON response, will buffer");
                }
            } else {
                // Error response - send as JSON error
                self.sse_manager.mark_disconnected(stream_handle);
                self.send_error_response(envoy, status_code, "Backend error");
                return;
            }
        }
        
        if status_code >= 400 {
            self.sse_manager.mark_disconnected(stream_handle);
        }
        
        if end_stream {
            self.sse_manager.mark_disconnected(stream_handle);
            if self.sse_manager.all_disconnected() {
                // For JSON POST, send buffered response
                if self.streaming_content_type == ResponseContentType::Json {
                    self.send_buffered_json_response(envoy);
                } else {
                    envoy.send_response_data(b"", true);
                }
            }
        }
    }

    fn on_http_stream_data(&mut self, envoy: &mut EHF, stream_handle: u64, 
        data: &[EnvoyBuffer], end_stream: bool) {
        let mut accumulated = String::new();
        for chunk in data {
            if let Ok(s) = std::str::from_utf8(chunk.as_slice()) {
                accumulated.push_str(s);
            }
        }
        
        // For SSE responses, stream events through
        if self.streaming_content_type == ResponseContentType::Sse {
            let events = self.sse_manager.append_data(stream_handle, &accumulated);
            for event in events {
                self.forward_sse_event(envoy, stream_handle, &event);
            }
        } else {
            // For JSON responses, buffer the data
            self.streaming_body_buffer.push_str(&accumulated);
        }
        
        if end_stream {
            self.sse_manager.mark_disconnected(stream_handle);
            if self.sse_manager.all_disconnected() {
                if self.streaming_content_type == ResponseContentType::Json {
                    self.send_buffered_json_response(envoy);
                } else {
                    envoy.send_response_data(b"", true);
                }
            }
        }
    }
    
    /// Send buffered JSON response (for POST with JSON backend response)
    fn send_buffered_json_response<EHF: EnvoyHttpFilter>(&mut self, envoy: &mut EHF) {
        if self.streaming_body_buffer.is_empty() {
            self.send_error_response(envoy, 500, "Empty response from backend");
            return;
        }
        
        // Parse and validate JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&self.streaming_body_buffer) {
            self.send_json_response(envoy, 200, &json);
        } else {
            envoy_log_warn!("send_buffered_json_response: invalid JSON from backend");
            self.send_error_response(envoy, 500, "Invalid JSON response from backend");
        }
    }

    fn on_http_stream_complete(&mut self, _envoy: &mut EHF, stream_handle: u64) {
        self.sse_manager.mark_disconnected(stream_handle);
    }

    fn on_http_stream_reset(&mut self, envoy: &mut EHF, stream_handle: u64, _reason: HttpStreamResetReason) {
        self.sse_manager.mark_disconnected(stream_handle);
        if self.sse_manager.all_disconnected() {
            envoy.send_response_data(b"", true);
        }
    }
}

// Type aliases for SDK compatibility
type MetadataSource = abi::envoy_dynamic_module_type_metadata_source;
type OnHttpFilterRequestHeadersStatus = abi::envoy_dynamic_module_type_on_http_filter_request_headers_status;
type OnHttpFilterRequestBodyStatus = abi::envoy_dynamic_module_type_on_http_filter_request_body_status;
type HttpCalloutResult = abi::envoy_dynamic_module_type_http_callout_result;
type HttpCalloutInitResult = abi::envoy_dynamic_module_type_http_callout_init_result;
type HttpStreamResetReason = abi::envoy_dynamic_module_type_http_stream_reset_reason;
