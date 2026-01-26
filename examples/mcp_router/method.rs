//! MCP Method Definitions and Routing Behavior
//!
//! Comprehensive support for all MCP protocol methods including:
//! - Client→Server requests (tools, resources, prompts, etc.)
//! - Server→Client requests (sampling, elicitation, roots)
//! - Notifications (bidirectional)
//!
//! Based on MCP spec version 2025-06-18.

use crate::config::{NAME_DELIMITER, URI_DELIMITER};

// ============================================================================
// MCP Methods Enum
// ============================================================================

/// All supported MCP methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpMethod {
    // ========================================
    // Lifecycle Methods
    // ========================================
    /// Initialize session - fanout to all backends
    Initialize,
    /// Ping for health check - respond locally
    Ping,
    
    // ========================================
    // Tool Methods
    // ========================================
    /// List all available tools - fanout and aggregate
    ToolsList,
    /// Call a specific tool - targeted routing
    ToolsCall,
    
    // ========================================
    // Resource Methods
    // ========================================
    /// List all resources - fanout and aggregate
    ResourcesList,
    /// Read a specific resource - targeted routing
    ResourcesRead,
    /// Subscribe to resource updates - targeted routing
    ResourcesSubscribe,
    /// Unsubscribe from resource updates - targeted routing
    ResourcesUnsubscribe,
    /// List resource templates - fanout and aggregate
    ResourcesTemplatesList,
    
    // ========================================
    // Prompt Methods
    // ========================================
    /// List all prompts - fanout and aggregate
    PromptsList,
    /// Get a specific prompt - targeted routing
    PromptsGet,
    
    // ========================================
    // Completion Methods
    // ========================================
    /// Request completion suggestions - targeted routing
    CompletionComplete,
    
    // ========================================
    // Logging Methods
    // ========================================
    /// Set logging level - broadcast to all backends
    LoggingSetLevel,
    
    // ========================================
    // Sampling Methods (Server→Client)
    // ========================================
    /// Server requests client to create a message via LLM
    SamplingCreateMessage,
    
    // ========================================
    // Elicitation Methods (Server→Client)
    // ========================================
    /// Server requests user input/confirmation
    ElicitationCreate,
    
    // ========================================
    // Roots Methods (Server→Client)
    // ========================================
    /// Server requests list of root URIs from client
    RootsList,
    
    // ========================================
    // Client→Server Notifications
    // ========================================
    /// Client notifies server that initialization is complete
    NotificationInitialized,
    /// Client cancels a pending request
    NotificationCancelled,
    /// Client notifies that roots list has changed
    NotificationRootsListChanged,
    /// Client sends progress update
    NotificationProgress,
    
    // ========================================
    // Server→Client Notifications
    // ========================================
    /// Server notifies that resources list changed
    NotificationResourcesListChanged,
    /// Server notifies that a specific resource was updated
    NotificationResourcesUpdated,
    /// Server notifies that tools list changed
    NotificationToolsListChanged,
    /// Server notifies that prompts list changed
    NotificationPromptsListChanged,
    /// Server sends a log message
    NotificationMessage,
    
    // ========================================
    // Unknown
    // ========================================
    /// Unknown or unsupported method
    Unknown,
}

impl McpMethod {
    /// Parse method string to enum
    pub fn from_str(s: &str) -> Self {
        match s {
            // Lifecycle
            "initialize" => McpMethod::Initialize,
            "ping" => McpMethod::Ping,
            
            // Tools
            "tools/list" => McpMethod::ToolsList,
            "tools/call" => McpMethod::ToolsCall,
            
            // Resources
            "resources/list" => McpMethod::ResourcesList,
            "resources/read" => McpMethod::ResourcesRead,
            "resources/subscribe" => McpMethod::ResourcesSubscribe,
            "resources/unsubscribe" => McpMethod::ResourcesUnsubscribe,
            "resources/templates/list" => McpMethod::ResourcesTemplatesList,
            
            // Prompts
            "prompts/list" => McpMethod::PromptsList,
            "prompts/get" => McpMethod::PromptsGet,
            
            // Completion
            "completion/complete" => McpMethod::CompletionComplete,
            
            // Logging
            "logging/setLevel" => McpMethod::LoggingSetLevel,
            
            // Sampling (Server→Client)
            "sampling/createMessage" => McpMethod::SamplingCreateMessage,
            
            // Elicitation (Server→Client)
            "elicitation/create" => McpMethod::ElicitationCreate,
            
            // Roots (Server→Client)
            "roots/list" => McpMethod::RootsList,
            
            // Client→Server Notifications
            "notifications/initialized" => McpMethod::NotificationInitialized,
            "notifications/cancelled" => McpMethod::NotificationCancelled,
            "notifications/roots/list_changed" => McpMethod::NotificationRootsListChanged,
            "notifications/progress" => McpMethod::NotificationProgress,
            
            // Server→Client Notifications
            "notifications/resources/list_changed" => McpMethod::NotificationResourcesListChanged,
            "notifications/resources/updated" => McpMethod::NotificationResourcesUpdated,
            "notifications/tools/list_changed" => McpMethod::NotificationToolsListChanged,
            "notifications/prompts/list_changed" => McpMethod::NotificationPromptsListChanged,
            "notifications/message" => McpMethod::NotificationMessage,
            
            _ => McpMethod::Unknown,
        }
    }
    
    /// Get the method string
    pub fn as_str(&self) -> &'static str {
        match self {
            McpMethod::Initialize => "initialize",
            McpMethod::Ping => "ping",
            McpMethod::ToolsList => "tools/list",
            McpMethod::ToolsCall => "tools/call",
            McpMethod::ResourcesList => "resources/list",
            McpMethod::ResourcesRead => "resources/read",
            McpMethod::ResourcesSubscribe => "resources/subscribe",
            McpMethod::ResourcesUnsubscribe => "resources/unsubscribe",
            McpMethod::ResourcesTemplatesList => "resources/templates/list",
            McpMethod::PromptsList => "prompts/list",
            McpMethod::PromptsGet => "prompts/get",
            McpMethod::CompletionComplete => "completion/complete",
            McpMethod::LoggingSetLevel => "logging/setLevel",
            McpMethod::SamplingCreateMessage => "sampling/createMessage",
            McpMethod::ElicitationCreate => "elicitation/create",
            McpMethod::RootsList => "roots/list",
            McpMethod::NotificationInitialized => "notifications/initialized",
            McpMethod::NotificationCancelled => "notifications/cancelled",
            McpMethod::NotificationRootsListChanged => "notifications/roots/list_changed",
            McpMethod::NotificationProgress => "notifications/progress",
            McpMethod::NotificationResourcesListChanged => "notifications/resources/list_changed",
            McpMethod::NotificationResourcesUpdated => "notifications/resources/updated",
            McpMethod::NotificationToolsListChanged => "notifications/tools/list_changed",
            McpMethod::NotificationPromptsListChanged => "notifications/prompts/list_changed",
            McpMethod::NotificationMessage => "notifications/message",
            McpMethod::Unknown => "unknown",
        }
    }
    
    /// Get the routing behavior for this method
    pub fn routing_behavior(&self) -> RoutingBehavior {
        match self {
            // Local handling
            McpMethod::Ping => RoutingBehavior::Local,
            
            // Fanout to all backends, aggregate results
            McpMethod::Initialize => RoutingBehavior::Fanout,
            McpMethod::ToolsList => RoutingBehavior::Fanout,
            McpMethod::ResourcesList => RoutingBehavior::Fanout,
            McpMethod::ResourcesTemplatesList => RoutingBehavior::Fanout,
            McpMethod::PromptsList => RoutingBehavior::Fanout,
            
            // Targeted to specific backend based on name/URI prefix
            McpMethod::ToolsCall => RoutingBehavior::Targeted,
            McpMethod::ResourcesRead => RoutingBehavior::Targeted,
            McpMethod::ResourcesSubscribe => RoutingBehavior::Targeted,
            McpMethod::ResourcesUnsubscribe => RoutingBehavior::Targeted,
            McpMethod::PromptsGet => RoutingBehavior::Targeted,
            McpMethod::CompletionComplete => RoutingBehavior::Targeted,
            
            // Broadcast to all backends, no aggregation needed
            McpMethod::LoggingSetLevel => RoutingBehavior::Broadcast,
            McpMethod::NotificationInitialized => RoutingBehavior::Broadcast,
            McpMethod::NotificationCancelled => RoutingBehavior::Broadcast,
            McpMethod::NotificationRootsListChanged => RoutingBehavior::Broadcast,
            McpMethod::NotificationProgress => RoutingBehavior::Broadcast,
            
            // Server→Client methods (forwarded from backend to client)
            McpMethod::SamplingCreateMessage => RoutingBehavior::ServerToClient,
            McpMethod::ElicitationCreate => RoutingBehavior::ServerToClient,
            McpMethod::RootsList => RoutingBehavior::ServerToClient,
            McpMethod::NotificationResourcesListChanged => RoutingBehavior::ServerToClient,
            McpMethod::NotificationResourcesUpdated => RoutingBehavior::ServerToClient,
            McpMethod::NotificationToolsListChanged => RoutingBehavior::ServerToClient,
            McpMethod::NotificationPromptsListChanged => RoutingBehavior::ServerToClient,
            McpMethod::NotificationMessage => RoutingBehavior::ServerToClient,
            
            McpMethod::Unknown => RoutingBehavior::Unknown,
        }
    }
    
    /// Check if this is a notification (no response expected)
    pub fn is_notification(&self) -> bool {
        matches!(self,
            McpMethod::NotificationInitialized |
            McpMethod::NotificationCancelled |
            McpMethod::NotificationRootsListChanged |
            McpMethod::NotificationProgress |
            McpMethod::NotificationResourcesListChanged |
            McpMethod::NotificationResourcesUpdated |
            McpMethod::NotificationToolsListChanged |
            McpMethod::NotificationPromptsListChanged |
            McpMethod::NotificationMessage
        )
    }
    
    /// Check if this is a server→client method
    pub fn is_server_to_client(&self) -> bool {
        matches!(self.routing_behavior(), RoutingBehavior::ServerToClient)
    }
    
    /// Get the method group for classification
    pub fn group(&self) -> &'static str {
        match self {
            McpMethod::Initialize | McpMethod::Ping => "lifecycle",
            McpMethod::ToolsList | McpMethod::ToolsCall => "tool",
            McpMethod::ResourcesList | McpMethod::ResourcesRead | 
            McpMethod::ResourcesSubscribe | McpMethod::ResourcesUnsubscribe |
            McpMethod::ResourcesTemplatesList => "resource",
            McpMethod::PromptsList | McpMethod::PromptsGet => "prompt",
            McpMethod::CompletionComplete => "completion",
            McpMethod::LoggingSetLevel => "logging",
            McpMethod::SamplingCreateMessage => "sampling",
            McpMethod::ElicitationCreate => "elicitation",
            McpMethod::RootsList => "roots",
            McpMethod::NotificationInitialized | McpMethod::NotificationCancelled |
            McpMethod::NotificationRootsListChanged | McpMethod::NotificationProgress |
            McpMethod::NotificationResourcesListChanged | McpMethod::NotificationResourcesUpdated |
            McpMethod::NotificationToolsListChanged | McpMethod::NotificationPromptsListChanged |
            McpMethod::NotificationMessage => "notification",
            McpMethod::Unknown => "unknown",
        }
    }
}

// ============================================================================
// Routing Behavior
// ============================================================================

/// How a method should be routed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingBehavior {
    /// Handle locally without contacting backends (e.g., ping)
    Local,
    
    /// Send to all backends and aggregate responses (e.g., tools/list)
    Fanout,
    
    /// Route to a specific backend based on name/URI prefix (e.g., tools/call)
    Targeted,
    
    /// Send to all backends, return 202 Accepted (notifications)
    Broadcast,
    
    /// Server→Client method (forwarded from backend SSE to client)
    ServerToClient,
    
    /// Unknown routing behavior
    Unknown,
}

// ============================================================================
// Name/URI Parsing and Prefixing
// ============================================================================

/// Parse a prefixed tool/prompt name to extract backend and original name
///
/// Format: `{backend}__{name}` → `("backend", "name")`
///
/// If no prefix found, returns `("", original_name)`
pub fn parse_tool_name(prefixed_name: &str, multiplexing: bool) -> (String, String) {
    if !multiplexing {
        return (String::new(), prefixed_name.to_string());
    }
    
    if let Some(pos) = prefixed_name.find(NAME_DELIMITER) {
        let backend = &prefixed_name[..pos];
        let name = &prefixed_name[pos + NAME_DELIMITER.len()..];
        (backend.to_string(), name.to_string())
    } else {
        (String::new(), prefixed_name.to_string())
    }
}

/// Parse a prefixed prompt name (same format as tool names)
pub fn parse_prompt_name(prefixed_name: &str, multiplexing: bool) -> (String, String) {
    parse_tool_name(prefixed_name, multiplexing)
}

/// Parse a prefixed resource URI to extract backend and original URI
///
/// Format: `{backend}+{scheme}://{path}` → `("backend", "scheme://path")`
///
/// If no prefix found, returns `("", original_uri)`
pub fn parse_resource_uri(prefixed_uri: &str, multiplexing: bool) -> (String, String) {
    if !multiplexing {
        return (String::new(), prefixed_uri.to_string());
    }
    
    if let Some(pos) = prefixed_uri.find(URI_DELIMITER) {
        let backend = &prefixed_uri[..pos];
        let uri = &prefixed_uri[pos + 1..];
        (backend.to_string(), uri.to_string())
    } else {
        (String::new(), prefixed_uri.to_string())
    }
}

/// Add backend prefix to a tool/prompt name
///
/// `("backend", "name")` → `"backend__name"`
pub fn prefix_tool_name(backend: &str, name: &str) -> String {
    format!("{}{}{}", backend, NAME_DELIMITER, name)
}

/// Add backend prefix to a prompt name (same as tool names)
pub fn prefix_prompt_name(backend: &str, name: &str) -> String {
    prefix_tool_name(backend, name)
}

/// Add backend prefix to a resource URI
///
/// `("backend", "scheme://path")` → `"backend+scheme://path"`
pub fn prefix_resource_uri(backend: &str, uri: &str) -> String {
    format!("{}{}{}", backend, URI_DELIMITER, uri)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_parsing() {
        assert_eq!(McpMethod::from_str("tools/call"), McpMethod::ToolsCall);
        assert_eq!(McpMethod::from_str("resources/read"), McpMethod::ResourcesRead);
        assert_eq!(McpMethod::from_str("sampling/createMessage"), McpMethod::SamplingCreateMessage);
        assert_eq!(McpMethod::from_str("unknown/method"), McpMethod::Unknown);
    }

    #[test]
    fn test_routing_behavior() {
        assert_eq!(McpMethod::Ping.routing_behavior(), RoutingBehavior::Local);
        assert_eq!(McpMethod::ToolsList.routing_behavior(), RoutingBehavior::Fanout);
        assert_eq!(McpMethod::ToolsCall.routing_behavior(), RoutingBehavior::Targeted);
        assert_eq!(McpMethod::NotificationInitialized.routing_behavior(), RoutingBehavior::Broadcast);
        assert_eq!(McpMethod::SamplingCreateMessage.routing_behavior(), RoutingBehavior::ServerToClient);
    }

    #[test]
    fn test_tool_name_parsing() {
        let (backend, name) = parse_tool_name("time__get_current_time", true);
        assert_eq!(backend, "time");
        assert_eq!(name, "get_current_time");
        
        let (backend, name) = parse_tool_name("no_prefix", true);
        assert_eq!(backend, "");
        assert_eq!(name, "no_prefix");
        
        // With multiplexing disabled
        let (backend, name) = parse_tool_name("time__get_current_time", false);
        assert_eq!(backend, "");
        assert_eq!(name, "time__get_current_time");
    }

    #[test]
    fn test_resource_uri_parsing() {
        let (backend, uri) = parse_resource_uri("time+file:///config.json", true);
        assert_eq!(backend, "time");
        assert_eq!(uri, "file:///config.json");
        
        let (backend, uri) = parse_resource_uri("https://example.com", true);
        assert_eq!(backend, "");
        assert_eq!(uri, "https://example.com");
    }

    #[test]
    fn test_prefixing() {
        assert_eq!(prefix_tool_name("backend", "tool"), "backend__tool");
        assert_eq!(prefix_resource_uri("backend", "file:///path"), "backend+file:///path");
    }

    #[test]
    fn test_is_notification() {
        assert!(McpMethod::NotificationInitialized.is_notification());
        assert!(McpMethod::NotificationResourcesUpdated.is_notification());
        assert!(!McpMethod::ToolsCall.is_notification());
        assert!(!McpMethod::Initialize.is_notification());
    }
}
