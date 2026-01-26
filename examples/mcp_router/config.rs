//! MCP Router Configuration
//!
//! Configuration structures for the MCP Router filter, including backend
//! definitions, timeout settings, and multiplexing options.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ============================================================================
// Constants
// ============================================================================

/// Name delimiter for multiplexed tool/prompt names (e.g., "backend__tool_name")
pub const NAME_DELIMITER: &str = "__";

/// URI prefix delimiter for multiplexed resource URIs (e.g., "backend+scheme://path")
pub const URI_DELIMITER: char = '+';

/// Session ID header name per MCP spec
pub const SESSION_ID_HEADER: &str = "mcp-session-id";

/// MCP protocol version supported
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Gateway implementation name
pub const GATEWAY_NAME: &str = "envoy-mcp-gateway";

/// Gateway version
pub const GATEWAY_VERSION: &str = "1.0.0";

/// Dynamic metadata namespace used by mcp_filter
/// mcp_router reads from this namespace - it does NOT re-parse JSON-RPC
pub const MCP_METADATA_NAMESPACE: &str = "mcp_proxy";

/// Default timeout for backend requests (5 seconds)
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

// ============================================================================
// Backend Configuration
// ============================================================================

/// Configuration for a single MCP backend server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpBackendConfig {
    /// Unique name for this backend (used in multiplexing prefixes)
    pub name: String,
    
    /// Envoy cluster name for routing
    #[serde(default)]
    pub cluster: String,
    
    /// Path to the MCP endpoint (default: "/mcp")
    #[serde(default = "default_path")]
    pub path: String,
    
    /// Request timeout in milliseconds
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    
    /// Optional host rewrite for the upstream request
    #[serde(default)]
    pub host_rewrite: Option<String>,
}

fn default_path() -> String {
    "/mcp".to_string()
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_MS
}

impl McpBackendConfig {
    /// Get the cluster name (defaults to backend name if not specified)
    pub fn cluster(&self) -> &str {
        if self.cluster.is_empty() {
            &self.name
        } else {
            &self.cluster
        }
    }
    
    /// Get the MCP endpoint path
    pub fn path(&self) -> &str {
        &self.path
    }
    
    /// Get the request timeout as Duration
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
    
    /// Get the host rewrite value if configured
    pub fn host_rewrite(&self) -> Option<&str> {
        self.host_rewrite.as_deref()
    }
}

// ============================================================================
// Router Configuration
// ============================================================================

/// Main configuration for the MCP Router filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRouterConfig {
    /// List of backend MCP servers
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
    
    /// Enable multiplexing mode (add backend prefixes to names/URIs)
    #[serde(default = "default_multiplexing")]
    pub multiplexing: bool,
    
    /// Route name (used in composite session IDs)
    #[serde(default = "default_route")]
    pub route_name: String,
}

fn default_multiplexing() -> bool {
    true
}

fn default_route() -> String {
    "default".to_string()
}

/// Server configuration entry (supports both inline and reference styles)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Backend name
    pub name: String,
    
    /// MCP cluster configuration
    #[serde(default)]
    pub mcp_cluster: Option<McpClusterConfig>,
    
    /// Direct cluster reference (alternative to mcp_cluster)
    #[serde(default)]
    pub cluster: Option<String>,
    
    /// Direct path (alternative to mcp_cluster)
    #[serde(default)]
    pub path: Option<String>,
    
    /// Direct timeout (alternative to mcp_cluster)
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    
    /// Direct host rewrite (alternative to mcp_cluster)
    #[serde(default)]
    pub host_rewrite: Option<String>,
}

/// MCP cluster configuration (nested style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpClusterConfig {
    pub cluster: String,
    
    #[serde(default = "default_path")]
    pub path: String,
    
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    
    #[serde(default)]
    pub host_rewrite_literal: Option<String>,
}

impl McpRouterConfig {
    /// Parse configuration from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Config parse error: {}", e))
    }
    
    /// Check if multiplexing is enabled
    pub fn is_multiplexing(&self) -> bool {
        self.multiplexing
    }
    
    /// Get the route name
    pub fn route_name(&self) -> &str {
        &self.route_name
    }
    
    /// Get all backend configurations
    pub fn backends(&self) -> Vec<McpBackendConfig> {
        self.servers.iter().map(|s| s.to_backend_config()).collect()
    }
    
    /// Build a lookup map from backend name to config
    pub fn backend_map(&self) -> HashMap<String, McpBackendConfig> {
        self.backends()
            .into_iter()
            .map(|b| (b.name.clone(), b))
            .collect()
    }
    
    /// Get a specific backend by name
    pub fn get_backend(&self, name: &str) -> Option<McpBackendConfig> {
        self.servers.iter()
            .find(|s| s.name == name)
            .map(|s| s.to_backend_config())
    }
    
    /// Check if a backend exists
    pub fn has_backend(&self, name: &str) -> bool {
        self.servers.iter().any(|s| s.name == name)
    }
}

impl ServerConfig {
    /// Convert to McpBackendConfig
    pub fn to_backend_config(&self) -> McpBackendConfig {
        if let Some(ref mcp) = self.mcp_cluster {
            McpBackendConfig {
                name: self.name.clone(),
                cluster: mcp.cluster.clone(),
                path: mcp.path.clone(),
                timeout_ms: mcp.timeout_ms,
                host_rewrite: mcp.host_rewrite_literal.clone(),
            }
        } else {
            McpBackendConfig {
                name: self.name.clone(),
                cluster: self.cluster.clone().unwrap_or_else(|| self.name.clone()),
                path: self.path.clone().unwrap_or_else(default_path),
                timeout_ms: self.timeout_ms.unwrap_or_else(default_timeout),
                host_rewrite: self.host_rewrite.clone(),
            }
        }
    }
}

impl Default for McpRouterConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            multiplexing: true,
            route_name: "default".to_string(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let json = r#"{
            "servers": [
                {
                    "name": "time",
                    "mcp_cluster": {
                        "cluster": "time_cluster",
                        "path": "/mcp",
                        "timeout_ms": 5000
                    }
                },
                {
                    "name": "files",
                    "cluster": "files_cluster"
                }
            ],
            "multiplexing": true,
            "route_name": "default"
        }"#;
        
        let config = McpRouterConfig::from_json(json).unwrap();
        assert_eq!(config.servers.len(), 2);
        assert!(config.is_multiplexing());
        
        let backends = config.backends();
        assert_eq!(backends[0].name, "time");
        assert_eq!(backends[0].cluster(), "time_cluster");
        assert_eq!(backends[1].name, "files");
        assert_eq!(backends[1].cluster(), "files_cluster");
    }

    #[test]
    fn test_backend_lookup() {
        let json = r#"{
            "servers": [
                {"name": "backend1", "cluster": "cluster1"},
                {"name": "backend2", "cluster": "cluster2"}
            ]
        }"#;
        
        let config = McpRouterConfig::from_json(json).unwrap();
        let map = config.backend_map();
        
        assert!(map.contains_key("backend1"));
        assert!(map.contains_key("backend2"));
        assert!(!map.contains_key("backend3"));
    }
}
