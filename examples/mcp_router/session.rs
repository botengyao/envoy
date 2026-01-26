//! Stateless Session Management
//!
//! Implements composite session IDs that encode all session state, allowing
//! any gateway replica to route requests without external session storage.
//!
//! ## Composite Session ID Format
//!
//! ```text
//! {route}@{base64(subject)}@{backend1}:{base64(sid1)},{backend2}:{base64(sid2)}
//! ```
//!
//! Example:
//! ```text
//! default@dXNlcjEyMw==@time:YWJjMTIz,files:ZGVmNDU2
//!         ↑              ↑              ↑
//!      "user123"      "abc123"       "def456"
//! ```

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;

// ============================================================================
// Session Codec
// ============================================================================

/// Utility for base64 encoding/decoding session components
pub struct SessionCodec;

impl SessionCodec {
    /// Encode a string to base64
    pub fn encode(s: &str) -> String {
        BASE64.encode(s.as_bytes())
    }
    
    /// Decode a base64 string
    pub fn decode(s: &str) -> Result<String, String> {
        BASE64.decode(s)
            .map_err(|e| format!("Base64 decode error: {}", e))
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|e| format!("UTF-8 decode error: {}", e))
            })
    }
}

// ============================================================================
// Composite Session ID
// ============================================================================

/// Parsed composite session ID with all routing information
#[derive(Debug, Clone, Default)]
pub struct CompositeSessionId {
    /// Route name (e.g., "default")
    pub route: String,
    
    /// Subject identifier (e.g., user ID from JWT)
    pub subject: String,
    
    /// Backend-specific session IDs
    pub backend_sessions: HashMap<String, String>,
}

impl CompositeSessionId {
    /// Create a new empty composite session ID
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create with route and subject
    pub fn with_route_subject(route: &str, subject: &str) -> Self {
        Self {
            route: route.to_string(),
            subject: subject.to_string(),
            backend_sessions: HashMap::new(),
        }
    }
    
    /// Add or update a backend session ID
    pub fn set_backend_session(&mut self, backend: &str, session_id: &str) {
        self.backend_sessions.insert(backend.to_string(), session_id.to_string());
    }
    
    /// Get a backend session ID
    pub fn get_backend_session(&self, backend: &str) -> Option<&str> {
        self.backend_sessions.get(backend).map(|s| s.as_str())
    }
    
    /// Check if we have a session for a specific backend
    pub fn has_backend(&self, backend: &str) -> bool {
        self.backend_sessions.contains_key(backend)
    }
    
    /// Encode to wire format
    ///
    /// Format (inner): `{route}@{base64(subject)}@{backend1}:{base64(sid1)},{backend2}:{base64(sid2)}`
    pub fn encode(&self) -> String {
        let encoded_subject = if self.subject.is_empty() {
            String::new()
        } else {
            SessionCodec::encode(&self.subject)
        };
        
        let backend_part: String = self.backend_sessions
            .iter()
            .map(|(backend, session_id)| {
                format!("{}:{}", backend, SessionCodec::encode(session_id))
            })
            .collect::<Vec<_>>()
            .join(",");
        
        // Build composite string
        let composite = format!("{}@{}@{}", self.route, encoded_subject, backend_part);
        
        // Apply outer Base64 encoding to match C++ implementation
        SessionCodec::encode(&composite)
    }
    
    /// Parse from wire format
    /// 
    /// The incoming value is first Base64 decoded (outer decoding).
    /// Then it is parsed into route@subject@backends format.
    pub fn parse(encoded: &str) -> Result<Self, String> {
        // First, apply outer Base64 decoding to match C++ implementation
        let decoded = SessionCodec::decode(encoded)?;
        
        let parts: Vec<&str> = decoded.splitn(3, '@').collect();
        
        if parts.len() < 3 {
            return Err("Invalid session ID format: expected route@subject@backends".to_string());
        }
        
        let route = parts[0].to_string();
        
        let subject = if parts[1].is_empty() {
            String::new()
        } else {
            SessionCodec::decode(parts[1])?
        };
        
        let mut backend_sessions = HashMap::new();
        
        if !parts[2].is_empty() {
            for entry in parts[2].split(',') {
                if let Some(colon_pos) = entry.find(':') {
                    let backend = &entry[..colon_pos];
                    let encoded_session = &entry[colon_pos + 1..];
                    
                    if !backend.is_empty() && !encoded_session.is_empty() {
                        let session_id = SessionCodec::decode(encoded_session)?;
                        backend_sessions.insert(backend.to_string(), session_id);
                    }
                }
            }
        }
        
        Ok(Self {
            route,
            subject,
            backend_sessions,
        })
    }
}

// ============================================================================
// Session Builder
// ============================================================================

/// Builder for creating composite session IDs from backend responses
pub struct SessionBuilder {
    route: String,
    subject: String,
    sessions: HashMap<String, String>,
}

impl SessionBuilder {
    /// Create a new session builder
    pub fn new(route: &str, subject: &str) -> Self {
        Self {
            route: route.to_string(),
            subject: subject.to_string(),
            sessions: HashMap::new(),
        }
    }
    
    /// Add a backend session from an initialize response
    pub fn add_backend_session(&mut self, backend: &str, session_id: &str) {
        if !session_id.is_empty() {
            self.sessions.insert(backend.to_string(), session_id.to_string());
        }
    }
    
    /// Build the composite session ID
    pub fn build(self) -> CompositeSessionId {
        CompositeSessionId {
            route: self.route,
            subject: self.subject,
            backend_sessions: self.sessions,
        }
    }
    
    /// Encode directly to string
    pub fn encode(self) -> String {
        self.build().encode()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_codec() {
        let original = "hello world 123";
        let encoded = SessionCodec::encode(original);
        let decoded = SessionCodec::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_composite_session_roundtrip() {
        let mut session = CompositeSessionId::with_route_subject("default", "user123");
        session.set_backend_session("time", "session-abc");
        session.set_backend_session("files", "session-def");
        
        let encoded = session.encode();
        let parsed = CompositeSessionId::parse(&encoded).unwrap();
        
        assert_eq!(parsed.route, "default");
        assert_eq!(parsed.subject, "user123");
        assert_eq!(parsed.get_backend_session("time"), Some("session-abc"));
        assert_eq!(parsed.get_backend_session("files"), Some("session-def"));
    }

    #[test]
    fn test_session_builder() {
        let mut builder = SessionBuilder::new("myroute", "user456");
        builder.add_backend_session("backend1", "sid1");
        builder.add_backend_session("backend2", "sid2");
        
        let session = builder.build();
        assert_eq!(session.route, "myroute");
        assert_eq!(session.subject, "user456");
        assert!(session.has_backend("backend1"));
        assert!(session.has_backend("backend2"));
    }

    #[test]
    fn test_empty_subject() {
        let session = CompositeSessionId::with_route_subject("default", "");
        session.encode();
        
        let mut session2 = CompositeSessionId::with_route_subject("default", "");
        session2.set_backend_session("test", "abc");
        let encoded = session2.encode();
        let parsed = CompositeSessionId::parse(&encoded).unwrap();
        assert_eq!(parsed.subject, "");
        assert_eq!(parsed.get_backend_session("test"), Some("abc"));
    }
}
