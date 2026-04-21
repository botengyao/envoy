#pragma once

#include <string>
#include <vector>

#include "source/extensions/filters/http/ai_protocol_manager/codec/ai_payload.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace Codec {

// DESIGN.md §4.1 Agent variant.

enum class AgentDialect { Unknown, A2a, Mcp };

enum class AgentInvocation {
  Unknown,
  // MCP
  Initialize,
  Ping,
  ToolsList,
  ToolsCall,
  ResourcesList,
  ResourcesRead,
  ResourcesSubscribe,
  ResourcesUnsubscribe,
  PromptsList,
  PromptsGet,
  SamplingCreateMessage,
  CompletionComplete,
  LoggingSetLevel,
  // A2A
  MessageSend,
  MessageStream,
  TaskSubmit,
  TaskGet,
  TaskCancel,
};

struct AgentTarget {
  std::string agent_id;    // logical agent / skill id for routing
  std::string session_id;  // MCP session / A2A context id
  std::string task_id;     // A2A task id (empty outside task ops)
};

struct AgentPayload {
  AgentDialect dialect{AgentDialect::Unknown};
  AgentInvocation invocation{AgentInvocation::Unknown};
  AgentTarget target;

  // Selector fields — small, protocol-specific; only those relevant to
  // `invocation` are populated.
  std::string tool_name;       // ToolsCall
  std::string resource_uri;    // Resources*
  std::string prompt_name;     // PromptsGet
  std::string completion_ref;  // CompletionComplete

  // Potentially large — offloadable.
  std::vector<PayloadRef> parts;  // A2A Parts | MCP content[]
  PayloadRef arguments;           // ToolsCall.arguments, PromptsGet.arguments
  PayloadRef capabilities;        // Initialize

  PayloadRef residual_params;
};

} // namespace Codec
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
