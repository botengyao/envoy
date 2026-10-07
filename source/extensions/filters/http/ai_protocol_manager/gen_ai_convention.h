#pragma once

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

// Names and values from the OpenTelemetry GenAI semantic conventions, as of commit cb10b70c15.
namespace GenAiConvention {

constexpr absl::string_view UsageInputTokens = "gen_ai.client.inference.usage.input_tokens";
constexpr absl::string_view UsageOutputTokens = "gen_ai.client.inference.usage.output_tokens";
constexpr absl::string_view UsageCacheReadInputTokens =
    "gen_ai.client.inference.usage.cache_read.input_tokens";
constexpr absl::string_view UsageCacheWriteInputTokens =
    "gen_ai.client.inference.usage.cache_write.input_tokens";
constexpr absl::string_view UsageReasoningOutputTokens =
    "gen_ai.client.inference.usage.reasoning.output_tokens";
constexpr absl::string_view OperationInputTokens = "gen_ai.client.inference.operation.input_tokens";
constexpr absl::string_view OperationOutputTokens =
    "gen_ai.client.inference.operation.output_tokens";

constexpr absl::string_view OperationName = "gen_ai.operation.name";
constexpr absl::string_view ProviderName = "gen_ai.provider.name";
constexpr absl::string_view RequestModel = "gen_ai.request.model";
constexpr absl::string_view ResponseModel = "gen_ai.response.model";
constexpr absl::string_view ServerAddress = "server.address";
constexpr absl::string_view ServerPort = "server.port";
constexpr absl::string_view TokenModality = "gen_ai.token.modality";
// From the OpenTelemetry metrics SDK specification rather than the GenAI conventions.
constexpr absl::string_view MetricOverflow = "otel.metric.overflow";

constexpr absl::string_view Chat = "chat";
constexpr absl::string_view GenerateContent = "generate_content";
constexpr absl::string_view OpenAi = "openai";
constexpr absl::string_view Anthropic = "anthropic";
constexpr absl::string_view GcpGenAi = "gcp.gen_ai";
constexpr absl::string_view Unknown = "unknown";
constexpr absl::string_view Other = "_OTHER";
constexpr absl::string_view True = "true";

} // namespace GenAiConvention
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
