#pragma once

#include "source/extensions/filters/http/ai_protocol_manager/schema.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {
namespace GeminiInteractions {

// Reusable sub-schemas and complete payload schema definition for the Gemini Interactions API.
const Schema& contentSchema();
const Schema& stepSchema();
const Schema& toolSchema();
const Schema& generationConfigSchema();

// Returns the full Gemini Interactions PayloadSchema.
PayloadSchema createPayloadSchema();

} // namespace GeminiInteractions
} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
