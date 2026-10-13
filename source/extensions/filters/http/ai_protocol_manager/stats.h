#pragma once

#include "envoy/stats/stats_macros.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace AiProtocolManager {

/**
 * All stats for the AI Protocol Manager filter. @see stats_macros.h
 */
#define ALL_AI_PROTOCOL_MANAGER_STATS(COUNTER)                                                     \
  COUNTER(request_parsed)                                                                          \
  COUNTER(request_parse_error)                                                                     \
  COUNTER(request_passthrough)                                                                     \
  COUNTER(request_external_buffer_error)                                                           \
  COUNTER(response_external_buffer_error)                                                          \
  COUNTER(unsupported_content_encoding)

struct AiProtocolManagerStats {
  ALL_AI_PROTOCOL_MANAGER_STATS(GENERATE_COUNTER_STRUCT)
};

} // namespace AiProtocolManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
