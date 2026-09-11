# Experiment: request_info AI filter, read from a file access log

Runs a real `envoy-static` built from `ai-request-info-filter` and checks that the
`envoy.filters.ai.request_info` AI filter publishes `envoy.data.ai.v3.RequestInfo` for every
declared AI endpoint, by reading the record back in a file access log.

```
curl ──> :10000 ai_gateway ─────────────────────────────────> :10001 mock_llm
         ai_protocol_manager                                   direct_response stand-ins
           request_handling.filters: [request_info]            for OpenAI / Anthropic / Gemini
           response_handling.token_usage: {}
         router
         access_log: logs/access.log (JSON)
```

Both listeners live in one Envoy process, so nothing else needs to run.

## Result

- 7 requests to declared AI endpoints, 7 records: `request_info.published: 7`, one of them
  `partial`. The undeclared route and the malformed body publish nothing.
- `%DYNAMIC_METADATA(envoy.ai.request_info)%` is `null` on every line.
- `%TYPED_CEL(metadata.typed_filter_metadata['envoy.ai.request_info'])%` prints the whole record.

## Reading the record

`request_info` publishes **typed** dynamic metadata only (`typed_filter_metadata`, an `Any`). The
stock `%DYNAMIC_METADATA%` formatter reads the untyped `filter_metadata` Struct, so it never sees
the record. CEL's `metadata` is the whole `Metadata` message, and CEL unpacks the `Any` through the
descriptor pool, so these work (`ri` stands for
`metadata.typed_filter_metadata['envoy.ai.request_info']`):

| Want | Formatter |
|---|---|
| whole record, as a JSON object | `%TYPED_CEL(ri)%` |
| a string attribute | `%CEL(ri.model)%` |
| a wrapper attribute | `%TYPED_CEL(has(ri.stream) ? ri.stream : null)%` |
| whether a record exists | `%TYPED_CEL('envoy.ai.request_info' in metadata.typed_filter_metadata)%` |
| token usage, same way | `%TYPED_CEL(metadata.typed_filter_metadata['envoy.ai.token_usage'])%` |

`CEL` and `TYPED_CEL` are built-in commands, so no `formatters:` entry is needed. Two things to
know:

- **Guard wrapper fields with `has()`.** `stream`, `max_output_tokens`, `message_count` and
  `tool_count` are wrappers so that "absent" differs from `false`/`0`. Envoy leaves cel-cpp's
  `enable_empty_wrapper_null_unboxing` off, so a bare `ri.stream` reads an absent field as its zero
  value. Checked on this binary:

  | Request body | `ri.stream`, `ri.tool_count` | guarded | `%TYPED_CEL(ri)%` |
  |---|---|---|---|
  | no `stream`, no `tools` | `false`, `0` | `null`, `null` | both omitted |
  | `"stream": false, "tools": []` | `false`, `0` | `false`, `0` | `"stream": false, "tool_count": 0` |

- **uint64 prints as a string in the whole record.** `%TYPED_CEL(ri)%` goes through proto3 JSON,
  so `max_output_tokens` is `"256"`. Read the field on its own (`%TYPED_CEL(ri.max_output_tokens)%`)
  to get the number `256`.

## Steps

### 1. Branch

```bash
git fetch origin ai-request-info-filter
git switch --no-track -c ai-request-info-demo origin/ai-request-info-filter
```

### 2. macOS build settings

`user.bazelrc` is gitignored, so each worktree needs its own. Both lines are required: the second
covers V8 built for the exec configuration.

```bash
printf 'build --macos_minimum_os=14.0\nbuild --host_macos_minimum_os=14.0\n' > user.bazelrc
```

### 3. Build Envoy

A cold build took 29 minutes on 18 cores (17,320 actions).

```bash
bazel build -c opt //source/exe:envoy-static
```

### 4. Stage the binary

`bazel-bin` follows the last build's configuration, so copy the binary out. `bin/` is gitignored.

```bash
mkdir -p experiment/ai-request-info/bin
cp -f bazel-bin/source/exe/envoy-static experiment/ai-request-info/bin/envoy
experiment/ai-request-info/bin/envoy --version
```

```
bin/envoy  version: 9713ed28d7adf11c871aa2b462347593ad9af2a0/1.40.0-dev/Modified/RELEASE/BoringSSL
```

### 5. Validate the config

```bash
cd experiment/ai-request-info
bin/envoy --mode validate -c envoy.yaml
```

The work-in-progress API warnings for `ai_protocol_manager` are expected; it ends with
`configuration 'envoy.yaml' OK`.

### 6. Run Envoy (terminal 1)

```bash
./run_envoy.sh
```

The terminal stays quiet: the server log goes to `logs/envoy.log`, with `ai_protocol_manager` at
trace (the AI filters) and `filter` at debug (the manager itself). The access log is
`logs/access.log`.

### 7. Send requests (terminal 2)

```bash
./send_requests.sh
```

### 8. Read the access log

```bash
jq -c '{path, response_code, dynamic_metadata, request_info}' logs/access.log
jq -c '{path, token_usage}' logs/access.log
```

## Captured run

From 2026-09-11 at `9713ed28d7`. The raw files are in [captured/](captured/).

### Requests

```
1 openai chat completions          POST /v1/chat/completions                                       -> 200
2 openai chat completions (sse)    POST /v1/chat/completions                                       -> 200
3 openai responses                 POST /v1/responses                                              -> 200
4 anthropic messages               POST /v1/messages                                               -> 200
5 gemini generateContent           POST /v1beta/models/gemini-2.5-flash:generateContent            -> 200
6 gemini streamGenerateContent     POST /v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse -> 200
7 anthropic, unusable values       POST /v1/messages                                               -> 200
8 undeclared route                 POST /v1/embeddings                                             -> 200
9 malformed json                   POST /v1/chat/completions                                       -> 400
```

### Access log: request_info

`jq -c '{path, response_code, dynamic_metadata, request_info}' logs/access.log`

```
{"path":"/v1/chat/completions","response_code":200,"dynamic_metadata":null,"request_info":{"api_protocol":"OPENAI_CHAT_COMPLETIONS","max_output_tokens":"256","message_count":2,"model":"gpt-4o-mini","tool_count":1}}
{"path":"/v1/chat/completions","response_code":200,"dynamic_metadata":null,"request_info":{"api_protocol":"OPENAI_CHAT_COMPLETIONS","max_output_tokens":"64","message_count":1,"model":"gpt-4o-mini","stream":true}}
{"path":"/v1/responses","response_code":200,"dynamic_metadata":null,"request_info":{"api_protocol":"OPENAI_RESPONSES","max_output_tokens":"512","message_count":1,"model":"gpt-4.1","tool_count":2}}
{"path":"/v1/messages","response_code":200,"dynamic_metadata":null,"request_info":{"api_protocol":"ANTHROPIC_MESSAGES","max_output_tokens":"1024","message_count":3,"model":"claude-sonnet-5","tool_count":1}}
{"path":"/v1beta/models/gemini-2.5-flash:generateContent","response_code":200,"dynamic_metadata":null,"request_info":{"api_protocol":"GEMINI_GENERATE_CONTENT","max_output_tokens":"200","message_count":1,"model":"gemini-2.5-flash","stream":false}}
{"path":"/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse","response_code":200,"dynamic_metadata":null,"request_info":{"api_protocol":"GEMINI_GENERATE_CONTENT","max_output_tokens":"32","message_count":1,"model":"gemini-2.5-flash","stream":true}}
{"path":"/v1/messages","response_code":200,"dynamic_metadata":null,"request_info":{"api_protocol":"ANTHROPIC_MESSAGES","message_count":1,"model":"claude-sonnet-5"}}
{"path":"/v1/embeddings","response_code":200,"dynamic_metadata":null,"request_info":null}
{"path":"/v1/chat/completions","response_code":400,"dynamic_metadata":null,"request_info":null}
```

| # | What it shows |
|---|---|
| 1 | `max_completion_tokens` → `max_output_tokens`; `stream` was not sent, so it is absent rather than `false` |
| 2 | no `max_completion_tokens`, so `max_tokens` is used |
| 3 | a string `input` counts as one message |
| 4 | Anthropic `max_tokens`, `messages`, `tools` |
| 5 | Gemini `model` and `stream` come from the path; `generationConfig.maxOutputTokens` |
| 6 | `:streamGenerateContent` → `stream: true`; the snake_case `generation_config.max_output_tokens` also works |
| 7 | `"max_tokens": "lots"` and an object `tools` read as absent; the record is still published and counted `partial` |
| 8 | no per-route declaration: passed through, no record |
| 9 | rejected with 400 (`ai_protocol_manager_invalid_json`) before the AI filters run: no record |

### Access log: token usage

`jq -c '{path, token_usage}' logs/access.log`

```
{"path":"/v1/chat/completions","token_usage":{"api_protocol":"OPENAI_CHAT_COMPLETIONS","extraction_status":"COMPLETE","input_token_details":{"cached_tokens":"0"},"input_tokens":"42","model":"gpt-4o-mini-2024-07-18","output_token_details":{"reasoning_tokens":"0"},"output_tokens":"7","provider_total_tokens":"49","total_tokens":"49"}}
{"path":"/v1/chat/completions","token_usage":{"api_protocol":"OPENAI_CHAT_COMPLETIONS","extraction_status":"COMPLETE","input_tokens":"18","model":"gpt-4o-mini-2024-07-18","output_tokens":"2","provider_total_tokens":"20","total_tokens":"20"}}
{"path":"/v1/responses","token_usage":{"api_protocol":"OPENAI_RESPONSES","extraction_status":"COMPLETE","input_token_details":{"cached_tokens":"0"},"input_tokens":"36","model":"gpt-4.1-2025-04-14","output_token_details":{"reasoning_tokens":"0"},"output_tokens":"3","provider_total_tokens":"39","total_tokens":"39"}}
{"path":"/v1/messages","token_usage":{"api_protocol":"ANTHROPIC_MESSAGES","extraction_status":"COMPLETE","input_token_details":{"cache_creation_tokens":"0","cached_tokens":"100"},"input_tokens":"125","model":"claude-sonnet-5","output_tokens":"12","total_tokens":"137"}}
{"path":"/v1beta/models/gemini-2.5-flash:generateContent","token_usage":{"api_protocol":"GEMINI_GENERATE_CONTENT","extraction_status":"COMPLETE","input_tokens":"12","model":"gemini-2.5-flash","output_token_details":{"reasoning_tokens":"40"},"output_tokens":"57","provider_total_tokens":"69","total_tokens":"69"}}
{"path":"/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse","token_usage":{"api_protocol":"GEMINI_GENERATE_CONTENT","extraction_status":"COMPLETE","input_tokens":"8","model":"gemini-2.5-flash","output_tokens":"2","provider_total_tokens":"10","total_tokens":"10"}}
{"path":"/v1/messages","token_usage":{"api_protocol":"ANTHROPIC_MESSAGES","extraction_status":"COMPLETE","input_token_details":{"cache_creation_tokens":"0","cached_tokens":"100"},"input_tokens":"125","model":"claude-sonnet-5","output_tokens":"12","total_tokens":"137"}}
{"path":"/v1/embeddings","token_usage":null}
{"path":"/v1/chat/completions","token_usage":null}
```

The model here is the one the mock answered with, not the one requested. Anthropic's input is
canonicalized to 25 + 100 cache read = 125, and Gemini's output to 17 + 40 thoughts = 57.

### One full line

```json
{
  "dynamic_metadata": null,
  "method": "POST",
  "model": "gpt-4o-mini",
  "path": "/v1/chat/completions",
  "request_info": {
    "api_protocol": "OPENAI_CHAT_COMPLETIONS",
    "max_output_tokens": "256",
    "message_count": 2,
    "model": "gpt-4o-mini",
    "tool_count": 1
  },
  "response_code": 200,
  "response_code_details": "via_upstream",
  "start_time": "2026-09-11T18:51:53.752Z",
  "token_usage": {
    "api_protocol": "OPENAI_CHAT_COMPLETIONS",
    "extraction_status": "COMPLETE",
    "input_token_details": {
      "cached_tokens": "0"
    },
    "input_tokens": "42",
    "model": "gpt-4o-mini-2024-07-18",
    "output_token_details": {
      "reasoning_tokens": "0"
    },
    "output_tokens": "7",
    "provider_total_tokens": "49",
    "total_tokens": "49"
  }
}
```

### Server log

The AI lines from `logs/envoy.log`, with the date, thread id and source path trimmed. Each record is
published before the body replay, which is what releases the held headers to later filters.

```
[14:51:53.752][debug][filter] filter.cc: ai_protocol_manager: route declares request API OPENAI_CHAT_COMPLETIONS
[14:51:53.752][trace][ai_protocol_manager] filter.cc: request_info: published to namespace envoy.ai.request_info
[14:51:53.752][debug][filter] buffer_manager.cc: ai_protocol_manager: in-memory replay requested for 287 bytes
[14:51:53.760][debug][filter] filter.cc: ai_protocol_manager: route declares request API OPENAI_CHAT_COMPLETIONS
[14:51:53.760][trace][ai_protocol_manager] filter.cc: request_info: published to namespace envoy.ai.request_info
[14:51:53.760][debug][filter] buffer_manager.cc: ai_protocol_manager: in-memory replay requested for 141 bytes
[14:51:53.768][debug][filter] filter.cc: ai_protocol_manager: route declares request API OPENAI_RESPONSES
[14:51:53.768][trace][ai_protocol_manager] filter.cc: request_info: published to namespace envoy.ai.request_info
[14:51:53.768][debug][filter] buffer_manager.cc: ai_protocol_manager: in-memory replay requested for 168 bytes
[14:51:53.774][debug][filter] filter.cc: ai_protocol_manager: route declares request API ANTHROPIC_MESSAGES
[14:51:53.775][trace][ai_protocol_manager] filter.cc: request_info: published to namespace envoy.ai.request_info
[14:51:53.775][debug][filter] buffer_manager.cc: ai_protocol_manager: in-memory replay requested for 280 bytes
[14:51:53.781][debug][filter] filter.cc: ai_protocol_manager: route declares request API GEMINI_GENERATE_CONTENT
[14:51:53.781][trace][ai_protocol_manager] filter.cc: request_info: published to namespace envoy.ai.request_info
[14:51:53.781][debug][filter] buffer_manager.cc: ai_protocol_manager: in-memory replay requested for 122 bytes
[14:51:53.788][debug][filter] filter.cc: ai_protocol_manager: route declares request API GEMINI_GENERATE_CONTENT
[14:51:53.788][trace][ai_protocol_manager] filter.cc: request_info: published to namespace envoy.ai.request_info
[14:51:53.788][debug][filter] buffer_manager.cc: ai_protocol_manager: in-memory replay requested for 102 bytes
[14:51:53.794][debug][filter] filter.cc: ai_protocol_manager: route declares request API ANTHROPIC_MESSAGES
[14:51:53.794][trace][ai_protocol_manager] filter.cc: request_info: published to namespace envoy.ai.request_info
[14:51:53.794][debug][filter] buffer_manager.cc: ai_protocol_manager: in-memory replay requested for 123 bytes
[14:51:53.807][debug][filter] filter.cc: ai_protocol_manager: route declares request API OPENAI_CHAT_COMPLETIONS
[14:51:53.807][debug][filter] filter.cc: ai_protocol_manager: rejecting request: wuffs json: json: bad input
```

### Counters

`curl -s '127.0.0.1:9901/stats?filter=ai_protocol_manager'`, non-zero only:

```
ai_protocol_manager.request_info.partial: 1
ai_protocol_manager.request_info.published: 7
ai_protocol_manager.request_parse_error: 1
ai_protocol_manager.request_parsed: 7
ai_protocol_manager.token_usage_found: 7
```
