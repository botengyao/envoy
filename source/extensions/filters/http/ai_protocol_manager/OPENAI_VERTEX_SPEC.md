# OpenAI ↔ GCP Vertex AI Conversion Spec

Reference spec derived from the Go implementation in
`envoy-ai-gateway/internal/translator/{openai_gcpvertexai,openai_gcpvertexai_embeddings,gemini_helper}.go`.
This is the source of truth for the C++ port in this filter. Kept alongside `DESIGN.md`
because the port must match this behavior exactly; deviations should be explicit.

Scope:
- OpenAI `chat/completions` ↔ Gemini `generateContent` / `streamGenerateContent` (streaming + non-streaming)
- OpenAI `embeddings` ↔ Vertex `predict`
- **Not** covered: Claude-on-Vertex path.

---

## 1. Translator interface contract

Go interface: `Translator[ReqT, SpanT any]`.

```
RequestBody(raw []byte, body *ReqT, flag bool)
  → newHeaders, mutatedBody, err
ResponseHeaders(headers map[string]string)
  → newHeaders, err
ResponseBody(respHeaders, body io.Reader, endOfStream bool, span SpanT)
  → newHeaders, mutatedBody, tokenUsage, responseModel, err
ResponseError(respHeaders, body io.Reader)
  → newHeaders, mutatedBody, err
```

One translator instance per request, not thread-safe. Streaming state held on the instance:
`stream`, `streamDelimiter`, `bufferedBody`, `requestModel`, `toolCallIndex`, `responseMode`.

Optional `ResponseRedactor` interface for debug-log redaction; out of scope for first port.

---

## 2. Request: OpenAI chat/completions → Gemini generateContent

### URL path

```
publishers/google/models/{model}:{method}{?alt=sse}
```

- `model` = `modelNameOverride` if set, else request `model`.
- `method` = `generateContent` when `stream=false`, `streamGenerateContent` when `stream=true`.
- Query `alt=sse` only when streaming.

### Headers

Set `:path` to computed path, set `content-length` to serialized body length. No other mutations.

### Body field mapping

| OpenAI | Gemini | Rule |
|---|---|---|
| `model` | (URL path) | Extracted into path; not in body. |
| `stream` | (routing only) | Picks endpoint + adds `alt=sse`. |
| `messages[]` | `contents[]` + `systemInstruction` | See §2.1 message conversion. |
| `temperature` | `generationConfig.temperature` | `*float32` copy. |
| `top_p` | `generationConfig.topP` | `*float32` copy. |
| `max_tokens` / `max_completion_tokens` | `generationConfig.maxOutputTokens` | `cmp.Or(max_completion_tokens, max_tokens)` → `int32`. |
| `n` | `generationConfig.candidateCount` | `int32`. |
| `stop` (string or []string) | `generationConfig.stopSequences` | Scalar → singleton slice; array copied. |
| `seed` | `generationConfig.seed` | `*int32`. |
| `frequency_penalty` | `generationConfig.frequencyPenalty` | `*float64`. |
| `presence_penalty` | `generationConfig.presencePenalty` | `*float64`. |
| `logprobs` | `generationConfig.responseLogprobs` | bool. |
| `top_logprobs` | `generationConfig.logprobs` | `int32`. |
| `response_format` | `generationConfig.responseMimeType` + `responseSchema` / `responseJsonSchema` | See §2.4. |
| `tools[]` | `tools[].functionDeclarations[]` (+ `googleSearch`, `enterpriseWebSearch`) | See §2.2. |
| `tool_choice` | `toolConfig.functionCallingConfig` | See §2.3. |
| `thinking` | `generationConfig.thinkingConfig` | See §2.5. |
| `reasoning_effort` | `generationConfig.thinkingConfig.thinkingLevel` | Gemini 3 only; see §2.6. |
| `guided_choice` | `responseSchema` + `responseMimeType: "text/x.enum"` | Enum schema. |
| `guided_regex` | `responseSchema` (pattern string) + `responseMimeType: "application/json"` | |
| `guided_json` | `responseJsonSchema` + `responseMimeType: "application/json"` | Direct copy. |
| `user` | (dropped) | Not sent. |
| `service_tier` | (dropped) | Not supported. |
| `gcp_vertex_ai_vendor_fields.generationConfig.mediaResolution` | `generationConfig.mediaResolution` | Gemini 3+ only; vendor override. |
| `gcp_vertex_ai_vendor_fields.safetySettings[]` | `safetySettings[]` | Vendor override. |

**response_format / guided_* mutual exclusion:** at most one; >1 → validation error.

### 2.1 Message conversion — `openAIMessagesToGeminiContents`

Buffer-and-flush algorithm to satisfy Gemini's alternating user/model roles:

1. system / developer messages → parts appended to a single `systemInstruction`.
2. user and tool messages → accumulate parts in a pending buffer.
3. When an assistant message is seen: flush pending buffer as one `genai.Content{role:"user"}`, then emit an assistant `Content{role:"model"}`.
4. End of list: flush remaining pending as a user `Content` if non-empty.

Per-role rules:

**system / developer:**
- content string or []string → text parts; appended to `systemInstruction.Parts`.
- Both kinds merge into the same `systemInstruction`.

**user:**
- content string → single text part.
- content parts array:
  - `text` → text part.
  - `image_url` → image part. `parseDataURI` for `data:` URIs (extract MIME + base64 bytes) else determine MIME from file extension (default `image/jpeg`). `NewPartFromBytes` for data URIs, `NewPartFromURI` for HTTP URLs.
    - `detail` field, if model supports media resolution (Gemini 3+): `low/medium/high/auto` → `PartMediaResolutionLevel`; attach as `PartMediaResolution`.
  - `input_audio` → **rejected** (not supported yet).
  - `file` → **rejected** (not supported yet).

**tool:**
- requires matching `tool_call_id` from a prior assistant message (looked up in `knownToolCalls` map populated by assistant msg handler).
- content string or []string → concatenated; wrapped in `NewPartFromFunctionResponse(name, {"output": concatenated})`.

**assistant:**
- flush pending buffer as user Content first.
- role `"model"`.
- `tool_calls[]` → one `NewPartFromFunctionCall` per call; `name` stored in `knownToolCalls[id]` for later tool-message lookup.
- content: string or parts.
  - text part → text.
  - thinking part with `signature` (base64) → thought part; signature attaches to first tool call's `ThoughtSignature` if tool calls present, else stays on thought part.
  - refusal → **ignored** (no Gemini mapping).

### 2.2 Tools — `openAIToolsToGeminiTools`

Per-tool:

| OpenAI type | Gemini |
|---|---|
| `function` | `Tool.FunctionDeclarations[].FunctionDeclaration` |
| `google_search` | `Tool.GoogleSearch` (+ optional `BlockingConfidence`, `ExcludeDomains`, `TimeRangeFilter`) |
| `enterprise_search` | `Tool.EnterpriseWebSearch{}` |
| `image_generation` | **rejected** |

FunctionDeclaration:
- `function.name` → `Name`
- `function.description` → `Description`
- `function.parameters` (JSON-Schema):
  - Gemini 2.5+: `ParametersJsonSchema` (verbatim copy).
  - Else: `Parameters` via `jsonSchemaToGemini()` (simplified Gemini schema).

`jsonSchemaToGemini` mapping: `object`→`OBJECT`, `string`→`STRING`, `number`/`integer`→`NUMBER`, `boolean`→`BOOLEAN`, `array`→`ARRAY` (recurse on items), `enum`→`Schema.Enum`, `required` propagated.

### 2.3 Tool choice — `openAIToolChoiceToGeminiToolConfig`

| tool_choice | `functionCallingConfig` |
|---|---|
| `"auto"` | `Mode = AUTO` |
| `"none"` | `Mode = NONE` |
| `"required"` | `Mode = ANY` |
| `{type: "function", function: {name: "foo"}}` | `Mode = ANY`, `AllowedFunctionNames = ["foo"]` |
| null | nil (field omitted) |

### 2.4 Response format

| OpenAI | Gemini |
|---|---|
| `{type: "text"}` | `responseMimeType = "text/plain"` |
| `{type: "json_object"}` | `responseMimeType = "application/json"`, no schema |
| `{type: "json_schema", json_schema:{schema:S}}` | `responseMimeType = "application/json"` + `responseJsonSchema=S` (Gemini 2.5+) or `responseSchema=jsonSchemaToGemini(S)` |

### 2.5 Thinking

OpenAI `thinking` union → Gemini `thinkingConfig`:
- `OfEnabled{IncludeThoughts, BudgetTokens int64}` → `{IncludeThoughts, ThinkingBudget: int32(BudgetTokens)}`
- `OfDisabled` → `{IncludeThoughts: false, ThinkingBudget: nil}`
- unset → field omitted.

### 2.6 Reasoning effort (Gemini 3+)

Feature gate: model name contains both `"gemini"` and `"3"`.

| reasoning_effort | Flash | Pro |
|---|---|---|
| `none` | `THINKING_LEVEL_MINIMAL` | **error** |
| `low` | `THINKING_LEVEL_LOW` | `THINKING_LEVEL_LOW` |
| `medium` | `THINKING_LEVEL_MEDIUM` | `THINKING_LEVEL_HIGH` |
| `high` | `THINKING_LEVEL_HIGH` | **error** |

Flash detection: model name contains `"flash"`.

### 2.7 Vendor fields

`gcp_vertex_ai_vendor_fields` applied **after** standard translation; overrides conflicting fields. Currently `mediaResolution` (Gemini 3+) and `safetySettings`.

---

## 3. Request: OpenAI embeddings → Vertex predict

### URL path

```
publishers/google/models/{model}:predict
```

### Headers

Set `:path`, `content-length`.

### Body mapping

| OpenAI | Gemini | Rule |
|---|---|---|
| `input` | `instances[]` | See §3.1. |
| `dimensions` | `parameters.outputDimensionality` | If >0. |
| `encoding_format` | (dropped) | |
| `user` | (dropped) | |
| `gcp_vertex_ai_embedding_vendor_fields.autoTruncate` | `parameters.autoTruncate` | |
| `gcp_vertex_ai_embedding_vendor_fields.taskType` | per-instance `task_type` (override) | See §3.1. |

### 3.1 Instance construction — `setInstances`

Input polymorphism:

| input | instances |
|---|---|
| `string` | `[{content}]` |
| `[]string` | one per element |
| `EmbeddingInputItem` | one with content + optional task_type, title |
| `[]EmbeddingInputItem` | one per element |

Instance = `{Content, TaskType, Title}`. Title kept only when `TaskType == "RETRIEVAL_DOCUMENT"` (else dropped). Global vendor `taskType` overrides per-item.

---

## 4. Response: generateContent → chat.completion (non-streaming)

### Status

2xx → `ResponseBody`. Non-2xx → `ResponseError` (§8).

### Body mapping — `geminiResponseToOpenAIMessage`

| Gemini | OpenAI | Rule |
|---|---|---|
| `responseId` | `id` | Copy. |
| `createTime` | `created` | Unix seconds. |
| `modelVersion` (if present) | `model` | Else `requestModel`. |
| `candidates[]` | `choices[]` | §4.1. |
| `usageMetadata` | `usage` | §4.2. |
| (const) | `object` | `"chat.completion"`. |

### 4.1 Candidate → choice — `geminiCandidatesToOpenAIChoices`

Per candidate:

| Gemini | OpenAI | |
|---|---|---|
| index (loop) | `index` | |
| `content.parts[]` | `message` | see below |
| `finishReason` | `finish_reason` | §4.3 |
| `safetyRatings[]` | `message.safety_ratings` | copy as-is |
| `groundingMetadata` | `message.grounding_metadata` | copy as-is |
| `logprobsResult` | `logprobs` | float32→float64, flatten chosen+top |

Part extraction:
- `Thought==true` text → `message.reasoning_content.text`.
- `Thought==false` text → `message.content` (concat).
- `FunctionCall` → `message.tool_calls[]`: id = UUID, `function.name`, `function.arguments = json.Marshal(args)`, `type="function"`.
- `ThoughtSignature` (base64) → `message.reasoning_content.signature` (first tool call only if calls present).

Role always `"assistant"`. If tool calls present, `content` is omitted (Gemini never emits both simultaneously). If neither, `content = nil`.

### 4.2 Usage — `geminiUsageToOpenAIUsage`

```
prompt_tokens        = PromptTokenCount
completion_tokens    = CandidatesTokenCount + ThoughtsTokenCount
total_tokens         = TotalTokenCount
prompt_tokens_details.cached_tokens         = CachedContentTokenCount
completion_tokens_details.reasoning_tokens  = ThoughtsTokenCount
```

TokenUsage metrics struct also populated: input / output / total / cached_input / reasoning.

### 4.3 Finish reason — `geminiFinishReasonToOpenAI`

| Gemini | OpenAI |
|---|---|
| `STOP` + no tool calls | `stop` |
| `STOP` + tool calls | `tool_calls` |
| `MAX_TOKENS` | `length` |
| `""` (streaming intermediate) | `""` |
| anything else | `content_filter` (default fallback) |

---

## 5. Response: predict → embedding response

Structure:
```
predictions[] → data[]
  embeddings.values float32[]  → embedding float64[] (cast)
  statistics.token_count       → summed across predictions → usage.prompt_tokens
  statistics.truncated          → data[i].truncated
```
`object = "list"`, `model = requestModel`, `usage.total_tokens = usage.prompt_tokens` (no output tokens).

---

## 6. SSE streaming — the critical part

### 6.1 Delimiter detection

`detectSSEDelimiter(bytes)`: check `\r\n\r\n`, then `\n\n`, then `\r\r`; first match wins. Stored in `streamDelimiter`, reused for all subsequent chunks.

### 6.2 Reassembly — `parseGCPStreamingChunks`

State: `bufferedBody []byte`, `streamDelimiter []byte`.

Per call:
1. Concatenate `bufferedBody` with new data.
2. Split on `streamDelimiter`.
3. For each part except last:
   - Trim whitespace; skip empty.
   - Strip `data: ` prefix if present.
   - Try `json.Unmarshal` as `GenerateContentResponse`.
     - Success → add to chunk list.
     - Fail → treat as partial; prepend to `bufferedBody` along with anything after.
4. Last part always retained in `bufferedBody` (may be incomplete).

Empty body case: return `[]byte{}` (not nil) so Envoy doesn't pass through original body.

### 6.3 Per-chunk conversion — `convertGCPChunkToOpenAI`

Per parsed chunk:

```
{
  id:      responseId,          // from first chunk, reused
  created: createTime,          // from first chunk, reused
  object:  "chat.completion.chunk",
  model:   requestModel,
  choices: geminiCandidatesToOpenAIStreamingChoices(candidates),
  usage:   nil     // except final usage chunk (see 6.5)
}
```

Serialize via `serializeOpenAIChatCompletionChunk`: `"data: " + json + "\n\n"`.

### 6.4 Streaming choice delta — `geminiCandidatesToOpenAIStreamingChoices`

For each candidate:
- text parts `Thought==false` → `delta.content` (string pointer).
- text parts `Thought==true` → `delta.reasoning_content.text`.
- `FunctionCall` parts → `delta.tool_calls[]` via `extractToolCallsFromGeminiPartsStream`:
  - UUID id, function name/args as in non-streaming.
  - **`index` is a global counter on the translator instance** (`o.toolCallIndex`), NOT position within this frame. Starts at 0, increments per tool call emitted across the whole stream.
- `ThoughtSignature` (base64) → `delta.reasoning_content.signature`.
- `finishReason` mapped as §4.3; empty valid for intermediate chunks.

### 6.5 Usage emission

When `usageMetadata` is present AND `PromptTokenCount > 0`:
- Emit a dedicated final chunk: `choices=[]`, `usage=populated`, no finish reason.
- Matches OpenAI's `stream_options.include_usage` protocol.

### 6.6 [DONE]

When `endOfStream==true` in `ResponseBody`: append `"data: [DONE]\n"` to outbound body.

### 6.7 Mid-stream errors

Parse failure on a frame: return error; Envoy terminates stream; translator discarded. No recovery.

### 6.8 Per-instance state across chunks

Preserved in translator instance:
- `bufferedBody`, `streamDelimiter` — reassembly state.
- `toolCallIndex` — global tool-call counter.
- `requestModel` — used in every chunk's `model` field.
- response id / created — captured from first chunk, reused.

Token totals accumulated by the **caller** (not the translator).

---

## 7. Helpers to port as-is

`gemini_helper.go`:
- `openAIMessagesToGeminiContents`, `userMsgToGeminiParts`, `developerMsgToGeminiParts`, `assistantMsgToGeminiParts`, `toolMsgToGeminiParts`
- `openAIToolsToGeminiTools`, `openAIToolChoiceToGeminiToolConfig`
- `openAIReqToGeminiGenerationConfig`
- `geminiCandidatesToOpenAIChoices`, `geminiCandidatesToOpenAIStreamingChoices`
- `geminiUsageToOpenAIUsage`, `geminiFinishReasonToOpenAI`
- `extractTextAndThoughtSummaryFromGeminiParts`, `extractToolCallsFromGeminiParts`, `extractToolCallsFromGeminiPartsStream`
- `jsonSchemaToGemini`, `mapDetailMediaResolution`, `mapReasoningEffortToThinkingLevel`, `getGenerationConfigThinkingConfig`
- Feature gates: `responseJSONSchemaAvailable`, `mediaResolutionAvailable`, `reasoningEffortAvailable`, `isGeminiFlashModel`

`util.go`:
- `systemMsgToDeveloperMsg`, `serializeOpenAIChatCompletionChunk`, `parseDataURI`

`openai_gcpvertexai.go`:
- `convertGCPVertexAIErrorToOpenAI`, `detectSSEDelimiter`

---

## 8. Error translation

GCP error JSON:
```json
{"error": {"code": 400, "message": "...", "status": "INVALID_ARGUMENT", "details": [...]}}
```

→ OpenAI error:
```json
{"type": "error",
 "error": {"type": "INVALID_ARGUMENT", "message": "...", "code": "400"}}
```

Rules:
- Parse as GCP JSON; if OK, use `status` as type, `message` as message.
- If `details` present: `message = "Error: "+msg+"\nDetails: "+json(details)`.
- If body not JSON: use raw body as message, type `"GCPVertexAIBackendError"`.
- Code from `:status` header, stringified.

---

## 9. Invariants & gotchas

1. **Model is deterministic:** Gemini models don't virtualize; `modelNameOverride` wins for path. Response `model` = `modelVersion` if present else `requestModel`.
2. **Tool-call `index` in streaming is global**, not per-frame. Counter persists across all chunks in a stream.
3. **Signature attachment:** in a response with both thinking and tool calls, signature goes on the first tool call only (not the thought).
4. **Role flush:** user/tool parts buffer until assistant message — required for strict user/model alternation.
5. **SystemInstruction is singular:** all system + developer messages merge into one `Content` object's `Parts[]`.
6. **Response-format / guided_* exclusivity:** at most one; >1 is an error.
7. **Streaming buffering:** incomplete JSON across TCP chunks must be retained in `bufferedBody`; parse only complete JSON.
8. **Empty streaming body:** return `[]byte{}` (not nil) to suppress pass-through.
9. **Tool+text mutual exclusion in response:** if tool calls present, `content` is nil/omitted.
10. **Title-only-with-RETRIEVAL_DOCUMENT:** title silently dropped for other task types.
11. **Media resolution:** Gemini 3+ only; silently no-op on older models even if `detail` is set.
12. **Reasoning effort validation:** invalid effort×model combos are errors, not silent degradation (none/high require Flash).
13. **Audio & file content in user messages:** rejected (explicit error).
14. **Refusal content:** silently ignored.
15. **Feature gates are model-name heuristics:** `contains("gemini") && contains("3")`, `contains("flash")`. Fragile; capability registry would be better but not what the Go code does.

---

## 10. Gaps / deferred

- Audio / file content parts (rejected today).
- Grounding metadata / safety ratings: copied through opaquely; no transform.
- Stream cancellation: no graceful cleanup path.
- Request validation is minimal; assumes prior filter validated.
- No response-level caching.
