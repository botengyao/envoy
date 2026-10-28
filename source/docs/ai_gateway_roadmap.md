# Envoy as an AI gateway: a roadmap to parity with LiteLLM and agentgateway

Status: proposal, 2026-10-27.

Facts below were checked on 2026-10-27 against Envoy `main` at `585dcff330` (after #48497),
LiteLLM v1.106.5 (`main` at `c7c895db45`), agentgateway v1.7.0 (`main` at `3ef1040786`), and the
specifications and provider documentation listed under [Sources](#appendix-b-sources).

## Summary

- **Envoy already has the hard part.** The AI Protocol Manager parses four LLM APIs, moving large
  payload strings into an external buffer. It transcodes between them through one intermediate
  representation (IR), and extracts canonical token usage. The MCP and A2A filters parse agent
  traffic, and `mcp_router` federates MCP servers. Underneath sit the retries, load balancing,
  rate limiting, auth, ext_proc and dynamic modules that both peers had to build from scratch. All
  of the AI extensions are alpha, and their security posture is `unknown`.
- **Envoy trails on the features buyers check first.** Both peers ship all of these, and Envoy has
  none of them end to end:
  - the Responses API as a front door;
  - a model catalog with prices;
  - token limits that settle on actual usage;
  - a guardrail pipeline;
  - MCP 2026-07-28 federation;
  - MCP OAuth with token exchange;
  - per-identity tool filtering;
  - GenAI telemetry.
- **The bar moved in 2026.**
  - Open Responses joined the Agentic AI Foundation (AAIF) on 2026-10-22, and OpenAI now ships new
    capabilities on Responses only.
  - MCP 2026-07-28 made MCP stateless, and A2A reached 1.0.
  - agentgateway and Agent Router (the former Envoy AI Gateway) are both AAIF projects. Agent
    Router names Envoy as its data plane, but still runs its AI logic in a Go ext_proc sidecar.
  - Google Cloud's Agent Gateway preview is also built on Envoy.
  - An AI Protocol Manager chain that covers the hot path would become the shared in-process data
    plane for all of them.
- **Strategy.** Match the peers in the data plane, not as a product. Every capability a peer ships
  should be expressible as Envoy configuration and should run natively in Envoy. Keys, budget
  objects, price catalogs and UIs stay in control planes such as Agent Router.
- **The list.** Twelve P0 items in six themes (below), then 16 P1 and 14 P2 items. If staffed, the
  P0 items can land across Envoy 1.41 and 1.42.
- **Where Envoy can lead, not just follow:**
  - resilience depth;
  - in-process extensibility;
  - protocol breadth and workload identity;
  - its position under self-hosted inference routing;
  - a security process that keeps control-plane code out of the serving process.

  LiteLLM shipped compromised release artifacts twice in 2026.

### P0 at a glance

| ID | Item | LiteLLM | agentgateway | Envoy today |
|---|---|---|---|---|
| [A1](#a1-responses-and-open-responses-as-a-first-class-api) | Responses / Open Responses front door | yes | yes | usage and request facts only |
| [M1](#m1-usage-fidelity) | Usage fidelity | yes | yes | misses compaction, cache-write TTLs, tier |
| [M2](#m2-model-catalog-and-virtual-models) | Model catalog and virtual models | yes | yes | per-request model override; #48492 open |
| [M3](#m3-cost) | Cost | yes | yes | none |
| [M4](#m4-token-limits-and-budgets-that-settle) | Token limits and budgets that settle | yes | yes | pieces exist, loop untested |
| [R1](#r1-provider-aware-retries-and-fallback) | Provider-aware retries and fallback | yes | yes | generic retries; per-attempt state leaks |
| [S1](#s1-guardrail-ai-filter) | Guardrail AI filter | yes | yes | ext_proc only |
| [G1](#g1-mcp-2026-07-28-federation) | MCP 2026-07-28 federation | yes | yes | router is session-based |
| [G2](#g2-mcp-authorization-and-credential-brokering) | MCP authorization and credential brokering | yes | yes | JWT validation only |
| [G3](#g3-mcp-tool-governance) | MCP tool governance | yes | yes | call-time RBAC only |
| [O1](#o1-genai-telemetry) | GenAI telemetry | yes | yes | counters only |
| [O2](#o2-production-readiness) | Production readiness | n/a | n/a | alpha, posture `unknown` |

## 1. Thinking it through

### What parity means for Envoy

The three projects are different kinds of software, so a feature-for-feature copy is the wrong
target.

- **LiteLLM is a product.** It is a Python SDK and proxy with a Postgres-backed key and spend
  ledger, Redis for multi-instance correctness, and an admin UI.
- **agentgateway is an agent-first data plane** with its own Kubernetes controller and a standalone
  mode that keeps keys, budgets and analytics in SQLite or Postgres.
- **Envoy is a data plane** whose behavior a control plane assembles from filters over xDS.

Copying either product would put a database, a UI and a billing ledger into a proxy. That is the
wrong shape for Envoy, and upstream would not accept it.

The bar used here is: **a control plane can express every capability the peers ship using Envoy
configuration alone, and the per-request work runs natively in Envoy.** That means no Python hop,
no mandatory ext_proc round trip, and bounded memory on streams. Each capability belongs in one of
three places:

- **Data plane (Envoy):** anything that must see or change a request or response, or decide per
  request. That covers parsing, translation, routing, limits, guardrail enforcement and telemetry.
- **Control plane (Agent Router, Envoy Gateway, Istio, custom xDS):** keys, teams and budgets as
  objects; provider catalogs; price tables; UIs; policy authoring. Envoy owes these clean hooks.
- **Out of scope:** SDKs, admin UIs, billing ledgers, agent runtimes and stdio MCP servers.

### How the items were ranked

1. **P0 when both peers ship it and Envoy has no end-to-end answer.** The exception is something
   that is large and serves a narrow workload.
2. **A standard requiring it raises priority.** Examples: the Open Responses core, the MCP
   2026-07-28 MUSTs, A2A 1.0.
3. **Foundations come first.** Usage feeds cost, and cost feeds budgets, so usage is P0 even though
   nobody buys it on its own.
4. **P1 or P2 when only one peer ships it,** or when it serves a narrower workload.
5. **Envoy-specific blockers count as P0.** Nobody puts an internet-facing gateway on extensions
   whose security posture is `unknown`.

### Principles

1. **Parse once, publish typed facts.** The AI Protocol Manager is the only component that
   understands AI payloads. Rate limits, RBAC, routing, logs and traces consume the facts it
   publishes (request info, token usage, the IR) instead of parsing again.
2. **Compose generic Envoy features before inventing AI-specific ones.** A token limit is a rate
   limit with a token addend. Model access is RBAC on a model fact. Fallback is retries over
   candidates. New AI-only machinery is the exception and needs a reason.
3. **Streaming first, memory bounded.** Responses are long SSE streams, and requests carry
   megabytes of context. Every feature states what it holds and for how long.
4. **Upstreams are untrusted too.** Model output and MCP servers are reachable by attackers.
5. **Declarative by default, code as the escape hatch.** Transcoding packs, bindings and model
   tables are data. ext_proc and dynamic modules cover the rest.
6. **Track the standards, not one vendor.** Open Responses, MCP, A2A and the OpenTelemetry GenAI
   conventions decide what clients send next year. Vendor APIs are supported through bindings and
   packs.

## 2. The peers

### LiteLLM (v1.106.5)

**What it is**
- A Python (FastAPI) proxy and SDK, MIT-licensed, with a license-gated enterprise tier.
- It needs Postgres for keys, the UI and spend, and Redis for correct limits once there is more
  than one worker or pod.
- It ships 794 HTTP/WebSocket routes, 178 provider enum entries (87 of them chat-capable), and a
  cost map with 4,333 model entries.

**Strengths**
- **Any-to-any translation.** Responses, Anthropic Messages, Gemini generateContent and Gemini
  Interactions are each bridged to every chat provider. That covers reasoning-effort mapping,
  tools, structured output and prompt-cache markers.
- **Hierarchical budgets and limits.** Budgets and TPM/RPM/ITPM/OTPM limits apply per key, user,
  team, org, customer, tag, model and agent, with reservations for in-flight requests.
- **Guardrails.** 62 guardrail integrations, with pre-, during-, post- and MCP-call modes.
- **MCP gateway.** The gateway is also the OAuth server: RFC 9728 and RFC 8414 metadata, DCR and
  Client ID Metadata Documents, RFC 8707. It does OBO and ID-JAG exchange, offers toolsets, and
  pins tool descriptions against rug pulls (v1.105).
- **A2A.** An agent registry, with per-session budgets and a kill switch.
- **Its 2026 headline:** classifier-driven auto-routing, now license-metered.

**Weaknesses**
- **Throughput.** About 8 ms P95 overhead at 1k RPS on four instances, and at least 4 GiB per
  worker.
- **State on the hot path.** Postgres and Redis sit on the request path, and spend flushes every
  60 s.
- **Release churn.** A minor release every week, with breaking changes.
- **Security record in 2026:**
  - compromised release artifacts on 2026-03-24 (PyPI) and 2026-10-21 (PyPI, Docker Hub, GHCR);
  - 18 advisories, five of them critical, the latest (CVSS 10.0) fixed on 2026-10-27;
  - the advisories cluster where control-plane features share the serving process.
- **Rust is not yet the data plane.** It serves OCR, and `/v1/messages` only as an opt-in.

### agentgateway (v1.7.0)

**What it is**
- A Rust data plane, a Go Kubernetes controller, and its own delta-xDS types.
- A standalone mode with SQLite or Postgres for keys, budgets, analytics and the UI.
- A Linux Foundation project and AAIF member since 2026-06-04. Solo.io sells an enterprise edition.

**Strengths**
- **MCP is the deepest part:**
  - 2026-07-28 support since v1.4 (2026-07-27): `server/discover` with version intersection, tasks,
    Apps, encrypted resumable sessions;
  - an MCP-level check-and-mutate callout (ExtMcp);
  - CEL authorization that also hides items from `tools/list`;
  - the OAuth resource-server profile, with per-IdP shims, RFC 8693 token exchange and ID-JAG.
- **LLM APIs:** Chat, Responses, Messages (with `count_tokens`), native Gemini and Vertex,
  embeddings, rerank, and OpenAI Realtime over WebSocket.
- **Translation:** pairwise converters, including to Bedrock Converse.
- **Model routing:** `AgentgatewayModel` with virtual models (weighted, failover, CEL-conditional,
  external callout).
- **Metering:** a built-in pricing catalog of 920 models, and local token limits that charge an
  estimate, amend it with actual usage, and refund on later rejection.
- **Guardrails:** regex/PII rules, a webhook API, OpenAI moderation, Bedrock Guardrails, Model
  Armor and Azure Content Safety, scoped to system prompt, messages, tool input and output, and
  reasoning.
- **Telemetry:** GenAI span attributes and TTFT/TPOT metrics.
- **Kubernetes:** passes Gateway API Inference Extension conformance.
- **Performance (vendor-published):** about 35k QPS with p99 near 2 ms in about 25 MiB.

**Weaknesses**
- **Unstable APIs.** CRDs are still `v1alpha1`, and every monthly minor release breaks something.
- **Kubernetes trails standalone.** Budgets, OIDC and OpenAPI-to-MCP are missing from the CRDs.
- **Thin resilience.** Passive health checks only, fixed-backoff retries, no retry budgets, no
  hedging.
- **No caching.** There is no response or semantic cache.
- **Limited extensibility.** No in-process plugins (no Wasm, Lua or dynamic modules), one ext_proc
  per route, and no STREAMED ext_proc mode.
- **Gaps elsewhere:**
  - no HTTP/3;
  - metrics by Prometheus pull only;
  - thin A2A support;
  - no Gemini Interactions;
  - seven security advisories, all MCP or cross-namespace;
  - heavy vendor concentration in commits.

### The rest of the market

A scan of 15 products that handle LLM traffic (Agent Router, Higress, Kong, Portkey, Cloudflare,
AWS AgentCore, Azure API Management, Apigee, F5, Traefik, Vercel, Bifrost, TrueFoundry, OpenRouter
and Helicone) finds the same baseline.

**Table stakes in late 2026**
- **API formats.**
  - An OpenAI-compatible API with translation across providers: 13 of the 15.
  - Anthropic Messages accepted as input: 12 of the 15. This is new in 2026, driven by Claude Code
    and Codex users.
  - The Responses API, at least as passthrough: nearly all.
- **Fallback and retries:** all 15.
- **Metering and limits:** token accounting that includes cache reads and writes, plus token limits
  (self-hosted products) or dollar budgets (SaaS routers).
- **Guardrails:** integrations with third-party guardrail vendors.
- **MCP:** a proxy with OAuth and tool filtering, in 14 products.
- **Operations:** OTel export.

**Becoming table stakes**
- Classifier or decision-model routing: seven products shipped it in September and October 2026.
- Latency-aware routing, and a time-to-first-token (TTFT) cutoff that falls back to another backend.
- MCP 2026-07-28 in production: AWS, Higress, Kong, Traefik, Microsoft's MCP Gateway and IBM
  ContextForge shipped it within weeks of the spec.
- Prompt-cache affinity, and automatic `cache_control` insertion.
- Tool-authorization policy engines (Cedar, AuthZEN, CEL).
- Controls on tool bloat: virtual MCP servers, tool search, code mode.

**Envoy-based neighbors**
- **Agent Router**, the former Envoy AI Gateway, was renamed and moved under AAIF in September
  2026; its latest release is v1.2.0 (2026-10-07). Its data plane is Envoy plus a Go sidecar
  running two ext_proc filters: one at the router, which parses the body and picks the model, and
  one upstream, which runs per attempt to translate, authenticate and meter. An in-memory map links
  the two, so every pod needs a stateful sidecar, and its port to dynamic modules has stalled.
  - It lacks: caching, guardrails, PII masking, dollar costs, quotas longer than a day, latency or
    semantic routing, Realtime, MCP 2026-07-28, and first-class A2A. Its A2A recipe uses Envoy's
    alpha `a2a` filter.
  - [Appendix C](#appendix-c-agent-routers-ext_proc-duties-and-their-native-homes) maps its
    ext_proc duties onto native Envoy filters.
- **Higress** (Envoy plus Wasm) ships the broadest open-source AI plugin set: semantic caching over
  seven vector stores, data masking, a context-window limit, and an in-gateway Wasm endpoint
  picker that scores KV-cache use and LoRA residency.
- **Google Cloud Agent Gateway** (preview, 2026-04-22) is "built on an open foundation including
  Envoy and Kubernetes".

**Consolidation**
- Palo Alto Networks bought Portkey (closed 2026-05-29); its open-source gateway has had no release
  since January.
- Kong split its AI gateway into a separate runtime.
- Helicone's open-source Rust gateway is abandoned.
- Open and neutral options are thinning, which is the opening for Envoy.

## 3. The 2026 bar

**APIs**
- **Open Responses** joined AAIF on 2026-10-22.
  - The model: items (`message`, `function_call`, `function_call_output`, `reasoning`), semantic
    SSE events with `sequence_number`, and vendor extensions that must carry a `slug:` prefix.
  - The 2026-04-24 revision added a WebSocket transport and `/v1/responses/compact`.
  - A compliance suite exists.
  - Adopters: vLLM, Ollama (stateless only), Hugging Face, OpenRouter, Vercel and Bedrock.
    Anthropic and Google have not adopted it.
- **OpenAI** now ships new capabilities on Responses only: tool calling on GPT-6 Astra
  (2026-09-03), and async tool calls and mid-turn steering over WebSockets.
  - It returns a distinct 429 `slow_down` and 503 `server_is_overloaded`, both with
    `Retry-After`.
  - Prompt caching routes on `prompt_cache_key`, and cache writes are priced by TTL (30 minutes or
    12 hours).
  - It accepts workload identity federation, including mTLS (GA 2026-08-29).
- **Server-side state is the norm.** OpenAI has `previous_response_id` and `conversation`. Gemini
  Interactions has `previous_interaction_id` (55-day retention on paid tiers). Bedrock's Responses
  state is scoped to a region. The gateway consequence: affinity, data residency, and no blind
  failover.
- **Anthropic:**
  - server-side compaction, where top-level usage excludes compaction iterations, so billing must
    sum them;
  - automatic prompt caching;
  - `effort`;
  - structured outputs GA;
  - the MCP connector;
  - Skills and Files GA.
- **Google:** Interactions went GA in June 2026, and `generateContent` is called legacy. From
  2026-10-26, new paid projects store `generateContent` requests by default.

**Agent protocols**
- **MCP 2026-07-28** removes `initialize` and `Mcp-Session-Id`.
  - `Mcp-Method` and `Mcp-Name` are REQUIRED, and must match the body (400 with -32020 if not).
  - Server-to-client requests become Multi Round-Trip Requests (MRTR), carrying an opaque
    `requestState`.
  - List results gain `ttlMs` and `cacheScope`.
  - Tasks, Apps, Skills and Enterprise-Managed Authorization become extensions. Sampling, roots and
    logging are deprecated.
  - Authorization MUSTs: RFC 9728 metadata, RFC 8707 audience, and no token passthrough.
  - Fleets that mix eras need a bridge between the session era and the stateless era.
- **A2A 1.0:**
  - PascalCase methods;
  - JSON-RPC, gRPC and HTTP+JSON bindings;
  - the `A2A-Version` header;
  - JWS-signed Agent Cards;
  - a `tenant` field on every request.

  It became an AAIF Growth Stage project in August 2026.

**Identity, telemetry and security**
- **Agent identity:**
  - ID-JAG (draft-04) underpins MCP Enterprise-Managed Authorization and Okta Agent SSO;
  - Transaction Tokens (draft-11) reached WG consensus;
  - WIMSE AIMS (adopted 2026-09-15) treats agents as SPIFFE workloads.
- **Telemetry:** the GenAI conventions moved to `semantic-conventions-genai` (2026-06-12) and are
  still at Development stability. v1.41 added time-to-first-chunk and time-per-output-chunk
  metrics.
- **Security frameworks:**
  - OWASP LLM Top 10 2026 (2026-08-03), with the Agent Control Standard v0.1;
  - OWASP Top 10 for Agentic Applications (2025-12-09);
  - OWASP MCP Top 10 (beta).

  Gateway mitigations: audience checks with no passthrough, virtual MCP servers, tool pinning, DLP,
  SSRF-safe egress, and spend caps.

**Inference and payments**
- **Inference routing:** Gateway API Inference Extension v1.6 (2026-08-17) moved the endpoint
  picker (EPP) and body-based routing into llm-d. The EPP protocol is Envoy ext_proc in
  `FULL_DUPLEX_STREAMED` mode, and vLLM Semantic Router is also an Envoy ext_proc.
- **Agent payments:** x402 (Linux Foundation, operational 2026-07-14), AP2 (FIDO), ACP and UCP.
  Today a gateway's job is to pass 402 flows through untouched.

## 4. Envoy today

### AI Protocol Manager (`envoy.filters.http.ai_protocol_manager`, alpha)

| Capability | Where | Notes |
|---|---|---|
| AI endpoint declaration | `AiProtocolManagerPerRoute`; filter state `envoy.ai.llm_protocol.request` | Per route, or per request (#48497) |
| Wire APIs | `type.ai.v3.LLMProtocol` | OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, Gemini generateContent |
| Provider HTTP carriage | `type.ai.v3.LLMBinding` | URI pattern plus body edits; built-in Vertex forms for Gemini and Claude |
| Payload parsing | core, external buffer | 400 on malformed JSON; large strings offloaded; the in-memory buffer is unbounded |
| AI filter chain | `envoy.http.ai_filters` | Ordered; runs over the parsed document |
| Schema validation | `schema_validation` (alpha) | Chat, Anthropic, Gemini; API detection by path, header, payload |
| Request facts | `request_info` (alpha) | model, stream, output cap, message and tool counts, byte-based token estimate |
| Transcoding | `transcoder` (wip) | IR is Chat Completions; packs for Chat, Anthropic, Gemini; unary and SSE; **no Responses pack** |
| Per-request instructions | filter state | `llm_protocol.response`, `binding.request/response`, `model.resolved` |
| Token usage | response handling | JSON and SSE for all four APIs; cached, cache-write, tool-use, reasoning; typed metadata only |
| Upstream placement | upstream HTTP filter | Per-attempt replay; dynamic-forward-proxy egress |
| Stats | counters | No per-model dimension, no latency histograms, no cost |

### Agent protocols

| Extension | Status | What it does |
|---|---|---|
| `mcp` | alpha | JSON-RPC parsing to metadata or filter state; method groups; 2026-07-28 headers and `_meta` checks; trace context and baggage from `_meta` |
| `mcp_router` | alpha | Federates MCP servers with tool prefixing; lazy init; elicitation, sampling and roots relayed with id rewriting; identity-bound, HMAC-signed session ids; no client token passthrough by default. **Session-based (2025 era); no `server/discover`, MRTR, tasks or `subscriptions/listen`** |
| `mcp_json_rest_bridge` | alpha | tools/call to REST via `HttpRule`; local `tools/list` with cache scope; `Mcp-Param-*` checks; 2026-07-28 gated on `max_supported_protocol_version` |
| `a2a` | alpha | JSON-RPC parsing and method groups; no card handling, no 1.0 bindings |
| `sse_to_metadata`, `aws_eventstream_parser` | alpha | Generic field extraction from SSE and AWS event streams |

### Generic building blocks an AI gateway composes

- **Global rate limiting:**
  - descriptors from metadata, filter state, JWT claims or CEL (`rate_limit_descriptors.expr`);
  - `hits_addend` as a number or a format string, and `%CEL(...)%` is built in;
  - `apply_on_stream_done`;
  - `is_negative_hits` to refund.

  RLQS (`rate_limit_quota`) is stable.
- **Local rate limiting:** token buckets with a request-time `hits_addend`. It runs on the decode
  path only (#48530 adds `apply_on_stream_done`).
- **Identity:** `jwt_authn`, `oauth2`, `api_key_auth`, `ext_authz`, and RBAC with CEL conditions and
  a filter-state principal.
- **Upstream credentials:** `credential_injector` (generic, OAuth2 client credentials),
  `aws_request_signing`, `gcp_authn`.
- **Resilience:** retries with budgets, hedging, outlier detection, active health checks, circuit
  breakers, overload manager, and priority and locality failover.
- **Cluster selection:** the `priority_group` and `matcher` cluster specifiers, the composite
  cluster, `refresh_cluster_on_retry`, the dynamic forward proxy, and the `override_host` load
  balancer for endpoint pickers. The `host_allowlist` load balancer (#47805) excludes hosts per
  request.
- **Programmability:** ext_proc (including full-duplex streamed bodies), Lua, Wasm, dynamic modules
  (stable), `set_filter_state`.
- **Telemetry:** access logs (file, gRPC, OTel, stats logger), `%CEL%`/`%TYPED_CEL%`, OTel tracing.
  No GenAI conventions.
- **Not there:** no cache keyed on request bodies or meaning, and no WebSocket message parsing, so
  Realtime and Live traffic is opaque after the upgrade.

## 5. Gap matrix

`yes` / `part` / `no`. The last column names the roadmap item that closes the gap.

| Capability | LiteLLM | agentgateway | Envoy | Item |
|---|---|---|---|---|
| Chat front door translated to Anthropic and Gemini | yes | yes | yes (wip) | A6 |
| Responses API front door and translation | yes | yes (no WebSocket) | part (usage only) | A1 |
| Anthropic Messages, Gemini generateContent | yes | yes | yes | - |
| Gemini Interactions | yes | no | in flight | A4 |
| Bedrock (Converse, Claude on Bedrock, Responses) | yes | part (outbound Converse) | part (event stream, SigV4) | A2 |
| Embeddings | yes | yes | no | A3 |
| Realtime / Live / Responses over WebSocket | yes | part (Realtime) | no | A5 |
| Reasoning, cache-marker, structured-output mapping | yes | yes | part | A6 |
| `/v1/models` listing | yes | yes | no | M2 |
| Batches, files, background jobs | yes | no | no | A7 |
| Model catalog, aliases, wildcards | yes | yes | part (#48492) | M2 |
| Virtual models (weighted, failover, conditional, callout) | yes | yes | part (cluster specifiers, ext_proc) | M2, R4 |
| Cross-provider fallback with per-attempt translation | yes | yes | part (state leaks) | R1 |
| Provider error classes, `Retry-After`, context-window fallback | yes | part | no | R1 |
| Health- and latency-aware selection | yes | yes (P2C over EWMA latency) | part (least request, outlier detection; no latency EWMA) | R6 |
| Retry budgets, hedging, active health checks | part | no | yes | - |
| Stateful-id affinity (`previous_response_id` and others) | yes | no | no | R2 |
| Prompt-cache affinity and marker injection | yes | yes | no | R3 |
| Semantic or classifier routing | yes | part (callout, vSR) | part (ext_proc) | R4 |
| Inference pools (EPP) | part (pod hashing) | yes | yes (ext_proc, `override_host`) | R5 |
| Normalized usage (TTL cache writes, tier, compaction) | yes | yes | part | M1 |
| Pricing catalog and cost | yes | yes | no | M2, M3 |
| Token limits that settle on actual usage | yes | yes (no global refunds) | part (untested) | M4 |
| Budgets in currency or tokens | yes (DB) | yes (DB, standalone) | no | M4 + control plane |
| Virtual keys | yes | yes | part (`api_key_auth`) | control plane |
| Exact response cache | yes | no | no | C1 |
| Semantic cache | yes | no | no | C2 |
| Guardrail framework with vendor adapters | yes | yes | no (ext_proc) | S1 |
| Built-in PII and regex rules | yes | yes | no | S2 |
| Streaming response guardrails | yes | yes | no | S4 |
| Request policy (model allowlists, parameter clamps, `store`) | yes | yes | part (RBAC) | S3 |
| MCP federation | yes | yes | yes | - |
| MCP 2026-07-28 stateless, tasks, `subscriptions/listen` | yes | yes | part (filter, bridge) | G1 |
| MCP OAuth resource server (RFC 9728, RFC 8707, step-up) | yes | yes | no | G2 |
| Token exchange, OBO, ID-JAG to upstreams | yes | yes | no | G2 |
| Per-identity tool lists and virtual servers | yes | yes | no | G3 |
| Tool definition pinning | yes | enterprise | no | G3 |
| MCP policy callout per method | yes | yes | part (ext_authz on metadata) | S1 |
| OpenAPI to MCP | yes | yes (standalone) | part (REST bridge) | G8 |
| A2A 1.0 parsing, cards, signed cards | part (no signed cards found) | part | part (parsing) | G4 |
| Agent session limits, kill switch | yes | no | no | G5 |
| GenAI spans and token/TTFT/TPOT metrics | yes | yes | no | O1 |
| In-process extensions (Wasm, Lua, dynamic modules) | Python hooks | no | yes | O3 |
| HTTP/3 | not found | no | yes | - |
| Reviewed security posture for AI extensions | n/a | n/a | no | O2 |

## 6. Roadmap

Sizes: S (one PR), M (two to four PRs), L (a series). Each P0 item says what it builds on.

### P0

#### A1. Responses and Open Responses as a first-class API

Size L.

- **Why:**
  - Both peers accept Responses, and LiteLLM bridges it to 87 providers.
  - Open Responses is now the AAIF standard for multi-provider LLM APIs.
  - OpenAI ships new features on Responses only.
  - Agent frameworks emit it.

  A gateway that cannot take Responses cannot front those clients at all.
- **Today:** `OPENAI_RESPONSES` exists, and request info and token usage read it. There is no
  payload schema and no transcoding pack, so a Responses client can reach only a Responses backend,
  and the payload goes unvalidated.
- **Proposal:**
  1. A Responses payload schema. It is strict on the Open Responses core and permissive on
     `slug:`-prefixed extensions.
  2. A Responses↔IR pack:
     - input items to Chat messages and tool calls (`function_call.arguments` is a JSON string on
       both sides);
     - `instructions` to a system message;
     - `max_output_tokens`, `text.format`, `reasoning.effort`, and `tool_choice` (including
       `allowed_tools`).

     Streaming maps semantic events to chunks and back, with a monotonic `sequence_number` and
     exactly one terminal event.
  3. Unmapped members ride in the IR's reserved `_envoy` member, so Responses→IR→Responses is
     lossless. `encrypted_content` reasoning and `slug:` items never go to another provider.
  4. State-bound requests stay on a Responses backend, on the account that holds the state (R2).
     These are `previous_response_id`, `store: true` follow-ups, `background` and `conversation`.
     Cross-API requests are refused with an Open Responses error.
  5. Run the Open Responses HTTP compliance tests against the transcoder in CI.
- **Done when:**
  - an Open Responses client reaches Anthropic and Gemini backends through one route, with
    streaming, tools and usage, and passes the HTTP compliance tests;
  - a Chat client reaches a Responses-only model.
- **Builds on:** the IR `_envoy` mechanism from the Gemini Interactions design, and the transcoding
  engine.

#### M1. Usage fidelity

Size S–M.

- **Why:** limits, cost and budgets are only as right as the counts. Both peers normalize cache
  writes by TTL, reasoning and service tier.
- **Today:** `envoy.data.ai.v3.TokenUsage` covers cached reads, cache creation, tool-use and
  reasoning tokens. It misses:
  - Anthropic compaction iterations: top-level usage excludes them, so Envoy under-counts;
  - cache-write TTL buckets, which are priced differently;
  - the service tier;
  - server-side tool calls priced per call;
  - Bedrock streams, which only the generic `aws_eventstream_parser` sees.
- **Proposal:**
  - Add cache-write TTL detail, `service_tier` and server-tool call counts to the record, plus a
    compaction-aware total.
  - Teach the response pipeline Bedrock's event-stream framing. A Bedrock token filter (#43492)
    was closed as not planned; this puts that work in the AI Protocol Manager instead.
  - Add Interactions usage (in flight).
  - Extraction follows the token-usage AI filter design, which reads usage on the IR.
- **Done when:** golden tests exist per API for every new field, including an Anthropic compaction
  stream whose total equals the sum of its iterations.

#### M2. Model catalog and virtual models

Size M.

- **Why:** a logical model name that maps to providers is the abstraction users configure. In
  LiteLLM it is `model_list` and routing groups; in agentgateway it is `AgentgatewayModel` with
  virtual models and a `/v1/models` endpoint.
- **Today:** `envoy.ai.model.resolved` lets a filter replace the model. #48492 adds the
  `model_router` and `route_selector` AI filters. There is no catalog and no listing.
- **Proposal:** one declarative, xDS-delivered table that maps a logical model (exact, alias or
  wildcard) to ordered candidates. Each candidate carries:
  - a backend, API and binding;
  - the upstream model id and a credential reference;
  - the context window and output cap;
  - prices and tags.

  Selection strategies: weighted, failover, conditional (CEL), and callout (the existing ext_proc
  decision-point pattern). An unknown model gets a 404 in the client's API shape. `/v1/models` is
  answered locally. Envoy defines the schema; control planes supply the data. Price lists change
  daily, so they should not be vendored into Envoy.
- **Done when:** one route serves named and wildcard models to different providers with failover,
  and `/v1/models` lists them.
- **Builds on:** #48492, #48082 (client and backend model per request, merged), and the
  `model_table` filter in the budget-routing design.

#### M3. Cost

Size S–M.

- **Why:** budgets in currency, chargeback, and cost-aware routing. Both peers expose cost to logs,
  metrics and policy.
- **Today:** none.
- **Proposal:**
  - Prices live on catalog entries: input, cached read, cache write by TTL, output, reasoning, and
    per-call tools. Tiers can depend on context size and service tier, and a residency multiplier
    is supported.
  - Envoy publishes an estimated cost at request time (input estimate plus output cap) for
    reservations, and the actual cost at stream end. Both are typed metadata that CEL can read.
  - Amounts use integer micro-units, not floats.
- **Done when:** one request's cost appears both in an access-log line and in a rate-limit
  descriptor, and an interrupted stream records partial cost.

#### M4. Token limits and budgets that settle

Size M.

- **Why:** token limits are the first thing enterprises buy.
  - agentgateway charges an estimate, then amends it with actual usage, and refunds when a later
    rule rejects the request.
  - LiteLLM reserves expected output and limits input and output tokens separately.
- **Today:** global rate limiting can already do most of this, but no test or doc proves the loop
  over the AI Protocol Manager's typed records. The pieces:
  - `hits_addend.format` accepts the built-in `%CEL(...)%`;
  - `apply_on_stream_done` charges at the end of the stream;
  - `is_negative_hits` refunds;
  - `rate_limit_descriptors.expr` builds descriptors from CEL.

  Local rate limiting runs on the decode path only.
- **Proposal:**
  1. An integration test and a documented recipe. Reserve the estimate plus the output cap at
     request time, then settle the difference at stream done, charging or refunding.
     - `is_negative_hits` is fixed per descriptor, so settling takes two stream-done descriptors:
       one charges the shortfall and one refunds the excess.
     - Descriptors are per identity, model and API, with separate input and output buckets.
  2. Land #48530 so local limits can charge actual usage too.
  3. Decide what retries cost: per attempt for upstream spend, per request for client quota.
  4. Budgets are the same loop in cost units (M3) against RLS or RLQS. Budget objects and windows
     belong to the control plane. The `host_allowlist` load balancer routes away from exhausted
     deployments.
  5. A real tokenizer for estimates can come later; settling corrects the estimate anyway.
- **Done when:** an end-to-end test shows a per-key TPM limit that refunds an over-estimate and
  charges an under-estimate, on both global and local limits.
- **Note:** RLS is the shared counter, so this loop is consistent across replicas. The peers fall
  short here:
  - LiteLLM's spend is eventually consistent. It flushes every 60 seconds, and an over-budget key
    gets back in until the next flush.
  - agentgateway charges budgets only after the response, in its own database.

#### R1. Provider-aware retries and fallback

Size L; in flight.

- **Why:** both peers fail over across providers and translate on each attempt. LiteLLM maps every
  provider error to a class, and the classes drive retries, fallbacks (context window, content
  policy) and cooldowns.
- **Today:** Envoy's retry machinery (budgets, hedging, outlier detection, priority failover) is
  deeper than agentgateway's, but per-attempt AI state leaks:
  - upstream filters edit the router's header map in place, so a fallback can carry the previous
    provider's credential or path;
  - auto SNI is computed once per request;
  - no retry condition understands provider errors.
- **Proposal:**
  1. Restore headers per attempt, and rebuild TLS options when the cluster changes.
  2. Take each attempt's candidate from M2. The upstream AI Protocol Manager applies its model,
     path, authority, credential and API (#48492 `route_selector`; #48717 `RetryPolicyFactory`).
  3. Add AI retry classes:
     - rate limited (429, OpenAI `slow_down`) vs overloaded (503, Anthropic 529);
     - context length exceeded, which falls back to a larger-context candidate (pre-filtered by
       the request estimate);
     - content filter.

     `Retry-After` feeds both back-off and outlier ejection.
  4. A stateful chain never moves to another account (A1, R2).
  5. A first-token deadline triggers fallback before any byte reaches the client. #43193 asked for
     a TTFT timeout separate from the body timeout and was closed as stale. Agent Router
     approximates one with `per_try_idle_timeout`.
- **Done when:**
  - an OpenAI 429 leads to an Anthropic attempt with a fresh credential and a transcoded body;
  - a context-length error leads to a larger-context model.

#### S1. Guardrail AI filter

Size L.

- **Why:** both peers have one.
  - LiteLLM integrates 62 vendors, with modes before, during and after the call, and for MCP
    calls.
  - agentgateway ships regex/PII rules, a webhook API and four vendor guards, with scopes for
    system prompt, messages, tool input and output, and reasoning.
  - The umbrella proposal (#44681) calls for an AI-native callout.
- **Today:** ext_proc sees raw provider JSON, so every vendor has to parse four dialects and SSE.
- **Proposal:** `envoy.http.ai_filters.guardrail` sends the IR to a callout over gRPC or HTTP JSON.
  - **What it sends:** normalized messages, tools, tool results, the model and identity
    attributes.
  - **Verdicts:** allow; block, which returns an error in the client's API shape; or modify, which
    applies redactions to IR fields and re-serializes.
  - **Coverage:** requests and unary responses first; streaming windows later (S4).
  - **Operation:** guards run in parallel, each with its own fail-open or fail-closed setting and
    timeout.
  - **Vendors:** OpenAI moderation, Bedrock ApplyGuardrail, Model Armor and Azure Content Safety,
    as configuration templates.
  - **MCP:** the same callout checks MCP `tools/call` arguments and results. agentgateway's ExtMcp
    shows the shape.
- **Done when:** one configuration blocks a prompt injection on the request and masks PII in a
  tool result, returning the client's error shape for both OpenAI and Anthropic clients.

#### G1. MCP 2026-07-28 federation

Size L.

- **Why:** 2026-07-28 removes `initialize` and sessions. agentgateway has supported it since v1.4,
  intersecting versions across targets. LiteLLM supports it for upstreams since v1.106.
- **Today:** the `mcp` filter checks 2026-07-28 headers and metadata, and the REST bridge serves
  2026-07-28 tools. `mcp_router` is session-based.
- **Proposal:** stateless federation in `mcp_router`.
  - Answer `server/discover` with the intersection of the backends' versions and capabilities.
  - Route on `Mcp-Method` and `Mcp-Name`, validated against the body (-32020 on mismatch).
  - Pass MRTR `requestState` through byte-exact. A retried call names the same tool or URI, so it
    routes back to the backend that asked without any router state.
  - Route tasks by `taskId`, bound to the principal.
  - Merge `subscriptions/listen` streams.
  - Honor `ttlMs` and `cacheScope` when caching lists; only `public` entries may go in a shared
    cache.
  - Keep the merged tool order deterministic, so provider prompt caches survive.
  - Keep the session path on the same listener for 2025-era clients.
- **Done when:** the MCP conformance suite passes for both eras through one federated endpoint.

#### G2. MCP authorization and credential brokering

Size M–L.

- **Why:** RFC 9728 metadata, RFC 8707 audience binding and no token passthrough are MUSTs in the
  spec. Both peers implement the resource-server profile, RFC 8693 token exchange and ID-JAG.
- **Today:** `jwt_authn` validates tokens, RBAC and ext_authz act on MCP metadata, and `mcp_router`
  drops the client's `authorization` header by default. There is no metadata endpoint, no
  challenge and no exchange.
- **Proposal:**
  1. An MCP resource-server mode:
     - serve `/.well-known/oauth-protected-resource`;
     - answer a 401 with `WWW-Authenticate: Bearer resource_metadata=...`, and a 403
       `insufficient_scope` for step-up;
     - require the token audience to be the resource.
  2. Two new credential types in `credential_injector`, per MCP backend:
     - RFC 8693 token exchange, whose subject is the validated client token, cached per subject and
       audience;
     - ID-JAG (jwt-bearer).
  3. SSRF-safe egress for metadata and Client ID Metadata Document fetches.
  4. Per-IdP quirks (Entra, Okta, Auth0) are documented as configuration, not code.
- **Done when:** an official SDK client authenticates through Envoy to two backends with different
  audiences, and no client token reaches a backend.

#### G3. MCP tool governance

Size M.

- **Why:**
  - OWASP's MCP Top 10 lists tool poisoning and rug pulls, and its Agentic Top 10 lists tool
    misuse.
  - LiteLLM intersects entitlements at list time and call time, offers toolsets, and pins tool
    definitions.
  - agentgateway's CEL rules hide items from lists.
- **Today:** RBAC can deny `tools/call` per tool, but `tools/list` returns every tool. There is no
  rename, no override and no pinning.
- **Proposal:** in `mcp_router`:
  - filter `tools/list` per identity, with the same policy as call-time authorization;
  - virtual servers: a route exposes a named subset of tools across backends;
  - rename tools, and override descriptions and annotations;
  - pin definitions: hash each tool's name, description and input schema, then block or flag drift;
  - check arguments against `inputSchema`, plus per-argument CEL. agentgateway lacks this (#2069).
- **Done when:** two identities see different tool lists on one endpoint, and a changed tool
  description is blocked until it is re-approved.

#### O1. GenAI telemetry

Size M–L; designs exist.

- **Why:** both peers emit token usage, duration, time to first token and time per output token.
  Customers compare these dashboards first.
- **Today:** AI Protocol Manager counters only, with no model dimension, no latency histograms and
  no spans.
- **Proposal:**
  - Ship the no-config GenAI metrics design. Metrics: token usage, operation duration, time to
    first chunk and time per output chunk. Attributes: operation, provider, request and response
    model, error type. Cardinality is capped.
  - Ship the GenAI span plan.
  - Pin the `semantic-conventions-genai` revision, because the names still move.
  - MCP and A2A spans follow.
- **Done when:** a dashboard shows TTFT, TPOT and token usage per model from Envoy alone.

#### O2. Production readiness

Size M; ongoing.

- **Why:** an AI gateway faces untrusted clients and untrusted upstreams. Every AI, MCP and A2A
  extension is alpha with posture `unknown`.
- **Today:** the in-memory external buffer is unbounded. #48708 hardens the streaming JSON parser.
- **Proposal:**
  - **Fuzzers** for the external-buffer JSON parser, the SSE codec, the transcoding engine, LLM
    bindings and URI patterns, and the MCP and A2A JSON-RPC parsers.
  - **Bounded memory:** a bounded external buffer integrated with the overload manager, plus an
    offload implementation (milestone 2 of #44681).
  - **A posture review** toward `robust_to_untrusted_downstream_and_upstream`, and an API freeze
    path per extension.
  - **Reproducible benchmarks** against both peers: throughput, added p99 latency, TTFT overhead,
    and memory per stream at 100 KB, 1 MB and 10 MB payloads.
- **Done when:** the AI Protocol Manager core and the MCP and A2A filters carry a reviewed posture,
  run in OSS-Fuzz, and have published benchmark numbers.

### P1

| ID | Item | Why and shape |
|---|---|---|
| A2 | Bedrock | Claude on Bedrock as a binding (`/model/{model}/invoke`, `anthropic_version`); a Converse pack; the Bedrock Responses endpoints (state scoped to a region; `model` required). SigV4 signs after translation, on every attempt. agentgateway translates to Converse |
| A3 | Embeddings | API values, usage, routing and limits for `/v1/embeddings` and Gemini `embedContent`. Both peers have it, and RAG traffic is mostly embeddings |
| A4 | Gemini Interactions | In flight (three phases: model change, recognition without route config, IR pack). LiteLLM bridges it; agentgateway does not |
| A5 | WebSocket and realtime | A message codec for upgraded streams (frames, unmasking, defragmentation), JSON events, and usage and limits per session. Covers Responses WebSocket mode (connection-local state, a 60-minute cap), Realtime and Live |
| A6 | Translation fidelity | Reasoning effort to thinking budgets, adaptive thinking and effort; prompt-cache markers (`prompt_cache_key`, `cache_control`, `cachePoint`); structured outputs; tool choice; error shapes. Published as a compatibility matrix |
| R2 | Stateful affinity | Map state ids (`previous_response_id`, `conversation`, `previous_interaction_id`, background, file and batch ids) to the account and region that own them, through an HMAC id envelope or a lookup callout. No silent failover |
| R3 | Prompt-cache affinity | Derive and propagate `prompt_cache_key`; hash conversations onto deployments; inject Anthropic and Bedrock markers above a minimum size; keep tool order and prefixes stable |
| R4 | Routing callout and heuristic routing | One decision-point contract (ext_proc now, the AI-native callout later) carrying request facts; the heuristic routing AI filter; a vLLM Semantic Router example |
| R5 | Inference pools | Hand AI facts to the endpoint picker so it does not parse again; fallback lists and `x-gateway-destination-endpoint-served`; prefix-hash hints; llm-d Router conformance |
| R6 | Latency-aware selection | A load balancer that weighs EWMA latency or TTFT next to active requests (agentgateway runs P2C over EWMA; LiteLLM routes on latency and TTFT percentiles). Generic Envoy work; #42091 proposes Prequal. `least_request` already tracks in-flight load, which narrows the gap |
| S2 | Built-in detectors | Regex and keywords, Luhn-checked cards, SSNs, emails, secret patterns; mask or reject on requests, responses and tool I/O |
| S3 | Request policy AI filter | Model allow and deny per identity; output-token clamps; parameter bounds; `store: false` and region enforcement; hosted-tool and remote-MCP `server_url` allowlists; defaults and overrides |
| G4 | A2A 1.0 | JSON-RPC (0.3 and 1.0 method names), HTTP+JSON and gRPC bindings; `A2A-Version` and `A2A-Extensions`; `tenant`; serve, rewrite and verify signed Agent Cards; SSRF-safe push-notification egress |
| O3 | AI extensibility | CEL access to AI facts everywhere (model, usage, cost); a dynamic-module ABI for AI filters over the parsed document (milestone 4 of #44681) |
| O4 | Agent Router alignment and examples | Map Agent Router's ext_proc duties onto native filters; sandboxes; "by example" docs |
| O5 | Provider workload identity | OpenAI workload identity federation and mTLS, plus GCP, AWS and Azure federation, through `credential_injector` instead of static keys |

### P2

| ID | Item | Shape |
|---|---|---|
| C1 | Exact response cache | Opt-in and per tenant; keyed on the normalized request; replays SSE |
| C2 | Semantic cache | An AI filter that calls an embedding and vector service; scoped per tenant |
| S4 | Streaming guardrails | Bounded look-behind windows on response streams; injection scanning of tool output |
| A7 | Async jobs | Route lifecycle calls (background responses, batches, files, MCP tasks, A2A push) to the owning account; verify Standard Webhooks signatures; settlement hooks |
| A8 | Other APIs | Rerank; usage and pricing units for images, audio and OCR |
| G5 | Agent session governance | Per-session limits and iteration budgets keyed on agent session ids; a kill switch over xDS |
| G6 | Agent identity | Mint and propagate Transaction Tokens; record delegation (`act`) in logs; DPoP; validate ID-JAG |
| G7 | Agent egress | Per-agent egress policy on CONNECT and the dynamic forward proxy, with TLS interception and credential brokering |
| G8 | OpenAPI import | Tooling that generates `mcp_json_rest_bridge` config from OpenAPI (control-plane side) |
| G9 | MCP Apps and Skills | Scan `ui://` resources and enforce a CSP; pin Skills digests |
| G10 | Tool search | Progressive disclosure and tool search, to cut tool-definition tokens (LiteLLM has it; enterprise-only in agentgateway) |
| R7 | Priority classes | Map tenants to provider service tiers; admission control per tenant |
| O6 | Content capture | Opt-in prompt and completion capture, with redaction, for evals |
| O7 | Request shaping | Prompt prepend and append, templates |

### Watch

- **Agent payments (x402, AP2, ACP, UCP):** make sure 402 responses and payment headers pass through
  untouched; policy hooks later.
- **AG-UI and remote Agent Client Protocol transports.**
- **MCP roadmap items:** ETags, progressive discovery, HTTP/2 over stdio.
- **Provider-hosted agents:** the OpenAI Agents API, and Anthropic and Gemini managed agents, all
  stateful resources a gateway must scope.

## 7. Sequencing

- **Phase 1, Envoy 1.41 (about January 2027): make the foundations real.**
  - O2 starts with fuzzers and a bounded buffer.
  - M1 and M4 (the recipe and #48530).
  - M2 lands #48492.
  - The O1 metrics MVP.
  - The first R1 PRs (header restore, TLS rebuild).
  - The A1 schema and stateless pack.
  - The G1 design.
- **Phase 2, Envoy 1.42 (about April 2027): govern.**
  - A1 complete, M3, the rest of R1, and S1 v1.
  - G1, G2 and G3.
  - O1 spans.
- **Phase 3, Envoy 1.43 (about July 2027): breadth.**
  - The P1 items, led by A2, A5, G4 and R2.

Dependencies:
- M1 feeds M3, which feeds the budgets in M4.
- M2 supplies R1's candidates and M3's prices.
- A1's state rules need R2.
- S1 and G3 share the callout.
- O3 makes S1, R4 and S3 cheaper.

## 8. Where Envoy should lead, not follow

- **Resilience.**
  - Envoy has retry budgets, hedging, active health checks, outlier detection, priority and
    locality failover, circuit breakers and the overload manager.
  - agentgateway has passive health only and fixed-backoff retries.
  - LiteLLM reimplements these in Python on top of Redis.
- **Native AI with no sidecar hop.** Agent Router pays two ext_proc round trips per request and
  ships the whole body over gRPC. Native filters remove both; O2 should measure the difference.
- **Extensibility.**
  - Envoy offers Wasm, Lua, dynamic modules, ext_proc and CEL.
  - agentgateway has no in-process plugins.
  - LiteLLM's hooks run inside the serving Python process.
- **Protocols and identity.**
  - HTTP/3, gRPC, SPIFFE and mTLS.
  - The xDS ecosystem: Istio, Envoy Gateway, Agent Router and the clouds.
  - WIMSE treats agents as SPIFFE workloads, which Envoy already speaks.
- **The inference substrate.**
  - The endpoint picker protocol and llm-d's router are built on Envoy ext_proc.
  - vLLM Semantic Router is an Envoy ext_proc.
  - Outside the Envoy and NGINX Kubernetes family, no gateway does KV-cache-aware or
    inference-pool routing.
  - Self-hosted inference routing already runs on Envoy.
- **One data plane for the Envoy family.** Agent Router, Envoy Gateway, Higress and Google Cloud's
  Agent Gateway all sit on Envoy. Native filters that cover their hot path (Appendix C) remove a
  sidecar hop for each of them at once.
- **Security process.** Keep the data plane free of control-plane code. LiteLLM's 2026 advisories
  cluster where management features share the serving process.
- **Correct budgets.** Reserve-and-settle against RLS gives cross-replica accuracy that neither
  peer has (M4).

## 9. Reasoning notes

These are the calls that were not obvious.

- **No key database or spend ledger in Envoy.** LiteLLM's virtual keys and budgets sit on Postgres.
  Envoy's equivalent has three parts:
  - identity from `api_key_auth` or `jwt_authn`;
  - limits and budgets in RLS or RLQS, counting tokens or cost units;
  - key objects in the control plane.

  What Envoy must add is the per-request arithmetic (estimate, settle, price), not storage.
- **Responses before Bedrock.** Claude on Bedrock is one binding away: the Messages schema with a
  different path and SigV4. Responses, by contrast, is what agent frameworks emit and the base of
  Open Responses.
- **Guardrails as an AI filter rather than "use ext_proc".** ext_proc works, but every vendor would
  have to parse four dialects and SSE. Sending the IR gives vendors one contract, and lets Envoy
  apply redactions consistently. This is the case #44681 makes for an AI-native callout.
- **MCP authorization is P0.** An MCP gateway without the resource-server profile cannot front a
  spec-compliant client, and token passthrough is the most common MCP gateway vulnerability.
  agentgateway leads with this. Envoy has half of it already: JWT validation, RBAC on tool
  metadata, and a no-passthrough default.
- **Semantic caching is P2.** It puts an embedding call and a vector store on the request path, and
  its hit rates depend on the workload. agentgateway does without one. Prompt-cache affinity (R3)
  is cheaper, and pays off on every provider that discounts cached tokens.
- **One IR, not pairwise converters.** agentgateway maintains about 600 KB of pairwise converters.
  Envoy's IR costs one pack per API. The risk is that Responses is richer than Chat Completions
  (reasoning items, hosted tools, `phase`), so the `_envoy` member could end up carrying most of a
  Responses payload. The Gemini Interactions design settled on Chat Completions plus `_envoy`
  (2026-10-19). Revisit only if A1 shows the stash dominating.
- **A byte-based estimate is enough for now.** agentgateway runs an o200k tokenizer and multiplies
  by 1.3 for Claude. Settling at stream done corrects any estimate, so a tokenizer only matters for
  hard caps on long prompts.
- **One manager or many.** The #44681 discussion asked whether MCP and A2A belong in the AI Protocol
  Manager. This roadmap keeps the MCP and A2A filters where they are, and shares what is common:
  JSON-RPC parsing, identity binding, the policy callout and telemetry.
- **No gateway-run agent loops.** LiteLLM can run tool loops itself (web search interception, MCP
  `require_approval: never`). That makes the gateway an agent runtime holding user credentials.
  Envoy should govern such calls (S3) rather than execute them.

## 10. Non-goals

- A key database, spend ledger, admin UI or price catalog. Envoy defines the schemas; control
  planes ship the data.
- SDKs, agent runtimes, gateway-run tool loops, stdio MCP servers, and an MCP registry service.
- A bespoke adapter per provider. OpenAI-compatible providers need no adapter, bindings cover path
  and body differences, and a pack is warranted only for an API with its own schema.

## 11. Risks and open questions

1. **The IR choice:** Chat Completions plus `_envoy`, or Open Responses items. See the reasoning
   notes.
2. **Where policy lives.** The rule of thumb: a generic filter when the concept already exists
   (rate limits, RBAC); an AI filter when the payload is needed (guardrails, transcoding).
3. **Spec churn.** MCP and the GenAI conventions move every quarter. Gate new behavior on a version
   setting, as `max_supported_protocol_version` does in the REST bridge.
4. **Review bandwidth.** This is roughly 40 PRs, and each area needs a sponsor under the extension
   policy.
5. **Duplication with Agent Router.** Agree which ext_proc features move into Envoy, and when.
6. **Streaming guardrail semantics.** Holding output costs latency; releasing it risks leaks.
7. **Metric cardinality** per model, key and tenant.
8. **Control-plane convergence at scale.** agentgateway's benchmarks target the route-propagation
   time of Envoy-based gateways. That is outside this roadmap, but it shapes how users perceive
   Envoy.

## Appendix A: work in flight

| Item | Upstream | Design notes (author's fork, botengyao/envoy) |
|---|---|---|
| A1 | - | `_envoy` IR stash in `gemini-interactions` |
| A4 | - | `gemini-interactions`, `gemini-interactions-schema`, `apm-response-passthrough` |
| M1 | #48707 (configurable request_info extraction) | `token-usage-ai-filter` |
| M2 | #48492 (`model_router`, `route_selector`), #48082 (merged) | `ai-budget-routing` (`model_table`) |
| M4 | #48530 (local `apply_on_stream_done`), #47805 (`host_allowlist`, merged) | `ai-budget-routing` |
| R1 | #48717 (`RetryPolicyFactory`), #48455 (binding writes request headers) | `ai-model-fallback`, `retry-header-restore`, `retry-buffer-ai-design`, `router-retry-held-trailers`, `model-failover-retry` (local) |
| R4 | #48088 (draft, route cluster refresh) | `ai-heuristic-routing` (local) |
| G1 | #48720 (protocol version metadata) | - |
| O1 | #48038, #48249, #48250 (MCP span reparenting) | `otel-genai-metrics`, `otel-genai-tracing` (local) |
| O2 | #48708 (streaming JSON parser hardening) | - |
| Umbrella | #44681 (native AI), #43268 (A2A), #39174 (MCP), #41812 (upstream filters to GA) | - |

## Appendix B: sources

All were read on 2026-10-27 unless dated otherwise.

**Envoy**
- `source/extensions/extensions_metadata.yaml` and the AI Protocol Manager, MCP and A2A docs and
  protos at `585dcff330`.
- Issue #44681 (umbrella proposal and milestone plan, 2026-06-29).

**LiteLLM**
- github.com/BerriAI/litellm at `c7c895db45`; docs.litellm.ai release notes v1.80.15–v1.107.0rc1.
- The security incident postmortems (2026-03-24 and 2026-10-21) and the GitHub security advisories
  page.

**agentgateway**
- github.com/agentgateway/agentgateway at `3ef1040786`; the release notes v0.11–v1.7.0.
- agentgateway.dev docs and benchmark posts (2026-06-26, 2026-08-13, 2026-08-20).
- docs.solo.io (enterprise edition comparison).

**Specifications and standards**
- Open Responses: openresponses.org specification, changelog and compliance pages; AAIF and Linux
  Foundation announcement (2026-10-22).
- AAIF: aaif.io, including the Agent Router (2026-09-09) and agentgateway (2026-06-04) posts.
- MCP: modelcontextprotocol.io 2026-07-28 changelog, transports, authorization, MRTR, tasks and
  security best practices; the roadmap (2026-08-22).
- A2A: a2a-protocol.org "What's new in v1" and the specification.
- IETF: OAuth WG documents (ID-JAG, Transaction Tokens, CIMD); WIMSE (`draft-ietf-wimse-aims-00`).
- OpenTelemetry: semantic-conventions releases v1.38–v1.42, and `semantic-conventions-genai`.
- OWASP: GenAI Security Project (LLM Top 10 2025 and 2026, Agentic Top 10, MCP Top 10).
- Gateway API Inference Extension releases v1.4–v1.6.2; llm-d router README.
- x402 v2 spec, AP2, ACP and UCP sites.

**Providers**
- developers.openai.com changelog and guides (WebSocket mode, conversation state, background,
  prompt caching).
- platform.claude.com API release notes and the compaction guide.
- ai.google.dev Interactions and changelog.
- AWS Bedrock Responses API and AgentCore Gateway docs.
- Azure API Management GenAI gateway capabilities.

**Other gateways**
- Agent Router: github.com/theagentrouter/agent-router at `3b8f8393`; the v1.2.0 release notes;
  issues #90 and PR #1564 (dynamic-module port).
- Higress at `36f2f1ac` (v2.2.5).
- Release notes and docs for Kong AI Gateway, Portkey, Cloudflare AI Gateway, Traefik Hub, Vercel
  AI Gateway, Bifrost, TrueFoundry, IBM ContextForge, and Microsoft's and Docker's MCP gateways.

## Appendix C: Agent Router's ext_proc duties and their native homes

Agent Router's Go sidecar does this work per request today. The roadmap item that gives it a
native home is in the last column.

| Duty in the sidecar | Native home | Envoy piece | Item |
|---|---|---|---|
| Parse the body, extract the model, clear the route cache | AI Protocol Manager | `request_info` publishes `envoy.ai.model.request` | shipped |
| Translate the request on every attempt; rewrite the path and model; apply header and body edits | Upstream AI Protocol Manager | `transcoder`, bindings, `header_mutation` | A1, A6, R1 |
| Upstream auth: API keys, Entra and GCP tokens, SigV4 over the translated body | Native injection and signing; the control plane mints tokens | `credential_injector`, `aws_request_signing` after the transcoder | A2, O5 |
| Translate responses: SSE and event-stream framing, error shapes | Upstream AI Protocol Manager | transcoder response legs, `decompressor` | A6, M1 |
| Extract token usage | AI Protocol Manager | `envoy.ai.token_usage` | shipped; M1 |
| Compute cost and charge rate limits | Native evaluation; the control plane owns prices and formulas | CEL, `hits_addend`, `apply_on_stream_done` | M3, M4 |
| GenAI metrics and tracing | Native stats and tracer | - | O1 |
| Link router and upstream state through an in-memory map | Goes away | filter state | - |
| MCP sessions, fan-out, merging, authorization, version negotiation | `mcp`, `mcp_router` | - | G1, G2, G3 |
| Serve `/v1/models` | Catalog, or a generated direct response | - | M2 |

These stay in the control plane:
- CRDs and xDS generation;
- credential lifecycle (OIDC, STS, workload identity);
- quota configuration;
- catalog and price data;
- InferencePool wiring;
- discovery of OAuth authorization-server metadata.
