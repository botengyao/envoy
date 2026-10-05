# Budget-based routing for AI traffic

Status: proposal, no code. Written against upstream/main `9c3d9aff1a` (2026-10-05). Extension and
field names are proposals; everything not marked as new exists today.

## Summary

Teams that run Envoy as an LLM gateway want what LiteLLM's proxy gives them: a dollar budget on a
key, a team, a user or a provider; requests stopped or rerouted when it runs out; and spend in a
database they can query. The AI Protocol Manager (APM) already has most of the inputs: the
requested model, `max_tokens`, an input-token estimate, and the token usage the provider reports.
Nothing turns tokens into money, keeps spend across Envoy instances, or lets a budget choose the
upstream.

This proposal adds:

- **`envoy.http.ai_filters.cost`** (new AI filter): prices each response from its token usage and a
  configured price list, and publishes the cost as the `envoy.ai.cost` filter state object.
- **`envoy.http.ai_filters.budget`** (new AI filter): before the request is routed, reads the
  budgets that apply from a budget service. When a budget is spent it rejects with a 429 in the
  client's API dialect. Otherwise it orders the upstream targets that still have budget and hands
  them to the existing `priority_group` cluster specifier. After the response it records the spend.
- **`envoy.service.budget.v3.BudgetService`** (new API): two unary RPCs, `GetBudgets` and
  `RecordSpend`. The service owns the database: limits, windows, spend and a per-request ledger.
  Envoy owns pricing and routing.
- **Three small APM core changes**, each useful beyond budgets: an AI filter hook at stream
  completion that carries the final token usage, a route cluster refresh after the AI filters, and
  local replies with headers and an error body in the client's dialect.

The MVP enforces soft caps: a request is admitted while spend is under the limit, and charged when
it completes. It makes one RPC before and one after each request. Caching, reservations and
batching come later.

## 1. The user's view

### 1.1 Who uses it

| Persona | Wants | Touches |
|---|---|---|
| Platform operator | LLM access for many teams with spend caps; cheaper paths when money runs short; predictable behavior when something fails | Envoy config (xDS) |
| Budget owner (team lead, finance) | Limits set and changed without an Envoy rollout; spend by team, key and model | The budget service's API and database |
| App developer | Errors their SDK understands; no retry storms; optionally, which target served them | The HTTP API only |

### 1.2 Journeys

| | Journey | LiteLLM equivalent |
|---|---|---|
| J1 | Every request's cost reaches access logs, metrics and a spend ledger | cost tracking, `x-litellm-response-cost`, `LiteLLM_SpendLogs` |
| J2 | A key, team, user or global budget per window; past it, a 429 | `max_budget` and `budget_duration` on keys, teams, users and end users |
| J3 | One model from several providers, each with its own budget. Exhausted providers are skipped; a 429 only when none is left | `provider_budget_config`; "No deployments available - crossed budget" |
| J4 | A team past 80% of its monthly budget is served by a cheaper model until it reaches 100% | none; LiteLLM's `soft_budget` only alerts |
| J5 | Which target served a request; spend per team and model in Prometheus; the ledger in SQL | `/spend/logs`, `/key/info`, Prometheus metrics |

### 1.3 What runs

LiteLLM's quick start is the proxy plus Postgres, and LiteLLM does not enforce budgets without the
database. Here the equivalent is Envoy, a budget service, and Postgres:

```
             ┌──────────────────────────── Envoy ─────────────────────────────┐
  client ───►│ ext_authz ──► ai_protocol_manager ──► router (priority_group)  │───► OpenAI, Azure, ...
             └─────┬────────────────────┬─────────────────────────────────────┘
         key check │         GetBudgets │ before routing
                   │        RecordSpend │ after the response
                   ▼                    ▼
             ┌─────────────────── budget service ───────────────────┐
             │ keys, budgets (limit, window), spend, ledger          │───► Postgres
             └───────────────────────────────────────────────────────┘
```

The key check can go to the same service, which then plays the part of LiteLLM's virtual keys, or
to any identity provider: JWTs and `api_key_auth` work too.

### 1.4 What the operator writes

Envoy, with the new pieces marked:

```yaml
http_filters:
- name: envoy.filters.http.ext_authz              # virtual key -> {key_id, team_id} metadata
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    grpc_service: {envoy_grpc: {cluster_name: budget_service}, timeout: 0.1s}
- name: envoy.filters.http.ai_protocol_manager
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
    request_handling:
      refresh_route_cluster: true                   # new (PR 3)
    response_handling:
      token_usage: {}
    filters:
    - name: envoy.http.ai_filters.request_info
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.http.ai_filters.request_info.v3.RequestInfo
    - name: envoy.http.ai_filters.budget            # new (PRs 5 and 6)
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.http.ai_filters.budget.v3.Budget
        budget_service: {envoy_grpc: {cluster_name: budget_service}, timeout: 0.05s}
        budgets:                                    # checked and charged on every request
        - name: key-monthly
          subject: "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:key_id)%"
        - name: team-monthly
          subject: "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:team_id)%"
        routing:
        - models: [{exact: gpt-4o}]
          targets:                                  # the first target with budget left wins
          - name: gpt-4o-openai
            cluster: openai
            budgets:
            - {name: provider-daily, subject: openai}
            - name: team-monthly                    # J4: only while the team is under 80%
              subject: "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:team_id)%"
              spend_threshold: {value: 80}
          - name: gpt-4o-azure
            cluster: azure_openai
            budgets:
            - {name: provider-daily, subject: azure}
            - name: team-monthly
              subject: "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:team_id)%"
              spend_threshold: {value: 80}
          - name: gpt-4o-mini
            cluster: openai
            model: gpt-4o-mini                      # rewrites the request's model
    - name: envoy.http.ai_filters.cost              # new (PR 2)
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.http.ai_filters.cost.v3.Cost
        prices:
        - {models: [gpt-4o], input_per_million: 2.50, cached_input_per_million: 1.25, output_per_million: 10.00}
        - {models: [gpt-4o-mini], input_per_million: 0.15, cached_input_per_million: 0.075, output_per_million: 0.60}
        ensure_stream_usage: true
- name: envoy.filters.http.router
```

The route declares the AI endpoint and lets the existing `priority_group` cluster specifier read
the budget filter's choice:

```yaml
- match: {prefix: /v1/chat/completions}
  request_headers_to_remove: [accept-encoding]      # APM reads usage only from uncompressed bodies
  route:
    inline_cluster_specifier_plugin:
      extension:
        name: envoy.router.cluster_specifier_plugin.priority_group
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.router.cluster_specifiers.priority_group.v3.PriorityGroupClusterSpecifier
          priority_groups:
          - {name: default, clusters: [{cluster_name: openai, weight: 1}]}
          override_metadata_namespace: envoy.ai.budget
    retry_policy: {retry_on: "5xx,reset", num_retries: 2, refresh_cluster_on_retry: true}
  typed_per_filter_config:
    envoy.filters.http.ai_protocol_manager:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
      request: {llm_protocol: OPENAI_CHAT_COMPLETIONS}
```

A retry to another cluster keeps the request's path and headers, so a target on a provider with a
different URL or credential, such as Azure OpenAI, needs upstream HTTP filters on its cluster that
set them (`credential_injector`, `header_mutation`).

The budget owner sets limits in the service. With the reference service of section 8:

```
PUT /budgets/team-monthly/search      {"limit": 500, "window": "month"}
PUT /budgets/key-monthly/*            {"limit": 20,  "window": "month"}    # default for every key
PUT /budgets/provider-daily/openai    {"limit": 100, "window": "day"}
GET /budgets/team-monthly/search   -> {"limit": 500, "spent": 412.17, "resets_at": "2026-11-01T00:00:00Z"}
```

### 1.5 What the client sees

| Team `search` has spent | Result |
|---|---|
| under 80% | `gpt-4o` on OpenAI, or on Azure once OpenAI's daily budget is spent |
| 80% to 100% | `gpt-4o-mini`; the response's `model` field says so |
| 100% | rejected |

A rejection in the OpenAI dialect:

```
HTTP/1.1 429 Too Many Requests
content-type: application/json
retry-after: 2203200
x-should-retry: false

{"error": {"message": "Budget 'team-monthly' is spent until 2026-11-01T00:00:00Z.",
           "type": "insufficient_quota", "param": null, "code": "insufficient_quota"}}
```

`insufficient_quota` is what OpenAI itself returns for an exhausted billing quota, so clients that
handle that case handle this one. The OpenAI and Anthropic SDKs retry 429s by default and skip the
retry when the response carries `x-should-retry: false`, so a rejected call is not retried against
a budget that will not clear for days. Anthropic and Gemini clients get their own error shapes
(6.5).

An operator who wants clients to see the target chosen for the initial attempt adds a route
response header with the value `%FILTER_STATE(envoy.ai.budget.target:PLAIN)%`.

## 2. LiteLLM to Envoy

| LiteLLM | Here |
|---|---|
| `model_list` deployment | a cluster, named by a budget target |
| model group (`model_name`) | the `models` of a `routing` entry |
| virtual key, `/key/generate` | ext_authz to a key service, which can be the budget service; `api_key_auth` for static keys; JWT |
| key, team, user, end-user, tag and global budgets | entries in `budgets`, each with a subject format string: `%DYNAMIC_METADATA(...)%`, `%FILTER_STATE(...)%`, `%REQ(...)%`, or a constant |
| `model_max_budget` | a subject that joins key and model: `%DYNAMIC_METADATA(...:key_id)%/%FILTER_STATE(envoy.ai.model.request:PLAIN)%` |
| `provider_budget_config` | budgets on targets, with a constant subject |
| `max_budget`, `budget_duration` | a limit and a window, stored by the budget service |
| model price map, `input_cost_per_token` | `cost.prices`, per million tokens |
| spend in Postgres, synced through Redis | the budget service; Envoy keeps no budget state in the MVP |
| budget reservation | after the MVP (section 10) |
| `fail_closed_budget_enforcement` | `failure_mode_deny: true`, which answers 503 when the service is unreachable |
| `x-litellm-response-cost` | `%FILTER_STATE(envoy.ai.cost:PLAIN)%` in access logs. A response header cannot carry it: the cost is known only after the last byte |
| spend metrics in Prometheus | the stats access logger, counting `envoy.ai.cost` with team and model tags |

## 3. What APM has today

- **The body is parsed before later filters see the request.** APM holds the headers, parses the
  body, runs the AI filters, and only then releases headers and body (`filter.cc`,
  `decodeHeaders()` and `finalizeDecode()`).
- **AI filters can await.** `AiFilter::decode()` is a coroutine (`ai_filter.h:103`), so a filter
  can wait on a gRPC call through a `Coroutine::LeafAwaitable`
  (`source/common/coroutine/leaf_awaitable.h`). Stream teardown cancels the wait. A filter can
  rewrite the body through `AiRequest::json()` and the headers through
  `AiFilterContext::request_headers`, and reject through `LocalReplier(code, details)`
  (`ai_filter.h:86`). No helper for gRPC calls exists yet, and the context carries no dispatcher.
- **Request attributes.** `request_info` publishes `envoy.data.ai.v3.RequestInfo` (model,
  `stream`, `max_output_tokens`, `estimated_input_tokens`, ...) as typed metadata under
  `envoy.ai.request_info`. Since #47916 it also stores the model as the `envoy.ai.model.request`
  string filter state object, which formatters, route matching and the `matcher` cluster specifier
  can read.
- **Token usage.** APM extracts it from OpenAI Chat Completions and Responses, Anthropic and Gemini
  responses, unary and SSE. It publishes once, at a clean end of stream, as typed metadata under
  `envoy.ai.token_usage` (`finalizeResponseHandling()`, `filter.cc:672`). Input counts include
  cached and cache-creation tokens; output includes reasoning. Nothing is published on a reset or a
  non-2xx response, and only the attempt the router selected is counted.
- **No cost, no budget.** Nothing prices tokens. The APM docs say costing needs provider identity
  and a price model, and that usage is provider-reported and unverified.
- **No re-routing after the AI filters.** Route and cluster are fixed before APM runs. A
  `refresh_route_cluster` knob exists only on the local branch `apm-refresh-route-cluster`
  (`0bcf76df63`).
- **Local replies are bare.** `LocalReplier` sends `details` as a plain-text body; a filter cannot
  add headers (`filter.cc:465-471`).
- **No completion hook.** AI filters live for their decode and encode coroutines. Nothing tells
  them the stream finished, and nothing hands them the final usage.

Pieces outside APM that this design reuses:

- **The `priority_group` cluster specifier.** With `override_metadata_namespace`, a filter supplies
  a per-request ordered list of groups as a typed `PriorityGroupsOverride`. The initial attempt
  takes the first group and each retry the next, given `refresh_cluster_on_retry`. Every
  `refreshRouteCluster()` re-selects.
- **The connection manager's order.** Every filter's `onStreamComplete()` runs first, then the
  access log (deferred until later on HTTP/3), then every filter's `onDestroy()`
  (`conn_manager_impl.cc:454-470`). A cost published in `onStreamComplete()` is visible to access
  loggers and to the global rate limit filter's `apply_on_stream_done`, which runs from
  `onDestroy()`.
- **Formatters.** `%FILTER_STATE(key:PLAIN)%` and `%FILTER_STATE(key:FIELD:name)%` work in access
  logs, the stats access logger, `set_filter_state` and `hits_addend.format`.

## 4. Gaps

| Need | Today |
|---|---|
| Tokens priced in money | missing |
| Spend shared across Envoy instances, per subject and window, with limits from a database | missing; RLS counts, but see 5.2 |
| A budget check after the body is parsed and before the model is rewritten | an AI filter could do it; none exists |
| A budget decision that changes the upstream | the `priority_group` override exists; nothing refreshes the cluster after the AI filters |
| The final usage handed to an AI filter | missing |
| A rejection with `retry-after`, `x-should-retry` and an error body in the client's dialect | missing |

## 5. Options

### 5.1 No new Envoy code

ext_authz placed after APM decides; gRPC access logs carry the spend.

- ext_authz receives `envoy.ai.request_info` through `typed_metadata_context_namespaces` and
  answers OK, or 429 with an OpenAI-style body the service writes itself.
- For J3 the service returns a `priority_groups` list as dynamic metadata, which `priority_group`
  reads from the untyped `envoy.filters.http.ext_authz` namespace. ext_authz clears the route cache
  only when it also changes a header, so the service has to set a dummy header.
- The service prices `envoy.ai.token_usage` from the access log stream. gRPC access logs include
  typed metadata only when the stream also has an untyped namespace
  (`grpc_access_log_utils.cc:318`), and APM publishes typed metadata only.

This is enough to prototype J2 and J3 today. It cannot do J4, because the body is serialized before
ext_authz runs. Every operator's service has to reimplement pricing and the dialect error shapes,
and it depends on two workarounds.

### 5.2 The rate limit service as the spend counter

Once the cost filter exists, a descriptor in the global rate limit filter's own `rate_limits` (route
level `rate_limits` ignore `hits_addend`) can charge money at stream end:

```yaml
rate_limits:
- actions:
  - metadata:
      descriptor_key: team
      metadata_key: {key: envoy.filters.http.ext_authz, path: [{key: team_id}]}
  hits_addend: {format: "%FILTER_STATE(envoy.ai.cost:PLAIN)%"}
  apply_on_stream_done: true
```

Token quotas are built this way today; Envoy AI Gateway uses the same mechanism. For money it falls
short:

- `requests_per_unit`, `limit_remaining` and the request-level `hits_addend` are `uint32`. Counted
  in micro-units, a limit tops out near 4,295 currency units per window.
- There is no defined read-only check. A request-level `hits_addend` of 0 counts as 1, and what a
  descriptor-level 0 means is up to the service.
- Limits live in the rate limit service's config, not in rows a budget owner edits. The
  per-request `limit` override is `uint32` too.
- It cannot steer routing. The rate limit filter runs after the AI filters and never clears the
  route cache, and `limit_remaining` only reaches response headers.

Rate limits stay the right tool for tokens or requests per minute.

### 5.3 Recommended: AI filters and a budget service

- The decision runs inside the AI filter chain, after parsing and before the body is serialized,
  so it can rewrite the model (J4).
- Amounts are integer micro-units end to end, as `uint64`.
- `GetBudgets` reads without charging, and `RecordSpend` charges once per request id. The ledger is
  idempotent, and reservations can be added later without a new API.
- The routing output is the existing `priority_group` override, so retries fall back across
  targets with no router change.
- Rejections speak the client's dialect.
- The cost filter alone improves 5.1 and 5.2: both can read `envoy.ai.cost` instead of pricing
  usage themselves.

## 6. Design

### 6.1 Terms

- **Price**: currency units per million tokens, per model, for input, cached input, cache writes
  and output. One unit per million tokens is one micro-unit per token, so a cost in micro-units is
  `tokens × price`.
- **Cost**: the integer micro-units (1e-6 of the operator's currency) that one request spent.
- **Budget**: a named limit, such as `team-monthly`. The service keeps a state per subject: the
  limit, the amount spent, and when the window ends.
- **Subject**: whom a budget is for on this request, produced by a substitution format string.
- **Target**: an upstream choice: a cluster, an optional model rewrite, and the budgets it draws
  on.
- **Eligible**: a target whose every budget has spent less than `spend_threshold` (default 100%) of
  its limit. A budget without a limit never blocks.

### 6.2 Request path

AI filter order: `request_info`, `budget`, `cost`, then `transcoder` if present. The budget filter
reads the model filter state that `request_info` sets; the cost filter runs after the budget filter
so it prices the model that was chosen.

1. An auth filter has already put the caller's identity in metadata or filter state.
2. `budget` formats each subject. If any substitution in a subject has no value, that budget does
   not apply and `subject_missing` counts it, just as a rate limit descriptor with a missing value
   is dropped. Checking each substitution matters: a missing value otherwise renders as `-`, and a
   composite subject such as `key/model` is never empty, so callers without a key would share one
   subject.
3. It picks the first `routing` entry whose `models` match `envoy.ai.model.request`. With no match
   there is no routing, only the budgets.
4. It collects the distinct (budget, subject) keys of `budgets` and of the entry's targets, sends
   one `GetBudgets`, and awaits it with the configured timeout. No keys, no call.
5. If any entry of `budgets` is spent, it rejects with 429.
6. It walks the targets in order and keeps the eligible ones. If none is eligible, it rejects with
   429.
7. It keeps the eligible targets that send the same model as the first one, and writes them as a
   `PriorityGroupsOverride` under `override_metadata_namespace`: one group per target, named after
   the target and holding its cluster at weight 1 (a group with weight 0 is ignored and the route's
   configured groups are used instead). A retry cannot change the body, so a target with a
   different model is no fallback (6.9).
8. It sets `envoy.ai.budget.target` to the first target's name. If that target names a `model`, it
   rewrites the request's model.
9. `cost` looks up the price of the model the request now carries and keeps it for completion.
10. After the last AI filter, APM calls `refreshRouteCluster()`, then serializes and replays the
    body. `priority_group` sends the initial attempt to the first target's cluster, and retries
    move down the list.

### 6.3 Completion

APM's own `onStreamComplete()` calls the new `AiFilter::onStreamComplete()` of each AI filter in
reverse chain order, before the access log runs, passing the final `TokenUsage` if one was
published.

1. `cost` computes the cost (6.4) and sets `envoy.ai.cost`.
2. `budget` finds the served target: the first target of the override whose cluster is the
   upstream cluster that answered. It sends `RecordSpend` with an id it generated for the request,
   the distinct keys of `budgets` and of the served target, the cost, the priced model, the served
   target, and the configured metadata namespaces. The call is fire-and-forget.

What gets charged:

- Only a response that came from an upstream with a 2xx status (response code details
  `via_upstream`). A local reply, including the budget filter's own 429 or a rejection by another
  AI filter, and an upstream error are never charged. The hook still runs for those streams,
  because the AI filters outlive a cancelled chain.
- Each (budget, subject) once, even when it appears both in `budgets` and on the target, as
  `team-monthly` does in 1.4.
- Under an id the budget filter generates. `x-request-id` is not used: Envoy keeps a client's value
  unless the request is an edge request, so a client could replay one id and have every later
  request deduplicated away.
- Nothing when there is no cost record or the cost is zero.

### 6.4 Pricing

```
uncached = max(0, input - cached - cache_creation)   # TokenUsage counts both inside input
cost     = ceil(uncached       * input_price
              + cached         * cached_input_price    # defaults to input_price
              + cache_creation * cache_write_price     # defaults to input_price
              + output         * output_price)         # output includes reasoning
```

- **Which model is priced.** First the model in the request body after the AI filters ran, then the
  model the response reports, then `default_price`. An unpriced request costs 0 and `unpriced`
  counts it. An operator who enforces budgets should set `default_price`; otherwise an unpriced
  model is free.
- **Missing usage.** A 2xx response can end without usable counts: the client cut the stream, the
  provider sent none, the body was compressed (APM reads only identity-encoded bodies and counts
  `unsupported_content_encoding`; the route in 1.4 strips `accept-encoding` for this reason), or
  extraction failed and APM published a `FAILED` record without counts. All are handled alike: the
  cost is the input estimate, `estimated_input_tokens × input_price`, when `request_info` has
  `token_estimation` set, and 0 otherwise. The record's `source` says `ESTIMATED` or `NONE`.
- **Untrusted counts.** Counts come from the upstream and are not checked for consistency, hence
  the saturating subtraction. `max_cost_per_request`, when set, caps one request's cost, so one
  inflated usage report cannot empty a budget.
- **OpenAI streams.** An OpenAI Chat Completions stream reports usage only if the request sets
  `stream_options.include_usage`; without it a streamed request is charged only its input
  estimate. With `ensure_stream_usage`, the cost filter sets it on OpenAI Chat streaming requests,
  as the transcoder already does for streams it sends to an OpenAI-shaped backend
  (`transcoding_engine.cc:766-769`). The client then receives one extra chunk with an empty
  `choices`. Anthropic, Gemini and OpenAI Responses streams always carry usage.
- **Rounding.** `ceil` never undercounts; it overcounts by less than one micro-unit per request.
- **The record.** `envoy.ai.cost` is a read-only filter state object with life span `FilterChain`.
  It serializes as the micro-unit count, so `%FILTER_STATE(envoy.ai.cost:PLAIN)%` prints e.g.
  `1234`. The fields `micros`, `model` and `source` are readable with `:FIELD:`, and gRPC access
  logs receive it as an `envoy.data.ai.v3.Cost` message through `filter_state_objects_to_log`.

### 6.5 Rejection

The reply is a 429 with `retry-after` (seconds until the earliest window end that would admit the
request), `x-should-retry: false`, response code details `ai_budget_exhausted`, and the error body
of the client's API:

| Client API | Body |
|---|---|
| OpenAI Chat Completions, Responses | `{"error": {"message": M, "type": "insufficient_quota", "param": null, "code": "insufficient_quota"}}` |
| Anthropic Messages | `{"type": "error", "error": {"type": "rate_limit_error", "message": M}}` |
| Gemini | `{"error": {"code": 429, "message": M, "status": "RESOURCE_EXHAUSTED"}}` |
| unknown | `M` as plain text |

`M` names the budget and when its window ends, never the limit, the spend or the subject. The
connection manager's `local_reply_config` still applies on top.

### 6.6 Failures

| Event | Behavior | Counter |
|---|---|---|
| `GetBudgets` fails or times out | `failure_mode_deny: false` (default): admit, with every target in configured order. `true`: 503 | `service_error`, `failure_mode_allowed` |
| A key with no limit in the service | does not limit | none |
| A substitution in a subject has no value | that budget does not apply | `subject_missing` |
| The model matches no `routing` entry | budgets only; the route is untouched | none |
| The served cluster matches no target | only `budgets` are charged | `target_unmatched` |
| A local reply or an upstream error | not charged | none |
| A 2xx response without usable counts | the input estimate is charged (6.4) | `cost.estimated` |
| No `envoy.ai.cost` at completion | nothing is recorded | `cost_missing` |
| `RecordSpend` fails | dropped; the ledger undercounts | `spend_record_error` |

Failing open matches the rate limit filter's default. A budget is a financial guardrail, not an
access control, and an outage of the budget service should not take the gateway down with it.
Operators who need a hard stop set `failure_mode_deny`, the counterpart of LiteLLM's
`fail_closed_budget_enforcement`.

### 6.7 How firm a budget is

Admission reads spend when the request starts; the cost is added when the response ends. A budget
can therefore be overspent by the cost of requests that were admitted before it ran out and were
still running, roughly concurrency × cost per request. Twenty concurrent agents at $0.50 per call
can overshoot by about $10. LiteLLM without reservations behaves the same way. Reservations
(section 10) close most of the gap: admission reserves the request's maximum cost, and completion
releases it.

### 6.8 Trust

- Subjects must come from something the client cannot forge: ext_authz metadata, JWT claims,
  `api_key_auth`'s forwarded client header (it overwrites whatever the client sent), or filter
  state set by a trusted filter. A client-supplied header as subject lets a caller spend someone
  else's budget or dodge their own.
- Token counts are provider-reported. A budget against an untrusted upstream can be gamed by that
  upstream; `max_cost_per_request` bounds the damage per request.
- Nothing the client sends decides what gets charged: the spend id is generated by Envoy (6.3).
- The budget service is a write path for money. Use mTLS between Envoy and the service, and
  authenticate its admin endpoints.

### 6.9 Interactions

- **Transcoder.** Budget and cost run before it, on the client's dialect; the transcoder carries
  the model through. Usage is extracted from the provider's response before any response
  transcoding, so the cost reflects what the provider reported.
- **Body rewrites.** The model rewrite and `ensure_stream_usage` edit the parsed body, so they need
  `reserialize_body` at its default, `ALWAYS`. The MVP rewrites the model only for APIs that carry
  it in the body (OpenAI, Anthropic); Gemini names it in the path, which a target cannot rewrite
  yet.
- **Retries and model fallback.** In the MVP the body is rewritten once, for the first target, so
  fallback by retry is limited to targets that send the same model (6.2, step 7). Rewriting per
  attempt belongs to the upstream APM and the model fallback work, which can take the same ordered
  target list as input.
- **Attempts.** The downstream APM only sees the attempt the router selected. A failed or hedged
  attempt that the provider still billed is not charged. Per-attempt accounting belongs in the
  upstream APM, but upstream filters never get `onStreamComplete()`: an upstream request only calls
  `destroyFilters()` (`upstream_request.cc:199`). There APM would have to run the hook from
  `onDestroy()`.
- **Rate limits.** Complementary: rate limits for tokens or requests per minute, budgets for money
  per day or month.

### 6.10 Observability

- Counters under the APM stat prefix:
  - `cost.{priced, unpriced, estimated, usage_missing}`
  - `budget.{allowed, rerouted, rejected, service_error, failure_mode_allowed, subject_missing,
    target_unmatched, cost_missing, spend_recorded, spend_record_error}`
- Access log fields: `%FILTER_STATE(envoy.ai.cost:PLAIN)%`, the priced (served) model
  `%FILTER_STATE(envoy.ai.cost:FIELD:model)%`, the requested model
  `%FILTER_STATE(envoy.ai.model.request:PLAIN)%`, the target chosen for the initial attempt
  `%FILTER_STATE(envoy.ai.budget.target:PLAIN)%`, and the cluster that served `%UPSTREAM_CLUSTER%`.
- Spend metrics with no new code: a stats access logger counter with
  `value_format: "%FILTER_STATE(envoy.ai.cost:PLAIN)%"`, tagged by team and by the priced model.
  Tagging by the requested model would count a downgraded request against the model it asked for.

## 7. API sketches

### 7.1 Cost filter

```proto
package envoy.extensions.http.ai_filters.cost.v3;

// [#extension: envoy.http.ai_filters.cost]
message Cost {
  // Currency units per million tokens.
  message Price {
    // Exact model names, matched against the model the request is sent with, then the model the
    // response reports.
    repeated string models = 1;
    double input_per_million = 2 [(validate.rules).double = {gte: 0}];
    double output_per_million = 3 [(validate.rules).double = {gte: 0}];
    // Default to input_per_million.
    google.protobuf.DoubleValue cached_input_per_million = 4;
    google.protobuf.DoubleValue cache_write_per_million = 5;
  }

  repeated Price prices = 1;

  // For models no entry names. Unset leaves them unpriced, at cost 0.
  Price default_price = 2;

  // Sets stream_options.include_usage on OpenAI Chat Completions streaming requests.
  bool ensure_stream_usage = 3;

  // Caps one request's cost, in currency units. Unset: no cap.
  google.protobuf.DoubleValue max_cost_per_request = 4;
}
```

### 7.2 Budget filter

```proto
package envoy.extensions.http.ai_filters.budget.v3;

// [#extension: envoy.http.ai_filters.budget]
message Budget {
  message BudgetRef {
    // The budget's name in the budget service.
    string name = 1 [(validate.rules).string = {min_len: 1}];
    // Substitution format string naming whom the budget is for, e.g.
    // "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:team_id)%". If any substitution has no
    // value, the budget does not apply to the request.
    string subject = 2 [(validate.rules).string = {min_len: 1}];
    // Admits while spend is below this share of the limit. Defaults to 100%.
    type.v3.Percent spend_threshold = 3;
  }

  message Target {
    string name = 1 [(validate.rules).string = {min_len: 1}];
    string cluster = 2 [(validate.rules).string = {min_len: 1}];
    // Replaces the request's model when this target serves the initial attempt.
    string model = 3;
    repeated BudgetRef budgets = 4;
  }

  message Routing {
    // Matched against envoy.ai.model.request. Empty matches every model.
    repeated type.matcher.v3.StringMatcher models = 1;
    repeated Target targets = 2 [(validate.rules).repeated = {min_items: 1}];
  }

  config.core.v3.GrpcService budget_service = 1 [(validate.rules).message = {required: true}];

  // When the budget service cannot be reached: admit (false) or reply 503 (true).
  bool failure_mode_deny = 2;

  // Checked and charged on every request.
  repeated BudgetRef budgets = 3;

  // The first entry whose models match is used.
  repeated Routing routing = 4;

  // Where the PriorityGroupsOverride is written. Defaults to "envoy.ai.budget".
  string override_metadata_namespace = 5;

  // Metadata namespaces sent with RecordSpend, e.g. envoy.ai.request_info, envoy.ai.token_usage.
  repeated string spend_metadata_namespaces = 6;
}
```

### 7.3 Budget service

```proto
package envoy.service.budget.v3;

// Reads and charges spend budgets. Amounts are micro-units of the operator's currency.
service BudgetService {
  // Returns the state of each budget without charging it. Called before a request is routed.
  rpc GetBudgets(GetBudgetsRequest) returns (GetBudgetsResponse);

  // Adds a finished request's cost to each budget. The service applies a request_id once.
  rpc RecordSpend(RecordSpendRequest) returns (RecordSpendResponse);
}

message BudgetKey {
  string budget = 1;
  string subject = 2;
}

message GetBudgetsRequest {
  repeated BudgetKey keys = 1;
}

message BudgetState {
  // Unset: no limit, so the budget never blocks.
  google.protobuf.UInt64Value limit_micros = 1;
  uint64 spent_micros = 2;
  // When spend resets. Unset for a budget without a window.
  google.protobuf.Timestamp resets_at = 3;
}

message GetBudgetsResponse {
  // One per requested key, in request order.
  repeated BudgetState states = 1;
}

message RecordSpendRequest {
  // Generated by Envoy for the request; the service applies each id once.
  string request_id = 1;
  // Distinct keys.
  repeated BudgetKey keys = 2;
  uint64 cost_micros = 3;
  string model = 4;
  string target = 5;
  config.core.v3.Metadata metadata = 6;
}

message RecordSpendResponse {
}
```

Nothing in the service is about tokens, so a non-AI route with another cost producer could use it
too. Windows (calendar day or month, rolling, none) are the service's business; Envoy only compares
spend with the limit.

### 7.4 APM core

- `AiFilter::onStreamComplete(const AiStreamCompletion&)`, a no-op by default. `AiStreamCompletion`
  carries the `StreamInfo` and a pointer to the published `TokenUsage`, null when there is none; a
  `FAILED` record is passed as published.
  `AiProtocolManagerFilter::onStreamComplete()` calls it in reverse chain order, only on streams
  whose AI filter chain ran. The MVP covers the downstream placement only (6.9, Attempts).
- `RequestHandling.refresh_route_cluster`, from `apm-refresh-route-cluster`: after the last AI
  filter and before the replay, call `refreshRouteCluster()`.
- `LocalReplier` takes extra response headers, response code details and an error type. When a type
  is given and the request's API is known, the body is that API's error JSON (6.5). Existing
  callers keep their plain-text body.

## 8. Reference budget service

It lives outside the Envoy repo, next to the other sandboxes in envoyproxy/examples: Envoy, the
service and Postgres in one `docker compose up`, like LiteLLM's quick start.

```sql
CREATE TABLE budget (
  name         TEXT   NOT NULL,
  subject      TEXT   NOT NULL,        -- '*' is the default for every subject
  limit_micros BIGINT NOT NULL,
  window_kind  TEXT   NOT NULL,        -- 'day', 'month' or 'total'
  PRIMARY KEY (name, subject));

CREATE TABLE budget_spend (
  name         TEXT        NOT NULL,
  subject      TEXT        NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  spent_micros BIGINT      NOT NULL DEFAULT 0,
  PRIMARY KEY (name, subject, window_start));

CREATE TABLE spend_log (
  request_id  TEXT        PRIMARY KEY,
  at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  cost_micros BIGINT      NOT NULL,
  model       TEXT,
  target      TEXT,
  keys        JSONB       NOT NULL,
  metadata    JSONB);
```

- `RecordSpend` is one transaction: insert into `spend_log` with `ON CONFLICT DO NOTHING`, and only
  when the row is new, add the cost once to each distinct key's `budget_spend` row for the current
  window.
- `GetBudgets` reads the `budget` row, falling back to `*`, and the current window's spend.
- Admin endpoints set limits and read spend (1.4). A `/keys` endpoint plus an ext_authz `Check`
  give LiteLLM-style virtual keys.
- Putting Redis in front of Postgres is the service's own scaling choice; Envoy does not see it.

## 9. MVP breakdown

Each PR is reviewable on its own; together they cover J1 to J5.

| # | PR | Scope | Unlocks |
|---|---|---|---|
| 1 | `ai_protocol_manager: add an AI filter stream-complete hook` | `AiFilter::onStreamComplete`, `AiStreamCompletion`, call order; tests for reset, non-2xx and missing usage | 2, 5 |
| 2 | `ai_filters: add a cost filter` | `cost.proto`, `envoy.data.ai.v3.Cost`, pricing, `envoy.ai.cost`, `ensure_stream_usage`, stats, docs | J1 |
| 3 | `ai_protocol_manager: refresh the route cluster after the AI filters` | the existing `apm-refresh-route-cluster` branch | 6 |
| 4 | `ai_protocol_manager: let AI filters reply with headers and a dialect error body` | `LocalReplier` change, the three error shapes, response code details | 5 |
| 5 | `ai_filters: add a budget filter` | `BudgetService` API; `budget.proto` without `routing`; `GetBudgets` awaited with a timeout; 429; failure modes; the charging rules of 6.3; `RecordSpend` from a per-worker reporter that outlives the stream; stats; integration test against a fake budget service | J2 |
| 6 | `ai_filters: route by budget` | `routing`, eligibility and thresholds, `PriorityGroupsOverride`, `envoy.ai.budget.target`, model rewrite, served-target attribution; integration test with `priority_group` and retries | J3, J4 |
| 7 | examples: AI budget sandbox | reference service, schema, compose file, walkthrough | J5, quick start |

PRs 1 and 2 give spend tracking on their own, plus money-denominated rate limits as in 5.2. PRs 3
and 4 can land in parallel with 2. PR 5 needs 1, 2 and 4; PR 6 needs 3 and 5.

Tests follow the repo's rules: unit tests with `StrictMock` and simulated time, integration tests
with a fake upstream for the budget service in the style of `ratelimit_integration_test.cc`, and
the sandbox against a real provider end to end.

## 10. After the MVP

- **A budget cache.** A process-wide cache of `BudgetState` with a TTL the service hints at, spend
  accumulated locally between refreshes, and coalesced lookups, so a busy subject stops costing one
  RPC per request.
- **Reservations.** `GetBudgets` reserves the request's maximum cost (input estimate × input price
  plus `max_output_tokens` × output price) under its request id, and `RecordSpend` releases it. The
  price is needed at admission, so the price list may have to move where both filters can read it
  (open question 2).
- **Batched, retried `RecordSpend`** with a bounded queue; the request id keeps retries safe.
- **Per-attempt accounting and rewriting** in the upstream APM, so failed and hedged attempts are
  charged and a fallback can change the model.
- **Remaining-budget response headers**, and the cost in trailers or a final SSE comment for
  clients that want it.
- **A mid-stream cutoff** for a stream that outruns its budget.
- **Pricing**: per-cluster prices from cluster metadata, long-context tiers, batch and service
  tiers, cache-duration variants, a price file from a `DataSource`, and removing the usage chunk
  that `ensure_stream_usage` added when the client did not ask for it.
- **An HTTP/JSON transport** for the budget service, in line with the AI-native callout in #44681.

## 11. Open questions

1. API home: `envoy.service.budget.v3`, which is generic, or `envoy.service.ai.budget.v3`?
2. The price list: in the cost filter, as proposed, or in the APM config, where the budget filter
   could also read it for reservations?
3. Targets name clusters, as proposed, which keeps one source of truth and exact attribution. Or
   they reference groups configured on the route, which keeps routing in route config but needs
   group membership for attribution.
4. Failure mode default: open, like the rate limit filter?
5. Rejection: 429 with OpenAI's `insufficient_quota`, as proposed, or 402?
6. Missing usage: charge the input estimate, as proposed, zero, or a reservation?
