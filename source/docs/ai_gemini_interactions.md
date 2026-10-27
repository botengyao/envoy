# Gemini Interactions in the AI Protocol Manager

Design, with phase 1 prototyped on this branch. Base: upstream/main `e320af5281` (2026-10-19).

## Summary

Envoy's AI filters should work on one request shape: the IR, or intermediate representation.
The transcoder converts the client's API into the IR. The AI filters work on the IR. Then the
transcoder converts the IR into the backend's API, and the response takes the same path back.

The first release needs none of that. It serves Gemini models, not agents, and lets the gateway
change the model name on a backend that speaks the client's API. A request that changes only its
model needs no conversion, so the AI Protocol Manager in front of the backend writes the model
into the body itself (see [Changing only the model](#changing-only-the-model)).

The design gets there in three phases (see [Phased plan](#phased-plan)):

1. **Change the model.** Gemini Interactions becomes an API Envoy knows, and the AI Protocol
   Manager writes the resolved model without a transcoder.
2. **One DFP route.** Behind a dynamic forward proxy (DFP), a single `*` route takes all traffic.
   The first AI Protocol Manager, before the router, recognizes AI calls and reads them. The
   second, in the cluster, follows it and sends the model.
3. **The IR.** Today the IR is OpenAI Chat Completions, and it cannot hold everything an
   Interactions request carries. The IR gains a reserved `_envoy` member, so Interactions converts
   into it and back without loss, for when an AI filter reads the IR or the backend speaks another
   API.

Schema validation checks what the client sent, before anything converts it.

Interactions keeps state per provider account, so a call that continues a chain must stay on the
account that holds it. Failover across accounts comes after the three phases (see [Stateful calls
and failover](#stateful-calls-and-failover)).

## Principles

1. **AI filters work on the IR.** The exceptions are the transcoders, which convert, and schema
   validation, which checks what the client sent before it is converted.
2. **The IR loses nothing on a same-API hop.** A request that goes from API A into the IR and back
   to A comes out as it came in, except for intended edits such as the model. A request going from
   A to another API B keeps what B can express, and is refused when B cannot serve it.
3. **Convert only when needed.** A request needs the IR when an AI filter reads it, or when the
   backend speaks another API. Otherwise it is not converted, and only its model changes.

## Changing only the model

A transcoder pair converts a request into the IR and back. For a request whose backend speaks the
client's API, and which only changes its model, that round trip returns the request it started
from with one field changed. So the pair does not run. The AI Protocol Manager in front of the
backend writes `envoy.ai.model.resolved` into the body's `model` itself, as it re-serializes the
body.

The model has to be picked before the router, which picks the backend from it, and written after,
on every attempt:

| Step | Where | What |
|---|---|---|
| Read | AI Protocol Manager 1, before the router | Schema validation and request info read the request as the client sent it. The body goes on as received (`reserialize_body: DISABLE`). |
| Pick | a selector, such as ext_proc with `set_filter_state` | Sets `envoy.ai.model.resolved`. |
| Write | AI Protocol Manager 2, in the cluster | Re-serializes the body with the resolved model (`reserialize_body: ALWAYS`, the default), and records the response's usage. |

The AI Protocol Manager writes the model when all of these hold:

- **It re-serializes the body.** With `DISABLE` the body goes on byte for byte, so the model cannot
  change.
- **The body names its model.** Interactions, Chat Completions, Responses and Messages do. Gemini's
  `generateContent` names it in the path, which only a transcoder's binding renders.
- **No AI filter in its chain applies a binding, that is, no transcoder.** A transcoder writes the
  model itself, in the body or in the path. A chain with only the `TO_IR` leg leaves the body in
  the IR, whose model the `FROM_IR` leg sets later.

Nothing changes the response's content, so the client sees the model that served it. With the
transcoder pair, the client sees the one it asked for (see [Open questions](#open-questions)).

## What differs between Chat Completions and Interactions

| | Chat Completions | Interactions |
|---|---|---|
| Model | `model` | `model`, or `agent` instead |
| Instructions | `system` and `developer` messages | `system_instruction` |
| Conversation | `messages`, each with a `role` | `input`: a string, a content item, or a list of typed steps, with no roles |
| Reasoning | no field to send it back | `thought` steps with a `signature`, which Gemini needs back when thinking and tools mix |
| Tool calls | `tool_calls` on an assistant message, with arguments as a JSON string | `function_call` steps, with arguments as an object |
| Tool results | `tool` messages | `function_result` steps, with `is_error` |
| Server-side tools | none | search, code execution, URL context, file search, maps and MCP, whose calls and results are steps |
| Media | image, audio and file parts | image, audio, video and document content, by data or by URI |
| Generation | `max_completion_tokens`, `temperature`, `top_p`, `stop`, `seed`, `reasoning_effort` | `generation_config`: `max_output_tokens`, `stop_sequences`, `seed`, `thinking_level`, `thinking_summaries` |
| Server-side state | none: `store` keeps a copy for OpenAI's evals, not the conversation | `store` (true by default), `previous_interaction_id`, `background` |
| Response | `choices[].message`, `finish_reason` | `steps[]`, `status` |
| Usage | `completion_tokens` includes reasoning | `total_output_tokens` and `total_thought_tokens` are separate |
| Stream | unnamed chunks, ending in `data: [DONE]` | named events (`interaction.created`, `interaction.status_update`, `step.start`, `step.delta`, `step.stop`, `interaction.completed`, `error`), ending in `event: done` and `data: [DONE]` |

Converting Interactions into Chat Completions would lose three things:

- **Thoughts and their signatures.** Gemini needs them back in later turns; its error codes include
  `missing_thought_signature`.
- **Server-side state and tools.** `previous_interaction_id`, `store`, and server-side tool steps
  are dropped.
- **Shape details.** Media by URI, `is_error`, and the stream's step structure are dropped.

So the IR cannot stay plain Chat Completions. Phases 1 and 2 do not convert, so none of this is
lost there: the request reaches the backend as the client sent it, with the gateway's model.

## The IR

This is phase 3. The IR keeps the shape of Chat Completions. Chat clients therefore convert for
free, and today's Anthropic and Gemini conversions keep working. What the IR adds is one reserved
member, `_envoy`, which any element may carry: the request, a message, a response, or a stream
chunk.

| Member | Holds | Comes from |
|---|---|---|
| `_envoy.reasoning`, on an assistant message or a stream delta | The model's thoughts in order, each `{text, signature}`; defined for every API | Interactions `thought` steps; later Anthropic `thinking` blocks and Gemini `thought` parts |
| `_envoy.<API name>`, on any element | What only that API has | e.g. `{"GEMINI_INTERACTIONS": {"store": false}}` |

The rules:

1. **One element stays one element.** One source element becomes one IR element: a step becomes a
   message, and an event becomes a chunk. Their order is kept.
2. **Mapped members go in IR fields.** What the IR has a field for goes in that field, where AI
   filters can read and edit it.
3. **The rest goes in `_envoy.<API>`.** Converting back to the same API rebuilds the element from
   its IR fields, filter edits included, plus what `_envoy.<API>` kept.
4. **Another API leaves `_envoy.<API>` behind.** Where leaving it would change the meaning, as
   `previous_interaction_id` or `agent` would, the request is refused instead.
5. **Only Envoy writes `_envoy`, and it never leaves Envoy.** A client's request and a backend's
   response lose any `_envoy` they arrive with. Otherwise a Chat client, whose request already is
   the IR, could forge thoughts or another API's fields. Before sending, the AI Protocol Manager
   removes `_envoy`, and drops a stream chunk that holds nothing else.

An Interactions request:

```json
{"model": "assistant-default", "system_instruction": "Be concise.",
 "input": [
   {"type": "user_input", "content": [{"type": "text", "text": "Plan a trip."}]},
   {"type": "thought", "signature": "Cs4B...", "summary": [{"type": "text", "text": "Ask where."}]},
   {"type": "model_output", "content": [{"type": "text", "text": "Where to?"}]},
   {"type": "user_input", "content": [{"type": "text", "text": "Paris."}]}],
 "generation_config": {"max_output_tokens": 256, "thinking_level": "low"},
 "store": false}
```

Its IR:

```json
{"model": "assistant-default",
 "messages": [
   {"role": "system", "content": "Be concise."},
   {"role": "user", "content": [{"type": "text", "text": "Plan a trip."}]},
   {"role": "assistant", "content": null,
    "_envoy": {"reasoning": [{"text": "Ask where.", "signature": "Cs4B..."}]}},
   {"role": "assistant", "content": [{"type": "text", "text": "Where to?"}]},
   {"role": "user", "content": [{"type": "text", "text": "Paris."}]}],
 "max_completion_tokens": 256,
 "reasoning_effort": "low",
 "_envoy": {"GEMINI_INTERACTIONS": {"store": false}}}
```

Converting this IR back to Interactions gives the client's request again, with the gateway's model
if one is set.

### Gemini Interactions and the IR

| Interactions | IR |
|---|---|
| `system_instruction` | a `system` message |
| `user_input` step | a `user` message |
| `model_output` step | an `assistant` message with `content` |
| `thought` step | an `assistant` message with `_envoy.reasoning` |
| any other step: function calls and results, server-side tools, for now | a message holding the step in `_envoy.GEMINI_INTERACTIONS` |
| `generation_config.max_output_tokens`, `stop_sequences`, `seed` | `max_completion_tokens`, `stop`, `seed` |
| `generation_config.thinking_level` | `reasoning_effort`: same values, `minimal` to `high` |
| `model`, `stream` | `model`, `stream` |
| `store`, `previous_interaction_id`, `background`, `agent`, `tools`, anything else | `_envoy.GEMINI_INTERACTIONS` |
| response `steps` | `choices[0].message`: `content` from `model_output`, `_envoy.reasoning` from `thought` |
| response `status` | `finish_reason`: `completed` is `stop`, `incomplete` is `length` |
| response `usage` | IR `usage`, with output including thought tokens |
| stream event | one chunk: `step.delta` text as `delta.content`, thought deltas as `delta._envoy.reasoning`, `interaction.completed` as the closing chunk with usage; other events carry only `_envoy` |

A chunk that carries only `_envoy` becomes an Interactions event again for an Interactions
client, and is dropped for any other (rule 5).

### When to convert

| Backend speaks | An AI filter reads the IR | What runs |
|---|---|---|
| the client's API | no | No transcoder; the second AI Protocol Manager writes the model (phase 1). |
| the client's API | yes | The transcoder pair, losing nothing (phase 3). |
| another API | either | The transcoder pair: today for the APIs it converts, and for Interactions in phase 3. |

In phases 1 and 2 the operator decides, by configuring a transcoder pair or not. Later, filters
declare that they read the IR, the way they declare the bindings they apply today
(`AiFilter::bindingUse()`), and the pair skips a same-API request that no filter reads.

## Two AI Protocol Managers

The work splits in two around the router. The model has to be picked before the router, which
picks the backend from it. The model is written after, once per attempt, for the host that
attempt goes to, and so is any conversion.

```mermaid
sequenceDiagram
    participant C as Client
    participant D as Before the router
    participant U as In the cluster
    participant G as Gemini API
    C->>D: POST /v1beta/interactions, model "assistant-default"
    Note over D: AI Protocol Manager 1:<br/>schema validation checks the request<br/>request info reads it<br/>then a selector sets envoy.ai.model.resolved
    D->>U: the request as received, plus filter state
    Note over U: AI Protocol Manager 2, on every attempt:<br/>writes model gemini-3-flash-preview into the body
    U->>G: POST /v1beta/interactions
    G->>U: Interactions response
    Note over U: usage recorded
    U->>C: Interactions response, model "gemini-3-flash-preview"
```

| | AI Protocol Manager 1, before the router | AI Protocol Manager 2, in the cluster |
|---|---|---|
| Runs | once per request | once per attempt, after the host is picked |
| AI filters | schema validation, then request info. The model selector runs right after them. | None, for a request that only changes its model. In phase 3, the transcoder pair, with IR filters such as guardrails between them. |
| The request body | forwarded as received: `reserialize_body: DISABLE` | re-serialized with the resolved model |
| Filter state | writes the API, the client's model and the selector's choices | reads them |
| The response | not touched | its usage recorded; converted back when a transcoder ran |

- **The second follows the first.** On a route that declares the API, both read it there. Behind a
  DFP's single route, the first records the API it recognized in `envoy.ai.llm_protocol.request`,
  and the second takes it from there (phase 2; see [Which requests are AI
  calls](#which-requests-are-ai-calls)).
- **The selector.** Today it can be an external service behind ext_proc. It reads the request
  info and answers in dynamic metadata, which `set_filter_state` copies into
  `envoy.ai.model.resolved`. Later it can be an AI filter in the first AI Protocol Manager.
- **Filter names.** The two can share a filter name, and so the route's entry, while they agree on
  the API. When the second needs its own route config, such as a backend binding in phase 3, give
  it its own name, e.g. `vertex.ai_protocol_manager`.
- **Two costs, both follow-ups.** The request is parsed twice: the second does not reuse the first's
  parse yet. And neither has an AI filter with a response role, but today each parses and
  re-renders the response of every request it parsed: an SSE event's JSON reaches the client with
  its content intact, in canonical form. An AI Protocol Manager should leave a response alone when
  no AI filter handles it.

## Recognizing AI calls behind a DFP

This is phase 2. Behind a DFP, a single `*` route takes all traffic, and nothing on it says which
requests are AI calls. So the first AI Protocol Manager decides per request, from the request
itself, and the second follows it.

### Which requests are AI calls

A request runs the AI filters when one of these names its API. When several do, the first wins:

1. **Filter state.** A filter ahead, such as ext_proc, `set_filter_state` or a model router, sets
   `envoy.ai.llm_protocol.request`. Today this counts only on a route that declares `request`;
   here it counts on any route. A filter ahead can therefore make a call an AI call, or correct
   the API recognition would pick.
2. **The route.** The route declares an API in its AI config, as today.
3. **Recognition.** The AI Protocol Manager recognizes it. The request must be a `POST` with a JSON
   body, and its path must be one a listed API uses.

The other instructions in filter state apply to every AI call, however it was found:

- `envoy.ai.llm_protocol.response` names the backend's API;
- `envoy.ai.binding.request` and `envoy.ai.binding.response` name the bindings;
- `envoy.ai.model.resolved` names the model to send.

Each API is recognized by how its path ends, so gateway prefixes still match:

| API | Path ends with |
|---|---|
| `GEMINI_INTERACTIONS` | `/interactions`: `/v1beta/interactions`, `/v1/interactions`, and Vertex AI's `.../locations/global/interactions` |
| `GEMINI_GENERATE_CONTENT` | `:generateContent` or `:streamGenerateContent` |
| `OPENAI_CHAT_COMPLETIONS` | `/chat/completions` |
| `ANTHROPIC_MESSAGES` | `/v1/messages`, or Vertex AI's `.../publishers/anthropic/models/{model}:rawPredict` and `:streamRawPredict` |

These come from schema validation's path detection and the transcoder's built-in bindings, such
as Claude on Vertex AI's. The table moves into the AI Protocol Manager, which needs the API before
it decides to hold the body.

With `parse_unconfigured_routes` off, its default, everything else passes untouched, and is
neither held nor parsed:

- a get or a delete, which has no body;
- a cancel, whose path ends in `/cancel`;
- a file upload, whose path names no API;
- a call of an API that is not listed.

### What the recognized API decides

- **The client's API.** The recognized API is the client's API for every AI filter.
- **The backend's API.** It defaults to the client's, since behind a DFP the host serves the API
  the client called. A filter ahead can still name another with `envoy.ai.llm_protocol.response`.
  Today, a route that declares no backend API makes the backend-side transcoder fail.
- **The record.** The AI Protocol Manager records the API of every AI call in
  `envoy.ai.llm_protocol.request`, unless a filter ahead already set it. The second AI Protocol
  Manager follows that record, and access logs can show it.
- **Responses.** Responses of recognized calls are metered, and converted when a transcoder ran, as
  on a declared route.

### Why the APIs are listed

Listing an API makes all of its calls AI calls. Without a transcoder that changes nothing but their
model. With the transcoder pair, until an API converts to the IR and back without loss, it would
change their traffic: today's IR drops Anthropic thinking and tool-use blocks from responses, for
example. Chat Completions is safe to convert, since it is the IR's shape. Gemini Interactions is
safe once its conversion lands. OpenAI Responses has no conversion, so the transcoders would refuse
its calls.

### By the payload, later

A path that names no listed API, such as a gateway's own `/llm`, could still be recognized by its
payload. The AI Protocol Manager would hold a JSON `POST`, parse it, and look for the markers
schema validation uses today. A payload that names no API is forwarded as received. This holds
every JSON `POST`, so it is an option, off by default.

## Schema validation

| Check | Where | Against |
|---|---|---|
| The client's request | The schema validation filter, first in the first AI Protocol Manager | The client's API, as declared or recognized |
| The IR | Tests: every golden IR document (phase 3) | The IR schema: Chat Completions, plus `_envoy` |
| The backend's request | The backend-side transcoder, before sending; it does this today | The backend's API |

Schema validation runs first because it checks what the client sent, before anything converts it.
Until the Interactions schema lands (PR 3), it detects Interactions but skips validating it,
counted by `schema_validation.skipped`. In phase 2, detection by path moves out of it, into the AI
Protocol Manager, which needs the API before it holds the body. Schema validation keeps its other
detection, by the `anthropic-version` header and then the payload, for a route that declares
`request` without naming an API.

## Stateful calls and failover

Interactions keeps state at Google: stored interactions, the chains `previous_interaction_id`
continues, background runs, and streams a client can resume. That state belongs to a provider
account, not to a model or a host:

| Backend | Account | Kept for |
|---|---|---|
| Gemini API | the Cloud project behind the API key, on one global host | 55 days on the paid tier, which can be set to 7, 14 or 28; 1 day on the free tier |
| Vertex AI | the project and the location in the path: `global`, or the `us` or `eu` multi-region | 7 days |

An interaction id names no account, and only the account that made it can find it. So any
cluster of that account can serve a stateful call, and no cluster of another account can. A
stateful call is one of these:

- a create that sets `previous_interaction_id`;
- a get, a stream resume (a get with `stream=true` and `last_event_id`), a cancel or a delete;
- anything about a background run or an agent's environment.

A create without `previous_interaction_id` starts a new conversation, and can go to any account.
With `store` true, its default, the account that serves it holds the new chain from then on.

This design treats one Vertex AI project in two locations as two accounts, until a chain is shown
to cross them (see [Open questions](#open-questions)).

### Three kinds of failover

| Failover to | A new conversation | A stateful call |
|---|---|---|
| another host of the cluster | yes | yes |
| another cluster of the same account | yes | yes |
| a cluster of another account | yes | no: it fails closed, or is rehydrated where configured |

When all of a route's clusters belong to one account, none of this needs anything new. When they
span accounts, the AI Protocol Managers must know each call's account. Changing the model on a
retry is a separate matter: Google lets one chain mix models, within their modality limits, so a
chain can change models within its account.

### Account groups

Envoy fails over between clusters with the route's `refresh_cluster_on_retry` and the priority
group cluster specifier. The first attempt uses the first group, each retry the next, and the last
group serves every attempt after the list runs out. A group picks a cluster by weight, from one
random value per request, so a retry within a group goes back to the same cluster. Two clusters of
one account that back each other up therefore go in two groups.

Each group holds the clusters of one account. The first AI Protocol Manager's config lists the
accounts and their groups in order. For a stateful call, it writes that account's groups as the
specifier's per-request override, a `PriorityGroupsOverride` in dynamic metadata, and clears the
route cache. The override's last group repeats, so no retry leaves the account. A new conversation
gets no override, and follows the route's groups across accounts.

Here two Vertex AI projects back each other up; the first is reached two ways, such as two egress
paths. `stateful_calls` does not exist yet.

```yaml
# The route.
- match: {prefix: /}
  route:
    timeout: 300s
    inline_cluster_specifier_plugin:
      extension:
        name: envoy.router.cluster_specifier_plugin.priority_group
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.router.cluster_specifiers.priority_group.v3.PriorityGroupClusterSpecifier
          override_metadata_namespace: envoy.filters.http.ai_protocol_manager
          priority_groups:
          - name: a-1
            clusters: [{cluster_name: vertex_a_1, weight: 1}]
          - name: a-2
            clusters: [{cluster_name: vertex_a_2, weight: 1}]
          - name: b
            clusters: [{cluster_name: vertex_b, weight: 1}]
    retry_policy:
      retry_on: connect-failure,refused-stream,reset-before-request,retriable-status-codes
      retriable_status_codes: [429, 503]
      num_retries: 2
      refresh_cluster_on_retry: true

# The first AI Protocol Manager, in the listener.
- name: envoy.filters.http.ai_protocol_manager
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
    request_handling: {reserialize_body: DISABLE}
    stateful_calls:
      id_envelope: {hmac_keys: {name: interaction-id-keys}}
      accounts:
      - label: project-a
        priority_groups: [a-1, a-2]
      - label: project-b
        priority_groups: [b]

# The second, in the cluster vertex_b.
- name: envoy.filters.http.ai_protocol_manager
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
    request_handling: {}
    response_handling: {token_usage: {}}
    stateful_calls:
      account: project-b
      id_envelope: {hmac_keys: {name: interaction-id-keys}}
      path_prefix: /v1beta1/projects/project-b/locations/global
```

A new conversation tries `vertex_a_1`, then `vertex_a_2`, then `vertex_b`. A call chained in
`project-a` tries `vertex_a_1`, then `vertex_a_2` twice.

### Who knows the account

| | The first AI Protocol Manager, before the router | The second, in each cluster |
|---|---|---|
| Knows the account | from the envelope on the call's id: `previous_interaction_id` in the body, or the id in the path | from its config: the account its cluster serves |
| The request | verifies the envelope; writes the account and the provider's id to filter state, and the account's groups as the override; forwards the body as received | checks that the call's account is its own; writes the provider's id, and the path for its account |
| The response | not touched | wraps every interaction id with its own account |

- **The winning attempt names the account.** Only the response of the attempt that succeeded
  reaches the client, and that attempt's second AI Protocol Manager wrapped its ids. So an id
  always names the account that holds it, whichever cluster served it. The first AI Protocol
  Manager runs once, before any attempt has succeeded, so it cannot know. Nor can the route's
  config, once its groups span accounts.
- **Every attempt starts from the client's request.** The router sends each attempt its own copy
  of the client's body, envelope included. Headers are shared: on main, an upstream filter's
  header edits stay for the next attempt. So the second AI Protocol Manager renders the whole path
  from filter state and its `path_prefix`, rather than editing the path it receives. Credential
  injectors overwrite their header. A header one cluster adds and the next does not still reaches
  the next; a router change that restores the request headers before each retry would end that,
  and is separate.
- **A call in the wrong account fails there.** When a call bound to one account reaches a cluster
  of another, and rehydration does not cover it, the second AI Protocol Manager refuses the attempt
  locally, and counts `stateful.account_mismatch`. This means the config is wrong: the override
  should have kept the call in its account.
- **The ids.** The second wraps the `id` and `previous_interaction_id` of every interaction it
  returns: in the response to a create or a get, and in the stream's `interaction.created` and
  `interaction.completed` events. The first reads `previous_interaction_id`, and the id in the
  path of a get, a stream resume, a cancel or a delete. Those four become calls the AI Protocol
  Managers take for their ids: no request body is held, and no usage is recorded.

### Id envelopes

An envelope carries the account with the id, so a later call finds its account whichever route
it takes. It is a version prefix, then the URL-safe base64 of the account's label, the provider's
id, and an HMAC-SHA256 over both.

- **The label** is the operator's name for the account, not its project id.
- **The HMAC** keeps a client from moving a chain to another account by editing the label. The
  keys come from SDS: the first signs, and all of them verify. A retired key stays as long as an
  id it signed can still be used: up to 55 days on the Gemini API's paid tier.
- **An id without a valid envelope** is refused with 400, and counted `stateful.envelope_invalid`.
  While clients move over, `accept_plain_ids` sends it on with no override, to the route's groups.
- **Without envelopes**, a route keeps each call in its account only when all its groups belong to
  that account. Ids then pass untouched. That is where to start: envelopes are for a route whose
  groups span accounts.

### Fail closed

By default, a stateful call never leaves its account. When every group of the account has failed,
the client gets the last attempt's error. It can then send the turn again in stateless form, with
the whole conversation in `input`.

Some calls never leave their account, even with rehydration: a get, a stream resume, a cancel, a
delete, a background run, and anything about an agent's environment. What they name exists only
where it was made.

### Rehydration, opt in

Rehydration turns a chained create into a stateless one, for an account that does not hold the
chain. Envoy asks an external service for the conversation. It neither reads chains from Google
nor keeps them.

1. The first AI Protocol Manager's config lets an account rehydrate into others, with
   `rehydrate_into` on the account. For a call chained in `project-a`, the override lists
   `project-a`'s groups, then `project-b`'s.
2. An attempt reaches a cluster of `project-b`. Its second AI Protocol Manager sees that the chain
   is in `project-a`, and sends the rehydration service the account, the provider's id and the
   request, over gRPC.
3. The service answers with the conversation as a list of steps, or refuses. It can read the chain
   from `project-a` with gets, following each interaction's `previous_interaction_id` back, since
   a stored interaction keeps its `user_input` steps. Or it can read a copy it keeps itself.
4. The second AI Protocol Manager puts those steps ahead of the request's `input`, and removes
   `previous_interaction_id`. `tools`, `system_instruction` and `generation_config` belong to each
   interaction, not to the chain, so the request already carries them.
5. `project-b` answers with a new id, which the second wraps with `project-b`. The conversation
   goes on there, and its earlier ids still name `project-a`.

The service refuses when:

- it cannot read the chain: a 429 leaves `project-a` readable, but an outage may not;
- the chain uses what the other account cannot reach, such as Files API files, or an agent's
  environment;
- the chain's last interaction is still running.

What it costs:

- **Tokens.** The new account bills the whole conversation as input, with no cache for that turn.
- **Signatures.** Thought and tool steps carry signatures. Whether one account accepts the
  signatures another made is not known yet (see [Open questions](#open-questions)).
- **Data location.** The conversation is copied between accounts, so `rehydrate_into` lists only
  accounts that may hold each other's data.
- **Latency.** The attempt waits for the service, and the wait counts against the route's timeout.

The second AI Protocol Manager counts `stateful.rehydrated` and `stateful.rehydration_refused`.

### Retry policy

The router never retries once the response has started. So a stream cut halfway does not fail
over: the client resumes it on the same account, with a get, `stream=true` and the last
`event_id` it saw. Before the response starts, what a retry may do depends on the call:

| Call | Repeatable | `retry_on` |
|---|---|---|
| A create | No. A retry after Google started work can leave a second stored interaction the client never sees, or start a second background run, and both are billed. | `connect-failure`, `refused-stream`, `reset-before-request`, and `retriable-status-codes` with 429 and 503 |
| A get, a stream resume, a cancel or a delete | Yes, by id. | Also `reset` and `5xx`. |

- `reset-before-request` retries a reset only when no byte of the request was sent. `reset`
  retries any reset.
- A 429 or a 503 says Google turned the call away, for quota or load. A 500 or a 504 may come
  after it started work.
- No `per_try_timeout` and no hedging on a create: each sends another create while the first may
  still be running.
- A route that serves every call, such as a DFP's single route, gives them one policy, so it takes
  the create's.
- A retry to another cluster keeps the first cluster's circuit breakers and retry policy (a TODO
  in `Filter::doRetry`), so accounts share one retry budget.
- A body larger than the route's `request_body_buffer_limit` is not retried at all.

### Plan

| PR | Change |
|---|---|
| 9. `ai_protocol_manager: keep Interactions calls on their account` | `stateful_calls` in both AI Protocol Managers. The second wraps ids with its account, unwraps the call's id, renders its path, and refuses a call of another account. The first verifies the envelope, records the account and the id in filter state, and writes the account's groups as the priority group override. Get, stream resume, cancel and delete are taken for their ids. |
| 10. `ai_protocol_manager: rehydrate a chain into another account` | `rehydrate_into`, and the gRPC callout from the second AI Protocol Manager. |

PR 9's integration test: a create fails over from one account to another on a 429, and its id
names the second; the next chained create goes straight to the second; and a get for an id whose
account's clusters are all down fails closed.

## Examples

### 1. Same API, new model

The client sends the Interactions request shown in [The IR](#the-ir) to
`generativelanguage.googleapis.com`:

1. The first AI Protocol Manager takes it as Gemini Interactions: its route declares the API
   (phase 1), or it recognizes the method, the body and the path (phase 2). Schema validation
   checks the request, and request info reads `assistant-default`. The body goes on as received.
2. The selector picks `gemini-3-flash-preview`, and `envoy.ai.model.resolved` is set.
3. The router sends the call to the cluster.
4. The second AI Protocol Manager re-serializes the body with `"model": "gemini-3-flash-preview"`.
   No transcoder runs, so the thought step, its signature and `store` reach Google as sent.

Google's response goes back through the second AI Protocol Manager, which records its usage for
`gemini-3-flash-preview`. The client sees `"model": "gemini-3-flash-preview"`.

### 2. Streaming

In phases 1 and 2 nothing changes the stream's content; until PR 5, its JSON is re-rendered in
canonical form. The AI Protocol Manager reads usage from `interaction.completed`, and skips the
step events and `interaction.created` by their names, without parsing them. In phase 3, each event
becomes one IR chunk and comes back as the same event:

| Interactions event | IR chunk |
|---|---|
| `interaction.created` | the opening chunk; `id` and `model` in IR fields, the rest in `_envoy` |
| `step.start`, `step.stop`, `interaction.status_update` | `_envoy` only |
| `step.delta`, text | `delta.content`; the step `index` in `_envoy` |
| `step.delta`, thought summary or signature | `delta._envoy.reasoning` |
| `interaction.completed` | the closing chunk: `finish_reason` and `usage` |
| `error` | an error chunk |
| `data: [DONE]` | the end of the stream |

### 3. A filter that reads the IR

In phase 3, a guardrail between the transcoder pair of the second AI Protocol Manager reads the IR.
The pair converts the request into the IR and back, the guardrail reads it on the way, and the
request goes out as it came in, with the gateway's model. The client sees the model it asked for.

### 4. Get, delete and cancel

The AI Protocol Manager does not take these as AI calls: a get or a delete has no body, and a
cancel's path ends in `/cancel`, which no declared route or recognized path covers. They are
forwarded without AI processing. A get returns a stored interaction, which can carry the usage of
the request that created it, so that usage is not counted twice. With id envelopes (PR 9), the AI
Protocol Managers take these calls for their ids only (see [Who knows the
account](#who-knows-the-account)).

## Configuration

The Vertex AI example runs on phase 1, which this branch prototypes. The DFP example also needs
phase 2: `endpoint_recognition`, and the second AI Protocol Manager following the first's record.
With `endpoint_recognition` removed, `GEMINI_GENERATE_CONTENT` in place of the new enum value, and
the CA path adjusted, both pass `envoy --mode validate` on a build of `d5eb7030ad`. The config
protos they use are the same on today's main.

### A DFP for any provider

One route sends everything to the DFP cluster. The first AI Protocol Manager, in the listener,
recognizes AI calls and reads them; an external selector picks the model; the second, in the
cluster, writes it.

```yaml
static_resources:
  listeners:
  - name: ai_egress
    address:
      socket_address: {address: 0.0.0.0, port_value: 10000}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ai_egress
          route_config:
            name: egress
            virtual_hosts:
            - name: egress
              domains: ["*"]
              routes:
              # The only route. The AI Protocol Managers decide what is an AI call.
              - match: {prefix: /}
                route: {cluster: dfp, timeout: 300s}
                request_headers_to_remove: [accept-encoding]
          http_filters:
          # 1. Reads the request and leaves its findings in filter state. The body goes on as
          #    received.
          - name: envoy.filters.http.ai_protocol_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
              request_handling:
                reserialize_body: DISABLE
                endpoint_recognition:
                  llm_protocols: [GEMINI_INTERACTIONS, OPENAI_CHAT_COMPLETIONS]
              filters:
              - name: envoy.http.ai_filters.schema_validation
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.http.ai_filters.schema_validation.v3.SchemaValidation
              - name: envoy.http.ai_filters.request_info
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.http.ai_filters.request_info.v3.RequestInfo
          # 2. Picks the model. Here an external service does it, from the request info.
          - name: envoy.filters.http.ext_proc
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
              grpc_service:
                envoy_grpc: {cluster_name: model_selector}
              processing_mode:
                request_header_mode: SEND
                response_header_mode: SKIP
              metadata_options:
                forwarding_namespaces: {typed: [envoy.ai.request_info]}
                receiving_namespaces: {untyped: [envoy.ai.selection]}
          - name: envoy.filters.http.set_filter_state
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config
              on_request_headers:
              - object_key: envoy.ai.model.resolved
                skip_if_empty: true
                format_string:
                  omit_empty_values: true
                  text_format_source: {inline_string: "%DYNAMIC_METADATA(envoy.ai.selection:model)%"}
          # 3. Routes, to the host the client named.
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config: {name: ai_providers, dns_lookup_family: V4_PREFERRED}
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: dfp
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config: {name: ai_providers, dns_lookup_family: V4_PREFERRED}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
          validation_context:
            trusted_ca: {filename: /etc/ssl/certs/ca-certificates.crt}
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        upstream_http_protocol_options: {auto_sni: true, auto_san_validation: true}
        auto_config:
          http_protocol_options: {}
          http2_protocol_options: {}
        # 4. Writes the resolved model into the body, on every attempt, following the filter
        #    state. Re-serializing is the default.
        http_filters:
        - name: envoy.filters.http.ai_protocol_manager
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
            request_handling: {}
            response_handling:
              token_usage: {}
        - name: envoy.filters.http.upstream_codec
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec

  - name: model_selector
    type: STATIC
    load_assignment:
      cluster_name: model_selector
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: {address: 127.0.0.1, port_value: 9000}
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
```

- Clients send plain HTTP with the provider's host, as through an egress sidecar. The DFP resolves
  the host, and Envoy originates TLS (`auto_sni`, `auto_san_validation`). Clients bring their own
  provider keys.
- The selector picks the model, not the provider: `auto_sni` follows the Host header, so a selector
  that sent a call elsewhere would have to change that header too.
- `accept-encoding` is removed on the route, so for all traffic, because Envoy can neither read nor
  convert a compressed response.
- Request info reads Interactions as the client sent it. In phase 3 it reads the IR instead, between
  the transcoders.

### Gemini on Vertex AI, one DNS cluster

The same pattern, with one DNS cluster to Vertex AI instead of the DFP. Clients call Gemini API
paths such as `/v1beta/interactions`, and Vertex AI serves the Interactions API at a project path.
The listener's filters are the DFP example's, without the DFP filter and without
`endpoint_recognition`, since the route declares the API. The route and the cluster change:

```yaml
          route_config:
            name: vertex
            virtual_hosts:
            - name: gemini
              domains: ["*"]
              request_headers_to_remove: [authorization, accept-encoding]
              routes:
              # Interactions calls, sent to Gemini on Vertex AI.
              - match:
                  safe_regex: {regex: "/v1(beta)?/interactions"}
                  headers: [{name: ":method", string_match: {exact: POST}}]
                route:
                  cluster: vertex_ai
                  auto_host_rewrite: true
                  timeout: 300s
                  regex_rewrite:
                    pattern: {regex: "^/v1(beta)?/interactions$"}
                    substitution: /v1beta1/projects/my-project/locations/global/interactions
                typed_per_filter_config:
                  # Read by both AI Protocol Managers: the client and the backend speak
                  # Interactions.
                  envoy.filters.http.ai_protocol_manager:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManagerPerRoute
                    request: {llm_protocol: GEMINI_INTERACTIONS}
              # Get, delete and cancel, moved to Vertex AI's path; no AI config.
              - match:
                  safe_regex: {regex: "/v1(beta)?/interactions/.+"}
                route:
                  cluster: vertex_ai
                  auto_host_rewrite: true
                  timeout: 300s
                  regex_rewrite:
                    pattern: {regex: "^/v1(beta)?/interactions/"}
                    substitution: /v1beta1/projects/my-project/locations/global/interactions/

  clusters:
  - name: vertex_ai
    type: LOGICAL_DNS
    dns_lookup_family: V4_PREFERRED
    connect_timeout: 5s
    load_assignment:
      cluster_name: vertex_ai
      endpoints:
      - lb_endpoints:
        - endpoint:
            hostname: aiplatform.googleapis.com
            address:
              socket_address: {address: aiplatform.googleapis.com, port_value: 443}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: aiplatform.googleapis.com
        common_tls_context:
          alpn_protocols: [h2]
          validation_context:
            trusted_ca: {filename: /etc/ssl/certs/ca-certificates.crt}
            match_typed_subject_alt_names:
            - san_type: DNS
              matcher: {exact: aiplatform.googleapis.com}
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
        http_filters:
        # Vertex AI takes an OAuth access token; something outside Envoy refreshes it.
        - name: envoy.filters.http.credential_injector
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.credential_injector.v3.CredentialInjector
            overwrite: true
            credential:
              name: envoy.http.injected_credentials.generic
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.http.injected_credentials.generic.v3.Generic
                credential: {name: vertex-access-token}
                header: authorization
                header_value_prefix: "Bearer "
        - name: envoy.filters.http.ai_protocol_manager
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.ai_protocol_manager.v3.AiProtocolManager
            request_handling: {}
            response_handling:
              token_usage: {}
        - name: envoy.filters.http.upstream_codec
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec
```

- The route declares the client's API once, and both AI Protocol Managers read it. The backend's
  API defaults to the client's.
- A path rewrite moves every call to Vertex AI's path. In phase 3, a converted request gets the
  path from the backend's binding instead, which needs its own route entry for the second AI
  Protocol Manager.
- Get, delete and cancel carry no AI config.
- Vertex AI takes an OAuth access token rather than an API key. Here it comes from a secret that
  something outside Envoy refreshes.

## Phased plan

Each phase ships on its own and is useful by itself. Tests come with each PR.

### Phase 1: change the model

A route declares Gemini Interactions. The first AI Protocol Manager reads the request, a selector
picks the model, and the second writes it. No transcoder runs. This branch prototypes PRs 1 and 2.

| PR | Change |
|---|---|
| 1. `ai_protocol_manager: add the Gemini Interactions protocol` | `GEMINI_INTERACTIONS = 5`. Usage from a response's `usage` and a stream's `interaction.completed`, with thought tokens summed into the output. `interaction.created` and the step events skipped by name, unparsed. Schema validation detects the API by its `/interactions` path, or by payload: keys only Interactions has, or Gemini's `system_instruction` or `generation_config` beside `input`. Request info reads its attributes. |
| 2. `ai_protocol_manager: write the resolved model without a transcoder` | When no AI filter applies a binding and the body is re-serialized, the request sink sets the body's `model` to `envoy.ai.model.resolved`. |
| 3. `ai_protocol_manager: add the Gemini Interactions request schema` | Schema validation checks Interactions requests: `model` or `agent`, the shapes of `input`, `generation_config`'s types, and which fields stay inline. |

PR 2's integration test runs the pattern: a downstream `set_filter_state` resolves the model, and
the upstream AI Protocol Manager sends it in an Interactions body and meters the stream.

### Phase 2: one DFP route

| PR | Change |
|---|---|
| 4. `ai_protocol_manager: recognize AI calls without route config` | `RequestHandling.endpoint_recognition`, listing the APIs to recognize. A request is an AI call when `envoy.ai.llm_protocol.request` names its API, on any route; when its route declares one; or when recognition does. The first of these wins. The path table moves in from schema validation. The backend API defaults to the client's. The API of every AI call is recorded in `envoy.ai.llm_protocol.request`, which a second AI Protocol Manager follows. |
| 5. `ai_protocol_manager: leave a response no AI filter handles` | An AI Protocol Manager whose AI filters have no response role, or which has none, stops parsing and re-rendering the response. Usage is still read from the bytes as they pass. |

Its integration test runs the DFP example: an Interactions call is recognized by the first AI
Protocol Manager and gets its model from the second, and a get, a cancel and a file upload pass
untouched.

### Phase 3: the IR

For when an AI filter reads the IR, or the backend speaks another API.

| PR | Change |
|---|---|
| 6. `ai_protocol_manager: carry what the IR has no field for` | The `_envoy` member: engine rules that move unmapped members into `_envoy.<API>` and back. The AI Protocol Manager drops any `_envoy` a client or backend sends, removes `_envoy` before sending, and drops a stream chunk left with nothing else. The IR schema accepts it. |
| 7. `ai_protocol_manager: transcode Gemini Interactions to and from the IR` | Request, response and stream, in both directions: text, instructions, generation settings and thoughts; everything else in `_envoy`; the gateway's model on the way out and the client's on the way back. |
| 8. `request_info: read the IR` | One reader for every API, between the transcoders, in place of today's per-API readers. |

Its tests include round-trip goldens: every Interactions request, response and stream event goes
into the IR and back unchanged, and every golden IR document passes the IR schema.

### Later

- recognition by payload;
- skipping the conversion when nothing reads the IR;
- the second AI Protocol Manager reusing the first's parse;
- writing the model without re-serializing the whole body;
- an AI filter for picking the model, in place of ext_proc;
- the Anthropic and Gemini conversions carrying thoughts and unmapped members the same way;
- tools and media;
- stateful calls across accounts: id envelopes, then rehydration (PRs 9 and 10; see [Stateful
  calls and failover](#stateful-calls-and-failover)).

## Limits of the first release

- **Agents.** An `agent` request names no model, so none is written. It goes through as sent.
- **The response's model.** The client sees the model that served the request, not the one it
  asked for.
- **Path-carried models.** Gemini's `generateContent` names its model in the path, which only a
  transcoder renders. Writing the model without a transcoder serves body-carried models.
- **No Interactions schema** until PR 3. Schema validation detects the API and skips it.
- **Recognition** is phase 2. Until then a route declares the API.
- **Get, delete and cancel.** These calls are not AI calls, and are forwarded without AI processing
  or usage records.
- **Failover across accounts.** Nothing keeps a chained call on the account that holds it, so all
  of a route's clusters must belong to one account until PR 9.

## Decisions

- **The IR's form** (2026-10-19): Chat Completions' shape plus `_envoy`. A new Envoy-defined
  format would be cleaner, but every conversion would be rewritten, and Chat clients would convert
  too.
- **A model change converts nothing** (2026-10-20): the AI Protocol Manager writes the resolved
  model when no transcoder runs, rather than running a same-API transcoder pair.

## Open questions

1. **The model a same-API response reports.** Without a transcoder, the client sees the backend's
   model. Should the AI Protocol Manager write the client's model back, as the transcoder does?
   That needs a model writer per API, beside the usage readers.
2. **Where thoughts live.** `_envoy.reasoning` cannot clash with a future OpenAI field. Other
   gateways put thoughts in a top-level field, such as `reasoning_content` or `reasoning_details`.
3. **Converting only when needed.** Should filters declare that they read the IR, or should the
   transcoder pair always convert?
4. **State-bound fields.** Should a cross-API request carrying `previous_interaction_id` or `agent`
   be refused? Doing so needs a refuse rule in the engine.
5. **Which APIs recognition takes.** This design lists them in the config. Should every API whose
   conversion loses nothing be recognized by default instead?
6. **`accept-encoding`.** Should the AI Protocol Manager remove it only from the calls it takes,
   instead of the route removing it from all traffic?
7. **Vertex AI locations.** Can a chain made in one location of a project be continued, or read,
   from another? Until it is shown, each location is its own account.
8. **Signatures across accounts.** Does one account accept the thought and tool signatures another
   made? Rehydration depends on it, and it needs a test against both backends.
9. **A typed error when failing closed.** Should a stateful call whose account is down get an error
   that tells the client to resend the turn in stateless form, rather than the last attempt's?
10. **The label in the envelope.** It is readable, which helps an operator reading logs but shows
    clients how accounts are split. Should the envelope encrypt it?

## References

- Interactions API: https://ai.google.dev/api/interactions-api and
  https://ai.google.dev/api/interactions-api-v1
- Streaming: https://ai.google.dev/gemini-api/docs/streaming
- Errors, including `missing_thought_signature`: https://ai.google.dev/gemini-api/docs/api-errors
- State and retention: https://ai.google.dev/gemini-api/docs/interactions-overview
- Background runs: https://ai.google.dev/gemini-api/docs/background-execution
- The priority group cluster specifier:
  `api/envoy/extensions/router/cluster_specifiers/priority_group/v3/priority_group.proto`
