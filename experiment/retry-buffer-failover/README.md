# Retry-session failover prototype

Gemini API to Vertex AI failover with an upstream retry session
(`source/docs/ai_retry_session.md`). Past `request_body_buffer_limit`, the router keeps no copy of
the body. Attempt 1's upstream AI protocol manager keeps the body and its parsed JSON in a retry
session that later attempts adopt. If attempt 1 fails while the body is still arriving, the router
writes the rest of the body to the session itself.

```
client -> :19010 ai_protocol_manager -> ext_proc PDP -> router (priority_group)
       -> gemini  127.0.0.1:18443  SNI generativelanguage.googleapis.com
       -> vertex  127.0.0.1:18444  SNI us-central1-aiplatform.googleapis.com
```

## Listeners

| Listener | Router | Clusters |
|----------|--------|----------|
| :19010 | `request_body_buffer_limit: 0`: keeps no copy | `gemini`, `vertex` |
| :19012 | keeps bodies up to 1 MiB, hands a larger one over at 1 MiB | `gemini`, `vertex` |
| :19014 | as :19010 without the PDP: nothing holds the headers ahead of the router | `gemini`, `vertex` |
| :19016 | as :19012 without the PDP: the router keeps exactly the first 1 MiB | `gemini`, `vertex` |
| :19002 | control: no session, so today's in-memory retry buffer | `gemini_plain`, `vertex_plain` |

`gemini_refused` has the session chain but points at a port nothing listens on. The refused sweep
sends bodies from 16 KiB to 64 MiB to it first, and prints how each one reached vertex.

All listeners use a 32 KiB connection buffer limit. Admin is on :19901.

## Provider clusters

Each provider cluster adapts the request to its backend with C++ filters only:

1. An upstream `ai_protocol_manager` named for its provider (`ai_protocol_manager.gemini`,
   `ai_protocol_manager.vertex`), with `retry_session: true`. An upstream filter's per-route
   config is looked up on the shared route by its own name, so each name gets its own
   `AiProtocolManagerPerRoute`: the clients' API, and the API and binding that provider takes.
   Clusters of one provider share it (`vertex`, `vertex_plain`). Its transcoder pair runs the
   request to the IR and out in the provider's binding, which renders `:path`, and the response
   back.
2. `header_mutation`, which drops the other provider's credential.
3. `credential_injector`, which sets this provider's credential.

`gemini_plain` has no APM: the clients already speak its API and, with header restore on, every
attempt starts from the client's path. With restore off it gets the path an earlier attempt
rendered (`no-restore-plain-reverse`), so it needs the restore. `vertex_plain` transcodes without a
session.

A Gemini -> IR -> Gemini round trip keeps five `generationConfig` fields (`maxOutputTokens`,
`temperature`, `topP`, `stopSequences`, `seed`) and refuses function call and media parts with a
400 in one attempt, which does not fail over. The `limit-*` cases pin these down.

## Files

- `envoy.yaml`: the gateway and the provider clusters, with no Lua.
- `pdp/`: a Go ext_proc server. It returns the priority groups from, in order, the `x-pdp-groups`
  header (groups with optional clusters and weights), the `x-pdp-order` header, or a policy keyed
  by the model the APM parsed. On `x-pdp-rewrite-body` it replaces the body with `CONTINUE_AND_REPLACE`;
  on `x-test-mutate-body` it switches the body to `BUFFERED` through `mode_override` and edits it.
- `mock_llm.py`: TLS mock backends. Each request is scripted by `x-test-behavior` (per backend,
  and per hit with `429|200`) and logged to JSONL with its SNI, path, credentials, and the
  SHA-256 of the body and of its canonical JSON. Streaming methods are answered with SSE.
- `e2e.py`: the cases.
- `run.sh`: starts everything, runs the cases, and stops everything.
- `build_config/`: a trimmed extension set for a faster build.

## Run

`run.sh` writes logs and certificates under `run/`, which is gitignored.

1. Build the binary:

   ```bash
   bazel build //source/exe:envoy-static
   ```

   The trimmed build needs these lines in the workspace's `user.bazelrc` (macOS flags shown):

   ```
   build --macos_minimum_os=14.0
   build --host_macos_minimum_os=14.0
   build --override_repository=+envoy_build_config_ext+envoy_build_config=<abs path>/experiment/retry-buffer-failover/build_config
   build --@proxy-wasm-cpp-host//bazel:engine=disabled
   build --//bazel:http3=False
   ```

   It leaves out most extensions (tcp_proxy among them), so build the default configuration too
   before relying on a change to shared interfaces.

2. Run the cases with the prototype's behavior:

   ```bash
   experiment/retry-buffer-failover/run.sh
   ```

3. Run them again with request header restore turned off through the admin runtime. Each
   provider cluster's APM renders its own path and the chains set only their own credential, so
   the :19010 walks still pass; the run checks that the guard is off, and that the control's
   APM-free `gemini_plain` then gets an earlier attempt's path:

   ```bash
   experiment/retry-buffer-failover/run.sh --no-restore
   ```

`captured/` holds the logs of the last runs: e2e results, access and upstream logs, the backends'
view of every attempt, router debug lines and stats. The `*_naive_chains` files are from an
earlier configuration whose chains neither rebuilt the path nor dropped the other credential, run
with restore off: they show the cross-cluster leak the restore and the chains each prevent.
