# Retry-buffer failover prototype

Gemini API to Vertex AI failover. Retries replay from a request body log that the router writes
into an AI protocol manager's external buffer. The design is `source/docs/ai_retry_buffer.md`.

```
client -> :19000 ai_protocol_manager -> ext_proc PDP -> router (priority_group)
       -> gemini  127.0.0.1:18443  SNI generativelanguage.googleapis.com
       -> vertex  127.0.0.1:18444  SNI us-central1-aiplatform.googleapis.com
```

## Listeners

| Listener | Request body log lent by | Clusters |
|----------|--------------------------|----------|
| :19000 | each provider cluster's upstream APM (attempt 1) | gemini/vertex with an upstream APM |
| :19004 | the downstream APM (re-serializing) | `*_plain`, no APM |
| :19006 | the downstream APM; the upstream APMs read their payload back from it | gemini/vertex with an upstream APM |
| :19008 | as :19006, capped at 1 MiB | gemini/vertex with an upstream APM |
| :19002 | none: today's in-memory retry buffer (control) | `*_plain` |

All listeners use a 32 KiB connection buffer limit. Admin is on :19901.

## Files

- `envoy.yaml`: the gateway and the two provider clusters. Each cluster has its own Lua path
  rewrite, `credential_injector` and SNI.
- `pdp/`: a Go ext_proc server. It orders the priority groups by the `x-pdp-order` header, or by
  the model the APM parsed. On `x-pdp-rewrite-body` it replaces the body with
  `CONTINUE_AND_REPLACE`.
- `mock_llm.py`: TLS mock backends. Each request is scripted by `x-test-behavior` and logged to
  JSONL with its SNI, path, credentials and the body's SHA-256.
- `e2e.py`: the cases.
- `run.sh`: starts everything, runs the cases, and stops everything.
- `build_config/`: a trimmed extension set for a faster build.
- `c_plus_prototype.patch`: the earlier design, in which the downstream APM published its emitted
  body.

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

3. Run them again with request header restore turned off through the admin runtime. This shows
   the cross-cluster header leak:

   ```bash
   experiment/retry-buffer-failover/run.sh --no-restore
   ```

`captured/` holds the logs of the last runs: e2e results, access and upstream logs, the backends'
view of every attempt, router debug lines and stats.
