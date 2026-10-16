# Gemini on Vertex AI to Claude on Vertex AI

A Gemini on Vertex AI client calls `generateContent` or `streamGenerateContent` in its own project
and region, and Claude on Vertex AI answers through `rawPredict` or `streamRawPredict` in the same
project and region. Everything is declared on the route in [envoy.yaml](envoy.yaml), and
`envoy-static` runs it against [mock_vertex.py](mock_vertex.py).

## What happens to a request

1. The client sends
   `POST /v1/projects/acme/locations/us-east5/publishers/google/models/gemini-2.5-flash:generateContent`
   to the gateway.
2. The route declares the client's API (`request.llm_protocol: GEMINI_GENERATE_CONTENT`), the
   backend's (`response.llm_protocol: ANTHROPIC_MESSAGES`), and Claude on Vertex AI's binding
   (`response.binding`). Its `set_filter_state` values name the Claude model that answers.
3. The client-side transcoder reads the path under Envoy's built-in binding for Gemini on Vertex
   AI. The model and the streaming mode go into the body, and the project and location into the
   `envoy.ai.binding.read` filter state object.
4. The backend-side transcoder converts the request to Anthropic Messages and renders the route's
   binding: `/v1/projects/acme/locations/us-east5/publishers/anthropic/models/claude-sonnet-4-5@20250929:rawPredict`,
   with `model` taken out of the body and `anthropic_version: vertex-2023-10-16` added.
5. `header_mutation` names the regional endpoint from the location the transcoder read. The dynamic
   forward proxy rewrites `Host` to it, resolves it, and connects over TLS with the SNI and the
   SAN check of that host.
6. Claude's answer reaches the client as a Gemini `GenerateContentResponse`, or as a Gemini SSE
   stream.

## Run

```bash
bazel build //source/exe:envoy-static
experiment/vertex-gemini-to-claude/run.sh
```

On macOS, two unrelated extensions do not build in a fastbuild at this commit: `splice_pump.h` has
fields only Linux uses, and `-DDEBUG` collides with an enum value in `backtrace_action.cc`. Build
with:

```bash
bazel build //source/exe:envoy-static \
  '--per_file_copt=source/extensions/transport_sockets/dynamic_modules/.*@-Wno-unused-private-field' \
  '--per_file_copt=source/extensions/watchdog/backtrace_action/.*@-UDEBUG'
```

`run.sh` makes the mock's certificates, starts the mock and Envoy, sends
[requests.sh](requests.sh), and leaves what each side saw in [captured/](captured/):

- `requests.log`: what the client got back, and the AI Protocol Manager's counters.
- `mock.log`: what Vertex AI was sent.
- `access.log`: one line per request, with the client's model, project and location, the backend
  model, and the upstream request.
- `envoy.log`: the AI Protocol Manager's debug log.

## Against Vertex AI

Three settings in envoy.yaml, each marked "Local run", serve the mock:

- Remove `typed_dns_resolver_config`, so the system resolver finds the regional endpoint.
- Remove `:8443` from the `x-vertex-host` value.
- Point `trusted_ca` at the system CA bundle, such as `/etc/ssl/certs/ca-certificates.crt`.

Then replace the route's static `authorization` header with the `gcp_authn` filter, which fetches an
access token for the gateway's service account.
