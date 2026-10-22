# coding_model: model routing and token management around two AI Protocol Managers

```
agent_registry -> input schema update -> ai_gateway (AIPM) -> model_router (ext_proc)
  -> model_routing_keys -> ai_transcoder (AIPM) -> dynamic forward proxy -> Vertex AI
```

Clients send OpenAI Chat Completions requests for `coding_model`. [envoy.yaml](envoy.yaml) runs on
envoy-static with [ext_proc/main.go](ext_proc/main.go) and [mock_vertex.py](mock_vertex.py).

1. `ai_gateway` validates the request against its API's schema and publishes
   `envoy.ai.request_info`, with an input token estimate.
2. `model_router` (ext_proc) gets the buffered body with that record. It routes `coding_model` to
   Claude on Vertex AI while the tenant (`x-tenant`) has Claude budget left, and to Gemini on
   Vertex AI after that. Its choice leaves as `x-ai-backend-*` request headers.
3. `model_routing_keys` stands in for a custom routing filter: it turns those headers into the
   filter state keys `envoy.ai.llm_protocol.response`, `envoy.ai.binding.response` and
   `envoy.ai.model.resolved`.
4. `ai_transcoder` transcodes the request to the backend's API, renders the path from the binding,
   and swaps in the backend model. The dynamic forward proxy sends it to the regional endpoint.
5. On the way back, `ai_transcoder` reads token usage from the backend's own response, in the API
   the filter state names. It publishes `envoy.ai.token_usage` and adds trailers
   (`SYNTHESIZE_TRAILERS`). ext_proc receives the record on those trailers and charges the tenant.
   The client gets an OpenAI response.

The agent registry and the input schema update are your filters; they sit ahead of `ai_gateway`.

## Run

```bash
bazel build //source/exe:envoy-static \
  --override_repository=+envoy_build_config_ext+envoy_build_config=$PWD/experiment/coding-model-routing/build_config \
  --@proxy-wasm-cpp-host//bazel:engine=disabled --//bazel:http3=False
experiment/coding-model-routing/run.sh
```

[build_config/](build_config/) trims the extension set to what envoy.yaml uses. `run.sh` needs Go
and Python 3. It leaves what each side saw in [captured/](captured/): `requests.log` (the client),
`ext_proc.log` (routing and usage), `mock.log` (what Vertex AI was sent), `access.log` (one line
per request, with the token usage record) and `envoy.log`.

## Against Vertex AI

Drop `typed_dns_resolver_config`, trust the system CA bundle, run ext_proc without
`-vertex-host`, and replace the route's static `authorization` header with the `gcp_authn` filter.
