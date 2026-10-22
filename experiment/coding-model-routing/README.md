# coding_model: model routing and token management behind a forward proxy

```
agent_registry -> input schema update -> ai_gateway (AIPM) -> model_router (ext_proc)
  -> model_routing_keys -> ai_transcoder (AIPM) -> dynamic forward proxy
```

One `*` route carries all traffic to the dynamic forward proxy, and no route declares an AI
endpoint. What makes a request LLM traffic is the `envoy.ai.llm_protocol.request` filter state
key: agent_registry sets it, and it alone engages both AI Protocol Managers and ext_proc. Every
other request passes through untouched to the host it names. [envoy.yaml](envoy.yaml) runs on
envoy-static with [ext_proc/main.go](ext_proc/main.go) and [mock_vertex.py](mock_vertex.py).

1. `agent_registry` stands in for your filter: a composite filter that, for OpenAI Chat
   Completions requests, sets `envoy.ai.llm_protocol.request: OPENAI_CHAT_COMPLETIONS`.
2. `ai_gateway` engages on that key. It validates the request against its API's schema and
   publishes `envoy.ai.request_info`, with an input token estimate.
3. `model_router` runs ext_proc only where the key is set. ext_proc gets the buffered body and the
   request_info record, and routes `coding_model` to Claude on Vertex AI while the tenant
   (`x-tenant`) has Claude budget left, and to Gemini on Vertex AI after that. Its choice leaves as
   `x-ai-backend-*` request headers, with the backend's credential.
4. `model_routing_keys` stands in for your custom routing filter: it turns those headers into
   `envoy.ai.llm_protocol.response`, `envoy.ai.binding.response` and `envoy.ai.model.resolved`.
5. `ai_transcoder` engages on the same keys. It transcodes the request to the backend's API,
   renders the path from the binding and swaps in the backend model. The dynamic forward proxy
   sends it to the host ext_proc named.
6. On the way back, `ai_transcoder` reads token usage from the backend's own response, in the API
   the filter state names, publishes `envoy.ai.token_usage`, and adds trailers
   (`SYNTHESIZE_TRAILERS`). ext_proc receives the record on them and charges the tenant. The
   client gets an OpenAI response.

The input schema update is your filter; it sits ahead of `ai_gateway`.

## Run

```bash
bazel build //source/exe:envoy-static \
  --override_repository=+envoy_build_config_ext+envoy_build_config=$PWD/experiment/coding-model-routing/build_config \
  --@proxy-wasm-cpp-host//bazel:engine=disabled --//bazel:http3=False
experiment/coding-model-routing/run.sh
```

[build_config/](build_config/) trims the extension set to what envoy.yaml uses. `run.sh` needs Go
and Python 3. It sends three `coding_model` requests and one plain-text request to another service,
and leaves what each side saw in [captured/](captured/): `requests.log` (the client),
`ext_proc.log` (routing and usage), `mock.log` (what the upstreams were sent), `access.log` (one
line per request, with the token usage record) and `envoy.log`.

## Against Vertex AI

Drop `typed_dns_resolver_config`, trust the system CA bundle, run ext_proc without
`-vertex-host`, and have ext_proc (or `gcp_authn`) supply a real access token.
