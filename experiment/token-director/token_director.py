#!/usr/bin/env python3
"""Token Director: an ext_proc server that admits AI requests against a token
budget and settles them against the usage Envoy extracted from the response.

It never sees a request or response body. Everything it needs arrives as typed
dynamic metadata in ``ProcessingRequest.metadata_context``:

  request_headers   <- envoy.ai.request_info  (envoy.data.ai.v3.RequestInfo)
                       model, streaming, requested max output, pre-flight
                       input estimate. Published by ai_protocol_manager after
                       it parsed the payload and before it replayed it, so it
                       is already present on the first message of the stream.

  response_trailers <- envoy.ai.token_usage   (envoy.data.ai.v3.TokenUsage)
                       provider-reported counts, normalized. Published by the
                       upstream ai_protocol_manager instance at a clean end of
                       stream, just before this message is built.

The reservation made at admission is released and replaced by the real counts
at settlement, and the reconciled record is written back as untyped dynamic
metadata (envoy.token_director) so it shows up in Envoy's access log.
"""
import argparse
import json
import os
import sys
import threading
import time
from collections import defaultdict

import grpc

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "pb"))

from envoy.service.ext_proc.v3 import external_processor_pb2 as ep
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc as ep_grpc
from envoy.data.ai.v3 import request_info_pb2 as ai_req
from envoy.data.ai.v3 import token_usage_pb2 as ai_usage
from envoy.type.v3 import http_status_pb2

REQUEST_INFO_NS = "envoy.ai.request_info"
TOKEN_USAGE_NS = "envoy.ai.token_usage"
LEDGER_NS = "envoy.token_director"

PROTOCOL_NAMES = {
    0: "unspecified",
    1: "openai_chat_completions",
    2: "openai_responses",
    3: "anthropic_messages",
    4: "gemini_generate_content",
}
STATUS_NAMES = {0: "unspecified", 1: "complete", 2: "partial", 3: "failed"}

# Illustrative only -- USD per 1M tokens, (input, output).
PRICES = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4.1-mini": (0.40, 1.60),
    "claude-haiku-4-5": (1.00, 5.00),
    "gemini-2.5-flash": (0.30, 2.50),
}


def price_for(model):
    for prefix, price in PRICES.items():
        if model.startswith(prefix):
            return price
    return (0.0, 0.0)


class Budget:
    """Per-model token budget with in-flight reservations.

    Admission charges the estimate up front so concurrent requests cannot each
    see the same headroom; settlement swaps the estimate for the real count.
    """

    def __init__(self, per_model_limit):
        self._lock = threading.Lock()
        self._limit = per_model_limit
        self._spent = defaultdict(int)
        self._reserved = defaultdict(int)

    def reserve(self, model, amount):
        with self._lock:
            committed = self._spent[model] + self._reserved[model]
            if committed + amount > self._limit:
                return False, self._limit - committed
            self._reserved[model] += amount
            return True, self._limit - committed - amount

    def settle(self, model, reserved, actual):
        with self._lock:
            self._reserved[model] = max(0, self._reserved[model] - reserved)
            self._spent[model] += actual
            return self._limit - self._spent[model] - self._reserved[model]

    def snapshot(self):
        with self._lock:
            return {
                m: {"spent": self._spent[m], "reserved": self._reserved[m], "limit": self._limit}
                for m in set(self._spent) | set(self._reserved)
            }


def unpack_typed(metadata_context, namespace, message):
    """Pull one typed metadata record out of a ProcessingRequest."""
    any_msg = metadata_context.typed_filter_metadata.get(namespace)
    if any_msg is None:
        return None
    if not any_msg.Unpack(message):
        return None
    return message


def u64(wrapper_field, present):
    return wrapper_field.value if present else None


class TokenDirector(ep_grpc.ExternalProcessorServicer):
    def __init__(self, budget, ledger_path, verbose):
        self._budget = budget
        self._ledger_path = ledger_path
        self._verbose = verbose
        self._seq = 0
        self._seq_lock = threading.Lock()

    def _next_id(self):
        with self._seq_lock:
            self._seq += 1
            return self._seq

    def Process(self, request_iterator, context):
        hop = "unknown"
        for key, value in context.invocation_metadata():
            if key == "x-hop":
                hop = value

        state = {
            "id": self._next_id(),
            "hop": hop,
            "model": "",
            "protocol": "",
            "streaming": False,
            "estimate": 0,
            "reserved": 0,
            "path": "",
            "start": time.time(),
        }

        for req in request_iterator:
            kind = req.WhichOneof("request")
            if kind == "request_headers":
                yield self._on_request_headers(req, state)
            elif kind == "response_trailers":
                yield self._on_response_trailers(req, state)
            else:
                # Nothing else is subscribed to, but a stream must stay in
                # lockstep: every message gets exactly one response.
                yield self._empty_response(kind)

    # ---- request path: admission ----------------------------------------

    def _on_request_headers(self, req, state):
        headers = {h.key: (h.raw_value.decode() if h.raw_value else h.value)
                   for h in req.request_headers.headers.headers}
        state["path"] = headers.get(":path", "")

        info = unpack_typed(req.metadata_context, REQUEST_INFO_NS, ai_req.RequestInfo())
        if info is None:
            # Not an AI endpoint (or the filter published nothing): admit
            # without touching the budget.
            self._log(state, "admit", "no request_info; not an AI endpoint")
            return ep.ProcessingResponse(request_headers=ep.HeadersResponse())

        state["model"] = info.model
        state["protocol"] = PROTOCOL_NAMES.get(info.api_protocol, str(info.api_protocol))
        state["streaming"] = info.streaming
        estimated_input = info.estimated_input_tokens.value if info.HasField(
            "estimated_input_tokens") else 0
        max_output = info.requested_max_output_tokens.value if info.HasField(
            "requested_max_output_tokens") else 0
        # Worst case for this request: everything it may consume.
        estimate = estimated_input + max_output
        state["estimate"] = estimate
        state["estimated_input"] = estimated_input
        state["max_output"] = max_output

        admitted, headroom = self._budget.reserve(info.model, estimate)
        if not admitted:
            self._log(state, "deny",
                      f"estimate {estimate} exceeds headroom {headroom} for {info.model}")
            return ep.ProcessingResponse(
                immediate_response=ep.ImmediateResponse(
                    status=http_status_pb2.HttpStatus(code=429),
                    # ImmediateResponse.body is `bytes` on the wire.
                    body=json.dumps({
                        "error": {
                            "type": "token_budget_exceeded",
                            "message": (f"model {info.model}: estimated {estimate} tokens "
                                        f"exceeds remaining budget {max(0, headroom)}"),
                        }
                    }).encode(),
                    details="token_director_budget_exceeded",
                ))

        state["reserved"] = estimate
        self._log(state, "admit",
                  f"reserved {estimate} (est_in={estimated_input}, max_out={max_output}), "
                  f"headroom {headroom}")

        # Hand the decision to the upstream so the provider-side hop (and any
        # later filter) can see what was admitted.
        return ep.ProcessingResponse(
            request_headers=ep.HeadersResponse(
                response=ep.CommonResponse(
                    header_mutation=ep.HeaderMutation(
                        set_headers=[
                            _header("x-token-director-decision", "admit"),
                            _header("x-token-director-estimate", str(estimate)),
                        ]))))

    # ---- response path: settlement --------------------------------------

    def _on_response_trailers(self, req, state):
        usage = unpack_typed(req.metadata_context, TOKEN_USAGE_NS, ai_usage.TokenUsage())
        response = ep.ProcessingResponse(response_trailers=ep.TrailersResponse())

        if usage is None:
            if state["reserved"]:
                headroom = self._budget.settle(state["model"], state["reserved"], 0)
                self._log(state, "settle-empty",
                          f"no usage record; released {state['reserved']}, headroom {headroom}")
            return response

        actual_in = usage.input_tokens.value if usage.HasField("input_tokens") else 0
        actual_out = usage.output_tokens.value if usage.HasField("output_tokens") else 0
        actual_total = usage.total_tokens.value if usage.HasField("total_tokens") else (
            actual_in + actual_out)
        headroom = self._budget.settle(state["model"] or usage.model, state["reserved"],
                                       actual_total)

        in_price, out_price = price_for(usage.model or state["model"])
        cost = (actual_in * in_price + actual_out * out_price) / 1_000_000

        record = {
            "id": state["id"],
            "hop": state["hop"],
            "path": state["path"],
            "model": usage.model or state["model"],
            "api_protocol": PROTOCOL_NAMES.get(usage.api_protocol, str(usage.api_protocol)),
            "streaming": state["streaming"],
            "estimated_total": state["estimate"],
            "estimated_input_tokens": state.get("estimated_input", 0),
            "requested_max_output_tokens": state.get("max_output", 0),
            "input_tokens": actual_in,
            "output_tokens": actual_out,
            "total_tokens": actual_total,
            "extraction_status": STATUS_NAMES.get(usage.extraction_status,
                                                  str(usage.extraction_status)),
            "cost_usd": round(cost, 6),
            "headroom": headroom,
            "latency_ms": round((time.time() - state["start"]) * 1000, 1),
        }
        if usage.HasField("provider_total_tokens"):
            record["provider_total_tokens"] = usage.provider_total_tokens.value
        if usage.HasField("input_token_details"):
            d = usage.input_token_details
            if d.HasField("cached_tokens"):
                record["cached_tokens"] = d.cached_tokens.value
            if d.HasField("cache_creation_tokens"):
                record["cache_creation_tokens"] = d.cache_creation_tokens.value
        if usage.HasField("output_token_details") and usage.output_token_details.HasField(
                "reasoning_tokens"):
            record["reasoning_tokens"] = usage.output_token_details.reasoning_tokens.value

        drift = state["estimate"] - actual_total
        self._log(state, "settle",
                  f"in={actual_in} out={actual_out} total={actual_total} "
                  f"({record['extraction_status']}) est_drift={drift:+d} "
                  f"cost=${record['cost_usd']:.6f} headroom={headroom}")
        self._append_ledger(record)

        # Write the reconciled record back as untyped metadata so it reaches
        # the access log, which cannot read the typed records above.
        for key, value in record.items():
            response.dynamic_metadata.fields[LEDGER_NS].struct_value.fields[key].MergeFrom(
                _value(value))
        return response

    # ---- plumbing -------------------------------------------------------

    def _empty_response(self, kind):
        if kind == "request_body":
            return ep.ProcessingResponse(request_body=ep.BodyResponse())
        if kind == "response_body":
            return ep.ProcessingResponse(response_body=ep.BodyResponse())
        if kind == "response_headers":
            return ep.ProcessingResponse(response_headers=ep.HeadersResponse())
        if kind == "request_trailers":
            return ep.ProcessingResponse(request_trailers=ep.TrailersResponse())
        return ep.ProcessingResponse(response_trailers=ep.TrailersResponse())

    def _log(self, state, action, detail):
        print(f"[{state['hop']:>6}] #{state['id']:<4} {action:<13} "
              f"{state['model'] or '-':<28} {detail}", flush=True)

    def _append_ledger(self, record):
        with open(self._ledger_path, "a") as f:
            f.write(json.dumps(record) + "\n")


def _header(key, value):
    from envoy.config.core.v3 import base_pb2
    return base_pb2.HeaderValueOption(
        header=base_pb2.HeaderValue(key=key, raw_value=value.encode()))


def _value(v):
    from google.protobuf import struct_pb2
    out = struct_pb2.Value()
    if isinstance(v, bool):
        out.bool_value = v
    elif isinstance(v, (int, float)):
        out.number_value = v
    else:
        out.string_value = str(v)
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--budget", type=int, default=100_000,
                        help="per-model token budget for the process lifetime")
    parser.add_argument("--ledger", default="/tmp/token-director/ledger.jsonl")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.ledger), exist_ok=True)
    server = grpc.server(__import__("concurrent.futures", fromlist=["x"]).ThreadPoolExecutor(
        max_workers=16))
    ep_grpc.add_ExternalProcessorServicer_to_server(
        TokenDirector(Budget(args.budget), args.ledger, args.verbose), server)
    server.add_insecure_port(f"127.0.0.1:{args.port}")
    server.start()
    print(f"token director listening on 127.0.0.1:{args.port} "
          f"(budget {args.budget} tokens/model, ledger {args.ledger})", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    main()
