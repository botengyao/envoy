#!/usr/bin/env python3
"""Render what the demo produced: the Director's ledger, Envoy's access logs,
and the counters on both proxies.

Three views, because they answer three different questions:

  --ledger   what was billed      (the Director's own record)
  --access   what Envoy logged    (and what it structurally cannot log)
  --stats    what the filters did (which instance, and how few bytes moved)
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

RUN = os.environ.get("RUN_DIR", "/tmp/token-director")
BOLD, DIM, RED, YEL, RESET = "\033[1m", "\033[2m", "\033[31m", "\033[33m", "\033[0m"

PROXIES = [("dfp", 9901, "dfp_proxy", "dfp_egress"),
           ("tunnel", 9902, "tunnel_proxy", "next_hop_dfp")]


def head(title):
    print(f"\n{BOLD}=== {title} ==={RESET}")


def rows(path):
    out = []
    try:
        with open(path) as f:
            for line in f:
                if line.strip():
                    out.append(json.loads(line))
    except FileNotFoundError:
        pass
    return out


# ---------------------------------------------------------------- ledger

LEDGER_COLS = (f"{'#':<4}{'hop':>7} {'model':<26}{'fr':<5}"
               f"{'in':>6}{'out':>6}{'total':>7}{'est':>6}{'drift':>7}"
               f"{'cache':>6}{'think':>6} {'status':<9}{'cost($)':>10}{'ms':>7}")


def show_ledger(records):
    head("token accounting (Token Director ledger)")
    if not records:
        print("  (empty -- run ./run.sh demo first)")
        return
    print(LEDGER_COLS)
    print("-" * len(LEDGER_COLS))
    for r in records:
        drift = r["estimated_total"] - r["total_tokens"]
        status = r["extraction_status"]
        # Only degraded rows are coloured; a bare reset on every row shows up
        # as noise anywhere the output is captured rather than rendered.
        shown = status.ljust(9) if status == "complete" else f"{YEL}{status:<9}{RESET}"
        # A provider total that disagrees with the canonical sum is worth
        # seeing: it means the extractor and the provider counted different
        # things.
        mismatch = ("provider_total_tokens" in r
                    and r["provider_total_tokens"] != r["total_tokens"])
        print(f"{r['id']:<4}{r['hop']:>7} {r['model'][:26]:<26}"
              f"{'sse' if r['streaming'] else 'json':<5}"
              f"{r['input_tokens']:>6}{r['output_tokens']:>6}{r['total_tokens']:>7}"
              f"{r['estimated_total']:>6}{drift:>+7}"
              f"{r.get('cached_tokens', 0):>6}{r.get('reasoning_tokens', 0):>6} "
              f"{shown}{r['cost_usd']:>10.6f}{r['latency_ms']:>7.0f}"
              f"{'  ← provider says ' + str(r['provider_total_tokens']) if mismatch else ''}")

    # Per-model rollup: the number an operator actually bills on.
    head("per-model totals")
    by_model = {}
    for r in records:
        m = by_model.setdefault(r["model"], {"n": 0, "in": 0, "out": 0, "cost": 0.0})
        m["n"] += 1
        m["in"] += r["input_tokens"]
        m["out"] += r["output_tokens"]
        m["cost"] += r["cost_usd"]
    print(f"{'model':<30}{'reqs':>6}{'input':>9}{'output':>9}{'total':>9}{'cost($)':>11}")
    print("-" * 74)
    for model, m in sorted(by_model.items()):
        print(f"{model[:30]:<30}{m['n']:>6}{m['in']:>9}{m['out']:>9}"
              f"{m['in'] + m['out']:>9}{m['cost']:>11.6f}")
    grand = sum(m["in"] + m["out"] for m in by_model.values())
    cost = sum(m["cost"] for m in by_model.values())
    print("-" * 74)
    print(f"{'ALL':<30}{len(records):>6}{sum(m['in'] for m in by_model.values()):>9}"
          f"{sum(m['out'] for m in by_model.values()):>9}{grand:>9}{cost:>11.6f}")

    # Per-hop: in the tunnel topology both hops account for the same bytes.
    by_hop = {}
    for r in records:
        by_hop.setdefault(r["hop"], []).append(r)
    if len(by_hop) > 1:
        head("per-hop totals (both hops account for the same responses)")
        for hop, rs in sorted(by_hop.items()):
            print(f"  {hop:<8} {len(rs):>3} settled   "
                  f"{sum(x['total_tokens'] for x in rs):>6} tokens   "
                  f"${sum(x['cost_usd'] for x in rs):.6f}")

    # How good the pre-flight bound was. It is a bound, not an estimate of
    # the truth: it should sit above actual, and the gap is the headroom the
    # Director reserved and gave back.
    head("admission estimate vs. actual")
    drifts = [r["estimated_total"] - r["total_tokens"] for r in records]
    inputs = [(r["estimated_total"] - r.get("requested_max_output_tokens", 0), r["input_tokens"])
              for r in records if "requested_max_output_tokens" in r]
    over = sum(1 for d in drifts if d >= 0)
    print(f"  reserved above actual : {over}/{len(drifts)} requests")
    print(f"  mean drift            : {sum(drifts) / len(drifts):+.1f} tokens")
    print(f"  largest over-reserve  : {max(drifts):+d} tokens")
    if min(drifts) >= 0:
        print(f"  tightest margin       : {min(drifts):+d} tokens  "
              f"{DIM}(reservation never fell short){RESET}")
    else:
        print(f"  worst under-reserve   : {min(drifts):+d} tokens  "
              f"{RED}← more was spent than the Director reserved{RESET}")
    if inputs:
        exact = sum(1 for est_in, actual_in in inputs if est_in == actual_in)
        print(f"  input estimate exact  : {exact}/{len(inputs)}"
              f"  {DIM}(the heuristic's own accuracy, output cap excluded){RESET}")
    bad = [r for r in records if r["extraction_status"] != "complete"]
    if bad:
        print(f"  {YEL}degraded extractions  : {len(bad)}{RESET}")


# ---------------------------------------------------------------- access log

def show_access(tail):
    head("envoy access logs")
    any_lines = False
    for name, _, _, _ in PROXIES:
        path = f"{RUN}/{name}-access.log"
        lines = rows(path)
        if not lines:
            continue
        any_lines = True
        shown, total = (lines[-tail:], len(lines)) if tail else (lines, len(lines))
        elided = "" if len(shown) == total else f"  {DIM}(last {len(shown)} of {total}){RESET}"
        print(f"\n  {BOLD}{name}{RESET}  ({path}){elided}")
        lines = shown
        for e in lines:
            ledger = e.get("ledger")
            if isinstance(ledger, dict):
                summary = (f"{ledger.get('model', '?')} "
                           f"in={ledger.get('input_tokens')} out={ledger.get('output_tokens')} "
                           f"total={ledger.get('total_tokens')} "
                           f"${ledger.get('cost_usd', 0):.6f}")
            else:
                summary = f"{DIM}(no ledger -- request not accounted){RESET}"
            print(f"    {e.get('status')} {str(e.get('duration_ms')) + 'ms':>8} "
                  f"{str(e.get('path'))[:44]:<44} {str(e.get('upstream', '-'))[:21]:<21} {summary}")
    if not any_lines:
        print("  (no access log lines yet)")
        return

    # The teaching point: the two typed namespaces are structurally invisible
    # to the access logger, and the ledger beside them is how the same data
    # becomes loggable.
    sample = next((e for e in rows(f"{RUN}/dfp-access.log") if e.get("ledger")), None)
    if sample:
        head("why the ledger field exists")
        print(f"  ai_request_info_typed : {json.dumps(sample.get('ai_request_info_typed'))}"
              f"   {DIM}envoy.ai.request_info{RESET}")
        print(f"  ai_token_usage_typed  : {json.dumps(sample.get('ai_token_usage_typed'))}"
              f"   {DIM}envoy.ai.token_usage{RESET}")
        print(f"  ledger                : populated   {DIM}envoy.token_director{RESET}")
        print(f"\n  {DIM}Both AI records are TYPED dynamic metadata, and no access-log{RESET}")
        print(f"  {DIM}formatter can read typed metadata -- %DYNAMIC_METADATA% is untyped{RESET}")
        print(f"  {DIM}only. The ledger is the Director writing the same numbers back as{RESET}")
        print(f"  {DIM}untyped metadata over ext_proc, which is what makes them loggable.{RESET}")


# ---------------------------------------------------------------- stats

def fetch_stats(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/stats", timeout=2) as r:
            body = r.read().decode()
    except (urllib.error.URLError, OSError):
        return None
    out = {}
    for line in body.splitlines():
        if ": " in line:
            k, _, v = line.partition(": ")
            if v.strip().isdigit():
                out[k] = int(v)
    return out


def show_stats():
    head("envoy counters")
    collected = [(name, fetch_stats(port), prefix, cluster)
                 for name, port, prefix, cluster in PROXIES]
    live = [c for c in collected if c[1] is not None]
    if not live:
        print("  (admin endpoints unreachable -- is the stack up?)")
        return

    def line(label, key_fn, note=""):
        cells = ""
        for _, stats, prefix, cluster in live:
            cells += f"{stats.get(key_fn(prefix, cluster), 0):>14}"
        suffix = f"   {DIM}{note}{RESET}" if note else ""
        print(f"  {label:<34}{cells}{suffix}")

    header = "".join(f"{name:>14}" for name, _, _, _ in live)
    print(f"  {'':<34}{header}")

    print(f"\n  {BOLD}downstream ai_protocol_manager{RESET} {DIM}(request side){RESET}")
    for stat in ("request_info_published", "request_info_protocol_detected", "request_info_empty"):
        line(stat, lambda p, c, s=stat: f"ai_protocol_manager.{s}")

    print(f"\n  {BOLD}upstream ai_protocol_manager{RESET} {DIM}(response side, per cluster){RESET}")
    for stat in ("token_usage_found", "token_usage_partial", "token_usage_missing",
                 "token_usage_total_mismatch", "usage_trailers_synthesized",
                 "unsupported_content_encoding"):
        line(stat, lambda p, c, s=stat: f"cluster.{c}.ai_protocol_manager.{s}")

    print(f"\n  {BOLD}ext_proc ↔ token director{RESET}")
    line("streams_started", lambda p, c: f"http.{p}.ext_proc.token_director.streams_started")
    line("stream_msgs_sent", lambda p, c: f"http.{p}.ext_proc.token_director.stream_msgs_sent",
         "2 per accounted request")
    line("stream_msgs_received",
         lambda p, c: f"http.{p}.ext_proc.token_director.stream_msgs_received")
    line("bytes sent to director", lambda p, c: "cluster.token_director.upstream_cx_tx_bytes_total")
    line("bytes received", lambda p, c: "cluster.token_director.upstream_cx_rx_bytes_total")

    # The headline: no request or response body ever crosses the gRPC boundary,
    # so per-request cost is flat regardless of prompt or generation size.
    for name, stats, prefix, _ in live:
        started = stats.get(f"http.{prefix}.ext_proc.token_director.streams_started", 0)
        tx = stats.get("cluster.token_director.upstream_cx_tx_bytes_total", 0)
        if started:
            print(f"\n  {name}: {tx / started:.0f} bytes per request to the Director "
                  f"{DIM}-- flat, no body in either direction{RESET}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ledger", action="store_true")
    p.add_argument("--access", action="store_true")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--path", default=f"{RUN}/ledger.jsonl")
    p.add_argument("--tail", type=int, default=25,
                   help="access-log lines per proxy; 0 for all")
    args = p.parse_args()
    everything = not (args.ledger or args.access or args.stats)

    if args.ledger or everything:
        show_ledger(rows(args.path))
    if args.access or everything:
        show_access(args.tail)
    if args.stats or everything:
        show_stats()
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
