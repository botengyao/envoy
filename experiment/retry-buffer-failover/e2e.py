#!/usr/bin/env python3
"""E2E cases for the retry-buffer failover prototype; run through run.sh."""

import argparse
import hashlib
import http.client
import json
import os
import sys
import time

RUN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run")
UPSTREAM_LOG, DOWNSTREAM_LOG, CONTROL = 19000, 19004, 19002
DOWNSTREAM_LOG_UPSTREAM_BORROW, CAPPED_LOG = 19006, 19008
# Must match rewrittenBody in pdp/main.go.
PDP_REWRITTEN = (b'{"contents":[{"role":"user","parts":[{"text":"rewritten by the routing PDP"}]}]}')
BIG = 4 * 1024 * 1024


def gemini_path(model="gemini-2.5-flash"):
    return f"/v1beta/models/{model}:generateContent"


def vertex_path(model="gemini-2.5-flash"):
    return (f"/v1/projects/test-project/locations/us-central1/publishers/google/models/"
            f"{model}:generateContent")


def body_of(size):
    text = "hello from the client. "
    padding = "x" * max(0, size - 200)
    doc = {"contents": [{"role": "user", "parts": [{"text": text + padding}]}],
           "generationConfig": {"temperature": 0.2}}
    return json.dumps(doc).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def send(port, name, behavior, body, extra_headers=None, chunked=False, model="gemini-2.5-flash"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    headers = {"content-type": "application/json", "x-test-name": name,
               "x-test-behavior": behavior}
    headers.update(extra_headers or {})
    if chunked:
        def chunks():
            for i in range(0, len(body), 64 * 1024):
                yield body[i:i + 64 * 1024]
        conn.request("POST", gemini_path(model), body=chunks(), headers=headers,
                     encode_chunked=True)
    else:
        conn.request("POST", gemini_path(model), body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def records(name):
    rows = []
    for backend in ("gemini", "vertex"):
        path = os.path.join(RUN, f"{backend}.jsonl")
        if os.path.exists(path):
            with open(path) as f:
                rows += [r for r in map(json.loads, f) if r.get("test") == name]
    return sorted(rows, key=lambda r: r["ts"])


def stat(name):
    conn = http.client.HTTPConnection("127.0.0.1", 19901, timeout=5)
    conn.request("GET", "/stats?format=json&filter=" + name)
    stats = json.loads(conn.getresponse().read())["stats"]
    conn.close()
    return sum(s.get("value", 0) for s in stats if s.get("name", "").endswith(name))


def envoy_log_count(text):
    with open(os.path.join(RUN, "envoy.log")) as f:
        return sum(text in line for line in f)


results = []


def check(case, label, ok, detail=""):
    results.append((case, label, bool(ok), detail))


def check_attempt(case, rec, expected_sha, expected_len, model):
    backend = rec["backend"]
    check(case, f"{backend} got the router's bytes",
          rec["body_sha256"] == expected_sha and rec["body_len"] == expected_len,
          f"{rec['body_len']} bytes")
    host = ("generativelanguage.googleapis.com" if backend == "gemini" else
            "us-central1-aiplatform.googleapis.com")
    path = gemini_path(model) if backend == "gemini" else vertex_path(model)
    check(case, f"{backend} SNI, host, path", rec["sni"] == rec["host"] == host and
          rec["path"] == path, f"sni={rec['sni']} path={rec['path'][:48]}")
    if backend == "gemini":
        ok = rec["x-goog-api-key"] and not rec["authorization"]
    else:
        ok = (rec["authorization"] or "").startswith("Bearer ") and not rec["x-goog-api-key"]
    check(case, f"{backend} own credential only", ok,
          f"key={bool(rec['x-goog-api-key'])} authz={bool(rec['authorization'])}")


def failover(case, port, behavior, served_by, attempts, body, sent=None, extra=None,
             chunked=False, model="gemini-2.5-flash", exact=True):
    """`sent` is what the router forwards when a filter ahead of it replaces the client's body.
    Without `exact` the router's bytes are not known up front (a re-serializing APM ahead of it),
    so every attempt must carry the same bytes as the first."""
    sent = body if sent is None else sent
    started = time.time()
    status, data = send(port, case, behavior, body, extra, chunked, model)
    elapsed = time.time() - started
    time.sleep(0.3)
    recs = records(case)
    check(case, "status 200", status == 200, f"{status} {data[:100]!r} in {elapsed:.2f}s")
    check(case, f"served by {served_by}", f"served by {served_by}".encode() in data)
    check(case, "attempt order", [r["backend"] for r in recs] == attempts,
          str([r["backend"] for r in recs]))
    full = [r for r in recs if not r.get("early_reset")]
    if not exact and full:
        check(case, "every attempt got the same bytes",
              len({(r["body_sha256"], r["body_len"]) for r in full}) == 1,
              str({(r["body_sha256"][:12], r["body_len"]) for r in full}))
    for rec in full:
        expected = (sha(sent), len(sent)) if exact else (full[0]["body_sha256"], full[0]["body_len"])
        check_attempt(case, rec, expected[0], expected[1], model)


def run_cases(port, tag, exact):
    small, big = body_of(1024), body_of(BIG)
    failover(f"failover-429-{tag}", port, "gemini=429;vertex=200", "vertex",
             ["gemini", "vertex"], small, exact=exact)
    failover(f"failover-4MiB-{tag}", port, "gemini=429;vertex=200", "vertex",
             ["gemini", "vertex"], big, exact=exact)
    failover(f"failover-4MiB-chunked-{tag}", port, "gemini=503;vertex=200", "vertex",
             ["gemini", "vertex"], big, chunked=True, exact=exact)
    # The PDP replaces the body after the downstream APM: every attempt carries the PDP's body.
    failover(f"pdp-rewrites-body-{tag}", port, "gemini=429;vertex=200", "vertex",
             ["gemini", "vertex"], big, sent=PDP_REWRITTEN, extra={"x-pdp-rewrite-body": "1"})
    failover(f"pdp-rewrites-body-reset-{tag}", port, "gemini=reset-early;vertex=200", "vertex",
             ["gemini", "vertex"], big, sent=PDP_REWRITTEN, extra={"x-pdp-rewrite-body": "1"})
    # A filter between the APM and the router rewrites the body; it buffers the whole body, so
    # it stays under the 32 KiB connection limit.
    mutable = body_of(16 * 1024)
    failover(f"lua-rewrites-body-{tag}", port, "gemini=429;vertex=200", "vertex",
             ["gemini", "vertex"], mutable, sent=mutable.replace(b"hello", b"HELLO"),
             extra={"x-test-mutate-body": "1"}, exact=exact)
    # Attempt 1 is reset while the body is still streaming; the router keeps logging it.
    failover(f"reset-mid-upload-64MiB-{tag}", port, "gemini=reset-early;vertex=200", "vertex",
             ["gemini", "vertex"], body_of(16 * BIG), exact=exact)
    failover(f"pdp-reverse-{tag}", port, "vertex=503;gemini=200", "gemini", ["vertex", "gemini"],
             big, extra={"x-pdp-order": "vertex,gemini"}, exact=exact)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--restore", default="true")
    args = parser.parse_args()

    if args.restore != "true":
        # Header restore off. The cluster chains rebuild :path and drop the other provider's
        # credential themselves, so failover stays clean without the router's help.
        # captured/e2e_no_restore_naive_chains.log is the same run with chains that do not.
        failover("no-restore-429", UPSTREAM_LOG, "gemini=429;vertex=200", "vertex",
                 ["gemini", "vertex"], body_of(1024))
        failover("no-restore-reverse", UPSTREAM_LOG, "vertex=503;gemini=200", "gemini",
                 ["vertex", "gemini"], body_of(1024), extra={"x-pdp-order": "vertex,gemini"})
        return report()

    logged = stat("retry_body_logged")
    borrowed = envoy_log_count("reading the payload back from the router's request body log")

    failover("baseline", UPSTREAM_LOG, "gemini=200", "gemini", ["gemini"], body_of(1024))
    run_cases(UPSTREAM_LOG, "upstream-log", exact=True)
    failover("pdp-model-policy", UPSTREAM_LOG, "vertex=429;gemini=200", "gemini",
             ["vertex", "gemini"], body_of(BIG), model="gemini-2.5-pro")
    # This listener's APM re-serializes the body, so the router's bytes are its output.
    run_cases(DOWNSTREAM_LOG, "downstream-log", exact=False)
    run_cases(DOWNSTREAM_LOG_UPSTREAM_BORROW, "downstream-lends-upstream-borrows", exact=True)

    # A 1 MiB log. A body known to fit is retried from it; a longer one is left to the in-memory
    # buffer, which gives up on it as it does today; a chunked one fails the log at 1 MiB, and the
    # first attempt's own answer reaches the client.
    failover("capped-fits", CAPPED_LOG, "gemini=429;vertex=200", "vertex", ["gemini", "vertex"],
             body_of(512 * 1024))
    for case, chunked in (("capped-too-long", False), ("capped-too-long-chunked", True)):
        failed = stat("retry_body_log_failed")
        status, _ = send(CAPPED_LOG, case, "gemini=429;vertex=200", body_of(BIG), chunked=chunked)
        time.sleep(0.3)
        recs = records(case)
        check(case, "no retry, the client gets gemini's 429", status == 429, str(status))
        check(case, "gemini got the whole body",
              [r["backend"] for r in recs] == ["gemini"] and
              recs[0]["body_sha256"] == sha(body_of(BIG)), str([r["backend"] for r in recs]))
        if chunked:
            check(case, "log failure counted", stat("retry_body_log_failed") - failed == 1)

    status, _ = send(UPSTREAM_LOG, "both-fail", "gemini=429;vertex=503", body_of(1024))
    time.sleep(0.3)
    order = [r["backend"] for r in records("both-fail")]
    check("both-fail", "last attempt's 503 reaches the client", status == 503, str(status))
    check("both-fail", "three attempts, last group repeated", order == ["gemini", "vertex", "vertex"],
          str(order))

    check("log", "router wrote a request body log for every retried request",
          stat("retry_body_logged") - logged >= 27, f"{stat('retry_body_logged') - logged}")
    borrowed = envoy_log_count(
        "reading the payload back from the router's request body log") - borrowed
    # Bodies within the APM's 32 KiB in-memory tier never reach a store; the larger attempts on
    # the upstream-log listener all read from the log rather than storing a copy.
    check("log", "upstream APM read its payload from the log on large attempts", borrowed >= 18,
          f"{borrowed} attempts")
    check("log", "no replay errors or mismatches",
          stat("retry_body_replay_error") + stat("retry_body_replay_mismatch") == 0)

    # Control: no log, today's in-memory retry buffer capped by the 32 KiB connection limit.
    failover("control-small", CONTROL, "gemini=429;vertex=200", "vertex", ["gemini", "vertex"],
             body_of(1024))
    abandoned = stat("retry_or_shadow_abandoned")
    status, _ = send(CONTROL, "control-4MiB", "gemini=429;vertex=200", body_of(BIG))
    time.sleep(0.3)
    check("control-4MiB", "retry abandoned for size, client gets 429", status == 429, str(status))
    check("control-4MiB", "vertex never called",
          [r["backend"] for r in records("control-4MiB")] == ["gemini"])
    check("control-4MiB", "abandon counted", stat("retry_or_shadow_abandoned") - abandoned >= 1)
    return report()


def report():
    width = max(len(c) for c, *_ in results)
    failed = 0
    for case, label, ok, detail in results:
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {case:<{width}}  {label}" +
              (f"  [{detail}]" if detail else ""))
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
