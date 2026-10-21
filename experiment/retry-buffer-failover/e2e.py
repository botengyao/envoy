#!/usr/bin/env python3
"""E2E cases for the retry-buffer failover prototype; run through run.sh."""

import argparse
import hashlib
import re
import http.client
import json
import os
import sys
import time

RUN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run")
CONTROL = 19002
# The router keeps no copy (limit 0), or bodies up to 1 MiB.
UPSTREAM_SESSION, SESSION_GRADED = 19010, 19012
# The same without the PDP, so nothing holds the headers ahead of the router.
SESSION_DIRECT, SESSION_DIRECT_GRADED = 19014, 19016
SESSION_LISTENERS = {UPSTREAM_SESSION: ("upstream_session", 0),
                     SESSION_GRADED: ("upstream_session_graded", 1024 * 1024),
                     SESSION_DIRECT: ("upstream_session_direct", 0),
                     SESSION_DIRECT_GRADED: ("upstream_session_direct_graded", 1024 * 1024)}
HANDED_OVER = re.compile(rb"handing the request body over to the retry session after (\d+) bytes")
ROUTER_WRITES = re.compile(rb"writing the request body to the retry session from byte (\d+)")
# Must match rewrittenBody in pdp/main.go.
PDP_REWRITTEN = (b'{"contents":[{"role":"user","parts":[{"text":"rewritten by the routing PDP"}]}]}')
BIG = 4 * 1024 * 1024
RESTORE_GUARD = "envoy.reloadable_features.restore_request_headers_on_cross_cluster_retry"


def method(stream):
    return "streamGenerateContent?alt=sse" if stream else "generateContent"


def gemini_path(model="gemini-2.5-flash", stream=False):
    return f"/v1beta/models/{model}:{method(stream)}"


def vertex_path(model="gemini-2.5-flash", stream=False):
    return (f"/v1/projects/test-project/locations/us-central1/publishers/google/models/"
            f"{model}:{method(stream)}")


def body_of(size, generation_config=None):
    text = "hello from the client. "
    padding = "x" * max(0, size - 200)
    doc = {"contents": [{"role": "user", "parts": [{"text": text + padding}]}],
           "generationConfig": generation_config or {"temperature": 0.2}}
    return json.dumps(doc).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical_sha(data):
    """Must match canonical() in mock_llm.py."""
    return sha(json.dumps(json.loads(data), sort_keys=True, separators=(",", ":")).encode())


def send(port, name, behavior, body, extra_headers=None, chunked=False, model="gemini-2.5-flash",
         stream=False):
    """Returns the status, the body and the content type of the answer."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    headers = {"content-type": "application/json", "x-test-name": name,
               "x-test-behavior": behavior}
    headers.update(extra_headers or {})
    path = gemini_path(model, stream)
    if chunked:
        def chunks():
            for i in range(0, len(body), 64 * 1024):
                yield body[i:i + 64 * 1024]
        conn.request("POST", path, body=chunks(), headers=headers, encode_chunked=True)
    else:
        conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data, resp.getheader("content-type") or ""


def first_candidate(doc):
    return (doc.get("candidates") or [{}])[0]


def check_answer(case, data, content_type, served_by, stream):
    """A unary answer is one finished JSON document; a streamed one is at least two events, the
    last finished with usage. Either way its text is exactly the backend's."""
    if stream:
        check(case, "an event stream", content_type.startswith("text/event-stream"), content_type)
        docs = []
        for line in data.splitlines():
            if line.startswith(b"data:"):
                try:
                    docs.append(json.loads(line[len(b"data:"):]))
                except ValueError:
                    check(case, "well-formed events", False, line[:80])
        last = docs[-1] if docs else {}
        check(case, "two events or more, the last finished with usage",
              len(docs) >= 2 and first_candidate(last).get("finishReason") == "STOP" and
              "usageMetadata" in last, f"{len(docs)} events")
        expected = f"served by {served_by}."
    else:
        check(case, "a JSON answer", content_type.startswith("application/json"), content_type)
        try:
            docs = [json.loads(data)]
        except ValueError:
            docs = []
        check(case, "finished", bool(docs) and first_candidate(docs[0]).get("finishReason") == "STOP")
        expected = f"served by {served_by}"
    text = "".join(part.get("text", "") for doc in docs for cand in doc.get("candidates", [])
                   for part in cand.get("content", {}).get("parts", []))
    check(case, f"served by {served_by}", text == expected, text[:40])


def access_rows(name):
    with open(os.path.join(RUN, "access.log")) as f:
        return [r for r in map(json.loads, f) if r.get("test") == name]


def records(name):
    rows = []
    for backend in ("gemini", "vertex"):
        path = os.path.join(RUN, f"{backend}.jsonl")
        if os.path.exists(path):
            with open(path) as f:
                rows += [r for r in map(json.loads, f) if r.get("test") == name]
    return sorted(rows, key=lambda r: r["ts"])


def admin(path):
    conn = http.client.HTTPConnection("127.0.0.1", 19901, timeout=5)
    conn.request("GET", path)
    data = json.loads(conn.getresponse().read())
    conn.close()
    return data


def stat(name):
    stats = admin("/stats?format=json&filter=" + name)["stats"]
    return sum(s.get("value", 0) for s in stats if s.get("name", "").endswith(name))


def runtime_value(key):
    return admin("/runtime?format=json")["entries"].get(key, {}).get("final_value")


def log_mark():
    return os.path.getsize(os.path.join(RUN, "envoy.log"))


def log_since(mark):
    with open(os.path.join(RUN, "envoy.log"), "rb") as f:
        f.seek(mark)
        return f.read()


def log_count_since(mark, text):
    return log_since(mark).count(text.encode())


results = []


def check(case, label, ok, detail=""):
    results.append((case, label, bool(ok), detail))


def check_attempt(case, rec, expected_canonical, model, stream):
    backend = rec["backend"]
    check(case, f"{backend} got the router's document", rec["canonical_sha256"] == expected_canonical,
          f"{rec['body_len']} bytes")
    host = ("generativelanguage.googleapis.com" if backend == "gemini" else
            "us-central1-aiplatform.googleapis.com")
    path = gemini_path(model, stream) if backend == "gemini" else vertex_path(model, stream)
    check(case, f"{backend} SNI, host, path", rec["sni"] == rec["host"] == host and
          rec["path"] == path, f"sni={rec['sni']} path={rec['path'][-48:]}")
    if backend == "gemini":
        ok = rec["x-goog-api-key"] == "test-gemini-api-key" and not rec["authorization"]
    else:
        ok = rec["authorization"] == "Bearer test-vertex-access-token" and not rec["x-goog-api-key"]
    check(case, f"{backend} own credential only", ok,
          f"key={bool(rec['x-goog-api-key'])} authz={bool(rec['authorization'])}")


def failover(case, port, behavior, served_by, attempts, body, sent=None, extra=None,
             chunked=False, model="gemini-2.5-flash", stream=False, same_bytes=True):
    """`sent` is the document the router forwards when a filter ahead of it replaces the client's
    body. Each provider cluster may re-serialize it on the way out, so attempts are compared by
    their canonical JSON, and attempts to one backend through the same chain (`same_bytes`) must
    also carry the same bytes."""
    sent = body if sent is None else sent
    started = time.time()
    status, data, content_type = send(port, case, behavior, body, extra, chunked, model, stream)
    elapsed = time.time() - started
    time.sleep(0.3)
    recs = records(case)
    check(case, "status 200", status == 200, f"{status} {data[:100]!r} in {elapsed:.2f}s")
    check_answer(case, data, content_type, served_by, stream)
    check(case, "attempt order", [r["backend"] for r in recs] == attempts,
          str([r["backend"] for r in recs]))
    full = [r for r in recs if not r.get("early_reset") and not r.get("truncated")]
    for backend in ("gemini", "vertex") if same_bytes else ():
        seen = {(r["body_sha256"], r["body_len"]) for r in full if r["backend"] == backend}
        if len(seen) > 1:
            check(case, f"every {backend} attempt got the same bytes", False, str(seen))
    for rec in full:
        check_attempt(case, rec, canonical_sha(sent), model, stream)


def groups(*names):
    return {"x-pdp-groups": json.dumps([{"name": n} for n in names])}


def walks(prefix, port):
    """Failover walks that stay clean whether or not the router restores the request headers; run
    in both modes."""
    failover(f"{prefix}-429", port, "gemini=429;vertex=200", "vertex", ["gemini", "vertex"],
             body_of(1024))
    failover(f"{prefix}-reverse", port, "vertex=503;gemini=200", "gemini", ["vertex", "gemini"],
             body_of(1024), extra={"x-pdp-order": "vertex,gemini"})
    failover(f"{prefix}-three-step", port, "gemini=429|200;vertex=503", "gemini",
             ["gemini", "vertex", "gemini"], body_of(1024), extra=groups("gemini", "vertex", "gemini"))
    failover(f"{prefix}-three-step-reverse", port, "vertex=429|200;gemini=503", "vertex",
             ["vertex", "gemini", "vertex"], body_of(1024), extra=groups("vertex", "gemini", "vertex"))
    failover(f"{prefix}-same-cluster", port, "vertex=503|429|200", "vertex",
             ["vertex", "vertex", "vertex"], body_of(1024), extra=groups("vertex"))
    failover(f"{prefix}-4MiB", port, "vertex=503;gemini=200", "gemini", ["vertex", "gemini"],
             body_of(BIG), extra={"x-pdp-order": "vertex,gemini"})
    failover(f"{prefix}-stream", port, "vertex=429;gemini=200", "gemini", ["vertex", "gemini"],
             body_of(1024), extra={"x-pdp-order": "vertex,gemini"}, stream=True)


def session_stats(port):
    name = SESSION_LISTENERS[port][0]
    return {
        "handed_over": stat(f"http.{name}.retry_session_handed_over"),
        "incomplete": stat(f"http.{name}.retry_session_incomplete"),
        "not_adopted": stat(f"http.{name}.retry_session_not_adopted"),
        "failed": stat(f"http.{name}.retry_session_failed"),
        "adopted": stat("request_session_adopted"),
        "reparsed": stat("request_session_reparsed"),
        # The provider clusters' upstream APMs, not the downstream one.
        "parsed": sum(stat(f"cluster.{c}.ai_protocol_manager.request_parsed")
                      for c in ("gemini", "vertex", "gemini_refused")),
    }


def session_failover(case, port, behavior, served_by, attempts, body, **kwargs):
    """A failover on a session listener, checked for the hand-over, one parse for the whole request
    and every retry adopting the session."""
    before = session_stats(port)
    mark = log_mark()
    failover(case, port, behavior, served_by, attempts, body, **kwargs)
    after = session_stats(port)
    delta = {k: after[k] - before[k] for k in after}
    limit = SESSION_LISTENERS[port][1]
    handed = len(kwargs.get("sent") or body) > limit
    retries = len(attempts) - 1
    check(case, "handed over to the session" if handed else "kept by the router",
          delta["handed_over"] == int(handed), str(delta))
    check(case, "never short of the body, every retry adopted",
          delta["incomplete"] == 0 and delta["not_adopted"] == 0 and delta["failed"] == 0,
          str(delta))
    offsets = [int(n) for n in HANDED_OVER.findall(log_since(mark))]
    if handed and port in (SESSION_DIRECT, SESSION_DIRECT_GRADED):
        # Frames reach the router one 64 KiB replay chunk at a time, so it keeps what fits.
        check(case, "handed over where the router's copy would overflow",
              len(offsets) == 1 and limit - 64 * 1024 < offsets[0] + 1 <= limit + 1, str(offsets))
    if handed:
        check(case, f"{retries} retries adopted it; the body was parsed once",
              delta["adopted"] == retries and delta["parsed"] == 1 and delta["reparsed"] == 0,
              str(delta))
    else:
        check(case, "each attempt parsed the router's copy",
              delta["adopted"] == 0 and delta["parsed"] == len(attempts), str(delta))


def run_session_cases(port, tag):
    small, big = body_of(1024), body_of(BIG)
    session_failover(f"s-429-1KiB-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], small)
    session_failover(f"s-429-4MiB-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], big)
    session_failover(f"s-503-4MiB-chunked-{tag}", port, "gemini=503;vertex=200", "vertex",
                     ["gemini", "vertex"], big, chunked=True)
    session_failover(f"s-429-64MiB-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], body_of(16 * BIG))
    session_failover(f"s-reset-early-4MiB-{tag}", port, "gemini=reset-early;vertex=200", "vertex",
                     ["gemini", "vertex"], big)
    session_failover(f"s-reset-early-64MiB-{tag}", port, "gemini=reset-early;vertex=200", "vertex",
                     ["gemini", "vertex"], body_of(16 * BIG))
    session_failover(f"s-reverse-4MiB-{tag}", port, "vertex=503;gemini=200", "gemini",
                     ["vertex", "gemini"], big, extra={"x-pdp-order": "vertex,gemini"})
    session_failover(f"s-three-step-{tag}", port, "gemini=503|200;vertex=429", "gemini",
                     ["gemini", "vertex", "gemini"], big, extra=groups("gemini", "vertex", "gemini"))
    session_failover(f"s-same-cluster-{tag}", port, "vertex=503|429|200", "vertex",
                     ["vertex", "vertex", "vertex"], big, extra=groups("vertex"))
    session_failover(f"s-stream-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], big, stream=True)
    session_failover(f"s-pdp-rewrites-body-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], big, sent=PDP_REWRITTEN,
                     extra={"x-pdp-rewrite-body": "1"})
    session_failover(f"s-pdp-rewrites-body-reset-{tag}", port, "gemini=reset-early;vertex=200",
                     "vertex", ["gemini", "vertex"], big, sent=PDP_REWRITTEN,
                     extra={"x-pdp-rewrite-body": "1"})
    editable = body_of(16 * 1024)
    session_failover(f"s-pdp-edits-body-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], editable, sent=editable.replace(b"hello", b"HELLO"),
                     extra={"x-test-mutate-body": "1"})


def run_direct_session_cases(port, tag):
    big = body_of(BIG)
    session_failover(f"s-429-1KiB-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], body_of(1024))
    session_failover(f"s-429-4MiB-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], big)
    session_failover(f"s-503-4MiB-chunked-{tag}", port, "gemini=503;vertex=200", "vertex",
                     ["gemini", "vertex"], big, chunked=True)
    session_failover(f"s-reset-early-4MiB-{tag}", port, "gemini=reset-early;vertex=200", "vertex",
                     ["gemini", "vertex"], big)
    session_failover(f"s-429-64MiB-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], body_of(16 * BIG))
    session_failover(f"s-stream-{tag}", port, "gemini=429;vertex=200", "vertex",
                     ["gemini", "vertex"], big, stream=True)


def refused_sweep():
    """Attempt 1 to a port nothing listens on fails while the body is still arriving. The router
    writes the rest of the body to the session, and vertex parses it back from there; a body the
    router kept, or one attempt 1 took in whole, needs neither."""
    refused_first = {"x-pdp-groups": json.dumps(
        [{"name": "refused", "clusters": [{"cluster_name": "gemini_refused", "weight": 100}]},
         {"name": "vertex"}])}
    outcomes = {}
    for size in (16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024,
                 16 * 1024 * 1024, 64 * 1024 * 1024):
        body = body_of(size)
        for port in (UPSTREAM_SESSION, SESSION_GRADED):
            case = f"refused-{size // 1024}KiB-{port}"
            before = session_stats(port)
            mark = log_mark()
            status, data, _ = send(port, case, "vertex=200", body, refused_first)
            time.sleep(0.3)
            delta = {k: v - before[k] for k, v in session_stats(port).items()}
            recs = records(case)
            check(case, "failed over to vertex with the whole body",
                  status == 200 and [r["backend"] for r in recs] == ["vertex"] and
                  recs[0]["canonical_sha256"] == canonical_sha(body),
                  f"{status} {[r['backend'] for r in recs]} {data[:60]!r}")
            check(case, "never short of the body", delta["incomplete"] == 0 and
                  delta["not_adopted"] == 0 and delta["failed"] == 0, str(delta))
            writes = [int(n) for n in ROUTER_WRITES.findall(log_since(mark))]
            if writes:
                check(case, "vertex parsed back what the router finished",
                      delta["reparsed"] == 1 and delta["adopted"] == 1, str(delta))
                outcomes[(size, port)] = f"router wrote from {writes[0] // 1024} KiB"
            elif delta["handed_over"]:
                outcomes[(size, port)] = "attempt 1 took it whole"
            else:
                outcomes[(size, port)] = "router kept it"
            if status != 200:
                outcomes[(size, port)] = str(status)
    for port in (UPSTREAM_SESSION, SESSION_GRADED):
        row = "; ".join(f"{size // 1024} KiB: {outcomes[(size, p)]}"
                        for (size, p) in outcomes if p == port)
        print(f"refused sweep :{port}  {row}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--restore", default="true")
    args = parser.parse_args()

    unresolved, unused = stat("transcoder.unresolved"), stat("route_binding_unused")
    if args.restore != "true":
        check("runtime", "header restore is off", runtime_value(RESTORE_GUARD) == "false",
              str(runtime_value(RESTORE_GUARD)))
        # Each attempt's upstream APM reads the path the previous attempt rendered, and renders
        # its own; header_mutation drops the other provider's credential.
        # captured/e2e_no_restore_naive_chains.log is an earlier run with chains that did neither.
        walks("no-restore", UPSTREAM_SESSION)
        # Known limit: the APM-free gemini_plain relies on the restore, so after vertex_plain it
        # gets the path vertex_plain's APM rendered.
        status, _, _ = send(CONTROL, "no-restore-plain-reverse", "vertex=503;gemini=200",
                            body_of(1024), {"x-pdp-order": "vertex,gemini"})
        time.sleep(0.3)
        recs = records("no-restore-plain-reverse")
        check("no-restore-plain-reverse", "known limit: gemini_plain gets vertex's path, 404",
              status == 404 and [r["backend"] for r in recs] == ["vertex", "gemini"] and
              recs[-1]["path"] == vertex_path(), f"{status} {[r['path'][-40:] for r in recs]}")
        check("transcoder", "no unresolved instruction",
              stat("transcoder.unresolved") - unresolved == 0)
        return report()

    check("runtime", "header restore is on", runtime_value(RESTORE_GUARD) != "false",
          str(runtime_value(RESTORE_GUARD)))
    failover("baseline", UPSTREAM_SESSION, "gemini=200", "gemini", ["gemini"], body_of(1024))
    run_session_cases(UPSTREAM_SESSION, "limit-0")
    run_session_cases(SESSION_GRADED, "limit-1MiB")
    run_direct_session_cases(SESSION_DIRECT, "direct-limit-0")
    run_direct_session_cases(SESSION_DIRECT_GRADED, "direct-limit-1MiB")
    walks("restore", UPSTREAM_SESSION)
    session_failover("pdp-model-policy", UPSTREAM_SESSION, "vertex=429;gemini=200", "gemini",
                     ["vertex", "gemini"], body_of(BIG), model="gemini-2.5-pro")
    # For this model the PDP supplies a group the route does not configure, with its own clusters.
    session_failover("pdp-policy-group", UPSTREAM_SESSION, "vertex=429;gemini=200", "gemini",
                     ["vertex", "gemini"], body_of(BIG), model="gemini-2.5-flash-lite")
    failover("pdp-order-beats-model-policy", UPSTREAM_SESSION, "gemini=429;vertex=200", "vertex",
             ["gemini", "vertex"], body_of(1024), model="gemini-2.5-flash-lite",
             extra={"x-pdp-order": "gemini,vertex"})
    failover("same-cluster-gemini", UPSTREAM_SESSION, "gemini=503|200", "gemini",
             ["gemini", "gemini"], body_of(1024), extra=groups("gemini"))
    # Each provider gets only its own credential, whatever the client sent.
    failover("client-credentials-stripped", UPSTREAM_SESSION, "gemini=429;vertex=200", "vertex",
             ["gemini", "vertex"], body_of(1024),
             extra={"x-goog-api-key": "client-key", "authorization": "Bearer client-token"})

    # A retry target whose cluster has no session APM: after the hand-over the router has no body
    # to give it, so it fails closed; a body the router kept goes anywhere.
    plain_second = {"x-pdp-groups": json.dumps(
        [{"name": "gemini"}, {"name": "plain", "clusters": [{"cluster_name": "gemini_plain",
                                                             "weight": 100}]}])}
    before = session_stats(UPSTREAM_SESSION)
    status, data, _ = send(UPSTREAM_SESSION, "s-not-adopted", "gemini=429|200", body_of(BIG),
                           plain_second)
    time.sleep(0.3)
    not_adopted = session_stats(UPSTREAM_SESSION)["not_adopted"] - before["not_adopted"]
    complete = [r["backend"] for r in records("s-not-adopted") if not r.get("truncated")]
    check("s-not-adopted", "503, and the APM-free cluster never got a whole request",
          status == 503 and complete == ["gemini"] and not_adopted == 1,
          f"{status} not_adopted+{not_adopted} {complete} {data[:60]!r}")
    # The two attempts go through different chains: one re-serializes, the other does not.
    failover("s-graded-to-plain", SESSION_GRADED, "gemini=429|200", "gemini", ["gemini", "gemini"],
             body_of(512 * 1024), extra=plain_second, same_bytes=False)
    # Attempt 1 to a cluster without the session APM makes no session: today's behavior.
    plain_first = {"x-pdp-groups": json.dumps(
        [{"name": "plain", "clusters": [{"cluster_name": "gemini_plain", "weight": 100}]},
         {"name": "vertex"}])}
    status, _, _ = send(UPSTREAM_SESSION, "s-plain-first", "gemini=429;vertex=200", body_of(BIG),
                        plain_first)
    time.sleep(0.3)
    check("s-plain-first", "no session, no retry: gemini's 429 reaches the client",
          status == 429 and [r["backend"] for r in records("s-plain-first")] == ["gemini"],
          str(status))
    refused_sweep()

    # Known limits of a Gemini -> IR -> Gemini round trip in the provider clusters.
    config = {"maxOutputTokens": 64, "temperature": 0.2, "topP": 0.9, "stopSequences": ["END"],
              "seed": 7, "topK": 40, "candidateCount": 1}
    status, _, _ = send(UPSTREAM_SESSION, "limit-generation-config", "gemini=200",
                        body_of(1024, generation_config=config))
    time.sleep(0.3)
    recs = records("limit-generation-config")
    kept = recs[0]["generation_config"] if recs else []
    check("limit-generation-config", "status 200", status == 200, str(status))
    check("limit-generation-config", "five fields kept, topK and candidateCount dropped",
          kept == ["maxOutputTokens", "seed", "stopSequences", "temperature", "topP"], str(kept))
    refused = {
        "limit-function-call": [
            {"role": "user", "parts": [{"text": "hello"}]},
            {"role": "model", "parts": [{"functionCall": {"name": "lookup", "args": {}}}]},
            {"role": "user", "parts": [{"functionResponse": {"name": "lookup", "response": {}}}]},
        ],
        "limit-media": [{"role": "user", "parts": [
            {"text": "describe"}, {"inlineData": {"mimeType": "image/png", "data": "iVBORw0K"}}]}],
    }
    for case, contents in refused.items():
        status, data, _ = send(UPSTREAM_SESSION, case, "gemini=200",
                               json.dumps({"contents": contents}).encode())
        time.sleep(0.3)
        attempts = [str(r.get("attempts")) for r in access_rows(case)]
        check(case, "refused with 400 before any backend, in one attempt",
              status == 400 and records(case) == [] and attempts == ["1"],
              f"{status} attempts={attempts} {data[:60]!r}")

    status, _, _ = send(UPSTREAM_SESSION, "both-fail", "gemini=429;vertex=503", body_of(1024))
    time.sleep(0.3)
    order = [r["backend"] for r in records("both-fail")]
    check("both-fail", "last attempt's 503 reaches the client", status == 503, str(status))
    check("both-fail", "three attempts, last group repeated", order == ["gemini", "vertex", "vertex"],
          str(order))

    check("transcoder", "no unresolved instruction", stat("transcoder.unresolved") - unresolved == 0)
    check("transcoder", "every route binding applied", stat("route_binding_unused") - unused == 0)

    # Control: no session, today's in-memory retry buffer capped by the 32 KiB connection limit.
    failover("control-small", CONTROL, "gemini=429;vertex=200", "vertex", ["gemini", "vertex"],
             body_of(1024))
    abandoned = stat("retry_or_shadow_abandoned")
    status, _, _ = send(CONTROL, "control-4MiB", "gemini=429;vertex=200", body_of(BIG))
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
