#!/usr/bin/env python3
"""E4: tenant-cardinality scaling — simulate agent traffic with 10 / 100 / 1000 tenants.

Holds total offered load roughly constant (~80 light GET/s + ~40-200 concurrent heavy POSTs)
while sweeping the number of distinct tenants, so the variable under test is tenant
cardinality: shed fairness, light-tenant latency, and Envoy CPU/RSS overhead per scale.

Per scale: fresh envoy, 15s baseline at pressure 0.0, then 20s shed phase at pressure 0.85
(severity 0.5). Results land in results_scale.json.

Usage: python3 scale_experiment.py --envoy ../../bazel-bin/source/exe/envoy-static
"""

import argparse
import asyncio
import json
import os
import resource
import signal
import statistics
import subprocess
import time
import urllib.request

EXP_DIR = "/tmp/tenant_load_shed_exp"
PRESSURE_FILE = os.path.join(EXP_DIR, "pressure")
ADMIN = "http://127.0.0.1:9901"
L7_PORT = 10000
UPSTREAM_HTTP = 8080

SCALES = [10, 100, 1000]
BASELINE_SECONDS = 15
SHED_SECONDS = 20
SHED_PRESSURE = 0.85  # severity 0.5 on the 0.80..0.90 ramp
HEAVY_BODY = 262144
TOTAL_LIGHT_RPS = 80.0
TOTAL_HEAVY_STREAMS = 40  # per-tenant concurrency = max(1, this // n_heavy)


def proxy_v1(src_ip: str) -> bytes:
    return f"PROXY TCP4 {src_ip} 127.0.0.1 40000 {L7_PORT}\r\n".encode()


def tenant_ips(n: int):
    heavy = [f"10.1.{i // 256}.{i % 256}" for i in range(1, max(1, n // 5) + 1)]
    light = [f"10.2.{i // 256}.{i % 256}" for i in range(1, n - len(heavy) + 1)]
    return heavy, light


def set_pressure(value: float) -> None:
    tmp = PRESSURE_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(value))
    os.replace(tmp, PRESSURE_FILE)


def scrape_stats() -> dict:
    try:
        url = f"{ADMIN}/stats?filter=tenant_load_shed&format=json"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.load(r)
        return {s["name"].split(".")[-1]: s["value"] for s in data.get("stats", [])
                if "value" in s and "tenant_load_shed" in s["name"]}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


async def http_upstream(reader, writer):
    try:
        await reader.readline()
        headers = {}
        while True:
            h = await reader.readline()
            if h in (b"\r\n", b""):
                break
            k, _, v = h.decode(errors="replace").partition(":")
            headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", 0))
        read = 0
        while read < length:
            chunk = await reader.read(min(8192, length - read))
            if not chunk:
                break
            read += len(chunk)
            await asyncio.sleep(len(chunk) / 65536)
        writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: close\r\n\r\nok\n")
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def request(ip: str, body_size: int, counters: dict, latencies=None) -> None:
    start = time.monotonic()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", L7_PORT)
    except OSError:
        counters["error"] += 1
        return
    try:
        writer.write(proxy_v1(ip))
        if body_size:
            writer.write(b"POST / HTTP/1.1\r\nhost: t\r\ncontent-length: %d\r\nconnection: close\r\n\r\n"
                         % body_size)
            sent = 0
            while sent < body_size:
                writer.write(b"x" * min(16384, body_size - sent))
                sent += min(16384, body_size - sent)
                await writer.drain()
        else:
            writer.write(b"GET / HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout=30)
        rest = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
        if b" 503" in status and b"x-envoy-tenant-load-shed" in rest:
            counters["shed"] += 1
        elif b" 200" in status:
            counters["ok"] += 1
            if latencies is not None:
                latencies.append(time.monotonic() - start)
        else:
            counters["other"] += 1
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError, OSError):
        counters["error"] += 1
    finally:
        writer.close()


async def heavy_loop(ip, conc, counters, stop):
    async def one():
        while not stop.is_set():
            await request(ip, HEAVY_BODY, counters)
    await asyncio.gather(*(one() for _ in range(conc)))


async def light_loop(ip, period, counters, latencies, stop):
    while not stop.is_set():
        await request(ip, 0, counters, latencies)
        await asyncio.sleep(period)


async def sample_proc(pid: int, samples: list, stop: asyncio.Event):
    while not stop.is_set():
        try:
            out = subprocess.check_output(["ps", "-o", "%cpu=,rss=", "-p", str(pid)], text=True)
            cpu, rss = out.split()
            samples.append((float(cpu), int(rss)))
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(1.0)


def summarize_phase(counters, heavy, light, latencies, proc_samples, stats):
    def agg(tenants):
        t = {"ok": 0, "shed": 0, "other": 0, "error": 0}
        for ip in tenants:
            for k in t:
                t[k] += counters[ip][k]
        n = sum(t.values())
        t["shed_rate"] = round(t["shed"] / n, 4) if n else None
        return t

    lat = sorted(latencies)
    return {
        "heavy": agg(heavy),
        "light": agg(light),
        "light_latency_ms": {
            "p50": round(1000 * statistics.median(lat), 1) if lat else None,
            "p95": round(1000 * lat[int(0.95 * len(lat))], 1) if len(lat) >= 20 else None,
            "n": len(lat),
        },
        "envoy_cpu_pct_avg": round(statistics.mean(s[0] for s in proc_samples), 1)
        if proc_samples else None,
        "envoy_rss_mb": round(proc_samples[-1][1] / 1024, 1) if proc_samples else None,
        "stats": stats,
    }


async def run_scale(n: int, envoy: str, config: str) -> dict:
    heavy, light = tenant_ips(n)
    conc = max(1, TOTAL_HEAVY_STREAMS // len(heavy))
    period = len(light) / TOTAL_LIGHT_RPS

    os.makedirs(EXP_DIR, exist_ok=True)
    set_pressure(0.0)
    server = await asyncio.start_server(http_upstream, "127.0.0.1", UPSTREAM_HTTP)
    log = open(os.path.join(EXP_DIR, f"envoy_scale_{n}.log"), "w")
    proc = subprocess.Popen([envoy, "-c", config, "--concurrency", "4", "--base-id", "77"],
                            stdout=log, stderr=log)
    result = {"tenants": n, "heavy_tenants": len(heavy), "light_tenants": len(light),
              "heavy_concurrency_per_tenant": conc,
              "light_period_s": round(period, 3)}
    try:
        await asyncio.sleep(3)
        if proc.poll() is not None:
            raise RuntimeError(f"envoy exited early; see {log.name}")

        stop = asyncio.Event()
        counters = {ip: {"ok": 0, "shed": 0, "other": 0, "error": 0} for ip in heavy + light}
        latencies: list = []
        proc_samples: list = []
        tasks = [asyncio.create_task(heavy_loop(ip, conc, counters[ip], stop)) for ip in heavy]
        tasks += [asyncio.create_task(light_loop(ip, period, counters[ip], latencies, stop))
                  for ip in light]
        tasks.append(asyncio.create_task(sample_proc(proc.pid, proc_samples, stop)))

        await asyncio.sleep(5)  # warm-up

        for phase, pressure, hold in [("baseline", 0.0, BASELINE_SECONDS),
                                      ("shed", SHED_PRESSURE, SHED_SECONDS)]:
            set_pressure(pressure)
            await asyncio.sleep(2)
            # Reset in place: the traffic tasks hold references to these dicts.
            for c in counters.values():
                for k in c:
                    c[k] = 0
            latencies.clear()
            proc_samples.clear()
            await asyncio.sleep(hold)
            result[phase] = summarize_phase(counters, heavy, light, latencies, proc_samples,
                                            scrape_stats())

        stop.set()
        for t in tasks:
            t.cancel()
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        server.close()
        log.close()
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--envoy", required=True)
    args = ap.parse_args()
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(8192, hard), hard))
    except (ValueError, OSError):
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    config = os.path.join(here, "l7.yaml")
    results = []
    for n in SCALES:
        row = asyncio.run(run_scale(n, args.envoy, config))
        results.append(row)
        print(json.dumps(row), flush=True)
        time.sleep(2)
    out = os.path.join(here, "results_scale.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"results written to {out}")


if __name__ == "__main__":
    main()
