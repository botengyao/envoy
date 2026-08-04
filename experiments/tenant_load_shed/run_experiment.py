#!/usr/bin/env python3
"""Water-fill load-shedding experiment orchestrator (E1 = L7, E2 = L4).

Simulates N tenants from one host via PROXY protocol v1 headers, drives shed severity
deterministically through the injected_resource overload monitor, and measures per-tenant-class
outcomes at each pressure step.

Usage:
  python3 run_experiment.py --mode l7 --envoy /path/to/envoy-static
  python3 run_experiment.py --mode l4 --envoy /path/to/envoy-static
"""

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

EXP_DIR = "/tmp/tenant_load_shed_exp"
PRESSURE_FILE = os.path.join(EXP_DIR, "pressure")
ADMIN = "http://127.0.0.1:9901"
L7_PORT, L4_PORT = 10000, 10001
UPSTREAM_HTTP, UPSTREAM_SINK = 8080, 8081

HEAVY_TENANTS = [f"10.1.0.{i}" for i in range(1, 9)]    # 8 heavy micro-VMs
LIGHT_TENANTS = [f"10.2.0.{i}" for i in range(1, 33)]   # 32 light micro-VMs
# Pressure sweep: below ramp, ramp entry, mid-ramp, near saturation, reject-all, recovery.
STEPS = [0.70, 0.82, 0.85, 0.88, 0.92, 0.70]
STEP_SECONDS = 15

HEAVY_BODY = 262144      # 256 KiB POST bodies
HEAVY_CONCURRENCY = 6    # concurrent streams/connections per heavy tenant
LIGHT_PERIOD = 0.5       # light tenant request period (s)


def proxy_v1(src_ip: str, dst_port: int) -> bytes:
    return f"PROXY TCP4 {src_ip} 127.0.0.1 40000 {dst_port}\r\n".encode()


def set_pressure(value: float) -> None:
    tmp = PRESSURE_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(value))
    os.replace(tmp, PRESSURE_FILE)  # rename => MovedTo event for the envoy watcher


def scrape_stats() -> dict:
    try:
        url = f"{ADMIN}/stats?filter=tenant_load_shed%7Coverload&format=json"
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.load(r)
        return {s["name"]: s["value"] for s in data.get("stats", []) if "value" in s}
    except Exception as e:  # noqa: BLE001 - stats are best-effort
        return {"error": str(e)}


# ----------------------------------------------------------------------------- upstreams

async def http_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Responds to GET immediately; drains POST bodies slowly (64 KiB/s) to force buffering."""
    try:
        line = await reader.readline()
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
            await asyncio.sleep(len(chunk) / 65536)  # ~64 KiB/s drain
        body = b"ok\n"
        writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: %d\r\nconnection: close\r\n\r\n%s"
                     % (len(body), body))
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def sink_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """TCP sink reading at ~8 KiB/s so envoy's upstream write buffers fill."""
    try:
        while True:
            chunk = await reader.read(2048)
            if not chunk:
                break
            await asyncio.sleep(0.25)
    except ConnectionError:
        pass
    finally:
        writer.close()


# ----------------------------------------------------------------------------- L7 traffic

async def l7_request(ip: str, body_size: int, counters: dict) -> None:
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", L7_PORT)
    except OSError:
        counters["error"] += 1
        return
    try:
        writer.write(proxy_v1(ip, L7_PORT))
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
        else:
            counters["other"] += 1
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError, OSError):
        counters["error"] += 1
    finally:
        writer.close()


async def l7_heavy_loop(ip: str, counters: dict, stop: asyncio.Event) -> None:
    async def one() -> None:
        while not stop.is_set():
            await l7_request(ip, HEAVY_BODY, counters)
    await asyncio.gather(*(one() for _ in range(HEAVY_CONCURRENCY)))


async def l7_light_loop(ip: str, counters: dict, stop: asyncio.Event) -> None:
    while not stop.is_set():
        await l7_request(ip, 0, counters)
        await asyncio.sleep(LIGHT_PERIOD)


# ----------------------------------------------------------------------------- L4 traffic

async def l4_hold(ip: str, stop: asyncio.Event, rate_bps: int) -> None:
    """A long-lived connection writing continuously at rate_bps toward the slow sink."""
    while not stop.is_set():
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", L4_PORT)
            writer.write(proxy_v1(ip, L4_PORT))
            while not stop.is_set():
                writer.write(b"x" * 8192)
                await asyncio.wait_for(writer.drain(), timeout=30)
                await asyncio.sleep(8192 / rate_bps)
        except (ConnectionError, asyncio.TimeoutError, OSError):
            await asyncio.sleep(1.0)  # connection shed or reset; retry
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass


async def l4_probe(ip: str, counters: dict, stop: asyncio.Event) -> None:
    """Probes acceptance of NEW connections: shed connections are closed at accept.

    close(NoFlush) surfaces client-side as either EOF or ECONNRESET depending on timing, so
    both count as shed; an admitted connection simply times out on the read."""
    while not stop.is_set():
        writer = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", L4_PORT)
            writer.write(proxy_v1(ip, L4_PORT))
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1), timeout=0.5)
                counters["shed" if data == b"" else "ok"] += 1
            except asyncio.TimeoutError:
                counters["ok"] += 1
            except ConnectionResetError:
                counters["shed"] += 1
        except (ConnectionError, OSError):
            counters["error"] += 1
        finally:
            if writer is not None:
                writer.close()
        await asyncio.sleep(1.0)


# ----------------------------------------------------------------------------- harness

def fresh_counters(tenants):
    return {ip: {"ok": 0, "shed": 0, "other": 0, "error": 0} for ip in tenants}


def summarize(counters: dict, tenants) -> dict:
    total = {"ok": 0, "shed": 0, "other": 0, "error": 0}
    for ip in tenants:
        for k in total:
            total[k] += counters[ip][k]
    n = sum(total.values())
    total["shed_rate"] = round(total["shed"] / n, 3) if n else None
    return total


async def run(mode: str, envoy: str, config: str, results_path: str) -> None:
    os.makedirs(EXP_DIR, exist_ok=True)
    set_pressure(0.0)

    servers = [await asyncio.start_server(http_upstream, "127.0.0.1", UPSTREAM_HTTP),
               await asyncio.start_server(sink_upstream, "127.0.0.1", UPSTREAM_SINK)]

    envoy_log = open(os.path.join(EXP_DIR, f"envoy_{mode}.log"), "w")
    proc = subprocess.Popen(
        [envoy, "-c", config, "--concurrency", "4", "--base-id", "77"],
        stdout=envoy_log, stderr=envoy_log)
    try:
        await asyncio.sleep(3)  # listener warm-up
        if proc.poll() is not None:
            raise RuntimeError(f"envoy exited early; see {envoy_log.name}")

        stop = asyncio.Event()
        counters = fresh_counters(HEAVY_TENANTS + LIGHT_TENANTS)
        if mode == "l7":
            tasks = [asyncio.create_task(l7_heavy_loop(ip, counters[ip], stop)) for ip in HEAVY_TENANTS]
            tasks += [asyncio.create_task(l7_light_loop(ip, counters[ip], stop)) for ip in LIGHT_TENANTS]
        else:
            tasks = [asyncio.create_task(l4_hold(ip, stop, 65536)) for ip in HEAVY_TENANTS
                     for _ in range(HEAVY_CONCURRENCY)]
            tasks += [asyncio.create_task(l4_hold(ip, stop, 1024)) for ip in LIGHT_TENANTS]
            tasks += [asyncio.create_task(l4_probe(ip, counters[ip], stop)) for ip in HEAVY_TENANTS]
            tasks += [asyncio.create_task(l4_probe(ip, counters[ip], stop)) for ip in LIGHT_TENANTS]

        await asyncio.sleep(5)  # usage warm-up before the sweep
        results = []
        for step in STEPS:
            set_pressure(step)
            await asyncio.sleep(2)  # let severity propagate (0.25s refresh + 0.1s eval)
            # Reset in place: traffic tasks hold references to these dicts, so rebinding
            # them would silently detach every future increment from the measurement.
            for per_tenant in counters.values():
                for key in per_tenant:
                    per_tenant[key] = 0
            await asyncio.sleep(STEP_SECONDS)
            stats = scrape_stats()
            row = {
                "pressure": step,
                "heavy": summarize(counters, HEAVY_TENANTS),
                "light": summarize(counters, LIGHT_TENANTS),
                "stats": {k.split(".")[-1]: v for k, v in stats.items() if "error" not in k},
            }
            results.append(row)
            print(json.dumps(row), flush=True)

        stop.set()
        for t in tasks:
            t.cancel()
        with open(results_path, "w") as f:
            json.dump({"mode": mode, "steps": results,
                       "per_tenant_final": counters}, f, indent=2)
        print(f"results written to {results_path}")
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        for s in servers:
            s.close()
        envoy_log.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["l7", "l4"], required=True)
    ap.add_argument("--envoy", required=True)
    args = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    config = os.path.join(here, f"{args.mode}.yaml")
    results = os.path.join(here, f"results_{args.mode}.json")
    asyncio.run(run(args.mode, args.envoy, config, results))


if __name__ == "__main__":
    main()
