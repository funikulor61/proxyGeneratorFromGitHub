#!/usr/bin/env python3
"""
Proxy parser & checker (ASYNC / aiohttp) — fixed for Windows.

All 3 fixes applied:
  1) WindowsSelectorEventLoop — kills WinError 10054 noise
  2) await resp.read() — flush body before close, prevents leftover socket state
  3) force_close=True — never reuse proxy connections
"""

import argparse
import asyncio
import os
import re
import sys
import time

try:
    import aiohttp
except ImportError:
    sys.stderr.write("ERROR: 'aiohttp' is not installed. Run: pip install aiohttp\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Default settings
# ---------------------------------------------------------------------------
DEFAULT_INPUT_URL = (
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/"
    "main/proxies/protocols/http/data.txt"
)
# можно поменять http на https
CHECK_URL = "http://httpbin.org/ip"

PROXY_LINE_RE = re.compile(
    r"^(?:(https?|socks[45])://)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{2,5})$"
)


# ---------------------------------------------------------------------------
# Step 1: download the proxy list
# ---------------------------------------------------------------------------
async def download_proxy_list(session, url):
    print(f"[1/4] Downloading proxy list from:")
    print(f"      {url}")
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
        r.raise_for_status()
        text = await r.text()
        print(f"      OK — {len(text)} bytes received")
        return text


# ---------------------------------------------------------------------------
# Step 2: parse the list
# ---------------------------------------------------------------------------
def parse_proxies(text):
    proxies, bad = [], 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = PROXY_LINE_RE.match(line)
        if not m:
            bad += 1
            continue
        scheme = m.group(1) or "http"
        ip = m.group("ip")
        port = int(m.group("port"))
        proxies.append({
            "url": f"{scheme}://{ip}:{port}",
            "ip": ip, "port": port, "scheme": scheme,
        })
    print(f"[2/4] Parsed {len(proxies)} proxy entries ({bad} skipped).")
    return proxies


# ---------------------------------------------------------------------------
# Step 3: test each proxy
# ---------------------------------------------------------------------------
async def check_one(session, proxy, timeout, max_latency_ms, sem):
    async with sem:
        start = time.perf_counter()
        try:
            async with session.get(
                CHECK_URL,
                proxy=proxy["url"],
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                latency_ms = (time.perf_counter() - start) * 1000.0
                if resp.status == 200 and latency_ms < max_latency_ms:
                    try:
                        data = await resp.json()
                        echoed = data.get("origin", "?")
                    except Exception:
                        echoed = "?"
                        await resp.read()
                    return {**proxy, "ok": True,
                            "latency_ms": latency_ms, "echoed_ip": echoed}
                await resp.read()  # flush body — Windows fix
                return {**proxy, "ok": False, "latency_ms": latency_ms}
        except Exception:
            return {**proxy, "ok": False,
                    "latency_ms": (time.perf_counter() - start) * 1000.0}


async def check_all(proxies, concurrency, timeout, max_latency_ms):
    print(f"[3/4] Testing {len(proxies)} proxies "
          f"(concurrency={concurrency}, timeout={timeout}s, "
          f"max_latency={max_latency_ms}ms)...")

    sem = asyncio.Semaphore(concurrency)

    connector = aiohttp.TCPConnector(
        limit=concurrency,
        limit_per_host=0,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
        force_close=True,
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            asyncio.create_task(
                check_one(session, p, timeout, max_latency_ms, sem)
            )
            for p in proxies
        ]

        results = []
        done = 0
        ok = 0
        for fut in asyncio.as_completed(tasks):
            res = await fut
            results.append(res)
            done += 1
            if res["ok"]:
                ok += 1
                print(f"  OK [{done}/{len(proxies)}] {res['url']}  "
                      f"{res['latency_ms']:.0f}ms  (echo={res['echoed_ip']})")
            elif done % 50 == 0:
                print(f"  .. [{done}/{len(proxies)}] checked, {ok} working so far")
        return results


# ---------------------------------------------------------------------------
# Step 4: write working proxies
# ---------------------------------------------------------------------------
def write_output(results, out_path, max_latency_ms):
    working = sorted((r for r in results if r["ok"]),
                     key=lambda r: r["latency_ms"])

    print(f"[4/4] {len(working)} working proxies (<{max_latency_ms}ms).")
    print(f"      Writing to: {out_path}")

    with open(out_path, "w", encoding="utf-8") as f:
        for r in working:
            f.write(r["url"] + "\n")

    if working:
        print("\nTop 10 fastest working proxies:")
        print(f"  {'#':>3}  {'URL':40}  {'latency':>8}  echoed IP")
        for i, r in enumerate(working[:10], 1):
            print(f"  {i:>3}  {r['url']:40}  {r['latency_ms']:>7.0f}ms  {r['echoed_ip']}")
    return working


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
async def amain():
    parser = argparse.ArgumentParser(description="Proxy parser & checker (async)")
    parser.add_argument("--input-url", default=DEFAULT_INPUT_URL,
                        help="Source TXT URL with proxy list")
    parser.add_argument(
        "--out",
        default=os.path.join(os.getcwd(), "working_proxies.txt"),
        help="Output TXT file path for working proxies",
    )
    parser.add_argument("--timeout", type=float, default=4.0,
                        help="Per-proxy connect+read timeout (seconds)")
    parser.add_argument("--concurrency", type=int, default=300,
                        help="Number of simultaneous requests")
    parser.add_argument("--max-latency", type=int, default=400,
                        help="Keep proxies with latency below this (ms)")
    args = parser.parse_args()

    print("=" * 70)
    print(" PROXY PARSER & CHECKER  (ASYNC / aiohttp)")
    print("=" * 70)

    # Для скачивания списка прокси используем свой короткоживущий session
    download_connector = aiohttp.TCPConnector(
        limit=10,
        force_close=True,
    )
    async with aiohttp.ClientSession(
        connector=download_connector
    ) as dl_session:
        text = await download_proxy_list(dl_session, args.input_url)

    proxies = parse_proxies(text)
    if not proxies:
        print("No proxies found. Exiting.")
        sys.exit(1)

    results = await check_all(
        proxies, args.concurrency, args.timeout, args.max_latency
    )
    working = write_output(results, args.out, args.max_latency)

    print("\n" + "=" * 70)
    print(f" DONE.  {len(working)}/{len(results)} OK,  "
          f"{len(results) - len(working)} failed/timeout/too-slow.")
    print(f" Output file: {args.out}")
    print("=" * 70)


if __name__ == "__main__":
    # Windows fix: используем SelectorEventLoop — нет бага Proactor с WinError 10054
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(
            asyncio.WindowsSelectorEventLoopPolicy()
        )
    asyncio.run(amain())