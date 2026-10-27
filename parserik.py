#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MULTI-SOURCE PROXY PARSER & CHECKER (fully async, aiohttp)

Finds proxies from ~30 sources IN PARALLEL:
  - GitHub raw lists: proxifly, TheSpeedX, monosans, clarketm, vakhov,
    roosterkid, hideip.me, hookzof, sunny9577, casals-ar, mmpx12
  - API endpoints:    proxyscrape.com, proxyspace.pro, geonode
  - HTML tables:      free-proxy-list.net, sslproxies.org, us-proxy.org

Then:
  2) deduplicates by ip:port
  3) checks EVERY proxy concurrently (rotating echo endpoints,
     SOCKS4/SOCKS5 via aiohttp-socks)
  4) saves working proxies (latency < --max-latency ms) sorted by speed:
     working_all.txt + per-protocol files (working_http.txt, ...)

USAGE:
    python parserik.py                                  # everything, default
    python parserik.py --only http,https                # check only these schemes
    python parserik.py --limit 5000                     # check random 5000
    python parserik.py --concurrency 800 --timeout 3    # faster / stricter
    python parserik.py --no-html --no-socks             # skip source groups

REQUIRES:
    pip install aiohttp aiohttp-socks
"""

import argparse
import asyncio
import json
import os
import random
import re
import sys
import time
from collections import defaultdict

try:
    import aiohttp
except ImportError:
    sys.stderr.write("ERROR: 'aiohttp' is not installed.\n"
                     "Run: pip install aiohttp aiohttp-socks\n")
    sys.exit(1)

try:
    from aiohttp_socks import ProxyConnector
    SOCKS_SUPPORT = True
except ImportError:
    SOCKS_SUPPORT = False


# ===========================================================================
# SOURCES  (kind: text = any plain text / html = table / geonode = json api)
# ===========================================================================
GH = "https://raw.githubusercontent.com"

SOURCES = [
    # ---------- GitHub: proxifly (original source) ----------
    {"name": "proxifly/http",     "kind": "text", "scheme": "http",
     "url": f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"},
    {"name": "proxifly/https",    "kind": "text", "scheme": "https",
     "url": f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt"},
    {"name": "proxifly/socks4",   "kind": "text", "scheme": "socks4",
     "url": f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt"},
    {"name": "proxifly/socks5",   "kind": "text", "scheme": "socks5",
     "url": f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"},
    # ---------- GitHub: TheSpeedX ----------
    {"name": "thespeedx/http",    "kind": "text", "scheme": "http",
     "url": f"{GH}/TheSpeedX/PROXY-List/master/http.txt"},
    {"name": "thespeedx/socks4",  "kind": "text", "scheme": "socks4",
     "url": f"{GH}/TheSpeedX/PROXY-List/master/socks4.txt"},
    {"name": "thespeedx/socks5",  "kind": "text", "scheme": "socks5",
     "url": f"{GH}/TheSpeedX/PROXY-List/master/socks5.txt"},
    # ---------- GitHub: monosans ----------
    {"name": "monosans/http",     "kind": "text", "scheme": "http",
     "url": f"{GH}/monosans/proxy-list/main/proxies/http.txt"},
    {"name": "monosans/socks4",   "kind": "text", "scheme": "socks4",
     "url": f"{GH}/monosans/proxy-list/main/proxies/socks4.txt"},
    {"name": "monosans/socks5",   "kind": "text", "scheme": "socks5",
     "url": f"{GH}/monosans/proxy-list/main/proxies/socks5.txt"},
    # ---------- GitHub: other big lists ----------
    {"name": "casals-ar/http",    "kind": "text", "scheme": "http",
     "url": f"{GH}/casals-ar/proxy-list/main/http"},
    {"name": "casals-ar/https",   "kind": "text", "scheme": "https",
     "url": f"{GH}/casals-ar/proxy-list/main/https"},
    {"name": "hookzof/socks5",    "kind": "text", "scheme": "socks5",
     "url": f"{GH}/hookzof/socks5_list/master/proxy.txt"},
    {"name": "vakhov/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/vakhov/fresh-proxy-list/master/http.txt"},
    {"name": "vakhov/https",      "kind": "text", "scheme": "https",
     "url": f"{GH}/vakhov/fresh-proxy-list/master/https.txt"},
    {"name": "clarketm/http",     "kind": "text", "scheme": "http",
     "url": f"{GH}/clarketm/proxy-list/master/proxy-list-raw.txt"},
    {"name": "roosterkid/https",  "kind": "text", "scheme": "https",
     "url": f"{GH}/roosterkid/openproxylist/main/HTTPS_RAW.txt"},
    {"name": "hideip/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/zloi-user/hideip.me/main/http.txt"},
    {"name": "hideip/https",      "kind": "text", "scheme": "https",
     "url": f"{GH}/zloi-user/hideip.me/main/https.txt"},
    {"name": "hideip/socks4",     "kind": "text", "scheme": "socks4",
     "url": f"{GH}/zloi-user/hideip.me/main/socks4.txt"},
    {"name": "hideip/socks5",     "kind": "text", "scheme": "socks5",
     "url": f"{GH}/zloi-user/hideip.me/main/socks5.txt"},
    {"name": "sunny9577/http",    "kind": "text", "scheme": "http",
     "url": f"{GH}/sunny9577/proxy-scraper/master/generated/http_proxies.txt"},
    {"name": "mmpx12/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/mmpx12/proxy-list/master/http.txt"},
    {"name": "mmpx12/https",      "kind": "text", "scheme": "https",
     "url": f"{GH}/mmpx12/proxy-list/master/https.txt"},
    # ---------- API endpoints ----------
    {"name": "proxyscrape/http",  "kind": "text", "scheme": "http",
     "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all"},
    {"name": "proxyscrape/https", "kind": "text", "scheme": "https",
     "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=10000&country=all"},
    {"name": "proxyscrape/socks4","kind": "text", "scheme": "socks4",
     "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all"},
    {"name": "proxyscrape/socks5","kind": "text", "scheme": "socks5",
     "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all"},
    {"name": "proxyspace/http",   "kind": "text", "scheme": "http",
     "url": "https://proxyspace.pro/http.txt"},
    {"name": "proxyspace/https",  "kind": "text", "scheme": "https",
     "url": "https://proxyspace.pro/https.txt"},
    {"name": "geonode/mixed",     "kind": "geonode", "scheme": "http",
     "url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc"},
    # ---------- HTML tables ----------
    {"name": "free-proxy-list.net", "kind": "html", "scheme": "http",
     "url": "https://free-proxy-list.net/"},
    {"name": "sslproxies.org",      "kind": "html", "scheme": "https",
     "url": "https://sslproxies.org/"},
    {"name": "us-proxy.org",        "kind": "html", "scheme": "http",
     "url": "https://www.us-proxy.org/"},
]

# ===========================================================================
# CHECK ENDPOINTS — rotated round-robin to spread the load
# ===========================================================================
CHECK_URLS = [
    "http://httpbin.org/ip",              # {"origin": "..."}
    "http://api.ipify.org/?format=json",  # {"ip": "..."}
    "http://checkip.amazonaws.com/",      # plain text ip
    "http://ipinfo.io/ip",                # plain text ip
]

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/124.0 Safari/537.36"),
    "Accept": "*/*",
}

# ===========================================================================
# PARSING
# ===========================================================================
PAIR_RE = re.compile(
    r"(?:(?:https?|socks[45])://)?"
    r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b"
)
HTML_PAIR_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s*</td>\s*<td[^>]*>\s*(\d{2,5})",
    re.IGNORECASE,
)


def _valid_ip(ip: str) -> bool:
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def parse_text(text: str):
    out = []
    for m in PAIR_RE.finditer(text):
        ip, port = m.group(1), int(m.group(2))
        if _valid_ip(ip) and 1 <= port <= 65535:
            out.append((ip, port))
    return out


def parse_html(text: str):
    out = []
    for m in HTML_PAIR_RE.finditer(text):
        ip, port = m.group(1), int(m.group(2))
        if _valid_ip(ip) and 1 <= port <= 65535:
            out.append((ip, port))
    return out


def parse_geonode(text: str):
    out = []
    try:
        data = json.loads(text).get("data", [])
    except Exception:
        return out
    for item in data:
        ip, port = item.get("ip"), item.get("port")
        if ip and port and _valid_ip(ip):
            out.append((ip, int(port)))
    return out


def parse_source(src, text: str):
    if src["kind"] == "html":
        return parse_html(text)
    if src["kind"] == "geonode":
        return parse_geonode(text)
    return parse_text(text)


# ===========================================================================
# STEP 1 — fetch all sources CONCURRENTLY
# ===========================================================================
async def fetch_one(session, src):
    try:
        async with session.get(
            src["url"], headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as r:
            if r.status != 200:
                return src, None
            return src, await r.text(errors="ignore")
    except Exception:
        return src, None


async def fetch_all_sources(sources):
    print(f"[1/5] Fetching {len(sources)} sources in parallel...")
    connector = aiohttp.TCPConnector(limit=40, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(*(fetch_one(session, s) for s in sources))
    return results


# ===========================================================================
# STEP 2 — parse & deduplicate
# ===========================================================================
def collect_proxies(fetched):
    print("[2/5] Parsing sources and deduplicating...")
    seen = set()
    proxies = []
    stats = []
    for src, text in fetched:
        if text is None:
            stats.append((src["name"], 0, 0))
            continue
        pairs = parse_source(src, text)
        new = 0
        for ip, port in pairs:
            key = f"{ip}:{port}"
            if key in seen:
                continue
            seen.add(key)
            proxies.append({
                "url": f"{src['scheme']}://{ip}:{port}",
                "ip": ip, "port": port,
                "scheme": src["scheme"],
                "src": src["name"],
            })
            new += 1
        stats.append((src["name"], len(pairs), new))
    for name, total, new in stats:
        mark = "-" if total == 0 else "+"
        print(f"   {mark} {name:22} parsed={total:6}  new={new:6}")
    print(f"      TOTAL UNIQUE: {len(proxies)}")
    return proxies


# ===========================================================================
# STEP 3 — check every proxy
# ===========================================================================
def extract_origin(body: str):
    try:
        d = json.loads(body)
        for k in ("origin", "ip", "query"):
            if k in d:
                return d[k]
    except Exception:
        pass
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", body)
    return m.group(0) if m else "?"


async def check_http(session, proxy, check_url, timeout):
    start = time.perf_counter()
    async with session.get(
        check_url,
        proxy=f"http://{proxy['ip']}:{proxy['port']}",  # always http:// for aiohttp
        timeout=aiohttp.ClientTimeout(total=timeout),
        allow_redirects=False,
    ) as resp:
        latency = (time.perf_counter() - start) * 1000.0
        body = await resp.read()
        return resp.status == 200, latency, body.decode("utf-8", "ignore")


async def check_socks(proxy, check_url, timeout):
    start = time.perf_counter()
    connector = ProxyConnector.from_url(proxy["url"], rdns=True)
    async with aiohttp.ClientSession(connector=connector) as s:
        async with s.get(
            check_url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
        ) as resp:
            latency = (time.perf_counter() - start) * 1000.0
            body = await resp.read()
            return resp.status == 200, latency, body.decode("utf-8", "ignore")


async def check_one(session, proxy, idx, timeout, max_latency_ms, sem):
    async with sem:
        start = time.perf_counter()
        check_url = CHECK_URLS[idx % len(CHECK_URLS)]
        try:
            if proxy["scheme"].startswith("socks"):
                ok, latency, body = await check_socks(proxy, check_url, timeout)
            else:
                ok, latency, body = await check_http(session, proxy, check_url, timeout)
            if ok and latency < max_latency_ms:
                return {**proxy, "ok": True,
                        "latency_ms": latency,
                        "echoed_ip": extract_origin(body)}
            return {**proxy, "ok": False, "latency_ms": latency}
        except Exception:
            return {**proxy, "ok": False,
                    "latency_ms": (time.perf_counter() - start) * 1000.0}


async def check_all(proxies, concurrency, timeout, max_latency_ms):
    print(f"[3/5] Checking {len(proxies)} proxies "
          f"(concurrency={concurrency}, timeout={timeout}s, "
          f"max_latency={max_latency_ms}ms)...")
    if not SOCKS_SUPPORT:
        n_socks = sum(1 for p in proxies if p["scheme"].startswith("socks"))
        if n_socks:
            print(f"      WARNING: aiohttp-socks not installed — "
                  f"{n_socks} SOCKS proxies will be SKIPPED. "
                  f"Run: pip install aiohttp-socks")

    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            asyncio.create_task(
                check_one(session, p, i, timeout, max_latency_ms, sem)
            )
            for i, p in enumerate(proxies)
        ]
        results = []
        done, ok = 0, 0
        for fut in asyncio.as_completed(tasks):
            res = await fut
            results.append(res)
            done += 1
            if res.get("ok"):
                ok += 1
                print(f"   OK [{done}/{len(proxies)}] {res['url']}  "
                      f"{res['latency_ms']:.0f}ms  (echo={res.get('echoed_ip', '?')})")
            elif done % 100 == 0:
                print(f"   .. [{done}/{len(proxies)}] checked, {ok} working so far")
    return results


# ===========================================================================
# STEP 4 — write output files
# ===========================================================================
def write_output(results, out_dir, max_latency_ms, elapsed):
    working = sorted((r for r in results if r.get("ok")),
                     key=lambda r: r["latency_ms"])

    os.makedirs(out_dir, exist_ok=True)

    # combined file
    all_path = os.path.join(out_dir, "working_all.txt")
    with open(all_path, "w", encoding="utf-8") as f:
        for r in working:
            f.write(r["url"] + "\n")

    # per-protocol files
    by_scheme = defaultdict(list)
    for r in working:
        by_scheme[r["scheme"]].append(r)
    for scheme, items in by_scheme.items():
        path = os.path.join(out_dir, f"working_{scheme}.txt")
        with open(path, "w", encoding="utf-8") as f:
            for r in items:
                f.write(r["url"] + "\n")

    print(f"[4/5] Working proxies (<{max_latency_ms}ms): {len(working)}")
    for scheme in ("http", "https", "socks4", "socks5"):
        if scheme in by_scheme:
            print(f"      working_{scheme}.txt: {len(by_scheme[scheme])}")
    print(f"      working_all.txt:    {len(working)}")
    print(f"      Saved to: {out_dir}")

    # per-source stats
    src_ok = defaultdict(int)
    for r in working:
        src_ok[r["src"]] += 1
    if src_ok:
        print("\n      Best sources:")
        for name, cnt in sorted(src_ok.items(), key=lambda kv: -kv[1])[:10]:
            print(f"        {name:22} {cnt:5} working")

    if working:
        print("\n      Top 15 fastest:")
        for i, r in enumerate(working[:15], 1):
            print(f"        {i:>3}  {r['url']:38} {r['latency_ms']:>7.0f}ms")
    return working


# ===========================================================================
# MAIN
# ===========================================================================
async def amain():
    ap = argparse.ArgumentParser(description="Multi-source proxy parser & checker")
    ap.add_argument("--out-dir", default=os.getcwd(),
                    help="Directory for output files")
    ap.add_argument("--timeout", type=float, default=4.0,
                    help="Per-proxy timeout, seconds")
    ap.add_argument("--concurrency", type=int, default=500,
                    help="Simultaneous checks (Windows-safe up to ~1000)")
    ap.add_argument("--max-latency", type=int, default=400,
                    help="Keep proxies with latency below this, ms")
    ap.add_argument("--limit", type=int, default=0,
                    help="Check only N random proxies (0 = all)")
    ap.add_argument("--only", default=None,
                    help="Comma-separated schemes to check, e.g. http,https")
    ap.add_argument("--no-html", action="store_true", help="Skip HTML sources")
    ap.add_argument("--no-socks", action="store_true", help="Skip SOCKS sources")
    args = ap.parse_args()

    t0 = time.perf_counter()
    print("=" * 70)
    print(" MULTI-SOURCE PROXY PARSER & CHECKER (async)")
    print("=" * 70)

    # -- 1. fetch --
    sources = SOURCES
    if args.no_html:
        sources = [s for s in sources if s["kind"] != "html"]
    if args.no_socks:
        sources = [s for s in sources if not s["scheme"].startswith("socks")]
    fetched = await fetch_all_sources(sources)

    # -- 2. parse & dedupe --
    proxies = collect_proxies(fetched)
    if not proxies:
        print("No proxies found. Exiting.")
        sys.exit(1)

    # -- filter by scheme / limit --
    if args.only:
        allowed = {s.strip() for s in args.only.split(",")}
        proxies = [p for p in proxies if p["scheme"] in allowed]
        print(f"      Filtered by --only {allowed}: {len(proxies)} left")
    if args.limit and len(proxies) > args.limit:
        random.shuffle(proxies)
        proxies = proxies[:args.limit]
        print(f"      Random sample (--limit): {len(proxies)}")

    # -- 3. check --
    results = await check_all(proxies, args.concurrency, args.timeout, args.max_latency)

    # -- 4. output --
    elapsed = time.perf_counter() - t0
    write_output(results, args.out_dir, args.max_latency, elapsed)

    print("\n" + "=" * 70)
    print(f" DONE in {elapsed:.0f}s.  "
          f"{sum(1 for r in results if r.get('ok'))}/{len(results)} OK.")
    print(f" Output: {os.path.abspath(args.out_dir)}")
    print("=" * 70)


def _silence_proactor_noise(loop, context):
    """Windows/Proactor: swallow ConnectionResetError noise from
    _ProactorBasePipeTransport._call_connection_lost (known CPython quirk)."""
    exc = context.get("exception")
    if isinstance(exc, ConnectionResetError):
        return
    loop.default_exception_handler(context)


if __name__ == "__main__":
    if sys.platform == "win32":
        # Proactor handles high concurrency without FD_SETSIZE(512) limit;
        # its cosmetic ConnectionResetError noise is silenced above.
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(_silence_proactor_noise)
    try:
        loop.run_until_complete(amain())
    finally:
        loop.close()