"""
recon_scanner.py

ReconScanner - a reusable class for passive & active reconnaissance and light scanning.
- Designed with safe defaults.
- Requires: aiohttp, python-whois, dnspython
- Usage: see examples at bottom of file.

WARNING: Use only on targets you are authorized to test.
"""

import asyncio
import aiohttp
import socket
import time
import re
import html
import urllib.parse
from datetime import datetime
from typing import List, Optional, Dict, Any, Set
import whois
import dns.resolver
import logging

# ---------- Configuration ----------
SAFE_MAX_CONCURRENCY = 80
DEFAULT_PORTS = [80, 443, 8080, 8443]
DEFAULT_TIMEOUT = 4.0
DIR_BRUTEFORCE_ENABLED = False  # <-- keep False unless explicitly enabled
DIR_DEFAULT_WORDLIST = ["admin","backup",".env","config.php","wp-admin","login","dashboard"]

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ReconScanner")

# ---------- Utilities ----------
def _normalize_target(target: str):
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc.split(":")[0]
        scheme = parsed.scheme
    else:
        domain = target
        scheme = "https"
    return domain, scheme

def _extract_links(base_url: str, html_text: str) -> List[str]:
    hrefs = set()
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html_text, re.IGNORECASE):
        href = m.group(1)
        href = html.unescape(href)
        hrefs.add(urllib.parse.urljoin(base_url, href))
    return list(hrefs)

# ---------- ReconScanner class ----------
class ReconScanner:
    def __init__(self,
                 concurrency: int = 20,
                 timeout: float = DEFAULT_TIMEOUT,
                 dir_wordlist: Optional[List[str]] = None):
        self.concurrency = min(concurrency, SAFE_MAX_CONCURRENCY)
        self.timeout = timeout
        self.dir_wordlist = dir_wordlist or DIR_DEFAULT_WORDLIST

    # ---------------- Passive Recon ----------------
    async def passive_recon(self, target: str) -> Dict[str, Any]:
        """
        Perform passive recon:
         - whois
         - DNS records (A, AAAA, MX, TXT, NS, CNAME)
         - crt.sh lookup for cert subdomains (public)
         - try robots.txt and sitemap.xml (http & https)
         - quick GitHub code search page (limited scraping)
        """
        domain, _ = _normalize_target(target)
        out = {"target": domain, "timestamp": datetime.utcnow().isoformat()}

        # WHOIS (blocking) -> run in thread
        try:
            who = await asyncio.to_thread(whois.whois, domain)
            out["whois"] = {
                "domain_name": who.get("domain_name"),
                "registrar": who.get("registrar"),
                "creation_date": str(who.get("creation_date")),
                "expiration_date": str(who.get("expiration_date")),
                "emails": who.get("emails")
            }
        except Exception as e:
            out["whois_error"] = str(e)

        # DNS lookups
        dns_records = {}
        resolver = dns.resolver.Resolver()
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
            try:
                ans = await asyncio.to_thread(resolver.resolve, domain, rtype, lifetime=3.0)
                dns_records[rtype] = [str(r.to_text()) for r in ans]
            except Exception:
                dns_records[rtype] = []
        out["dns"] = dns_records

        # crt.sh
        try:
            crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                resp = await session.get(crt_url, timeout=6)
                if resp.status == 200:
                    j = await resp.json()
                    subs = set()
                    for entry in j:
                        name = entry.get("name_value")
                        if name:
                            for n in name.split("\n"):
                                subs.add(n.strip().lstrip("*."))
                    out["crtsh_subdomains"] = sorted(subs)
                else:
                    out["crtsh_status"] = resp.status
        except Exception as e:
            out["crtsh_error"] = str(e)

        # robots & sitemap
        robots = {}
        sitemaps = {}
        async with aiohttp.ClientSession() as session:
            for scheme in ("https", "http"):
                for path, store in (("/robots.txt", robots), ("/sitemap.xml", sitemaps)):
                    url = f"{scheme}://{domain}{path}"
                    try:
                        r = await session.get(url, ssl=False, timeout=self.timeout)
                        text = await r.text(errors='ignore') if r.status == 200 else ""
                        store[url] = {"status": r.status, "text_snippet": text[:500]}
                    except Exception as e:
                        store[url] = {"error": str(e)}
        out["robots"] = robots
        out["sitemaps"] = sitemaps

        # quick github search page (just to check hits; limited)
        try:
            q = urllib.parse.quote(domain)
            gh_url = f"https://github.com/search?q={q}&type=code"
            async with aiohttp.ClientSession() as session:
                r = await session.get(gh_url, timeout=6)
                if r.status == 200:
                    text = await r.text()
                    hits = re.findall(r'href="(/[^/]+/[^/]+/blob/[^"]+)"', text, re.IGNORECASE)
                    out["github_example_hits"] = list(dict.fromkeys(hits))[:10]
                else:
                    out["github_status"] = r.status
        except Exception as e:
            out["github_error"] = str(e)

        return out
    async def scan_ports_range(self,
                               target: str,
                               start_port: int = 1,
                               end_port: int = 65535,
                               batch_size: int = 2000,
                               timeout: Optional[float] = None,
                               concurrency: Optional[int] = None,
                               pause_between_batches: float = 0.05
                               ) -> Dict[str, Any]:
        timeout = timeout or self.timeout
        concurrency = min(concurrency or self.concurrency, SAFE_MAX_CONCURRENCY)

        # resolve target
        try:
            resolved = socket.gethostbyname(target)
        except Exception as e:
            return {"error": f"resolve_failed: {e}"}

        # validate range
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            return {"error": "invalid port range"}

        all_results = []
        ports = list(range(start_port, end_port + 1))

        # process in batches
        for i in range(0, len(ports), batch_size):
            batch = ports[i:i + batch_size]
            sem = asyncio.Semaphore(concurrency)

            async def scan_one(p):
                async with sem:
                    return await asyncio.to_thread(self._sync_connect, resolved, p, timeout)

            # create tasks for this batch
            tasks = [asyncio.create_task(scan_one(p)) for p in batch]
            # gather results
            batch_results = await asyncio.gather(*tasks)
            all_results.extend(batch_results)

            # optional small pause to avoid bursts
            if pause_between_batches and (i + batch_size) < len(ports):
                await asyncio.sleep(pause_between_batches)

        return {"target": target, "resolved_ip": resolved, "start_port": start_port, "end_port": end_port, "results": all_results}

    # ---------------- Active Recon ----------------
    async def active_recon(self, target: str, fetch_sitemap: bool = True, vhost_checks: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Active recon: fetch base page, headers (fingerprinting), robots/sitemap,
                     check optional virtual hosts (Host header).
        """
        domain, scheme = _normalize_target(target)
        out = {"target": domain, "timestamp": datetime.utcnow().isoformat(), "actions": {}}

        async with aiohttp.ClientSession() as session:
            # base fetch
            try:
                base_url = f"{scheme}://{domain}/"
                r = await session.get(base_url, ssl=False, timeout=self.timeout)
                text = await r.text(errors='ignore') if r.status == 200 else ""
                out["actions"]["base_fetch"] = {
                    "url": base_url, "status": r.status,
                    "server": r.headers.get("Server"),
                    "x_powered_by": r.headers.get("X-Powered-By"),
                    "content_type": r.headers.get("Content-Type"),
                    "snippet": text[:500]
                }
            except Exception as e:
                out["actions"]["base_fetch_error"] = str(e)

            # robots/sitemap
            if fetch_sitemap:
                for path in ["/robots.txt", "/sitemap.xml"]:
                    try:
                        url = f"{scheme}://{domain}{path}"
                        r = await session.get(url, ssl=False, timeout=self.timeout)
                        text = await r.text(errors='ignore') if r.status == 200 else ""
                        out["actions"][path] = {"url": url, "status": r.status, "snippet": text[:500]}
                    except Exception as e:
                        out["actions"][path] = {"error": str(e)}

            # vhost checks
            vhosts = vhost_checks or []
            vhost_res = {}
            for v in vhosts:
                try:
                    headers = {"Host": v}
                    r = await session.get(f"{scheme}://{domain}/", headers=headers, ssl=False, timeout=self.timeout)
                    vhost_res[v] = {"status": r.status, "server": r.headers.get("Server")}
                except Exception as e:
                    vhost_res[v] = {"error": str(e)}
            out["vhost_checks"] = vhost_res

        return out

    # ---------------- Simple TCP connect port scan ----------------
    async def scan_ports(self, target: str, ports: Optional[List[int]] = None, timeout: Optional[float] = None, concurrency: Optional[int] = None) -> Dict[str, Any]:
        """
        TCP connect scan (non-stealthy, requires no root).
        """
        timeout = timeout or self.timeout
        concurrency = min(concurrency or self.concurrency, SAFE_MAX_CONCURRENCY)
        ports = ports or DEFAULT_PORTS
        if len(ports) > 1000:
            raise ValueError("Too many ports requested (>1000). Limit scans to reasonable size.")

        # resolve target to IP
        try:
            resolved = socket.gethostbyname(target)
        except Exception as e:
            return {"error": f"resolve_failed: {e}"}

        sem = asyncio.Semaphore(concurrency)
        async def _check(p):
            async with sem:
                return await asyncio.to_thread(self._sync_connect, resolved, p, timeout)

        tasks = [asyncio.create_task(_check(p)) for p in ports]
        results = await asyncio.gather(*tasks)
        return {"target": target, "resolved_ip": resolved, "results": results}

    def _sync_connect(self, ip: str, port: int, timeout: float):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                try:
                    banner = s.recv(1024).decode(errors='ignore').strip()
                except Exception:
                    banner = ""
                return {"port": port, "open": True, "banner": banner}
        except Exception:
            return {"port": port, "open": False}

    # ---------------- Simple web crawler (enumerate links & params) ----------------
    async def discover_web(self, start_url: str, max_depth: int = 2, same_host_only: bool = True) -> Dict[str, Any]:
        """
        Crawl pages up to max_depth. Returns pages with status and collected links/params.
        """
        start_url = start_url.rstrip("/")
        parsed_base = urllib.parse.urlparse(start_url)
        base_host = parsed_base.netloc

        session_timeout = aiohttp.ClientTimeout(total=10)
        found_pages: Dict[str, Any] = {"start": start_url, "pages": {}, "links": set(), "params": set()}
        visited: Set[str] = set()
        q: asyncio.Queue = asyncio.Queue()
        await q.put((start_url, 0))

        async with aiohttp.ClientSession(timeout=session_timeout) as session:
            sem = asyncio.Semaphore(self.concurrency)

            async def worker():
                while not q.empty():
                    u, depth = await q.get()
                    if u in visited or depth > max_depth:
                        q.task_done()
                        continue
                    visited.add(u)
                    try:
                        async with sem:
                            r = await session.get(u, ssl=False, timeout=self.timeout)
                            status = r.status
                            text = await r.text(errors='ignore') if status == 200 else ""
                            found_pages["pages"][u] = {"status": status}
                            links = _extract_links(u, text)
                            for l in links:
                                p = urllib.parse.urlparse(l)
                                if p.query:
                                    found_pages["params"].add(l)
                                if same_host_only and p.netloc != base_host:
                                    continue
                                if l not in visited and depth+1 <= max_depth:
                                    await q.put((l, depth+1))
                                found_pages["links"].add(l)
                    except Exception as e:
                        found_pages["pages"][u] = {"error": str(e)}
                    q.task_done()

            workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
            await q.join()
            for w in workers:
                w.cancel()

        # convert sets to lists
        found_pages["links"] = sorted(list(found_pages["links"]))
        found_pages["params"] = sorted(list(found_pages["params"]))
        return found_pages

    # ---------------- Directory brute-force (dangerous) ----------------
    async def bruteforce_dirs(self, base_url: str, wordlist: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Directory brute-force using wordlist. Disabled by default via global flag. Use only in authorized environment.
        """
        if not DIR_BRUTEFORCE_ENABLED:
            raise PermissionError("Directory brute-force is disabled by default. Enable only in authorized tests.")
        wl = wordlist or self.dir_wordlist
        async with aiohttp.ClientSession() as session:
            results = {}
            for w in wl:
                test = base_url.rstrip("/") + "/" + w.lstrip("/")
                try:
                    r = await session.get(test, ssl=False, timeout=self.timeout)
                    results[test] = {"status": r.status}
                except Exception as e:
                    results[test] = {"error": str(e)}
        return {"base": base_url, "results": results}

# ---------- Example usage ----------
if __name__ == "__main__":
    async def main():
        scanner = ReconScanner(concurrency=10, timeout=4.0)
        target = "example.com"

        print("=== Passive recon ===")
        pr = await scanner.passive_recon(target)
        print(pr.keys())

        print("=== Active recon ===")
        ar = await scanner.active_recon(target, fetch_sitemap=True, vhost_checks=["dev.example.com","test.example.com"])
        print(ar.keys())

        print("=== Port scan ===")
        ps = await scanner.scan_ports(target, ports=[80,443,22], concurrency=10)
        print(ps)

        print("=== Web discovery (depth=1) ===")
        d = await scanner.discover_web("https://example.com", max_depth=1)
        print("Found links:", len(d["links"]))

    asyncio.run(main())
