"""Recon & passive/light scanning primitives for the bug-bounty MCP server.

Everything here is pure Python (httpx + dnspython + stdlib sockets) so it runs
on a stock Windows box with no native scanners installed. Active scanning
(target fuzzing) is intentionally light and rate-limited; always scan ONLY
targets you are explicitly authorized to test (in-scope on a bug bounty
program or your own assets).
"""

from __future__ import annotations

import asyncio
import concurrent.futures as cf
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field

import httpx
import dns.resolver

TIMEOUT = 10.0
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
    ),
    "Accept": "*/*",
}

# ---------------------------------------------------------------------------
# small bundled wordlists so the tools work out of the box (no external files)
# ---------------------------------------------------------------------------

SUBDOMAIN_WORDLIST = [
    "admin", "api", "app", "bbs", "blog", "cdn", "cms", "demo", "dev", "docs",
    "download", "ftp", "git", "graphql", "img", "images", "login", "mail", "m",
    "mobile", "my", "new", "news", "old", "pay", "portal", "sso", "static",
    "status", "store", "staging", "test", "vpn", "w", "web", "www", "ww1",
    "ww2", "ww3", "www2", "auth", "oauth", "console", "dashboard", "db",
]

DIR_WORDLIST = [
    "admin", "api", "backup", "bak", "config", "console", "css", "data", "db",
    "debug", "dev", "docs", "env", "error", "favicon.ico", "files", "git",
    "graphql", "health", "images", "img", "index", "js", "json", "login",
    "logout", "metrics", "phpinfo.php", "private", "robots.txt", "sitemap.xml",
    "source", "src", "static", "status", "test", "tmp", "upload", "uploads",
    "user", "users", "web", "www", "wp-admin", "wp-content", "wp-login.php",
    ".git/HEAD", ".env", ".gitignore", ".htaccess", "server-status",
    "actuator", "actuator/env", "actuator/health", "swagger", "swagger-ui.html",
    "api/v1", "api/v2", ".well-known/security.txt",
]

SECURITY_HEADERS = [
    ("Content-Security-Policy", "CSP missing or partially configured"),
    ("Strict-Transport-Security", "HSTS not set (only relevant over HTTPS)"),
    ("X-Frame-Options", "Clickjacking protection header missing"),
    ("X-Content-Type-Options", "MIME-sniffing protection header missing"),
    ("Referrer-Policy", "Referrer policy header missing"),
    ("Permissions-Policy", "Permissions policy header missing"),
]

SENSITIVE_PATHS = [
    ".git/config", ".git/HEAD", ".env", ".env.local", "backup.zip", "backup.sql",
    "wp-config.php.bak", ".htaccess", "config.php.bak", "db.sql", "dump.sql",
    ".DS_Store", "phpinfo.php",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _norm_host(host: str) -> str:
    host = host.strip().lower()
    if host.startswith(("http://", "https://")):
        host = host.split("://", 1)[1]
    host = host.split("/")[0]
    host = re.sub(r":\d+$", "", host)
    return host.strip()


def _fmt_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


@dataclass
class Finding:
    severity: str  # info | low | medium | high
    title: str
    detail: str = ""

    def render(self) -> str:
        return f"[{self.severity.upper()}] {self.title}" + (f" :: {self.detail}" if self.detail else "")


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def resolve(host: str) -> str:
    """Resolve A/AAAA/CNAME records for a host."""
    host = _norm_host(host)
    res = dns.resolver.Resolver()
    res.timeout = TIMEOUT
    res.lifetime = TIMEOUT
    out = []
    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        try:
            ans = res.resolve(host, rtype)
            items = sorted({str(r.to_text() if rtype == "TXT" else r).strip('"') for r in ans})
            out.append(f"{rtype}: {', '.join(items)}")
        except Exception:
            pass
    if not out:
        return f"NO_RECORDS for {host}"
    return "\n".join(out)


def subdomains(domain: str, wordlist: list[str] | None = None, verify: bool = False) -> str:
    """Enumerate subdomains via Certificate Transparency (crt.sh) + DNS brute force.

    `verify=True` additionally probes each subdomain over HTTP(S) and marks it
    [live]/[dead], deduping catch-all hosts (same IP + same title = likely a
    wildcard/CGNAT catch-all, e.g. campus networks where every name resolves).
    """
    domain = _norm_host(domain)
    wl = wordlist or SUBDOMAIN_WORDLIST
    found: set[str] = set()

    # 1) certificate transparency
    try:
        r = httpx.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=TIMEOUT,
            headers=HEADERS,
        )
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith("." + domain) or name == domain:
                        found.add(name)
    except Exception as e:
        found_note = f"(crt.sh failed: {e})"
    else:
        found_note = "(crt.sh ok)"

    # 2) DNS brute force
    # lifetime must outlive a single flaky nameserver (CGNAT gateways commonly
    # drop DNS) so the resolver can fall through to the backup servers.
    res = dns.resolver.Resolver()
    res.timeout = 4.0
    res.lifetime = 8.0

    def try_name(name: str) -> str | None:
        try:
            res.resolve(f"{name}.{domain}", "A")
            return f"{name}.{domain}"
        except Exception:
            return None

    with cf.ThreadPoolExecutor(max_workers=50) as ex:
        for r in ex.map(try_name, wl):
            if r:
                found.add(r)

    if not found:
        return f"No subdomains found for {domain} {found_note}"

    rows = sorted(found)
    if not verify:
        head = f"Subdomains for {domain} ({len(rows)} total) {found_note}:\n"
        return head + "\n".join(f"  {r}" for r in rows)

    # --- live verification: probe each name, catch duplicates (wildcard/CGNAT)
    def probe_sub(name: str) -> dict:
        for scheme in ("https", "http"):
            info = _probe(f"{scheme}://{name}", follow=True, timeout=6.0)
            if info.get("status"):
                return info
        return {"status": 0, "error": "unreachable"}

    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        probed = {n: probe_sub(n) for n in rows}

    import hashlib

    def _sig(name: str, info: dict) -> str:
        # catch-all signature: redirect destination (if any) + title + size bucket.
        # final_url is NOT used — it's the requested host itself when there is no
        # redirect, which would make every dead twin look unique.
        redirects = info.get("redirects") or []
        dest = str(redirects[-1][1]) if redirects else ""
        key = (dest[:80],
               str(info.get("title", ""))[:60],
               str((info.get("length", 0) or 0) // 256))
        return hashlib.md5("|".join(key).encode()).hexdigest()[:8]

    sigs = {n: _sig(n, i) for n, i in probed.items() if i.get("status")}
    first_of: dict[str, str] = {}
    for n in sorted(sigs):
        first_of.setdefault(sigs[n], n)

    out = [f"Subdomains for {domain} ({len(rows)} total, HTTP-verified) {found_note}:"]
    live = dead = 0
    for n in rows:
        info = probed[n]
        status = info.get("status") or 0
        if not status or status >= 500:
            dead += 1
            why = f" (HTTP {status})" if status else ""
            out.append(f"  [dead]{why:14} {n}")
            continue
        live += 1
        twin = ""
        if sum(1 for m, s in sigs.items() if s == sigs[n]) > 1:
            twin = f"  ⚠ same page as {first_of[sigs[n]]} (wildcard/catch-all?)"
        title = info.get("title", "")
        out.append(
            f"  [live]  {n}  {status} [{info.get('length', 0) or 0}B]"
            f"{'  title=' + title if title else ''}{twin}"
        )
    out.insert(1, f"({live} live / {dead} dead — rows marked ⚠ serve the same page as another name: wildcard/catch-all, trust them least)")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Port scan
# ---------------------------------------------------------------------------

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445,
                465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389,
                5000, 5432, 5601, 6379, 7001, 8000, 8008, 8080, 8081, 8088,
                8443, 8888, 9000, 9090, 9200, 9201, 9443, 10000, 11211, 27017]


def port_scan(host: str, ports: list[int] | None = None, timeout: float = 1.0) -> str:
    """Concurrent TCP connect() port scan (no privileges needed)."""
    host = _norm_host(host)
    ports = ports or COMMON_PORTS
    open_ports: list[tuple[int, str]] = []
    closed: int = 0

    def check(p: int) -> tuple[int, str] | None:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                return p, socket.getservbyport(p) if _has_servbyport(p) else "?"
        except Exception:
            return None

    try:
        with cf.ThreadPoolExecutor(max_workers=100) as ex:
            results = list(ex.map(check, ports))
    except Exception as e:
        return f"port_scan failed: {e}"

    for i, p in enumerate(ports):
        if results[i]:
            open_ports.append((p, results[i][1]))
        else:
            closed += 1

    if not open_ports:
        return f"No open ports found on {host} ({closed} closed/filtered tested)."
    lines = [f"Open ports on {host}:"]
    for p, svc in sorted(open_ports):
        lines.append(f"  {p:<6} {svc}")
    return "\n".join(lines)


def _has_servbyport(p: int) -> bool:
    try:
        socket.getservbyport(p)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# HTTP probing & fingerprinting
# ---------------------------------------------------------------------------

def _probe(url: str, follow: bool = True, timeout: float = TIMEOUT) -> dict:
    try:
        with httpx.Client(follow_redirects=follow, timeout=timeout, headers=HEADERS,
                          verify=False, http2=False) as c:
            r = c.get(url)
        return {
            "status": r.status_code,
            "final_url": str(r.url),
            "title": _extract_title(r.text),
            "server": r.headers.get("server", ""),
            "tech": _tech_from_headers(r.headers) or _tech_from_body(r.text),
            "length": len(r.content),
            "headers": dict(r.headers),
            "redirects": [(str(h.status_code), str(h.headers.get("location", "")))
                          for h in r.history],
        }
    except Exception as e:
        return {"error": str(e), "status": 0}


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


def _tech_from_headers(headers: dict) -> str:
    sig = []
    server = (headers.get("server") or "").lower()
    for marker in ("cloudflare", "nginx", "apache", "iis", "openresty",
                   "caddy", "gunicorn", "werkzeug", "node", "express", "tomcat"):
        if marker in server:
            sig.append(marker)
    if headers.get("x-powered-by"):
        sig.append(headers["x-powered-by"])
    if headers.get("x-generator"):
        sig.append(headers["x-generator"])
    return ", ".join(sig)


def _tech_from_body(html: str) -> str:
    sig = set()
    checks = [
        ("WordPress", r"wp-content", "wordpress"),
        ("Drupal", r"drupal", "drupal"),
        ("Joomla", r"joomla", "joomla"),
        ("Laravel", r"laravel", "laravel"),
        ("Django", r"csrfmiddlewaretoken", "django"),
        ("Rails", r"rails", "rails"),
        ("jQuery", r"jquery", "jquery"),
        ("React", r"data-reactroot|__NEXT_DATA__|_next/static", "react/nextjs"),
        ("Vue", r"data-v-|vue\.js", "vue"),
        ("Bootstrap", r"bootstrap", "bootstrap"),
        ("Swagger", r"swagger", "swagger"),
    ]
    for _, pat, name in checks:
        if re.search(pat, html, re.I):
            sig.add(name)
    return ", ".join(sorted(sig))


def http_probe(targets: str, follow: bool = True) -> str:
    """Probe a list of URLs/hosts (one per line or comma-separated)."""
    parts = [p for p in re.split(r"[\n,]+", targets) if p.strip()]
    urls = [_fmt_url(p) for p in parts]
    if not urls:
        return "No targets given."
    out = []
    for u in urls:
        info = _probe(u, follow=follow)
        if info.get("status"):
            out.append(
                f"{info['status']}  {u}"
                f"{'  -> ' + info['final_url'] if info['final_url'] != u else ''}"
                f"  [{info['length']}B]"
                f"{'  title=' + info['title'] if info['title'] else ''}"
                f"{'  tech=' + info['tech'] if info['tech'] else ''}"
            )
        else:
            out.append(f"ERR   {u}  ({info.get('error', 'unreachable')})")
    return "\n".join(out)


def tech_detect(url: str) -> str:
    """Fingerprint web technologies for a URL."""
    u = _fmt_url(url)
    info = _probe(u, follow=True)
    if not info.get("status"):
        return f"Could not reach {u}: {info.get('error')}"
    lines = [
        f"Target: {u}",
        f"Status: {info['status']}  Server: {info.get('server') or '(none)'}",
        f"Title : {info.get('title') or '(none)'}",
        f"Tech  : {info.get('tech') or '(none detected)'}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Directory / endpoint fuzzing
# ---------------------------------------------------------------------------

def dir_fuzz(base_url: str, wordlist: list[str] | None = None,
             extensions: str = "", timeout: float = 8.0,
             max_threads: int = 20) -> str:
    """Brute force directories/endpoints under base_url (HTTP GET)."""
    base = _fmt_url(base_url)
    wl = wordlist or DIR_WORDLIST
    exts = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()]

    def candidates() -> list[str]:
        c = []
        for w in wl:
            if "." in w.split("/")[-1] or "/" in w:  # has extension or is a path
                c.append(w)
                continue
            c.append(w)
            for e in exts:
                c.append(f"{w}.{e}")
        return list(dict.fromkeys(c))

    paths = candidates()
    found: list[tuple[int, str, int, str]] = []

    def check(path: str) -> tuple[int, str, int, str] | None:
        url = f"{base.rstrip('/')}/{path}"
        try:
            with httpx.Client(follow_redirects=False, timeout=timeout,
                              headers=HEADERS, verify=False) as c:
                r = c.get(url)
            if r.status_code in (200, 301, 302, 307, 308, 401, 403, 405, 500):
                loc = r.headers.get("location", "")
                return r.status_code, url, len(r.content), loc
        except Exception:
            pass
        return None

    with cf.ThreadPoolExecutor(max_workers=max_threads) as ex:
        for r in ex.map(check, paths):
            if r:
                found.append(r)

    if not found:
        return f"No interesting endpoints found under {base} ({len(paths)} paths tested)."
    out = [f"Found {len(found)}/{len(paths)} endpoints under {base}:"]
    for status, url, size, loc in sorted(found, key=lambda x: x[0]):
        line = f"  {status}  [{size}B]  {url}"
        if loc:
            line += f"  -> {loc}"
        out.append(line)

    # catch-all / SPA detection: if the vast majority of hits look identical,
    # the app is probably redirecting/serving the same page for any path.
    if len(found) >= 5:
        import collections
        buckets = collections.Counter((s, size // 256) for s, _u, size, _l in found)
        (top_key, top_n), = buckets.most_common(1)
        if top_n >= max(5, int(0.7 * len(found))):
            out.append(
                f"  ⚠ CATCH-ALL WARNING: {top_n}/{len(found)} responses share "
                f"status {top_key[0]} and similar size (~{top_key[1] * 256}B). "
                "The app likely serves the same page for any path (SPA/auth filter) "
                "— treat most hits as false positives; verify top candidates manually."
            )
        locs = collections.Counter(l for _s, _u, _z, l in found if l)
        if locs:
            top_loc, top_loc_n = locs.most_common(1)[0]
            if top_loc_n >= max(5, int(0.8 * len(found))):
                out.append(
                    f"  ⚠ UNIFORM REDIRECT: {top_loc_n}/{len(found)} hits redirect to "
                    f"{top_loc[:120]} — probably an auth filter, not real endpoints."
                )
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Header / config / CORS analysis
# ---------------------------------------------------------------------------

def headers_check(url: str) -> str:
    """Passive check of security headers, CORS posture, cookies and sensitive files."""
    u = _fmt_url(url)
    with httpx.Client(follow_redirects=True, timeout=TIMEOUT, headers=HEADERS,
                      verify=False) as c:
        r = c.get(u)
        headers = r.headers

    findings: list[Finding] = []

    # positive headers present
    present = [h for h in ("content-security-policy", "strict-transport-security",
                           "x-frame-options", "x-content-type-options",
                           "referrer-policy", "permissions-policy") if h in headers]

    # missing security headers
    for h, msg in SECURITY_HEADERS:
        if h.lower() not in headers:
            findings.append(Finding("low", f"Missing header: {h}", msg))

    # CORS
    cors = headers.get("access-control-allow-origin", "")
    if cors:
        if cors == "*":
            findings.append(Finding("medium", "CORS wildcard `*`", "Any origin allowed (check if credentials are used)."))
        elif re.search(r"https?://", cors):
            findings.append(Finding("low", "CORS reflects specific origin", cors))

    # cookies
    for ch in r.headers.get_list("set-cookie"):
        if "HttpOnly" not in ch:
            findings.append(Finding("medium", "Cookie without HttpOnly", ch.split(";")[0].strip()[:60]))
        if "Secure" not in ch:
            findings.append(Finding("low", "Cookie without Secure flag", ch.split(";")[0].strip()[:60]))

    # server banner / powered-by
    if headers.get("server"):
        findings.append(Finding("info", "Server banner exposed", headers["server"]))
    if headers.get("x-powered-by"):
        findings.append(Finding("info", "X-Powered-By exposed", headers["x-powered-by"]))

    out = [
        f"=== Security analysis for {u} ===",
        f"HTTP {r.status_code}",
        f"Present headers : {', '.join(present) if present else '(none)'}",
        f"Server banner   : {headers.get('server') or '(none)'}",
    ]
    out += [f"  {f.render()}" for f in findings] if findings else ["No header-level issues detected."]

    # sensitive files (light, low-concurrency)
    out.append("\n=== Sensitive file checks ===")
    found_files = 0
    # baseline for catch-all detection: SPAs often echo the path/size into the
    # body, so exact-match fails — strip digits and compare structure instead
    import difflib
    import hashlib

    def _norm(body: str) -> str:
        return re.sub(r"\d+", "", body or "")[:8000]

    base_sig = hashlib.md5(r.content).hexdigest()
    base_norm = _norm(r.text)
    for path in SENSITIVE_PATHS:
        try:
            with httpx.Client(follow_redirects=False, timeout=5.0, headers=HEADERS,
                              verify=False) as c:
                rr = c.get(f"{u.rstrip('/')}/{path}")
            if rr.status_code in (200, 301, 302) and rr.status_code != 404:
                found_files += 1
                note = ""
                if rr.status_code == 200:
                    if hashlib.md5(rr.content).hexdigest() == base_sig:
                        note = "  ⚠ identical to homepage — SPA/catch-all, likely FALSE"
                    else:
                        ratio = difflib.SequenceMatcher(
                            None, base_norm, _norm(rr.text)).ratio()
                        if ratio > 0.95:
                            note = (f"  ⚠ {ratio:.0%} identical to homepage — "
                                    "SPA/catch-all, likely FALSE")
                        elif len(rr.content) < max(200, int(0.1 * max(len(r.content), 1))):
                            note = "  (small body — could be a real file, verify)"
                out.append(f"  FOUND ({rr.status_code}, {len(rr.content)}B): /{path}{note}")
        except Exception:
            pass
    if not found_files:
        out.append("  (none of the common sensitive files were exposed)")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Integrated quick recon
# ---------------------------------------------------------------------------

def target_analyse(target: str, do_subdomains: bool = True, do_ports: bool = True) -> str:
    """Run a quick one-shot recon report for a target (web probe, headers, tech, ports, subdomains)."""
    host = _norm_host(target)
    section = lambda t: f"\n=============================\n{'- {} -'.format(t)}"
    out = [f"QUICK RECON  ::  {target}  (host: {host})"]

    out.append(section("DNS"))
    out.append(resolve(host))

    out.append(section("HTTP probe (https)"))
    probe = _probe(f"https://{host}", follow=True)
    if probe.get("status"):
        out.append(f"  {probe['status']}  title={probe.get('title')!r}  server={probe.get('server')!r}  tech={probe.get('tech')!r}  size={probe.get('length')}B")
    else:
        out.append(f"  https unreachable: {probe.get('error')}")
        p2 = _probe(f"http://{host}", follow=True)
        out.append(f"  http probe: {p2.get('status')} {p2.get('title')!r} tech={p2.get('tech')!r}")
    # redirect chain
    if probe.get("redirects"):
        out.append("  redirect chain: " + " -> ".join(f"{s}->{l}" for s, l in probe["redirects"]) + f" -> {probe['final_url']}")

    if do_ports:
        out.append(section("Top ports (Web/DB/common)"))
        out.append(port_scan(host))

    if do_subdomains:
        out.append(section("Subdomains (CT + wordlist)"))
        out.append(subdomains(host))

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Nuclei (template-based vulnerability scanning)
# ---------------------------------------------------------------------------

# Resolve the nuclei binary + templates directory relative to this package so
# the tool is portable if the project is moved.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NUCLEI_EXE = os.path.join(_PKG_ROOT, "bin", "nuclei.exe")

def _find_templates() -> str:
    candidates = [
        os.path.abspath(os.path.join(_PKG_ROOT, "..", "bb-repos", "nuclei-templates")),
        r"C:\Users\LT\Desktop\Workspace\bb-repos\nuclei-templates",
        os.path.join(_PKG_ROOT, "nuclei-templates"),
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    return candidates[0]

TEMPLATES_DIR = _find_templates()
LOOT_DIR = os.path.join(_PKG_ROOT, "loot")


def _summarize_jsonl(jsonl_path: str) -> tuple[int, list[str]]:
    """Parse a nuclei -jsonl output file into (count, formatted finding lines)."""
    import json as _json
    count = 0
    lines: list[str] = []
    if not os.path.exists(jsonl_path):
        return 0, lines
    try:
        with open(jsonl_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    j = _json.loads(line)
                except Exception:
                    continue
                count += 1
                info = j.get("info", {}) or {}
                lines.append(
                    f"[{info.get('severity') or j.get('severity') or '?'}] "
                    f"{info.get('name') or j.get('template-id', '?')} "
                    f"({j.get('template-id','?')}) "
                    f"-> {j.get('host','')}{j.get('matched-at','')}"
                )
    except Exception:
        pass
    return count, lines


def nuclei_scan(
    target: str,
    templates: str = "",
    tags: str = "",
    severity: str = "",
    threads: int = 25,
    timeout: float = 120.0,
    extra_args: str = "",
    background: bool = False,
) -> str:
    """Run Nuclei against an authorized target with a light, rate-limited config.

    `templates`: optional path to a template file/dir (default: full local lib).
    `tags`: comma-separated nuclei tags to filter (e.g. "exposures,cves").
    `severity`: min severity to report (info/low/medium/high/critical).
    `extra_args`: raw extra nuclei CLI args appended verbatim.
    `background`: True => launch and return a job handle immediately (use
    bb_nuclei_result to poll). Recommended — a full-lib scan takes minutes and
    the MCP client would otherwise time out waiting.
    Output (full JSONL + text) is saved under loot/.
    """
    if not os.path.exists(NUCLEI_EXE):
        return f"nuclei.exe not found at {NUCLEI_EXE}. Run the setup script first."
    os.makedirs(LOOT_DIR, exist_ok=True)

    safe = _norm_host(target)
    ts = time.strftime("%Y%m%d-%H%M%S")
    stem = f"{safe}_{ts}"
    jsonl_out = os.path.join(LOOT_DIR, f"nuclei_{stem}.jsonl")
    txt_out = os.path.join(LOOT_DIR, f"nuclei_{stem}.txt")

    cmd = [
        NUCLEI_EXE,
        "-t", templates if templates else TEMPLATES_DIR,
        "-jsonl", "-o", jsonl_out,
        "-silent", "-no-color",
        "-c", str(max(1, min(threads, 60))),          # concurrency
        "-rl", str(max(1, min(threads, 60))),          # rate limit (req/s)
        "-timeout", "10",                              # per-request timeout
        "-retries", "1",
        "-stats",
        "-duc",                                         # disable update check
    ]
    if tags:
        cmd += ["-tags", tags]
    if severity:
        cmd += ["-severity", severity]
    if extra_args:
        cmd += extra_args.split()

    target_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    cmd += ["-target", target_url]

    env = dict(os.environ, PYTHONIOENCODING="utf-8")

    if background:
        import json as _json
        jobs_dir = os.path.join(LOOT_DIR, "nuclei_jobs")
        os.makedirs(jobs_dir, exist_ok=True)
        log_fh = open(txt_out, "w", encoding="utf-8")
        proc = subprocess.Popen(
            cmd, stdout=log_fh, stderr=subprocess.STDOUT,
            env=env, cwd=_PKG_ROOT,
        )
        job = {
            "stem": stem, "target": target_url, "pid": proc.pid,
            "started": time.time(), "cmd": " ".join(cmd),
            "jsonl": jsonl_out, "txt": txt_out,
        }
        with open(os.path.join(jobs_dir, f"{stem}.json"), "w", encoding="utf-8") as f:
            _json.dump(job, f)
        return (
            f"nuclei started in background: job='{stem}' pid={proc.pid} target={target_url}\n"
            f"  JSONL: {jsonl_out}\n  log:   {txt_out}\n"
            f"Poll with bb_nuclei_result(stem='{stem}') — full-lib scans take ~2-6 min."
        )

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=env,
            cwd=_PKG_ROOT,
        )
        out = (proc.stdout or "") + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")
    except subprocess.TimeoutExpired:
        out = f"nuclei timed out after {timeout}s. Partial results may be in: {txt_out}"

    # also write a plain text copy for easy reading
    try:
        with open(txt_out, "w", encoding="utf-8") as f:
            f.write(out)
    except Exception:
        pass

    findings, lines = _summarize_jsonl(jsonl_out)
    if findings:
        head = f"Nuclei found {findings} match(es) on {safe}. Full output: {txt_out}\n"
        tail = "\n".join(lines[:200])
        return head + ("\n" + tail if tail else "") + "\n(see JSONL: %s)" % jsonl_out

    # no findings — return a short tail of the run output
    return (
        f"Nuclei completed with 0 findings on {safe}.\n"
        f"Full run log: {txt_out}\n--- tail ---\n{out[-1500:]}"
    )


def nuclei_result(stem: str) -> str:
    """Check a background nuclei job (started with bb_nuclei background=true).

    Returns 'still running' with partial findings count, or the full finding
    summary once the process exits.
    """
    import json as _json
    job_file = os.path.join(LOOT_DIR, "nuclei_jobs", f"{stem}.json")
    if not os.path.exists(job_file):
        # tolerate passing the jsonl path or a partial stem
        matches = [f for f in os.listdir(os.path.join(LOOT_DIR, "nuclei_jobs"))
                   if f.startswith(stem)] if os.path.isdir(os.path.join(LOOT_DIR, "nuclei_jobs")) else []
        if matches:
            job_file = os.path.join(LOOT_DIR, "nuclei_jobs", sorted(matches)[-1])
        else:
            return f"No background nuclei job named '{stem}'. Check {LOOT_DIR}\\nuclei_jobs."
    with open(job_file, encoding="utf-8") as f:
        job = _json.load(f)

    pid = job.get("pid")
    alive = False
    try:
        os.kill(pid, 0)
        alive = True
    except (OSError, TypeError):
        alive = False

    findings, lines = _summarize_jsonl(job["jsonl"])
    elapsed = int(time.time() - job.get("started", time.time()))
    status_line = f"nuclei job '{stem}' (pid {pid}) — {'STILL RUNNING' if alive else 'FINISHED'} after {elapsed}s"
    if alive:
        return (
            f"{status_line}\n"
            f"  partial findings so far: {findings}\n"
            f"  poll again in ~30-60s."
        )
    if findings:
        head = f"{status_line}\nNuclei found {findings} match(es). Full output: {job['txt']}\n"
        tail = "\n".join(lines[:200])
        return head + ("\n" + tail if tail else "") + "\n(see JSONL: %s)" % job["jsonl"]
    tail_txt = ""
    if os.path.exists(job["txt"]):
        try:
            with open(job["txt"], encoding="utf-8", errors="replace") as f:
                tail_txt = f.read()[-1200:]
        except Exception:
            pass
    return f"{status_line}\n0 findings.\n--- log tail ---\n{tail_txt}"


# ---------------------------------------------------------------------------
# Manual testing helpers (login flows, subsystem discovery, captchas)
# ---------------------------------------------------------------------------
# These support the "deep-dive a login" workflow that consistently outperforms
# template scanning on in-house systems (OA/CMS/教务/portal): enumerate real
# subsystems from the homepage, capture captcha images for an external OCR
# tool, and fire controlled login attempts (differential SQLi, enumeration).

_ASSET_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
              ".woff", ".woff2", ".ttf", ".mp4", ".pdf")


def site_map(url: str, max_links: int = 120) -> str:
    """Mine a homepage (or portal page) for real subsystems.

    Extracts every internal link, groups by host, and skips asset files.
    On multi-department sites (universities, hospitals) this is the single most
    valuable recon step: the homepage links are the authoritative inventory of
    live subsystems (OA, 教务, 招生, 人事, 图书馆...), far better than subdomain
    guesses.
    """
    u = _fmt_url(url)
    info = _probe(u, follow=True)
    if not info.get("status"):
        return f"Could not reach {u}: {info.get('error')}"
    try:
        with httpx.Client(follow_redirects=True, timeout=TIMEOUT, headers=HEADERS,
                          verify=False) as c:
            body = c.get(u).text
    except Exception as e:
        return f"Fetch failed: {e}"

    from urllib.parse import urljoin, urlparse
    root = urlparse(u)
    same_host: dict[str, str] = {}
    other_hosts: dict[str, list[str]] = {}
    for m in re.finditer(r'(?:href|src)\s*=\s*["\']([^"\'#?]+)', body, re.I):
        raw = m.group(1).strip()
        if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        absu = urljoin(u, raw)
        p = urlparse(absu)
        if p.scheme not in ("http", "https") or not p.netloc:
            continue
        if p.path.lower().endswith(_ASSET_EXT):
            continue
        if p.netloc == root.netloc:
            same_host.setdefault(p.path or "/", absu)
        else:
            other_hosts.setdefault(p.netloc, []).append(absu)

    out = [f"Site map of {u} (followed to {info.get('final_url')}):"]
    if same_host:
        # collapse same-host links by top-level directory (news archives etc. are noise)
        sections: dict[str, list[str]] = {}
        for path in same_host:
            top = path.strip("/").split("/")[0] or "(root)"
            sections.setdefault(top, []).append(path)
        out.append(f"== same host ({len(same_host)} links in {len(sections)} sections) ==")
        for top in sorted(sections)[:max_links]:
            paths = sections[top]
            sample = paths[0] if len(paths) == 1 else f"{len(paths)} links, e.g. {paths[0]}"
            out.append(f"  /{top}/  ({sample})")
    if other_hosts:
        out.append(f"== other hosts on the same site ({len(other_hosts)}) ==")
        for host in sorted(other_hosts):
            shown = sorted(set(other_hosts[host]))[:8]
            out.append(f"  {host}  ({len(set(other_hosts[host]))} links)")
            for s in shown:
                out.append(f"     {s}")
    if not same_host and not other_hosts:
        out.append("  (no useful links found — JS-rendered page? try a real browser)")
    return "\n".join(out)


def captcha_capture(url: str) -> str:
    """Download a captcha image to loot/ for OCR (use the ocr MCP tool on the
    returned path), and return the session cookie so a later bb_login_attempt
    can reuse the same session.

    url: e.g. https://oa.example.com/login/code.jsp?d=ts
    """
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    try:
        with httpx.Client(follow_redirects=False, timeout=TIMEOUT, headers=HEADERS,
                          verify=False) as c:
            r = c.get(url)
    except Exception as e:
        return f"captcha fetch failed: {e}"
    ctype = r.headers.get("content-type", "")
    magic = r.content[:4]
    if magic.startswith(b"\x89PNG"):
        ext = "png"
    elif magic[:3] == b"\xff\xd8\xff":
        ext = "jpg"
    elif magic.startswith(b"GIF8"):
        ext = "gif"
    else:
        ext = "bin"
    path = os.path.join(LOOT_DIR, f"captcha_{ts}.{ext}")
    with open(path, "wb") as f:
        f.write(r.content)
    # keep only name=value pairs for reuse in a Cookie request header
    cookie_pairs = [c.split(";")[0].strip() for c in r.headers.get_list("set-cookie")]
    setc = "; ".join(cookie_pairs)
    return (
        f"HTTP {r.status_code}  {len(r.content)}B  content-type={ctype}\n"
        f"image saved: {path}\n"
        f"cookie to reuse in bb_login_attempt: {setc or '(none set — send empty cookie)'}\n"
        f"next: run the ocr MCP tool on that path, then POST the code back with the cookie."
    )


def login_attempt(url: str, cookie: str, data: str, method: str = "POST") -> str:
    """Fire ONE controlled login attempt and report the full result.

    Built for differential testing (SQLi quotes, username enumeration):
    the response body is returned verbatim, and connection-level failures
    (server reset / no HTTP response) are reported as DISCONNECT — which is
    itself a finding worth submitting.

    url:    login endpoint, e.g. https://oa.example.com/doLogin.jsp
    cookie: full cookie header value from bb_captcha_capture
    data:   raw form body, e.g. "userId=admin&password=xxx&yzm=1234"
    """
    headers = dict(HEADERS)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        headers["Cookie"] = cookie
    try:
        with httpx.Client(follow_redirects=False, timeout=TIMEOUT,
                          headers=headers, verify=False) as c:
            r = c.request(method, url, content=data.encode("utf-8"))
        return (
            f"HTTP {r.status_code}  {len(r.content)}B\n"
            f"--- body ---\n{r.text[:2000]}"
            + (f"\n--- (truncated) ---" if len(r.text) > 2000 else "")
        )
    except Exception as e:
        name = type(e).__name__
        hint = ""
        if "RemoteProtocol" in name or "read" in name.lower():
            hint = (" ⚠ DISCONNECT: the server dropped the TCP connection without "
                    "any HTTP response — reproducible? That IS the vulnerability signal.")
        return f"{name}: {e}{hint}"


# ---------------------------------------------------------------------------
# Butian (补天) platform: task/vendor discovery + submission report generator
# ---------------------------------------------------------------------------
# Reverse-engineered from the site's Vue bundles (2026-10):
#   POST /Reward/corps    {"page":N,"size":M}        -> dedicated SRC vendors (~46)
#   POST /Reward/pub      form: name=&p=N            -> welfare SRC vendors (2000+,
#                                                      FORM-encoded only — JSON is
#                                                      ignored and always returns p1)
#   POST /Active/center   {}                         -> all activities (total+list)
#   GET  /Active/detail?id=X                         -> full activity rules text
#   GET  /Company/<cid>                              -> vendor page (activity status)
#   GET  /Loo/submit?cid=<cid>                       -> submission form for that vendor
# The API needs a session cookie (warm up with a GET of the page) plus
# XHR/Referer headers; a bare POST is rate-limited ("换个姿势，再来一次").

BUTIAN_BASE = "https://www.butian.net"


def _butian_json(path: str, payload: dict, referer: str, tries: int = 3, form: bool = False) -> dict:
    """POST to a butian XHR endpoint with session warm-up and polite retry.

    `form=True` sends the payload as application/x-www-form-urlencoded (required
    by /Reward/pub; JSON is ignored by its parser and always returns page 1).
    """
    referer_url = referer if referer.startswith("http") else BUTIAN_BASE + referer
    last: dict = {}
    with httpx.Client(
        headers={
            "User-Agent": HEADERS["User-Agent"],
            "Referer": referer_url,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/plain, */*",
        },
        timeout=25.0,
        follow_redirects=True,
    ) as client:
        try:
            client.get(referer_url)
        except Exception:
            pass
        for attempt in range(tries):
            try:
                if form:
                    import urllib.parse
                    resp = client.post(
                        BUTIAN_BASE + path,
                        content=urllib.parse.urlencode(payload),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                else:
                    resp = client.post(BUTIAN_BASE + path, json=payload)
                last = resp.json()
            except Exception as e:
                last = {"status": 0, "info": f"request failed: {e}"}
            if last.get("status") == 1:
                return last
            if "换个姿势" not in (last.get("info") or ""):
                return last
            time.sleep(2.0 + attempt * 2.0)
    return last


def butian_vendors(kind: str = "welfare", limit: int = 30, page: int = 1, name: str = "") -> str:
    """List Butian SRC vendors from the 项目大厅 page.

    kind: 'welfare' (公益SRC 厂商库, 2000+ registered vendors, default) or
          'dedicated' (专属SRC, ~46 vendors with bounty ranges).
    limit: page size (welfare is server-capped at 30; dedicated 1-200).
    page: page number (default 1).
    name: vendor name search filter (welfare only), e.g. "大学".
    Returns vendor id (cid for welfare — use in /Loo/submit?cid=X) + name.
    """
    if kind == "dedicated":
        j = _butian_json("/Reward/corps", {"page": max(1, page), "size": max(1, min(limit, 200))}, "/Reward/plan/2")
        if j.get("status") != 1:
            return f"butian /Reward/corps failed: {j.get('info')} (status={j.get('status')})"
        lst = (j.get("data") or {}).get("list") or []
        if not lst:
            return f"No dedicated vendors returned (page={page}). Try another page."
        out = [f"但天项目大厅 专属SRC厂商  page={page} got={len(lst)}\n" + "-" * 60]
        for v in lst:
            reward = f"{v.get('min_reward','?')}~{v.get('max_reward','?')}元"
            flag = " [推荐]" if str(v.get("recommend")) == "1" else ""
            out.append(
                f"- id={v.get('company_id')}  {v.get('company_name')}  奖金:{reward}{flag}"
                f"  更新:{v.get('change_time','?')[:10]}"
            )
        out.append("\n下一步: 用 bb_target_analyse / bb_subdomains 对厂商范围内的域名开测; 提交时用 bb_report 生成补天格式报告。")
        return "\n".join(out)

    j = _butian_json("/Reward/pub", {"name": name or "", "p": max(1, page)}, "/Reward/plan/2", form=True)
    if j.get("status") != 1:
        return f"butian /Reward/pub failed: {j.get('info')} (status={j.get('status')})"
    lst = (j.get("data") or {}).get("list") or []
    if not lst:
        return f"No welfare vendors returned (page={page}, name={name!r}). Try another page/keyword."
    out = [f"但天项目大厅 公益SRC厂商库  page={page} got={len(lst)}  (cid 用于 /Loo/submit?cid= 提交)\n" + "-" * 60]
    for v in lst:
        out.append(f"- cid={v.get('company_id')}  {v.get('company_name')}")
    out.append(
        "\n选靶标准: gov/edu/医疗/征信优先(无权重要求); 独立域名 > 省级统一门户; "
        "避开 kb/butian-plan.md 不关注名单(JeeCms/泛微OA/正方教务等)。"
        "厂商详情: /Company/<cid>; 提交: /Loo/submit?cid=<cid>"
    )
    return "\n".join(out)


def butian_activities(status: str = "ongoing", limit: int = 10, with_details: bool = True) -> str:
    """List Butian activities (活动中心).

    status: 'ongoing' (进行中, default) | 'all'.
    limit: max activities to show (default 10).
    with_details: fetch full rules text (description+detail) per shown activity.
    """
    j = _butian_json("/Active/center", {}, "/Active/center")
    if j.get("status") != 1:
        return f"butian /Active/center failed: {j.get('info')} (status={j.get('status')})"
    lst = (j.get("data") or {}).get("list") or []
    total = (j.get("data") or {}).get("total", "?")
    if status != "all":
        lst = [a for a in lst if a.get("status") == "进行中"]
    lst = lst[: max(1, limit)]
    if not lst:
        return f"No {('ongoing' if status != 'all' else '')} activities (total on site: {total})."
    out = [f"但天活动中心  显示={len(lst)}  站内总数={total}\n" + "-" * 60]
    for a in lst:
        out.append(
            f"[id={a.get('id')}] {a.get('title')}\n"
            f"    类型: {a.get('type')}  标签: {a.get('tags')}\n"
            f"    时间: {a.get('start')} ~ {a.get('end')}  状态: {a.get('status')}"
        )
        if with_details:
            try:
                d = httpx.get(
                    BUTIAN_BASE + "/Active/detail",
                    params={"id": a.get("id")},
                    headers={
                        "User-Agent": HEADERS["User-Agent"],
                        "Referer": BUTIAN_BASE + "/Active/center",
                        "X-Requested-With": "XMLHttpRequest",
                    },
                    timeout=20.0,
                ).json()
                dd = d.get("data") or {}
                if dd.get("description"):
                    out.append(f"    说明: {dd['description']}")
                det = (dd.get("detail") or "").strip()
                if det:
                    out.append("    规则:\n" + "\n".join("      " + line for line in det.splitlines()[:25]))
            except Exception as e:
                out.append(f"    (detail fetch failed: {e})")
    out.append(
        "\n下一步: 报名活动(浏览器点报名)后, 提交漏洞时勾选对应活动名, "
        "活动奖励是额外叠加的, 不影响漏洞本身奖金。"
    )
    return "\n".join(out)


def butian_report(
    title: str,
    url: str,
    vtype: str,
    level: str,
    detail: str,
    fix: str,
    method: str = "",
    post_data: str = "",
    param_name: str = "",
    poc: str = "",
    vendor: str = "",
    scope: str = "",
    weight: str = "",
    test_account: str = "",
    activity: str = "",
    summary: str = "",
    outdir: str = "",
) -> str:
    """Generate a Butian-compliant submission report draft (Markdown, paste-ready).

    Follows the official template (kb/butian-submission-template.md).
    title: e.g. "XX网站存在SQL注入漏洞"
    url: vulnerable URL (GET injection: full URL with params)
    vtype: 漏洞类型 (SQL注入/XSS/命令执行/越权/...)
    level: 低危 | 中危 | 高危
    detail: 功能点+到达步骤+利用过程 (the core narrative)
    fix: concrete remediation advice
    method: GET | POST (POST requires post_data + param_name: the official "三处" rule)
    post_data: full HTTP request packet (POST only)
    param_name: injected parameter name (POST only)
    poc: POC / payload (rendered in a code block, as required)
    vendor / scope: dedicated-SRC vendor name and test scope (empty for 公益SRC)
    weight: 补天权重 for 公益SRC (">=1" or "0"); 选错会驳回
    test_account: test credentials if login is required
    activity: activity/task name to check at submission (empty = no extra reward)
    summary: 简要描述 — one or two sentences: 漏洞概述 + 影响. Keep it general:
    DO NOT put detailed URLs in it (the form has a separate 漏洞URL field).
    outdir: output dir (default: <project>/reports)
    """
    out_dir = outdir or os.path.join(_PKG_ROOT, "reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^\w\u4e00-\u9fff]+", "-", title)[:40].strip("-") or "vuln"
    path = os.path.join(out_dir, f"{ts}_{slug}.md")

    is_post = method.upper().startswith("POST") or ("POST " in post_data.upper())
    is_dedicated = bool(vendor.strip())

    # 简要描述: must exist, must be general (no detailed URL)
    s = summary.strip()
    if s and re.search(r"https?://\S+", s):
        s = re.sub(r"https?://\S+", "（详见漏洞URL栏）", s)
        warn_summary = "简要描述含详细URL已自动屏蔽 — 官方要求简要描述只写概述+影响, 不暴露详细URL"
    if not s:
        s = (f"（待补: 一两句话概述漏洞+影响, 不写详细URL。示例: {title}漏洞, "
             f"未授权即可触发, 可能导致{vtype}相关风险, 需厂商修复。）")
        warn_summary = "简要描述未提供 — 表单该栏必填, 请补写(概述+影响, 不含详细URL)"
    else:
        warn_summary = None

    warn: list[str] = []
    if warn_summary:
        warn.append(warn_summary)
    if not url.strip().lower().startswith(("http://", "https://")):
        url = "https://" + url.strip()
        warn.append("URL 未带协议, 已自动补 https:// (请确认真实协议)")
    if is_post:
        if not post_data.strip():
            warn.append("POST 漏洞缺「完整注入数据包」— 官方要求三处: 基本URL+数据包+参数名")
        if not param_name.strip():
            warn.append("POST 漏洞缺「注入参数名」")
    if weight.strip() and not is_dedicated and weight.strip() not in (">=1", "0", "≥1"):
        warn.append(f"权重取值「{weight}」不在 [>=1 / 0], 请核对爱站权重")
    if not fix.strip():
        warn.append("修复方案为空 — 官方要求具体方案, 不能敷衍")
    if not poc.strip() and "poc" not in detail.lower():
        warn.append("未提供 POC — 详情里必须把 POC 放代码块")

    L: list[str] = []
    L.append(f"# 补天漏洞提交报告 — {title}")
    L.append("")
    L.append(f"> 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}  ")
    L.append("> 按官方模板生成(kb/butian-submission-template.md), 各节内容直接复制进对应表单项。")
    L.append("")
    L.append("---")
    L.append("")
    L.append("## 表单项填写")
    L.append("")
    L.append(f"| 表单项 | 填写内容 |")
    L.append(f"|--------|----------|")
    if is_dedicated:
        L.append(f"| 厂商名称 | {vendor} |")
        L.append(f"| 测试范围 | {scope or '(填厂商域名/IP, 如 www.test.com)'} |")
    else:
        L.append(f"| 权重(公益必选) | {weight or '(按主域名爱站权重: 百度≥1或谷歌≥3 选 >=1, 否则 0)'} |")
    L.append(f"| 漏洞类型 | {vtype} |")
    L.append(f"| 漏洞等级 | {level} |")
    if activity.strip():
        L.append(f"| 活动/任务 | {activity} (提交时勾选) |")
    else:
        L.append(f"| 活动/任务 | (不勾选 = 不参与额外奖励) |")
    L.append("")
    L.append("### 简要描述 (粘贴到「简要描述」栏)")
    L.append("")
    L.append(s)
    L.append("")
    L.append("### 漏洞URL")
    L.append("")
    if is_post:
        L.append(f"1. 基本URL:\n```\n{url}\n```")
        L.append(f"\n2. 完整注入数据包:\n```\n{post_data or '(粘贴完整 HTTP 请求包)'}\n```")
        L.append(f"\n3. 注入参数:\n```\n{param_name or '(参数名)'}\n```")
    else:
        L.append(f"```\n{url}\n```")
    L.append("")
    L.append("### 漏洞详情 (粘贴到「漏洞详情」栏)")
    L.append("")
    L.append(detail.strip() if detail.strip() else "(功能点+到达步骤+利用过程)")
    if poc.strip():
        L.append("")
        L.append("POC:")
        L.append("```")
        L.append(poc.strip())
        L.append("```")
    if test_account.strip():
        L.append("")
        L.append(f"测试账号: {test_account}")
    L.append("")
    L.append("### 修复方案")
    L.append("")
    L.append(fix.strip() if fix.strip() else "(具体修复建议)")
    L.append("")
    L.append("### 截图清单 (提交时本地上传, 勿复制粘贴)")
    L.append("")
    L.append("⚠️ 官方要求漏洞详情附两张证明截图, 未提供可能会被驳回:")
    L.append("")
    L.append("**① 漏洞完整复现过程截图 — 制作步骤:**")
    L.append("")
    L.append("1. 浏览器打开漏洞所在系统, 按 F12 打开开发者工具 → Network 标签, 勾选 Preserve log;")
    L.append("2. 按 POC 一步步触发漏洞(把每步页面 + 关键请求都留在 Network 里);")
    L.append("3. 截图: 顶部含地址栏, 下方是 Network 中该请求(失败请求为红色, 点开可见请求包/无响应);")
    L.append("   多步操作按顺序多截几张, 拼起来就是完整复现过程;")
    L.append("   若用 curl/HTTP 客户端复现: 截 `curl -v` 终端输出, 需显示断开/异常那一行。")
    L.append("")
    L.append("**② 厂商归属证明截图 — 制作步骤:**")
    L.append("")
    L.append("1. 百度搜索厂商全称(如「江西师范大学」), 截图搜索结果页 — 第一结果为官网,")
    L.append("   且官网主域与漏洞URL主域一致; 或截官网首页(必须含地址栏, 页面标题/Logo 能对应厂商名称)。")
    L.append("")
    L.append("- [ ] ① 漏洞完整复现过程截图 (本地上传)")
    L.append("- [ ] ② 厂商归属证明截图 (本地上传)")
    L.append("")
    L.append("---")
    L.append("")
    L.append("## 提交前自查")
    L.append("")
    for w in warn:
        L.append(f"- ⚠️ {w}")
    L.append("- [ ] 确认已在浏览器登录补天, 进入 提交漏洞 页面")
    L.append("- [ ] 公益SRC: 权重按爱站权重选对 (选错/漏选直接驳回)")
    L.append("- [ ] 同系统同类型漏洞最多 3 个, 不要重复堆量")
    L.append("- [ ] 提交后 7 天内关注认领通知; 专属SRC 平台 ~1 个工作日审核")
    L.append("")
    content = "\n".join(L)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    head = f"补天报告已生成: {path}\n"
    if warn:
        head += f"⚠️ {len(warn)} 个提醒:\n" + "\n".join(f"  - {w}" for w in warn) + "\n"
    head += f"\n报告共 {len(content)} 字符, 直接打开文件按节复制进表单即可。"
    return head

