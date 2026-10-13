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


def subdomains(domain: str, wordlist: list[str] | None = None) -> str:
    """Enumerate subdomains via Certificate Transparency (crt.sh) + DNS brute force."""
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
    res = dns.resolver.Resolver()
    res.timeout = 3.0
    res.lifetime = 3.0

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
    head = f"Subdomains for {domain} ({len(rows)} total) {found_note}:\n"
    return head + "\n".join(f"  {r}" for r in rows)


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
    for path in SENSITIVE_PATHS:
        try:
            with httpx.Client(follow_redirects=False, timeout=5.0, headers=HEADERS,
                              verify=False) as c:
                rr = c.get(f"{u.rstrip('/')}/{path}")
            if rr.status_code in (200, 301, 302) and rr.status_code != 404:
                found_files += 1
                out.append(f"  FOUND ({rr.status_code}, {len(rr.content)}B): /{path}")
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


def nuclei_scan(
    target: str,
    templates: str = "",
    tags: str = "",
    severity: str = "",
    threads: int = 25,
    timeout: float = 120.0,
    extra_args: str = "",
) -> str:
    """Run Nuclei against an authorized target with a light, rate-limited config.

    `templates`: optional path to a template file/dir (default: full local lib).
    `tags`: comma-separated nuclei tags to filter (e.g. "exposures,cves").
    `severity`: min severity to report (info/low/medium/high/critical).
    `extra_args`: raw extra nuclei CLI args appended verbatim.
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

    # summarize JSONL findings
    findings = 0
    lines: list[str] = []
    if os.path.exists(jsonl_out):
        import json as _json
        try:
            with open(jsonl_out, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        j = _json.loads(line)
                    except Exception:
                        continue
                    findings += 1
                    info = j.get("info", {}) or {}
                    lines.append(
                        f"[{info.get('severity') or j.get('severity') or '?'}] "
                        f"{info.get('name') or j.get('template-id', '?')} "
                        f"({j.get('template-id','?')}) "
                        f"-> {j.get('host','')}{j.get('matched-at','')}"
                    )
        except Exception:
            pass

    if findings:
        head = f"Nuclei found {findings} match(es) on {safe}. Full output: {txt_out}\n"
        tail = "\n".join(lines[:200])
        return head + ("\n" + tail if tail else "") + "\n(see JSONL: %s)" % jsonl_out

    # no findings — return a short tail of the run output
    return (
        f"Nuclei completed with 0 findings on {safe}.\n"
        f"Full run log: {txt_out}\n--- tail ---\n{out[-1500:]}"
    )


# ---------------------------------------------------------------------------
# Butian (补天) platform: task/vendor discovery + submission report generator
# ---------------------------------------------------------------------------
# Reverse-engineered from the site's Vue bundles (2026-10):
#   POST /Reward/corps    {"page":N,"size":M}  -> dedicated SRC vendor list
#   POST /Active/center   {}                   -> all activities (total+list)
#   GET  /Active/detail?id=X                   -> full activity rules text
# The API needs a session cookie (warm up with a GET of the page) plus
# XHR/Referer headers; a bare POST is rate-limited ("换个姿势，再来一次").

BUTIAN_BASE = "https://www.butian.net"


def _butian_json(path: str, payload: dict, referer: str, tries: int = 3) -> dict:
    """POST to a butian XHR endpoint with session warm-up and polite retry."""
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
                last = client.post(BUTIAN_BASE + path, json=payload).json()
            except Exception as e:
                last = {"status": 0, "info": f"request failed: {e}"}
            if last.get("status") == 1:
                return last
            if "换个姿势" not in (last.get("info") or ""):
                return last
            time.sleep(2.0 + attempt * 2.0)
    return last


def butian_vendors(limit: int = 50, page: int = 1) -> str:
    """List Butian dedicated-SRC vendors (项目大厅): name, bounty range, status.

    limit: page size 1-200 (default 50). page: page number (default 1).
    Returns one line per vendor with company_id, name, reward range (RMB),
    recommended flag and last update time.
    """
    j = _butian_json("/Reward/corps", {"page": max(1, page), "size": max(1, min(limit, 200))}, "/Reward/plan/2")
    if j.get("status") != 1:
        return f"butian /Reward/corps failed: {j.get('info')} (status={j.get('status')})"
    data = j.get("data") or {}
    lst = data.get("list") or []
    if not lst:
        return f"No vendors returned (page={page}). Try another page."
    out = [f"但天项目大厅 专属SRC厂商  page={page} got={len(lst)}\n" + "-" * 60]
    for v in lst:
        reward = f"{v.get('min_reward','?')}~{v.get('max_reward','?')}元"
        flag = " [推荐]" if str(v.get("recommend")) == "1" else ""
        out.append(
            f"- id={v.get('company_id')}  {v.get('company_name')}  奖金:{reward}{flag}"
            f"  更新:{v.get('change_time','?')[:10]}"
        )
    intro = [v for v in lst if v.get("introduce")]
    if intro:
        out.append("\n厂商简介(前3):")
        for v in intro[:3]:
            out.append(f"  {v.get('company_name')}: {str(v.get('introduce'))[:80]}")
    out.append(
        "\n下一步: 用 bb_target_analyse / bb_subdomains 对厂商范围内的域名开测; "
        "提交时用 bb_report 生成补天格式报告。"
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
    outdir: output dir (default: <project>/reports)
    """
    out_dir = outdir or os.path.join(_PKG_ROOT, "reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^\w\u4e00-\u9fff]+", "-", title)[:40].strip("-") or "vuln"
    path = os.path.join(out_dir, f"{ts}_{slug}.md")

    is_post = method.upper().startswith("POST") or ("POST " in post_data.upper())
    is_dedicated = bool(vendor.strip())

    warn: list[str] = []
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
    L.append("### 截图清单 (提交时上传)")
    L.append("")
    L.append("- [ ] 归属证明: 百度搜索目标站点结果截图")
    L.append("- [ ] 首页截图: **必须含地址栏**")
    L.append("- [ ] 漏洞证明截图: 能独立说明漏洞成立 (RCE 要 whoami 回显; 注入要数据回显)")
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

