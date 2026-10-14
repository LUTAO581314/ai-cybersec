"""Windows bug-bounty MCP server entry point (mcp SDK 2.x / MCPServer).

Run via stdio (opencode launches it as a local MCP server):
    python server.py

Exposes recon/scan primitives as MCP tools. Only ever target hosts you are
authorized to test (in-scope bug-bounty assets or your own systems).
"""

from __future__ import annotations

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.mcpserver import MCPServer

import bbmcp.tools as bb

mcp = MCPServer(
    "bugbounty",
    instructions=(
        "Authorized bug-bounty recon & scanning tools. Use ONLY on targets you are "
        "explicitly authorized to test (in-scope on a bounty program, or your own assets). "
        "Prefer passive checks first; keep active fuzzing light and rate-limited."
    ),
)


@mcp.tool()
def bb_resolve(host: str) -> str:
    """Resolve DNS records (A/AAAA/CNAME/MX/NS/TXT) for a host/domain."""
    return bb.resolve(host)


@mcp.tool()
def bb_subdomains(domain: str, use_wordlist: bool = True, verify: bool = False) -> str:
    """Enumerate subdomains via Certificate Transparency (crt.sh) and optional DNS brute force.

    verify: additionally probe each name over HTTP and mark [live]/[dead], flagging
    'same page as X' twins (wildcard/CGNAT catch-all — common on campus networks).
    Use verify=True on real targets; it's the difference between 45 noise rows and
    the ~20 real subsystems.
    """
    return bb.subdomains(domain, bb.SUBDOMAIN_WORDLIST if use_wordlist else None, verify=verify)


@mcp.tool()
def bb_port_scan(host: str, ports: str = "", timeout: float = 1.0) -> str:
    """TCP connect() port scan. ports: comma-separated list (default common web/db ports)."""
    plist = [int(p.strip()) for p in ports.split(",") if p.strip()] if ports else None
    return bb.port_scan(host, plist, timeout)


@mcp.tool()
def bb_http_probe(targets: str, follow: bool = True) -> str:
    """Probe a list of URLs/hosts (newline or comma separated): status, title, tech, size."""
    t = targets[:2048] if len(targets) > 2048 else targets
    return bb.http_probe(t, follow)


@mcp.tool()
def bb_tech_detect(url: str) -> str:
    """Fingerprint web technologies for a single URL (headers + body heuristics)."""
    return bb.tech_detect(url)


@mcp.tool()
def bb_dir_fuzz(base_url: str, extensions: str = "", wordlist: str = "") -> str:
    """HTTP directory/endpoint brute force. Optional comma-separated extensions and custom wordlist file path."""
    wl = None
    if wordlist:
        wl = [l.strip() for l in open(wordlist, encoding="utf-8", errors="ignore") if l.strip()]
    return bb.dir_fuzz(base_url, wl, extensions)


@mcp.tool()
def bb_headers_check(url: str) -> str:
    """Passive security analysis: headers, CORS, cookies, sensitive files."""
    return bb.headers_check(url)


@mcp.tool()
def bb_target_analyse(target: str, subdomains: bool = True, ports: bool = True) -> str:
    """One-shot quick recon report for a target host: DNS, HTTP, ports, subdomains."""
    return bb.target_analyse(target, do_subdomains=subdomains, do_ports=ports)


@mcp.tool()
def bb_nuclei(
    target: str,
    templates: str = "",
    tags: str = "",
    severity: str = "",
    threads: int = 25,
    timeout: float = 120.0,
    extra_args: str = "",
    background: bool = False,
) -> str:
    """Run the Nuclei template scanner against an authorized target (light/rate-limited).

    templates: optional template file/dir (default: full local lib).
    tags: comma-separated nuclei tags (e.g. 'exposures,cves').
    severity: minimum severity (info/low/medium/high/critical).
    threads: concurrency + rate limit (1-60). timeout: wall-clock seconds (foreground only).
    extra_args: raw extra nuclei CLI args appended verbatim.
    background: True => return a job handle immediately and poll with bb_nuclei_result.
    Recommended for full-lib scans (they take minutes and the MCP client times out
    waiting). For quick single-tag passes, foreground with a small timeout is fine.
    Full output is saved under loot/; only a summary is returned.
    """
    return bb.nuclei_scan(target, templates, tags, severity, threads, timeout, extra_args, background)


@mcp.tool()
def bb_nuclei_result(stem: str) -> str:
    """Check a background nuclei job (from bb_nuclei background=true).

    Returns 'STILL RUNNING' + partial finding count, or the full finding summary
    once the process exits. Poll every 30-60s.
    """
    return bb.nuclei_result(stem)


@mcp.tool()
def bb_site_map(url: str, max_links: int = 120) -> str:
    """Mine a homepage/portal for real subsystems (grouped by host, assets skipped).

    On multi-department sites (universities/hospitals) this is the single most
    valuable recon step: homepage links are the authoritative inventory of live
    subsystems (OA, 教务, 招生, 人事, 图书馆...) — far better than subdomain guesses.
    """
    return bb.site_map(url, max_links)


@mcp.tool()
def bb_captcha_capture(url: str) -> str:
    """Download a captcha image to loot/ and return its session cookie.

    url: the captcha image endpoint, e.g. https://oa.example.com/login/code.jsp?d=ts
    Next: run the ocr MCP tool on the saved path, then call bb_login_attempt
    with the returned cookie + the OCR'd code.
    """
    return bb.captcha_capture(url)


@mcp.tool()
def bb_login_attempt(url: str, cookie: str, data: str, method: str = "POST") -> str:
    """Fire ONE controlled login attempt; returns the response body verbatim.

    For differential testing (SQLi quotes, username enumeration). Connection-level
    failures are reported as DISCONNECT — a server dropping TCP without any HTTP
    response in response to a crafted param is itself a submittable finding.
    url: login endpoint (e.g. /doLogin.jsp). cookie: from bb_captcha_capture.
    data: raw form body (e.g. "userId=admin&password=xxx&yzm=1234").
    """
    return bb.login_attempt(url, cookie, data, method)


@mcp.tool()
def bb_vendors(kind: str = "welfare", limit: int = 30, page: int = 1, name: str = "") -> str:
    """List Butian SRC vendors from the 项目大厅 page.

    kind: 'welfare' (公益SRC 厂商库, 2000+ registered vendors, default) or
          'dedicated' (专属SRC, ~46 vendors with bounty ranges).
    limit: page size (welfare is server-capped at 30; dedicated 1-200).
    page: page number (default 1).
    name: vendor name search filter (welfare only), e.g. "大学".
    The welfare vendor cid is used for submission: /Loo/submit?cid=<cid>.
    """
    return bb.butian_vendors(kind, limit, page, name)


@mcp.tool()
def bb_activities(status: str = "ongoing", limit: int = 10, with_details: bool = True) -> str:
    """List Butian activities (活动中心) with full rules text.

    status: 'ongoing' (进行中, default) or 'all'. limit: max to show (default 10).
    with_details: fetch each activity's description + rules (default true).
    Join an activity in the browser, then check its name when submitting a vuln.
    """
    return bb.butian_activities(status, limit, with_details)


@mcp.tool()
def bb_report(
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
    repro: str = "",
    outdir: str = "",
) -> str:
    """Generate a Butian-compliant vulnerability submission report (Markdown, paste-ready).

    title: e.g. "XX网站存在SQL注入漏洞"
    url: vulnerable URL (GET injection: full URL with params)
    vtype: 漏洞类型 (SQL注入/XSS/命令执行/越权/...)
    level: 低危 | 中危 | 高危
    detail: 功能点+到达步骤+利用过程 (core narrative)
    fix: concrete remediation advice
    method: GET | POST (POST needs post_data + param_name per the official 三处 rule)
    post_data: full HTTP request packet (POST only)
    param_name: injected parameter name (POST only)
    poc: POC/payload (rendered in a code block as required)
    vendor/scope: dedicated-SRC vendor name + test scope (empty for 公益SRC)
    weight: 补天权重 for 公益SRC (">=1" or "0") — wrong choice gets rejected
    test_account: test credentials if login required
    activity: activity/task name to check at submission
    summary: 简要描述 — 漏洞概述+影响, 一两句话, 不写详细URL (表单该栏必填)
    repro: 小白复现手册 — 点击级步骤+每步预期现象+常见错误操作, 假设提交人是网安小白
    outdir: output dir (default <project>/reports)
    Returns the file path + a pre-submission warning list.
    """
    return bb.butian_report(
        title=title, url=url, vtype=vtype, level=level, detail=detail, fix=fix,
        method=method, post_data=post_data, param_name=param_name, poc=poc,
        vendor=vendor, scope=scope, weight=weight, test_account=test_account,
        activity=activity, summary=summary, repro=repro, outdir=outdir,
    )


def main() -> None:
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
