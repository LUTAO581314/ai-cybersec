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
def bb_subdomains(domain: str, use_wordlist: bool = True) -> str:
    """Enumerate subdomains via Certificate Transparency (crt.sh) and optional DNS brute force."""
    return bb.subdomains(domain, bb.SUBDOMAIN_WORDLIST if use_wordlist else None)


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
) -> str:
    """Run the Nuclei template scanner against an authorized target (light/rate-limited).

    templates: optional template file/dir (default: full local lib).
    tags: comma-separated nuclei tags (e.g. 'exposures,cves').
    severity: minimum severity (info/low/medium/high/critical).
    threads: concurrency + rate limit (1-60). timeout: wall-clock seconds.
    extra_args: raw extra nuclei CLI args appended verbatim.
    Full output is saved under loot/; only a summary is returned.
    """
    return bb.nuclei_scan(target, templates, tags, severity, threads, timeout, extra_args)


def main() -> None:
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
