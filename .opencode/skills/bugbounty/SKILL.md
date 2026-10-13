---
name: bugbounty
description: Drive the bugbounty MCP server for authorized bug-bounty recon and scanning (subdomains, ports, HTTP probing, tech fingerprinting, directory fuzzing, security-header checks) plus Butian (补天) task discovery and submission-report generation. Use when the user asks to analyze a target, enumerate subdomains, scan ports, fuzz directories/endpoints, probe HTTP services, detect technologies, check security headers, list Butian vendors/activities, or draft a Butian-formatted vulnerability report. Include the authorization guardrail whenever a target is named.
---

# Bug Bounty Workflow (bugbounty-mcp)

## 0. Authorization FIRST — non-negotiable

Before any scan, confirm the target is **authorized**:

- It is **in scope** of a bug-bounty program the user is enrolled in
  (HackerOne / Bugcrowd / Intigriti / 国内 SRC), **OR**
- It is the user's **own** asset/domain.

Ask which one applies if it isn't obvious. If the target is out of scope / not
owned / no program, **refuse** to scan and explain why. Note: passive OSINT
(e.g. resolving your own domains, reading public headers of a site you own)
is fine; active fuzzing is not against unauthorized third parties.

Also respect per-program rules of engagement: scan rate, allowed test
accounts, and scope boundaries (e.g. "no auth-endpoint fuzzing").

## 1. Tools (from the `bugbounty` MCP server)

| Tool | Purpose |
|------|---------|
| `bb_resolve(host)` | DNS records A/AAAA/CNAME/MX/NS/TXT |
| `bb_subdomains(domain, use_wordlist)` | Subdomain discovery — Certificate Transparency (crt.sh) + inline DNS wordlist |
| `bb_port_scan(host, ports, timeout)` | Concurrent TCP port scan (common web/db ports by default) |
| `bb_http_probe(targets)` | Batch HTTP probe: status / title / tech / size / redirects |
| `bb_tech_detect(url)` | Web technology fingerprint (headers + body heuristics) |
| `bb_dir_fuzz(base_url, extensions, wordlist)` | HTTP directory/endpoint brute force (light, rate-limited) |
| `bb_headers_check(url)` | Passive check: security headers, CORS, cookies, sensitive files (.git, .env, backups) |
| `bb_nuclei(target, templates, tags, severity, threads, timeout, extra_args)` | **Nuclei v3.11.1** template scan (14k local templates): vulns, exposures, CVEs, tech/WAF detection |
| `bb_target_analyse(target, subdomains, ports)` | One-shot quick recon report (DNS + HTTP + ports + subdomains) |
| `bb_vendors(limit, page)` | **补天项目大厅**: dedicated-SRC vendor list — name, bounty range (RMB), recommend flag, update time |
| `bb_activities(status, limit, with_details)` | **补天活动中心**: ongoing/ended activities with full rules text (join → extra rewards) |
| `bb_report(title, url, vtype, level, detail, fix, ...)` | **补天报告生成器**: Markdown draft in the official template format — POST 三处 rule, POC code block, screenshot checklist, self-check warnings |

## 2. Reference materials / wordlists (cloned locally)

- **Payloads/cheatsheets**: `C:\Users\LT\Desktop\Workspace\bb-repos\PayloadsAllTheThings\` — payload and exploit references by vuln class.
- **Nuclei**: binary at `C:\Users\LT\Desktop\Workspace\bugbounty-mcp\bin\nuclei.exe`, templates at `C:\Users\LT\Desktop\Workspace\bb-repos\nuclei-templates\` (14k+). Scan results land in `C:\Users\LT\Desktop\Workspace\bugbounty-mcp\loot\` (JSONL + txt per run).
- **平台知识库** (`C:\Users\LT\Desktop\Workspace\bugbounty-mcp\kb\`):
  - `butian-submission-template.md` — 补天官方提交模板(字段+自查清单,公告543)
  - `butian-faq.md` — 补天平台规则(审核流程/奖励/信誉分/数量限制/活动中心)
  - `butian-plan.md` — **收录细则+定价表**(Web/IoT/App/工控/系统软件;降级与不收录规则;不关注厂商名单)
  - `butian-role.md` — 白帽行为规范(自动化测试的行为边界:不跳板/不DoS/证明即停)
  - `butian-newneed.md` — 漏洞状态全流程/积分/称号/团队
- **Wordlists** (`C:\Users\LT\Desktop\Workspace\bb-repos\SecLists\Discovery\`):
  - Subdomains: `DNS/subdomains-top1million-20000.txt`, `DNS/bitquark-subdomains-top100000.txt`, `DNS/dns-Jhaddix.txt`
  - Directories: `Web-Content/common.txt`, `Web-Content/raft-medium-words.txt`, `Web-Content/raft-large-words.txt`, `Web-Content/big.txt`
  - Pass `wordlist="<abs path>"` to `bb_dir_fuzz` to use a real wordlist instead of the small built-in one.

## 3. Recommended workflow

Probe progressively — passive/recon first, then light active, escalating only
as authorized.

### 3a. 补天 (Butian) end-to-end loop

The user's money path is Butian (butian.net). Full loop:

1. **Pick the battlefield** (do this first if no target is given):
   - `bb_vendors(limit=50)` → list of dedicated-SRC vendors with bounty ranges.
     Prefer vendors with high `max_reward` + `[推荐]` + recent `update time`.
   - `bb_activities(status="ongoing")` → live campaigns (报名 in the browser, then
     check the name when submitting — extra reward on top of the vuln bounty).
   - Cross-check against `kb/butian-plan.md`: skip vendors/vuln types in the
     「不关注的系统和漏洞」 list; IP vulns not accepted; same system+type ≤ 3.
2. **Get the scope**: a vendor's test scope (domain/IP) is on the vendor's
   项目详情 page (browser) — record it, then treat those hosts as the authorized
   scope for Section 0.
3. **Hunt**: run the recon ladder (step 2–7 below) against the in-scope hosts.
4. **Verify + draft**: for each confirmed finding call `bb_report(...)` to emit a
   Butian-compliant Markdown draft (it enforces the POST 三处 rule, POC code
   block, weight check, screenshot checklist). The file lands in `reports/`.
5. **Human confirm, then submit**: per `kb/butian-role.md` — AI-found vulns must
   pass a human check of the POC screenshots before submission (repeated
   unverified AI vulns can freeze the account). First-come-first-served → submit
   fast once confirmed. Copy each section of the generated report into the
   matching form field.

### 3b. Recon ladder (for a confirmed in-scope target)

1. **Confirm authorization** (Section 0). Record the target, scope, and program.
   - **补天目标筛选**: 对照 `kb/butian-plan.md` 的「不关注的系统和漏洞」名单先排除;
     IP 漏洞暂不收;CORS 错误/self-xss/前台弱口令/URL跳转 不报;
     同系统同类型最多报 3 个;SQLi 同接口多参数算一处。
   - 测试行为遵守 `kb/butian-role.md`: 限速扫描、RCE 证明后立刻停(whoami 即可)、
     不拉数据、不跳板、不 DoS、不动业务数据、不留 webshell。
2. **Quick recon**: `bb_target_analyse("target.com")` for an overview.
3. **DNS & subdomains**: `bb_resolve`, then `bb_subdomains("target.com")`.
   Optional deeper pass with the big SecLists wordlist by extending the server
   or running the wordlist through `bb_dir_fuzz`-style enumeration manually.
4. **Services**: `bb_port_scan("target.com", ports="80,443,8080,8443,3000,...")`.
5. **HTTP layering**: `bb_http_probe` over discovered hosts, `bb_tech_detect` on
   interesting ones, then `bb_dir_fuzz` on live web roots (use a SecLists
   wordlist for real coverage).
6. **Weakness triage**: `bb_headers_check` for header/CORS/cookie/sensitive-file
   issues; correlate findings with PayloadsAllTheThings for exploit research.
7. **Template scan**: `bb_nuclei(target)` for in-scope live targets — start with
   a filter (`tags="exposures"`, `severity="medium"`) to keep runs short, then
   widen. Nuclei sends more requests than the recon tools; keep `threads` low
   (10-25) on production targets and avoid it during maintenance windows.
8. **Report**: for each finding give: URL, how to reproduce, severity
    (info/low/medium/high/critical) via `bb_headers_check` output and manual
    analysis. Only report verified issues; honor program disclosure policy.
    - **补天(Butian)提交**: 用 `bb_report(...)` 生成官方模板格式的 Markdown 草稿
      (自动处理 POST 三处/POC 代码块/权重校验/截图清单/自查提醒), 落盘在
      `reports/`。对照 `kb/butian-submission-template.md` 的「提交前自查清单」
      逐项确认后, 按节复制进表单提交。平台规则(审核时限、5个待审限制、
      重复按时间、信誉分)见 `kb/butian-faq.md`。先报先得 → 确认无误尽快提交。

## 4. Guardrails when driving the tools

- **Never** run fuzzing/scans against hosts already ruled out by the program's
  scope (e.g. subdomains under a *denied* wildcard).
- Keep scans **light and rate-limited** (`bb_dir_fuzz` is throttled; don't
  launch many parallel fuzz campaigns). Do not engineer new unbounded scanners
  without saying so.
- These tools are **recon/scanner primitives**, not exploit payload runners.
  Do not use them to deliver actual exploits against live third-party systems.
  **Nuclei caveat**: `bb_nuclei` runs the full template library — the most active
  tool here. Default to tag/severity filters, low threads (10-25), and run it
  only after recon confirms the host is in scope. Full run logs are saved in
  `loot/` for review before reporting.
- Prefer passive checks; escalate to active scans only within explicit scope.
- If a tool flags a finding, verify it manually (re-request) before reporting.

## 5. Output format

End a scan with a compact summary:

```
TARGET: <target>  (authorized: <program/own> <scope>)
[CRITICAL] ... 
[HIGH] ...
[MEDIUM] ...
[LOW] ...
[INFO] ...
NEXT: <suggested follow-up, within scope>
```
