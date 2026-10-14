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
| `bb_subdomains(domain, use_wordlist, verify)` | Subdomain discovery (crt.sh + DNS wordlist). **`verify=true`** probes each name and marks [live]/[dead] + flags "same page as X" catch-all twins — always use it on real targets |
| `bb_port_scan(host, ports, timeout)` | Concurrent TCP port scan (common web/db ports by default) |
| `bb_http_probe(targets)` | Batch HTTP probe: status / title / tech / size / redirects |
| `bb_tech_detect(url)` | Web technology fingerprint (headers + body heuristics) |
| `bb_dir_fuzz(base_url, extensions, wordlist)` | HTTP directory/endpoint brute force (light, rate-limited). Auto-warns **CATCH-ALL** when most hits share status+size (SPA false positives) |
| `bb_headers_check(url)` | Passive check: security headers, CORS, cookies, sensitive files (.git, .env, backups) — sensitive-file hits are similarity-checked against the homepage and flagged `⚠ likely FALSE` on SPAs |
| `bb_site_map(url)` | **Mine a homepage for real subsystems** (grouped by host, assets skipped). On multi-department sites (universities/hospitals) this is the highest-value recon step — homepage links are the authoritative subsystem inventory (OA/教务/招生/人事/图书馆) |
| `bb_nuclei(target, ..., background)` | **Nuclei v3.11.1** template scan (14k local templates). **Use `background=true`** for anything beyond a quick tag pass — full-lib scans take minutes and the MCP client times out on foreground waits |
| `bb_nuclei_result(stem)` | Poll a background nuclei job: "STILL RUNNING + partial count" → final finding summary |
| `bb_captcha_capture(url)` | Download a captcha image to `loot/` + return the session cookie for the next step |
| `bb_login_attempt(url, cookie, data)` | ONE controlled login attempt; response body verbatim. Reports **DISCONNECT** (server drops TCP, no HTTP response) — that is itself a submittable finding |
| `bb_target_analyse(target, subdomains, ports)` | One-shot quick recon report (DNS + HTTP + ports + subdomains) |
| `bb_vendors(kind, limit, page, name)` | **补天项目大厅**: `kind=welfare` (公益SRC 厂商库, 2000+ 家注册厂商, name 可搜"大学/医院"等) 或 `kind=dedicated` (专属SRC, ~46 家带奖金范围). welfare 的 cid 用于提交 `/Loo/submit?cid=X` |
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
   - **公益SRC** (default, no pre-approval): `bb_vendors(kind="welfare", name="大学"/"医院"/"征信")`
     → search the ~2000 registered 公益 vendors. 选靶标准: gov/edu/医疗/征信优先
     (**gov/edu 无权重要求**); 独立域名 > 省级统一门户; 避开 `kb/butian-plan.md`
     不关注名单(JeeCms/泛微OA/正方教务等); 厂商漏洞页(厂商详情页)活跃度高的优先
     (确认快=回款快)。
   - **专属SRC** (bounty): `bb_vendors(kind="dedicated")` → ~46 vendors with explicit
     bounty ranges. Prefer high `max_reward` + `[推荐]` + recent update.
   - `bb_activities(status="ongoing")` → live campaigns (报名 in the browser, then
     check the name when submitting — extra reward on top of the vuln bounty).
   - Cross-check against `kb/butian-plan.md`: skip vendors/vuln types in the
     「不关注的系统和漏洞」 list; IP vulns not accepted; same system+type ≤ 3.
2. **Get the scope**: for a 公益 vendor the scope is the vendor's public website
   (find the official domain via Baidu — that search result doubles as 归属证明).
   Enumerate real subsystems from the homepage's own links (not just the apex).
3. **Hunt**: run the recon ladder (step 2–7 below) against the in-scope hosts.
4. **Verify + draft**: for each confirmed finding call `bb_report(...)` to emit a
   Butian-compliant Markdown draft (it enforces the POST 三处 rule, POC code
   block, weight check, screenshot checklist). The file lands in `reports/`.
5. **Human confirm, then submit**: per `kb/butian-role.md` — AI-found vulns must
   pass a human check of the POC screenshots before submission (repeated
   unverified AI vulns can freeze the account). First-come-first-served → submit
   fast once confirmed. Copy each section of the generated report into the
   matching form field. The form's 简要描述 field is mandatory: 概述+影响, 不写
   详细URL (bb_report's `summary` param); the 漏洞详情 must include BOTH proof
   screenshots (复现过程 + 厂商归属) — the generated report's 截图清单 has the
   step-by-step recipe for making each image.
6. **Iterate**: run the post-run loop (§3e) — update skill/MCP/kb with what this
   engagement taught, then commit + push the repo.

### 3b. Recon ladder (for a confirmed in-scope target)

1. **Confirm authorization** (Section 0). Record the target, scope, and program.
   - **补天目标筛选**: 对照 `kb/butian-plan.md` 的「不关注的系统和漏洞」名单先排除;
     IP 漏洞暂不收;CORS 错误/self-xss/前台弱口令/URL跳转 不报;
     同系统同类型最多报 3 个;SQLi 同接口多参数算一处。
   - 测试行为遵守 `kb/butian-role.md`: 限速扫描、RCE 证明后立刻停(whoami 即可)、
     不拉数据、不跳板、不 DoS、不动业务数据、不留 webshell。
2. **Quick recon**: `bb_target_analyse("target.com")` for an overview.
3. **DNS & subdomains**: `bb_resolve`, then `bb_subdomains("target.com",
   verify=true)` — the verify pass is what separates real subsystems from
   wildcard/CGNAT noise (campus networks make every wordlist name "resolve" to
   the same catch-all; verify shows which ones actually serve distinct pages).
   If the apex resolves to a CGNAT IP (100.64.0.0/10 or 198.18.0.0/15), the apex
   itself is usually broken — work on the live subdomains instead.
4. **Map the real surface**: `bb_site_map("https://www.target.com")`. On
   multi-department sites this beats subdomain guessing — the homepage links
   are the inventory (and they double as 归属证明 material).
5. **Services**: `bb_port_scan("target.com", ports="80,443,8080,8443,3000,...")`.
6. **HTTP layering**: `bb_http_probe` over discovered hosts, `bb_tech_detect` on
   interesting ones, then `bb_dir_fuzz` on live web roots (use a SecLists
   wordlist for real coverage). **Read the CATCH-ALL warning**: if most hits
   share status+size (or all redirect to one login page), the app is a SPA/auth
   filter and the "found" endpoints are false positives — verify any you care
   about manually, and move on to its login page.
7. **Weakness triage**: `bb_headers_check` for header/CORS/cookie/sensitive-file
   issues (its sensitive-file hits are similarity-checked against the homepage —
   trust the ⚠ flags); correlate findings with PayloadsAllTheThings for exploit research.
8. **Template scan**: `bb_nuclei(target, background=true)` then poll with
   `bb_nuclei_result` — see §3d for the tag strategy. Nuclei sends more requests
   than the recon tools; keep `threads` low (10-25) on production targets.
9. **Login-flow deep-dive**: §3c — on in-house systems this is where findings
   actually come from.
10. **Report**: for each finding give: URL, how to reproduce, severity
     (info/low/medium/high/critical). Only report verified issues; honor program
     disclosure policy.
    - **补天(Butian)提交**: 用 `bb_report(...)` 生成官方模板格式的 Markdown 草稿
      (自动处理 POST 三处/POC 代码块/权重校验/截图清单/自查提醒), 落盘在
      `reports/`。对照 `kb/butian-submission-template.md` 的「提交前自查清单」
      逐项确认后, 按节复制进表单提交。平台规则(审核时限、5个待审限制、
      重复按时间、信誉分)见 `kb/butian-faq.md`。先报先得 → 确认无误尽快提交。

### 3c. Login-flow deep-dive (where the real findings come from)

Template scanners find what templates know. **In-house systems (OA/教务/门户 —
exactly what 公益SRC vendors run) yield to manual login-flow testing instead.**
This playbook produced the 2026-10-14 finding (see §6).

1. **Find the login endpoint.** `bb_site_map` on the portal → pick a subsystem
   (OA/招生/教务). Fetch the login page; read the form: action URL, param names,
   whether the password is hashed client-side (MD5/SHA in the login JS), and any
   captcha endpoint (e.g. `/login/code.jsp`). Also grep the page/JS for sibling
   endpoints (forget-password, QR login, SMS login) — each is an unauthenticated
   surface.
2. **Break the captcha with OCR.** `bb_captcha_capture(captcha_url)` → saves the
   image + returns the session cookie. Run the `ocr` MCP tool on the saved path
   (4-digit captchas are ~90% reliable; re-capture on a failed attempt).
3. **Baseline with a clean attempt.** `bb_login_attempt(endpoint, cookie,
   "user=admin&password=<wrong>&yzm=<ocr>")`. Learn the app's response grammar:
   wrong-code vs wrong-password vs unknown-user messages. **Watch `leftCount` /
   remaining-attempts fields — they leak per-username state (enumeration).**
4. **Differential testing, one variable at a time.**
   - Username only: `<name>'` → format error? → the quote reaches parsing.
   - `user=x' or '1'='1` vs `user=x' or '1'='2` (TRUE vs FALSE).
   - Repeat each payload 3-4× (rate limiting can mask the signal).
   - **Interpret connection-level behavior, not just bodies:** no HTTP response at
     all (DISCONNECT / connection reset) is a signal — a server that crashes on a
     crafted param before responding is submittable on its own (medium risk:
     unauthenticated crash / suspected SQL-handling flaw). Same result for TRUE
     and FALSE + existing and non-existing users ⇒ crash sits in
     parse/SQL-construction, not in the query itself.
   - Budget matters: login forms count attempts per username. Use throwaway
     usernames for crash testing; save real accounts for the final proof.
5. **Verify impact & scope.** After a crash, re-GET the login page and a second
   endpoint: if they still 200, it's per-request impact (honest, still
   submittable); if the app is down, say so. Never leave the app worse off than
   you found it.
6. **Report.** `bb_report(...)` — title: `XX系统XX接口存在未授权异常崩溃(疑似SQL注入)`,
   level 中危, method POST with the full packet in `post_data` and the injected
   param in `param_name`, POC = the crashing value. Screenshot the crash in a
   browser DevTools Network tab (red failed request) — that is the proof image.

### 3d. Nuclei usage (don't fight the MCP timeout)

- **Always `background=true` for full-lib or multi-tag scans**; poll with
  `bb_nuclei_result(stem)` every 30-60s. Foreground + short timeout is only for
  single quick tags.
- A focused tag set beats the full lib on in-house stacks (fewer templates, less
  noise, faster): `tags="sqli,xss,ssrf,auth-bypass,misconfig,exposures,cves,headless,default-login,lfi,rce"`
  ≈ 5.4k templates ≈ 2 min/host. Full lib ≈ 5+ min and mostly misses bespoke OA.
- Tag names are exact (`misconfig`, not `misconfiguration`; `exposures`, not `exposure`).
  If a scan "finds 0 with 7 templates loaded", the tag filter silently matched
  almost nothing — check the loaded template count in the result tail.
- Nuclei results on in-house OA are usually info-level (cookie flags, banners).
  Treat a quiet nuclei run as "no known CVEs", NOT as "clean" — then do §3c.

### 3e. Post-run iteration loop (MANDATORY after every real engagement)

After each 实战 (once the report is generated or the run is paused), iterate the
toolchain itself and push it — this is how the skill and MCP stay current:

1. **Capture lessons**: what slowed the run down? false positives? a manual step
   that should have been a tool? a platform rule that was missing/wrong?
2. **Iterate the skill** (both copies — global
   `C:\Users\LT\.config\opencode\skills\bugbounty\SKILL.md` and project
   `bugbounty-mcp\.opencode\skills\bugbounty\SKILL.md`, keep them identical):
   playbook tweaks, new warnings, corrected platform rules.
3. **Iterate the MCP** when a lesson is repeatable: add/change functions in
   `bbmcp/tools.py`, register in `server.py`, smoke-test the touched paths
   (compile + one real call), then re-run `smoke_test.py`.
4. **Fix knowledge**: wrong/outdated facts go to `kb/` (platform rules, pricing,
   vendor list). Refresh `kb/welfare-vendors-snapshot.json` when crawling new pages.
5. **Ship it**: `git add -A`, commit with a message naming the lesson
   (e.g. "实战XX大学: 报告补简要描述字段+双截图制作步骤"), `git push`
   (LUTAO581314/ai-cybersec, main). If the network to GitHub is down, retry once;
   if still down, note the commit is local and push at the next opportunity.

The bar for adding a tool: it fixed a **recurring** pain (seen ≥1× in a run and
obviously reusable), it is tested end-to-end, and the README tool table is updated.

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

## 6. Case study: 江西师范大学 (2026-10-14, 公益SRC)

First full loop run — the pattern to repeat.

- **Pick**: `bb_vendors(kind="welfare", name="大学")` → 江西师范大学 (cid 65415).
  Chosen because the vendor page showed an active pipeline (96 vulns, 22 已处理,
  a 确认 within the last 12h — fast reviews). edu = no 补天权重 requirement.
- **Recon**: apex on CGNAT (198.18.x) with broken https → subdomains with
  verify=true + `bb_site_map` on www → 18 real subsystems (www=Dswjcms,
  oa=legacy 贝凯 OA, oas/oa6=**new 贝凯 JSP OA**, jwc=ASP.NET 教务, yz/rsc/...).
- **Nuclei** (5.4k focused tags): 2 info-level (cookie without Secure) — a
  "quiet" run, i.e. no known CVEs; the OA is bespoke.
- **Finding** (via §3c): `POST /oa6/doLogin.jsp` with `userId=x' or 'y'='z`
  → server drops TCP with no HTTP response (4/4 repro, TRUE/FALSE identical,
  existing + non-existing users). Single quote → format error (quote reaches
  parsing). App healthy afterwards (per-request impact). Reported 中危 as
  未授权异常崩溃 (疑似SQL注入) via `bb_report`; bonus observations (leftCount
  per-username leak, client-side MD5 password, cookie flags) kept as low-risk
  candidates.
- **Lessons encoded in this skill**: CGNAT apex → trust verify=true + site_map;
  SPA dir-fuzz → trust the catch-all warning; quiet nuclei → go manual on the
  login; OCR loop works for 4-digit captchas; crash-without-response is the
  finding.
