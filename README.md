# ai-cybersec

**AI 网安工具链** — 给 AI agent 用的 bug bounty 侦察/扫描/报告工具集。
一个本地 MCP server(16 个工具)+ 一个 opencode skill(工作流与平台规范)+ 补天知识库 + 一键环境部署。

纯 Python 核心(httpx + dnspython),Windows 直接跑,无需原生扫描器;
漏洞模板扫描由 **Nuclei v3.11+** 承担(14k+ 模板,离线可用)。

> ⚠️ 只用于**授权目标**:Bug Bounty 项目内的资产,或自己的系统。

## 目录结构

```
├── server.py                  # MCP server 入口 (mcp SDK 2.x / MCPServer)
├── bbmcp/
│   └── tools.py               # 全部工具实现
├── .opencode/skills/bugbounty/SKILL.md   # opencode skill(工作流+授权护栏+实战playbook)
├── kb/
│   ├── butian-submission-template.md    # 补天官方提交模板(公告543, 含字段+自查清单)
│   ├── butian-faq.md                    # 补天平台规则(审核/奖励/信誉分/限制)
│   ├── butian-plan.md                   # 收录细则+定价表+不关注厂商名单
│   ├── butian-role.md                   # 白帽行为规范(自动化测试行为边界)
│   ├── butian-newneed.md                # 漏洞状态全流程/积分/称号
│   └── welfare-vendors-snapshot.json    # 公益SRC厂商库快照(1200家, 离线选靶用)
├── setup.ps1                  # 一键部署: venv + nuclei + 模板 + 词表 + skill
├── smoke_test.py              # MCP 端到端自测
├── requirements.txt
└── run_server.bat             # 手动启动 stdio server
```

## MCP 工具(16 个)

| 工具 | 说明 |
|------|------|
| `bb_resolve` | DNS 解析 (A/AAAA/CNAME/MX/NS/TXT) |
| `bb_subdomains` | 子域枚举(crt.sh + 字典爆破);`verify=true` 存活探测 + 去 wildcard/CGNAT 假子域 |
| `bb_port_scan` | TCP 端口扫描(默认常用 web/db 端口) |
| `bb_http_probe` | 批量 HTTP 探测:状态/标题/技术/跳转 |
| `bb_tech_detect` | Web 技术指纹(headers + body) |
| `bb_dir_fuzz` | 目录/端点爆破(限速;可接 SecLists 词表;**自动识别 SPA catch-all 误报**) |
| `bb_headers_check` | 安全头/CORS/Cookie/敏感文件;敏感文件命中与首页做相似度比对,SPA 误报自动标 ⚠ |
| `bb_site_map` | **主页子系统挖掘**(按 host 分组、跳过静态资源)——多部门站点(高校/医院)最高价值的侦察步骤 |
| `bb_nuclei` | **Nuclei 模板扫描**(14k 模板;`background=true` 后台跑, 修 MCP 超时) |
| `bb_nuclei_result` | 轮询后台 nuclei 任务(运行中=部分结果数, 结束=完整发现) |
| `bb_captcha_capture` | 抓验证码图到 loot/ + 返回 session cookie(配 ocr MCP 工具破图) |
| `bb_login_attempt` | 单次受控登录尝试(差异测试用);**服务器无响应断开=DISCONNECT, 本身即可报** |
| `bb_target_analyse` | 一键侦察报告(DNS+HTTP+端口+子域) |
| `bb_vendors` | **补天项目大厅**:`kind=welfare` 公益SRC厂商库(2000+家,可按"大学/医院"等关键词搜索) 或 `kind=dedicated` 专属SRC(~46家,含奖金范围) |
| `bb_activities` | **补天活动中心**:进行中/已结束活动 + 完整活动规则文本 |
| `bb_report` | **补天报告生成器**:按官方模板生成 Markdown 草稿(简要描述/POST三处/POC代码块/权重校验/双截图制作步骤/自查提醒) |

## 快速开始

```powershell
git clone https://github.com/LUTAO581314/ai-cybersec
cd ai-cybersec
powershell -ExecutionPolicy Bypass -File .\setup.ps1   # 装 venv/nuclei/模板/词表/skill
# 按提示把输出的 JSON 片段加进 opencode 全局配置,重启 opencode
```

部署完成后,`bb-repos\` 下会有(与本仓库同级,共享):
- `nuclei-templates\` — Nuclei 模板
- `SecLists\Discovery\` — 子域 + 目录词表
- `PayloadsAllTheThings\` — payload/利用参考

手动验证:

```powershell
.\.venv\Scripts\python.exe smoke_test.py
```

## 工作流(skill 内置)

```
[补天闭环] bb_vendors / bb_activities → 选定厂商+活动+范围
授权确认 → bb_target_analyse → bb_subdomains(verify) → bb_site_map(子系统挖掘)
         → bb_port_scan → bb_http_probe / bb_dir_fuzz → bb_headers_check
         → bb_nuclei(background) + bb_nuclei_result 轮询
         → 登录流深打: bb_captcha_capture → OCR → bb_login_attempt(差异测试)
         → bb_report 生成补天模板报告(reports/, 含简要描述+双截图制作步骤)
         → 人工核对POC截图 → 按节复制进表单提交
[每次实战后] 迭代 skill/MCP/kb(把本次教训固化) → git commit + push 本仓库
```

## 实战案例(2026-10-14, 江西师范大学 公益SRC)

完整跑通"选靶→侦察→挖洞→报告"闭环,产出 1 个中危:

- `bb_vendors(kind="welfare", name="大学")` 选靶 → 挑活跃厂商(漏洞页 12h 内有确认 = 审核快)
- apex 在 CGNAT 后 + https 断 → `bb_subdomains(verify=true)` + `bb_site_map` 挖出 18 个真实子系统
- nuclei 聚焦扫描(5.4k 模板)仅 2 个 info 级 → **转登录流手工深打**(skill §3c playbook)
- OCR 破 4 位验证码,差异测试发现:`POST /oa6/doLogin.jsp` 的 `userId=x' or 'y'='z`
  形态触发**服务端无响应断连**(4/4 复现,TRUE/FALSE 一致)→ 中危"未授权异常崩溃(疑似SQL注入)"
- `bb_report` 生成官方格式报告,待人工核对截图后提交

经验(已固化进 skill):CGNAT 主站信 verify+site_map;SPA 目录爆破信 catch-all 告警;
nuclei 安静=去手工打登录;无 HTTP 响应的崩溃本身就是可报发现。

## 补天(Butian)知识库

- 提交必须按官方规范:**权重选错/漏选直接驳回**,POST 注入三要素、
  首页截图含地址栏、POC 放代码块、需登录给测试账号、修复方案不敷衍。
- 规则要点:先报先得;新用户 5 个待审上限;公益SRC ~7 天认领期;
  专属SRC 一周不复审自动通过;现金每周三发;信誉分 ≤60 封号。
- 详见 `kb/` 五个 md 文件,skill 的报告环节会自动引用。
- `kb/welfare-vendors-snapshot.json` — 公益厂商库离线快照(2026-10-14, 前 1200 家),
  断网时也能按关键词挑靶;在线全量用 `bb_vendors(kind="welfare", page=N)` 翻页。

## 说明

- 侦察类工具是"原语",不是漏洞利用执行器;nuclei 是最激进的,
  生产目标先用 tags/severity 过滤 + 低线程(全库扫描用 `background=true`)。
- 每次 nuclei 扫描的完整输出(JSONL + txt)保存在 `loot/`,报告前可复查。
- **每次实战后必做**:把本次教训迭代进 skill/MCP/kb,然后 `git commit + push`
  (skill 里的 §3e 迭代闭环)。
