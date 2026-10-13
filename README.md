# ai-cybersec

**AI 网安工具链** — 给 AI agent 用的 bug bounty 侦察/扫描/报告工具集。
一个本地 MCP server(9 个工具)+ 一个 opencode skill(工作流与平台规范)+ 补天知识库 + 一键环境部署。

纯 Python 核心(httpx + dnspython),Windows 直接跑,无需原生扫描器;
漏洞模板扫描由 **Nuclei v3.11+** 承担(14k+ 模板,离线可用)。

> ⚠️ 只用于**授权目标**:Bug Bounty 项目内的资产,或自己的系统。

## 目录结构

```
├── server.py                  # MCP server 入口 (mcp SDK 2.x / MCPServer)
├── bbmcp/
│   └── tools.py               # 全部工具实现
├── .opencode/skills/bugbounty/SKILL.md   # opencode skill(工作流+授权护栏)
├── kb/
│   ├── butian-submission-template.md    # 补天官方提交模板(公告543, 含字段+自查清单)
│   └── butian-faq.md                    # 补天平台规则(审核/奖励/信誉分/限制)
├── setup.ps1                  # 一键部署: venv + nuclei + 模板 + 词表 + skill
├── smoke_test.py              # MCP 端到端自测
├── requirements.txt
└── run_server.bat             # 手动启动 stdio server
```

## MCP 工具(9 个)

| 工具 | 说明 |
|------|------|
| `bb_resolve` | DNS 解析 (A/AAAA/CNAME/MX/NS/TXT) |
| `bb_subdomains` | 子域枚举(证书透明 crt.sh + 字典爆破) |
| `bb_port_scan` | TCP 端口扫描(默认常用 web/db 端口) |
| `bb_http_probe` | 批量 HTTP 探测:状态/标题/技术/跳转 |
| `bb_tech_detect` | Web 技术指纹(headers + body) |
| `bb_dir_fuzz` | 目录/端点爆破(限速;可接 SecLists 词表) |
| `bb_headers_check` | 安全头/CORS/Cookie/敏感文件(.git/.env/备份) |
| `bb_nuclei` | **Nuclei 模板扫描**(14k 模板;tags/severity/线程/超时可控;结果落盘 loot/) |
| `bb_target_analyse` | 一键侦察报告(DNS+HTTP+端口+子域) |
| `bb_vendors` | **补天项目大厅**:专属SRC厂商列表(名称/奖金范围/推荐/更新时间) |
| `bb_activities` | **补天活动中心**:进行中/已结束活动 + 完整活动规则文本 |
| `bb_report` | **补天报告生成器**:按官方模板生成 Markdown 草稿(POST三处/POC代码块/权重校验/截图清单/自查提醒) |

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
授权确认 → bb_target_analyse → bb_subdomains → bb_port_scan
        → bb_http_probe / bb_dir_fuzz → bb_headers_check
        → bb_nuclei → bb_report 生成补天模板报告(reports/)
        → 人工核对POC截图 → 按节复制进表单提交
```

## 补天(Butian)知识库

- 提交必须按官方规范:**权重选错/漏选直接驳回**,POST 注入三要素、
  首页截图含地址栏、POC 放代码块、需登录给测试账号、修复方案不敷衍。
- 规则要点:先报先得;新用户 5 个待审上限;公益SRC ~7 天认领期;
  专属SRC 一周不复审自动通过;现金每周三发;信誉分 ≤60 封号。
- 详见 `kb/` 两个文件,skill 的报告环节会自动引用。

## 说明

- 侦察类工具是"原语",不是漏洞利用执行器;nuclei 是最激进的,
  生产目标先用 tags/severity 过滤 + 低线程。
- 每次 nuclei 扫描的完整输出(JSONL + txt)保存在 `loot/`,报告前可复查。
