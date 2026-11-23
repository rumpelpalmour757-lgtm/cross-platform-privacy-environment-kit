<p align="center">
  <img src="docs/images/logo.svg" alt="" width="76" height="76">
</p>

<h1 align="center">跨平台网络隐私与本机环境工具包</h1>

<p align="center">
  <b>只读体检、统一路由、Windows 防泄漏护盾、配置安全快照、干净原创实测报告与离线交互工作台——按需取用，不做黑箱。</b>
</p>

<p align="center">
  <a href="#这是什么"><b>这是什么</b></a>
  &nbsp;·&nbsp;
  <a href="#交互式展示与配置工作台ui"><b>交互工作台</b></a>
  &nbsp;·&nbsp;
  <a href="#快速开始"><b>快速开始</b></a>
  &nbsp;·&nbsp;
  <a href="#干净版跨端实测综合报告"><b>综合报告</b></a>
  &nbsp;·&nbsp;
  <a href="#验证到哪一步"><b>验证边界</b></a>
  &nbsp;·&nbsp;
  <a href="#包内目录与模块"><b>包内目录</b></a>
  &nbsp;·&nbsp;
  <a href="#许可与署名"><b>许可与署名</b></a>
</p>

<p align="center">
  <a href="https://github.com/rumpelpalmour757-lgtm/cross-platform-privacy-environment-kit/stargazers"><img alt="Stars" src="https://img.shields.io/github/stars/rumpelpalmour757-lgtm/cross-platform-privacy-environment-kit?style=flat-square&color=1D5F8A&logo=github&logoColor=white&label=Stars"></a>
  <a href="CHANGELOG.md"><img alt="版本 v0.4.0" src="https://img.shields.io/badge/%E7%89%88%E6%9C%AC-v0.4.0-1F2A44?style=flat-square"></a>
  <a href="claude-doh-domains.txt"><img alt="生态置顶域名 30 个" src="https://img.shields.io/badge/%E7%94%9F%E6%80%81%E5%9F%9F%E5%90%8D-30%20%E4%B8%AA-1F2A44?style=flat-square"></a>
  <a href="#验证到哪一步"><img alt="离线单测 128 项" src="https://img.shields.io/badge/%E6%B5%8B%E8%AF%95-128%20%E9%A1%B9-1F2A44?style=flat-square"></a>
  <img alt="需要 Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-1F2A44?style=flat-square">
  <a href="LICENSE"><img alt="许可 MIT" src="https://img.shields.io/badge/%E8%AE%B8%E5%8F%AF-MIT-1F2A44?style=flat-square"></a>
  <a href="https://github.com/rumpelpalmour757-lgtm/cross-platform-privacy-environment-kit/actions/workflows/tests.yml"><img alt="GitHub Actions 测试状态" src="https://github.com/rumpelpalmour757-lgtm/cross-platform-privacy-environment-kit/actions/workflows/tests.yml/badge.svg"></a>
</p>

<p align="center">
  <a href="https://rumpelpalmour757-lgtm.github.io/cross-platform-privacy-environment-kit/"><img alt="打开交互式工作台（GitHub Pages）" src="https://img.shields.io/badge/%E6%89%93%E5%BC%80%E4%BA%A4%E4%BA%92%E5%B7%A5%E4%BD%9C%E5%8F%B0-1D5F8A?style=for-the-badge"></a>
  <a href="https://github.com/rumpelpalmour757-lgtm/cross-platform-privacy-environment-kit/releases/tag/v0.4.0"><img alt="下载发布包（v0.4.0）" src="https://img.shields.io/badge/%E4%B8%8B%E8%BD%BD%E5%8F%91%E5%B8%83%E5%8C%85-1F2A44?style=for-the-badge"></a>
  <a href="docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md"><img alt="干净版综合报告" src="https://img.shields.io/badge/%E5%B9%B2%E5%87%80%E7%89%88%E7%BB%BC%E5%90%88%E6%8A%A5%E5%91%8A-1F2A44?style=for-the-badge"></a>
</p>

![跨平台网络隐私与本机环境工具包四层架构图：从只读边界与链路体检，到跨端 30 域置顶路由与加密 DNS，再到 Windows 物理网卡防 DNS 旁路与含 DHCP 保护的断网开关，以及本地私有权限配置快照与离线交互展示台](docs/images/architecture-cover.svg)

## 这是什么

这是一套面向 **Windows、macOS、Linux、Android、iPhone / iPad** 的开源网络隐私工程与本机环境自查工具包，主流程是：**只读体检摸清现状 → 生成并静态校验跨端路由 → 按需部署 Windows 防 DNS 旁路或严格断网开关 → 私有权限快照备份与还原**。所有脚本仅使用系统自带运行时与 Python 3.10+ 标准库，默认操作全部只读且自动脱敏本机路径，不内置客户端二进制，也不碰账号凭据。

- **先预览、后变更、随时可回退** — Windows 防火墙与断网脚本均强制区分 `Preview` / `Install` / `Status` / `Remove`，安装前自动导出 `.wfw` 防火墙策略备份并校验 SHA-256；检测到 DHCP 网卡但漏填 `-DhcpServer` 时直接拒绝安装，避免续租被拦锁死网络。
- **五端规则同源、与离线 UI 逐项对账** — Windows（v2rayN）、Android（v2rayNG + 离线二维码）与 iOS（Shadowrocket）共享同一套 30 域置顶生态与 IPv6 / QUIC 兜底口径；前端离线工作台的路由 JSON 与防火墙补集算法均与 Python 脚本在单测中做跨语言逐字节对账。
- **干净原创、无第三方原文镜像** — `v0.4.0` 公开前已彻底移除此前私有备份里的第三方文章与微信转发镜像目录，并重建干净的 Git 提交历史；所有外部背景仅保留公开出处链接（见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)）。
- **明确的能力与合规边界** — 本项目聚焦网络隐私工程、DNS 洁净度、断线防静默回落与安全备份可靠性；仅靠网络配置不能替代服务商的使用条款或地区政策，本项目也不提供任何检测绕过或风控对抗方案。

## 交互式展示与配置工作台（UI）

可以直接访问在线演示 **[GitHub Pages 交互工作台](https://rumpelpalmour757-lgtm.github.io/cross-platform-privacy-environment-kit/)**，或者克隆/下载后在浏览器离线双击打开 [docs/index.html](docs/index.html)（**零外部 CDN、零追踪脚本、支持明暗双主题**）。

<table>
  <tr>
    <td width="112" align="center">
      <img src="docs/images/hajimi-mascot.svg" alt="哈基米 (Gemini) 协作徽章" width="84" height="84">
    </td>
    <td>
      <b>五大交互面板 + 哈基米（Gemini）协作小助手</b><br>
      1. <b>总览与架构</b>：五端入口矩阵、四层纵深防护说明，以及 <b>Celeste × 哈基米（Gemini）</b> 共创名片与互动避坑贴士。<br>
      2. <b>路由工作台</b>：与 <code>build_routing.py</code> 同源的 5 套预设（默认/全局/生态置顶/外部优先），实时预览、复制或下载路由 JSON 与 30 域加密 DNS 清单。<br>
      3. <b>Windows 防火墙规划器</b>：与 <code>build_kill_switch.py</code> 同源的 IPv4 补集区间计算、DHCP 漏填预警、LAN DNS 旁路防护命令生成与副作用提示。<br>
      4. <b>跨端隐私自检清单</b>：可勾选并自动保存在本地浏览器 <code>localStorage</code>，支持一键导出 Markdown / JSON 验收记录。<br>
      5. <b>干净版报告浏览器</b>：可视化对照 CLI 冷启动归零实测、39 目标路由对账、五端边界矩阵与五大常见误区纠偏卡片；右下角随时可展开「哈基米贴士」。
    </td>
  </tr>
</table>

## 快速开始

### 按平台选择入口

| 平台 / 场景 | 推荐入口 |
| :--- | :--- |
| **在线 / 离线交互 UI** | 打开 [GitHub Pages 工作台](https://rumpelpalmour757-lgtm.github.io/cross-platform-privacy-environment-kit/) 或本地 [docs/index.html](docs/index.html) 生成配置与自检。 |
| **Windows** | 先看 [CLAUDE-PROXY-OPTIMIZATION-GUIDE.md](CLAUDE-PROXY-OPTIMIZATION-GUIDE.md) 与下方的只读体检、路由和防火墙命令；严格断网开关见 [WINDOWS-KILL-SWITCH.md](WINDOWS-KILL-SWITCH.md)。 |
| **macOS / Linux** | 运行 `python3 inspect_unix_network.py` 只读查看默认路由、DNS 与 IPv6，并按 [PRIVACY-CHECKLIST.md](PRIVACY-CHECKLIST.md) 核查边界。 |
| **Android** | 见 [mobile/README.md](mobile/README.md)，通过 13 条规则 JSON 或配套离线二维码导入 `v2rayNG`，并核对电池保活与原生 App 边界。 |
| **iPhone / iPad** | 见 [mobile/README.md](mobile/README.md)，导入已开启 IPv6 隧道接管的 Shadowrocket 模板并验收。 |
| **深度实测与边界** | 阅读干净原创综合报告 [docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md](docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md)。 |

### Windows 常用命令（默认先只读）

#### 1. 只读体检与客户端边界核查

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Inspect-WindowsProxy.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Inspect-WindowsFirewall.ps1
py -3 .\audit_client_boundary.py
```

输出自动遮盖个人用户名、自定义网卡名与启动项敏感路径；同时核查 CLI 的 5 项防后台外联开关与是否存在 MSIX 自动写入的显式防火墙放行规则。

#### 2. 跨端路由规则生成与静态校验

```powershell
py -3 .\build_routing.py validate .\routing-template.json
py -3 .\build_routing.py validate .\routing-claude-ecosystem.json --claude-ecosystem
py -3 .\build_routing.py validate .\routing-claude-global.json --global-proxy --claude-ecosystem
py -3 .\build_routing.py print-doh-domains
```

- 启用严格断网开关或要求最高出口一致性时，建议使用 [routing-claude-global.json](routing-claude-global.json)，将 `domainStrategy` 设为 `AsIs` 并把 [claude-doh-domains.txt](claude-doh-domains.txt) 绑定到远端加密 DNS。
- 保留国内直连分流时，建议使用 [routing-claude-ecosystem.json](routing-claude-ecosystem.json)（30 项生态域名、IPv4 网段与 IPv6/QUIC 兜底均排在 `geosite:cn` 之前）。
- 使用 [refresh_allowlists.py](refresh_allowlists.py) 拉取上游国内直连预览时，建议显式指定已审阅的 `--commit <40位SHA>` 及 `--expected-direct-sha256` / `--expected-cidr-sha256`。

#### 3. 物理网卡防路由器 DNS 旁路（保留分流时推荐）

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Preview -IncludeAllPhysicalAdapters
# 管理员 PowerShell 安装与核查：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Install -IncludeAllPhysicalAdapters
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Status -IncludeAllPhysicalAdapters
# 随时一键精准卸载：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Remove
```

> **明确副作用**：安装后只要关闭代理客户端或 TUN，系统 DNS 指向路由器（家用网络默认配置）的请求会全部解析失败，公司内网 `10.x` 等私网 DNS 也会被封。需要直连家用或内网 DNS 时，执行 `-Action Remove` 即可恢复，详见 [WINDOWS-KILL-SWITCH.md](WINDOWS-KILL-SWITCH.md)。

#### 4. 严格断网开关与真实 TUN 连通校验

完整步骤见 [WINDOWS-KILL-SWITCH.md](WINDOWS-KILL-SWITCH.md)（使用 DHCP 网卡时**必须**传入 `-DhcpServer`，安装前先 `Preview`）。需要验证系统 TUN 隧道真实出口时，用普通用户执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-ProxyState.ps1 -Stage normal -AsJson
```

未检测到活动 TUN 隧道路由时，`-Stage normal` 会默认拒绝发包，防止误用真实 IP 直连测试站点。

#### 5. 配置目录与 Claude 本地数据私有快照

```powershell
# 代理客户端配置快照（含订阅与口令，请仅存放在本机加密盘私人目录）
py -3 .\config_snapshot.py backup --config-dir "C:\实际路径\guiConfigs"
py -3 .\config_snapshot.py verify "生成的快照目录"

# Claude Code 本地数据体检、备份、校验与还原（默认拒绝保存明文 API Key/Token）
py -3 .\claude_local_data.py audit
py -3 .\claude_local_data.py backup --destination "C:\Users\<USER>\claude-backups"
py -3 .\claude_local_data.py verify "生成的快照目录"
```

## 干净版跨端实测综合报告

完整原创报告见 **[docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md](docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md)**，与操作清单 [CLAUDE-PROXY-OPTIMIZATION-GUIDE.md](CLAUDE-PROXY-OPTIMIZATION-GUIDE.md)、[PRIVACY-CHECKLIST.md](PRIVACY-CHECKLIST.md) 互相对应。报告采用干净原创结构，覆盖六大核心内容：

1. **研究方法与能力边界**：严格区分「本机独立实测验证」与「社区公开研究背景」，拒绝夸大网络工具的边界。
2. **五端客户端网络边界矩阵**：逐端梳理独立隔离浏览器、官方 CLI、官方 Windows MSIX Desktop、独立科研桌面端与 Android 原生 App 能管什么、管不了什么。
3. **四层无侵入本机实测实证（已彻底脱敏）**：包括 CLI `2.1.330` 未登录冷启动从 **3 次外联 + 549 KB（241 条事件）** 降为 **0** 的对照验证、Desktop `6.28899.6` MSIX 自动写入 Windows 防火墙显式 `Allow` 规则的冲突实证，以及 39 个生态目标的分流与 DoH 全量对账。
4. **五大常见误区纠偏**：拆解“CLI/Desktop 自动跨进程互扫”“全量改字体/UA 凑检测页低分”“手机代理能拦住本地硬件与网卡枚举”“应用分身等于独立隔离环境”“IPv4 单出口忽略 Anthropic IPv6 导致 502”等常见误解。
5. **工具包落地映射与操作副作用**：把每条实证直接落到本仓库的对应脚本与参数，并如实写明每一项副作用。
6. **干净的外部参考索引**：不夹带任何第三方原文，全部公开链接集中收录在 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

## 包内目录与模块

| 路径 / 文件 | 说明 |
| :--- | :--- |
| [docs/index.html](docs/index.html) · `docs/styles.css` · `docs/app.js` | 零外部依赖的离线交互式展示与配置工作台 UI（GitHub Pages 入口） |
| [docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md](docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md) | 干净原创的跨端客户端边界、四层本机实测与网络防泄漏综合报告 |
| [docs/images/](docs/images/architecture-cover.svg) | 项目徽标 `logo.svg`、架构总览图 `architecture-cover.svg` 与哈基米徽章 `hajimi-mascot.svg` |
| [CLAUDE-PROXY-OPTIMIZATION-GUIDE.md](CLAUDE-PROXY-OPTIMIZATION-GUIDE.md) · [PRIVACY-CHECKLIST.md](PRIVACY-CHECKLIST.md) | 代理与分流落地优化指南、全平台日常/排错核对清单 |
| [build_routing.py](build_routing.py) · [claude-doh-domains.txt](claude-doh-domains.txt) · `routing-*.json` | 30 域生态置顶路由生成器、DoH 域名清单与 3 套开箱即用路由模板 |
| [Manage-WindowsLanDnsGuard.ps1](Manage-WindowsLanDnsGuard.ps1) · [build_lan_dns_guard.py](build_lan_dns_guard.py) | Windows 物理网卡防路由器 53 端口旁路脚本与对照规划器 |
| [Manage-WindowsKillSwitch.ps1](Manage-WindowsKillSwitch.ps1) · [build_kill_switch.py](build_kill_switch.py) · [WINDOWS-KILL-SWITCH.md](WINDOWS-KILL-SWITCH.md) | Windows 严格断网开关（含 DHCP 防误锁与 `.wfw` 备份校验）及说明 |
| [Inspect-WindowsProxy.ps1](Inspect-WindowsProxy.ps1) · [Inspect-WindowsFirewall.ps1](Inspect-WindowsFirewall.ps1) · [Test-ProxyState.ps1](Test-ProxyState.ps1) | Windows 只读代理/防火墙体检、MSIX 放行规则告警与真实 TUN 校验 |
| [audit_client_boundary.py](audit_client_boundary.py) · [inspect_unix_network.py](inspect_unix_network.py) · `environment_report.py` | 跨平台客户端边界只读审计、macOS/Linux 网络检查与脱敏环境报告 |
| [config_snapshot.py](config_snapshot.py) · [claude_local_data.py](claude_local_data.py) · [refresh_allowlists.py](refresh_allowlists.py) | 私有权限配置快照备份/还原（防符号链接与明文密钥泄漏）与上游直连名单预览 |
| [mobile/README.md](mobile/README.md) · `mobile/` | Android `v2rayNG` 13 条规则、离线二维码、静态校验器与 iOS Shadowrocket 模板 |
| [CHANGELOG.md](CHANGELOG.md) · [LICENSE](LICENSE) · [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) · [AUTO-UPDATE.md](AUTO-UPDATE.md) | 版本记录、MIT 许可、第三方参考声明与每周本地自动同步安全闸门说明 |

## 验证到哪一步

只写跑过的，没跑过的不写成通过：

### 做过的

- **跨平台离线单元测试（128 项）**：在 Windows Python 3.13 与 Linux（WSL Ubuntu）Python 3 下运行全套 `test_*.py`，覆盖路由生成与校验、Windows 断网开关与 LAN DNS 规划器、配置快照安全边界、Android/iOS 规则静态校验、MIT 与零镜像回归检查、全仓 Markdown 相对链接检查，以及通过 Node.js 对 `docs/app.js` 与 Python `build_routing.py` / `build_kill_switch.py` 的算法一致性交叉对账（平台专属用例按运行环境显式跳过）。
- **PowerShell 语法与逻辑核验**：所有 `.ps1` 脚本经解析与逻辑核查，确认 DHCP 漏填拦截与 PowerShell 5.1 严格模式空数组分支已修复；断网开关补集输出与 Python 规划器一致。
- **本机四层无侵入实测与可视化核验**：在隔离临时目录下完成 CLI `2.1.330` 冷启动归零对照、MSIX 安装包离线静态拆检与 39 目标路由分流对账；并用无头浏览器实拍核验了 `docs/index.html` 明暗主题与矢量图的渲染排版。
- **公开前隐私与历史核查**：公开前重建单提交干净历史，确认仓库工作区与 Git 历史中均无本机用户名路径、个人代理节点链接、第三方原文镜像或微信转发原文。

### 没做的

- **未在 CI 中修改真实防火墙或连真实代理节点**：单元测试验证规则规划、参数拦截与回退逻辑，不会在 CI runner 上真实改写 Windows 防火墙或联网拨号；真实断网与断线演练需在个人主机按 [WINDOWS-KILL-SWITCH.md](WINDOWS-KILL-SWITCH.md) 受控执行。
- **包内不含 Xray 二进制**：`mobile/` 的校验器只做结构、域名顺序与网段静态检查，不做真实内核路由回放。
- **未在 macOS 真机与旧版 PowerShell 5.1 实跑全部脚本**：macOS 侧逻辑按 Unix 网络接口单测与静态审查验证；PowerShell 5.1 兼容性通过静态语法与空集合边界修复保障，未在独立 Win10 5.1 环境全量实机安装断网开关。
- **不承诺账号结果或规避平台政策**：网络层与本机边界工具无法替代服务商的使用条款或地区政策。

## 离线自检命令

在仓库根目录执行以下命令即可离线复核全部 128 项测试（包含 UI 算法与文档链接回归检查）：

```bash
python -B -m unittest discover -p "test_*.py" -v
```

如果你要复用本仓库的每周本地自动同步与干净打包脚本，请参阅 [AUTO-UPDATE.md](AUTO-UPDATE.md)（默认硬编码排除私有 `research-reports/` 目录并在提交前执行隐私与版权闸门）。

## 许可与署名

- **许可协议**：本仓库按 **MIT License** 开源发布，版权人 **Celeste**，全文见 [LICENSE](LICENSE)。外部背景链接与许可边界见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
- **作者与协作**：
  - 作者：**Celeste**（GitHub：[rumpelpalmour757-lgtm](https://github.com/rumpelpalmour757-lgtm)）
  - 协作开发与公开版重构：**哈基米（Gemini）** 与 AI 助手参与完成了 `v0.4.0` 的 MIT 公开化整理、干净版原创综合报告归纳、零依赖离线交互工作台 UI（[docs/index.html](docs/index.html)）与配套矢量视觉资产；项目定位、隐私边界与公开发布均由作者审核拍板。
- **同系列公开项目**：[novel-workshop（小说写作工坊）](https://github.com/rumpelpalmour757-lgtm/novel-workshop) · [bjm-portable（BJM 通用迁移包）](https://github.com/rumpelpalmour757-lgtm/bjm-portable) · [rule-conflict-constitution（AI 协作宪法）](https://github.com/rumpelpalmour757-lgtm/rule-conflict-constitution)
