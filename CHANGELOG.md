# 版本记录

## 2026-11-24 文档修订（适用 v0.4.1）

- 公开综合报告核对 Cage 的 WebGL 错误与两次客机网关事件，区分租约计时、从网关未开放到恢复任务结束的日志间隔，以及用户实际断网时长。
- 检查清单、代理指南与离线工作台加入网页登录分步排查，记录提示原文、首次可见时间和对照结果。个案中的账号处置类型和原因仍为未知。

## v0.4.1（2026-11-23）— 统一三态体检单与工程边界补强

- **合并客户端边界审计与三态安全摘要**：`environment_report.py` 现自动合并 `audit_client_boundary.py`，新增 10 项三态核验摘要（`pass` 已通过 / `gap` 存在缺口 / `unknown` 未知盲区）与三层证据分级（`observed_local` / `static_config` / `external_blind_spot`），强制把外部出口 IP 信誉、运行态 GPU/TPM 健康度与平台地区政策显式标为 `unknown`。
- **一键导出离线可打印 HTML 体检单**：`environment_report.py` 新增 `--html-out`、`--json-out`、`--from-json` 与 `--quiet` 参数，输出零外部 CDN、全量 HTML 转义、支持直接打印存 PDF 的单文件离线体检单（拒绝通过符号链接写入）。
- **本地 MCP 桥接只读盘点**：`audit_client_boundary.py` 新增 `--config-dir` 参数与 `localMcpBridges` 字段，只读统计 Desktop/CLI 本地 MCP Server 配置数量（绝不输出名称、命令、参数或密钥）并在配置存在时提醒复核宿主机跨界元信息。
- **补强文档、清单与交互工作台**：在 `PRIVACY-CHECKLIST.md`、`docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md`、`CLAUDE-PROXY-OPTIMIZATION-GUIDE.md` 与 `docs/index.html` 中增补本地 MCP 桥接自查、出口 IP 历史信誉盲区提示、第 6 条误区（「网络层零泄露 ≠ 虚拟化/运行态无异常」的工程权衡）及对应交互检查项，并修正 UI 中 Unix 体检命令示例。

## v0.4.0（2026-11-23）— MIT 公开开源版

- **正式以 MIT 许可公开发布**：新增根目录 [LICENSE](LICENSE)（Copyright (c) 2026 Celeste）与清晰的 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
- **清理第三方原文镜像并重写干净版综合报告**：彻底移除此前私有备份中包含第三方原文和微信文章的 `research-reports/` 镜像目录，并重建干净的提交历史；将全部跨端客户端边界、独立四层实测数据、五大常见误区纠偏与工具包落地映射整合为一份干净原创报告 [docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md](docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md)。
- **全新离线交互式展示与配置工作台 UI**：新增零外部依赖、可在线（GitHub Pages）亦可本地离线打开的 [docs/index.html](docs/index.html)（含路由生成器、Windows 断网开关与 LAN DNS 规划器、可持久化跨端隐私自检清单、原创实测报告阅读器，以及协作伙伴 **哈基米 (Gemini)** 署名与互动小助手）。
- **项目展示与工程基建对齐**：补齐统一风格的矢量图标（`docs/images/logo.svg`）、架构总览图（`docs/images/architecture-cover.svg`）、哈基米徽章（`docs/images/hajimi-mascot.svg`）、GitHub Actions 跨平台自动测试（`.github/workflows/tests.yml`）与版本发布工作流（`.github/workflows/release.yml`）。
- **公开仓库安全同步闸门**：升级 `tools/auto_update.py`，默认排除本机私有的 `research-reports/` 与镜像目录，并在隐私闸门中新增版权镜像拦截，防止后续每周自动同步误把私人资料推上公开仓库。

## v0.3.8（2026-11-23）— 外部审查修复版

- **修复 Linux 测试失败**：`test_claude_local_data.py` 的 `Path.open` 桩放行 `/proc/mounts` 挂载表读取，消除 Linux 下误报。
- **修复断网开关 DHCP 检测与 PowerShell 5.1 崩溃**：`Manage-WindowsKillSwitch.ps1` 新增 `Get-DhcpEnabledAliases`，所选网卡启用 DHCP 且未指定 `-DhcpServer` 时 `Preview` 发出告警、`Install` 拒绝安装；同时修复不带 `-DhcpServer` 时 `$dhcpAddressInts` 为 `$null` 在 PowerShell 5.1 严格模式触发崩溃的既有缺陷。
- **补全副作用与校验范围说明**：在 `WINDOWS-KILL-SWITCH.md`、`CLAUDE-PROXY-OPTIMIZATION-GUIDE.md`、`PRIVACY-CHECKLIST.md`、`README.md` 与 `mobile/README.md` 中补全路由器 DNS 旁路防护在关代理后的解析副作用，以及静态路由校验的范围边界。

## v0.3.7（2026-11-23）— 脱敏与移动端细节补全

- 清理旧报告中残留的本机路径标识；使 `build_routing.py` 帮助文案中的域名计数动态计算。
- 补充 Android 保活、开机自连、改设置后重启服务、网页认证 Wi-Fi 冲突与应用分身边界说明。

## v0.3.6（2026-11-23）— 全端实测补强

- 将 `CLAUDE_ECOSYSTEM_DOMAINS` 与 `claude-doh-domains.txt` 扩充至 30 项，补齐实测发现的外围与 Artifact 预览域名。
- `audit_client_boundary.py` 新增 5 项 CLI 防后台外联环境变量核查；`Inspect-WindowsFirewall.ps1` 新增 MSIX 显式出站放行规则检测。
- 更新 Android 13 条路由规则与配套离线二维码。

## v0.3.4 ~ v0.3.5（2026-11-22）— 跨平台安全加固基线

- 建立 `Manage-WindowsLanDnsGuard.ps1` 与 `build_lan_dns_guard.py` 物理网卡防路由器 53 端口旁路方案。
- 强化 `config_snapshot.py` 与 `claude_local_data.py` 的本地卷策略、符号链接拒绝、明文密钥拦截与 Windows 私有 NTFS ACL。
