# 第三方参考与许可范围

本仓库按 MIT 许可发布，全文见 [LICENSE](LICENSE)，版权人 Celeste。这份文件说明许可覆盖范围，以及外部参考资料的边界。

## 许可范围

- 根目录的 `LICENSE` 适用于本仓库中由作者与协作 AI 编写、整理的全部原创内容：Python 工具与单元测试脚本、Windows PowerShell 只读体检与防火墙规划/管理脚本、路由模板与移动端配置模板、说明文档、原创综合报告（[docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md](docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md)）、交互式离线展示台（`docs/index.html`、`docs/styles.css`、`docs/app.js`）以及 `docs/images/` 中的矢量图标与示意图。
- **本公开仓库不包含任何第三方文章原文镜像或微信转发原文。** 此前私有备份版中用于个人对照的 `research-reports/sources/` 目录已在公开发布前彻底移除，并在公开前重建了干净的提交历史；所有公开技术背景均以原创语言独立归纳并仅保留可核验的公开链接。

## 只作参考、没有带进来的外部项目与资料

下面列出的项目、数据源和文档仅在说明或脚本注释中作为公开链接引用，本仓库没有拷入它们的源码或原文：

### 1. 上游规则数据与客户端项目

| 项目 / 数据源 | 用途与边界 | 公开链接 |
| :--- | :--- | :--- |
| `Loyalsoldier/v2ray-rules-dat` | `refresh_allowlists.py` 可选拉取国内直连名单与 CIDR 预览（默认仅生成预览、不自动套用，建议固定 `--commit` 与 SHA-256 校验） | https://github.com/Loyalsoldier/v2ray-rules-dat |
| `v2rayN` / `v2rayNG` / `Xray-core` | Windows 与 Android 路由模板及配置快照备份的目标客户端；本仓库不内置客户端二进制或 Xray 核心 | https://github.com/2dust/v2rayN · https://github.com/2dust/v2rayNG |
| `Shadowrocket` | iOS 配置模板的目标客户端，仅提供纯文本配置模板与静态校验脚本 | — |

### 2. 客户端边界与网络行为参考链接（仅作背景索引，无正文拷贝）

原创综合报告 [docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md](docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md) 除本机独立四层实测外，还交叉参考了以下公开社区研究与官方文档（版权与各自许可均归原作者所有）：

- `B1anYu/claude-telemetry-audit`（三端遥测与本地枚举研究）：https://github.com/B1anYu/claude-telemetry-audit
- `benbaobaoshigemi/ImNotDragon`（Web / Android / Persona 网络与风控信号研究）：https://github.com/benbaobaoshigemi/ImNotDragon
- `BYK/loreai`（CLI 协议归因头与 `cch` 校验研究）：https://github.com/BYK/loreai
- `pwguler/pengepul`（CLI 请求头与版本特征分析）：https://github.com/pwguler/pengepul
- `6Kmfi6HP/opencode2api`（CLI 协议行为与版本演进记录）：https://github.com/6Kmfi6HP/opencode2api
- `itwanger/toBeBetterJavaer`（CLI 历史版本格式隐写分析）：https://github.com/itwanger/toBeBetterJavaer
- `aaddrick/claude-desktop-debian`（Desktop `DeviceRegistry` 硬件密钥机制分析）：https://github.com/aaddrick/claude-desktop-debian
- `ttfake92-lab/skills`（本地状态目录与证据边界核查）：https://github.com/ttfake92-lab/skills
- `wquguru/one-exit`（多端关联域名与出口一致性整理）：https://github.com/wquguru/one-exit
- Anthropic 官方公开政策与文档：https://www.anthropic.com/legal/supported-regions · https://code.claude.com/docs/en/cli-reference · https://support.claude.com
- Android VPN / Chrome 本地网络访问 / Proton 邮件追踪保护文档：https://developer.android.com/develop/connectivity/vpn · https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access · https://proton.me/support/email-tracker-protection

> 注：社区第三方研究由各自作者维护，观点与测试版本随时间变化，本仓库不对第三方链接的持续可用性或结论准确性作背书。
