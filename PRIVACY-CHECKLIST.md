# 浏览器、邮箱和 Claude 账号隐私检查

这份清单适用于日常使用自己的设备和账号。操作应通过当前客户端界面或官方支持渠道完成。

| 检查项 | 怎么核对 | 结果的范围 |
| --- | --- | --- |
| 网页定位 | 在 Chrome 或 Edge 的站点资料里检查「位置」，平时按需求选询问或阻止 | 控制浏览器定位权限。服务仍可能将连接 IP 用于粗略的地区判断。[Chrome 站点权限](https://support.google.com/chrome/answer/114662) · [Claude 位置说明](https://privacy.claude.com/en/articles/11186740-does-claude-use-my-location) |
| 网页访问局域网和本机服务 | 查看站点的本地网络和本机设备访问权限。对不需要访问打印机、路由器或开发服务的网站可以关掉 | 适用于浏览器内的本地连接。原生应用的网卡枚举由操作系统治理。[Chrome 本地网络访问](https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access) |
| 浏览器数据同步 | 检查浏览器或配置文件的同步开关、同步项目和可访问该配置的人 | 以实际设置为准。部分浏览器的团队同步会将选定数据存到云端。[AdsPower 数据同步](https://help.adspower.com/docs/global_settings) |
| 邮件远程图片 | 核对邮件客户端的加载与跟踪保护选项 | 邮件远程资源和点击登录链接是不同的连接。[Proton 跟踪保护](https://proton.me/support/email-tracker-protection) |
| 路由器 DNS 旁路防护 | Windows 分流模式运行 `Manage-WindowsLanDnsGuard.ps1 -Action Status -IncludeAllPhysicalAdapters` 确认物理网卡端口 53 阻断规则生效 | 防止程序绕过系统 DNS 直查路由器 53 端口；不影响路由器后台管理、DHCP、局域网共享与 TUN 网卡。副作用：关掉代理/TUN 后，DNS 指向路由器或内网私网 DNS 的网络会全部解析失败 |
| 断网开关 DHCP 例外 | 网卡用 DHCP 时，`Manage-WindowsKillSwitch.ps1` 已带 `-DhcpServer` | 不带时续租被拦、可能突然断网；v0.3.8 起 `Install` 会拒绝安装 |
| 宿主机与隔离浏览器边界 | 运行 `py -3 .\environment_report.py --html-out .\env-health.html` 或 `py -3 .\audit_client_boundary.py` 核对宿主机时区/语言、本地客户端足迹及三态体检摘要 | 宿主机原生客户端直接读取系统时区与语言，且桌面端未登录即会发起冷启动外联；不要与独立隔离浏览器环境混用。导出 HTML 支持离线双击查看与打印存 PDF |
| CLI 防后台外联开关 | 运行 `py -3 .\audit_client_boundary.py` 查看 `cliAntiTelemetryFlags`（`DISABLE_TELEMETRY=1`、`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` 等 5 项） | 实测未开启时 CLI 冷启动仍会发起 `api.anthropic.com:443` 外联并落盘遥测，开启后可归零 |
| 本地 MCP 与宿主机桥接自查 | 运行 `py -3 .\environment_report.py --html-out .\env-health.html` 或 `py -3 .\audit_client_boundary.py` 核对 `localMcpBridges` | 本地 MCP 服务运行在宿主机语境下（只读统计配置数量，不输出名称与命令），可能把宿主机系统时钟、时区或本地文件元信息桥接入会话；需要严格隔离时应逐项复核已启用的桥接插件 |
| 出口 IP 历史信誉盲区 | 核对 `environment_report.py` 三态摘要中的 `exit_ip_reputation`（固定标为 `unknown`） | 离线本机脚本不查询外部 IP 信誉/代理池库（如 Spur、IPQS、MaxMind），也无法核实共享出口是否存在前任「坏邻居」记录；不要把“本地零泄露通过”等同于“出口信誉干净” |
| 网络层零泄露 ≠ 运行环境无异常 | 若尝试使用独立虚拟机运行桌面客户端，核对图形加速（GPU/WebGL）、TPM 可用性与冷启动频率 | 即使网络边界做到严格 fail-closed 零泄露，无 GPU / 无 TPM 的残缺虚拟机仍可能产生持续 WebGL 拉黑报错、`no_tpm` 降级，以及为适配字体/输入法/剪贴板引入的额外侵入式桥接副作用；短时间反复冷启动也会放大客户端启动遥测 |
| 移动端原生 App 限制 | 核对 [mobile/README.md](mobile/README.md) 中的 Android 与 iOS 架构差异 | 代理/VPN 仅管网络层；Android 原生 App 可在应用层直接读取设备标识与物理网卡 IPv6，高敏感场景建议固定在电脑端隔离浏览器 |
| Android VPN 保活与防漏 | `v2rayNG` 已加入电池「不限制后台」、开启「设备启动后自动连接」、系统「始终开启 VPN」与「阻止不使用 VPN 的连接」；改设置后已停止再启动服务 | 网页认证 Wi-Fi 需临时关闭阻断开关；应用分身与主应用共用物理网卡、SIM 与时区，不算独立环境 |
| 防火墙第三方与 MSIX 放行复核 | 运行 `Inspect-WindowsFirewall.ps1` 查看 `EnabledOutboundAllowBreakdown` 与 `MsixClaudeOutboundAllowCount` | 确认无闲置第三方全地址直连放行，且未残留官方桌面端 MSIX 自动写入的 `Claude.exe`/`cowork-svc.exe` TCP 出站放行规则（该类显式放行会在断 TUN 时穿透默认出站阻断） |
| 闲置物理网卡 IPv6 绑定 | Windows 检查所有物理网卡（含当前断开的以太网）的 IPv6 绑定状态 | 避免日后切换有线网线或热点时从物理网卡直接走原生 IPv6 绕行 |
| 模型改进隐私选项 | 按实际偏好从账户隐私界面查看或调整 | Anthropic 说明关闭模型训练选项后，新的聊天和编码会话不会用于后续训练。[模型改进选项](https://privacy.claude.com/en/articles/12109829-how-do-i-change-my-model-improvement-privacy-settings) |
| 登录状态和错误 | 用已安装的官方客户端查看状态。CLI 可运行 `claude auth status --text`，对外汇报只记录是否登录和错误类别 | 不转发邮箱、令牌、验证码或完整配置。[CLI 参考](https://code.claude.com/docs/en/cli-reference) |
| 官方申诉或退款 | 分别使用 Anthropic 申诉、Apple 或购买渠道的退款页面，说明真实情况 | 账号处置与付款渠道分别调查，需等待正式回复。[Claude 申诉](https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals) · [Apple 退款](https://support.apple.com/en-us/118223) |

本地网络诊断可验证指定连接和特定故障条件。是否符合 Anthropic 的服务范围按官方地区政策判断，包含用户实际所在地。没有公开依据表明指纹测试评分能预测账号处置。包里的脚本不要求你提供账号凭据。[Anthropic 地区政策](https://www.anthropic.com/legal/supported-regions)

更多基于逆向研究报告的代理层优化与边界说明，见 [CLAUDE-PROXY-OPTIMIZATION-GUIDE.md](CLAUDE-PROXY-OPTIMIZATION-GUIDE.md)。
