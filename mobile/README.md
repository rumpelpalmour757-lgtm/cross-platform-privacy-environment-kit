# 手机端网络隐私验收

在自己的手机和有权使用的网络上验收。用同一组普通测试网址，在 Wi-Fi 与蜂窝网络下分别记录结果。保留测试时间、连接状态和是否收到响应即可。出口地址如果需要核对，留在本机记录。

## Android

v2rayNG 是使用 Android VPN 接口的客户端之一。优先沿用自己已验证的连接配置，先确认手机状态栏和系统 VPN 设置都显示连接。若系统里未出现该 VPN，检查客户端是否以 VPN 模式启动。桌面端 v2rayN 的规则文件与备份请在各自客户端的支持范围内使用。[v2rayNG 项目](https://github.com/2dust/v2rayNG)

### 随包 Claude 生态规则包（13 条）

> 校验范围说明：这套规则在制作时曾用作者本机的 Xray 核心做过离线语法与地理数据检查，但包内**不带 Xray**。随包的 `validate_android_v2rayng.py` 只做静态结构检查，**不逐条比对** 13 条规则，也不要求有兜底规则，改动过的文件也可能通过。它查的是：至少 8 条规则，每条都已启用，出站是 `proxy`、`direct`、`block` 之一；含 UDP/443 阻断、两个 Anthropic IPv6 前缀的阻断、包含全部 30 项生态条目的代理规则、`160.79.104.0/21` 的代理规则、同时含 `geoip:private` 和 `100.64.0.0/10` 的直连规则；IPv6 阻断、生态条目、IPv4 网段这三条排在第一条国内直连规则（`geosite:cn` 或 `geoip:cn`）之前；直连规则不能不带条件，也不能含 `0.0.0.0/0`、`::/0` 或全端口；最后一条若是全端口规则必须走 `proxy`；不出现已知拼错的域名。字段类型不对、会让脚本出错的（比如 `domain` 写成数字、`outboundTag` 写成数组）报一行错；`domain`、`ip` 写成字符串而不是数组时不一定报错。通过校验不代表在你的手机上实际路由正确；导入后请按下方步骤重连并实测。

本目录提供 `android-v2rayng-claude-routing.json`（剪贴板直导单行版）、`android-v2rayng-claude-routing.pretty.json`（可读版）与扫码直导二维码 `android-v2rayng-claude-routing-qr.png`。13 条规则按顺序是：

| 顺序 | 匹配 | 去向 |
| --- | --- | --- |
| 1 | `udp` 的 `443` 端口（QUIC），不分目的地 | 阻断 |
| 2 | Anthropic IPv6 前缀 `2607:6bc0::/48`、`2607:6bc0:11::/48`（防单 IPv4 出口 502） | 阻断 |
| 3 | 30 项核心与外围生态条目 | 代理 |
| 4 | Anthropic 官方 IPv4 网段 `160.79.104.0/21` | 代理 |
| 5 | `geoip:private` 与 `100.64.0.0/10` | 直连 |
| 6 | `geosite:private` | 直连 |
| 7 | 微信的 3 个域名、`geosite:bilibili`、关键词 `mirrorakam` | 直连 |
| 8 | `geosite:geolocation-!cn`、`googletagmanager.com`、`doubleclick.net` | 代理 |
| 9 | `geosite:google` | 代理 |
| 10 | 35 个国内公共 DNS 服务器地址 | 直连 |
| 11 | 5 个国内公共 DNS 服务域名 | 直连 |
| 12 | `geosite:cn` | 直连 |
| 13 | `geoip:cn` | 直连 |

- 第 3 条的 30 项与桌面版 `claude-doh-domains.txt` 相同（29 条域名后缀加 1 条关键词 `browser-intake`），已修正 `claudemcpcontent.com` 拼写，并补齐 `datadoghq-browser-agent.com`、`hexagon-analytics.com`、`segment.com`、`statsigapi.net`、`claude.site`、`cdnjs.cloudflare.com`、`cdn.jsdelivr.net`。
- 第 7 到 13 条是通用的国内外分流，导入后你原有的分流习惯会跟着变。
- 第 1 条对所有目的地生效：国内直连站点的 HTTP/3 也会被丢弃、回落到 TCP；进了隧道的局域网 UDP/443（个别 NAS 的 HTTP/3、部分 VPN 的 DTLS 通道）同样会被丢弃。
- 规则包**没有兜底规则**。13 条都没命中的流量走哪里，取决于 v2rayNG 自身的默认行为，没有在真机上核对。
- 需要手机上的地理数据文件含这些分类：geosite 的 `private`、`bilibili`、`geolocation-!cn`、`google`、`cn`，geoip 的 `private`、`cn`。
- 局域网直连的写法三端不同：Android 用 `geoip:private` 加 `100.64.0.0/10`，`geoip:private` 实际包含哪些网段取决于手机上的地理数据文件，没有核对；桌面模板列的是 9 个显式网段，不用宽泛的保留地址数据集，免得把虚拟 DNS 用的合成地址段算进直连；iOS 模板的 9 个网段里有 8 个和桌面相同，只差 IPv6 唯一本地地址：桌面写 `fd00::/8`，iOS 写 `fc00::/7`。
- 域名策略：这套规则在哪种域名策略下检查过没有记录，各种策略都没有实机测过。第 2 条按 IP 阻断，排在第 3 条按域名代理之前；如果选的策略在遇到 IP 规则时先解析域名（如 `IPOnDemand`），解析出这两个 IPv6 前缀地址的主机名可能在第 2 条就被阻断，表现为打不开。桌面端文档建议的是 `AsIs`。
- 二维码已经用到版本 39、纠错级别 L，装着单行版的 2776 字节；单个二维码最多装 2953 字节（版本 40、纠错级别 L），规则包再加六七个域名条目就放不进一个码。

> 导入前先备份现有规则：在 `v2rayNG` → 路由设置的右上角菜单里找导出规则集到剪贴板的选项（名称以所装版本为准），把导出的内容粘贴保存到本机文件。导入是替换原有规则还是追加，没有在真机上核对过，请按会被替换来准备。要恢复时，用同一菜单的「从剪贴板导入」导回保存的内容，再在主页面停止并重新启动一次服务。

导入与补强步骤：
1. 打开 `v2rayNG` → 路由设置 → 右上角「从 QRcode 导入规则集」扫描 `android-v2rayng-claude-routing-qr.png`（或复制 `android-v2rayng-claude-routing.json` 选择「从剪贴板导入」）；
2. **导入后手动断开并重新连接 VPN**，确保 Xray 核心加载新规则；
3. 进入 `v2rayNG` → 设置，逐项核对关键 DNS 与运行选项：
   - **启用本地 DNS**：**开启**（必须开启，DNS 请求才会交给 Xray 核心按路由分流，防止境内/海外解析分裂）；
   - **启用虚拟 DNS（FakeDNS）**：保持**关闭**（避免部分应用异常）；
   - **远程 DNS**：改为加密 DoH `https://cloudflare-dns.com/dns-query`（避免沿用明文 `1.1.1.1`）；
   - **境内 DNS**：保持 `223.5.5.5` 或 `119.29.29.29`；
   - **VPN DNS**：保留 `1.1.1.1` 即可（开启本地 DNS 后由核心 DNS 模块接管）；
   - **IPv6 / 优先使用 IPv6**：若节点仅支持 IPv4 出口，保持**关闭**（已由路由规则同步阻断 Anthropic IPv6 防 502）；
   - **设备启动后自动连接**：**开启**（`v2rayNG` → 设置 → 页面底部），手机重启后不用手动再连；
4. 防止系统在后台杀掉 VPN：打开系统设置 → 电池（或「应用管理 → v2rayNG → 耗电」），把 `v2rayNG` 设为**不限制后台 / 允许后台高耗电 / 不优化**（不同机型叫法不同，vivo / iQOO 在「电池 → 后台耗电管理」）。不加白名单时，息屏一段时间后隧道可能被系统回收，期间流量会悄悄走直连。
5. 在桌面可随时离线校验随包规则：
   ```text
   python3 mobile/validate_android_v2rayng.py mobile/android-v2rayng-claude-routing.json
   ```

   Windows 上把 `python3` 换成 `py -3`（python.org 的安装程序默认不把 `python`、`python3` 加进 PATH）。

> 改完 DNS、路由或「启用本地 DNS」后，都要在 `v2rayNG` 主页面**停止再启动**一次服务。只保存设置不会让正在运行的核心重新加载。

### Android 系统防漏开关与架构边界提醒

1. 打开系统设置，搜索「VPN」，点已连接应用旁的设置图标。菜单位置、名称和能使用的开关以机型、系统、VPN 应用和工作资料策略为准。[Android 帮助](https://support.google.com/android/answer/9089766)
2. 如有「始终开启 VPN」，先开启并确认正常连接。如还提供「阻止不使用 VPN 的连接」，先记下原值，再开启并测试。被排除的应用在此模式下可能失去网络。某些应用会明确退出对始终开启的支持。[Android VPN 官方文档](https://developer.android.com/develop/connectivity/vpn)
3. 保持 VPN 开启，用一个已知无法建立代理连接的自有测试节点观察故障行为，再恢复原节点。单独检查隧道实际断开时的结果。如果系统一直自动重连，记录「未观察到隧道断开」。各状态按下方表格记录。
4. 恢复时回到同一 VPN 设置页，把刚才改过的开关恢复成原值，再恢复原节点。若原本使用工作资料 VPN，请由管理者核对策略。
5. **需要网页登录的 Wi-Fi**（酒店、商场、机场等）：开启「阻止不使用 VPN 的连接」后，弹出的认证页面可能打不开，Wi-Fi 一直显示「无法上网」。处理方法：先临时关闭该开关，完成网页认证后，再连上 VPN 并把开关打开。
6. **应用分身 / 双开空间**：vivo「应用分身」、小米「应用双开」等分身里的 App 一般也走同一个 VPN（可在系统 VPN 详情或 `v2rayNG` 分应用设置里核对），但分身和主应用共用同一台手机的物理网卡、SIM 卡和系统时区。所以用分身装 Claude **不算一个独立环境**，本节下方的架构边界同样适用。

> **重要架构边界（Android vs iOS）**：根据公开社区研究（`B1anYu/claude-telemetry-audit` 与 `benbaobaoshigemi/ImNotDragon`，公开链接见 [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md)），Android 原生客户端可在应用层直接读取不可重置的 `ANDROID_ID`、通过 `NetworkInterface` 枚举物理网卡上的公网 IPv6 地址（即使 VPN 已连接），以及读取 SIM 卡 MCC/MNC 与 Play Integrity 状态。**任何 VPN 或代理客户端都只能控制网络层路由与 DNS，无法拦截应用层本地系统 API 读取。** 因此，高敏感账户操作仍建议固定在电脑端隔离浏览器环境中进行，不要依赖 Android 原生客户端。

## iPhone 和 iPad

`shadowrocket-local-proxy.conf` 是修复了原生 IPv6 绕过问题的全代理模板：只有本地地址直连，公网 IPv6 地址在隧道内拒绝，其余都走 `FINAL,PROXY`。它没有国内直连分流，不含 30 项生态条目，也没有 UDP/443 阻断（这些条目因为 `FINAL,PROXY` 同样走代理）。
- 在 `[General]` 中启用 **`ipv6 = true`** 与 **`hijack-dns = *:53`**，强制虚拟网卡（`utun`）接管手机 4G/5G 蜂窝网络与双栈 Wi-Fi 的 IPv6 路由及 53 端口明文 DNS，防止 iOS 因 `ipv6 = false` 将原生 IPv6 流量直接从物理网卡裸连发出。
- 将回环、`.local` 及私有/链路本地 IPv4 与 IPv6 网段设为直连，在 `FINAL,PROXY` 之前通过 `IP-CIDR6,::/0,REJECT,no-resolve` 在隧道内阻断直接公网 IPv6 连接（域名访问仍经 `FINAL,PROXY` 转发，兼容仅支持 IPv4 出站的节点；若节点已验证支持 IPv6 出站，可按需改为 `PROXY`）。

1. 在 Shadowrocket 里记下当前配置文件、全局路由模式和所选节点，保留原配置作为回滚选项。
2. 导入 `shadowrocket-local-proxy.conf`（建议通过本地 AirDrop 或「文件」App 本机存储导入，避免将含自定义节点的配置长期留在云盘）。在界面里选中并启用导入的配置，将「全局路由」设为「配置」，再选择自己有权使用的已验证节点，并在设置中配置受信任的加密 DNS（DoH/DoT）。[Shadowrocket App Store 页面](https://apps.apple.com/us/app/shadowrocket/id932747118)
3. 分别在 Wi-Fi 与 4G/5G 蜂窝网络下验证局域网、IPv4 与 IPv6 表现。先用自己的局域网测试地址看能否连通并查看客户端规则记录，再用测试站点核对公网请求是否全部进入代理且无真实运营商 IPv6 泄漏。
4. 将「代理节点故障，隧道仍开」和「隧道已关」当成两次独立实验。非设备监督管理（MDM）下的普通 iOS VPN 断开后系统不会自动断网，只有监督模式下的 Apple IKEv2「始终开启 VPN」支持系统级强制阻断。[Apple IKEv2 部署设置](https://support.apple.com/guide/deployment/ikev2-settings-dep4ce9487d/web)
5. 回滚时重新选择原有配置、路由模式和节点，再验证正常连通性。

可在桌面离线检查随包模板：

```text
python3 mobile/validate_shadowrocket.py mobile/shadowrocket-local-proxy.conf
```

Windows 上同样把 `python3` 换成 `py -3`。

校验要求开启 `ipv6 = true` 与 `hijack-dns = *:53`（拒绝会导致原生 IPv6 绕过隧道的 `ipv6 = false`），核对全部 11 条本地直连例外（2 条域名、9 条 IPv4/IPv6 网段）、公网 IPv6 兜底处置以及末条 `FINAL,PROXY` 规则。它只认随包模板的写法：`[General]` 里只接受这两行，加了 `dns-server` 之类的其他设置会报 `unsupported [General] setting`；加密 DNS 不在校验范围内，要在 App 里另行确认。

## 实机记录表

| 状态 | 在 Wi-Fi 上记录 | 在蜂窝网络（4G/5G）上记录 |
| --- | --- | --- |
| 原配置或回滚后 | 公共测试地址是否有响应 | 公共测试地址是否有响应 |
| VPN 正常，节点可用 | 公共请求结果、IPv4/IPv6 是否均未漏真机 IP | 公共请求结果、IPv4/IPv6 是否均未漏真机 IP |
| VPN 仍在，节点故障 | 公共请求是否失败和实际系统状态 | 公共请求是否失败和实际系统状态 |
| VPN 确实断开 | 公共请求是否失败和实际系统状态 | 公共请求是否失败和实际系统状态 |
| VPN 正常，使用自有局域网地址 | 能否连通及直连规则命中 | 有可用的自有局域网目标时再测 |

若预期断网时仍收到公共站点响应，该次测试失败。公共请求失败可能另由 DNS、超时或站点故障造成，可用恢复后的正常基线和客户端记录进一步核对。
