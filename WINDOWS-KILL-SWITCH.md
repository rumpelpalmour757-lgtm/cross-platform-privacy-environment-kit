# Windows 断网开关安装与实机验收

本工具在指定物理网卡上创建持久化的 Windows Defender 防火墙出站阻断规则。代理客户端或 TUN 退出后，规则仍由 Windows 防火墙服务执行。

> **安全加固说明**：
> - `Manage-WindowsKillSwitch.ps1` 现已完全采用原生 PowerShell 计算规则，**不再在管理员权限下调用外部 `py.exe` 或外部 Python 脚本**。`Install` 前检查脚本所在目录和脚本文件本身：普通共享用户组（Everyone、Users、Authenticated Users、Guests、INTERACTIVE）有改动类权限（写入、追加、删除、改权限、取得所有权）就拒绝，只读和执行不算。所以放在个人主目录下的子文件夹（例如 `%USERPROFILE%\cppek-kit`）或 `C:\Program Files` 下的子文件夹都可以；放在 `D:\` 这类数据盘根目录下新建的文件夹通常不行（默认给 Authenticated Users 修改权限）。这几种位置的结果是按 Windows 的默认权限推断的，没有在真机上逐一试过。被拒时报错会写出是哪个路径、哪个用户组、什么权限。上级目录里有符号链接、目录联接或被 OneDrive 接管的文件夹（带重解析点属性）时，报错会写出是哪一级目录；FAT32、exFAT（常见于 U 盘）这类没有文件权限的卷，`Install` 也拒绝。LAN DNS Guard 的检查和这里相同。
> - `Remove` 对上面这些位置问题只在窗口里打印 `WARNING:`，照样删除规则：脚本被改过的话这项检查本身也已经不在了，拦下 `Remove` 只会让网络一直断着。日志目录不可用时，`Remove` 打印一行警告后不写日志继续；`Install` 仍然要求日志写得进去。
> - 默认要求覆盖**所有当前处于连接（Up）状态的物理网卡**（推荐直接使用 `-IncludeAllPhysicalAdapters` 把机器上所有有线/无线物理网卡一次全部纳入），防止漏掉第二张活动网卡。新增 USB 共享网络或扩展坞网卡后，要先 `-Action Remove` 再用新参数 `-Action Install`，见下文[更新保护范围](#更新保护范围新网卡新上游)。
> - **虚拟网卡选不进保护范围，不保证覆盖。** `-IncludeAllPhysicalAdapters` 只取物理网卡（`HardwareInterface` 为 `True` 的网卡，脚本里挑网卡、核对网卡、查覆盖都按这一个口径）；用 `-InterfaceAlias` 指定虚拟网卡（例如 Hyper-V 虚拟交换机的 `vEthernet` 网卡）会报 `The selected physical adapter could not be identified`。处于连接状态的非隧道虚拟网卡会列在 `Install`、`Status` 输出的 `Prerequisites.ActiveVirtualNonTunnelAdapters` 里，同时在窗口里打印一行 `WARNING: Connected virtual adapters are outside this guard: …`；`ConfigurationMatched` 照样是 `true`，这一项不为空时不要当作已受保护。建了 Hyper-V 外部虚拟交换机以后主机流量会改从 `vEthernet` 网卡出去，这时只绑物理网卡名的规则还拦不拦得住，没有实测；WSL2、虚拟机 NAT、移动热点共享这类由主机转发的流量是否经过这些规则，也没有实测。
> - 对例外 IP（上游地址与可选 DHCP 地址）已同步封堵 ICMPv4、IGMP、IP-in-IP、IPv6-in-IPv4（6to4/ISATAP）、GRE、ESP、AH 与 SCTP 这 8 种协议；其余协议号发往这些地址的流量没有封。
> - 安装日志 `CPPEK-KillSwitch-*.jsonl`（默认写在 `%LOCALAPPDATA%`）自动设置私有 NTFS 权限，并**已脱敏移除真实代理上游 IP、内网网关 IP 与网卡名**。`Install`、`Status`、`Remove` 在窗口里打印的结果、警告和报错**没有脱敏**：含网卡名、日志和脚本目录的完整路径（路径里有 Windows 用户名）和开机时间，贴到公开的问题反馈前请自己遮掉。
> - 断网开关**不导出 `.wfw` 防火墙备份**。它的规则都在自己的规则组 `CPPEK-KillSwitch-v1` 里，回退办法是 `-Action Remove`，脚本跑不起来时用下文的[手工撤销命令](#脚本跑不起来时的手工撤销)。

## 装之前要知道的副作用

装好以后，所选物理网卡上除了上游地址的那一个端口（和可选的 DHCP 续租）以外，出站一律被拦：

- 所选网卡上的 IPv6 出站全部阻断；IPv4 只放行指定上游的单一 TCP/UDP 端口。
- 局域网里的打印机、NAS、路由器管理页都连不上（它们也是从物理网卡出去的私网地址）。
- 直连分流（如 `geosite:cn` / `geoip:cn` 直连）会被拦。**启用断网保护时，客户端应配合使用全局代理路由，不要混用国内直连分流**：建议导入随包的 [routing-claude-global.json](routing-claude-global.json)（全公网代理，30 项生态条目置顶，与 README 推荐的是同一份）；不需要生态条目置顶时，可以用 `py -3 .\build_routing.py generate .\routing-global.json --global-proxy` 生成最简的全局代理规则。
- 从物理网卡发出的 DNS 查询也被拦：客户端里的节点如果写的是域名，客户端解析不了节点地址就连不上。上游要填本机代理直接拨接的固定 IPv4。
- 服务商换了节点 IP 以后，新地址不在例外里，会一直断网，直到先 `Remove` 再用新地址 `Install`。
- 需要网页登录的 Wi-Fi（酒店、商场、机场等）过不了认证页：先 `Remove`，认证完再装。
- 恢复办法：`-Action Remove`；脚本跑不起来时用下文的手工撤销命令。

## 预览、安装与卸载

在个人主目录下的解压目录中打开 Windows PowerShell 5.1。安装、卸载使用本机管理员 PowerShell。上游是**本机代理直接拨接的固定独享 IPv4 地址**（避免使用与日常网页共用的共享 CDN IP，否则代理退出后访问同 IP 站点仍会匹配端口例外）。

本节在同一个窗口里直接调用脚本（`& .\Manage-WindowsKillSwitch.ps1`），Windows 默认的执行策略会拒绝运行脚本。每打开一个新窗口（包括后面的管理员窗口），先执行一次：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

这一行只对当前窗口生效，关掉窗口就失效，不改系统设置。`-Force` 不能省：不加的话，Windows PowerShell 5.1 会先问一句是否更改执行策略，默认答案是“否”，直接按回车或者把下一行一起粘贴进去，策略都不会改，后面的 `& .\…` 照样被拒。

```powershell
Get-NetAdapter -IncludeHidden | Where-Object HardwareInterface | Select-Object Name, ifIndex, Status

$settings = @{
    IncludeAllPhysicalAdapters = $true
    UpstreamAddress            = '<固定上游 IPv4>'
    UpstreamPort               = 443
    UpstreamProtocol           = 'TCP'
}
& .\Manage-WindowsKillSwitch.ps1 -Action Preview @settings
```

- **电脑通过 DHCP 自动获取 IP 时（家用路由器、热点基本都是），必须加 DHCP 例外**：在预览前加入 `$settings['DhcpServer'] = '<DHCP 服务器的私有 IPv4>'`，仅放行本机 68 端口至该地址及广播地址 67 端口的 UDP 续租包（只要给了任意一个 `-DhcpServer`，发往广播地址 `255.255.255.255` 的续租就会放行）。不加的话续租会被拦，租约到期后可能突然断网。DHCP 服务器地址可用 `Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object DHCPEnabled | Select-Object Description, DHCPServer` 或 `ipconfig /all` 查到。从 v0.3.8 起，检测到所选网卡启用 DHCP 却没给 `DhcpServer` 时，`Preview` 会提示，`Install` 会直接拒绝安装，报错里列出是哪几张网卡。检测看的是所有选中的网卡，包括没插线的网口：平时用静态 IP、但没插线的网口默认开着 DHCP 时，也会被要求给 `-DhcpServer`。读不到 IPv4 设置的网卡（被禁用的网卡、没有绑定 IPv4 的网卡）按“可能开着 DHCP”处理，同样要求 `-DhcpServer`：以后启用它时续租会被拦。不想给的话，先启用它再 `Preview` 看一次，或者改用 `-InterfaceAlias` 不选它。
- `-DhcpServer` 只接受 RFC 1918 私网地址（`10.x`、`172.16-31.x`、`192.168.x`）。DHCP 服务器是公网地址或 `100.64.0.0/10` 地址的网络（部分校园网、光猫桥接）目前装不了。
- 代理跑在路由器或旁路由上、上游地址正好也是 DHCP 服务器时，脚本报 `The upstream and a DHCP server cannot share an address.`（报错后半句会提示改用静态 IP），这种拓扑目前不支持：给网卡设静态 IP 后，不带 `-DhcpServer` 安装。
- 规则按网卡名绑定。之后新插的 USB 网卡、新建的热点网卡不在保护范围内，见下文[更新保护范围](#更新保护范围新网卡新上游)。

确认预览后，在管理员 PowerShell（先执行上面那行 `Set-ExecutionPolicy`）运行安装：

```powershell
& .\Manage-WindowsKillSwitch.ps1 -Action Install @settings
& .\Manage-WindowsKillSwitch.ps1 -Action Status @settings
```

`Status` 不匹配时以退出码 2 结束；`ConfigurationMatched` 为 `true` 只说明规则和计划一致，`Prerequisites.AllActivePhysicalCovered`、`Prerequisites.ActiveVirtualNonTunnelAdapters` 也要看一眼。`WARNING:` 开头的提示打印在标准错误里，不混进 JSON。

需要恢复连接时，在管理员窗口运行离线卸载。下面的写法不依赖当前窗口的执行策略设置，新开的管理员窗口里可以直接用：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsKillSwitch.ps1 -Action Remove
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsKillSwitch.ps1 -Action Status
```

已经执行过 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` 的窗口里，也可以写成 `& .\Manage-WindowsKillSwitch.ps1 -Action Remove`。用 `-File` 调用时，多个网卡名不能用逗号写成数组，所以预览和安装请用上面 `& .\…` 加 `@settings` 的写法；`Remove` 不需要网卡参数，不受影响。

`Remove` 只删名字、规则组、描述三项都和脚本一致的规则，删完再查一遍同组和同名的规则：

- 输出 `"Status": "removed"`、退出码 0：本工具包的规则删干净了，同组里也没有别的规则。
- 输出 `"Status": "removed-other-rules-remain"`、退出码 2：本工具包的规则删了，但同组或同名里还剩 `RemainingRules` 列出的规则（比如有人在 `wf.msc` 里改过描述，或者以后版本用同一规则组建的规则），它们可能仍在拦网络，处理办法见下文[Remove 报告还剩规则时](#remove-报告还剩规则时)。
- 报错 `Some rules created by this kit remain visible after Remove`：删除没有生效，在本机管理员窗口再运行一次 `Remove`，仍不行就用下面的手工撤销命令。

`Remove` 的位置检查只打印警告，所以即使工具包放在了 `Install` 不接受的位置（例如装完以后才挪进 OneDrive 文件夹），`Remove` 照样能用。

### 脚本跑不起来时的手工撤销

工具目录无法访问，或者脚本因为执行策略、目录检查跑不起来时，可从本机管理员 PowerShell 用系统命令撤销。下面是在窗口里直接输入的命令，不是脚本文件，不受执行策略限制；执行策略由组策略下发、`-ExecutionPolicy Bypass` 也被拒的机器上，只能用这一段：

```powershell
$group = 'CPPEK-KillSwitch-v1'
$names = @(
    'IPv4OtherAddresses', 'IPv6', 'UpstreamOtherTransport', 'UpstreamOtherPorts',
    'ExceptionProtoICMPv4', 'ExceptionProtoIGMP', 'ExceptionProtoIPv4Encap', 'ExceptionProtoIPv6Encap',
    'ExceptionProtoGRE', 'ExceptionProtoESP', 'ExceptionProtoAH', 'ExceptionProtoSCTP',
    'DhcpTcp', 'DhcpOtherRemotePorts', 'DhcpOtherLocalPorts'
) | ForEach-Object { "$group-$_" }
Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {
    $_.Name -cin $names -and $_.Group -ceq $group -and
        $_.Description -ceq 'Cross-platform privacy environment kit: managed uplink guard v1'
} | ForEach-Object { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $_.Name }
```

这段命令和 `Remove` 用的是同一组过滤条件（规则名、规则组、描述三项都对上才删）。删完仍然断网时，按下一节查同组里剩下的规则。

### Remove 报告还剩规则时

`Remove` 输出 `removed-other-rules-remain`，或者手工撤销以后仍然断网，用下面三种办法之一看同组和同前缀还剩什么：

- 运行 `-Action Status`（不带其他参数），看输出里的 `ForeignOrUnexpectedRules`；
- 打开 `wf.msc` → 出站规则 → 右侧“按组筛选”，选 `CPPEK-KillSwitch-v1`；
- 在管理员 PowerShell 里列出来：

  ```powershell
  $group = 'CPPEK-KillSwitch-v1'
  Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {
      $_.Group -eq $group -or $_.Name -like "$group-*"
  } | Select-Object Name, DisplayName, Enabled, Action, Description
  ```

列出来的确实是本工具包建的规则（名字以 `CPPEK-KillSwitch-v1-` 开头）时，在管理员窗口逐个删除：`Remove-NetFirewallRule -PolicyStore PersistentStore -Name '<规则名>'`。`Remove` 不替你删这些规则，因为它们不是这个脚本按原样建的，可能是别的工具或你自己改过的。

## 更新保护范围（新网卡、新上游）

新插的 USB 网卡、新建的热点网卡不在保护范围内；换了代理上游的 IP、端口或协议，或者换了 DHCP 服务器，旧规则也不再对得上。直接重跑 `Install` 会被拒，什么都不改：已有规则和新计划不一致时，脚本报 `The managed namespace already contains a different, incomplete, or foreign policy. Nothing was changed. …`（后半句提示先 `Remove`）；沿用旧的网卡名重跑时，会先因为有没覆盖的活动物理网卡被拒。用同样的参数重跑 `Install` 时输出 `already-installed`，不改规则。请按这个顺序：

1. 先 `-Action Remove` 删掉旧规则。
2. 再用新参数 `-Action Preview` 核对，然后 `-Action Install`，最后 `-Action Status`。

**两步之间断网开关不起作用**：这段时间里代理一断，流量会直接从物理网卡出去。建议先断开新网卡，或者先关掉不想直连的程序，再做这两步。`Install` 做到一半按了 Ctrl+C 时，已经建好的禁用规则可能留下，之后再装也会报上面那句，同样先 `Remove` 再 `Install`。

## 参数

| 参数 | 用在哪个脚本 | 作用 |
| --- | --- | --- |
| `-Action` | 两个都有 | `Preview`、`Install`、`Status`、`Remove` |
| `-InterfaceAlias` | 两个都有 | 指定物理网卡名，可以给多个。和 Python 规划器同一套规则：不能有通配符、引号、反斜杠和不可见字符（不间断空格、零宽字符等），不分大小写重复也算重复 |
| `-IncludeAllPhysicalAdapters` | 两个都有 | 自动纳入全部物理网卡。断网开关可以和 `-InterfaceAlias` 一起给（两者合并）；LAN DNS Guard 两个一起给会报错 |
| `-AllowUncoveredPhysicalAdapters` | 两个都有 | 允许有处于连接状态的物理网卡不在保护范围内。带上以后，没覆盖的网卡**不受保护**，`Status` 的 `ConfigurationMatched`（断网开关）或 `MatchedPlan`（LAN DNS Guard）照样可能是 `true`；要看 `AllActivePhysicalCovered`（断网开关在 `Prerequisites` 下面）才知道有网卡没覆盖 |
| `-UpstreamAddress`、`-UpstreamPort`、`-UpstreamProtocol` | 断网开关 | 上游的字面 IPv4、端口、`TCP` 或 `UDP`（默认 `TCP`） |
| `-DhcpServer` | 断网开关 | DHCP 服务器的 RFC 1918 私网 IPv4，可以给多个 |
| `-LogDirectory` | 两个都有 | 日志（LAN DNS Guard 还有 `.wfw` 备份）写在哪里，默认 `%LOCALAPPDATA%`。要给本机磁盘上已经存在、上级目录没有重定向的目录，两个脚本都要求写绝对路径；默认目录过不了这项检查时，用它换一个本机目录。`Remove` 遇到日志目录不可用时不写日志继续 |

两个脚本的 `Status` 带了计划参数（网卡；断网开关还有上游、DHCP），规则和计划对不上时都以退出码 2 结束（LAN DNS Guard 看 `MatchedPlan`，断网开关看 `ConfigurationMatched`）；不带参数时只列出现状，退出码 0。两个脚本的 `Remove` 还剩同组的其他规则时退出码也是 2。

## 断线演练：Test-ProxyState.ps1

这个脚本用普通用户（不要用管理员）运行，不改网络，只用系统自带的 `curl.exe` 向一个网址发一次 HTTPS `HEAD` 请求，看连没连上，不报告出口 IP。默认探测地址是 `https://example.com/`，会真的向这个站点发请求；要换成自己的站点用 `-ProbeUrl`。`curl` 不走系统代理（`--noproxy "*"`），流量走哪里只取决于系统路由。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-ProxyState.ps1 -Stage normal -AsJson
```

| `-Stage` | 什么时候运行 | 期望 | 预检 |
| --- | --- | --- | --- |
| `normal` | 代理和 TUN 都正常时 | 能拿到 HTTPS 响应 | 隧道网卡上有要测的那个地址族的默认路由才发包 |
| `upstream-unreachable` | 让上游连不上时（例如在客户端里把节点切到一个连不上的地址） | 主探测连不上；另给了 `-DirectUrl`（你在客户端里设为直连的站点）时，这个地址应能响应 | 同上 |
| `tun-down` | 关掉 TUN 以后 | 连不上 | 不做预检 |
| `client-down` | 退出代理客户端以后 | 连不上 | 不做预检 |

- `tun-down`、`client-down` 不做预检：断网开关没装或没生效时，请求会从物理网卡直连到探测站点，对方能看到你的真实 IP。用自己控制的站点做 `-ProbeUrl` 更稳妥。
- 没检测到 TUN 默认路由时，`normal`、`upstream-unreachable` 默认拒绝发包；`-AllowDirectWithoutTun` 跳过这项检查，等于有意用真实 IP 直连，只在明白后果时用。
- 预检按地址族分开看。`-AddressFamily` 默认是 `auto`：在 `normal`、`upstream-unreachable` 阶段，只测隧道网卡上有默认路由的那几个地址族。TUN 只接管 IPv4 时只发 IPv4 请求（`curl --ipv4`），物理网卡上的原生 IPv6 路由碰不到这次探测；IPv4、IPv6 都接管时两个都不限定。输出里的 `TunnelRouteFamilies` 是检测到的地址族，`ProbedAddressFamily` 是这次实际测的。`tun-down`、`client-down` 阶段不做预检，`auto` 不限定地址族，两种直连都算进结果。显式给 `-AddressFamily ipv4` 或 `ipv6` 时只测这一个，隧道没有它的默认路由就拒绝。
- 预检只看隧道网卡上有没有默认路由（`0.0.0.0/0`、`0.0.0.0/1`、`128.0.0.0/1`，IPv6 的 `::/0`、`::/1`、`8000::/1`、`2000::/3`），不比较路由的跃点数，也不看别的网卡上有没有更具体的路由。
- 隧道网卡按名字认（`tun`、`wintun`、`wireguard`、`tailscale`、`sing-box`、`mihomo`、`clash` 等）。客户端的虚拟网卡叫别的名字时，`normal` 会因为“没检测到隧道”被拒；这时用 `-TunnelInterfaceAlias '<网卡名>'` 指明哪张是隧道网卡（`Get-NetAdapter -IncludeHidden` 里的 `Name`），不要用 `-AllowDirectWithoutTun` 代替。
- 怎么读结果：每个探测的 `Verdict` 是 `observed`（符合预期）、`not-observed`（期望能连上却没连上）、`unexpected-connectivity`（期望断开却连上了，可能回落了直连）或 `inconclusive`。总的 `ObservationsMatchStage` 为 `true` 才算这一阶段符合预期。
- 断网开关正常工作时，`tun-down`、`client-down` 常见的结果是 `inconclusive`、`Observation` 为 `name-resolution-failed`（curl 退出码 6）：断网开关把物理网卡上发往任何地址的 53 端口也拦了，系统解析不了探测站点的域名，这次没测到连接这一层。想测到连接层，先在隧道正常时跑一次 `normal`，让域名进系统 DNS 缓存（输出里的 `DnsCachedBeforeProbe` 会是 `true`），再马上做断线阶段；缓存过期后又会回到 `inconclusive`。

## 实机验收与 5157 阻断事件关联

临时开启筛选平台连接失败审计（测完按原状恢复）：

```powershell
$subcategory = '{0CCE9226-69AE-11D9-BED3-505054503030}'
auditpol.exe /get "/subcategory:$subcategory"
auditpol.exe /set "/subcategory:$subcategory" /failure:enable
```

探测前先退出代理客户端或关掉 TUN，用 `Get-NetRoute -DestinationPrefix 0.0.0.0/0` 确认默认路由回到了物理网卡。TUN 还开着时，连接从虚拟网卡出去，物理网卡上的阻断规则碰不到：curl 会正常返回，安全日志里也没有对应的 5157。测完再恢复客户端。

在普通用户 PowerShell 固定源端口发起单次直连探测：

```powershell
$testName = '<自有 HTTPS 测试站点的证书域名>'
$testIp = '<该站点的固定 IPv4>'
$sourcePort = 49231
$since = Get-Date
$since.ToUniversalTime().ToString('o')
& "$env:SystemRoot\System32\curl.exe" -q --noproxy '*' --ipv4 --head --connect-timeout 5 --max-time 10 --local-port $sourcePort --resolve "${testName}:443:${testIp}" "https://$testName/"
$LASTEXITCODE
[DateTime]::UtcNow.ToString('o')
```

在管理员窗口关联同一次探测。默认必须给 `-SourcePort`（和 curl 的 `--local-port` 一致），防止误关联窗口内其他阻断记录；也可以显式加 `-AllowAnySourcePort` 免填，但这时窗口内别的阻断记录可能被算进来：

```powershell
$since = [DateTimeOffset]::Parse('<上一条探测输出的 UTC 时间>').LocalDateTime
$until = [DateTimeOffset]::Parse('<同一次探测结束的 UTC 时间>').LocalDateTime
& .\Get-WindowsKillSwitchEvidence.ps1 -Since $since -Until $until -DestinationAddress '<同一测试 IP>' -DestinationPort 443 -Protocol TCP -ApplicationName 'curl.exe' -SourcePort 49231
```

预期结果：curl 的 `$LASTEXITCODE` 不是 0（通常是 7 或 28），关联脚本输出的 `EvidenceStatus` 是 `attributed-block-observed`。得到 `inconclusive` 时，先核对 TUN 是否真的关了、时间窗、源端口和测试 IP。

若测试前失败审计原为关闭，验收后恢复关闭：

```powershell
auditpol.exe /set "/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}" /failure:disable
```

## 补充：保留国内直连分流时的「物理网卡防路由器 DNS 旁路」

如果你当前使用国内直连分流（未开启上文的全量断网开关），仍建议安装独立的轻量级物理网卡防 DNS 旁路规则 `Manage-WindowsLanDnsGuard.ps1`（规则组 `CPPEK-LanDnsGuard-v1`，仅阻断物理网卡发往 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`100.64.0.0/10`、`fc00::/7`、`fe80::/10` 的 TCP/UDP 53；不含 IPv4 链路本地 `169.254.0.0/16`）。放置位置的要求和断网开关相同，见文首。

```powershell
# 1. 普通用户预览规则计划（不改动系统）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Preview -IncludeAllPhysicalAdapters

# 2. 管理员 PowerShell 安装（安装前导出一份 .wfw 防火墙备份，SHA-256 记进日志）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Install -IncludeAllPhysicalAdapters

# 3. 核查生效状态（看输出里的 MatchedPlan 是否为 true）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Status -IncludeAllPhysicalAdapters
```

`Install` 只在系统里还没有 LAN DNS Guard 规则时才建规则：先建成禁用状态、读回核对一致后再一起启用，中途哪一步失败都先删掉这次建的规则再报错（报错里有 `Rollback … completed`），系统回到安装前的样子。已经装过、参数也一样时输出 `already-installed`，不改规则；已经装过但网卡变了（或者规则被禁用、被改过）时拒绝，什么都不改，要换网卡请先 `Remove` 再 `Install`，两步之间这几条规则不起作用。同组里有不是这个脚本建的规则时，`Install` 也拒绝，并列出它们的名字。

卸载单独一条，不要和上面几条一起粘贴执行（一起执行等于装完马上又卸掉）：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Remove
```

该规则不依赖具体路由器 IP（切换 `192.168.0.1` / `192.168.1.1` / `192.168.5.1` 或手机热点均自动生效），且不影响路由器 80/443 管理页、DHCP（67/68）、局域网文件共享及 TUN 虚拟网卡。

**装之前要知道的副作用：**

- 家用网络里系统 DNS 默认就是路由器（如 `192.168.1.1`）。装上这条规则后，**一旦关掉代理客户端或 TUN，几乎所有网站都会打不开**（域名解析全部失败），这是设计如此，不是故障。临时不用代理时，运行 `-Action Remove` 卸载，或把网卡 DNS 改成公网 DNS。
- 规则不分程序：代理客户端自己从物理网卡发往路由器或内网 DNS 的查询同样被拦。节点写的是域名、客户端靠路由器的 DNS 解析节点域名或直连域名时，装上规则后可能开着代理也全部连不上。安装前确认客户端用来解析这些域名的 DNS 不是路由器或内网地址；装完连不上时先运行 `-Action Remove`。
- 公司、学校等内网的 DNS 服务器通常是 `10.x` / `172.16-31.x` 私网地址，同样会被封掉，内网域名（OA、打印机、NAS 主机名等）会解析不了。在这类网络里使用前先卸载。
- 手机热点、酒店 Wi-Fi 的 DNS 也多是私网网关地址，表现与上面相同。

### `.wfw` 备份和日志

- `Install` 真要建规则时，先用 `netsh advfirewall export` 把整机的防火墙策略导出到 `-LogDirectory`（默认 `%LOCALAPPDATA%`）下的 `CPPEK-LanDnsGuard-before-<UTC 时间>-<随机串>.wfw`，日志是同一目录下的 `CPPEK-LanDnsGuard-<UTC 时间>-<随机串>.jsonl`（每次运行一个新文件）。输出 `already-installed` 或被拒绝的那次不导出备份。备份的 SHA-256 记进日志和 `Install` 的输出（`BackupSha256`）：脚本只记录这个值，之后不拿它比对，也不提供还原命令。
- 每装一次多一份备份，不会自动删除，请自己清理旧的。`Install` 中途失败、删掉了这次建的规则时，备份也留着。
- 一般用不到它：卸载规则用 `-Action Remove` 或下面的手工撤销。确实要整份恢复时，在管理员 PowerShell 里运行 `netsh advfirewall import "<备份文件的完整路径>"`。导入会用备份**整份替换**当前的防火墙策略，备份之后新加或改过的所有规则都会丢掉；如果那份备份是在断网开关装着的时候导出的，导回去会把断网开关的阻断规则一起带回来。（“整份替换”是按 netsh 的通常行为说的，本工具包没有实测。）
- `.wfw` 文件里是整机的防火墙规则，含各个程序的安装路径（路径里常带 Windows 用户名），不要发给别人或传到公开的地方。
- 断网开关不导出 `.wfw`，见文首。

### LAN DNS Guard 的手工撤销

工具目录无法访问、脚本跑不起来时，在本机管理员 PowerShell 里直接输入（不是脚本，不受执行策略限制）：

```powershell
$group = 'CPPEK-LanDnsGuard-v1'
$names = @('IPv4-UDP53', 'IPv4-TCP53', 'IPv6-UDP53', 'IPv6-TCP53') | ForEach-Object { "$group-$_" }
Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {
    $_.Name -cin $names -and $_.Group -ceq $group -and
        $_.Description -ceq 'Cross-platform privacy environment kit: physical-NIC LAN DNS port 53 guard v1'
} | ForEach-Object { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $_.Name }
```

`Remove` 删掉名字、规则组、描述三项都对得上的规则以后，同组或同名里还有别的规则时，输出 `"Status": "removed-other-rules-remain"`、退出码 2，`RemainingRules` 列出它们（比如有人在 `wf.msc` 里改过描述）。这时，或者手工撤销以后 DNS 仍然解析不了，列出同组和同前缀剩下的规则：

```powershell
Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {
    $_.Group -eq $group -or $_.Name -like "$group-*"
} | Select-Object Name, DisplayName, Enabled, Action, Description
```

确认列出的是本工具包建的规则后，逐个删除：`Remove-NetFirewallRule -PolicyStore PersistentStore -Name '<规则名>'`。

## 已知问题

v0.4.2 的「已知问题」里五条（目录权限检查的掩码、断网开关 `Remove` 报 `removed` 而同组还留规则、LAN DNS Guard `Install` 中途失败不恢复和遇到对不上的规则整体拒绝卸载、`Test-ProxyState.ps1` 默认把两个地址族混在一起预检）以及几处较小的问题，在这一版的脚本里改了，改了什么见 [CHANGELOG.md](CHANGELOG.md)。**这些改动还没有在 Windows 真机上跑过**：CI 只在 windows-latest 上做语法解析、`Preview` 对账和几个纯函数的单测，`Install`、`Remove`、`Status` 和断线演练要在真机上跑过才算数。下面是仍然存在的：

1. **虚拟网卡选不进保护范围。** 建了 Hyper-V 外部虚拟交换机以后，只绑物理网卡名的规则还拦不拦得住，没有实测；WSL2、虚拟机 NAT、移动热点共享这类由主机转发的流量是否经过这些规则，也没有实测。`Install`、`Status` 现在会对处于连接状态的非隧道虚拟网卡打印警告，但 `ConfigurationMatched` 仍然只看规则。
2. **DHCP 的两种情况装不了。** `-DhcpServer` 只接受 RFC 1918 私网地址；上游地址和 DHCP 服务器是同一个地址时也装不了，都见上文。
3. **两个规划器还有几处细节不同**，只影响极少见的网卡名和地址：Python 用 `casefold` 比较大小写，PowerShell 用 `ToLowerInvariant`（`ß` 这类字母结果不同）；BMP 以外的字符（例如表情符号）排序和计长不同；新近才进 Unicode 的字符，Windows PowerShell 5.1 自带的字符表可能当作未分配而拒绝；上游地址 `192.0.0.9`、`192.0.0.10` Python 接受、PowerShell 拒绝。
4. **窗口里的输出没有脱敏**，见文首。
5. **`Test-ProxyState.ps1` 不比较路由跃点数**，隧道网卡默认按名字认，见「断线演练」一节。
6. **工具包放在被 OneDrive 接管的文件夹里时 `Install` 一律拒绝**，不区分 OneDrive 和符号链接、目录联接（三者都带重解析点属性）。这是有意的：同步文件夹里的脚本可能被另一台设备上的改动替换。请放到不同步的本机文件夹。
7. 如果 `Preview` 能出计划、`Install` 却报 `The selected physical adapter could not be identified`：看这张网卡在 `Get-NetAdapter -IncludeHidden | Select-Object Name, HardwareInterface, Status` 里的 `HardwareInterface` 是否为 `True`。`-IncludeAllPhysicalAdapters` 现在和核对用的是同一个口径，但手工写的网卡名不在这个口径里时仍会这样报错。
