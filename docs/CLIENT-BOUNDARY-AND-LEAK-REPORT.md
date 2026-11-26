# 跨端网络隐私边界与客户端外联实测综合报告

> 适用工具包 `v0.4.2`（MIT 公开版）。四层实测整理于 2026-11-23，Cage 个案于 2026-11-24 核对。
> **性质声明**：本报告为干净原创的隐私工程与网络边界技术报告，由作者的本机独立四层实测数据与公开技术背景的原创归纳构成。**不包含任何第三方文章原文拷贝或未授权转载文本**，主要公开背景来源以可复核的外链形式列于文末，正文另有少量就地引用的官方文档链接。

---

## 一、研究范围、方法论与合规边界

### 1.1 我们真正要解决的工程问题

日常跨平台使用代理与隔离环境（Windows、macOS、Linux、Android、iOS）时，最常见的隐私与稳定性事故往往并非来自主站流量本身，而是来自**被忽略的边界缺口**：

1. **出口分裂（Split Egress）**：主站走代理，但外围遥测、错误上报、前端 RUM、人机验证、支付或 Artifact 预览 CDN 走直连或境内 DNS 解析；
2. **断线静默回落（Fail-Open）**：代理客户端重启、TUN 虚拟网卡异常或手机息屏回收 VPN 后，流量静默回退至物理网卡直连；
3. **防火墙规则优先级穿透**：系统级安装包（如 Windows MSIX）自动写入显式出站「允许」规则，在 Windows 防火墙中优先级高于「默认阻止出站（`DefaultOutboundAction=Block`）」，导致断线兜底失效；
4. **宿主系统与浏览器隔离边界混淆**：隔离浏览器只保护 Web 会话层，无法覆盖同机运行的原生桌面端、CLI 子进程或后台系统服务；
5. **移动端网络层边界误判**：Android VPN 仅接管网络层转发，无法拦截原生 App 在应用层直接读取硬件/系统标识或枚举物理网卡地址。

### 1.2 四层只读与隔离实测方法论

为避免停留在传言或二手结论，本工具包配套采用**四层无侵入、可复现的审计方法**：

| 层级 | 验证目标 | 执行原则 |
| :--- | :--- | :--- |
| **第 1 层：只读静态核验** | 二进制封装结构、内置域名清单、遥测门控开关、安装包清单权限与防火墙声明 | 仅离线只读拆包，不安装、不修改、不运行目标安装包 |
| **第 2 层：无侵入行为观测** | 隔离空配置冷启动外联次数、本地落盘遥测体量、环境变量开关生效前后的归零对比 | 使用临时隔离配置目录与假凭据，测完销毁 |
| **第 3 层：网络元数据对账** | Xray / v2rayN 路由匹配优先级、远程 DoH 绑定、端口 53 旁路与 IPv6 状态、防火墙出站规则盘点 | 不解密 HTTPS、不触碰账号登录态、不导出私密节点 |
| **第 4 层：隔离回环明文载荷** | 指向 `127.0.0.1` 回环记录器的 HTTP 请求头、JSON 载荷与一方事件脱敏字段结构 | 纯本机回环、零外网发出、不携带真实密钥 |

为避免把“未检测项”误读为“安全通过”，自 `v0.4.1` 起本工具包与本报告统一采用**三层证据分级 + 三态核验模型**：

- **三层证据分级**：**【本机观测（`observed_local`）】**（本机网络/防火墙/回环实测）、**【静态配置（`static_config`）】**（离线解包与本地配置文件存在性/开关核验）、**【外部盲区（`external_blind_spot`）】**（本地工具无权或无法观测的外部状态）。
- **三态核验结果**：**`pass`（已通过）**、**`gap`（存在缺口）**、**`unknown`（未知盲区）**——像出口 IP 历史信誉、运行态 GPU/TPM 健康度与平台地区政策这类本地脚本无法核实的项目，**强制显式标为 `unknown`**，绝不默认放行。

### 1.3 诚实的合规与能力边界

- **网络工程能解决的**：保持出口路径一致、减少 DNS/IPv6/WebRTC 泄漏、阻断断线静默回落、降低配置误改或未备份带来的锁网风险、清晰识别各端暴露面。
- **仅靠网络工程解决不了的**：平台服务条款与地区适用政策（按用户实际所在地判断）、客户端协议层校验、账单与支付信息一致性、服务端使用行为模型。本工具包与本报告**仅面向隐私工程、防泄漏与系统卫生审计**，不提供任何绕过平台检测、人机验证或服务条款的指导。

---

## 二、跨端客户端边界与信号暴露全景

结合独立实测与公开社区审计索引，Web、CLI、Windows Desktop、Android 与 iOS 五类入口在架构层面的隐私边界存在本质差异：

| 维度 | 隔离浏览器（Web） | 独立 CLI 终端 | Windows 原生桌面端（MSIX / Electron） | Android 原生 App | iOS 原生 App / 浏览器 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **网络栈归属** | 遵循浏览器配置与系统代理 / TUN | 独立进程走系统 TUN 或 `HTTP_PROXY` / 自定义 `ANTHROPIC_BASE_URL` | 主进程 + 独立后台虚拟机服务（`gvisor-tap-vsock`）双网络栈 | 经系统 VPN 接口转发，但物理网卡状态可被本地枚举 | 经 Network Extension（如 Shadowrocket）统一接管 |
| **未登录冷启动外联** | 打开页面即加载前端脚本与风控探针 | 默认状态下仍会向官方端点发起探活/遥测，**可通过 5 项环境变量归零** | **冷启动早于登录即触发**自动更新与 Sentry 报错初始化 | 启动即初始化 SDK 与网络探测 | 受系统沙盒与代理规则约束 |
| **宿主机时区 / 语言暴露** | 可在独立浏览器配置中统一管理 | HTTP 头与一方遥测中未见时区/语言字段，仅上下文注入纯 ASCII 日期 | **直接采集宿主机真实时区与区域设置**（Sentry `CultureContext` + `Accept-Language`） | 可读取系统语言、时区及 SIM 运营商 MCC/MNC | 受系统语言与区域设置影响，无公开物理网卡底层越权枚举 |
| **本地硬件 / 接口枚举** | 受浏览器权限沙盒约束；**切忌局部篡改 UA/OS/语言**（易触发一致性告警） | 仅使用随机 64 位软件 ID；硬件标识仅在手动开启特定 OTel 选项时门控调用 | 不采集主板序列号，改用本地持久化安装 UUID（`ant-did`）与系统 TPM/Secure Enclave 随机密钥对 | 可在应用层读取 `ANDROID_ID`、枚举物理网卡公网 IPv6、读取 SIM 与 Play Integrity | 不暴露可跨应用追踪的硬件硬码 |
| **防火墙断网兜底冲突** | 无额外系统级放行规则 | 无额外系统级放行规则 | **高危**：MSIX 安装清单自动写入 `Claude.exe` 与 `cowork-svc.exe` 全配置 TCP 出站允许规则 | 依赖系统「始终开启 VPN」+「阻止非 VPN 连接」+ 电池后台白名单 | 依赖规则集接管 IPv6 与远程 DoH，避免系统默认回落 |
| **推荐角色定位** | **高敏感 Web 会话的首选隔离入口** | **补齐 5 项防外联开关后适合作为独立开发终端** | 如非必需建议保持不装；若安装须立刻清理 MSIX 防火墙放行规则 | 网络层可补强，但不可将原生 App 等同于桌面隔离浏览器 | 补齐 IPv6 接管与加密 DNS 后适合作为移动辅助端 |

> 来源说明：表中 Android 与 iOS 两列来自公开社区研究，作者没有在手机上亲测；第三节的本机实测只覆盖 CLI、网页前端脚本和 Windows 桌面端安装包。

---

## 三、独立四层实测审计详录（2026-11-22 ~ 2026-11-23）

以下数据全部来自脱敏后的独立本机实测，已剔除本机用户名、个人目录与私人代理节点信息。

### 3.1 第 1 层：全端只读静态核验

#### A. Claude Code CLI（`2.1.330` & `2.1.278`）

对两个实测版本（Bun 打包二进制）进行离线符号与逻辑核验，证实 7 项关键机制：

1. **第一方判定不看自定义中转地址**：提供方判定逻辑仅识别 Bedrock / Vertex / Foundry / Gateway 等云托管模式，设置自定义 `ANTHROPIC_BASE_URL` 时默认仍归类为第一方模式，后台遥测与实验开关继续直连官方域名。
2. **实验门控与 `apiBaseUrlHost`**：GrowthBook 客户端默认以约 6 小时周期刷新配置，并会解析非官方 `ANTHROPIC_BASE_URL` 的主机名上报为 `apiBaseUrlHost`；静态核查发现除常规遥测开关外，显式配置 `DISABLE_GROWTHBOOK=1` 可直接触发硬门控阻断。
3. **推理载荷中的 `metadata.user_id`**：每次 `/v1/messages` 请求体均固定写入 JSON 字符串 `{"device_id","account_uuid","session_id"}`（上限 512 字节），属于业务载荷而非遥测通道，关闭遥测开关后仍存在。
4. **无默认物理硬件序列号采集**：虽然依赖库中包含系统机器 ID 读取代码，但受严格条件门控——仅当同时显式开启 `OTEL_RESOURCE_INCLUDE_HOST=true` 与 `CLAUDE_CODE_ENABLE_TELEMETRY=1` 时才会执行；干净配置下每次生成的 64 位 `device_id`、`userID` 与 `machineID` 均为独立随机值。
5. **归因头与 `cch` 哈希特征**：系统提示首块包含 `x-anthropic-billing-header`，第一方或 Vertex 模式下会使用非标准 xxHash64 变体计算 5 位十六进制校验值；自定义中转地址模式下不生成 `cch=`。
6. **历史 3-bit 提示词格式隐写已移除**：2026 年中早期版本中曾出现过的日期分隔符与异形撇号格式编码，在 `2.1.278` 与 `2.1.330` 源码及实测输出中均已确认移除，恢复为标准 ASCII 文本。
7. **环境卫生加固结果**：在 CLI 配置中补齐全部 5 项防后台外联开关（`DISABLE_TELEMETRY=1`、`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`、`DISABLE_ERROR_REPORTING=1`、`DISABLE_AUTOUPDATER=1`、`DISABLE_GROWTHBOOK=1`）后，双版本复测后台外联均降为 0。

#### B. Web 端前端探针（`s-cdn.anthropic.com/s.js` 与登录页观测）

- 实拆线上前端脚本确认其集成 Sift 1x1 GIF 信标、浏览器指纹特征采集与隐身模式检测，并额外包含 `tl`/`tr`/`ts`/`tb` 四类一致性校验位，用于识别局部篡改（如只改 `User-Agent`、操作系统或语言而与底层渲染/环境自相矛盾）。
- 静态脚本能说明客户端具备哪些检测能力。要确定某次登录实际发出了哪些数据，需要该次会话的观测记录。平台对某个字段赋予的权重、该字段与某次账号处置的关联，在本研究中均为未知。
- 同时检出 Sift 的兜底分析域名 `hexagon-analytics.com`，已纳入工具包 30 项高优先级生态域名清单。

#### C. 官方 Windows Desktop MSIX（`6.28899.6`）离线全量拆检

对引导器及其指向的正式版 MSIX 安装包（约 297.77 MB，解压后约 801.51 MB，Electron `45.3.3` / Chromium `156`）进行全程不安装、只读离线分析，核心工程发现如下：

1. **高权限清单与最关键的防火墙冲突**：
   - 清单声明 `runFullTrust`、`localSystemServices` 与 `unvirtualizedResources`；
   - **最高危发现**：`AppxManifest.xml` 内置两条面向全网络配置（Domain / Private / Public）的 TCP 出站「允许」规则，分别授予 `app\Claude.exe` 与 `app\resources\cowork-svc.exe`。在 Windows 防火墙规则求值顺序中，显式「允许」高于「默认阻止出站」，但低于显式「阻止」——这意味着仅依赖 `DefaultOutboundAction=Block` 的环境一旦断开 TUN，这两个进程会直接穿过防漏网出网；若采用本工具包的显式物理网卡 Block 规则（`Manage-WindowsKillSwitch.ps1`）或安装后手动禁用这两条 MSIX Allow 规则，方可堵死穿透。（这一条是对安装清单的静态分析加防火墙求值规则的推断：全程没有安装，规则是否真的写入、断开 TUN 后是否真的穿透，都没有在已安装的环境里观测过。）
2. **冷启动即外联，且个人账号无法屏蔽核心遥测**：
   - 官方主进程外联端点总表证实：自动更新（`releases.claude.com` / `downloads.claude.ai`）与 Sentry（`o1158394.ingest.us.sentry.io`）均在应用启动瞬间、用户登录之前触发；后台还会每 5–15 分钟定期拉取 `downloads.claude.ai/model-catalog/v1/catalog.json`。
   - 源码中关闭 Sentry、Datadog RUM、使用遥测及非必要外围服务的企业策略键（`disableEssentialTelemetry`、`disableNonessentialTelemetry`、`disableNonessentialServices`）均限定于企业/第三方部署范围（`3p`），个人常规部署（`1p`）无法关闭。
3. **宿主机特征与跨配置边界**：
   - 窗口入口默认注入 Sentry `CultureContext`（直接读取宿主机真实 `timezone` 与 `locale`）并发送宿主机 `Accept-Language`；
   - 持久化安装标识写入本地数据目录（`ant-did`），并具备扫描同胞安装目录与辅助导入浏览器会话状态的逻辑；
   - 渲染层反常地主动桩化了 `MediaDevices.prototype.enumerateDevices`（返回空设备标签），侧面佐证 PC 端并非通过媒体硬件枚举做识别。
4. **内置微虚拟机与 CLI 环境变量清洗**：
   - 随包携带实盘化的 37.75 MB 微虚拟机磁盘镜像（`smol-bin.x64.vhdx`）及基于 `gvisor-tap-vsock` 的独立服务进程 `cowork-svc.exe`；
   - 桌面端内部启动内置 CLI 会话时，会显式将 `ANTHROPIC_BASE_URL`、`ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN` 置空，不继承宿主机独立终端的防外联或代理配置。
5. **新增外围域名清点**：
   - 从主进程与前端包合并去重出 4 个此前易漏掉的外围域：`datadoghq-browser-agent.com`（独立主域，不命中 `datadoghq.com` 或 `browser-intake`）、`claude.site`（Artifact 站点）、`cdnjs.cloudflare.com` 与 `cdn.jsdelivr.net`（官方 Artifact 预览 CDN），已全部补齐至工具包规则集。

---

### 3.2 第 2 层：无侵入系统行为与未登录冷启动对照实测

在完全清空临时配置目录且**不登录账号**的隔离条件下，对 `claude.exe 2.1.330` 执行对照观测：

| 测试场景 | 外部 `api.anthropic.com:443` 连接次数 | 本地遥测目录落盘体量 | 落盘事件数 |
| :--- | :---: | :---: | :---: |
| `--version` 仅查版本 | `0` | `0 B` | `0` |
| 默认未登录冷启动（即使提示未登录立即退出） | **`3` 次** | **`549 KB`** | **`241` 条** |
| 开启全部 5 项防后台外联开关后冷启动 | **`0` 次** | **`0 B`** | **`0` 条** |

额外观测到：即使指向隔离配置目录，CLI 仍会沿当前工作目录向上检索父目录中的 `CLAUDE.md` 与本地技能定义（该行为属于本地上下文读取，但未在遥测落盘中发现时区或系统语言字段）。

---

### 3.3 第 3 层：网络层分流、DNS 与防火墙全链路对账

对 **39 个目标**（37 个全端核心与外围域名 + 官方 IPv4 网段 `160.79.104.0/21` + 官方 IPv6 前缀 `2607:6bc0::/48`）逐条校验路由匹配与 DNS 解析路径，得出以下工程基线。这 39 个目标的逐条清单没有随仓库发布，其中 37 个域名与现行的 30 项清单不是同一份；仓库里能复核的是现行 30 项、`160.79.104.0/21` 和两个 IPv6 前缀：

- **30 项核心与外围生态条目**（29 条域名后缀加 1 条关键词，完整列表见 [claude-doh-domains.txt](../claude-doh-domains.txt)）必须显式排在 `geosite:cn` 与 `geoip:cn` 之前，并同步绑定远端加密 DNS（DoH），避免任何一条子请求回落境内线路或本地 53 端口；
- **官方 IPv4 网段 `160.79.104.0/21`**（AS399358）置顶走代理；
- **UDP/443（QUIC）** 与 **Anthropic IPv6 前缀（`2607:6bc0::/48`、`2607:6bc0:11::/48`）** 置顶阻断：在单 IPv4 出口节点上，屏蔽这两段 IPv6 可迫使客户端平稳回落 IPv4，大幅减少高频 502 错误；
- **端口 53 旁路与闲置网卡检查**：实时体检确认非回环端口 53 连接为 `0`、公网 IPv6 流量为 `0`；同时暴露出一个常见盲区——**当前断开状态的有线以太网适配器往往仍保留 IPv6 绑定**，日后插网线前应一并检查关闭。

---

### 3.4 第 4 层：隔离回环明文请求体核验

通过指向 `127.0.0.1` 的本地回环记录器（零外网连接、使用假密钥）抓取 `claude.exe 2.1.330` 真实请求：

- **HTTP 请求头（21 项）**：仅包含客户端版本、会话 ID、`anthropic-beta` 及运行时标识头，**0 个 `Accept-Language`、时区或 locale 请求头**；
- **请求体 `metadata.user_id`**：固定发送随机 64 位软件设备 ID + 会话 UUID，不受遥测开关影响；
- **提示词日期注入**：为纯 ASCII 文本 `Today's date is YYYY-MM-DD.`，不含时区名、UTC 偏移或隐写字符；
- **一方事件样本（`ClaudeCodeInternalEvent`）**：包含版本、模型与运行时统计字段，不含系统时区、语言、用户名、局域网 IP 或 `apiBaseUrlHost`。

---

## 四、六大常见认知误区与工程边界权衡

| 常见说法 | 实测结论 | 工程建议 |
| :--- | :--- | :--- |
| **1. “PC 端会读取主板/硬盘序列号做永久硬封”** | **不成立**。Desktop 与 CLI 默认均不采集物理硬件序列号（桌面端使用随机 `ant-did` 与 TPM/Secure Enclave 随机密钥对，CLI 使用随机 64 位软件 ID）。真正能在应用层读取系统硬码与枚举物理网卡公网 IPv6 的是 **Android 原生 App**。 | 明确区分桌面端与 Android 原生 App 的暴露面，不要把手机原生 App 当作桌面隔离浏览器的等价替代。 |
| **2. “只把 `ANTHROPIC_BASE_URL` 改成中转地址就不会连官方”** | **不成立**。CLI 第一方判定不看该变量，未配置防外联开关时仍会连接官方端点并由 GrowthBook 上报 `apiBaseUrlHost`。 | 在独立 CLI 环境中补齐全部 5 项防后台外联环境变量，并用 `audit_client_boundary.py` 定期复核。 |
| **3. “设了 `DISABLE_TELEMETRY=1` 就完全不发标识字段”** | **不完整**。该变量对桌面端无效；在 CLI 中也无法关闭推理请求体强制携带的 `metadata.user_id`，且须叠加 `DISABLE_GROWTHBOOK=1` 等 5 项开关才可将后台外联归零。 | 5 项开关配套设置，理解业务载荷与遥测通道的边界。 |
| **4. “同机装了 Desktop 和 CLI 就会自动本地跨进程互扫”** | **不准确**。独立终端运行的 CLI 与未联动的桌面端没有自动跨进程读取桥；真正建立强关联的是在桌面端内部直接拉起 CLI / Cowork 会话，或两端共用出口与时间窗。 | 坚持职责分离：Web 会话走隔离浏览器，开发终端走独立加固 CLI，尽量避免混用桌面端内置会话。 |
| **5. “单页指纹打分网站分数低就等于链路绝对干净”** | **片面**。浏览器单页工具只看表层特征，测不到外围域名出口分裂、MSIX 防火墙放行穿透、路由器 53 端口 DNS 旁路或移动原生 App 本地枚举；反过来强行魔改 UA/字体还可能触发一致性异常。 | 以系统化自检清单、路由/DNS 实测与受控断线演练为准，不盲目魔改浏览器底层指纹。 |
| **6. 客机网络检查通过后，还能从桌面日志看出什么？** | `WebGL blocklisted` 表明当次图形功能受限，`no_tpm` 表明客户端当时无法使用 TPM。两项都有各自的发生时间和客户端范围。 | 桌面显示异常时查同一次启动的图形日志。网页验证失败时查对应浏览器的实际提示。 |

### 4.1 三个易被忽略的工程盲区（`v0.4.1` 增补）

1. **网络检查的观察范围**限于当时测过的出口、DNS 和断线行为。图形能否正常显示、剪贴板桥接能否读取宿主机内容，都需要对应功能自己的测试。
2. **本地 MCP 与宿主机工具桥的隐蔽跨界**：凡是运行在宿主机上的 MCP Server 或本地工具桥（例如读取宿主机时钟、剪贴板或本地文件目录的桥接服务），其执行语境都是宿主机本身；若未先盘点就接入隔离会话，会绕过网络隔离把宿主机时区或本机信息带入上下文。自 `v0.4.1` 起，`audit_client_boundary.py` 与 `environment_report.py` 会只读统计本地 Desktop/CLI 的 MCP 配置数量（不输出名称与命令）并在三态摘要中显式提醒复核。
3. **出口 IP 历史信誉属于离线脚本的永久盲区（`unknown`）**：本地工具能核对路由规则与防漏状态，但不会也无法替用户核验外部商业代理库、住宅代理标记或共享出口的历史滥用记录；统一体检单固定将 `exit_ip_reputation` 标为 `unknown`，避免把“本地全绿”误当作“出口无风险”。

---

### 4.2 Cage 个案复核与网页登录排障

**这份个案首先缺的是账号事件本身。** 材料中没有首次看到账号提示的时间和原文，也缺少一例可以核对的网页版验证失败记录。登录时被要求补充验证、看到地区不可用、收到停用邮件，分别对应不同结果。在得到当事人的记录前，处置类型、服务端决定时间和原因均记为未知。

| 在原始诊断日志中核对到的事件 | 时间能说明什么 |
| --- | --- |
| 客机服务日志中，最后一次 Desktop 启动完成后约 10 至 15 秒，出现 26 条 WebGL 错误（WebGL 1 有 18 条，WebGL 2 有 8 条）。 | 26 条都属于同一次桌面启动后的短窗口。若账号提示更早，时间顺序已排除这批错误作为起因。即使错误更早，仍需证据把这次图形故障连到具体的账号事件。 |
| Windows 宿主机上的两次 Desktop 冷启动期间，Cage 监控记录到网关未开放，随后各有一次网络恢复任务结束。两次距上次验证分别为 92,594 和 92,628 毫秒，均超过 90 秒租约。 | 两次从“网关未开放”记录到恢复任务结束分别约 31 秒和 30 秒。日志未测量用户请求实际中断多久。维护者可优先在测试客机里复现冷启动，同时记录普通 HTTPS 请求何时失败、何时恢复。 |

目前没有依据把简中字体、无痕登录、客机特征或出口 IP 列为这次处置的高概率原因，也没有依据将换字体或换 IP 列作紧急修复。线下体检中的出口信誉仍为 `unknown`。当事人若已手动完成验证、成功登录并正常使用，可将那一次记录为成功样本。

| 实际卡住的步骤 | 应保留的观察和下一步 |
| --- | --- |
| 验证框空白或加载失败 | 记下浏览器版本、首次出现时间（含时区）和页面实际错误码。例如 Turnstile 的 `200500` 表示验证框加载失败，此时查看该页面对 `challenges.cloudflare.com` 的组件请求是否被拦截。这个码是官方示例，本案没有记录到。 |
| 手动操作后反复回到验证框 | 在同一出口、同一页面，用 Cage 和一款受支持的普通浏览器分别手动试一次，记录各自的时间、结果，以及页面显示的错误码、Ray ID。若现象只在 Cage 重现，再查看扩展、脚本加载和连接稳定性。无痕窗口可用于排查扩展或缓存的影响。 |
| 验证完成，回到 Claude 后出现站点提示 | 单独抄下 Claude 的提示或邮件原文，记首次看到的时间和时区。可同时记录最近一次已知正常使用的时间，以便限定排查区间。需要核实账号状态时，向官方支持提交该提示。 |

公开反馈可写客户端版本、脱敏提示和相对时间。完整 Ray ID 留给站点支持，登录链接与验证码留在自己的设备上。错误码与验证循环的释义见 [Cloudflare 错误码说明](https://developers.cloudflare.com/turnstile/troubleshooting/client-side-errors/error-codes/) 和 [Cloudflare 验证循环排查](https://developers.cloudflare.com/cloudflare-challenges/troubleshooting/challenge-solve-issues/)。

---

## 五、从实测发现到工具包 `v0.4.2` 的防护映射（含副作用说明）

| 实测识别的风险点 | 工具包对应脚本 / 配置 | 必须提前了解的副作用与取舍 |
| :--- | :--- | :--- |
| 外围域名出口分裂 & IPv6 502 | `build_routing.py`、`routing-claude-ecosystem.json`、`routing-claude-global.json`、`claude-doh-domains.txt` | **外溢取舍**：分流模式下把 `cdnjs`、`jsdelivr`、`sentry.io`、`stripe.com`、`segment.com`、`recaptcha.net` 等通用域名置顶走代理，会让访问这些资源的国内站点略有绕路变慢。 |
| 断 TUN 静默回落直连 & MSIX 允许规则穿透 | `Manage-WindowsKillSwitch.ps1`、`build_kill_switch.py`（显式物理网卡 Block 优先级高于 Allow） | **DHCP 例外必需**：网卡启用 DHCP 时必须指定 `-DhcpServer`，否则租约续期被拦会导致断网（`v0.3.8` 起 `Install` 会自动拦截未配 `-DhcpServer` 的 DHCP 网卡）；新增 USB 网卡或热点要先 `-Action Remove` 再用新参数 `-Action Install`，两步之间这些网卡不受保护。 |
| 分流模式下程序直查路由器 53 端口旁路 DNS | `Manage-WindowsLanDnsGuard.ps1`、`build_lan_dns_guard.py` | **离线解析影响**：安装后一旦关闭代理或 TUN，系统 DNS 指向家用路由器或公司 `10.x` 内网 DNS 的网络会全部解析失败；临时裸连前需运行 `-Action Remove` 精准卸载。 |
| 宿主机时区/语言、CLI 防外联漏配与防火墙审计 | `audit_client_boundary.py`、`Inspect-WindowsFirewall.ps1`、`Inspect-WindowsProxy.ps1` | 默认全部只读并自动脱敏个人路径与网卡名；仅反映检查时刻的本机状态，不能替代受控断线演练。 |
| 体检结果盲区隐匿 & 本地 MCP 跨界 | `environment_report.py`（合并 `audit_client_boundary.py` + 三态摘要 + `--html-out` 离线可打印报告） | 离线报告将外部出口信誉、运行态 GPU/TPM 与平台政策固定标为 `unknown`，**不代表自动通过**；MCP 盘点只统计数量、不读取命令和密钥，需人工核对具体桥接用途；体检单不含用户名路径，但带着宿主机时区、UTC 偏移和区域语言。 |
| Android 规则拼写错漏、后台杀进程与原生边界 | `mobile/android-v2rayng-claude-routing.json`、`mobile/validate_android_v2rayng.py`、`mobile/README.md` | 静态校验脚本不包含 Xray 核心，只做规则结构检查，不逐条比对 13 条规则，改过的文件也可能通过；导入后务必重启 VPN 服务并在真机核对「始终开启 VPN」与电池白名单。 |
| 客户端配置与本地数据损坏、误删或明文密钥外泄 | `config_snapshot.py`、`claude_local_data.py` | 两者都拒绝网络盘和符号链接，Windows 自动设置私有 NTFS ACL。明文密钥检查只有 `claude_local_data.py` 有：对 `settings.json`、`settings.local.json`、`.mcp.json` 做启发式检查，会话记录不查；`config_snapshot.py` 的快照是明文，含订阅和口令。仍应保存在启用了磁盘加密的本机私人目录中（脚本不检查磁盘是否加密）。 |

---

## 六、公开参考资料索引（无原文镜像）

本报告的独立实测部分由作者在脱敏环境完成；背景机理交叉对照了以下公开仓库与官方文档（版权与许可均归各自原作者所有，本公开仓库不捆绑任何第三方文本副本）：

- **客户端遥测与边界研究**：
  - `B1anYu/claude-telemetry-audit` — https://github.com/B1anYu/claude-telemetry-audit
  - `benbaobaoshigemi/ImNotDragon` — https://github.com/benbaobaoshigemi/ImNotDragon
  - `aaddrick/claude-desktop-debian`（`DeviceRegistry` 分析）— https://github.com/aaddrick/claude-desktop-debian
  - `ttfake92-lab/skills`（本地状态边界研究）— https://github.com/ttfake92-lab/skills
- **CLI 协议行为与历史机制研究**：
  - `BYK/loreai`（`cch` 归因头分析）— https://github.com/BYK/loreai
  - `pwguler/pengepul`（请求头与版本审计）— https://github.com/pwguler/pengepul
  - `6Kmfi6HP/opencode2api`（协议版本行为记录）— https://github.com/6Kmfi6HP/opencode2api
  - `itwanger/toBeBetterJavaer`（历史格式隐写分析）— https://github.com/itwanger/toBeBetterJavaer
  - `wquguru/one-exit`（外围域名清单参考）— https://github.com/wquguru/one-exit
- **平台官方文档与标准**：
  - Anthropic 支持地区政策 — https://www.anthropic.com/legal/supported-regions
  - Claude Code CLI 参考 — https://code.claude.com/docs/en/cli-reference
  - Android VPN 官方文档 — https://developer.android.com/develop/connectivity/vpn
  - Chrome 本地网络访问安全指南 — https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access
  - Proton 邮件追踪保护说明 — https://proton.me/support/email-tracker-protection
