(function () {
  "use strict";

  /* ==================== 与 build_routing.py 严格同步的常量 ==================== */
  const LOCAL_NETWORKS = [
    "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fd00::/8", "fe80::/10"
  ];

  const ANTHROPIC_IPV6_BLOCK = [
    "2607:6bc0::/48",
    "2607:6bc0:11::/48"
  ];

  const ANTHROPIC_IPV4_CIDRS = [
    "160.79.104.0/21"
  ];

  const ECOSYSTEM_ITEMS = [
    { rule: "domain:claude.ai", cat: "核心业务" },
    { rule: "domain:claude.com", cat: "核心业务" },
    { rule: "domain:clau.de", cat: "核心业务" },
    { rule: "domain:anthropic.com", cat: "核心业务" },
    { rule: "domain:claudeusercontent.com", cat: "核心业务" },
    { rule: "domain:claudemcpcontent.com", cat: "核心业务" },
    { rule: "domain:modelcontextprotocol.io", cat: "核心业务" },
    { rule: "domain:sentry.io", cat: "观测遥测" },
    { rule: "domain:datadoghq.com", cat: "观测遥测" },
    { rule: "keyword:browser-intake", cat: "观测遥测" },
    { rule: "domain:growthbook.io", cat: "观测遥测" },
    { rule: "domain:segment.io", cat: "观测遥测" },
    { rule: "domain:siftscience.com", cat: "风控验证" },
    { rule: "domain:usefathom.com", cat: "观测遥测" },
    { rule: "domain:hcaptcha.com", cat: "风控验证" },
    { rule: "domain:challenges.cloudflare.com", cat: "风控验证" },
    { rule: "domain:recaptcha.net", cat: "风控验证" },
    { rule: "domain:stripe.com", cat: "支付客服" },
    { rule: "domain:stripe.network", cat: "支付客服" },
    { rule: "domain:stripecdn.com", cat: "支付客服" },
    { rule: "domain:intercom.io", cat: "支付客服" },
    { rule: "domain:intercomcdn.com", cat: "支付客服" },
    { rule: "domain:withpersona.com", cat: "身份核验" },
    { rule: "domain:datadoghq-browser-agent.com", cat: "观测遥测" },
    { rule: "domain:hexagon-analytics.com", cat: "风控验证" },
    { rule: "domain:segment.com", cat: "观测遥测" },
    { rule: "domain:statsigapi.net", cat: "观测遥测" },
    { rule: "domain:claude.site", cat: "Artifact CDN" },
    { rule: "domain:cdnjs.cloudflare.com", cat: "Artifact CDN" },
    { rule: "domain:cdn.jsdelivr.net", cat: "Artifact CDN" }
  ];

  const CLAUDE_ECOSYSTEM_DOMAINS = ECOSYSTEM_ITEMS.map((item) => item.rule);

  function buildRoutingRules(opts) {
    const externalFirstXray = Boolean(opts.externalFirstXray);
    const globalProxy = Boolean(opts.globalProxy);
    const claudeEcosystem = Boolean(opts.claudeEcosystem);
    if (externalFirstXray && globalProxy) {
      throw new Error("externalFirstXray 与 globalProxy 不能同时启用");
    }
    const rules = [];
    if (claudeEcosystem) {
      rules.push(
        { remarks: "Block QUIC UDP 443", network: "udp", port: "443", outboundTag: "block" },
        { remarks: "Block Anthropic IPv6 (502 guard)", ip: [...ANTHROPIC_IPV6_BLOCK], outboundTag: "block" },
        { remarks: "Claude and peripheral ecosystem", domain: [...CLAUDE_ECOSYSTEM_DOMAINS], outboundTag: "proxy" },
        { remarks: "Anthropic IPv4 CIDR", ip: [...ANTHROPIC_IPV4_CIDRS], outboundTag: "proxy" }
      );
    }
    rules.push(
      { remarks: "Local domains", domain: ["geosite:private"], outboundTag: "direct" },
      { remarks: "Local address ranges", ip: [...LOCAL_NETWORKS], outboundTag: "direct" }
    );
    if (!globalProxy) {
      if (externalFirstXray) {
        rules.push({
          remarks: "External domain category",
          domain: ["geosite:geolocation-!cn"],
          outboundTag: "proxy"
        });
      }
      rules.push(
        { remarks: "Domestic domains", domain: ["geosite:cn"], outboundTag: "direct" },
        { remarks: "Domestic IP ranges", ip: ["geoip:cn"], outboundTag: "direct" }
      );
    }
    rules.push({ remarks: "Remaining traffic", port: "0-65535", outboundTag: "proxy" });
    return rules.map((rule) => Object.assign({}, rule, { enabled: true }));
  }

  /* ==================== 与 build_kill_switch.py 严格同步的算法 ==================== */
  const KS_PREFIX = "CPPEK-KillSwitch-v1-";
  const DHCP_BROADCAST_INT = 0xffffffff;

  function parseIpv4(raw) {
    const text = String(raw || "").trim();
    const parts = text.split(".");
    if (parts.length !== 4) {
      return null;
    }
    let value = 0;
    for (let i = 0; i < 4; i += 1) {
      if (!/^(0|[1-9]\d{0,2})$/.test(parts[i])) {
        return null;
      }
      const octet = Number(parts[i]);
      if (octet < 0 || octet > 255) {
        return null;
      }
      value = (value * 256) + octet;
    }
    return value;
  }

  function intToIpv4(num) {
    return [
      (num >>> 24) & 255,
      (num >>> 16) & 255,
      (num >>> 8) & 255,
      num & 255
    ].join(".");
  }

  function inCidr(ipInt, baseStr, prefixLen) {
    const base = parseIpv4(baseStr);
    const mask = prefixLen === 0 ? 0 : ((0xffffffff << (32 - prefixLen)) >>> 0);
    return ((ipInt & mask) >>> 0) === ((base & mask) >>> 0);
  }

  function isPrivateRfc1918(ipInt) {
    return (
      inCidr(ipInt, "10.0.0.0", 8) ||
      inCidr(ipInt, "172.16.0.0", 12) ||
      inCidr(ipInt, "192.168.0.0", 16)
    );
  }

  function isDisallowedUpstream(ipInt) {
    const specialNonGlobal = [
      ["0.0.0.0", 8],
      ["100.64.0.0", 10],
      ["127.0.0.0", 8],
      ["169.254.0.0", 16],
      ["192.0.0.0", 24],
      ["192.0.2.0", 24],
      ["198.18.0.0", 15],
      ["198.51.100.0", 24],
      ["203.0.113.0", 24],
      ["224.0.0.0", 4],
      ["240.0.0.0", 4]
    ];
    if (isPrivateRfc1918(ipInt)) {
      return false;
    }
    for (let i = 0; i < specialNonGlobal.length; i += 1) {
      if (inCidr(ipInt, specialNonGlobal[i][0], specialNonGlobal[i][1])) {
        return true;
      }
    }
    return false;
  }

  function complementRanges(start, end, exclusions) {
    const ranges = [];
    let lower = start;
    for (let i = 0; i < exclusions.length; i += 1) {
      const val = exclusions[i];
      if (lower < val) {
        ranges.push([lower, val - 1]);
      }
      lower = val + 1;
    }
    if (lower <= end) {
      ranges.push([lower, end]);
    }
    return ranges;
  }

  function validateInterfaces(rawList) {
    const cleaned = rawList.map((s) => s.trim()).filter(Boolean);
    if (!cleaned.length) {
      return { error: "请至少填写一个物理网卡名称（例如 WLAN）。" };
    }
    const seen = new Set();
    for (let i = 0; i < cleaned.length; i += 1) {
      const name = cleaned[i];
      if (
        name.length > 128 ||
        name.startsWith("-") ||
        name.toLowerCase() === "any" ||
        /[*?\[\]`"\\]/.test(name)
      ) {
        return { error: "网卡名称不可包含通配符、引号、反斜杠或为 Any：" + name };
      }
      const key = name.toLowerCase();
      if (seen.has(key)) {
        return { error: "物理网卡名称有重复：" + name };
      }
      seen.add(key);
    }
    cleaned.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
    return { aliases: cleaned };
  }

  function computeKillSwitchPlan(input) {
    const ifaceRes = validateInterfaces(input.interfaces);
    if (ifaceRes.error) {
      return { error: ifaceRes.error };
    }
    const upstreamInt = parseIpv4(input.upstreamIp);
    if (upstreamInt === null) {
      return { error: "代理上游地址不是有效的字面 IPv4 地址。" };
    }
    const isDocSample = (
      inCidr(upstreamInt, "192.0.2.0", 24) ||
      inCidr(upstreamInt, "198.51.100.0", 24) ||
      inCidr(upstreamInt, "203.0.113.0", 24)
    );
    if (isDisallowedUpstream(upstreamInt) && !isDocSample) {
      return { error: "上游地址必须是公网单播或 RFC 1918 私网 IPv4（拒绝回环、组播、链路本地与保留段）。" };
    }
    const port = Number(input.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { error: "代理上游端口必须在 1–65535 之间。" };
    }
    const proto = input.protocol === "UDP" ? "UDP" : "TCP";
    const otherProto = proto === "TCP" ? "UDP" : "TCP";

    const dhcpRaw = input.dhcpRaw.split(",").map((s) => s.trim()).filter(Boolean);
    const dhcpIntsSet = new Set();
    for (let i = 0; i < dhcpRaw.length; i += 1) {
      const dInt = parseIpv4(dhcpRaw[i]);
      if (dInt === null) {
        return { error: "DHCP 服务器地址不是合法 IPv4：" + dhcpRaw[i] };
      }
      if (!isPrivateRfc1918(dInt)) {
        return { error: "DHCP 服务器地址必须是 RFC 1918 私有 IPv4（10.x / 172.16-31.x / 192.168.x）：" + dhcpRaw[i] };
      }
      if (dInt === upstreamInt) {
        return { error: "DHCP 服务器地址不能与代理上游地址相同。" };
      }
      dhcpIntsSet.add(dInt);
    }

    const dhcpServerInts = Array.from(dhcpIntsSet).sort((a, b) => a - b);
    const dhcpAddressesInts = dhcpServerInts.length ? dhcpServerInts.concat([DHCP_BROADCAST_INT]) : [];
    const excInts = Array.from(new Set([upstreamInt].concat(dhcpAddressesInts))).sort((a, b) => a - b);
    const ipv4Other = complementRanges(0, 0xffffffff, excInts).map(([lo, hi]) => (
      lo === hi ? intToIpv4(lo) : intToIpv4(lo) + "-" + intToIpv4(hi)
    ));
    const blockedUpstreamPorts = complementRanges(1, 65535, [port]).map(([lo, hi]) => (
      lo === hi ? String(lo) : lo + "-" + hi
    ));

    const rules = [
      { Name: KS_PREFIX + "IPv6All", Protocol: "Any", RemoteAddresses: ["0000::/0"] },
      { Name: KS_PREFIX + "IPv4Other", Protocol: "Any", RemoteAddresses: ipv4Other },
      { Name: KS_PREFIX + "UpstreamOtherTransport", Protocol: otherProto, RemoteAddresses: [intToIpv4(upstreamInt)] },
      { Name: KS_PREFIX + "UpstreamOtherPorts", Protocol: proto, RemoteAddresses: [intToIpv4(upstreamInt)], RemotePorts: blockedUpstreamPorts }
    ];
    if (dhcpAddressesInts.length) {
      rules.push(
        { Name: KS_PREFIX + "DhcpTCP", Protocol: "TCP", RemoteAddresses: dhcpAddressesInts.map(intToIpv4) },
        { Name: KS_PREFIX + "DhcpOtherRemotePorts", Protocol: "UDP", RemoteAddresses: dhcpAddressesInts.map(intToIpv4), RemotePorts: ["1-66", "68-65535"] },
        { Name: KS_PREFIX + "DhcpOtherLocalPorts", Protocol: "UDP", RemoteAddresses: dhcpAddressesInts.map(intToIpv4), RemotePorts: ["67"], LocalPorts: ["1-67", "69-65535"] }
      );
    }
    rules.push({ Name: KS_PREFIX + "ExceptionNonTcpUdp (8 rules)", Protocol: "ICMPv4/IGMP/GRE/ESP/AH/SCTP...", RemoteAddresses: excInts.map(intToIpv4) });

    return {
      aliases: ifaceRes.aliases,
      upstreamIp: intToIpv4(upstreamInt),
      port: port,
      protocol: proto,
      dhcpServers: dhcpServerInts.map(intToIpv4),
      dhcpMissingWarning: Boolean(input.usesDhcp) && dhcpServerInts.length === 0,
      docSampleNotice: isDocSample,
      ipv4BlockedRanges: ipv4Other,
      ruleSummaryCount: 12 + (dhcpAddressesInts.length ? 3 : 0),
      previewJson: {
        SchemaVersion: 1,
        InterfaceAliases: ifaceRes.aliases,
        AllowedUpstream: intToIpv4(upstreamInt) + ":" + port + "/" + proto,
        AllowedDhcpServers: dhcpServerInts.map(intToIpv4),
        BlockedIPv4ComplementRanges: ipv4Other,
        TotalFirewallRulesPerAdapter: 12 + (dhcpAddressesInts.length ? 3 : 0),
        CoreRulesPreview: rules
      }
    };
  }

  /* ==================== 内容数据 ==================== */
  const PLATFORMS = [
    {
      id: "windows",
      label: "Windows（v2rayN）",
      badge: "支持最完整",
      summary: "提供只读代理/防火墙体检、客户端边界审计、路由生成与校验、防路由器 53 端口旁路、物理网卡断网开关以及私有 ACL 本地快照备份。",
      files: ["environment_report.py", "audit_client_boundary.py", "Inspect-WindowsProxy.ps1", "Inspect-WindowsFirewall.ps1", "build_routing.py", "Manage-WindowsLanDnsGuard.ps1", "Manage-WindowsKillSwitch.ps1"],
      commands: [
        "# 1. 一键导出三态体检单与可打印 HTML（含边界与 MCP 盘点）",
        "py -3 .\\environment_report.py --html-out .\\env-health.html",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Inspect-WindowsFirewall.ps1",
        "",
        "# 2. 校验随包路由模板",
        "py -3 .\\build_routing.py validate .\\routing-claude-ecosystem.json --claude-ecosystem",
        "py -3 .\\build_routing.py validate .\\routing-claude-global.json --global-proxy --claude-ecosystem"
      ].join("\n"),
      note: "如果使用官方 Windows 桌面端 MSIX，请务必核查 Inspect-WindowsFirewall.ps1 输出中的 MsixClaudeOutboundAllowCount，避免安装清单自动放行穿透断网兜底。"
    },
    {
      id: "unix",
      label: "macOS / Linux",
      badge: "只读体检 + 备份",
      summary: "支持跨平台网络与客户端边界只读诊断、路由模板生成校验，以及 Claude Code 本地状态备份与恢复校验。",
      files: ["inspect_unix_network.py", "environment_report.py", "audit_client_boundary.py", "claude_local_data.py", "build_routing.py"],
      commands: [
        "# 1. 一键导出三态体检单与可打印 HTML（含边界与 MCP 盘点）",
        "python3 environment_report.py --html-out ./env-health.html",
        "",
        "# 2. 备份与核验本地配置状态（自动拦截明文密钥）",
        "python3 claude_local_data.py audit",
        "python3 claude_local_data.py backup --destination ~/claude-backups"
      ].join("\n"),
      note: "Linux 与 macOS 的系统级断网防火墙规则未内置自动写入脚本，请在系统防火墙/客户端设置中单独验证断线行为。"
    },
    {
      id: "android",
      label: "Android（v2rayNG）",
      badge: "13 条规则 + 二维码",
      summary: "随包提供已修正拼写并补齐 30 个生态域名的 13 条规则集、扫码直导二维码与离线结构校验脚本。",
      files: ["mobile/android-v2rayng-claude-routing.json", "mobile/android-v2rayng-claude-routing-qr.png", "mobile/validate_android_v2rayng.py", "mobile/README.md"],
      commands: [
        "# 桌面端静态核验随包 Android 规则文件",
        "python3 mobile/validate_android_v2rayng.py mobile/android-v2rayng-claude-routing.json",
        "",
        "# 手机端必备核对：",
        "# 1. 扫码导入后务必「停止再启动」v2rayNG 服务",
        "# 2. 启用本地 DNS、远程 DNS 改为 https://cloudflare-dns.com/dns-query",
        "# 3. 开启系统「始终开启 VPN」「阻止不使用 VPN 的连接」与电池不限制后台"
      ].join("\n"),
      note: "架构边界提醒：Android VPN 只接管网络层转发，无法拦截原生 App 在应用层直接读取设备标识、SIM 运营商代码或枚举物理网卡 IPv6。"
    },
    {
      id: "ios",
      label: "iOS / iPadOS（Shadowrocket）",
      badge: "IPv6 接管模板",
      summary: "提供已开启 IPv6 隧道接管的纯文本 Shadowrocket 配置模板与静态语法校验器。",
      files: ["mobile/shadowrocket-local-proxy.conf", "mobile/validate_shadowrocket.py", "mobile/README.md"],
      commands: [
        "# 桌面端静态校验 Shadowrocket 配置模板",
        "python3 mobile/validate_shadowrocket.py mobile/shadowrocket-local-proxy.conf"
      ].join("\n"),
      note: "导入模板后，请在 Wi-Fi 与蜂窝网络下分别用普通测试地址记录连接状态，并确认启用加密 DNS。"
    },
    {
      id: "backup",
      label: "本地备份与恢复",
      badge: "防误删 + 私有 ACL",
      summary: "为 v2rayN 配置目录与 Claude 本地数据目录提供带 SHA-256 清单、拒绝符号链接/网络盘与明文密钥拦截的安全快照。",
      files: ["config_snapshot.py", "claude_local_data.py"],
      commands: [
        "# Claude 本地数据安全备份与验证",
        "py -3 .\\claude_local_data.py audit",
        "py -3 .\\claude_local_data.py backup --destination \"C:\\Users\\<你的用户名>\\claude-backups\"",
        "py -3 .\\claude_local_data.py verify \"<快照目录>\"",
        "",
        "# v2rayN 配置目录快照备份与验证",
        "py -3 .\\config_snapshot.py backup --config-dir \"<实际 guiConfigs 路径>\""
      ].join("\n"),
      note: "备份快照为明文目录，虽然 Windows 会自动设当前账户私有 NTFS 权限，仍请存放在启用了 BitLocker/FileVault 的本地盘，远离云盘同步目录。"
    }
  ];

  const LAYERS = [
    {
      num: 1,
      title: "只读体检与客户端边界识别",
      scripts: ["environment_report.py", "audit_client_boundary.py", "Inspect-WindowsProxy.ps1", "Inspect-WindowsFirewall.ps1", "inspect_unix_network.py"],
      solves: "一键输出三态摘要（已通过 / 存在缺口 / 未知盲区）与可打印离线 HTML 体检单，覆盖路由与 IPv6 暴露面、防火墙状态、宿主机时区/语言、CLI 5 项防外联开关、本地 MCP 桥接数量及 MSIX 放行规则。",
      tradeoff: "所有输出自动脱敏个人路径、网卡名与 MCP 命令；出口 IP 历史信誉、运行态 GPU/TPM 与平台政策显式标为 unknown，不能替代受控断线演练。"
    },
    {
      num: 2,
      title: "统一路由、远端 DoH 与防 502 策略",
      scripts: ["build_routing.py", "routing-claude-ecosystem.json", "routing-claude-global.json", "claude-doh-domains.txt", "mobile/*"],
      solves: "把 30 个核心与外围生态域及 160.79.104.0/21 置顶在国内直连规则之前并绑定远端 DoH，同时阻断 UDP/443 QUIC 与 Anthropic IPv6 502 前缀。",
      tradeoff: "分流模式下把 cdnjs、jsdelivr、sentry.io、stripe.com 等公共域置顶代理，会让国内网站加载同类静态资源时稍有绕路。"
    },
    {
      num: 3,
      title: "物理网卡断网开关与防路由器 DNS 旁路",
      scripts: ["Manage-WindowsKillSwitch.ps1", "build_kill_switch.py", "Manage-WindowsLanDnsGuard.ps1", "build_lan_dns_guard.py"],
      solves: "通过高优先级的显式物理网卡 Block 规则堵死断 TUN 静默回落（并压制 MSIX Allow 规则穿透），同时封堵绕过系统 DNS 直查路由器 53 端口的旁路请求。",
      tradeoff: "断网开关在 DHCP 网卡上必须提供 -DhcpServer 否则续租会断网；LAN DNS Guard 在关掉代理/TUN 后会让依赖路由器或内网 10.x DNS 的解析全部失败。"
    },
    {
      num: 4,
      title: "安全快照备份、验证与防密钥泄露",
      scripts: ["config_snapshot.py", "claude_local_data.py"],
      solves: "在调整网络或环境前生成带完整性清单的快照，拒绝网络盘与符号链接，自动检测并拦停配置文件中的明文 API Key / Token。",
      tradeoff: "如配置文件中确实保留明文密钥，需显式移入环境变量/系统钥匙串，或主动传 --allow-inline-secrets 后方可备份。"
    }
  ];

  const ROUTING_PRESETS = [
    {
      id: "eco-split",
      label: "分流 + 生态置顶（日常推荐）",
      filename: "routing-claude-ecosystem.json",
      opts: { externalFirstXray: false, globalProxy: false, claudeEcosystem: true },
      validateCmd: "py -3 .\\build_routing.py validate .\\routing-claude-ecosystem.json --claude-ecosystem",
      summary: "保留国内域名与 IP 直连，同时将 UDP/443、Anthropic IPv6（防 502）、30 个核心与外围生态域以及 160.79.104.0/21 置顶在国内直连之前。推荐配合 LAN DNS Guard 与远端 DoH 使用。"
    },
    {
      id: "eco-global",
      label: "全公网 + 生态置顶（断网开关首选）",
      filename: "routing-claude-global.json",
      opts: { externalFirstXray: false, globalProxy: true, claudeEcosystem: true },
      validateCmd: "py -3 .\\build_routing.py validate .\\routing-claude-global.json --global-proxy --claude-ecosystem",
      summary: "仅局域网私有地址直连，全部公网流量统一走单出口代理，并叠加 QUIC 与 IPv6 502 阻断。与 Windows 断网开关配合使用时，请将客户端 domainStrategy 设为 AsIs。"
    },
    {
      id: "base-split",
      label: "标准国内直连分流",
      filename: "routing-template.json",
      opts: { externalFirstXray: false, globalProxy: false, claudeEcosystem: false },
      validateCmd: "py -3 .\\build_routing.py validate .\\routing-template.json",
      summary: "最简 5 条分流基线（局域网直连 → 国内域名/IP 直连 → 其余走代理），不含外围生态域名置顶，适合不希望公共 CDN 绕路的一般日常场景。"
    },
    {
      id: "base-global",
      label: "标准全公网代理",
      filename: "routing-global.json",
      opts: { externalFirstXray: false, globalProxy: true, claudeEcosystem: false },
      validateCmd: "py -3 .\\build_routing.py validate .\\routing-global.json --global-proxy",
      summary: "最简 3 条全局代理规则（仅局域网私有地址直连，其余公网一律走代理），结构最简单，适合快速排查分流冲突。"
    },
    {
      id: "ext-first",
      label: "外网优先分流（Xray）",
      filename: "routing-external-first.json",
      opts: { externalFirstXray: true, globalProxy: false, claudeEcosystem: true },
      validateCmd: "py -3 .\\build_routing.py validate .\\routing-external-first.json --external-first-xray --claude-ecosystem",
      summary: "在命中 geosite:cn 之前增加 geosite:geolocation-!cn 优先走代理，兼顾生态域名置顶与外网优先策略。"
    }
  ];

  const CHECKLIST_ITEMS = [
    { id: "win-backup", cat: "备份与应急验证", priority: "高", title: "改网前已完成客户端与本地数据快照备份", desc: "运行 config_snapshot.py 与 claude_local_data.py backup，并将快照存放在启用磁盘加密的本机私有目录（避开云同步目录）。" },
    { id: "win-routing", cat: "Windows 网络与防火墙", priority: "高", title: "已导入并校验 v2rayN 路由规则与 30 项远程 DoH 域名", desc: "使用 build_routing.py validate 核验规则文件，确认核心与外围 30 项域名排在 geosite:cn 之前并绑定加密 DoH。" },
    { id: "win-dns-guard", cat: "Windows 网络与防火墙", priority: "高", title: "分流模式下已核对物理网卡路由器 53 端口防旁路", desc: "运行 Manage-WindowsLanDnsGuard.ps1 -Action Status -IncludeAllPhysicalAdapters；并已知晓关闭代理后路由器/内网 DNS 会解析失败的副作用。" },
    { id: "win-killswitch-dhcp", cat: "Windows 网络与防火墙", priority: "高", title: "启用断网开关且使用 DHCP 时已填写 -DhcpServer", desc: "防止 DHCP 续租被阻断导致租约到期突然断网（v0.3.8 起 Install 会自动拦截漏填）。" },
    { id: "win-fw-msix", cat: "Windows 网络与防火墙", priority: "高", title: "已复核防火墙放行项与 MSIX 自动放行规则", desc: "运行 Inspect-WindowsFirewall.ps1 确认 MsixClaudeOutboundAllowCount 为 0，无多余第三方全地址出站放行。" },
    { id: "win-ipv6-idle", cat: "Windows 网络与防火墙", priority: "中", title: "已检查所有物理网卡（含断开的以太网）的 IPv6 绑定", desc: "避免日后插上有线网线或连接新热点时经物理网卡走原生 IPv6 绕行。" },
    { id: "cli-flags", cat: "浏览器与客户端边界", priority: "高", title: "独立 CLI 环境已配置全部 5 项防后台外联开关", desc: "运行 audit_client_boundary.py 确认 DISABLE_TELEMETRY、CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC、DISABLE_ERROR_REPORTING、DISABLE_AUTOUPDATER、DISABLE_GROWTHBOOK 均为 1。" },
    { id: "host-boundary", cat: "浏览器与客户端边界", priority: "高", title: "明确区分隔离浏览器与宿主机原生客户端边界", desc: "不把宿主机原生桌面端与隔离浏览器混用；Web 高敏会话固定在独立隔离浏览器内完成。" },
    { id: "local-mcp-bridges", cat: "浏览器与客户端边界", priority: "高", title: "已核查本地 MCP 与宿主机桥接插件（localMcpBridges）", desc: "运行 environment_report.py --html-out 或 audit_client_boundary.py 查看本地 Desktop/CLI 的 MCP 配置数量，确认没有无意间把读取宿主机时钟或本地文件的桥接工具带入隔离会话。" },
    { id: "vm-runtime-health", cat: "浏览器与客户端边界", priority: "中", title: "已理解「网络零泄露 ≠ 虚拟化/运行态无异常」的工程权衡", desc: "避免在无 GPU 硬件加速、无 TPM 的残缺虚拟机中高频冷启动原生桌面端，防止持续 WebGL 拉黑报错、no_tpm 降级与侵入式字体/输入法桥接副作用。" },
    { id: "browser-webrtc", cat: "浏览器与客户端边界", priority: "中", title: "核对浏览器 WebRTC、本地网络权限与同步开关", desc: "关闭不需要访问局域网服务的站点本地访问权限，检查浏览器同步选项，且不手工局部魔改 UA/字体。" },
    { id: "mail-pixel", cat: "浏览器与客户端边界", priority: "中", title: "邮箱客户端已关闭自动加载远程图片", desc: "防止通知邮件内的远程追踪像素在非代理日常环境下自动加载，相关链接只在隔离浏览器中打开。" },
    { id: "android-rules", cat: "移动端 Android & iOS", priority: "高", title: "Android v2rayNG 已导入 13 条规则、设 DoH 并重启服务", desc: "开启「本地 DNS」、远程 DNS 设为 Cloudflare DoH、开启「开机自动连接」，修改设置后已停止并重新启动服务。" },
    { id: "android-alwayson", cat: "移动端 Android & iOS", priority: "高", title: "Android 系统已开「始终开启 VPN」「阻止非 VPN」与电池白名单", desc: "防止息屏后系统回收 VPN 隧道；明确网页认证 Wi-Fi 需临时关闭阻断，且应用分身不等于独立环境。" },
    { id: "android-boundary", cat: "移动端 Android & iOS", priority: "中", title: "已理解 Android 原生 App 的应用层本地枚举边界", desc: "明确 VPN 仅管网络层，无法阻断原生 App 读取系统标识、SIM 与物理网卡 IPv6，高敏场景留在电脑端。" },
    { id: "ios-template", cat: "移动端 Android & iOS", priority: "中", title: "iOS Shadowrocket 已验证 IPv6 隧道接管与加密 DNS", desc: "通过 mobile/validate_shadowrocket.py 核验模板，并在 Wi-Fi 与蜂窝网络下分别完成基线测试。" },
    { id: "disconnect-drill", cat: "备份与应急验证", priority: "高", title: "已执行一次受控短时断线演练", desc: "使用可控故障条件（而非盲断生产网）验证代理失效时请求被阻断而非静默回落物理网卡直连。" },
    { id: "exit-ip-blindspot", cat: "备份与应急验证", priority: "高", title: "已正视出口 IP 历史信誉盲区（exit_ip_reputation = unknown）", desc: "明确本工具包离线脚本不查外部代理库/欺诈分，不把本地零泄露全通过等同于共享出口历史干净，按需自行评估出口质量。" },
    { id: "account-privacy", cat: "备份与应急验证", priority: "中", title: "已核对账户隐私训练开关并了解服务地区政策边界", desc: "按个人偏好检查账户隐私选项；明确网络工程不替代官方地区政策与服务条款。" }
  ];

  const BOUNDARY_ROWS = [
    {
      client: "隔离浏览器（Web）",
      cold: "打开页面即加载前端与风控脚本",
      locale: "可在独立配置内保持一致",
      hw: "受浏览器沙盒约束；切忌局部魔改指纹",
      role: "高敏感 Web 会话的首选隔离入口"
    },
    {
      client: "独立 CLI 终端",
      cold: "默认 3 次外联 + 549 KB；开 5 项开关归零",
      locale: "HTTP 头与遥测无时区/语言；仅注纯 ASCII 日期",
      hw: "随机 64 位软件 ID（无默认主板序列号）",
      role: "加固 5 项开关后的独立开发终端"
    },
    {
      client: "Windows 桌面端（MSIX）",
      cold: "早于登录即触发更新与 Sentry；个人 1P 关不掉核心遥测",
      locale: "直接上报宿主机真实时区与语言",
      hw: "持久化 ant-did + TPM 随机密钥 + MSIX 防火墙放行冲突",
      role: "非必需保持不装；若装须清理防火墙 Allow 规则"
    },
    {
      client: "Android 原生 App",
      cold: "启动即初始化 SDK 与网络探测",
      locale: "读取系统时区、语言与 SIM 运营商代码",
      hw: "应用层可直读 ANDROID_ID 与物理网卡公网 IPv6",
      role: "网络层可补强，但不可等同于桌面隔离环境"
    },
    {
      client: "iOS 原生 / 浏览器",
      cold: "受系统沙盒与代理规则约束",
      locale: "遵循系统语言与区域设置",
      hw: "无公开跨应用硬件硬码或物理网卡越权枚举",
      role: "配合 IPv6 接管与加密 DNS 作移动辅助端"
    }
  ];

  const MYTHS = [
    {
      q: "误区 1：PC 端会读取主板 / 硬盘序列号做永久硬件封禁？",
      verdict: "实证否决",
      a: "Desktop 与 CLI 源码与实测均不默认采集物理硬件序列号（桌面端使用随机持久化 UUID 与 TPM/Secure Enclave 随机密钥对，CLI 仅在手动同时开启特定 OTel 变量时才读取系统机器 ID）。真正能在应用层读取系统硬码并枚举物理网卡公网 IPv6 的是 Android 原生 App。"
    },
    {
      q: "误区 2：只把 ANTHROPIC_BASE_URL 指向自建中转，CLI 就不会连官方？",
      verdict: "实证否决",
      a: "CLI 的第一方判定函数完全不检查 ANTHROPIC_BASE_URL。实测在不配防外联开关时，哪怕未登录也会发起 3 次 api.anthropic.com:443 外联，并由 GrowthBook 定时上报 apiBaseUrlHost。必须补齐全部 5 项防后台外联开关方可归零。"
    },
    {
      q: "误区 3：设了 DISABLE_TELEMETRY=1 就彻底静默、什么都不发？",
      verdict: "实证纠偏",
      a: "CLI 环境变量对桌面端完全无效；在 CLI 内部，推理请求体携带的 metadata.user_id 属于业务载荷而非遥测通道，无法通过遥测变量移除；此外还需叠加 DISABLE_GROWTHBOOK=1 等 5 项变量才可彻底阻断后台外联。"
    },
    {
      q: "误区 4：同一台电脑装了 Desktop 和 CLI 就会自动跨进程互扫？",
      verdict: "实证纠偏",
      a: "独立终端运行的 CLI 与未联动的桌面端在代码层没有自动跨进程互扫桥接；真正产生硬关联的是在桌面端内部直接拉起 CLI/Cowork 会话（且桌面端会清空内置 CLI 的外部中转环境变量），或两端共享同一出口与时间窗。"
    },
    {
      q: "误区 5：单页指纹检测网站跑出低分就代表链路完全干净？",
      verdict: "实证否决",
      a: "社区单页检测工具只能看到浏览器表层特征，完全测不到外围域名出口分裂、MSIX 防火墙放行穿透、物理网卡 53 端口旁路或移动原生 App 本地枚举；为了凑分手工篡改 UA/字体反而可能命中前端一致性异常检测。"
    },
    {
      q: "误区 6：套一层虚拟机把网络锁死零泄露，运行环境就一定更干净？",
      verdict: "工程权衡",
      a: "网络层零泄露不等于运行环境无异常。无 GPU 硬件加速与无 TPM 的轻/无头虚拟机在运行桌面端时，容易产生大量 WebGL 拉黑报错、no_tpm 降级与频繁冷启动遥测放大，为适配中文字体/剪贴板/输入法而注入的系统桥接也会引入额外副作用；同时宿主机 MCP 工具桥若未盘点也会跨界透出本机元信息。"
    }
  ];

  const HAJIMI_TIPS = [
    "喵～这个工作台 100% 离线运行，没有加载任何外部字体、统计脚本或 CDN，连你勾的自检清单都只存在本机浏览器里！",
    "装 Windows 断网开关前先看一眼是不是 DHCP 网卡！家用 Wi-Fi 和手机热点一定要填 -DhcpServer，不然租约一到期就会断网喵。",
    "装了 LAN DNS Guard 以后，如果哪天关掉代理想裸连，记得先跑 -Action Remove，不然指向路由器的 DNS 查询全都会被挡住！",
    "别被单页指纹打分网站带偏啦：手工乱改浏览器 UA 或字体反而容易触发自相矛盾，保持一套干净、自洽的独立环境更省心。",
    "CLI 终端千万别只改一个 ANTHROPIC_BASE_URL 就收工——补齐 5 项防后台外联开关，实测冷启动外联直接从 3 次 / 549 KB 归零！",
    "如果这台 Windows 上装过官方桌面端 MSIX，记得跑 Inspect-WindowsFirewall.ps1 查一眼 MsixClaudeOutboundAllowCount，防它穿透断网兜底。",
    "改完手机 v2rayNG 的 DNS 或路由规则后，光点保存不算生效！一定要回到主页点一次「停止」再「启动」重新加载核心喵。",
    "v0.4.1 可以直接跑 environment_report.py --html-out ./env-health.html 出一份可打印 PDF 的三态体检单！记住 unknown 代表“本地没测到”，千万别当成通过喵。",
    "本地 MCP 工具桥跑在宿主机上，需要严格隔离时记得用 environment_report.py 查一眼 localMcpBridges 数量，别让读本机时钟的桥接悄悄跨界啦！",
    "网络隐私工具包帮你把链路卫生、备份和防泄漏做到位，但合规边界还得按官方地区政策实事求是判断——诚实是第一准则！"
  ];

  const TAB_DOCK_TIPS = {
    overview: "欢迎来到离线工作台！我是协作小助手哈基米（Gemini）。先点选你正在用的设备，按「备份 → 体检 → 规则 → 演练」四步走最稳妥。",
    routing: "在路由工作台里选好模式，生成的 JSON 跟 build_routing.py 一字不差！如果配合断网开关，记得选「全公网 + 生态置顶」并把 domainStrategy 设为 AsIs。",
    firewall: "规划防火墙规则时别漏填 DHCP 服务器 IPv4 哦！这里只负责本地算区间和生成命令，绝不会偷偷改你的系统防火墙。",
    checklist: "自检清单会自动记住你的勾选进度（纯存在你本机浏览器）。全检完可以一键导出 Markdown 当作验收归档！",
    report: "这份报告已经把原来的第三方镜像和微信原文彻底清干净了，全是脱敏后的原创实测与可查出处链接，放心公开分享！"
  };

  /* ==================== 状态管理 ==================== */
  let activeTab = "overview";
  let activePlatform = "windows";
  let activeLayer = 1;
  let activePreset = "eco-split";
  let activeDomainCat = "全部";
  let activeCheckCat = "全部";
  let tipIndex = 0;
  const STORAGE_KEY = "cppek_checklist_v040";
  const THEME_KEY = "cppek_theme_v040";

  function loadChecklistState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch (_err) {
      return {};
    }
  }

  function saveChecklistState(state) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (_err) {
      // 隐私模式下忽略写入限制
    }
  }

  let checklistState = loadChecklistState();

  /* ==================== 工具函数 ==================== */
  let toastTimer = null;
  function showToast(msg) {
    const el = document.getElementById("toast");
    if (!el) {
      return;
    }
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 2200);
  }

  function copyText(text, successMsg) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        () => showToast(successMsg || "已复制到剪贴板"),
        () => fallbackCopy(text, successMsg)
      );
    } else {
      fallbackCopy(text, successMsg);
    }
  }

  function fallbackCopy(text, successMsg) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      showToast(successMsg || "已复制到剪贴板");
    } catch (_err) {
      showToast("复制失败，请手动选中复制");
    }
    document.body.removeChild(ta);
  }

  function downloadFile(filename, content, mime) {
    const blob = new Blob([content], { type: mime || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ==================== 主题切换 ==================== */
  function applyTheme(theme) {
    const root = document.documentElement;
    const btn = document.getElementById("themeToggle");
    if (theme === "dark") {
      root.setAttribute("data-theme", "dark");
      if (btn) btn.textContent = "暖纸模式";
    } else {
      root.removeAttribute("data-theme");
      if (btn) btn.textContent = "深色模式";
    }
  }

  function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem(THEME_KEY); } catch (_err) {}
    if (!saved && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      saved = "dark";
    }
    applyTheme(saved === "dark" ? "dark" : "light");
    const btn = document.getElementById("themeToggle");
    if (btn) {
      btn.addEventListener("click", () => {
        const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
        applyTheme(next);
        try { localStorage.setItem(THEME_KEY, next); } catch (_err) {}
      });
    }
  }

  /* ==================== 标签页切换 ==================== */
  function switchTab(tabId) {
    activeTab = tabId;
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      const isMatch = btn.dataset.tab === tabId;
      btn.classList.toggle("active", isMatch);
      btn.setAttribute("aria-selected", String(isMatch));
    });
    document.querySelectorAll(".panel").forEach((panel) => {
      panel.classList.toggle("active", panel.id === "panel-" + tabId);
    });
    const dockMsg = document.getElementById("hajimiDockMessage");
    if (dockMsg) {
      dockMsg.textContent = TAB_DOCK_TIPS[tabId] || HAJIMI_TIPS[tipIndex];
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  /* ==================== 渲染 Tab 1: 总览 ==================== */
  function renderPlatforms() {
    const chips = document.getElementById("platformChips");
    const detail = document.getElementById("platformDetail");
    if (!chips || !detail) return;
    chips.innerHTML = PLATFORMS.map((p) => (
      `<button type="button" class="chip ${p.id === activePlatform ? "active" : ""}" data-platform="${p.id}">${escapeHtml(p.label)}</button>`
    )).join("");
    chips.querySelectorAll(".chip").forEach((btn) => {
      btn.addEventListener("click", () => {
        activePlatform = btn.dataset.platform;
        renderPlatforms();
      });
    });

    const cur = PLATFORMS.find((p) => p.id === activePlatform) || PLATFORMS[0];
    detail.innerHTML = `
      <div class="grid-2">
        <div>
          <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
            <strong style="font-size:16px;">${escapeHtml(cur.label)}</strong>
            <span class="badge badge-accent">${escapeHtml(cur.badge)}</span>
          </div>
          <p style="margin:0 0 12px; color:var(--muted);">${escapeHtml(cur.summary)}</p>
          <div style="margin-bottom:12px;">
            <div style="font-size:12.5px; font-weight:700; margin-bottom:6px;">相关文件：</div>
            <div class="domain-grid">${cur.files.map((f) => `<span class="domain-tag">${escapeHtml(f)}</span>`).join("")}</div>
          </div>
          <div class="callout callout-warn" style="font-size:13px;">
            <strong>边界提示：</strong>${escapeHtml(cur.note)}
          </div>
        </div>
        <div>
          <div class="code-toolbar">
            <strong>常用起手命令</strong>
            <button type="button" class="btn btn-sm" id="copyPlatformCmdBtn">复制命令</button>
          </div>
          <pre class="code-block">${escapeHtml(cur.commands)}</pre>
        </div>
      </div>
    `;
    const copyBtn = document.getElementById("copyPlatformCmdBtn");
    if (copyBtn) {
      copyBtn.addEventListener("click", () => copyText(cur.commands, "已复制 " + cur.label + " 命令"));
    }
  }

  function renderLayers() {
    const list = document.getElementById("layerList");
    const detail = document.getElementById("layerDetail");
    if (!list || !detail) return;
    list.innerHTML = LAYERS.map((l) => `
      <button type="button" class="layer-card ${l.num === activeLayer ? "active" : ""}" data-layer="${l.num}">
        <span class="layer-num">${l.num}</span>
        <strong>${escapeHtml(l.title)}</strong>
      </button>
    `).join("");
    list.querySelectorAll(".layer-card").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeLayer = Number(btn.dataset.layer);
        renderLayers();
      });
    });
    const cur = LAYERS.find((l) => l.num === activeLayer) || LAYERS[0];
    detail.innerHTML = `
      <div>
        <div class="badge badge-accent" style="margin-bottom:8px;">第 ${cur.num} 层防线</div>
        <h3 style="margin:0 0 8px; font-size:18px; color:var(--ink-strong);">${escapeHtml(cur.title)}</h3>
        <p style="margin:0 0 12px;"><strong>解决什么问题：</strong>${escapeHtml(cur.solves)}</p>
        <div class="callout callout-warn" style="margin-bottom:12px;">
          <strong>需要知道的副作用 / 边界：</strong>${escapeHtml(cur.tradeoff)}
        </div>
      </div>
      <div>
        <div style="font-size:12.5px; font-weight:700; margin-bottom:6px;">涉及脚本与模板：</div>
        <div class="domain-grid">${cur.scripts.map((s) => `<span class="domain-tag">${escapeHtml(s)}</span>`).join("")}</div>
      </div>
    `;
  }

  /* ==================== 渲染 Tab 2: 路由工作台 ==================== */
  function renderRouting() {
    const chips = document.getElementById("routingPresetChips");
    const summary = document.getElementById("routingModeSummary");
    const title = document.getElementById("routingJsonTitle");
    const out = document.getElementById("routingJsonOutput");
    const hint = document.getElementById("routingValidateHint");
    if (!chips || !out) return;

    chips.innerHTML = ROUTING_PRESETS.map((p) => (
      `<button type="button" class="chip ${p.id === activePreset ? "active" : ""}" data-preset="${p.id}">${escapeHtml(p.label)}</button>`
    )).join("");
    chips.querySelectorAll(".chip").forEach((btn) => {
      btn.addEventListener("click", () => {
        activePreset = btn.dataset.preset;
        renderRouting();
      });
    });

    const preset = ROUTING_PRESETS.find((p) => p.id === activePreset) || ROUTING_PRESETS[0];
    const rules = buildRoutingRules(preset.opts);
    const jsonStr = JSON.stringify(rules, null, 2);
    const counts = { block: 0, proxy: 0, direct: 0 };
    rules.forEach((r) => { counts[r.outboundTag] = (counts[r.outboundTag] || 0) + 1; });

    summary.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:6px;">
        <strong>${escapeHtml(preset.filename)}（共 ${rules.length} 条规则）</strong>
        <div style="display:flex; gap:6px; flex-wrap:wrap;">
          <span class="badge badge-danger">block × ${counts.block}</span>
          <span class="badge badge-accent">proxy × ${counts.proxy}</span>
          <span class="badge badge-ok">direct × ${counts.direct}</span>
        </div>
      </div>
      <div>${escapeHtml(preset.summary)}</div>
    `;
    title.textContent = preset.filename + "（精确 JSON 预览）";
    out.textContent = jsonStr;
    hint.innerHTML = `导入前可用随包脚本校验：<code>${escapeHtml(preset.validateCmd)}</code>`;

    const copyBtn = document.getElementById("copyRoutingJsonBtn");
    const dlBtn = document.getElementById("downloadRoutingJsonBtn");
    copyBtn.onclick = () => copyText(jsonStr, "已复制 " + preset.filename);
    dlBtn.onclick = () => {
      downloadFile(preset.filename, jsonStr + "\n", "application/json;charset=utf-8");
      showToast("已下载 " + preset.filename);
    };
  }

  function renderDomainExplorer() {
    const catChips = document.getElementById("domainCategoryChips");
    const grid = document.getElementById("domainGrid");
    if (!catChips || !grid) return;
    const cats = ["全部", "核心业务", "观测遥测", "风控验证", "支付客服", "身份核验", "Artifact CDN"];
    catChips.innerHTML = cats.map((c) => {
      const count = c === "全部" ? ECOSYSTEM_ITEMS.length : ECOSYSTEM_ITEMS.filter((i) => i.cat === c).length;
      return `<button type="button" class="chip ${c === activeDomainCat ? "active" : ""}" data-cat="${escapeHtml(c)}">${escapeHtml(c)} (${count})</button>`;
    }).join("");
    catChips.querySelectorAll(".chip").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeDomainCat = btn.dataset.cat;
        renderDomainExplorer();
      });
    });

    const filtered = activeDomainCat === "全部"
      ? ECOSYSTEM_ITEMS
      : ECOSYSTEM_ITEMS.filter((i) => i.cat === activeDomainCat);
    grid.innerHTML = filtered.map((i) => `<span class="domain-tag" title="${escapeHtml(i.cat)}">${escapeHtml(i.rule)}</span>`).join("");

    const copyDoh = document.getElementById("copyDohBtn");
    if (copyDoh) {
      copyDoh.onclick = () => copyText(CLAUDE_ECOSYSTEM_DOMAINS.join("\n") + "\n", "已复制 30 项远程 DoH 域名清单");
    }
  }

  /* ==================== 渲染 Tab 3: 防火墙规划器 ==================== */
  function renderFirewallPlanner() {
    const ifaces = (document.getElementById("ksInterfaces").value || "").split(",");
    const upstreamIp = document.getElementById("ksUpstreamIp").value || "";
    const port = document.getElementById("ksPort").value || "443";
    const protocol = document.getElementById("ksProto").value || "TCP";
    const dhcpRaw = document.getElementById("ksDhcp").value || "";
    const usesDhcp = document.getElementById("ksUsesDhcp").checked;

    const alertBox = document.getElementById("ksAlertBox");
    const badge = document.getElementById("ksRuleCountBadge");
    const planOut = document.getElementById("ksPlanOutput");
    const cmdOut = document.getElementById("ksCmdOutput");
    const lanOut = document.getElementById("lanDnsCmdOutput");

    const res = computeKillSwitchPlan({
      interfaces: ifaces,
      upstreamIp: upstreamIp,
      port: port,
      protocol: protocol,
      dhcpRaw: dhcpRaw,
      usesDhcp: usesDhcp
    });

    const lanCmd = [
      "# 1. 只读预览物理网卡 53 端口旁路阻断规则",
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Manage-WindowsLanDnsGuard.ps1 -Action Preview -IncludeAllPhysicalAdapters",
      "",
      "# 2. 管理员 PowerShell 安装并检查状态",
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Manage-WindowsLanDnsGuard.ps1 -Action Install -IncludeAllPhysicalAdapters",
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Manage-WindowsLanDnsGuard.ps1 -Action Status -IncludeAllPhysicalAdapters",
      "",
      "# 3. 临时停用代理或卸载时，精准移除全部 4 条规则",
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Manage-WindowsLanDnsGuard.ps1 -Action Remove"
    ].join("\n");
    lanOut.textContent = lanCmd;
    document.getElementById("copyLanDnsCmdBtn").onclick = () => copyText(lanCmd, "已复制 LAN DNS Guard 命令");

    if (res.error) {
      alertBox.innerHTML = `<div class="callout callout-danger"><strong>输入校验未通过：</strong>${escapeHtml(res.error)}</div>`;
      badge.textContent = "待修正参数";
      planOut.textContent = "// 请先修正上方参数后查看精确补集规则预览";
      cmdOut.textContent = "# 参数合法后将自动生成可直接执行的 PowerShell 命令";
      document.getElementById("copyKsCmdBtn").onclick = () => showToast("请先修正错误参数");
      return;
    }

    const alerts = [];
    if (res.dhcpMissingWarning) {
      alerts.push(
        `<div class="callout callout-danger" style="margin-bottom:8px;"><strong>高危阻断提醒（v0.3.8 强制保护）：</strong>你勾选了网卡使用 DHCP，但未填写 <code>-DhcpServer</code>！不填时封锁规则会覆盖广播地址与整个私网，租约续期将被阻断导致突然断网；<code>Manage-WindowsKillSwitch.ps1 -Action Install</code> 会自动拒绝执行。请补填路由器 DHCP 地址，或确认网卡确实使用静态 IP 后取消勾选。</div>`
      );
    }
    if (res.docSampleNotice) {
      alerts.push(
        `<div class="callout callout-warn" style="margin-bottom:8px;"><strong>示例地址提示：</strong>当前填写的 <code>${escapeHtml(res.upstreamIp)}</code> 属于 RFC 5737 文档示例段（仅供预览演示）。在真机运行 <code>Manage-WindowsKillSwitch.ps1</code> 前，请替换为实际代理节点的公网 IPv4（真实脚本会拒绝 TEST-NET 示例段）。</div>`
      );
    }
    if (!alerts.length) {
      alerts.push(
        `<div class="callout callout-ok"><strong>规划参数有效：</strong>将为 <code>${escapeHtml(res.aliases.join(", "))}</code> 计算精准 IPv4 补集阻断，仅放行 <code>${escapeHtml(res.upstreamIp)}:${res.port}/${res.protocol}</code>${res.dhcpServers.length ? " 及 DHCP 续租（" + escapeHtml(res.dhcpServers.join(", ")) + "）" : ""}。</div>`
      );
    }
    alertBox.innerHTML = alerts.join("");
    badge.textContent = "每张网卡 " + res.ruleSummaryCount + " 条显式阻断规则";
    planOut.textContent = JSON.stringify(res.previewJson, null, 2);

    const aliasPs = "@(" + res.aliases.map((a) => "'" + a.replace(/'/g, "''") + "'").join(", ") + ")";
    const dhcpLine = res.dhcpServers.length
      ? "  DhcpServer       = @(" + res.dhcpServers.map((d) => "'" + d + "'").join(", ") + ")\n"
      : "";
    const ksCmd = [
      "$settings = @{",
      "  InterfaceAlias   = " + aliasPs,
      "  UpstreamAddress  = '" + res.upstreamIp + "'",
      "  UpstreamPort     = " + res.port,
      "  UpstreamProtocol = '" + res.protocol + "'",
      dhcpLine + "}",
      "",
      "# 1. 普通权限只读预览（不改系统）",
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Manage-WindowsKillSwitch.ps1 -Action Preview @settings",
      "",
      "# 2. 管理员 PowerShell 安装并核对状态",
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Manage-WindowsKillSwitch.ps1 -Action Install @settings",
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Manage-WindowsKillSwitch.ps1 -Action Status @settings",
      "",
      "# 3. 随时一键精准卸载",
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\Manage-WindowsKillSwitch.ps1 -Action Remove"
    ].join("\n");
    cmdOut.textContent = ksCmd;
    document.getElementById("copyKsCmdBtn").onclick = () => copyText(ksCmd, "已复制 Windows 断网开关命令");
  }

  /* ==================== 渲染 Tab 4: 交互式自检清单 ==================== */
  function renderChecklist() {
    const catChips = document.getElementById("checkCategoryChips");
    const container = document.getElementById("checklistContainer");
    const progText = document.getElementById("checkProgressText");
    const progFill = document.getElementById("checkProgressFill");
    const statusBadge = document.getElementById("checkStatusBadge");
    if (!catChips || !container) return;

    const cats = ["全部", "Windows 网络与防火墙", "浏览器与客户端边界", "移动端 Android & iOS", "备份与应急验证"];
    catChips.innerHTML = cats.map((c) => {
      const list = c === "全部" ? CHECKLIST_ITEMS : CHECKLIST_ITEMS.filter((i) => i.cat === c);
      const done = list.filter((i) => checklistState[i.id]).length;
      return `<button type="button" class="chip ${c === activeCheckCat ? "active" : ""}" data-cat="${escapeHtml(c)}">${escapeHtml(c)} (${done}/${list.length})</button>`;
    }).join("");
    catChips.querySelectorAll(".chip").forEach((btn) => {
      btn.addEventListener("click", () => {
        activeCheckCat = btn.dataset.cat;
        renderChecklist();
      });
    });

    const totalDone = CHECKLIST_ITEMS.filter((i) => checklistState[i.id]).length;
    const pct = Math.round((totalDone / CHECKLIST_ITEMS.length) * 100);
    progText.textContent = `已完成 ${totalDone} / ${CHECKLIST_ITEMS.length} 项（${pct}%）`;
    progFill.style.width = pct + "%";
    if (pct === 100) {
      statusBadge.textContent = "全部验收通过";
      statusBadge.className = "badge badge-ok";
    } else if (pct >= 50) {
      statusBadge.textContent = "验收进行中";
      statusBadge.className = "badge badge-accent";
    } else {
      statusBadge.textContent = "建议按优先级逐项核对";
      statusBadge.className = "badge badge-warn";
    }

    const visible = activeCheckCat === "全部"
      ? CHECKLIST_ITEMS
      : CHECKLIST_ITEMS.filter((i) => i.cat === activeCheckCat);

    container.innerHTML = visible.map((item) => {
      const checked = Boolean(checklistState[item.id]);
      const pClass = item.priority === "高" ? "badge-danger" : "badge-accent";
      return `
        <label class="check-item ${checked ? "done" : ""}">
          <input type="checkbox" data-check-id="${item.id}" ${checked ? "checked" : ""}>
          <div style="flex:1;">
            <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
              <span class="check-title">${escapeHtml(item.title)}</span>
              <span class="badge ${pClass}">优先级：${escapeHtml(item.priority)}</span>
              <span class="badge">${escapeHtml(item.cat)}</span>
            </div>
            <div class="check-desc">${escapeHtml(item.desc)}</div>
          </div>
        </label>
      `;
    }).join("");

    container.querySelectorAll('input[type="checkbox"]').forEach((box) => {
      box.addEventListener("change", () => {
        checklistState[box.dataset.checkId] = box.checked;
        saveChecklistState(checklistState);
        renderChecklist();
      });
    });
  }

  function exportChecklistMarkdown() {
    const stamp = new Date().toISOString().slice(0, 10);
    const lines = [
      `# 跨平台网络隐私环境自检记录（${stamp}）`,
      "",
      `> 由跨平台网络隐私与本机环境工具包 v0.4.1 离线工作台本地导出，不含账号凭据或节点信息。`,
      ""
    ];
    CHECKLIST_ITEMS.forEach((item) => {
      const mark = checklistState[item.id] ? "x" : " ";
      lines.push(`- [${mark}] **[${item.cat} / 优先级：${item.priority}]** ${item.title}`);
    });
    downloadFile(`privacy-checklist-${stamp}.md`, lines.join("\n") + "\n", "text/markdown;charset=utf-8");
    showToast("已导出 Markdown 验收记录");
  }

  function exportChecklistJson() {
    const stamp = new Date().toISOString().slice(0, 10);
    const payload = {
      kitVersion: "0.4.1",
      exportedAt: new Date().toISOString(),
      completedCount: CHECKLIST_ITEMS.filter((i) => checklistState[i.id]).length,
      totalCount: CHECKLIST_ITEMS.length,
      items: CHECKLIST_ITEMS.map((item) => ({
        id: item.id,
        category: item.cat,
        priority: item.priority,
        title: item.title,
        checked: Boolean(checklistState[item.id])
      }))
    };
    downloadFile(`privacy-checklist-${stamp}.json`, JSON.stringify(payload, null, 2) + "\n", "application/json;charset=utf-8");
    showToast("已导出 JSON 验收记录");
  }

  /* ==================== 渲染 Tab 5: 报告视图 ==================== */
  function renderReportView() {
    const tbody = document.getElementById("boundaryTableBody");
    if (tbody) {
      tbody.innerHTML = BOUNDARY_ROWS.map((r) => `
        <tr>
          <td><strong>${escapeHtml(r.client)}</strong></td>
          <td>${escapeHtml(r.cold)}</td>
          <td>${escapeHtml(r.locale)}</td>
          <td>${escapeHtml(r.hw)}</td>
          <td>${escapeHtml(r.role)}</td>
        </tr>
      `).join("");
    }

    const mythEl = document.getElementById("mythContainer");
    if (mythEl) {
      mythEl.innerHTML = MYTHS.map((m, idx) => `
        <div class="myth-card">
          <button type="button" class="myth-trigger" data-myth="${idx}" aria-expanded="${idx === 0 ? "true" : "false"}">
            <span>${escapeHtml(m.q)}</span>
            <span class="badge badge-warn">${escapeHtml(m.verdict)}</span>
          </button>
          <div class="myth-body" id="myth-body-${idx}" style="display:${idx === 0 ? "block" : "none"};">
            ${escapeHtml(m.a)}
          </div>
        </div>
      `).join("");
      mythEl.querySelectorAll(".myth-trigger").forEach((btn) => {
        btn.addEventListener("click", () => {
          const idx = btn.dataset.myth;
          const body = document.getElementById("myth-body-" + idx);
          const isOpen = body.style.display !== "none";
          body.style.display = isOpen ? "none" : "block";
          btn.setAttribute("aria-expanded", String(!isOpen));
        });
      });
    }
  }

  /* ==================== 哈基米互动模块 ==================== */
  function showNextHajimiTip(animateAvatar) {
    tipIndex = (tipIndex + 1) % HAJIMI_TIPS.length;
    const box = document.getElementById("hajimiTipBox");
    const dockMsg = document.getElementById("hajimiDockMessage");
    if (box) box.textContent = "哈基米说：" + HAJIMI_TIPS[tipIndex];
    if (dockMsg) dockMsg.textContent = HAJIMI_TIPS[tipIndex];
    if (animateAvatar) {
      const avatar = document.getElementById("hajimiAvatar");
      if (avatar) {
        avatar.classList.add("boop");
        setTimeout(() => avatar.classList.remove("boop"), 260);
      }
    }
  }

  function initHajimi() {
    const box = document.getElementById("hajimiTipBox");
    if (box) box.textContent = "哈基米说：" + HAJIMI_TIPS[0];
    const dockMsg = document.getElementById("hajimiDockMessage");
    if (dockMsg) dockMsg.textContent = TAB_DOCK_TIPS[activeTab];

    const pokeBtn = document.getElementById("pokeHajimiBtn");
    if (pokeBtn) pokeBtn.addEventListener("click", () => showNextHajimiTip(true));

    const fab = document.getElementById("hajimiFab");
    const pop = document.getElementById("hajimiPopover");
    const closeBtn = document.getElementById("closeHajimiBtn");
    const nextTipBtn = document.getElementById("dockNextTipBtn");
    const aboutBtn = document.getElementById("dockAboutBtn");

    if (fab && pop) {
      fab.addEventListener("click", () => {
        const open = pop.classList.toggle("open");
        fab.setAttribute("aria-expanded", String(open));
      });
    }
    if (closeBtn && pop && fab) {
      closeBtn.addEventListener("click", () => {
        pop.classList.remove("open");
        fab.setAttribute("aria-expanded", "false");
      });
    }
    if (nextTipBtn) {
      nextTipBtn.addEventListener("click", () => showNextHajimiTip(false));
    }
    if (aboutBtn && pop && fab) {
      aboutBtn.addEventListener("click", () => {
        pop.classList.remove("open");
        fab.setAttribute("aria-expanded", "false");
        switchTab("overview");
        setTimeout(() => {
          const sec = document.getElementById("hajimiSection");
          if (sec) sec.scrollIntoView({ behavior: "smooth", block: "center" });
        }, 120);
      });
    }
  }

  /* ==================== 初始化入口 ==================== */
  function init() {
    initTheme();

    if (typeof window !== "undefined" && window.location && window.location.protocol === "file:") {
      document.querySelectorAll("a[data-local-href]").forEach((anchor) => {
        anchor.setAttribute("href", anchor.dataset.localHref);
        anchor.removeAttribute("target");
      });
    }

    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });
    document.querySelectorAll("[data-jump]").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.jump));
    });

    renderPlatforms();
    renderLayers();
    renderRouting();
    renderDomainExplorer();
    renderFirewallPlanner();
    renderChecklist();
    renderReportView();
    initHajimi();

    ["ksInterfaces", "ksUpstreamIp", "ksPort", "ksProto", "ksDhcp", "ksUsesDhcp"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener("input", renderFirewallPlanner);
        el.addEventListener("change", renderFirewallPlanner);
      }
    });

    const expMd = document.getElementById("exportCheckMdBtn");
    const expJson = document.getElementById("exportCheckJsonBtn");
    const resetBtn = document.getElementById("resetCheckBtn");
    if (expMd) expMd.addEventListener("click", exportChecklistMarkdown);
    if (expJson) expJson.addEventListener("click", exportChecklistJson);
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        checklistState = {};
        saveChecklistState(checklistState);
        renderChecklist();
        showToast("已重置全部勾选状态");
      });
    }
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      buildRoutingRules,
      computeKillSwitchPlan,
      CLAUDE_ECOSYSTEM_DOMAINS,
      LOCAL_NETWORKS,
      ANTHROPIC_IPV6_BLOCK,
      ANTHROPIC_IPV4_CIDRS
    };
  } else if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
