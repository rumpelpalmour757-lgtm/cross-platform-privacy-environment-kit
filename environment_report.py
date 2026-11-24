"""Collect a local, read-only desktop environment report."""

import argparse
from datetime import datetime, timezone
import html
import json
import locale
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys

import audit_client_boundary
from config_snapshot import SnapshotError, checked_stat


ROOT = Path(__file__).resolve().parent
KIT_VERSION = "0.4.1"

STATUS_META = {
    "pass": ("已通过", "pass"),
    "gap": ("存在缺口", "gap"),
    "unknown": ("未知盲区", "unknown"),
}

TIER_META = {
    "observed_local": "本机观测",
    "static_config": "静态配置",
    "external_blind_spot": "外部盲区",
}

CHECK_LABELS_ZH = {
    "network_collector": "本机网络与系统观测采集",
    "routing_and_ipv6_surface": "默认路由与 IPv6 暴露面",
    "system_dns_observations": "系统 DNS 与加密传输观测",
    "firewall_and_fail_closed": "防火墙默认出站与断线兜底",
    "host_client_boundary": "宿主机原生客户端边界",
    "cli_anti_telemetry_switches": "CLI 5 项防后台外联开关",
    "local_mcp_host_bridges": "本地 MCP 与宿主机桥接工具",
    "claude_local_data_audit": "本地 Claude 数据脱敏盘点",
    "exit_ip_reputation": "出口 IP 历史信誉与代理库标记",
    "runtime_environment_and_policy_boundaries": "运行态图形 / TPM 健康度与平台合规边界",
}

IPV6_DEFAULT_PREFIXES = {"::/0", "::/1", "8000::/1"}


def _decode_json_bytes(raw):
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        encoding = locale.getpreferredencoding(False) or "utf-8"
        return raw.decode(encoding)


def _windows_powershell(system_root):
    root = Path(system_root)
    powershell_path = Path("WindowsPowerShell") / "v1.0" / "powershell.exe"
    if os.environ.get("PROCESSOR_ARCHITEW6432"):
        # Sysnative is Windows' native system directory alias for WOW64 processes.
        sysnative = root / "Sysnative" / powershell_path
        if sysnative.is_file():
            return str(sysnative)
    return str(root / "System32" / powershell_path)


def _ensure_unlinked_script(script_path):
    try:
        info = checked_stat(script_path)
        return stat.S_ISREG(info.st_mode)
    except (OSError, SnapshotError):
        return False


def capture_json(command):
    try:
        run_kwargs = {
            "stdin": subprocess.DEVNULL,
            "capture_output": True,
            "timeout": 70,
            "check": False,
        }
        if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
            run_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(command, **run_kwargs)
    except (OSError, subprocess.SubprocessError):
        return {"status": "unavailable", "reason": "collector-start-or-timeout"}
    if result.returncode != 0:
        return {"status": "unavailable", "reason": "collector-exit", "exitCode": result.returncode}
    try:
        data = json.loads(_decode_json_bytes(result.stdout))
    except (UnicodeError, ValueError):
        return {"status": "unavailable", "reason": "invalid-collector-output"}
    if not isinstance(data, dict):
        return {"status": "unavailable", "reason": "unexpected-collector-shape"}
    return {"status": "collected", "data": data}


def _collect_client_boundary(system, config_dir=None):
    boundary_script = ROOT / "audit_client_boundary.py"
    if not _ensure_unlinked_script(boundary_script):
        return {"status": "unavailable", "reason": "collector-script-invalid"}
    try:
        data = audit_client_boundary.collect_boundary_audit(
            system=system,
            config_dir=config_dir,
        )
    except Exception:
        return {"status": "unavailable", "reason": "boundary-audit-error"}
    if not isinstance(data, dict):
        return {"status": "unavailable", "reason": "unexpected-collector-shape"}
    return {"status": "collected", "data": data}


def _make_check(check_id, category, title, status, evidence_tier, detail):
    return {
        "id": check_id,
        "category": category,
        "title": title,
        "status": status,
        "evidenceTier": evidence_tier,
        "detail": detail,
    }


def _has_observed_network_subsystem(network_data):
    if not isinstance(network_data, dict):
        return False
    if "Routing" in network_data or "Dns" in network_data or "Firewall" in network_data:
        routing = network_data.get("Routing") if isinstance(network_data.get("Routing"), dict) else {}
        dns = network_data.get("Dns") if isinstance(network_data.get("Dns"), dict) else {}
        firewall = network_data.get("Firewall") if isinstance(network_data.get("Firewall"), dict) else {}
        return (
            routing.get("ActiveStore") == "observed"
            or dns.get("AdapterResolvers") == "observed"
            or firewall.get("ActiveStore") == "observed"
        )
    if "default_routes" in network_data or "dns_configuration" in network_data:
        routes = network_data.get("default_routes") if isinstance(network_data.get("default_routes"), dict) else {}
        ipv4 = routes.get("ipv4") if isinstance(routes.get("ipv4"), dict) else {}
        ipv6 = routes.get("ipv6") if isinstance(routes.get("ipv6"), dict) else {}
        dns = network_data.get("dns_configuration") if isinstance(network_data.get("dns_configuration"), dict) else {}
        return (
            ipv4.get("status") == "observed"
            or ipv6.get("status") == "observed"
            or dns.get("status") == "observed"
        )
    return False


def _unix_route_interface_types(route_obj):
    if not isinstance(route_obj, dict):
        return set()
    mapping = route_obj.get("candidate_interface_types")
    if not isinstance(mapping, dict):
        mapping = route_obj.get("interface_types")
    if not isinstance(mapping, dict):
        return set()
    return {key for key, count in mapping.items() if count}


def _evaluate_routing_check(network_data):
    if not isinstance(network_data, dict):
        return _make_check(
            "routing_and_ipv6_surface",
            "network",
            "Default route and IPv6 surface",
            "unknown",
            "observed_local",
            "Network collector data unavailable; routing and IPv6 surface were not observed.",
        )
    if "Routing" in network_data:
        routing = network_data.get("Routing")
        if not isinstance(routing, dict) or routing.get("ActiveStore") != "observed":
            return _make_check(
                "routing_and_ipv6_surface",
                "network",
                "Default route and IPv6 surface",
                "unknown",
                "observed_local",
                "Windows ActiveStore routing table could not be observed.",
            )
        candidates = [
            row for row in (routing.get("Candidates") or [])
            if isinstance(row, dict)
        ]
        active_v4 = [
            row for row in candidates
            if row.get("AddressFamily") == "IPv4" and row.get("InterfaceState") != "Disconnected"
        ]
        active_v6 = [
            row for row in candidates
            if row.get("AddressFamily") == "IPv6"
            and row.get("InterfaceState") != "Disconnected"
            and row.get("DestinationPrefix") in IPV6_DEFAULT_PREFIXES
        ]
        if active_v6:
            return _make_check(
                "routing_and_ipv6_surface",
                "network",
                "Default route and IPv6 surface",
                "gap",
                "observed_local",
                f"Observed {len(active_v6)} active IPv6 default/split-default route candidate(s); "
                "confirm IPv6 is tunnelled or blocked to prevent dual-stack bypass or 502 errors.",
            )
        if active_v4:
            return _make_check(
                "routing_and_ipv6_surface",
                "network",
                "Default route and IPv6 surface",
                "pass",
                "observed_local",
                f"Observed {len(active_v4)} active IPv4 default/split-default route candidate(s) and 0 active "
                "IPv6 default route candidates; live proxy exit still requires Test-ProxyState.ps1.",
            )
        return _make_check(
            "routing_and_ipv6_surface",
            "network",
            "Default route and IPv6 surface",
            "gap",
            "observed_local",
            "No active IPv4 default or split-default route candidate was observed.",
        )

    if "default_routes" in network_data:
        default_routes = network_data.get("default_routes") or {}
        split_routes = network_data.get("split_tunnel_routes") or {}
        ipv4 = default_routes.get("ipv4") if isinstance(default_routes, dict) else None
        ipv6 = default_routes.get("ipv6") if isinstance(default_routes, dict) else None
        if not isinstance(ipv4, dict) or ipv4.get("status") != "observed":
            return _make_check(
                "routing_and_ipv6_surface",
                "network",
                "Default route and IPv6 surface",
                "unknown",
                "observed_local",
                "Local IPv4 route table could not be observed.",
            )
        v4_types = _unix_route_interface_types(ipv4)
        split_v4 = split_routes.get("ipv4") if isinstance(split_routes, dict) else None
        if isinstance(split_v4, dict):
            v4_types.update(_unix_route_interface_types(split_v4))
        v6_types = set()
        v6_active = False
        if isinstance(ipv6, dict) and ipv6.get("status") == "observed":
            v6_active = (ipv6.get("forwarding_candidate_count") or 0) > 0
            v6_types.update(_unix_route_interface_types(ipv6))
        split_v6 = split_routes.get("ipv6") if isinstance(split_routes, dict) else None
        if isinstance(split_v6, dict):
            if split_v6.get("status") == "observed" and (split_v6.get("forwarding_candidate_count") or 0) > 0:
                v6_active = True
            v6_types.update(_unix_route_interface_types(split_v6))
        if v6_active and "tunnel_candidate" not in v6_types:
            return _make_check(
                "routing_and_ipv6_surface",
                "network",
                "Default route and IPv6 surface",
                "gap",
                "observed_local",
                "Active non-tunnel IPv6 default route candidate observed; confirm IPv6 is tunnelled or blocked.",
            )
        if "tunnel_candidate" in v4_types:
            return _make_check(
                "routing_and_ipv6_surface",
                "network",
                "Default route and IPv6 surface",
                "pass",
                "observed_local",
                "Tunnel interface candidate observed in local IPv4 routes; policy-routing precedence is not tested.",
            )
        return _make_check(
            "routing_and_ipv6_surface",
            "network",
            "Default route and IPv6 surface",
            "gap",
            "observed_local",
            "No tunnel interface candidate observed in local IPv4 default or split-tunnel routes.",
        )

    return _make_check(
        "routing_and_ipv6_surface",
        "network",
        "Default route and IPv6 surface",
        "unknown",
        "observed_local",
        "Unrecognized routing snapshot shape.",
    )


def _evaluate_dns_check(network_data):
    if not isinstance(network_data, dict):
        return _make_check(
            "system_dns_observations",
            "network",
            "System DNS and encrypted transport",
            "unknown",
            "observed_local",
            "Network collector data unavailable; DNS configuration was not observed.",
        )
    if "Dns" in network_data:
        dns = network_data.get("Dns")
        if not isinstance(dns, dict) or dns.get("AdapterResolvers") != "observed":
            return _make_check(
                "system_dns_observations",
                "network",
                "System DNS and encrypted transport",
                "unknown",
                "observed_local",
                "Windows adapter DNS resolvers could not be observed.",
            )
        interfaces = [row for row in (dns.get("Interfaces") or []) if isinstance(row, dict)]
        strict_doh = any(
            (row.get("AutoUpgradeCount") or 0) > 0 and (row.get("AutoUpgradeWithFallback") or 0) == 0
            for row in interfaces
        )
        if strict_doh:
            return _make_check(
                "system_dns_observations",
                "network",
                "System DNS and encrypted transport",
                "pass",
                "observed_local",
                "At least one adapter registers OS-level DoH auto-upgrade without UDP fallback; "
                "browser and app private DNS traffic remain unobserved.",
            )
        return _make_check(
            "system_dns_observations",
            "network",
            "System DNS and encrypted transport",
            "unknown",
            "observed_local",
            "Adapter resolvers observed without strict OS-level DoH auto-upgrade; live proxy DoH, "
            "LAN port-53 guard status, and browser DNS traffic are not verified statically.",
        )

    if "dns_configuration" in network_data:
        dns = network_data.get("dns_configuration")
        if not isinstance(dns, dict) or dns.get("status") != "observed":
            return _make_check(
                "system_dns_observations",
                "network",
                "System DNS and encrypted transport",
                "unknown",
                "observed_local",
                "Local Unix resolver configuration could not be observed.",
            )
        source = dns.get("source") or "local"
        count = dns.get("configured_resolver_count", 0)
        return _make_check(
            "system_dns_observations",
            "network",
            "System DNS and encrypted transport",
            "unknown",
            "observed_local",
            f"Observed {count} configured resolver(s) via {source} (dns_transport_tested=false); "
            "encrypted DNS transport and browser/app DNS are not tested by read-only snapshots.",
        )

    return _make_check(
        "system_dns_observations",
        "network",
        "System DNS and encrypted transport",
        "unknown",
        "observed_local",
        "DNS configuration data was not present in network snapshot.",
    )


def _evaluate_firewall_check(platform_name, network_data):
    if platform_name != "Windows":
        return _make_check(
            "firewall_and_fail_closed",
            "firewall",
            "Firewall outbound policy and fail-closed verification",
            "unknown",
            "observed_local",
            f"Windows Firewall checks do not apply on {platform_name}; verify pf/nftables/iptables separately.",
        )
    if not isinstance(network_data, dict):
        return _make_check(
            "firewall_and_fail_closed",
            "firewall",
            "Firewall outbound policy and fail-closed verification",
            "unknown",
            "observed_local",
            "Windows network evidence unavailable; firewall profiles were not observed.",
        )
    firewall = network_data.get("Firewall")
    if not isinstance(firewall, dict) or firewall.get("ActiveStore") != "observed":
        return _make_check(
            "firewall_and_fail_closed",
            "firewall",
            "Firewall outbound policy and fail-closed verification",
            "unknown",
            "observed_local",
            "Windows Firewall ActiveStore profiles could not be observed.",
        )
    profiles = [row for row in (firewall.get("Profiles") or []) if isinstance(row, dict)]
    if not profiles:
        return _make_check(
            "firewall_and_fail_closed",
            "firewall",
            "Firewall outbound policy and fail-closed verification",
            "unknown",
            "observed_local",
            "No Windows Firewall profile entries were returned.",
        )
    disabled = [str(row.get("Profile") or "?") for row in profiles if str(row.get("Enabled")) != "True"]
    if disabled:
        return _make_check(
            "firewall_and_fail_closed",
            "firewall",
            "Firewall outbound policy and fail-closed verification",
            "gap",
            "observed_local",
            f"Disabled Windows Firewall profile(s): {', '.join(disabled)}.",
        )
    allow_profiles = [
        str(row.get("Profile") or "?")
        for row in profiles
        if str(row.get("DefaultOutboundAction")) != "Block"
    ]
    if allow_profiles:
        return _make_check(
            "firewall_and_fail_closed",
            "firewall",
            "Firewall outbound policy and fail-closed verification",
            "gap",
            "observed_local",
            f"DefaultOutboundAction is not Block on {', '.join(allow_profiles)} "
            "(normal for split mode; enable Manage-WindowsKillSwitch.ps1 for strict fail-closed blocking).",
        )
    if network_data.get("FailClosedVerified") is True:
        return _make_check(
            "firewall_and_fail_closed",
            "firewall",
            "Firewall outbound policy and fail-closed verification",
            "pass",
            "observed_local",
            "All firewall profiles default-block outbound traffic and fail-closed verification is recorded.",
        )
    return _make_check(
        "firewall_and_fail_closed",
        "firewall",
        "Firewall outbound policy and fail-closed verification",
        "unknown",
        "observed_local",
        "All active firewall profiles default-block outbound, but live disconnect verification and explicit "
        "Allow-rule bypasses (such as MSIX Claude.exe) require Inspect-WindowsFirewall.ps1 and a disconnect drill.",
    )


def build_tri_state_summary(report):
    platform_name = report.get("platform") or "unknown"
    network = report.get("network") if isinstance(report.get("network"), dict) else {}
    network_data = network.get("data") if network.get("status") == "collected" and isinstance(network.get("data"), dict) else None
    boundary = report.get("clientBoundary") if isinstance(report.get("clientBoundary"), dict) else {}
    boundary_data = boundary.get("data") if boundary.get("status") == "collected" and isinstance(boundary.get("data"), dict) else None
    local_data = report.get("claudeLocalData") if isinstance(report.get("claudeLocalData"), dict) else {}
    local_payload = local_data.get("data") if local_data.get("status") == "collected" and isinstance(local_data.get("data"), dict) else None

    checks = []
    if network_data is not None and _has_observed_network_subsystem(network_data):
        checks.append(_make_check(
            "network_collector",
            "network",
            "Local network evidence collection",
            "pass",
            "observed_local",
            f"Read-only local network observations collected for {platform_name}.",
        ))
    elif network_data is not None:
        checks.append(_make_check(
            "network_collector",
            "network",
            "Local network evidence collection",
            "unknown",
            "observed_local",
            f"Network collector returned no observed routing, DNS, or firewall subsystem on {platform_name}.",
        ))
    else:
        reason = network.get("reason") or network.get("status") or "missing"
        checks.append(_make_check(
            "network_collector",
            "network",
            "Local network evidence collection",
            "unknown",
            "observed_local",
            f"Network collector unavailable ({reason}); network state was not verified.",
        ))

    checks.append(_evaluate_routing_check(network_data))
    checks.append(_evaluate_dns_check(network_data))
    checks.append(_evaluate_firewall_check(platform_name, network_data))

    if boundary_data is None:
        reason = boundary.get("reason") or boundary.get("status") or "missing"
        checks.append(_make_check(
            "host_client_boundary",
            "client_boundary",
            "Host native client boundary",
            "unknown",
            "static_config",
            f"Client boundary audit unavailable ({reason}).",
        ))
        checks.append(_make_check(
            "cli_anti_telemetry_switches",
            "client_boundary",
            "Claude CLI 5 anti-telemetry switches",
            "unknown",
            "static_config",
            f"Client boundary audit unavailable ({reason}).",
        ))
        checks.append(_make_check(
            "local_mcp_host_bridges",
            "client_boundary",
            "Local MCP / host-tool bridges",
            "unknown",
            "static_config",
            f"Client boundary audit unavailable ({reason}).",
        ))
    else:
        footprints = boundary_data.get("localClientFootprints") or {}
        has_desktop = bool(
            footprints.get("claudeDesktopDataPresent") or footprints.get("claudeDesktopMsixPresent")
        )
        has_cli = bool(
            footprints.get("claudeCliConfigDirPresent") or footprints.get("claudeCliStateFilePresent")
        )
        if has_desktop or has_cli:
            present_parts = []
            if has_desktop:
                present_parts.append("Desktop")
            if has_cli:
                present_parts.append("CLI")
            checks.append(_make_check(
                "host_client_boundary",
                "client_boundary",
                "Host native client boundary",
                "gap",
                "static_config",
                f"Native host Claude footprint detected ({', '.join(present_parts)}). Native clients read host OS "
                "timezone and locale directly; keep isolated browser profiles strictly separated.",
            ))
        else:
            checks.append(_make_check(
                "host_client_boundary",
                "client_boundary",
                "Host native client boundary",
                "pass",
                "static_config",
                "No native Claude Desktop or CLI data footprint detected in default host locations.",
            ))

        flags = boundary_data.get("cliAntiTelemetryFlags") or {}
        if not has_cli:
            checks.append(_make_check(
                "cli_anti_telemetry_switches",
                "client_boundary",
                "Claude CLI 5 anti-telemetry switches",
                "pass",
                "static_config",
                "No local Claude CLI footprint detected; CLI anti-telemetry switches are not required.",
            ))
        else:
            disabled_flags = [
                key[:-8] if key.endswith("_enabled") else key
                for key, enabled in flags.items()
                if not enabled
            ]
            if flags and not disabled_flags:
                checks.append(_make_check(
                    "cli_anti_telemetry_switches",
                    "client_boundary",
                    "Claude CLI 5 anti-telemetry switches",
                    "pass",
                    "static_config",
                    "All 5 CLI anti-telemetry and non-essential traffic switches are enabled.",
                ))
            else:
                missing_list = ", ".join(disabled_flags) if disabled_flags else "unverified"
                checks.append(_make_check(
                    "cli_anti_telemetry_switches",
                    "client_boundary",
                    "Claude CLI 5 anti-telemetry switches",
                    "gap",
                    "static_config",
                    f"Local Claude CLI detected with disabled anti-telemetry switch(es): {missing_list}.",
                ))

        mcp = boundary_data.get("localMcpBridges")
        if not isinstance(mcp, dict):
            checks.append(_make_check(
                "local_mcp_host_bridges",
                "client_boundary",
                "Local MCP / host-tool bridges",
                "unknown",
                "static_config",
                "Local MCP bridge summary missing from boundary audit.",
            ))
        else:
            desktop_mcp = int(mcp.get("claudeDesktopMcpServerCount") or 0)
            cli_mcp = int(mcp.get("claudeCliMcpServerCount") or 0)
            if desktop_mcp + cli_mcp > 0:
                checks.append(_make_check(
                    "local_mcp_host_bridges",
                    "client_boundary",
                    "Local MCP / host-tool bridges",
                    "gap",
                    "static_config",
                    f"Detected local MCP server config(s) (Desktop={desktop_mcp}, CLI={cli_mcp}). "
                    "Audit enabled bridges so host clock, timezone, or local filesystem metadata do not cross boundaries.",
                ))
            else:
                checks.append(_make_check(
                    "local_mcp_host_bridges",
                    "client_boundary",
                    "Local MCP / host-tool bridges",
                    "pass",
                    "static_config",
                    "No local Claude Desktop or CLI MCP server bridges configured.",
                ))

    if local_payload is not None:
        file_count = int(local_payload.get("files") or 0)
        byte_count = int(local_payload.get("bytes") or 0)
        checks.append(_make_check(
            "claude_local_data_audit",
            "local_data",
            "Redacted local Claude data inventory",
            "pass",
            "static_config",
            f"Inventory collected ({file_count} file(s), {byte_count} bytes); file contents were not read.",
        ))
    else:
        reason = local_data.get("reason") or local_data.get("status") or "missing"
        checks.append(_make_check(
            "claude_local_data_audit",
            "local_data",
            "Redacted local Claude data inventory",
            "unknown",
            "static_config",
            f"Local Claude data audit unavailable ({reason}).",
        ))

    checks.append(_make_check(
        "exit_ip_reputation",
        "external_blind_spot",
        "Exit IP historical reputation and proxy-pool databases",
        "unknown",
        "external_blind_spot",
        "Local offline reports never query external IP reputation or proxy-pool databases "
        "(such as Spur, IPQS, or MaxMind) or verify public exit history. Treat exit reputation as unknown.",
    ))
    checks.append(_make_check(
        "runtime_environment_and_policy_boundaries",
        "external_blind_spot",
        "Runtime GPU/TPM health and platform Terms/regional policy",
        "unknown",
        "external_blind_spot",
        "Network-layer zero-leak checks do not inspect runtime GPU/WebGL blocklists, hardware TPM attestation, "
        "virtualized desktop stability, or platform Terms of Service and regional eligibility.",
    ))

    counts = {"pass": 0, "gap": 0, "unknown": 0}
    tiers = {"observed_local": 0, "static_config": 0, "external_blind_spot": 0}
    for item in checks:
        counts[item["status"]] += 1
        tiers[item["evidenceTier"]] += 1

    blind_spots = [item["id"] for item in checks if item["status"] == "unknown"]
    return {
        "counts": counts,
        "totalChecks": len(checks),
        "evidenceTiers": tiers,
        "blindSpots": blind_spots,
        "checks": checks,
    }


def build_report(system, config_dir=None, project_dir=None, evidence_directory=None):
    report = {
        "schemaVersion": 2,
        "kitVersion": KIT_VERSION,
        "generatedAtUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": system,
        "scope": "Local observations only. No route, DNS, or disconnection guarantee.",
    }
    if system not in {"Windows", "Darwin", "Linux"}:
        report["status"] = "unsupported-platform"
        return report

    if system == "Windows":
        system_root = (os.environ.get("SystemRoot") or "").strip()
        win_collector = ROOT / "Collect-WindowsEvidence.ps1"
        if not system_root:
            report["network"] = {"status": "unavailable", "reason": "windows-system-root-unset"}
        elif not _ensure_unlinked_script(win_collector):
            report["network"] = {"status": "unavailable", "reason": "collector-script-invalid"}
        else:
            command = [
                _windows_powershell(system_root),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(win_collector),
            ]
            if evidence_directory is not None:
                # Preserve symlinks/junctions so Collect-WindowsEvidence.ps1 can reject reparse points.
                command.extend(["-EvidenceDirectory", os.path.abspath(evidence_directory)])
            report["network"] = capture_json(command)
    else:
        unix_collector = ROOT / "inspect_unix_network.py"
        if not _ensure_unlinked_script(unix_collector):
            report["network"] = {"status": "unavailable", "reason": "collector-script-invalid"}
        else:
            report["network"] = capture_json([sys.executable, "-B", str(unix_collector)])

    claude_script = ROOT / "claude_local_data.py"
    if not _ensure_unlinked_script(claude_script):
        report["claudeLocalData"] = {"status": "unavailable", "reason": "collector-script-invalid"}
    else:
        local_data = [sys.executable, "-B", str(claude_script), "audit"]
        if config_dir is not None:
            local_data.extend(["--config-dir", str(config_dir)])
        if project_dir is not None:
            local_data.extend(["--project-dir", str(project_dir)])
        report["claudeLocalData"] = capture_json(local_data)

    report["clientBoundary"] = _collect_client_boundary(system, config_dir=config_dir)
    report["summary"] = build_tri_state_summary(report)
    return report


def _escape(value):
    return html.escape(str(value), quote=True)


def render_html_report(report):
    summary = report.get("summary")
    if not isinstance(summary, dict):
        summary = build_tri_state_summary(report)
    counts = summary.get("counts") or {"pass": 0, "gap": 0, "unknown": 0}
    checks = summary.get("checks") or []
    boundary_wrap = report.get("clientBoundary") if isinstance(report.get("clientBoundary"), dict) else {}
    boundary = boundary_wrap.get("data") if isinstance(boundary_wrap.get("data"), dict) else {}
    host_env = boundary.get("hostEnvironment") if isinstance(boundary.get("hostEnvironment"), dict) else {}
    footprints = boundary.get("localClientFootprints") if isinstance(boundary.get("localClientFootprints"), dict) else {}
    anti_flags = boundary.get("cliAntiTelemetryFlags") if isinstance(boundary.get("cliAntiTelemetryFlags"), dict) else {}
    mcp = boundary.get("localMcpBridges") if isinstance(boundary.get("localMcpBridges"), dict) else {}
    notes = boundary.get("boundaryNotes") if isinstance(boundary.get("boundaryNotes"), list) else []

    rows_html = []
    for item in checks:
        check_id = str(item.get("id") or "")
        status = str(item.get("status") or "unknown")
        tier = str(item.get("evidenceTier") or "observed_local")
        status_zh, status_cls = STATUS_META.get(status, ("未知盲区", "unknown"))
        tier_zh = TIER_META.get(tier, tier)
        label_zh = CHECK_LABELS_ZH.get(check_id, str(item.get("title") or check_id))
        rows_html.append(
            "<tr>"
            f"<td><strong>{_escape(label_zh)}</strong><div class=\"code-sub\">{_escape(check_id)}</div></td>"
            f"<td><span class=\"pill pill-{_escape(status_cls)}\">{_escape(status_zh)} ({_escape(status)})</span></td>"
            f"<td><span class=\"tier\">{_escape(tier_zh)}</span></td>"
            f"<td>{_escape(item.get('detail') or '')}</td>"
            "</tr>"
        )

    flag_chips = []
    for key, enabled in anti_flags.items():
        short_key = key[:-8] if key.endswith("_enabled") else key
        cls = "pill-pass" if enabled else "pill-gap"
        state_txt = "ON" if enabled else "OFF"
        flag_chips.append(
            f"<span class=\"pill {cls}\">{_escape(short_key)}: {state_txt}</span>"
        )
    flags_html = " ".join(flag_chips) if flag_chips else "<span class=\"muted\">未采集</span>"

    notes_html = "".join(f"<li>{_escape(note)}</li>" for note in notes) or "<li>无额外提示。</li>"
    pretty_json = _escape(json.dumps(report, indent=2, ensure_ascii=False))

    platform_name = _escape(report.get("platform") or "unknown")
    generated_at = _escape(report.get("generatedAtUtc") or "unknown")
    kit_ver = _escape(report.get("kitVersion") or KIT_VERSION)
    tz_name = _escape(host_env.get("timezoneName", "unknown"))
    utc_offset = _escape(host_env.get("utcOffsetHours", "unknown"))
    detected_locale = _escape(host_env.get("detectedLocale", "unknown"))
    desktop_flag = "检测到" if (footprints.get("claudeDesktopDataPresent") or footprints.get("claudeDesktopMsixPresent")) else "未检测到"
    cli_flag = "检测到" if (footprints.get("claudeCliConfigDirPresent") or footprints.get("claudeCliStateFilePresent")) else "未检测到"
    mcp_summary = (
        f"Desktop {int(mcp.get('claudeDesktopMcpServerCount') or 0)} 项 / "
        f"CLI {int(mcp.get('claudeCliMcpServerCount') or 0)} 项"
        if mcp else "未采集"
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>跨平台网络隐私与本机边界体检报告（v{kit_ver}）</title>
  <style>
    :root {{
      --bg: #F6F4EE;
      --card: #FFFFFF;
      --ink: #1F2A44;
      --muted: #5B6478;
      --border: #DAD5C8;
      --accent: #1D5F8A;
      --pass-bg: #E6F4EE;
      --pass-ink: #176646;
      --gap-bg: #FCECE8;
      --gap-ink: #A3311E;
      --unk-bg: #F2EFE6;
      --unk-ink: #6D5417;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
      line-height: 1.6;
      padding: 28px 18px 48px;
    }}
    .wrap {{ max-width: 1020px; margin: 0 auto; }}
    .hero {{
      background: var(--card);
      border: 1px solid var(--border);
      border-top: 5px solid var(--accent);
      border-radius: 14px;
      padding: 22px 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .hero h1 {{ margin: 0 0 6px; font-size: 22px; }}
    .meta {{ color: var(--muted); font-size: 13.5px; }}
    .print-btn {{
      background: var(--accent);
      color: #fff;
      border: 0;
      border-radius: 8px;
      padding: 9px 15px;
      font-size: 13.5px;
      font-weight: 600;
      cursor: pointer;
    }}
    .print-btn:hover {{ opacity: 0.92; }}
    .kpis {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
      margin: 18px 0;
    }}
    .kpi {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 18px;
    }}
    .kpi-num {{ font-size: 28px; font-weight: 700; line-height: 1.2; }}
    .kpi-pass .kpi-num {{ color: var(--pass-ink); }}
    .kpi-gap .kpi-num {{ color: var(--gap-ink); }}
    .kpi-unk .kpi-num {{ color: var(--unk-ink); }}
    .kpi-label {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 20px;
      margin-top: 16px;
    }}
    .card h2 {{ margin: 0 0 10px; font-size: 17px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
    th, td {{
      text-align: left;
      padding: 10px 10px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    th {{ background: #F8F6F0; font-weight: 600; }}
    .code-sub {{
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 11.5px;
      color: var(--muted);
      margin-top: 2px;
    }}
    .pill {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      white-space: nowrap;
      margin: 2px 2px 2px 0;
    }}
    .pill-pass {{ background: var(--pass-bg); color: var(--pass-ink); }}
    .pill-gap {{ background: var(--gap-bg); color: var(--gap-ink); }}
    .pill-unknown {{ background: var(--unk-bg); color: var(--unk-ink); }}
    .tier {{
      display: inline-block;
      padding: 2px 7px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 12px;
      color: var(--muted);
      white-space: nowrap;
    }}
    .grid-2 {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }}
    .kv {{ font-size: 13.5px; }}
    .kv div {{ padding: 4px 0; border-bottom: 1px dashed var(--border); }}
    .kv strong {{ display: inline-block; min-width: 148px; }}
    .callout {{
      background: #FBF6EA;
      border: 1px solid #E3D3AD;
      border-left: 4px solid #B57B1C;
      border-radius: 8px;
      padding: 12px 14px;
      font-size: 13.5px;
    }}
    ul {{ margin: 8px 0 0; padding-left: 20px; font-size: 13.5px; }}
    details {{ margin-top: 10px; }}
    summary {{ cursor: pointer; font-weight: 600; font-size: 13.5px; color: var(--accent); }}
    pre {{
      background: #1B2436;
      color: #E8EEF8;
      padding: 14px;
      border-radius: 10px;
      overflow-x: auto;
      font-size: 12px;
      line-height: 1.5;
    }}
    .muted {{ color: var(--muted); }}
    footer {{
      margin-top: 22px;
      text-align: center;
      font-size: 12.5px;
      color: var(--muted);
    }}
    @media (max-width: 720px) {{
      .kpis, .grid-2 {{ grid-template-columns: 1fr; }}
    }}
    @media print {{
      body {{ background: #fff; padding: 0; }}
      .print-btn, details {{ display: none; }}
      .hero, .kpi, .card {{ box-shadow: none; break-inside: avoid; }}
      tr {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <h1>跨平台网络隐私与本机边界体检报告</h1>
        <div class="meta">
          平台：<strong>{platform_name}</strong> · 工具包版本：<strong>v{kit_ver}</strong> · 生成时间（UTC）：<strong>{generated_at}</strong><br>
          范围说明：仅本机只读脱敏观测，不含账号凭据、节点链接、本机用户名路径或 MCP 命令参数。
        </div>
      </div>
      <button type="button" class="print-btn" onclick="window.print()">打印 / 另存为 PDF</button>
    </section>

    <section class="kpis">
      <div class="kpi kpi-pass">
        <div class="kpi-num">{int(counts.get('pass', 0))}</div>
        <div class="kpi-label">已通过（pass）· 本机观测或配置符合预期</div>
      </div>
      <div class="kpi kpi-gap">
        <div class="kpi-num">{int(counts.get('gap', 0))}</div>
        <div class="kpi-label">存在缺口（gap）· 建议按需排查或加固</div>
      </div>
      <div class="kpi kpi-unk">
        <div class="kpi-num">{int(counts.get('unknown', 0))}</div>
        <div class="kpi-label">未知盲区（unknown）· 未测试或超出本机视角</div>
      </div>
    </section>

    <section class="card">
      <h2>三态安全核验摘要（通过 / 缺口 / 未知盲区）</h2>
      <table>
        <thead>
          <tr>
            <th style="width:24%;">核验项</th>
            <th style="width:17%;">状态</th>
            <th style="width:12%;">证据层级</th>
            <th>实测与边界说明</th>
          </tr>
        </thead>
        <tbody>
          {"".join(rows_html)}
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2>宿主机与客户端边界快照（已合并 audit_client_boundary）</h2>
      <div class="grid-2">
        <div class="kv">
          <div><strong>宿主机时区</strong> {tz_name}（UTC {utc_offset}）</div>
          <div><strong>宿主机区域语言</strong> {detected_locale}</div>
          <div><strong>原生 Desktop 足迹</strong> {_escape(desktop_flag)}</div>
          <div><strong>本地 CLI 足迹</strong> {_escape(cli_flag)}</div>
          <div><strong>本地 MCP 桥接数量</strong> {_escape(mcp_summary)}</div>
        </div>
        <div>
          <div style="font-size:13.5px; font-weight:600; margin-bottom:6px;">CLI 5 项防后台外联开关</div>
          <div>{flags_html}</div>
          <div style="font-size:13.5px; font-weight:600; margin:12px 0 4px;">边界提醒</div>
          <ul>{notes_html}</ul>
        </div>
      </div>
    </section>

    <section class="card">
      <h2>证据边界与工程提醒</h2>
      <div class="callout">
        <strong>不要把“未知盲区（unknown）”当成“已通过”：</strong><br>
        1. 本报告完全离线运行，不会查询外部出口 IP 信誉库或验证实时公网出口历史，因此 <code>exit_ip_reputation</code> 固定标为 <code>unknown</code>。<br>
        2. <strong>网络层零泄露不等于客户端或虚拟化环境无异常</strong>：无 GPU 加速或无 TPM 的虚拟机运行桌面客户端仍可能出现 WebGL 拉黑报错、<code>no_tpm</code> 降级或由本地 MCP / 宿主机桥接引入的跨界元信息。<br>
        3. 网络隐私工具包无法替代服务提供商的使用条款或地区政策，也不提供任何检测绕过方案。
      </div>
      <details>
        <summary>展开完整脱敏 JSON 原始观测数据（仅供排障核对）</summary>
        <pre>{pretty_json}</pre>
      </details>
    </section>

    <footer>
      Cross-Platform Privacy Environment Kit v{kit_ver} · MIT License · 100% 离线单文件报告（无外部 CDN）
    </footer>
  </div>
</body>
</html>
"""


def _write_text_safely(target_path, content):
    destination = Path(target_path)
    if os.path.islink(destination):
        raise ValueError(f"Refusing to write through symbolic link: {destination}")
    if destination.exists() and not destination.is_file():
        raise ValueError(f"Output path exists and is not a regular file: {destination}")
    parent = destination.parent
    if os.path.islink(parent):
        raise ValueError(f"Refusing to write into symbolic link directory: {parent}")
    parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_name(f".{destination.name}.{os.getpid()}.part")
    if os.path.islink(temp_path):
        raise ValueError(f"Refusing to overwrite symbolic link temp file: {temp_path}")
    try:
        with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temp_path, destination)
    finally:
        if temp_path.exists() and not os.path.islink(temp_path):
            try:
                temp_path.unlink()
            except OSError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, help="Override the Claude configuration directory.")
    parser.add_argument("--project-dir", type=Path, help="Inspect one explicit project configuration.")
    parser.add_argument("--evidence-directory", type=Path, help="Windows-only saved probe results.")
    parser.add_argument("--from-json", type=Path, help="Render from an existing redacted environment report JSON.")
    parser.add_argument("--json-out", type=Path, help="Write redacted JSON report to this file.")
    parser.add_argument("--html-out", type=Path, help="Write self-contained printable offline HTML report to this file.")
    parser.add_argument("--quiet", action="store_true", help="Suppress printing JSON to stdout.")
    args = parser.parse_args(argv)

    if args.from_json is not None:
        if not _ensure_unlinked_script(args.from_json):
            parser.error("--from-json must point to an unlinked regular JSON file")
        try:
            report = json.loads(args.from_json.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, ValueError) as exc:
            parser.error(f"Could not parse --from-json: {exc}")
        if not isinstance(report, dict):
            parser.error("--from-json must contain a JSON object")
        if "summary" not in report and report.get("status") != "unsupported-platform":
            report["summary"] = build_tri_state_summary(report)
    else:
        system = platform.system()
        if args.evidence_directory is not None and system != "Windows":
            parser.error("--evidence-directory is only supported on Windows")
        report = build_report(system, args.config_dir, args.project_dir, args.evidence_directory)

    serialized = json.dumps(report, indent=2, ensure_ascii=True)
    if args.json_out is not None:
        _write_text_safely(args.json_out, serialized + "\n")
    if args.html_out is not None:
        _write_text_safely(args.html_out, render_html_report(report))
    if not args.quiet:
        print(serialized)
    if report.get("status") == "unsupported-platform":
        return 2
    required_keys = ("network", "claudeLocalData", "clientBoundary")
    return 0 if all(
        isinstance(report.get(key), dict) and report[key].get("status") == "collected"
        for key in required_keys
    ) else 2


if __name__ == "__main__":
    sys.exit(main())
