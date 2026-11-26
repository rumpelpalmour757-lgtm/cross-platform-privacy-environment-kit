import contextlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import audit_client_boundary
from environment_report import (
    build_report,
    build_tri_state_summary,
    capture_json,
    main,
    render_html_report,
)
import inspect_unix_network


MAC_HEADER = "Destination Gateway Flags Netif Expire\n"


def checks_by_id(report):
    return {item["id"]: item for item in build_tri_state_summary(report)["checks"]}


def routing_check(network_data, platform_name="Linux"):
    report = {"platform": platform_name, "network": {"status": "collected", "data": network_data}}
    return checks_by_id(report)["routing_and_ipv6_surface"]


def unix_routes(ipv4_types, ipv6, split_ipv6=None, platform_key="linux", tunnel_split_prefixes=None):
    def observed(types):
        return {
            "status": "observed",
            "forwarding_candidate_count": sum(types.values()),
            "candidate_interface_types": types,
        }

    split = {"ipv4": observed({})}
    if split_ipv6 is not None:
        split["ipv6"] = observed(split_ipv6)
        if tunnel_split_prefixes is not None:
            split["ipv6"]["tunnel_split_prefixes"] = tunnel_split_prefixes
    return {
        "platform": platform_key,
        "default_routes": {
            "ipv4": observed(ipv4_types),
            "ipv6": observed(ipv6) if isinstance(ipv6, dict) and "status" not in ipv6 else ipv6,
        },
        "split_tunnel_routes": split,
    }


def boundary_report(data):
    return {"platform": "Linux", "clientBoundary": {"status": "collected", "data": data}}


def run_main_expecting_usage_error(test, arguments):
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr), test.assertRaises(SystemExit) as raised:
        main(arguments)
    test.assertEqual(raised.exception.code, 2)
    test.assertNotIn("Traceback", stderr.getvalue())
    return stderr.getvalue()


class ReportTests(unittest.TestCase):
    def test_unknown_platform_does_not_launch_anything(self):
        with patch("environment_report.capture_json") as run:
            self.assertEqual(build_report("Android")["status"], "unsupported-platform")
        run.assert_not_called()

    def test_unix_passes_paths_as_arguments(self):
        folder = Path("path with spaces")
        with patch("environment_report.capture_json", return_value={"status": "collected"}) as run:
            report = build_report("Darwin", config_dir=folder)
        self.assertEqual(report["network"]["status"], "collected")
        self.assertEqual(run.call_args_list[1].args[0][-2:], ["--config-dir", str(folder)])

    def test_windows_uses_system_powershell_and_explicit_evidence_path(self):
        with patch.dict(os.environ, {"SystemRoot": "C:/Windows"}):
            with patch("environment_report.capture_json", return_value={"status": "collected"}) as run:
                build_report("Windows", evidence_directory=Path("evidence"))
        first_call = run.call_args_list[0].args[0]
        self.assertTrue(first_call[0].lower().endswith("powershell.exe"))
        self.assertIn("Bypass", first_call)
        self.assertEqual(first_call[-2:], ["-EvidenceDirectory", os.path.abspath(Path("evidence"))])

    def test_windows_whitespace_system_root_is_unavailable(self):
        with patch.dict(os.environ, {"SystemRoot": "   "}):
            with patch("environment_report.capture_json", return_value={"status": "collected"}) as run:
                report = build_report("Windows")
        self.assertEqual(report["network"]["reason"], "windows-system-root-unset")
        self.assertEqual(run.call_count, 1)

    def test_windows_uses_sysnative_when_available_under_wow64(self):
        settings = {"SystemRoot": "C:/Windows", "PROCESSOR_ARCHITEW6432": "AMD64"}
        for available, expected_dir in ((True, "Sysnative"), (False, "System32")):
            with self.subTest(available=available), patch.dict(os.environ, settings), patch.object(
                Path, "is_file", return_value=available,
            ), patch("environment_report.capture_json", return_value={"status": "collected"}) as run:
                build_report("Windows")
                command = run.call_args_list[0].args[0]
                expected = Path("C:/Windows") / expected_dir / "WindowsPowerShell" / "v1.0" / "powershell.exe"
                self.assertEqual(command[0], str(expected))

    def test_utf8_bom_output_is_parsed(self):
        child = SimpleNamespace(returncode=0, stdout=b'\xef\xbb\xbf{"observed": true}')
        with patch("environment_report.subprocess.run", return_value=child):
            result = capture_json(["collector"])
        self.assertEqual(result, {"status": "collected", "data": {"observed": True}})

    def test_invalid_or_failed_output_is_not_copied(self):
        for exit_code, output in ((0, b"bad raw output"), (5, b'{"secret":"raw output"}')):
            child = SimpleNamespace(returncode=exit_code, stdout=output)
            with patch("environment_report.subprocess.run", return_value=child):
                result = capture_json(["collector"])
            self.assertEqual(result["status"], "unavailable")
            self.assertNotIn("raw output", json.dumps(result))

    def test_timed_out_collector_cannot_hang_report(self):
        with patch("environment_report.subprocess.run", side_effect=subprocess.TimeoutExpired("collector", 70)):
            self.assertEqual(capture_json(["collector"])["reason"], "collector-start-or-timeout")

    def test_build_report_merges_client_boundary_and_tri_state_summary(self):
        with patch("environment_report.capture_json", return_value={"status": "collected"}):
            report = build_report("Linux")
        self.assertEqual(report["schemaVersion"], 2)
        self.assertEqual(report["clientBoundary"]["status"], "collected")
        self.assertIn("localMcpBridges", report["clientBoundary"]["data"])
        summary = report["summary"]
        self.assertEqual(summary["totalChecks"], 10)
        self.assertEqual(
            sum(summary["counts"].values()),
            summary["totalChecks"],
        )
        checks_by_id = {item["id"]: item for item in summary["checks"]}
        self.assertEqual(checks_by_id["exit_ip_reputation"]["status"], "unknown")
        self.assertEqual(checks_by_id["exit_ip_reputation"]["evidenceTier"], "external_blind_spot")
        self.assertEqual(checks_by_id["runtime_environment_and_policy_boundaries"]["status"], "unknown")
        self.assertIn("exit_ip_reputation", summary["blindSpots"])

    def test_tri_state_summary_detects_windows_gaps_and_passes(self):
        sample = {
            "platform": "Windows",
            "network": {
                "status": "collected",
                "data": {
                    "Routing": {
                        "ActiveStore": "observed",
                        "Candidates": [
                            {"DestinationPrefix": "0.0.0.0/0", "AddressFamily": "IPv4", "InterfaceState": "Connected"},
                            {"DestinationPrefix": "::/0", "AddressFamily": "IPv6", "InterfaceState": "Connected"},
                        ],
                    },
                    "Dns": {
                        "AdapterResolvers": "observed",
                        "SystemRegistrations": "observed",
                        "Interfaces": [
                            {"ResolverCount": 1, "AutoUpgradeCount": 1, "AutoUpgradeWithFallback": 0},
                        ],
                    },
                    "Firewall": {
                        "ActiveStore": "observed",
                        "Profiles": [
                            {"Profile": "Private", "Enabled": "True", "DefaultOutboundAction": "Block"},
                            {"Profile": "Public", "Enabled": "True", "DefaultOutboundAction": "Block"},
                        ],
                    },
                    "FailClosedVerified": False,
                },
            },
            "clientBoundary": {
                "status": "collected",
                "data": {
                    "localClientFootprints": {
                        "claudeCliConfigDirPresent": True,
                        "claudeCliStateFilePresent": False,
                        "claudeDesktopDataPresent": False,
                        "claudeDesktopMsixPresent": False,
                    },
                    "cliAntiTelemetryFlags": {
                        "DISABLE_TELEMETRY_enabled": True,
                        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC_enabled": False,
                    },
                    "localMcpBridges": {
                        "claudeDesktopMcpConfigured": False,
                        "claudeDesktopMcpServerCount": 0,
                        "claudeCliMcpConfigured": True,
                        "claudeCliMcpServerCount": 2,
                    },
                },
            },
            "claudeLocalData": {
                "status": "collected",
                "data": {"files": 3, "bytes": 1024},
            },
        }
        summary = build_tri_state_summary(sample)
        checks = {item["id"]: item for item in summary["checks"]}
        self.assertEqual(checks["network_collector"]["status"], "pass")
        self.assertEqual(checks["routing_and_ipv6_surface"]["status"], "gap")
        self.assertEqual(checks["system_dns_observations"]["status"], "pass")
        self.assertEqual(checks["firewall_and_fail_closed"]["status"], "unknown")
        self.assertEqual(checks["host_client_boundary"]["status"], "gap")
        self.assertEqual(checks["cli_anti_telemetry_switches"]["status"], "gap")
        self.assertEqual(checks["local_mcp_host_bridges"]["status"], "gap")
        self.assertEqual(checks["claude_local_data_audit"]["status"], "pass")
        self.assertEqual(checks["exit_ip_reputation"]["status"], "unknown")
        self.assertEqual(checks["runtime_environment_and_policy_boundaries"]["status"], "unknown")

    def test_tri_state_summary_evaluates_unix_tunnel_and_unknown_dns(self):
        sample = {
            "platform": "Linux",
            "network": {
                "status": "collected",
                "data": {
                    "default_routes": {
                        "ipv4": {"status": "observed", "candidate_interface_types": {"tunnel_candidate": 1}},
                        "ipv6": {"status": "observed", "forwarding_candidate_count": 0, "candidate_interface_types": {}},
                    },
                    "split_tunnel_routes": {"ipv4": {"status": "observed", "candidate_interface_types": {}}},
                    "dns_configuration": {
                        "status": "observed",
                        "source": "systemd_resolved",
                        "configured_resolver_count": 1,
                        "dns_transport_tested": False,
                    },
                },
            },
            "clientBoundary": {
                "status": "collected",
                "data": {
                    "localClientFootprints": {
                        "claudeCliConfigDirPresent": False,
                        "claudeCliStateFilePresent": False,
                        "claudeDesktopDataPresent": False,
                        "claudeDesktopMsixPresent": False,
                    },
                    "cliAntiTelemetryFlags": {},
                    "localMcpBridges": {
                        "claudeDesktopMcpConfigured": False,
                        "claudeDesktopMcpServerCount": 0,
                        "claudeCliMcpConfigured": False,
                        "claudeCliMcpServerCount": 0,
                    },
                },
            },
            "claudeLocalData": {"status": "collected", "data": {"files": 0, "bytes": 0}},
        }
        summary = build_tri_state_summary(sample)
        checks = {item["id"]: item for item in summary["checks"]}
        self.assertEqual(checks["routing_and_ipv6_surface"]["status"], "pass")
        self.assertEqual(checks["system_dns_observations"]["status"], "unknown")
        self.assertEqual(checks["firewall_and_fail_closed"]["status"], "unknown")
        self.assertEqual(checks["host_client_boundary"]["status"], "pass")
        self.assertEqual(checks["cli_anti_telemetry_switches"]["status"], "pass")
        self.assertEqual(checks["local_mcp_host_bridges"]["status"], "pass")

    def test_all_unavailable_subsystems_mark_network_collector_unknown(self):
        sample = {
            "platform": "Windows",
            "network": {
                "status": "collected",
                "data": {
                    "Routing": {"ActiveStore": "unavailable"},
                    "Dns": {"AdapterResolvers": "unavailable"},
                    "Firewall": {"ActiveStore": "unavailable"},
                },
            },
            "clientBoundary": {"status": "unavailable"},
            "claudeLocalData": {"status": "unavailable"},
        }
        checks = {item["id"]: item for item in build_tri_state_summary(sample)["checks"]}
        self.assertEqual(checks["network_collector"]["status"], "unknown")

    def test_render_html_report_is_offline_printable_and_escapes_html(self):
        payload = {
            "schemaVersion": 2,
            "kitVersion": "0.4.2",
            "generatedAtUtc": "2026-11-23T14:30:00Z",
            "platform": "Windows",
            "network": {"status": "unavailable", "reason": "<script>alert(1)</script>"},
            "claudeLocalData": {"status": "unavailable", "reason": "none"},
            "clientBoundary": {
                "status": "collected",
                "data": {
                    "hostEnvironment": {
                        "timezoneName": "Asia/Taipei<img src=x>",
                        "utcOffsetHours": 8.0,
                        "detectedLocale": "zh_CN",
                    },
                    "localClientFootprints": {},
                    "cliAntiTelemetryFlags": {"DISABLE_TELEMETRY_enabled": True},
                    "localMcpBridges": {"claudeDesktopMcpServerCount": 0, "claudeCliMcpServerCount": 0},
                    "boundaryNotes": ["<b>note</b>"],
                },
            },
        }
        rendered = render_html_report(payload)
        self.assertIn("@media print", rendered)
        self.assertIn("window.print()", rendered)
        self.assertIn("未知盲区", rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertNotIn("<img src=x>", rendered)
        self.assertIsNone(re.search(r'<script[^>]+src=["\']https?://', rendered))
        self.assertIsNone(re.search(r'<link[^>]+href=["\']https?://', rendered))

    def test_cli_exports_json_and_html_from_saved_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_json = root / "in.json"
            out_json = root / "out.json"
            out_html = root / "out.html"
            source_json.write_text(
                json.dumps({
                    "schemaVersion": 2,
                    "platform": "Linux",
                    "network": {"status": "collected", "data": {}},
                    "claudeLocalData": {"status": "collected", "data": {"files": 0, "bytes": 0}},
                    "clientBoundary": {"status": "collected", "data": {"localMcpBridges": {}}},
                }),
                encoding="utf-8",
            )
            code = main([
                "--from-json", str(source_json),
                "--json-out", str(out_json),
                "--html-out", str(out_html),
                "--quiet",
            ])
            self.assertEqual(code, 0)
            saved = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertIn("summary", saved)
            html_text = out_html.read_text(encoding="utf-8")
            self.assertIn("跨平台网络隐私与本机边界体检报告", html_text)
            self.assertIn("exit_ip_reputation", html_text)

    def test_cli_refuses_symlink_html_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "real.html"
            target.write_text("keep", encoding="utf-8")
            link = root / "link.html"
            try:
                os.symlink(target, link)
            except OSError:
                self.skipTest("Symlink creation requires privilege on this host")
            source_json = root / "in.json"
            source_json.write_text(json.dumps({"platform": "Linux"}), encoding="utf-8")
            message = run_main_expecting_usage_error(
                self, ["--from-json", str(source_json), "--html-out", str(link), "--quiet"],
            )
            self.assertIn("symbolic link", message)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_cli_outputs_are_owner_only_and_replace_existing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_json = root / "in.json"
            source_json.write_text(json.dumps({"platform": "Linux"}), encoding="utf-8")
            out_json = root / "out.json"
            out_html = root / "out.html"
            out_json.write_text("old", encoding="utf-8")
            os.chmod(out_json, 0o644)
            main(["--from-json", str(source_json), "--json-out", str(out_json), "--html-out", str(out_html), "--quiet"])
            self.assertEqual(json.loads(out_json.read_text(encoding="utf-8"))["platform"], "Linux")
            self.assertIn("exit_ip_reputation", out_html.read_text(encoding="utf-8"))
            if os.name == "posix":
                for written in (out_json, out_html):
                    self.assertEqual(stat.S_IMODE(written.stat().st_mode), 0o600)
            self.assertEqual(sorted(entry.name for entry in root.iterdir()), ["in.json", "out.html", "out.json"])

    def test_cli_bad_output_target_is_one_error_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_json = root / "in.json"
            source_json.write_text(json.dumps({"platform": "Linux"}), encoding="utf-8")
            occupied = root / "occupied"
            occupied.mkdir()
            out_json = root / "out.json"
            message = run_main_expecting_usage_error(
                self,
                ["--from-json", str(source_json), "--json-out", str(out_json), "--html-out", str(occupied), "--quiet"],
            )
            self.assertIn("Could not write the report", message)
            self.assertFalse(out_json.exists())
            self.assertEqual(sorted(entry.name for entry in root.iterdir()), ["in.json", "occupied"])

    def test_cli_rejects_misshapen_saved_report_without_traceback(self):
        misshapen = {
            "summary-counts-text": {"platform": "Linux", "summary": {"counts": "abc", "checks": []}},
            "summary-checks-numbers": {"platform": "Linux", "summary": {"counts": {}, "checks": [1, 2]}},
            "count-not-a-number": {"platform": "Linux", "summary": {"counts": {"pass": "abc"}, "checks": []}},
            "mcp-count-text": boundary_report({"localMcpBridges": {"claudeCliMcpServerCount": "abc"}}),
            "mcp-count-infinite": boundary_report({"localMcpBridges": {"claudeCliMcpServerCount": float("inf")}}),
            "inventory-files-list": {
                "platform": "Linux", "claudeLocalData": {"status": "collected", "data": {"files": [1]}},
            },
            "windows-candidates-number": {
                "platform": "Windows",
                "network": {"status": "collected", "data": {"Routing": {"ActiveStore": "observed", "Candidates": 5}}},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_json = root / "in.json"
            out_json = root / "out.json"
            out_html = root / "out.html"
            arguments = [
                "--from-json", str(source_json), "--json-out", str(out_json), "--html-out", str(out_html), "--quiet",
            ]
            for name, payload in misshapen.items():
                with self.subTest(name):
                    source_json.write_text(json.dumps(payload), encoding="utf-8")
                    message = run_main_expecting_usage_error(self, arguments)
                    self.assertIn("--from-json", message)
                    self.assertFalse(out_json.exists())
                    self.assertFalse(out_html.exists())
            with self.subTest("lone-surrogate"):
                source_json.write_text(
                    '{"platform": "Linux", "network": {"status": "unavailable", "reason": "\\ud800"}}',
                    encoding="utf-8",
                )
                run_main_expecting_usage_error(self, arguments)
                self.assertFalse(out_json.exists())
            with self.subTest("deep-nesting"):
                source_json.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
                run_main_expecting_usage_error(self, arguments)
            with self.subTest("oversized"), patch("environment_report.MAX_REPORT_JSON_BYTES", 4):
                source_json.write_text(json.dumps({"platform": "Linux"}), encoding="utf-8")
                self.assertIn("larger", run_main_expecting_usage_error(self, arguments))


class RoutingSurfaceTests(unittest.TestCase):
    def test_macos_scoped_tunnel_rows_do_not_hide_native_ipv6_default(self):
        # IPv4-only tunnel, native IPv6 on the physical interface, system utun rows scoped (flag I).
        fixtures = {
            ("netstat", "-rn", "-f", "inet"): MAC_HEADER + (
                "default 10.8.0.1 UGScg utun4\ndefault 192.168.40.1 UGScIg en0\n"
            ),
            ("netstat", "-rn", "-f", "inet6"): MAC_HEADER + (
                "default fe80::1%en0 UGcg en0\n"
                "default fe80::%utun0 UcIg utun0\n"
                "default fe80::%utun1 UcIg utun1\n"
                "default fe80::%utun2 UcIg utun2\n"
            ),
        }
        data = inspect_unix_network.collect("Darwin", reader=lambda _: None, run=lambda *args: fixtures.get(args))
        check = routing_check(data, "Darwin")
        self.assertEqual(check["status"], "gap")
        self.assertIn("non-tunnel IPv6", check["detail"])
        self.assertIn("3 interface-scoped", check["detail"])

    def test_macos_tunnel_split_routes_over_native_ipv6_default(self):
        def check(ipv6_split_rows):
            fixtures = {
                ("netstat", "-rn", "-f", "inet"): MAC_HEADER + (
                    "default 192.168.40.1 UGScg en0\n0/1 198.18.0.1 UGSc utun4\n128.0/1 198.18.0.1 UGSc utun4\n"
                ),
                ("netstat", "-rn", "-f", "inet6"): MAC_HEADER + "default fe80::1%en0 UGcg en0\n" + ipv6_split_rows,
            }
            data = inspect_unix_network.collect("Darwin", reader=lambda _: None, run=lambda *args: fixtures.get(args))
            return routing_check(data, "Darwin")

        self.assertEqual(check("2000::/3 link#21 Uc utun4\n")["status"], "pass")
        self.assertEqual(check("::/1 link#21 Uc utun4\n8000::/1 link#21 Uc utun4\n")["status"], "pass")
        half = check("8000::/1 link#21 Uc utun4\n")
        self.assertEqual(half["status"], "unknown")
        self.assertIn("2000::/3", half["detail"])
        self.assertEqual(check("")["status"], "gap")

    def test_macos_only_scoped_ipv6_rows_leave_no_ipv6_surface(self):
        fixtures = {
            ("netstat", "-rn", "-f", "inet"): MAC_HEADER + "default 10.8.0.1 UGScg utun4\n",
            ("netstat", "-rn", "-f", "inet6"): MAC_HEADER + "default fe80::%utun0 UcIg utun0\n",
        }
        data = inspect_unix_network.collect("Darwin", reader=lambda _: None, run=lambda *args: fixtures.get(args))
        check = routing_check(data, "Darwin")
        self.assertEqual(check["status"], "pass")
        self.assertIn("no forwarding IPv6", check["detail"])

    def test_linux_mixed_ipv6_candidates_are_unknown(self):
        mixed = {"tunnel_candidate": 1, "wired_or_wifi_candidate": 1}
        check = routing_check(unix_routes(mixed, mixed))
        self.assertEqual(check["status"], "unknown")
        self.assertIn("precedence", check["detail"])
        split_mixed = routing_check(unix_routes(
            {"tunnel_candidate": 1}, {"wired_or_wifi_candidate": 1}, split_ipv6={"tunnel_candidate": 1},
        ))
        self.assertEqual(split_mixed["status"], "unknown")

    def test_macos_mixed_ipv6_candidates_follow_route_specificity(self):
        tunnel = {"tunnel_candidate": 1}
        physical = {"wired_or_wifi_candidate": 1}
        both_default = routing_check(
            unix_routes(tunnel, {"tunnel_candidate": 1, "wired_or_wifi_candidate": 1}, platform_key="macos"), "Darwin",
        )
        self.assertEqual(both_default["status"], "gap")
        for prefixes in (["2000::/3"], ["::/1", "8000::/1"], ["::/1"]):
            with self.subTest(prefixes):
                covered = routing_check(unix_routes(
                    tunnel, physical, split_ipv6=tunnel, platform_key="macos", tunnel_split_prefixes=prefixes,
                ), "Darwin")
                self.assertEqual(covered["status"], "pass")
                self.assertIn("cover global unicast", covered["detail"])
        # 8000::/1 alone leaves 2000::/3 on the physical default route; a saved report
        # without the prefix list cannot show coverage either.
        for prefixes in (["8000::/1"], None):
            with self.subTest(prefixes):
                uncovered = routing_check(unix_routes(
                    tunnel, physical, split_ipv6=tunnel, platform_key="macos", tunnel_split_prefixes=prefixes,
                ), "Darwin")
                self.assertEqual(uncovered["status"], "unknown")
                self.assertIn("not shown to cover global unicast", uncovered["detail"])
        split_physical = routing_check(unix_routes(tunnel, tunnel, split_ipv6=physical, platform_key="macos"), "Darwin")
        self.assertEqual(split_physical["status"], "gap")

    def test_single_kind_ipv6_candidates_keep_previous_results(self):
        tunnel = {"tunnel_candidate": 1}
        self.assertEqual(routing_check(unix_routes(tunnel, tunnel))["status"], "pass")
        self.assertEqual(routing_check(unix_routes(tunnel, {}))["status"], "pass")
        self.assertEqual(routing_check(unix_routes(tunnel, {"wired_or_wifi_candidate": 1}))["status"], "gap")
        self.assertEqual(routing_check(unix_routes({"wifi_candidate": 1}, {}))["status"], "gap")

    def test_unobserved_ipv6_table_is_unknown_unless_kernel_lacks_ipv6(self):
        tunnel = {"tunnel_candidate": 1}
        unreadable = routing_check(unix_routes(tunnel, {"status": "unavailable"}))
        self.assertEqual(unreadable["status"], "unknown")
        self.assertIn("IPv6 route table could not be observed", unreadable["detail"])
        missing = routing_check(unix_routes(tunnel, None))
        self.assertEqual(missing["status"], "unknown")
        no_stack = routing_check(unix_routes(
            tunnel, {"status": "unavailable", "reason": "address_family_unsupported"},
        ))
        self.assertEqual(no_stack["status"], "pass")
        self.assertIn("no IPv6 support", no_stack["detail"])
        no_tunnel = routing_check(unix_routes({"wifi_candidate": 1}, {"status": "unavailable"}))
        self.assertEqual(no_tunnel["status"], "gap")

    def test_windows_route_pass_says_tunnel_use_was_not_determined(self):
        check = routing_check({"Routing": {"ActiveStore": "observed", "Candidates": [
            {"DestinationPrefix": "0.0.0.0/0", "AddressFamily": "IPv4", "InterfaceState": "Connected"},
        ]}}, "Windows")
        self.assertEqual(check["status"], "pass")
        self.assertIn("was not determined", check["detail"])


class EvidenceCompletenessTests(unittest.TestCase):
    def _dns(self, rows):
        report = {
            "platform": "Windows",
            "network": {"status": "collected", "data": {"Dns": {"AdapterResolvers": "observed", "Interfaces": rows}}},
        }
        return checks_by_id(report)["system_dns_observations"]

    def test_windows_dns_passes_only_when_every_adapter_row_is_strict(self):
        strict = {"ResolverCount": 2, "AutoUpgradeCount": 2, "AutoUpgradeWithFallback": 0}
        empty = {"ResolverCount": 0, "AutoUpgradeCount": 0, "AutoUpgradeWithFallback": 0}
        self.assertEqual(self._dns([strict, empty])["status"], "pass")
        cases = {
            "another adapter is plain": [strict, {"ResolverCount": 1, "AutoUpgradeCount": 0, "AutoUpgradeWithFallback": 0}],
            "one resolver not upgraded": [{"ResolverCount": 2, "AutoUpgradeCount": 1, "AutoUpgradeWithFallback": 0}],
            "fallback allowed": [{"ResolverCount": 1, "AutoUpgradeCount": 1, "AutoUpgradeWithFallback": 1}],
            "resolver count missing": [{"AutoUpgradeCount": 1, "AutoUpgradeWithFallback": 0}],
            "registrations not observed": [{"ResolverCount": 1, "AutoUpgradeCount": None, "AutoUpgradeWithFallback": None}],
            "no adapter rows": [empty],
        }
        for name, rows in cases.items():
            with self.subTest(name):
                self.assertEqual(self._dns(rows)["status"], "unknown")
        self.assertIn("1 of 2", self._dns(cases["another adapter is plain"])["detail"])

    def _mcp(self, **bridges):
        return checks_by_id(boundary_report({"localMcpBridges": bridges}))["local_mcp_host_bridges"]

    def test_unreadable_mcp_config_is_unknown_instead_of_pass(self):
        unreadable = self._mcp(claudeDesktopMcpServerCount=0, claudeCliMcpServerCount=0, claudeCliMcpUnreadableConfigCount=1)
        self.assertEqual(unreadable["status"], "unknown")
        self.assertIn("1 config file(s) could not be read", unreadable["detail"])
        desktop = self._mcp(claudeDesktopMcpServerCount=0, claudeCliMcpServerCount=0, claudeDesktopMcpUnreadableConfigCount=1)
        self.assertEqual(desktop["status"], "unknown")
        partial = self._mcp(claudeDesktopMcpServerCount=0, claudeCliMcpServerCount=2, claudeCliMcpUnreadableConfigCount=1)
        self.assertEqual(partial["status"], "gap")
        self.assertIn("may be incomplete", partial["detail"])
        clean = self._mcp(claudeDesktopMcpServerCount=0, claudeCliMcpServerCount=0, claudeCliMcpUnreadableConfigCount=0)
        self.assertEqual(clean["status"], "pass")
        self.assertIn("--project-dir", clean["detail"])
        inspected = self._mcp(claudeDesktopMcpServerCount=0, claudeCliMcpServerCount=0, projectMcpConfigInspected=True)
        self.assertEqual(inspected["status"], "pass")
        self.assertNotIn("--project-dir", inspected["detail"])

    def test_boundary_audit_output_drives_the_mcp_result(self):
        server = {"command": "example-tool"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / ".claude.json"
            state.write_text(json.dumps({"projects": {"/work/demo": {"mcpServers": {"a": server}}}}), encoding="utf-8")
            counted = audit_client_boundary.collect_boundary_audit(system="Linux", home=root, env={})
            state.write_text('{"mcpServers": {"a": {}},}', encoding="utf-8")
            unreadable = audit_client_boundary.collect_boundary_audit(system="Linux", home=root, env={})
            state.unlink()
            project = root / "project"
            project.mkdir()
            (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"a": server}}), encoding="utf-8")
            with_project = audit_client_boundary.collect_boundary_audit(
                system="Linux", home=root, env={}, project_dir=project,
            )
        self.assertEqual(checks_by_id(boundary_report(counted))["local_mcp_host_bridges"]["status"], "gap")
        self.assertEqual(checks_by_id(boundary_report(unreadable))["local_mcp_host_bridges"]["status"], "unknown")
        self.assertEqual(checks_by_id(boundary_report(with_project))["local_mcp_host_bridges"]["status"], "gap")
        rendered = render_html_report(boundary_report(unreadable))
        self.assertIn("1 个配置文件未能读取", rendered)

    def test_build_report_passes_project_dir_to_boundary_audit(self):
        project = Path("project with spaces")
        with patch("environment_report.capture_json", return_value={"status": "collected"}), patch.object(
            audit_client_boundary, "collect_boundary_audit", return_value={},
        ) as audit:
            build_report("Linux", config_dir=Path("config"), project_dir=project)
        audit.assert_called_once_with(system="Linux", config_dir=Path("config"), project_dir=project)

    def _switches(self, read_state, enabled, undetermined=None):
        flags = {f"{key}_enabled": enabled for key in audit_client_boundary.CLI_ANTI_TELEMETRY_KEYS}
        data = {
            "localClientFootprints": {"claudeCliConfigDirPresent": True},
            "cliAntiTelemetryFlags": flags,
            "cliSettingsReadState": read_state,
        }
        if undetermined is not None:
            data["cliAntiTelemetryUndetermined"] = undetermined
        return checks_by_id(boundary_report(data))["cli_anti_telemetry_switches"], data

    def test_unreadable_cli_settings_make_switches_unknown_instead_of_gap(self):
        unreadable, data = self._switches("not_regular_file", False)
        self.assertEqual(unreadable["status"], "unknown")
        self.assertIn("could not be read (symbolic link or not a regular file)", unreadable["detail"])
        self.assertIn("settings.json 未能读取", render_html_report(boundary_report(data)))
        for state in ("too_large", "invalid_json", "unreadable"):
            with self.subTest(state):
                self.assertEqual(self._switches(state, False)[0]["status"], "unknown")
        self.assertEqual(self._switches("read", False)[0]["status"], "gap")
        self.assertEqual(self._switches("absent", False)[0]["status"], "gap")
        # A saved report from before the read state was recorded keeps its old result.
        self.assertEqual(self._switches(None, False)[0]["status"], "gap")
        self.assertEqual(self._switches(None, True)[0]["status"], "pass")
        # Values in an unread settings.json could still change a switch set in the environment.
        self.assertEqual(self._switches("not_regular_file", True)[0]["status"], "unknown")
        self.assertEqual(self._switches("read", True)[0]["status"], "pass")

    def test_undetermined_switches_are_unknown_instead_of_pass_or_gap(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                check, data = self._switches("read", enabled, undetermined=["DISABLE_TELEMETRY"])
                self.assertEqual(check["status"], "unknown")
                self.assertIn("could not be determined for: DISABLE_TELEMETRY", check["detail"])
        self.assertIn("DISABLE_TELEMETRY: 未确定", render_html_report(boundary_report(data)))
        self.assertEqual(self._switches("read", True, undetermined=[])[0]["status"], "pass")
        unread, _ = self._switches("not_regular_file", False, undetermined=["DISABLE_TELEMETRY"])
        self.assertEqual(unread["status"], "unknown")
        self.assertIn("Values not recognized as on or off: DISABLE_TELEMETRY.", unread["detail"])
        self.assertNotIn("environment: DISABLE_TELEMETRY,", unread["detail"])

    def test_incomplete_local_inventory_is_unknown_instead_of_pass(self):
        def inventory(**data):
            report = {"platform": "Linux", "claudeLocalData": {"status": "collected", "data": data}}
            return checks_by_id(report)["claude_local_data_audit"]

        skipped = inventory(files=0, bytes=0, unsafe_or_unavailable=1, user_config_present=False)
        self.assertEqual(skipped["status"], "unknown")
        self.assertIn("--config-dir", skipped["detail"])
        self.assertEqual(inventory(files=3, bytes=10, unsafe_or_unavailable=0)["status"], "pass")
        self.assertEqual(inventory(files=3, bytes=10)["status"], "pass")

    def test_html_scope_note_names_timezone_and_locale(self):
        rendered = render_html_report({"platform": "Linux"})
        scope_line = next(line for line in rendered.splitlines() if "范围说明" in line)
        self.assertIn("时区", scope_line)
        self.assertIn("区域语言", scope_line)


if __name__ == "__main__":
    unittest.main()
