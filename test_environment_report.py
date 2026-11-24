import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from environment_report import (
    build_report,
    build_tri_state_summary,
    capture_json,
    main,
    render_html_report,
)


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
                            {"AutoUpgradeCount": 1, "AutoUpgradeWithFallback": 0},
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
            "kitVersion": "0.4.1",
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
            with self.assertRaises(ValueError):
                main(["--from-json", str(source_json), "--html-out", str(link), "--quiet"])
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
