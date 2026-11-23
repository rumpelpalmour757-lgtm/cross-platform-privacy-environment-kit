from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import tempfile
import unittest

import audit_client_boundary as boundary


class ClientBoundaryAuditTests(unittest.TestCase):
    def test_empty_home_reports_no_footprints_and_no_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixed_time = datetime(2026, 11, 22, 12, 0, tzinfo=timezone(timedelta(hours=8)))
            report = boundary.collect_boundary_audit(
                system="Windows",
                home=Path(tmp),
                env={"APPDATA": str(Path(tmp) / "roaming"), "LOCALAPPDATA": str(Path(tmp) / "local")},
                now_local=fixed_time,
            )
        self.assertEqual(report["hostEnvironment"]["utcOffsetHours"], 8.0)
        self.assertFalse(report["localClientFootprints"]["claudeCliConfigDirPresent"])
        self.assertFalse(report["localClientFootprints"]["claudeDesktopDataPresent"])
        self.assertFalse(report["localClientFootprints"]["claudeDesktopMsixPresent"])
        self.assertFalse(report["environmentVariableFlags"]["ANTHROPIC_BASE_URL_set"])
        self.assertFalse(report["localMcpBridges"]["claudeDesktopMcpConfigured"])
        self.assertEqual(report["localMcpBridges"]["claudeDesktopMcpServerCount"], 0)
        self.assertFalse(report["localMcpBridges"]["claudeCliMcpConfigured"])
        self.assertEqual(report["localMcpBridges"]["claudeCliMcpServerCount"], 0)

    def test_detects_cli_desktop_msix_and_redacts_env_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".claude").mkdir()
            (root / ".claude.json").write_text("{}", encoding="utf-8")
            roaming = root / "Roaming"
            (roaming / "Claude").mkdir(parents=True)
            local = root / "Local"
            (local / "Packages" / "Claude_pzs8sxrjxfjjc").mkdir(parents=True)
            secret_url = "https://private-relay-secret.example.invalid/v1"
            report = boundary.collect_boundary_audit(
                system="Windows",
                home=root,
                env={
                    "APPDATA": str(roaming),
                    "LOCALAPPDATA": str(local),
                    "ANTHROPIC_BASE_URL": secret_url,
                    "HTTPS_PROXY": "http://127.0.0.1:10808",
                },
            )
        serialized = json.dumps(report)
        self.assertNotIn(secret_url, serialized)
        self.assertNotIn("10808", serialized)
        self.assertNotIn("pzs8sxrjxfjjc", serialized)
        self.assertTrue(report["localClientFootprints"]["claudeCliConfigDirPresent"])
        self.assertTrue(report["localClientFootprints"]["claudeCliStateFilePresent"])
        self.assertTrue(report["localClientFootprints"]["claudeDesktopDataPresent"])
        self.assertTrue(report["localClientFootprints"]["claudeDesktopMsixPresent"])
        self.assertTrue(report["environmentVariableFlags"]["ANTHROPIC_BASE_URL_set"])
        self.assertTrue(report["environmentVariableFlags"]["HTTPS_PROXY_set"])
        self.assertGreaterEqual(len(report["boundaryNotes"]), 3)
        self.assertFalse(report["cliAntiTelemetryFlags"]["DISABLE_TELEMETRY_enabled"])
        self.assertTrue(any("DISABLE_TELEMETRY=1" in note for note in report["boundaryNotes"]))

    def test_reads_cli_settings_anti_telemetry_switches_without_leaking_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli_dir = root / ".claude"
            cli_dir.mkdir()
            secret_token = "sk-ant-secret-never-emit"
            secret_base = "https://private-relay.example.invalid"
            (cli_dir / "settings.json").write_text(
                json.dumps({
                    "env": {
                        "ANTHROPIC_BASE_URL": secret_base,
                        "ANTHROPIC_API_KEY": secret_token,
                        "DISABLE_TELEMETRY": "1",
                        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                        "DISABLE_ERROR_REPORTING": "1",
                        "DISABLE_AUTOUPDATER": "1",
                        "DISABLE_GROWTHBOOK": "1",
                    }
                }),
                encoding="utf-8",
            )
            report = boundary.collect_boundary_audit(system="Linux", home=root, env={})
        serialized = json.dumps(report)
        self.assertNotIn(secret_token, serialized)
        self.assertNotIn(secret_base, serialized)
        self.assertTrue(report["environmentVariableFlags"]["ANTHROPIC_BASE_URL_set"])
        self.assertTrue(all(report["cliAntiTelemetryFlags"].values()))
        self.assertFalse(any("DISABLE_TELEMETRY=1" in note for note in report["boundaryNotes"]))

    def test_counts_local_mcp_bridges_without_leaking_server_names_or_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            roaming = root / "Roaming"
            desktop_dir = roaming / "Claude"
            desktop_dir.mkdir(parents=True)
            custom_cli = root / "custom-cli"
            custom_cli.mkdir()
            secret_server = "private_clock_bridge_secret"
            secret_cmd = "C:/secret/host-clock-tool.exe"
            (desktop_dir / "claude_desktop_config.json").write_text(
                json.dumps({
                    "mcpServers": {
                        secret_server: {"command": secret_cmd, "args": ["--tz"]},
                    }
                }),
                encoding="utf-8",
            )
            (custom_cli / "settings.json").write_text(
                json.dumps({
                    "mcpServers": {
                        "cli_secret_bridge_a": {"command": "python", "args": ["a.py"]},
                        "cli_secret_bridge_b": {"url": "http://127.0.0.1:9999/sse"},
                    }
                }),
                encoding="utf-8",
            )
            report = boundary.collect_boundary_audit(
                system="Windows",
                home=root,
                env={"APPDATA": str(roaming), "LOCALAPPDATA": str(root / "Local")},
                config_dir=custom_cli,
            )
        serialized = json.dumps(report)
        self.assertNotIn(secret_server, serialized)
        self.assertNotIn(secret_cmd, serialized)
        self.assertNotIn("cli_secret_bridge_a", serialized)
        self.assertNotIn("9999", serialized)
        self.assertTrue(report["localMcpBridges"]["claudeDesktopMcpConfigured"])
        self.assertEqual(report["localMcpBridges"]["claudeDesktopMcpServerCount"], 1)
        self.assertTrue(report["localMcpBridges"]["claudeCliMcpConfigured"])
        self.assertEqual(report["localMcpBridges"]["claudeCliMcpServerCount"], 2)
        self.assertTrue(any("Local MCP" in note for note in report["boundaryNotes"]))


if __name__ == "__main__":
    unittest.main()
