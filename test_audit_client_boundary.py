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


if __name__ == "__main__":
    unittest.main()
