import contextlib
from datetime import datetime, timezone, timedelta
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit_client_boundary as boundary


SERVER = {"command": "example-tool", "args": ["--demo"]}


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

    def _audit(self, home, **kwargs):
        kwargs.setdefault("env", {})
        return boundary.collect_boundary_audit(system="Linux", home=home, **kwargs)

    def test_counts_per_project_entries_in_cli_state_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".claude.json").write_text(
                json.dumps({
                    "mcpServers": {"user_scope_private": SERVER},
                    "projects": {
                        "/work/demo-one": {"mcpServers": {"local_scope_a": SERVER, "local_scope_b": SERVER}},
                        "/work/demo-two": {"mcpServers": {}},
                        "/work/demo-three": {"history": []},
                    },
                }),
                encoding="utf-8",
            )
            report = self._audit(root)
        bridges = report["localMcpBridges"]
        self.assertEqual(bridges["claudeCliMcpServerCount"], 3)
        self.assertTrue(bridges["claudeCliMcpConfigured"])
        self.assertEqual(bridges["claudeCliMcpUnreadableConfigCount"], 0)
        serialized = json.dumps(report)
        for private in ("user_scope_private", "local_scope_a", "demo-one", "example-tool"):
            self.assertNotIn(private, serialized)

    def test_project_mcp_file_is_counted_only_for_an_explicit_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"project_scope_private": SERVER}}), encoding="utf-8",
            )
            without_project = self._audit(root)
            with_project = self._audit(root, project_dir=project)
        self.assertEqual(without_project["localMcpBridges"]["claudeCliMcpServerCount"], 0)
        self.assertFalse(without_project["localMcpBridges"]["projectMcpConfigInspected"])
        self.assertEqual(with_project["localMcpBridges"]["claudeCliMcpServerCount"], 1)
        self.assertTrue(with_project["localMcpBridges"]["projectMcpConfigInspected"])
        self.assertNotIn("project_scope_private", json.dumps(with_project))

    def test_state_file_larger_than_one_mebibyte_is_still_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".claude.json").write_text(
                json.dumps({"mcpServers": {"big_state": SERVER}, "padding": "x" * (1024 * 1024 + 16)}),
                encoding="utf-8",
            )
            report = self._audit(root)
        self.assertEqual(report["localMcpBridges"]["claudeCliMcpServerCount"], 1)
        self.assertEqual(report["localMcpBridges"]["claudeCliMcpUnreadableConfigCount"], 0)

    def test_unreadable_config_is_kept_apart_from_zero(self):
        payload = json.dumps({"mcpServers": {"hidden_server": SERVER}})

        def oversized(root):
            (root / ".claude.json").write_text(payload, encoding="utf-8")
            return patch.object(boundary, "MAX_JSON_BYTES", 8)

        def not_json(root):
            (root / ".claude.json").write_text('{"mcpServers": {"hidden_server": {}},}  // note', encoding="utf-8")
            return contextlib.nullcontext()

        def directory(root):
            (root / ".claude.json").mkdir()
            return contextlib.nullcontext()

        for name, prepare in (("oversized", oversized), ("not-json", not_json), ("directory", directory)):
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with prepare(root):
                    report = self._audit(root)
                bridges = report["localMcpBridges"]
                self.assertEqual(bridges["claudeCliMcpServerCount"], 0)
                self.assertEqual(bridges["claudeCliMcpUnreadableConfigCount"], 1)
                self.assertTrue(any("could not be read" in note for note in report["boundaryNotes"]))
                self.assertNotIn("hidden_server", json.dumps(report))

    def test_symlinked_config_files_are_reported_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cli_dir = root / ".claude"
            cli_dir.mkdir()
            real_state = root / "dotfiles-state.json"
            real_state.write_text(json.dumps({"mcpServers": {"linked_server": SERVER}}), encoding="utf-8")
            real_settings = root / "dotfiles-settings.json"
            real_settings.write_text(
                json.dumps({"env": {key: "1" for key in boundary.CLI_ANTI_TELEMETRY_KEYS}}), encoding="utf-8",
            )
            try:
                os.symlink(real_state, root / ".claude.json")
                os.symlink(real_settings, cli_dir / "settings.json")
            except OSError:
                self.skipTest("Symlink creation requires privilege on this host")
            report = self._audit(root)
        bridges = report["localMcpBridges"]
        self.assertEqual(bridges["claudeCliMcpServerCount"], 0)
        self.assertEqual(bridges["claudeCliMcpUnreadableConfigCount"], 2)
        self.assertEqual(report["cliSettingsReadState"], "unreadable")
        self.assertFalse(any(report["cliAntiTelemetryFlags"].values()))

    def test_settings_read_state_distinguishes_absent_and_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(self._audit(root)["cliSettingsReadState"], "absent")
            (root / ".claude").mkdir()
            (root / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
            report = self._audit(root)
        self.assertEqual(report["cliSettingsReadState"], "read")
        self.assertEqual(report["localMcpBridges"]["claudeCliMcpUnreadableConfigCount"], 0)
        self.assertFalse(any("could not be read" in note for note in report["boundaryNotes"]))

    def test_relocated_config_dir_state_file_is_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relocated = root / "relocated"
            relocated.mkdir()
            (relocated / ".claude.json").write_text(
                json.dumps({"mcpServers": {"relocated_server": SERVER}}), encoding="utf-8",
            )
            from_env = self._audit(root, env={"CLAUDE_CONFIG_DIR": str(relocated)})
            from_argument = self._audit(root, config_dir=relocated)
            same_as_home = self._audit(relocated, config_dir=relocated)
        for report in (from_env, from_argument):
            self.assertEqual(report["localMcpBridges"]["claudeCliMcpServerCount"], 1)
            self.assertTrue(report["localClientFootprints"]["claudeCliStateFilePresent"])
        self.assertEqual(same_as_home["localMcpBridges"]["claudeCliMcpServerCount"], 1)

    def test_scope_names_the_host_environment_fields_it_includes(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = self._audit(Path(tmp))["scope"]
        self.assertIn("timezone", scope)
        self.assertIn("locale", scope)

    def test_cli_passes_config_and_project_dirs(self):
        output = io.StringIO()
        with patch.object(boundary, "collect_boundary_audit", return_value={"ok": True}) as audit:
            with contextlib.redirect_stdout(output):
                code = boundary.main(["--config-dir", "config dir", "--project-dir", "project dir"])
        self.assertEqual(code, 0)
        audit.assert_called_once_with(config_dir=Path("config dir"), project_dir=Path("project dir"))
        self.assertEqual(json.loads(output.getvalue()), {"ok": True})


if __name__ == "__main__":
    unittest.main()
