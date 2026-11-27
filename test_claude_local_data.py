from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO, TextIOWrapper
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import claude_local_data as data
import config_snapshot


class ClaudeLocalDataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = self.root / "private-config-name"
        self.project = self.root / "private-project-name"
        self.destination = self.root / "backups"
        self.recovery_path = self.root / "recovered"
        self.destination.mkdir()
        self.recovery_path.mkdir()

    def seed(self, path, content=b"private-test-content"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def test_absent_config_produces_empty_redacted_json(self):
        out = StringIO()
        before = set(self.root.iterdir())
        with redirect_stdout(out):
            self.assertEqual(data.main(["audit", "--config-dir", str(self.config)]), 0)
        self.assertEqual(set(self.root.iterdir()), before)
        result = json.loads(out.getvalue())
        self.assertFalse(result["user_config_present"])
        self.assertFalse(result["contents_read"])
        self.assertEqual(result["files"], 0)
        self.assertNotIn(self.config.name, out.getvalue())

    def test_default_override_applies_with_explicit_precedence(self):
        self.seed(self.config / "history.jsonl")
        out = StringIO()
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.config)}), redirect_stdout(out):
            self.assertEqual(data.selected_config(), self.config)
            self.assertEqual(data.selected_config(str(self.project)), self.project)
            self.assertEqual(data.main(["audit"]), 0)
        self.assertEqual(json.loads(out.getvalue())["files"], 1)

    def test_audit_reads_metadata_without_opening_files(self):
        self.seed(self.config / "projects" / "private-session-name.jsonl")
        self.seed(self.config / ".credentials.json", b"TEST-ONLY-NEVER-PRINT")
        self.seed(self.project / ".mcp.json")
        out = StringIO()
        original_open = Path.open

        def metadata_only_open(path, *args, **kwargs):
            if path.as_posix() == "/proc/mounts":
                return original_open(path, *args, **kwargs)
            raise AssertionError("unexpected content read")

        with patch.object(Path, "open", metadata_only_open), redirect_stdout(out):
            self.assertEqual(data.main(["audit", "--config-dir", str(self.config),
                                        "--project-dir", str(self.project)]), 0)
        value = json.loads(out.getvalue())
        self.assertEqual(value["files"], 2)
        self.assertEqual(value["excluded_secret_entries"], 1)
        for secret in ("private-config", "private-project", "private-session", "TEST-ONLY", "private-test-content"):
            self.assertNotIn(secret, out.getvalue())

    def test_backup_recovers_selected_files_byte_for_byte(self):
        items = (
            (self.config, "user-config", "projects/foo/session.jsonl"),
            (self.config, "user-config", "skills/example/SKILL.md"),
            (self.config, "user-config", "hooks/hook.py"),
            (self.config, "user-config", "hooks/hook.cmd"),
            (self.config, "user-config", "settings.json"),
            (self.project, "project", "CLAUDE.md"),
            (self.project, "project", ".claude/CLAUDE.md"),
            (self.project, "project", ".mcp.json"),
        )
        for base, _, relative in items:
            # Checked settings and .mcp.json files must be strict JSON to be backed up.
            content = relative.encode()
            if relative.endswith(".json"):
                content = b'{"fixture": "%s"}' % content
            self.seed(base / relative, content)
        self.seed(self.config / ".claude.json")
        self.seed(self.config / "projects" / "private" / ".env.local")
        self.seed(self.config / "skills" / "example" / "private.pem")
        self.seed(self.project / ".git" / "config")
        self.seed(self.project / "source.py")
        self.seed(self.config / "cache" / "cached.bin")
        snapshot = data.backup(self.config, self.project, self.destination)
        self.assertEqual(len(data.verify(snapshot)["files"]), len(items))
        recovered = data.recover(snapshot, self.recovery_path)
        for base, scope, relative in items:
            original = base / relative
            restored = recovered / scope / relative
            self.assertEqual(restored.read_bytes(), original.read_bytes())
        for unsupported in (".claude.json", "projects/private/.env.local", "skills/example/private.pem", "cache/cached.bin"):
            self.assertFalse((recovered / "user-config" / unsupported).exists())
        self.assertFalse((recovered / "project" / ".git").exists())
        self.assertFalse((recovered / "project" / "source.py").exists())
        self.assertFalse((recovered / data.MANIFEST_NAME).exists())
        again = data.recover(snapshot, self.recovery_path)
        self.assertNotEqual(recovered, again)

    def test_blocks_inline_secrets_in_mcp_and_settings_by_default(self):
        self.seed(
            self.project / ".mcp.json",
            b'{"mcpServers":{"gh":{"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"ghp_1234567890abcdefghij"}}}}',
        )
        with self.assertRaisesRegex(data.SnapshotError, "Inline API keys or auth tokens"):
            data.backup(self.config, self.project, self.destination, require_config=False)
        self.assertEqual(list(self.destination.iterdir()), [])

        # Placeholder env references (${TOKEN}) are safe and allowed.
        self.seed(
            self.project / ".mcp.json",
            b'{"mcpServers":{"gh":{"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"${GITHUB_TOKEN}"}}}}',
        )
        snapshot = data.backup(self.config, self.project, self.destination, require_config=False)
        self.assertEqual(set(data.verify(snapshot)["files"]), {"project/.mcp.json"})

    def test_inline_secret_check_covers_common_forms_and_names_file_and_key(self):
        fake_key = "sk-ant-TESTONLY-not-a-real-key-0000"
        fake_token = "fake-opaque-token-0000"
        cases = {
            "list argument": ({"mcpServers": {"s": {"args": ["-y", "srv", "--api-key", fake_token]}}},
                              "mcpServers.s.args[3]"),
            "flag=value argument": ({"mcpServers": {"s": {"args": [f"--token={fake_token}"]}}},
                                    "mcpServers.s.args[0]"),
            "header argument": ({"mcpServers": {"s": {"args": ["--header", f"X-Api-Key: {fake_token}"]}}},
                                "mcpServers.s.args[1]"),
            "plain TOKEN env name": ({"mcpServers": {"s": {"env": {"NOTION_TOKEN": fake_token}}}},
                                     "mcpServers.s.env.NOTION_TOKEN"),
            "PASSWORD env name": ({"mcpServers": {"s": {"env": {"DB_PASSWORD": "$" + fake_token}}}},
                                  "mcpServers.s.env.DB_PASSWORD"),
            "generic header name": ({"mcpServers": {"s": {"headers": {"X-Token": fake_token}}}},
                                    "mcpServers.s.headers.X-Token"),
            "cookie header": ({"mcpServers": {"s": {"headers": {"Cookie": f"session={fake_token}"}}}},
                              "mcpServers.s.headers.Cookie"),
            "URL user:pass": (
                {"mcpServers": {"s": {"env": {"DATABASE_URL": f"postgres://user:{fake_token}@db.example.com/x"}}}},
                "mcpServers.s.env.DATABASE_URL"),
            "URL ?token=": ({"mcpServers": {"s": {"url": f"https://mcp.example.com/sse?token={fake_token}"}}},
                            "mcpServers.s.url"),
            "key embedded in a command": ({"mcpServers": {"s": {"command": f"srv --key {fake_key}"}}},
                                          "mcpServers.s.command"),
            "literal default of a placeholder": (
                {"mcpServers": {"s": {"env": {"API_KEY": "${API_KEY:-" + fake_key + "}"}}}},
                "mcpServers.s.env.API_KEY"),
        }
        for name, (document, key_path) in cases.items():
            with self.subTest(name=name):
                self.seed(self.project / ".mcp.json", json.dumps(document).encode())
                with self.assertRaisesRegex(data.SnapshotError, "Inline API keys or auth tokens") as caught:
                    data.backup(self.config, self.project, self.destination, require_config=False)
                message = str(caught.exception)
                self.assertIn(f"project/.mcp.json: {key_path}", message)
                for value in (fake_key, fake_token, "TESTONLY", "opaque"):
                    self.assertNotIn(value, message)
                self.assertNotIn(self.project.name, message)
                self.assertEqual(list(self.destination.iterdir()), [])

    def test_inline_secret_check_allows_placeholders_and_known_non_secret_settings(self):
        settings = {
            "apiKeyHelper": "/opt/example/get-key.sh",
            "awsAuthRefresh": "aws sso login --profile example",
            "env": {
                "CLAUDE_CODE_API_KEY_HELPER_TTL_MS": "3600000",
                "SECRETS_DIR": "/home/example/secrets",
                "MAX_MCP_OUTPUT_TOKENS": "25000",
                "GITHUB_TOKEN": "${GITHUB_TOKEN}",
                "DISABLE_TOKEN_CHECK": "1",
                "EXAMPLE_PUBLIC_KEY": "ssh-ed25519 AAAAexamplepublickey",
            },
            "permissions": {"deny": ["Read(./.env)", "Read(~/.secrets/**)"]},
        }
        mcp = {"mcpServers": {"s": {
            "url": "https://user:${MCP_PASSWORD}@mcp.example.com/sse?token=${MCP_TOKEN}",
            "headers": {"Authorization": "Bearer ${MCP_TOKEN}"},
            "args": ["--api-key", "${MCP_KEY}", "--token=$MCP_TOKEN"],
            "env": {"API_KEY": "$(example-keychain read api-key)"},
        }}}
        self.seed(self.config / "settings.json", json.dumps(settings).encode())
        self.seed(self.project / ".mcp.json", json.dumps(mcp).encode())
        snapshot = data.backup(self.config, self.project, self.destination)
        self.assertEqual(set(data.verify(snapshot)["files"]), {"user-config/settings.json", "project/.mcp.json"})

    def assertBacksUp(self, settings):
        self.seed(self.config / "settings.json", json.dumps(settings).encode())
        snapshot = data.backup(self.config, None, self.destination)
        self.assertEqual(set(data.verify(snapshot)["files"]), {"user-config/settings.json"})

    def assertRefused(self, settings_text, *expected):
        self.seed(self.config / "settings.json", settings_text.encode() if isinstance(settings_text, str) else settings_text)
        before = set(self.destination.iterdir())
        with self.assertRaisesRegex(data.SnapshotError, "Inline API keys or auth tokens") as caught:
            data.backup(self.config, None, self.destination)
        for text in expected:
            self.assertIn(text, str(caught.exception))
        self.assertEqual(set(self.destination.iterdir()), before)
        return str(caught.exception)

    def test_inline_secret_check_allows_rules_paths_and_shell_references(self):
        cases = {
            # Permission rules that name commands which read credentials.
            "permission rules": {"permissions": {
                "allow": ["Bash(npm run test:*)", "Bash(export TOKEN=*)"],
                "deny": ["Bash(gh auth token:*)", "Bash(security find-generic-password:*)",
                         "Bash(aws secretsmanager get-secret-value:*)", "Bash(kubectl create token:*)"],
            }},
            "certificate and key file paths": {"mcpServers": {"s": {"args": [
                "--cert", "./cert.pem", "--key", "./key.pem", "--key", "/etc/example/client.key",
                "--secret", "C:\\example\\secret.p12", "--token", "~/example/token.pem"]}}},
            "lower-case shell variable in a hook": {"hooks": {"PreToolUse": [{"hooks": [{
                "type": "command", "command": 'curl -H "Authorization: Bearer $tok" https://example.com/hook'}]}]}},
            "flags that name a variable or a secret": {"mcpServers": {"s": {"args": [
                "--api-key-env", "EXAMPLE_API_KEY", "--secret-name", "prod/db"]}}},
            "key IDs": {"env": {"GPG_KEY_ID": "0123ABCD4567EF89"}},
            "client key and credentials file settings": {"env": {
                "CLAUDE_CODE_CLIENT_KEY": "/etc/example/client.key",
                "GOOGLE_APPLICATION_CREDENTIALS": "/home/example/gcp.json"}},
            "Bearer in prose without digits": {"mcpServers": {"s": {"description": "Uses Bearer authentication-only"}}},
        }
        for name, settings in cases.items():
            with self.subTest(name=name):
                self.assertBacksUp(settings)

    def test_inline_secret_check_allows_powershell_and_cmd_references(self):
        # Claude Code runs a hook with "shell": "powershell" in PowerShell; cmd /c expands %NAME%.
        def hook(command, shell=None):
            entry = {"type": "command", "command": command}
            if shell:
                entry["shell"] = shell
            return {"hooks": {"Stop": [{"hooks": [entry]}]}}

        cases = {
            "PowerShell $env: in a header": hook(
                'curl.exe -s -H "Authorization: Bearer $env:NTFY_TOKEN" https://ntfy.example.com/x', "powershell"),
            "PowerShell $env: in a query": hook(
                'Invoke-RestMethod "https://push.example.com/send?token=$env:PUSH_TOKEN&title=Claude"', "powershell"),
            "PowerShell ${env:} and $Env:": hook(
                'Invoke-RestMethod -Uri "https://push.example.com/?token=${env:PUSH_TOKEN}&key=$Env:PUSH_KEY"',
                "powershell"),
            "cmd %NAME% in a header": hook('cmd /c curl -s -H "Authorization: Bearer %NTFY_TOKEN%" https://x.example'),
            "cmd %NAME% in a form field": hook('curl -s -d "token=%PUSH_TOKEN%&title=Claude" https://x.example'),
            "cmd %NAME% after a flag": {"mcpServers": {"s": {"command": "cmd", "args": [
                "/c", "npx", "-y", "example-mcp", "--api-key", "%EXAMPLE_API_KEY%", "--token=%EXAMPLE_TOKEN%"]}}},
            "references as env values": {"env": {"API_TOKEN": "%API_TOKEN%", "GH_TOKEN": "$env:GH_TOKEN"}},
        }
        for name, settings in cases.items():
            with self.subTest(name=name):
                self.assertBacksUp(settings)
        message = self.assertRefused(json.dumps(hook(
            'curl.exe -H "Authorization: Bearer $env:NTFY_TOKEN" -d "token=plain-literal-0000"', "powershell")),
            "user-config/settings.json: hooks.Stop[0].hooks[0].command")
        self.assertNotIn("plain-literal", message)

    def test_inline_secret_check_allows_search_patterns_prose_and_limits(self):
        def hook(command):
            return {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": command}]}]}}

        cases = {
            "grep alternation": hook("jq -r '.tool_input.command' | grep -qiE 'api_key=|token=|password=' && exit 2 || exit 0"),
            "grep alternation in double quotes": hook('jq -r .tool_input.command | grep -E "password=|passwd="'),
            "rg escape": hook("rg -n 'token=\\w+' ."),
            "prose after Password:": hook("echo 'Password: not stored here' >&2"),
            "prose after Token:": hook("echo 'Token: expired, run claude /login'"),
            "prose after a header-like name": hook("echo 'X-Session-Secret: rotated weekly, see the wiki'"),
            "a limit flag": {"statusLine": {"type": "command", "command": "npx -y example-statusline --token-limit=200000"}},
            "limit and domain settings": {"env": {"TOKEN_LIMIT": "100000", "COOKIE_DOMAIN": "localhost",
                                                  "MAX_PASSWORD_LENGTH": "64"}},
        }
        for name, settings in cases.items():
            with self.subTest(name=name):
                self.assertBacksUp(settings)
        fake = "plain-literal-0000"
        refused = {
            "header option with several words": hook(f'curl -H "X-Session-Secret: {fake} extra" https://x.example'),
            "long header option with several words": hook(f'wget --header="X-Session-Secret: {fake} extra" x.example'),
            "credential header with several words": {"mcpServers": {"s": {"args": [
                "--header", f"Cookie: theme=dark; sid={fake}"]}}},
            "one word after Password:": hook(f"echo 'Password: {fake}'"),
            "assignment": hook(f"API_TOKEN={fake} claude"),
        }
        for name, settings in refused.items():
            with self.subTest(name=name):
                message = self.assertRefused(json.dumps(settings), "Inline API keys")
                self.assertNotIn(fake, message)

    def test_inline_secret_check_finds_token_keys_anywhere_and_more_forms(self):
        fake = "plain-literal-0000"
        cases = {
            "token key below another key": ({"mcpServers": {"z": {"auth": {"token": fake}}}}, "mcpServers.z.auth.token"),
            "apiToken key": ({"mcpServers": {"z": {"apiToken": fake}}}, "mcpServers.z.apiToken"),
            "X-Auth header": ({"mcpServers": {"z": {"headers": {"X-Auth": fake}}}}, "mcpServers.z.headers.X-Auth"),
            "PWD env name": ({"env": {"MYSQL_PWD": fake}}, "env.MYSQL_PWD"),
            "access token in a URL fragment": ({"mcpServers": {"z": {"url": f"https://example.com/cb#access_token={fake}"}}},
                                               "mcpServers.z.url"),
            "literal value that only looks like a variable": ({"env": {"DB_PASSWORD": "$uperSecret123"}}, "env.DB_PASSWORD"),
        }
        for name, (settings, key_path) in cases.items():
            with self.subTest(name=name):
                message = self.assertRefused(json.dumps(settings), f"user-config/settings.json: {key_path}")
                self.assertNotIn(fake, message)
        self.assertBacksUp({"env": {"MAX_MCP_OUTPUT_TOKENS": "25000"}})

    def test_inline_secret_check_reads_both_values_of_a_duplicate_key(self):
        self.assertRefused('{"env": {"API_KEY": "fake-literal-0000", "API_KEY": "${API_KEY}"}}',
                           "user-config/settings.json: env.API_KEY")

    def test_secret_shaped_key_name_is_reported_redacted(self):
        fake_key = "sk-ant-TESTONLY-not-a-real-key-0000"
        message = self.assertRefused(json.dumps({"mcpServers": {fake_key: {"command": "srv"}}}),
                                     "user-config/settings.json: mcpServers.<redacted>")
        self.assertNotIn("TESTONLY", message)

    def test_secret_shapes_are_found_in_values_with_neutral_names(self):
        github_classic = "gh" + "p_" + "TESTONLY" + "0" * 28
        github_fine_grained = "github" + "_pat_" + "TESTONLY_" + "0" * 30
        for name, value in (("PEM private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"),
                            ("GitHub classic token", github_classic),
                            ("GitHub fine-grained token", github_fine_grained)):
            with self.subTest(name=name):
                message = self.assertRefused(json.dumps({"env": {"EXAMPLE_NOTE": value}}),
                                             "user-config/settings.json: env.EXAMPLE_NOTE")
                self.assertNotIn("TESTONLY", message)

    def test_checked_files_that_are_not_utf8_are_refused(self):
        for name, content in (("GBK", '{"note": "设置"}'.encode("gbk")),
                              ("UTF-16", '{"note": "x"}'.encode("utf-16"))):
            with self.subTest(encoding=name):
                self.seed(self.config / "settings.json", content)
                with self.assertRaisesRegex(data.SnapshotError, r"user-config/settings\.json \(not UTF-8"):
                    data.backup(self.config, None, self.destination)
                self.assertEqual(list(self.destination.iterdir()), [])

    def test_error_lists_at_most_ten_findings(self):
        settings = {"env": {f"EXAMPLE_TOKEN_{number:02d}": "fake-opaque-0000" for number in range(12)}}
        message = self.assertRefused(json.dumps(settings), "; and 2 more")
        self.assertEqual(message.count("env.EXAMPLE_TOKEN_"), 10)

    def test_checked_files_that_are_not_strict_json_are_not_backed_up_silently(self):
        fake_key = "sk-ant-TESTONLY-not-a-real-key-0000"
        self.seed(self.config / "settings.json",
                  ('{\n  // comment\n  "env": {"ANTHROPIC_API_KEY": "%s",},\n}\n' % fake_key).encode())
        with redirect_stderr(StringIO()) as errors:
            self.assertEqual(data.main(["backup", "--config-dir", str(self.config),
                                        "--destination", str(self.destination)]), 1)
        self.assertIn("user-config/settings.json (not strict JSON", errors.getvalue())
        self.assertNotIn(fake_key, errors.getvalue())
        self.assertEqual(list(self.destination.iterdir()), [])
        # An empty file has nothing to leak.
        self.seed(self.config / "settings.json", b"")
        snapshot = data.backup(self.config, None, self.destination)
        self.assertEqual(set(data.verify(snapshot)["files"]), {"user-config/settings.json"})

    def test_allow_inline_secrets_still_lists_what_it_let_through(self):
        fake_token = "fake-opaque-token-0000"
        self.seed(self.config / "settings.json", json.dumps({"env": {"EXAMPLE_TOKEN": fake_token}}).encode())
        self.seed(self.config / "settings.local.json", b'{"env": {},}')
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as errors:
            self.assertEqual(data.main(["backup", "--config-dir", str(self.config),
                                        "--destination", str(self.destination), "--allow-inline-secrets"]), 0)
        warning = errors.getvalue()
        self.assertIn("--allow-inline-secrets kept", warning)
        self.assertIn("user-config/settings.json: env.EXAMPLE_TOKEN", warning)
        self.assertIn("user-config/settings.local.json (not strict JSON", warning)
        self.assertNotIn(fake_token, warning)
        snapshot, = self.destination.iterdir()
        self.assertEqual(len(data.verify(snapshot)["files"]), 2)

    def test_backup_reports_and_records_entries_left_out_by_name(self):
        self.seed(self.config / "skills" / "example" / "SKILL.md")
        self.seed(self.config / "skills" / "example" / "auth.json")
        self.seed(self.config / "skills" / "example" / ".env.example")
        with redirect_stdout(StringIO()) as output:
            self.assertEqual(data.main(["backup", "--config-dir", str(self.config),
                                        "--destination", str(self.destination)]), 0)
        self.assertIn("Left out by name: 2", output.getvalue())
        snapshot, = self.destination.iterdir()
        manifest = json.loads((snapshot / data.MANIFEST_NAME).read_text(encoding="utf-8"))
        self.assertEqual(manifest["excluded_secret_entries"], 2)
        self.assertEqual(set(data.verify(snapshot)["files"]), {"user-config/skills/example/SKILL.md"})

    def test_snapshot_written_before_the_left_out_count_still_recovers(self):
        self.seed(self.config / "history.jsonl")
        snapshot = data.backup(self.config, None, self.destination)
        manifest = snapshot / data.MANIFEST_NAME
        record = json.loads(manifest.read_text(encoding="utf-8"))
        record.pop("excluded_secret_entries", None)
        manifest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(set(data.verify(snapshot)["files"]), {"user-config/history.jsonl"})
        recovered = data.recover(snapshot, self.recovery_path)
        self.assertEqual((recovered / "user-config" / "history.jsonl").read_bytes(), b"private-test-content")

    def test_recovery_may_use_the_folder_that_holds_the_snapshot(self):
        self.seed(self.config / "history.jsonl")
        snapshot = data.backup(self.config, None, self.destination)
        recovered = data.recover(snapshot, self.destination)
        self.assertEqual(recovered.parent, self.destination)
        self.assertEqual(len(data.verify(snapshot)["files"]), 1)
        for inside in (snapshot, snapshot / data.PAYLOAD_NAME):
            with self.subTest(destination=inside):
                with self.assertRaisesRegex(data.SnapshotError, "outside the snapshot"):
                    data.recover(snapshot, inside)

    def test_unexpected_snapshot_entries_are_named(self):
        self.seed(self.config / "history.jsonl")
        snapshot = data.backup(self.config, None, self.destination)
        (snapshot / ".DS_Store").write_bytes(b"fixture")
        with self.assertRaisesRegex(data.SnapshotError, r"unexpected files: '\.DS_Store'"):
            data.verify(snapshot)

    def test_link_rejection_says_how_many_and_where(self):
        self.seed(self.config / "skills" / "real" / "SKILL.md")
        try:
            (self.config / "skills" / "linked").symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest("symlinks unavailable")
        self.assertEqual(data.audit(self.config)["unsafe_or_unavailable_by_area"], {"skills": 1})
        with self.assertRaisesRegex(data.SnapshotError, r"found 1 entry that is a link.*\(in: skills\)"):
            data.backup(self.config, None, self.destination)

    def test_entry_point_reports_runtime_errors_in_one_line(self):
        self.seed(self.config / "history.jsonl")
        snapshot = data.backup(self.config, None, self.destination)
        (snapshot / data.MANIFEST_NAME).write_text("[" * 200000 + "]" * 200000, encoding="utf-8")
        with redirect_stderr(StringIO()) as errors:
            self.assertEqual(data.main(["verify", str(snapshot)]), 1)
        self.assertIn("Invalid backup manifest", errors.getvalue())
        # Path.expanduser("~unknown-user") raises RuntimeError on POSIX only; make the
        # failure explicit so Windows exercises the same branch.
        with redirect_stderr(StringIO()) as errors, redirect_stdout(StringIO()), \
                patch.object(data, "selected_config_path", side_effect=RuntimeError("no home")):
            self.assertEqual(data.main(["audit", "--config-dir", "~no-such-user-fixture/x"]), 1)
        self.assertEqual(errors.getvalue(), "Claude work operation stopped (RuntimeError).\n")
        real_stat = data.checked_stat

        def too_deep(path):
            if path.name == "deep":
                raise RecursionError("fixture")
            return real_stat(path)

        self.seed(self.config / "projects" / "deep" / "session.jsonl")
        with patch.object(data, "checked_stat", side_effect=too_deep):
            self.assertEqual(data.audit(self.config)["unsafe_or_unavailable_by_area"],
                             {"sessions_and_project_data": 1})

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux mount table")
    def test_audit_runs_on_network_storage_and_says_so_while_backup_refuses(self):
        self.seed(self.config / "history.jsonl")
        mounts = f"/dev/sda1 / ext4 rw 0 0\nserver:/export {self.root} nfs4 rw 0 0\n"
        with patch.object(config_snapshot, "_read_proc_mounts", return_value=mounts):
            with redirect_stdout(StringIO()) as output:
                self.assertEqual(data.main(["audit", "--config-dir", str(self.config)]), 0)
            result = json.loads(output.getvalue())
            self.assertTrue(result["network_or_synced_storage"])
            self.assertEqual(result["files"], 1)
            with redirect_stderr(StringIO()) as errors:
                self.assertEqual(data.main(["backup", "--config-dir", str(self.config),
                                            "--destination", str(self.destination)]), 1)
            self.assertIn("network or shared filesystem", errors.getvalue())
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_symlinked_config_directory_is_counted_as_not_inspected(self):
        self.seed(self.root / "real-config" / "history.jsonl")
        try:
            self.config.symlink_to(self.root / "real-config", target_is_directory=True)
        except OSError:
            self.skipTest("symlinks unavailable")
        result = data.audit(self.config)
        self.assertFalse(result["user_config_present"])
        self.assertEqual(result["unsafe_or_unavailable_by_area"], {"user_config_root": 1})
        self.assertEqual(result["files"], 0)

    def test_hardlinked_secret_file_is_rejected(self):
        secret = self.config / ".credentials.json"
        self.seed(secret, b"TOP-SECRET-TOKEN")
        disguised = self.config / "projects" / "innocent.jsonl"
        disguised.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(secret, disguised)
        except OSError:
            self.skipTest("hardlinks unavailable")
        self.assertEqual(data.audit(self.config)["unsafe_or_unavailable"], 1)
        with self.assertRaises(data.SnapshotError):
            data.backup(self.config, None, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_windows_execute_bit_difference_between_lstat_and_fstat_is_ignored(self):
        lstat_info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o777, st_dev=1, st_ino=2, st_size=10, st_mtime_ns=100,
        )
        fstat_info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o666, st_dev=1, st_ino=2, st_size=10, st_mtime_ns=100,
        )
        self.assertEqual(data.identity_of(lstat_info), data.identity_of(fstat_info))

    def test_backup_rejects_missing_explicit_project_without_publishing(self):
        self.seed(self.config / "history.jsonl")
        with redirect_stderr(StringIO()) as errors:
            result = data.main(["backup", "--config-dir", str(self.config),
                                "--project-dir", str(self.project), "--destination", str(self.destination)])
        self.assertEqual(result, 1)
        self.assertIn("project directory does not exist", errors.getvalue())
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_backup_rejects_missing_explicit_or_configured_user_directory(self):
        self.seed(self.project / "CLAUDE.md")
        base = ["backup", "--project-dir", str(self.project), "--destination", str(self.destination)]
        for explicit in (True, False):
            with self.subTest(explicit=explicit), redirect_stderr(StringIO()) as errors:
                with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.config)}):
                    args = base + ["--config-dir", str(self.config)] if explicit else base
                    self.assertEqual(data.main(args), 1)
            self.assertIn("user configuration directory does not exist", errors.getvalue())
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_project_only_backup_allows_absent_implicit_user_and_project_dot_claude(self):
        self.seed(self.project / "CLAUDE.md")
        with patch.object(Path, "home", return_value=self.root), patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": ""}):
            with redirect_stdout(StringIO()):
                self.assertEqual(data.main(["backup", "--project-dir", str(self.project),
                                            "--destination", str(self.destination)]), 0)
        snapshot, = self.destination.iterdir()
        self.assertEqual(set(data.verify(snapshot)["files"]), {"project/CLAUDE.md"})

    def test_whitespace_env_and_claude_backup_secret_are_handled(self):
        self.seed(self.config / ".claude.json.backup")
        self.seed(self.config / "projects" / "private" / ".CLAUDE.JSON.BACKUP")
        self.seed(self.config / "history.jsonl")
        self.seed(self.project / "CLAUDE.md")

        self.assertEqual(data.audit(self.config)["excluded_secret_entries"], 2)
        snapshot = data.backup(self.config, None, self.destination)
        self.assertEqual(set(data.verify(snapshot)["files"]), {"user-config/history.jsonl"})
        with patch.object(Path, "home", return_value=self.root), patch.dict(
            os.environ, {"CLAUDE_CONFIG_DIR": "   "}
        ), redirect_stdout(StringIO()):
            self.assertEqual(data.selected_config(), self.root / ".claude")
            self.assertEqual(data.main(["backup", "--project-dir", str(self.project),
                                        "--destination", str(self.destination)]), 0)

    def test_missing_destination_raises_snapshot_error(self):
        self.seed(self.config / "history.jsonl")
        missing = self.root / "missing-dest"
        snapshot = data.backup(self.config, None, self.destination)
        with self.assertRaisesRegex(data.SnapshotError, "destination directory does not exist"):
            data.backup(self.config, None, missing)
        with self.assertRaisesRegex(data.SnapshotError, "destination directory does not exist"):
            data.recover(snapshot, missing)
        self.assertFalse(missing.exists())

    def test_windows_config_names_are_case_insensitive(self):
        self.seed(self.config / "History.JSONL")
        self.seed(self.project / "claude.md")
        with patch.object(data, "os", SimpleNamespace(name="nt")):
            files, _, _, _ = data.scan_work(self.config, self.project)
        self.assertEqual({entry.relative.as_posix() for entry in files},
                         {"user-config/History.JSONL", "project/claude.md"})

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_private_payload_recovers_checked_permissions_and_ignores_special_bits(self):
        modes = {"hooks/run.sh": 0o755, "skills/example/helper.sh": 0o700, "settings.json": 0o600}
        for name, mode in modes.items():
            source = self.config / name
            self.seed(source, b"{}" if name.endswith(".json") else b"private-test-content")
            source.chmod(mode)
        (self.config / "hooks/run.sh").chmod(0o4755)
        with redirect_stdout(StringIO()):
            self.assertEqual(data.main(["backup", "--config-dir", str(self.config),
                                        "--destination", str(self.destination)]), 0)
            snapshot, = self.destination.iterdir()
            self.assertEqual(data.main(["verify", str(snapshot)]), 0)
            self.assertEqual(data.main(["recover", str(snapshot), "--destination", str(self.recovery_path)]), 0)
        recovered, = self.recovery_path.iterdir()
        for name, mode in modes.items():
            private = snapshot / data.PAYLOAD_NAME / "user-config" / name
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
            target = recovered / "user-config" / name
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
            self.assertEqual(target.read_bytes(), private.read_bytes())

    def test_missing_invalid_overpermissive_and_corrupt_permission_records_fail_before_recovery(self):
        self.seed(self.config / "history.jsonl")
        snapshot = data.backup(self.config, None, self.destination)
        manifest = snapshot / data.MANIFEST_NAME
        original = json.loads(manifest.read_text(encoding="utf-8"))
        name = "user-config/history.jsonl"
        for modes in ({}, {name: 0o4755}, {name: True}, {name: 0o700}):
            with self.subTest(modes=modes):
                changed = dict(original, posix_modes=modes, posix_modes_sha256="bad")
                manifest.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(data.SnapshotError, "permissions"):
                    data.verify(snapshot)
                with self.assertRaises(data.SnapshotError):
                    data.recover(snapshot, self.recovery_path)
        # Even with a valid checksum, group/world-writable modes (0o777, 0o666) must fail.
        for writable_mode in (0o777, 0o666):
            modes = {name: writable_mode}
            changed = dict(original, posix_modes=modes, posix_modes_sha256=data.permissions_digest(modes))
            manifest.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(data.SnapshotError, "permissions"):
                data.verify(snapshot)
        self.assertEqual(list(self.recovery_path.iterdir()), [])

    def test_v1_and_windows_origin_snapshots_without_modes_recover_privately(self):
        self.seed(self.config / "hooks" / "run.sh")
        snapshot = data.backup(self.config, None, self.destination)
        manifest = snapshot / data.MANIFEST_NAME
        original = json.loads(manifest.read_text(encoding="utf-8"))
        legacy = {"format": 1, "inventory": original["inventory"]}
        windows = dict(original, posix_modes=None, posix_modes_sha256=data.permissions_digest(None))
        for record in (legacy, windows):
            with self.subTest(version=record["format"]):
                manifest.write_text(json.dumps(record), encoding="utf-8")
                self.assertEqual(len(data.verify(snapshot)["files"]), 1)
                recovered = data.recover(snapshot, self.recovery_path)
                restored = recovered / "user-config" / "hooks" / "run.sh"
                self.assertEqual(restored.read_bytes(), b"private-test-content")
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)

    def test_backup_and_recovery_reject_overlapping_destinations(self):
        self.seed(self.config / "history.jsonl")
        with self.assertRaises(data.SnapshotError):
            data.backup(self.config, None, self.config)
        nested_config = self.project / ".claude" / "nested"
        self.seed(nested_config / "history.jsonl")
        with self.assertRaises(data.SnapshotError):
            data.audit(nested_config, self.project)
        snapshot = data.backup(self.config, None, self.destination)
        with self.assertRaises(data.SnapshotError):
            data.recover(snapshot, snapshot)

    def test_audit_counts_links_and_backup_rejects_them(self):
        self.seed(self.config / "projects" / "safe.jsonl")
        self.seed(self.root / "outside.jsonl")
        candidate = self.config / "projects" / "unsafe.jsonl"
        try:
            candidate.symlink_to(self.root / "outside.jsonl")
        except OSError:
            self.skipTest("symlinks unavailable")
        self.assertEqual(data.audit(self.config)["unsafe_or_unavailable"], 1)
        with self.assertRaises(data.SnapshotError):
            data.backup(self.config, None, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_changed_source_aborts_without_publishing(self):
        source = self.config / "history.jsonl"
        self.seed(source)
        original = data.copy_file

        def copy_and_change(entry, destination):
            result = original(entry, destination)
            source.write_bytes(b"new longer synthetic contents")
            return result

        with patch.object(data, "copy_file", side_effect=copy_and_change):
            with self.assertRaises(data.SnapshotError):
                data.backup(self.config, None, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_verify_rejects_equal_length_altered_payload(self):
        path = "history.jsonl"
        self.seed(self.config / path, b"AAAA")
        snapshot = data.backup(self.config, None, self.destination)
        (snapshot / data.PAYLOAD_NAME / "user-config" / path).write_bytes(b"BBBB")
        with self.assertRaises(data.SnapshotError):
            data.verify(snapshot)
        with self.assertRaises(data.SnapshotError):
            data.recover(snapshot, self.recovery_path)
        self.assertEqual(list(self.recovery_path.iterdir()), [])

    def test_manifest_cannot_select_a_recovery_path(self):
        self.seed(self.config / "history.jsonl")
        snapshot = data.backup(self.config, None, self.destination)
        manifest = snapshot / data.MANIFEST_NAME
        expected = json.loads(manifest.read_text(encoding="utf-8"))
        expected["inventory"]["files"]["../outside.txt"] = {"size": 0, "sha256": "f" * 64}
        manifest.write_text(json.dumps(expected), encoding="utf-8")
        with self.assertRaises(data.SnapshotError):
            data.recover(snapshot, self.recovery_path)
        self.assertFalse((self.root / "outside.txt").exists())

    def test_snapshots_are_staged_at_the_length_of_their_published_path(self):
        # Windows refuses paths over 260 characters unless long paths are enabled. A snapshot
        # staged under a shorter name could verify there and fail to open once renamed.
        self.seed(self.config / "projects" / "session.jsonl")
        with patch.object(data, "verify", wraps=data.verify) as verified:
            snapshot = data.backup(self.config, None, self.destination)
        staged = verified.call_args_list[0].args[0]
        self.assertNotEqual(staged, snapshot)
        self.assertTrue(staged.name.startswith("."))
        self.assertEqual(len(str(staged)), len(str(snapshot)))
        self.assertEqual(sorted(path.name for path in self.destination.iterdir()), [snapshot.name])
        with patch.object(data, "copy_tree", wraps=data.copy_tree) as copied:
            recovered = data.recover(snapshot, self.recovery_path)
        self.assertEqual(len(str(copied.call_args.args[1])), len(str(recovered)))
        self.assertEqual(sorted(path.name for path in self.recovery_path.iterdir()), [recovered.name])

    def test_long_windows_path_errors_say_so_without_the_path(self):
        long_name = "C:\\Users\\example\\" + "private-session-" * 16
        error = FileNotFoundError(2, "No such file or directory", long_name)
        with patch.object(data, "_is_windows", return_value=True):
            self.assertIn("260 characters", data._long_path_hint(error))
            self.assertEqual(data._long_path_hint(FileNotFoundError(2, "x", "C:\\short")), "")
            with redirect_stderr(StringIO()) as errors, patch.object(data, "backup", side_effect=error):
                self.seed(self.config / "history.jsonl")
                code = data.main(["backup", "--config-dir", str(self.config), "--destination", str(self.destination)])
        self.assertEqual(code, 1)
        self.assertIn("(FileNotFoundError). A path involved is", errors.getvalue())
        self.assertNotIn("private-session", errors.getvalue())
        with patch.object(data, "_is_windows", return_value=False):
            self.assertEqual(data._long_path_hint(error), "")

    def test_printed_paths_survive_an_output_encoding_without_their_characters(self):
        # Redirected or piped output on Windows uses the ANSI code page; cp950 (Traditional
        # Chinese) has no simplified characters such as 备.
        destination = self.root / "备份"
        destination.mkdir()
        self.seed(self.config / "history.jsonl")
        output = BytesIO()
        stream = TextIOWrapper(output, encoding="cp950", errors="strict")
        with patch("sys.stdout", stream):
            code = data.main(["backup", "--config-dir", str(self.config), "--destination", str(destination)])
            stream.flush()
        self.assertEqual(code, 0)
        self.assertIn(b"Verified local backup: ", output.getvalue())
        self.assertIn(b"\\u5907", output.getvalue())
        self.assertEqual(len(list(destination.iterdir())), 1)

    def test_errors_suppress_source_filenames(self):
        output = StringIO()
        with redirect_stderr(output):
            self.assertEqual(data.main(["verify", str(self.root / "private-name")]), 1)
        self.assertNotIn("private-name", output.getvalue())


if __name__ == "__main__":
    unittest.main()
