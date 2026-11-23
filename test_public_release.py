"""Regression checks for the public MIT release, clean report, UI parity, and sync safety."""

import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import build_kill_switch
import build_routing
import environment_report


REPO = Path(__file__).resolve().parent
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


class PublicReleaseTests(unittest.TestCase):
    def test_mit_license_and_notices_present(self):
        license_text = (REPO / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT License", license_text)
        self.assertIn("Copyright (c) 2026 Celeste", license_text)
        notices_path = REPO / "THIRD-PARTY-NOTICES.md"
        self.assertTrue(notices_path.is_file())
        self.assertFalse((REPO / "THIRD-PARTY-NOTICE.md").exists())
        self.assertIn("不包含任何第三方文章原文镜像", notices_path.read_text(encoding="utf-8"))

    def test_no_third_party_mirror_directory_present(self):
        self.assertFalse((REPO / "research-reports").exists())
        for path in REPO.rglob("*"):
            if ".git" in path.parts or not path.is_file():
                continue
            rel = path.relative_to(REPO).as_posix()
            self.assertNotIn("微信原件", rel)
            self.assertNotIn("逆向国外 AI Cloud", rel)
            if path.suffix.lower() in {".md", ".html", ".json", ".txt"}:
                text = path.read_text(encoding="utf-8", errors="ignore")
                self.assertNotIn("逆向国外 AI Cloud", text, f"Unexpected mirror reference in {rel}")

    def test_markdown_relative_links_resolve(self):
        broken = []
        for md in sorted(REPO.rglob("*.md")):
            if ".git" in md.parts:
                continue
            text = md.read_text(encoding="utf-8")
            text = re.sub(r"```[\s\S]*?```", "", text)
            for match in MARKDOWN_LINK.finditer(text):
                target = match.group(1).strip().split()[0]
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                clean_target = target.split("#", 1)[0].split("?", 1)[0]
                if not clean_target:
                    continue
                resolved = (md.parent / clean_target).resolve()
                if not resolved.exists():
                    broken.append(f"{md.relative_to(REPO).as_posix()} -> {target}")
        self.assertEqual(broken, [], "Broken relative Markdown links:\n" + "\n".join(broken))

    def test_ui_assets_exist_and_have_no_external_cdns(self):
        required = [
            "docs/index.html",
            "docs/styles.css",
            "docs/app.js",
            "docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md",
            "docs/images/logo.svg",
            "docs/images/architecture-cover.svg",
            "docs/images/hajimi-mascot.svg",
        ]
        for rel in required:
            self.assertTrue((REPO / rel).is_file(), f"Missing public asset: {rel}")
        html = (REPO / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertNotRegex(html, r'<script[^>]+src=["\']https?://', "UI must stay offline without external scripts")
        self.assertNotRegex(html, r'<link[^>]+href=["\']https?://', "UI must stay offline without external stylesheets")
        self.assertNotIn("../", html, "docs/index.html must not contain parent-relative links that 404 on GitHub Pages")
        self.assertIn("哈基米", html)

    def test_ui_js_algorithms_match_python_builders(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is not installed")
        script = r"""
const path = require("path");
const app = require(path.resolve(process.argv[1]));
const cases = [
  { name: "base_split", opts: { externalFirstXray: false, globalProxy: false, claudeEcosystem: false } },
  { name: "base_global", opts: { externalFirstXray: false, globalProxy: true, claudeEcosystem: false } },
  { name: "eco_split", opts: { externalFirstXray: false, globalProxy: false, claudeEcosystem: true } },
  { name: "eco_global", opts: { externalFirstXray: false, globalProxy: true, claudeEcosystem: true } },
  { name: "ext_first", opts: { externalFirstXray: true, globalProxy: false, claudeEcosystem: true } }
];
const routing = {};
for (const c of cases) {
  routing[c.name] = app.buildRoutingRules(c.opts);
}
const ks = app.computeKillSwitchPlan({
  interfaces: ["WLAN"],
  upstreamIp: "1.1.1.1",
  port: 443,
  protocol: "TCP",
  dhcpRaw: "192.168.1.1",
  usesDhcp: true
});
console.log(JSON.stringify({ routing, ksRanges: ks.ipv4BlockedRanges, ksDhcpWarn: ks.dhcpMissingWarning }));
"""
        proc = subprocess.run(
            [node, "-e", script, str(REPO / "docs" / "app.js")],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        data = json.loads(proc.stdout)
        expected_cases = {
            "base_split": build_routing.build_rules(False, False, claude_ecosystem=False),
            "base_global": build_routing.build_rules(False, True, claude_ecosystem=False),
            "eco_split": build_routing.build_rules(False, False, claude_ecosystem=True),
            "eco_global": build_routing.build_rules(False, True, claude_ecosystem=True),
            "ext_first": build_routing.build_rules(True, False, claude_ecosystem=True),
        }
        for key, expected in expected_cases.items():
            self.assertEqual(data["routing"][key], expected, f"UI routing mismatch for {key}")
        py_plan = build_kill_switch.build_plan(["WLAN"], "1.1.1.1", 443, "TCP", dhcp_servers=("192.168.1.1",))
        py_ipv4_other = next(
            rule["RemoteAddresses"]
            for rule in py_plan["Rules"]
            if rule["Name"] == build_kill_switch.RULE_PREFIX + "IPv4OtherAddresses"
        )
        self.assertEqual(data["ksRanges"], py_ipv4_other)
        self.assertFalse(data["ksDhcpWarn"])

    def test_auto_update_excludes_private_research_mirrors(self):
        auto_path = REPO / "tools" / "auto_update.py"
        if not auto_path.is_file():
            self.skipTest("tools/auto_update.py is excluded from release archive")
        spec = importlib.util.spec_from_file_location("auto_update", auto_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for protected in ("LICENSE", "THIRD-PARTY-NOTICES.md", "docs", ".github", "CHANGELOG.md"):
            self.assertIn(protected, mod.REPO_ONLY)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "research-reports" / "sources").mkdir(parents=True)
            (root / "research-reports" / "sources" / "mirror.md").write_text("x", encoding="utf-8")
            (root / "THIRD-PARTY-NOTICE.md").write_text("old", encoding="utf-8")
            (root / "ok.py").write_text("pass\n", encoding="utf-8")
            rels = [p.as_posix() for p in mod.kit_files(root, skip_repo_only=True)]
            self.assertEqual(rels, ["ok.py"])
        mod.privacy_gate()

    def test_release_version_and_offline_html_report_consistency(self):
        version = environment_report.KIT_VERSION
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        ui_html = (REPO / "docs" / "index.html").read_text(encoding="utf-8")
        changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"v{version}", readme)
        self.assertIn(f"v{version}", ui_html)
        self.assertIn(f"## v{version}", changelog)
        sample = {
            "schemaVersion": 2,
            "kitVersion": version,
            "generatedAtUtc": "2026-11-23T14:30:00Z",
            "platform": "Linux",
            "network": {"status": "unavailable", "reason": "test"},
            "claudeLocalData": {"status": "unavailable", "reason": "test"},
            "clientBoundary": {"status": "unavailable", "reason": "test"},
        }
        rendered = environment_report.render_html_report(sample)
        self.assertNotRegex(rendered, r'<script[^>]+src=["\']https?://')
        self.assertNotRegex(rendered, r'<link[^>]+href=["\']https?://')
        self.assertIn("exit_ip_reputation", rendered)
        self.assertIn("@media print", rendered)


if __name__ == "__main__":
    unittest.main()
