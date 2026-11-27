"""Regression checks for the public MIT release, clean report, UI parity, and sync safety."""

import fnmatch
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unicodedata
import unittest

import build_kill_switch
import build_routing
import environment_report


REPO = Path(__file__).resolve().parent
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HTML_LINK = re.compile(r"""\b(?:href|src|data-local-href)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
CODE_FENCE = re.compile(r"```[\s\S]*?```")
HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$", re.MULTILINE)
VERSION_TOKEN = re.compile(r"v(\d+\.\d+\.\d+)")
SKIPPED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}


def _is_external(target):
    return target.startswith(("http://", "https://", "mailto:", "data:", "javascript:"))


def _github_slug(heading):
    """Approximate the anchor GitHub generates for a Markdown heading."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    kept = "".join(
        ch for ch in text
        if ch in " -_" or unicodedata.category(ch)[0] in "LNM"
    )
    return kept.replace(" ", "-")


def _anchors(markdown_text):
    seen = {}
    anchors = set()
    for match in HEADING.finditer(CODE_FENCE.sub("", markdown_text)):
        slug = _github_slug(match.group(2))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")
    return anchors


def _markdown_files():
    for path in sorted(REPO.rglob("*.md")):
        if SKIPPED_DIRS.intersection(path.relative_to(REPO).parts):
            continue
        yield path


def _relative_targets(path):
    """Yield (target, resolved path or None, fragment) for local links in a Markdown or HTML file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".md":
        text = CODE_FENCE.sub("", text)
        raw = [m.group(1) for m in MARKDOWN_LINK.finditer(text)] + [m.group(1) for m in HTML_LINK.finditer(text)]
    else:
        raw = [m.group(1) for m in HTML_LINK.finditer(text)]
    for target in raw:
        target = target.strip().split()[0] if target.strip() else ""
        if not target or _is_external(target):
            continue
        location, _, fragment = target.partition("#")
        location = location.split("?", 1)[0]
        resolved = (path.parent / location).resolve() if location else None
        yield target, resolved, fragment


def _export_ignored_patterns():
    attributes = REPO / ".gitattributes"
    if not attributes.is_file():
        return None
    patterns = []
    for line in attributes.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 2 and "export-ignore" in parts[1:] and not parts[0].startswith("#"):
            patterns.append(parts[0].strip("/"))
    return patterns


def _is_export_ignored(rel, patterns):
    parts = rel.split("/")
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch.fnmatchcase(rel, pattern) or any(
                fnmatch.fnmatchcase("/".join(parts[:i]), pattern) for i in range(1, len(parts))
            ):
                return True
        elif any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
    return False


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
        for md in _markdown_files():
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

    def test_html_links_and_heading_anchors_in_markdown_resolve(self):
        from urllib.parse import unquote

        anchor_cache = {}
        broken = []
        for md in _markdown_files():
            rel_md = md.relative_to(REPO).as_posix()
            for target, resolved, fragment in _relative_targets(md):
                if resolved is not None and not resolved.exists():
                    broken.append(f"{rel_md} -> {target}")
                    continue
                page = resolved if resolved is not None else md
                if not fragment or page.suffix != ".md":
                    continue
                if page not in anchor_cache:
                    anchor_cache[page] = _anchors(page.read_text(encoding="utf-8"))
                if unquote(fragment) not in anchor_cache[page]:
                    broken.append(f"{rel_md} -> {target} (no matching heading)")
        self.assertEqual(broken, [], "Broken HTML links or anchors in Markdown:\n" + "\n".join(broken))

    def test_offline_page_local_links_and_script_element_ids_resolve(self):
        page = REPO / "docs" / "index.html"
        html = page.read_text(encoding="utf-8")
        ids = set(re.findall(r'\bid="([^"]+)"', html))
        broken = []
        for target, resolved, fragment in _relative_targets(page):
            if resolved is not None and not resolved.exists():
                broken.append(target)
            elif resolved is None and fragment and fragment not in ids:
                broken.append(target)
        self.assertEqual(broken, [], "Broken local links in docs/index.html")
        app = (REPO / "docs" / "app.js").read_text(encoding="utf-8")
        # Some elements are written by app.js itself (for example the per-platform copy button).
        ids |= set(re.findall(r'\bid="([^"$]+)"', app))
        missing_ids = sorted(set(re.findall(r'getElementById\("([^"]+)"\)', app)) - ids)
        self.assertEqual(missing_ids, [], "docs/app.js looks up elements that docs/index.html does not have")
        missing_controls = sorted(set(re.findall(r'aria-controls="([^"]+)"', html)) - ids)
        self.assertEqual(missing_controls, [])

    def test_release_archive_keeps_relative_links_working(self):
        """Links must not point into paths that .gitattributes leaves out of the release ZIP."""
        patterns = _export_ignored_patterns()
        if patterns is None:
            self.skipTest(".gitattributes is not part of the release archive")
        broken = []
        for source in [*_markdown_files(), REPO / "docs" / "index.html"]:
            rel_source = source.relative_to(REPO).as_posix()
            if _is_export_ignored(rel_source, patterns):
                continue
            for target, resolved, _fragment in _relative_targets(source):
                if resolved is None:
                    continue
                try:
                    rel_target = resolved.relative_to(REPO).as_posix()
                except ValueError:
                    continue
                if _is_export_ignored(rel_target, patterns):
                    broken.append(f"{rel_source} -> {target}")
        self.assertEqual(
            broken, [],
            "These links break in the release ZIP (target is export-ignored):\n" + "\n".join(broken),
        )

    def test_release_notes_use_absolute_links(self):
        """release.yml pastes these files into the GitHub release page, where relative links 404."""
        notes_dir = REPO / "docs" / "releases"
        if not notes_dir.is_dir():
            self.skipTest("docs/releases is not part of the release archive")
        relative = [
            f"{notes.name} -> {target}"
            for notes in sorted(notes_dir.glob("*.md"))
            for target, _resolved, _fragment in _relative_targets(notes)
        ]
        self.assertEqual(relative, [], "Release notes must link to full repository URLs")

    def test_release_gate_checks_the_test_jobs_tests_yml_defines_before_packaging(self):
        """release.yml packages only after these jobs passed; a renamed job would block every release."""
        workflows = REPO / ".github" / "workflows"
        if not workflows.is_dir():
            self.skipTest(".github is not part of the release archive")
        tests_yml = (workflows / "tests.yml").read_text(encoding="utf-8")
        release_yml = (workflows / "release.yml").read_text(encoding="utf-8")
        template = re.search(r"^  tests:\n(?:    .*\n|\n)*?    name: (.+)$", tests_yml, re.MULTILINE).group(1)
        combos = re.findall(r'- os: (\S+)\n\s+python: "([^"]+)"', tests_yml)
        self.assertEqual(len(combos), 3, "tests.yml matrix changed; update the release gate too")
        expected = sorted(
            template.replace("${{ matrix.os }}", os_name).replace("${{ matrix.python }}", python)
            for os_name, python in combos
        )
        required = re.search(r"^\s*required=\((.*)\)$", release_yml, re.MULTILINE).group(1)
        self.assertEqual(sorted(re.findall(r'"([^"]+)"', required)), expected)
        self.assertLess(release_yml.index("actions/workflows/tests.yml/runs"), release_yml.index("git archive"))
        self.assertIn("workflow_dispatch:", tests_yml, "the gate's re-run instructions need a manual trigger")

    def test_public_text_does_not_cite_private_research_files(self):
        markers = ("research-reports", "随包研究资料")
        # Files that explain what was removed and why, plus the sync tooling and tests that guard it.
        allowed = {"THIRD-PARTY-NOTICES.md", "CHANGELOG.md", "AUTO-UPDATE.md", ".gitignore"}
        suffixes = {".md", ".html", ".js", ".css", ".json", ".txt", ".svg", ".conf", ".py", ".ps1", ".cmd", ".yml"}
        offenders = []
        for path in sorted(REPO.rglob("*")):
            rel = path.relative_to(REPO)
            if SKIPPED_DIRS.intersection(rel.parts) or not path.is_file():
                continue
            rel_posix = rel.as_posix()
            if rel.parts[0] == "tools" or path.name.startswith("test_") or rel_posix in allowed:
                continue
            if path.suffix.lower() not in suffixes:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            offenders.extend(f"{rel_posix}: {marker}" for marker in markers if marker in text)
        self.assertEqual(offenders, [], "Public files still point at the private research mirror")

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

    def _run_app_js(self, script):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is not installed")
        proc = subprocess.run(
            [node, "-e", script, str(REPO / "docs" / "app.js")],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        return json.loads(proc.stdout)

    def test_ui_kill_switch_preview_matches_python_rule_table(self):
        cases = [
            {"interfaces": ["WLAN"], "upstreamIp": "1.1.1.1", "port": 443, "protocol": "TCP", "dhcp": ["192.168.1.1"]},
            {"interfaces": ["WLAN", "Ethernet"], "upstreamIp": "8.8.8.8", "port": 8443, "protocol": "UDP", "dhcp": []},
            {"interfaces": ["以太网", "WLAN"], "upstreamIp": "192.168.50.2", "port": 1, "protocol": "TCP",
             "dhcp": ["192.168.50.1", "10.0.0.1"]},
            {"interfaces": ["Ethernet 3"], "upstreamIp": "9.9.9.9", "port": 65535, "protocol": "UDP", "dhcp": ["172.16.0.1"]},
        ]
        rejected_names = ["WLAN​", "WLAN\t2", "WLAN 2", "W\u0007LAN"]
        script = r"""
const path = require("path");
const app = require(path.resolve(process.argv[1]));
const cases = %s;
const plans = cases.map((c) => app.computeKillSwitchPlan({
  interfaces: c.interfaces, upstreamIp: c.upstreamIp, port: c.port, protocol: c.protocol,
  dhcpRaw: c.dhcp.join(", "), usesDhcp: c.dhcp.length > 0
}));
const rejected = %s.map((name) => Boolean(app.computeKillSwitchPlan({
  interfaces: [name], upstreamIp: "1.1.1.1", port: 443, protocol: "TCP", dhcpRaw: "", usesDhcp: false
}).error));
const curly = Boolean(app.computeKillSwitchPlan({
  interfaces: ["Office’s WLAN"], upstreamIp: "1.1.1.1", port: 443, protocol: "TCP", dhcpRaw: "", usesDhcp: false
}).error);
const okPlan = app.computeKillSwitchPlan({interfaces: ["WLAN"], upstreamIp: "1.1.1.1", port: 443, protocol: "TCP", dhcpRaw: "192.168.1.1", usesDhcp: true});
const cmds = app.buildPlannerCommands(okPlan);
const emptyPort = Boolean(app.computeKillSwitchPlan({interfaces: ["WLAN"], upstreamIp: "1.1.1.1", port: "", protocol: "TCP", dhcpRaw: "", usesDhcp: false}).error);
console.log(JSON.stringify({ previews: plans.map((p) => p.previewJson), counts: plans.map((p) => p.ruleCount), rejected, curly, cmds, emptyPort }));
""" % (json.dumps(cases, ensure_ascii=True), json.dumps(rejected_names, ensure_ascii=True))
        data = self._run_app_js(script)
        for case, preview, count in zip(cases, data["previews"], data["counts"]):
            expected = build_kill_switch.build_plan(
                case["interfaces"], case["upstreamIp"], case["port"], case["protocol"], dhcp_servers=tuple(case["dhcp"]),
            )
            self.assertEqual(preview, expected, f"UI kill-switch preview differs from build_kill_switch.py for {case}")
            self.assertEqual(count, len(expected["Rules"]))
        for name, rejected in zip(rejected_names, data["rejected"]):
            with self.assertRaises(ValueError):
                build_kill_switch.build_plan([name], "1.1.1.1", 443, "TCP")
            self.assertTrue(rejected, f"UI accepted an adapter name that the planners reject: {name!r}")
        self.assertTrue(data["curly"], "UI must refuse curly single quotes that PowerShell treats as quotes")
        self.assertTrue(data["emptyPort"], "An empty port box must be an error, not a silent 443")
        cmds = data["cmds"]
        self.assertNotIn("-Action Remove", cmds["ksCmd"])
        self.assertNotIn("-Action Remove", cmds["lanCmd"])
        self.assertIn("-Action Remove", cmds["ksRemoveCmd"])
        self.assertIn("-Action Remove", cmds["lanRemoveCmd"])
        # Without -Force, Windows PowerShell 5.1 asks for confirmation (default No), and a pasted
        # block would answer that prompt with its next line.
        self.assertIn("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force", cmds["ksCmd"])
        self.assertIn("& .\\Manage-WindowsKillSwitch.ps1 -Action Preview @settings", cmds["ksCmd"])
        self.assertNotIn("-File .\\Manage-WindowsKillSwitch.ps1 -Action Preview @settings", cmds["ksCmd"])

    def test_ui_checklist_storage_tolerates_corrupt_values(self):
        stored = ["null", "[1, 2]", "5", '"text"', "{broken", '{"win-backup": true}']
        script = r"""
const path = require("path");
const stored = %s;
const results = stored.map((value) => {
  globalThis.localStorage = { getItem: () => value, setItem: () => {} };
  const file = path.resolve(process.argv[1]);
  delete require.cache[require.resolve(file)];
  return require(file).loadChecklistState();
});
console.log(JSON.stringify(results));
""" % json.dumps(stored)
        results = self._run_app_js(script)
        self.assertEqual(results, [{}, {}, {}, {}, {}, {"win-backup": True}])

    def test_auto_update_excludes_private_research_mirrors(self):
        auto_path = REPO / "tools" / "auto_update.py"
        if not auto_path.is_file():
            self.skipTest("tools/auto_update.py is excluded from release archive")
        spec = importlib.util.spec_from_file_location("auto_update", auto_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for protected in ("LICENSE", "THIRD-PARTY-NOTICES.md", "docs", ".github", "CHANGELOG.md", "PRIVACY-CHECKLIST.md"):
            self.assertIn(protected, mod.REPO_ONLY)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "research-reports" / "sources").mkdir(parents=True)
            (root / "research-reports" / "sources" / "mirror.md").write_text("x", encoding="utf-8")
            (root / "THIRD-PARTY-NOTICE.md").write_text("old", encoding="utf-8")
            (root / "ok.py").write_text("pass\n", encoding="utf-8")
            rels = [p.as_posix() for p in mod.kit_files(root, skip_repo_only=True)]
            self.assertEqual(rels, ["ok.py"])
        # The gate reads what git tracks or would add. When git refuses this folder (for example
        # "detected dubious ownership" for a clone made in an administrator window), the gate falls
        # back to every file in the folder, ignored local ones such as .venv included. The sync
        # itself stops before that, so this check only runs where git lists the folder.
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        listing = subprocess.run(["git", "--literal-pathspecs", "ls-files", "-co", "--exclude-standard", "-z"],
                                 cwd=REPO, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if listing.returncode:
            message = (listing.stderr.strip().splitlines() or ["no message"])[0]
            self.skipTest(f"git does not list this folder: {message}")
        mod.privacy_gate()

    def test_release_version_and_offline_html_report_consistency(self):
        version = environment_report.KIT_VERSION
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        ui_html = (REPO / "docs" / "index.html").read_text(encoding="utf-8")
        changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"v{version}", readme)
        self.assertIn(f"v{version}", ui_html)
        self.assertIn(f"## v{version}", changelog)
        # Spots that went stale before: badge, download link, page title, page script, cover image.
        self.assertTrue(f'alt="版本 v{version}"' in readme, "README version badge is stale")
        self.assertTrue(f"/releases/tag/v{version}" in readme, "README download link is stale")
        title = re.search(r"<title>(.*?)</title>", ui_html, re.S).group(1)
        self.assertIn(f"v{version}", title)
        app_js = (REPO / "docs" / "app.js").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r'const KIT_VERSION = "([^"]+)";', app_js), [version])
        self.assertNotRegex(app_js, r'kitVersion:\s*"', "docs/app.js must export KIT_VERSION, not a literal")
        cover = (REPO / "docs" / "images" / "architecture-cover.svg").read_text(encoding="utf-8")
        self.assertEqual(sorted(set(VERSION_TOKEN.findall(cover)) - {version}), [])
        # Test counts are left out of the docs on purpose; a hard-coded number goes stale with every new test.
        for name, text in (("README.md", readme), ("docs/index.html", ui_html)):
            self.assertNotRegex(text, r"\d+\s*项测试|全部\s*\d+\s*项|%E6%B5%8B%E8%AF%95-\d+", name)
        notes = REPO / "docs" / "releases" / f"v{version}.md"
        if (REPO / "docs" / "releases").is_dir():
            self.assertTrue(notes.is_file(), f"Missing release notes docs/releases/v{version}.md")
            self.assertTrue(notes.read_text(encoding="utf-8").startswith(f"# v{version} — "))
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
