"""Parse and cross-verify PowerShell security scripts on Windows, and pin their shared parts everywhere."""

import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest

import build_kill_switch as kill_switch
import build_lan_dns_guard as lan_dns_guard


SCRIPTS = Path(__file__).resolve().parent
KILL_SWITCH = SCRIPTS / "Manage-WindowsKillSwitch.ps1"
LAN_DNS_GUARD = SCRIPTS / "Manage-WindowsLanDnsGuard.ps1"
MANAGEMENT_SCRIPTS = ("Manage-WindowsKillSwitch.ps1", "Manage-WindowsLanDnsGuard.ps1")

# Allow entries fed to Get-SharedWriteGrant, with the number of findings each must produce.
# Rights are FileSystemRights values; the generic bits (inherit-only entries on C:\Program Files,
# CREATOR OWNER) are not names of that enum, so those cases use plain numbers.
ACL_CASES = {
    "users-read-execute-synchronize": ("S-1-5-32-545", "ReadAndExecute, Synchronize", "None", "Allow", 0),
    "users-read": ("S-1-5-32-545", "Read", "None", "Allow", 0),
    "authenticated-users-read-execute": ("S-1-5-11", "ReadAndExecute, Synchronize", "None", "Allow", 0),
    "users-generic-read-execute-inherit-only": ("S-1-5-32-545", -1610612736, "InheritOnly", "Allow", 0),
    "creator-owner-generic-all-inherit-only": ("S-1-3-0", 268435456, "InheritOnly", "Allow", 0),
    "administrators-full-control": ("S-1-5-32-544", "FullControl", "None", "Allow", 0),
    "system-full-control": ("S-1-5-18", "FullControl", "None", "Allow", 0),
    "users-modify-deny": ("S-1-5-32-545", "Modify", "None", "Deny", 0),
    "users-modify-inherit-only": ("S-1-5-32-545", "Modify", "InheritOnly", "Allow", 0),
    "users-modify": ("S-1-5-32-545", "Modify", "None", "Allow", 1),
    "users-write": ("S-1-5-32-545", "Write", "None", "Allow", 1),
    "everyone-full-control": ("S-1-1-0", "FullControl", "None", "Allow", 1),
    "authenticated-users-append-data": ("S-1-5-11", "AppendData", "None", "Allow", 1),
    "interactive-write-data": ("S-1-5-4", "WriteData", "None", "Allow", 1),
    "guests-delete": ("S-1-5-32-546", "Delete", "None", "Allow", 1),
    "users-change-permissions": ("S-1-5-32-545", "ChangePermissions", "None", "Allow", 1),
    "users-take-ownership": ("S-1-5-32-545", "TakeOwnership", "None", "Allow", 1),
    "users-generic-write": ("S-1-5-32-545", 1073741824, "None", "Allow", 1),
    "users-generic-all": ("S-1-5-32-545", 268435456, "None", "Allow", 1),
}

# (requested family, stage, families with a tunnel default route) -> (family probed, preflight passes)
FAMILY_CASES = [
    (("auto", "normal", ["ipv4"]), ("ipv4", True)),
    (("auto", "normal", ["ipv6"]), ("ipv6", True)),
    (("auto", "normal", ["ipv4", "ipv6"]), ("auto", True)),
    (("auto", "normal", []), ("auto", False)),
    (("auto", "upstream-unreachable", ["ipv4"]), ("ipv4", True)),
    (("auto", "tun-down", ["ipv4"]), ("auto", True)),
    (("auto", "client-down", []), ("auto", False)),
    (("ipv4", "normal", ["ipv6"]), ("ipv4", False)),
    (("ipv4", "normal", ["ipv4"]), ("ipv4", True)),
    (("ipv6", "upstream-unreachable", ["ipv4", "ipv6"]), ("ipv6", True)),
]

ACCEPTED_ALIASES = ["无线网络连接", "以太网 2", "以太网", "Wi-Fi 2", "wifi", "WLAN", "Ethernet 10", "Ethernet 9"]
REJECTED_ALIAS_LISTS = [
    ["Wi\u00a0Fi"],          # no-break space
    ["WLAN\u200b"],          # zero-width space
    ["Eth\u2028ernet"],      # line separator
    ["Eth\ue000"],           # private use
    ["Wi-Fi", "wi-fi"],      # duplicate (the kill switch used to drop it silently)
    ["Eth*"],
    ["Any"],
]


def _function_source(text, name):
    match = re.search(r"^function " + re.escape(name) + r" \{\n.*?^\}$", text, re.M | re.S)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


def _read_script(name):
    return (SCRIPTS / name).read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def _extract_function_command(script, function_name):
    """PowerShell lines that define one function of a script without running the script."""
    return (
        "$ast = [System.Management.Automation.Language.Parser]::ParseFile("
        f"(Join-Path (Get-Location).Path '{script}'), [ref]$null, [ref]$null)\n"
        "$fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] "
        f"-and $n.Name -eq '{function_name}' }}, $true)\n"
        f"if ($null -eq $fn) {{ throw 'function {function_name} not found in {script}' }}\n"
        ". ([scriptblock]::Create($fn.Extent.Text))\n"
    )


class PowerShellSourcePinTests(unittest.TestCase):
    """Text checks on the .ps1 files that run on every platform."""

    def test_bomless_scripts_are_ascii(self):
        # Windows PowerShell 5.1 reads a .ps1 without a BOM in the ANSI code page, so any non-ASCII
        # byte would turn into a different character on Chinese Windows.
        for path in sorted(SCRIPTS.glob("*.ps1")):
            data = path.read_bytes()
            if data.startswith(b"\xef\xbb\xbf"):
                continue
            with self.subTest(script=path.name):
                self.assertTrue(data.isascii(), f"{path.name} has non-ASCII bytes but no UTF-8 BOM")

    def test_management_scripts_share_their_safety_functions(self):
        ks, lan = (_read_script(name) for name in MANAGEMENT_SCRIPTS)
        for name in ("Get-SharedWriteGrant", "Test-LiteralInterfaceAlias", "Format-AliasForMessage",
                     "Assert-UnlinkedLocalDirectory", "Set-PrivateFileAcl", "Write-StderrWarning",
                     "Test-OwnedRule", "Test-SameSet", "Test-Any", "Remove-OwnedRules"):
            with self.subTest(function=name):
                self.assertEqual(_function_source(ks, name), _function_source(lan, name))
        # The location check differs only in the script name and in what Remove would leave in place.
        ks_check = _function_source(ks, "Assert-SafeElevatedScriptPath").replace(
            "Manage-WindowsKillSwitch.ps1", "<script>").replace("keeps the network blocked", "<effect>")
        lan_check = _function_source(lan, "Assert-SafeElevatedScriptPath").replace(
            "Manage-WindowsLanDnsGuard.ps1", "<script>").replace("keeps the rules in place", "<effect>")
        self.assertEqual(ks_check, lan_check)

    def test_change_rights_mask_is_the_write_type_rights_only(self):
        # .NET FileSystemRights values.
        rights = dict(ReadData=1, WriteData=2, AppendData=4, ReadExtendedAttributes=8, WriteExtendedAttributes=16,
                      ExecuteFile=32, DeleteSubdirectoriesAndFiles=64, ReadAttributes=128, WriteAttributes=256,
                      Delete=65536, ReadPermissions=131072, ChangePermissions=262144, TakeOwnership=524288,
                      Synchronize=1048576)
        rights.update(Read=131209, ReadAndExecute=131241, Write=278, Modify=197055, FullControl=2032127)
        change = sum(rights[n] for n in ("WriteData", "AppendData", "WriteExtendedAttributes", "WriteAttributes",
                                         "Delete", "DeleteSubdirectoriesAndFiles", "ChangePermissions",
                                         "TakeOwnership"))
        self.assertEqual(change, 0x000D0156)
        mask = change | 0x10000000 | 0x40000000
        for name in ("Read", "ReadAndExecute", "Synchronize", "ReadPermissions"):
            self.assertEqual(rights[name] & mask, 0, name)
        self.assertEqual((rights["ReadAndExecute"] | rights["Synchronize"]) & mask, 0)
        self.assertEqual(0xA0000000 & mask, 0)  # GENERIC_READ | GENERIC_EXECUTE
        for name in ("Write", "Modify", "FullControl", "AppendData", "Delete", "ChangePermissions"):
            self.assertNotEqual(rights[name] & mask, 0, name)
        # The bug in v0.4.2: Write | Modify | FullControl | ChangePermissions | TakeOwnership is FullControl,
        # which also hits read-only entries.
        old = rights["Write"] | rights["Modify"] | rights["FullControl"] | rights["ChangePermissions"] | rights["TakeOwnership"]
        self.assertEqual(old, rights["FullControl"])
        self.assertNotEqual((rights["ReadAndExecute"] | rights["Synchronize"]) & old, 0)
        for name in MANAGEMENT_SCRIPTS:
            source = _function_source(_read_script(name), "Get-SharedWriteGrant")
            self.assertIn("$changeRights = [long]0x000D0156 -bor [long]0x10000000 -bor [long]0x40000000", source)
            for sid in ("S-1-1-0", "S-1-5-4", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546"):
                self.assertIn(f"'{sid}'", source)

    def test_rule_names_and_owner_text_match_planners_and_manual_removal(self):
        doc = (SCRIPTS / "WINDOWS-KILL-SWITCH.md").read_text(encoding="utf-8")
        ks = _read_script("Manage-WindowsKillSwitch.ps1")
        lan = _read_script("Manage-WindowsLanDnsGuard.ps1")
        known = re.search(r"^\$KnownNames = @\((.*?)\) \| ForEach-Object", ks, re.M | re.S).group(1)
        ks_names = re.findall(r"'([A-Za-z0-9]+)'", known)
        planned = [rule["Name"].removeprefix(kill_switch.RULE_PREFIX)
                   for rule in kill_switch.build_plan(["Wi-Fi"], "8.8.8.8", 443, "TCP", ["192.168.1.1"])["Rules"]]
        self.assertEqual(sorted(ks_names), sorted(planned))
        self.assertEqual(len(ks_names), 15)
        manual = re.search(r"\$group = 'CPPEK-KillSwitch-v1'\n\$names = @\((.*?)\) \| ForEach-Object", doc, re.S)
        self.assertIsNotNone(manual, "manual kill-switch removal snippet not found in WINDOWS-KILL-SWITCH.md")
        self.assertEqual(re.findall(r"'([A-Za-z0-9]+)'", manual.group(1)), ks_names)
        ks_owner = re.search(r"^\$Owner = '([^']+)'", ks, re.M).group(1)
        self.assertIn(f"$_.Description -ceq '{ks_owner}'", doc)
        self.assertIn("$Group = 'CPPEK-KillSwitch-v1'", ks)

        lan_known = re.search(r"^\$KnownNames = @\(([^)]*)\)", lan, re.M).group(1)
        lan_names = re.findall(r"'([A-Za-z0-9-]+)'", lan_known)
        lan_planned = [rule["Name"].removeprefix(lan_dns_guard.RULE_PREFIX)
                       for rule in lan_dns_guard.build_plan(["Wi-Fi"])["Rules"]]
        self.assertEqual(lan_names, lan_planned)
        self.assertIn("$names = @(" + ", ".join(f"'{n}'" for n in lan_names) + ")", doc)
        lan_owner = re.search(r"^\$Owner = '([^']+)'", lan, re.M).group(1)
        self.assertIn(f"$_.Description -ceq '{lan_owner}'", doc)
        for prefix in lan_dns_guard.LAN_IPV4_PREFIXES + lan_dns_guard.LAN_IPV6_PREFIXES:
            self.assertIn(f"'{prefix}'", lan)

    def test_tunnel_name_pattern_is_the_same_in_every_script(self):
        patterns = {}
        for name in ("Test-ProxyState.ps1", "Manage-WindowsKillSwitch.ps1", "Inspect-WindowsProxy.ps1"):
            found = re.findall(r"\$tunnel(?:Pattern|Regex) = '([^']+)'", _read_script(name))
            self.assertEqual(len(found), 1, name)
            patterns[name] = found[0]
        self.assertEqual(len(set(patterns.values())), 1, patterns)


@unittest.skipUnless(os.name == "nt", "Requires Windows PowerShell")
class KillSwitchPowerShellTests(unittest.TestCase):
    def setUp(self):
        system_root = Path(os.environ["SystemRoot"])
        self.powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"

    def run_powershell(self, command, env=None, timeout=30):
        # -EncodedCommand carries the text as UTF-16, so no quoting or code page gets in the way.
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        return subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded],
            cwd=SCRIPTS, env=env, capture_output=True, text=True, encoding="utf-8", timeout=timeout, check=False,
        )

    def test_windows_powershell_parses_all_bundled_scripts(self):
        command = """
$ErrorActionPreference = 'Stop'
$scripts = @(
    'Manage-WindowsKillSwitch.ps1',
    'Manage-WindowsLanDnsGuard.ps1',
    'Get-WindowsKillSwitchEvidence.ps1',
    'Test-ProxyState.ps1',
    'Inspect-WindowsProxy.ps1',
    'Inspect-WindowsFirewall.ps1',
    'Collect-WindowsEvidence.ps1'
)
foreach ($path in $scripts) {
    $parseTokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path (Get-Location).Path $path), [ref]$parseTokens, [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        $parseErrors | ForEach-Object { [Console]::Error.WriteLine($_.ToString()) }
        exit 1
    }
}
"""
        result = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=SCRIPTS, capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_powershell_planner_matches_python_without_external_py_exe(self):
        # Empty PATH proves Manage-WindowsKillSwitch.ps1 no longer resolves py.exe from PATH.
        isolated_env = dict(os.environ, PATH=r"C:\nonexistent-empty-path")
        command = (
            "& .\\Manage-WindowsKillSwitch.ps1 -Action Preview "
            "-InterfaceAlias @('Wi-Fi', 'Ethernet') "
            "-UpstreamAddress '8.8.8.8' -UpstreamPort 443 -UpstreamProtocol 'TCP' "
            "-DhcpServer @('192.168.1.1', '10.1.1.2')"
        )
        result = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=SCRIPTS, env=isolated_env, capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        ps_plan = json.loads(result.stdout)
        py_plan = kill_switch.build_plan(
            ["Wi-Fi", "Ethernet"], "8.8.8.8", 443, "TCP", ["192.168.1.1", "10.1.1.2"]
        )
        self.assertEqual(ps_plan, py_plan)

    def test_native_powershell_planner_without_dhcp_server_matches_python(self):
        isolated_env = dict(os.environ, PATH=r"C:\nonexistent-empty-path")
        command = (
            "& .\\Manage-WindowsKillSwitch.ps1 -Action Preview "
            "-InterfaceAlias @('CPPEK-Test-Missing-Adapter') "
            "-UpstreamAddress '8.8.8.8' -UpstreamPort 443 -UpstreamProtocol 'UDP'"
        )
        result = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=SCRIPTS, env=isolated_env, capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        ps_plan = json.loads(result.stdout)
        py_plan = kill_switch.build_plan(["CPPEK-Test-Missing-Adapter"], "8.8.8.8", 443, "UDP")
        self.assertEqual(ps_plan, py_plan)
        self.assertEqual(ps_plan["DhcpServers"], [])
        # A missing adapter has no IPv4 settings to read: Preview warns that Install would need -DhcpServer.
        self.assertIn("couldnotberead", re.sub(r"\s+", "", result.stderr))

    def test_native_lan_dns_guard_planner_matches_python_without_external_py_exe(self):
        isolated_env = dict(os.environ, PATH=r"C:\nonexistent-empty-path")
        command = (
            "& .\\Manage-WindowsLanDnsGuard.ps1 -Action Preview "
            "-InterfaceAlias @('Wi-Fi', 'Ethernet')"
        )
        result = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=SCRIPTS, env=isolated_env, capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        ps_plan = json.loads(result.stdout)
        py_plan = lan_dns_guard.build_plan(["Wi-Fi", "Ethernet"])
        self.assertEqual(ps_plan, py_plan)

    def test_adapter_name_rules_and_order_match_python_planners(self):
        def preview(script, names):
            extra = " -UpstreamAddress '8.8.8.8' -UpstreamPort 443" if script == "Manage-WindowsKillSwitch.ps1" else ""
            # JSON with \u escapes keeps the command ASCII; ConvertFrom-Json turns them back into characters.
            # Windows PowerShell 5.1 writes a parsed JSON array as one object, so assign it before casting.
            command = (
                "$parsed = ConvertFrom-Json '" + json.dumps(names, ensure_ascii=True) + "'\n"
                "$names = [string[]]$parsed\n"
                f"& .\\{script} -Action Preview -InterfaceAlias $names{extra}\n"
            )
            return self.run_powershell(command)

        for script, planner in (("Manage-WindowsKillSwitch.ps1",
                                 lambda names: kill_switch.build_plan(names, "8.8.8.8", 443, "TCP")),
                                ("Manage-WindowsLanDnsGuard.ps1", lan_dns_guard.build_plan)):
            with self.subTest(script=script, names="accepted"):
                result = preview(script, ACCEPTED_ALIASES)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), planner(ACCEPTED_ALIASES))
            for names in REJECTED_ALIAS_LISTS:
                with self.subTest(script=script, names=names):
                    with self.assertRaises(ValueError):
                        planner(names)
                    result = preview(script, names)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    # Windows PowerShell can wrap redirected error text at the console width, even mid-word.
                    compact = re.sub(r"\s+", "", result.stderr)
                    self.assertRegex(compact, r"Useliteralinterfacealiases|Interfacealiasesmustbeunique", result.stderr)

    def test_shared_write_grant_ignores_read_only_entries(self):
        cases = {}
        for label, (sid, rights, propagation, kind, _) in ACL_CASES.items():
            if isinstance(rights, int):
                cases[label] = {"Sid": sid, "Number": rights, "Propagation": propagation, "Type": kind}
            else:
                cases[label] = {"Sid": sid, "Names": rights, "Propagation": propagation, "Type": kind}
        for script in MANAGEMENT_SCRIPTS:
            command = (
                "$ErrorActionPreference = 'Stop'\n"
                + _extract_function_command(script, "Get-SharedWriteGrant")
                + "$cases = ConvertFrom-Json '" + json.dumps(cases) + "'\n"
                + """$out = [ordered]@{}
foreach ($property in $cases.PSObject.Properties) {
    $case = $property.Value
    $sid = [Security.Principal.SecurityIdentifier]::new($case.Sid)
    $propagation = [Security.AccessControl.PropagationFlags]$case.Propagation
    if ($case.PSObject.Properties['Names']) {
        # A real FileSystemAccessRule, as Get-Acl returns them.
        $inheritance = if ($propagation -eq 'InheritOnly') { 'ContainerInherit, ObjectInherit' } else { 'None' }
        $entry = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, [Security.AccessControl.FileSystemRights]$case.Names,
            [Security.AccessControl.InheritanceFlags]$inheritance, $propagation,
            [Security.AccessControl.AccessControlType]$case.Type)
    } else {
        # Generic rights cannot be put into a FileSystemAccessRule; use a stand-in with the same properties.
        $entry = [pscustomobject]@{
            IdentityReference = $sid; FileSystemRights = [int]$case.Number
            PropagationFlags = $propagation; AccessControlType = [string]$case.Type
        }
    }
    $out[$property.Name] = @(Get-SharedWriteGrant -Rule @($entry)).Count
}
[pscustomobject]$out | ConvertTo-Json
"""
            )
            with self.subTest(script=script):
                result = self.run_powershell(command)
                self.assertEqual(result.returncode, 0, result.stderr)
                counts = json.loads(result.stdout)
                self.assertEqual(counts, {label: case[4] for label, case in ACL_CASES.items()})

    def test_proxy_state_probes_only_the_families_the_tunnel_routes(self):
        cases = [{"Requested": r, "Stage": s, "Families": f} for (r, s, f), _ in FAMILY_CASES]
        command = (
            "$ErrorActionPreference = 'Stop'\n"
            + _extract_function_command("Test-ProxyState.ps1", "Resolve-ProbeAddressFamily")
            + "$cases = ConvertFrom-Json '" + json.dumps(cases) + "'\n"
            + """$decisions = @(foreach ($case in $cases) {
    $decision = Resolve-ProbeAddressFamily -Requested $case.Requested -Stage $case.Stage -TunnelFamilies ([string[]]@($case.Families))
    [pscustomobject]@{ Effective = [string]$decision.Effective; Detected = [bool]$decision.TunnelRouteDetected }
})
ConvertTo-Json -InputObject $decisions -Compress
"""
        )
        result = self.run_powershell(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        got = [(item["Effective"], item["Detected"]) for item in json.loads(result.stdout)]
        self.assertEqual(got, [expected for _, expected in FAMILY_CASES])

    def test_offline_page_preview_command_runs_and_matches_python(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is not installed")
        cases = [
            {"interfaces": ["WLAN"], "upstreamIp": "1.1.1.1", "port": 443, "protocol": "TCP", "dhcp": ["192.168.1.1"]},
            {"interfaces": ["Wi-Fi", "Ethernet 2"], "upstreamIp": "8.8.8.8", "port": 8443, "protocol": "UDP", "dhcp": []},
            {"interfaces": ["以太网", "WLAN 2"], "upstreamIp": "192.168.50.2", "port": 1, "protocol": "TCP",
             "dhcp": ["192.168.50.1", "10.0.0.1"]},
        ]
        script = r"""
const path = require("path");
const app = require(path.resolve(process.argv[1]));
const cases = JSON.parse(process.argv[2]);
console.log(JSON.stringify(cases.map((c) => app.buildPlannerCommands(app.computeKillSwitchPlan({
  interfaces: c.interfaces, upstreamIp: c.upstreamIp, port: c.port, protocol: c.protocol,
  dhcpRaw: c.dhcp.join(", "), usesDhcp: c.dhcp.length > 0
})).ksCmd)));
"""
        generated = subprocess.run(
            [node, "-e", script, str(SCRIPTS / "docs" / "app.js"), json.dumps(cases)],
            capture_output=True, text=True, encoding="utf-8", check=True,
        )
        for case, block in zip(cases, json.loads(generated.stdout)):
            with self.subTest(case=case):
                # Only the part up to and including Preview: the rest would install the rules.
                preview_part = block.split("# 2.", 1)[0]
                self.assertIn("-Action Preview @settings", preview_part)
                self.assertNotIn("-Action Install", preview_part)
                result = self.run_powershell(preview_part)
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = kill_switch.build_plan(case["interfaces"], case["upstreamIp"], case["port"],
                                                  case["protocol"], case["dhcp"])
                self.assertEqual(json.loads(result.stdout), expected)

    def test_evidence_collector_requires_source_port_by_default(self):
        command = (
            "& .\\Get-WindowsKillSwitchEvidence.ps1 "
            "-Since (Get-Date).AddMinutes(-5) -Until (Get-Date) "
            "-DestinationAddress '93.184.216.34' -DestinationPort 443 -ApplicationName 'curl.exe'"
        )
        result = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=SCRIPTS, capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SourcePort", result.stderr)


if __name__ == "__main__":
    unittest.main()
