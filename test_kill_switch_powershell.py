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

# Synthetic adapters for Select-NamedTunnelAdapter (Test-ProxyState.ps1), and what each set of
# -TunnelInterfaceAlias names must give: (tunnel ifIndex values, missing, not Up, physical).
TUNNEL_ADAPTERS = [
    {"Name": "WLAN", "InterfaceDescription": "Intel(R) Wi-Fi 6 AX201 160MHz", "Status": "Up", "HardwareInterface": True, "ifIndex": 12},
    {"Name": "以太网", "InterfaceDescription": "Realtek PCIe GbE Family Controller", "Status": "Disconnected", "HardwareInterface": True, "ifIndex": 5},
    {"Name": "Meta Tunnel", "InterfaceDescription": "Meta Tunnel", "Status": "Up", "HardwareInterface": False, "ifIndex": 30},
    {"Name": "tun-off", "InterfaceDescription": "Wintun Userspace Tunnel", "Status": "Disconnected", "HardwareInterface": False, "ifIndex": 31},
]
NAMED_TUNNEL_CASES = [
    (["Meta Tunnel"], ([30], [], [], [])),
    (["meta tunnel"], ([30], [], [], [])),            # Windows adapter names are not case-sensitive
    (["WLAN"], ([], [], [], ["WLAN"])),               # a physical adapter never counts as a tunnel
    (["以太网"], ([], [], [], ["以太网"])),            # physical, even when it is down
    (["Meta Tunnel", "WLAN"], ([30], [], [], ["WLAN"])),
    (["tun-off"], ([], [], ["tun-off"], [])),
    (["no-such-adapter"], ([], ["no-such-adapter"], [], [])),
]

FAKE_IP_SAMPLES = ["198.18.0.1", "198.19.255.254", "198.17.255.255", "198.20.0.0", "93.184.216.34",
                   "fc00::1", "fc00:3fff:ffff::1", "fc00:4000::1", "fc01::1", "fd00::1", "2606:2800:220:1::",
                   "", "not-an-address"]
# (DNS cache entries as Get-DnsClientCache gives them: Type 1 = A, 28 = AAAA, 5 = CNAME) -> FakeIpOnly
FAKE_IP_CACHE_CASES = [
    ([{"Type": 1, "Data": "198.18.0.5"}], True),
    ([{"Type": 28, "Data": "fc00::5"}, {"Type": 1, "Data": "198.18.3.4"}], True),
    ([{"Type": 1, "Data": "198.18.0.5"}, {"Type": 1, "Data": "93.184.216.34"}], False),
    ([{"Type": 1, "Data": "93.184.216.34"}], False),
    ([{"Type": 5, "Data": "cdn.example.net"}], False),
    ([{"Type": 1, "Data": ""}], False),
    ([], False),
]

# Rule groups for Test-MicrosoftRuleGroup (Inspect-WindowsFirewall.ps1) -> counted as built in or Microsoft.
RULE_GROUP_CASES = [
    ("@FirewallAPI.dll,-25000", True),
    ("@%SystemRoot%\\system32\\firewallapi.dll,-37302", True),
    ("@C:\\Windows\\system32\\wfapigp.dll,-1", True),
    ("@{Microsoft.WindowsCalculator_11.2405.2.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.WindowsCalculator/Resources/AppStoreName}", True),
    ("@{MicrosoftWindows.Client.CBS_1000.22700.1047.0_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.CBS/Resources/DisplayName}", True),
    ("@{MicrosoftWindows.Client.WebExperience_424.1301.270.9_x64__cw5n1h2txyewy?ms-resource://MicrosoftWindows.Client.WebExperience/Resources/AppName}", True),
    ("@{windows.immersivecontrolpanel_10.0.6.1000_neutral_neutral_cw5n1h2txyewy?ms-resource://windows.immersivecontrolpanel/resources/DisplayName}", True),
    ("@{MicrosoftCorporationII.QuickAssist_2.0.21.0_x64__8wekyb3d8bbwe?ms-resource://MicrosoftCorporationII.QuickAssist/Resources/AppName}", True),
    ("@{MSTeams_24004.1403.2634.2418_x64__8wekyb3d8bbwe?ms-resource://MSTeams/Resources/AppName}", True),
    ("Microsoft Edge", True),
    ("Core Networking", True),
    ("Windows Remote Management", True),
    ("Clash for Windows", False),
    ("WPS Office", False),
    ("Bitdefender Agent", False),
    ("WindowsApps helper", False),
    ("@{SomeVendor.SomeApp_1.2.3.0_x64__abcdefghjkmnp?ms-resource://SomeVendor.SomeApp/Resources/AppName}", False),
    ("@{SomeVendor.Fake8wekyb3d8bbwe_1.0.0.0_x64__abcdefghjkmnp?ms-resource://SomeVendor/Resources/AppName}", False),
    ("", False),
]

# Inspect-WindowsProxy.ps1 Protect-LocalPath: (path, expected) with a synthetic profile C:\Users\alice.
PROFILE_FOLDERS = [
    ("C:\\Users\\alice\\AppData\\Local", "<LocalApplicationData>"),
    ("C:\\Users\\alice\\AppData\\Roaming", "<ApplicationData>"),
    ("C:\\Program Files", "<ProgramFiles>"),
    ("C:\\Users\\alice", "<UserProfile>"),
]
MASK_CASES = [
    ("C:\\Users\\alice\\Desktop\\v2rayN 张三公司专用\\v2rayN.exe", "<UserProfile>\\...\\v2rayN.exe"),
    ("C:\\Users\\alice\\Tools\\Clash Verge 李四\\clash-verge.exe", "<UserProfile>\\...\\clash-verge.exe"),
    ("C:\\Users\\alice\\Desktop\\Tailscale 王五的电脑\\tailscale.exe", "<UserProfile>\\...\\tailscale.exe"),
    ("C:\\Users\\alice\\Desktop\\张三工作VPN\\v2rayN.exe", "<UserProfile>\\...\\v2rayN.exe"),
    ("C:\\Users\\alice\\Desktop\\v2rayN\\v2rayN.exe", "<UserProfile>\\...\\v2rayN\\v2rayN.exe"),
    ("C:\\Users\\alice\\Desktop\\v2rayN 7.2.1\\v2rayN.exe", "<UserProfile>\\...\\v2rayN 7.2.1\\v2rayN.exe"),
    ("C:\\Users\\alice\\Apps\\Clash Verge Rev\\clash-verge.exe", "<UserProfile>\\...\\Clash Verge Rev\\clash-verge.exe"),
    ("C:\\Users\\alice\\AppData\\Local\\Programs\\mihomo-party\\mihomo-party.exe",
     "<LocalApplicationData>\\...\\mihomo-party\\mihomo-party.exe"),
    ("C:\\Users\\alice\\AppData\\Local\\张三的项目\\v2rayN\\v2rayN.exe", "<LocalApplicationData>\\...\\v2rayN\\v2rayN.exe"),
    ("C:\\Users\\alice\\v2rayN.exe", "<UserProfile>\\v2rayN.exe"),
    ("C:\\Program Files\\Clash Verge\\clash-verge.exe", "<ProgramFiles>\\Clash Verge\\clash-verge.exe"),
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


# Windows PowerShell writes redirected output in the console code page unless told otherwise;
# the scripts set UTF-8 themselves, functions pulled out of them do not.
UTF8_OUTPUT = "$ErrorActionPreference = 'Stop'\n[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n"


def _function_source(text, name):
    match = re.search(r"^function " + re.escape(name) + r" \{\n.*?^\}$", text, re.M | re.S)
    if not match:
        raise AssertionError(f"function {name} not found")
    return match.group(0)


def _read_script(name):
    return (SCRIPTS / name).read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def _main_body(text):
    """The top-level statements of a script: everything except its function definitions."""
    return re.sub(r"^function [A-Za-z0-9-]+ \{\n.*?^\}$", "", text, flags=re.M | re.S)


def _block(text, start, end):
    """The lines strictly between the first line equal to `start` and the next line equal to `end`."""
    match = re.search("^" + re.escape(start) + r"\n(.*?)^" + re.escape(end) + "$", text, re.M | re.S)
    if not match:
        raise AssertionError(f"block {start!r} .. {end!r} not found")
    return match.group(1)


def _ps_single_quoted(text, variable):
    """The value of a one-line assignment $variable = '...' (PowerShell single quotes, '' for ')."""
    found = re.findall(r"^\s*\$" + re.escape(variable) + r" = '((?:[^']|'')*)'$", text, re.M)
    if len(found) != 1:
        raise AssertionError(f"${variable} = '...' found {len(found)} times")
    return found[0].replace("''", "'")


def _as_list(value):
    # Windows PowerShell 5.1 can write a one-element array as a bare value.
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _client_folder_match(pattern, name):
    # PowerShell's -match is case-insensitive; the patterns only use syntax that .NET and Python share.
    return re.search(pattern, name, re.IGNORECASE) is not None


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

    # The checks below pin the safety-relevant control flow of the management scripts, which no
    # test runs (Install, Remove and Status change the firewall). Each one fails if the line it
    # names is reverted to the v0.4.2 behaviour.

    def test_remove_is_never_stopped_by_the_location_or_log_checks(self):
        for name in MANAGEMENT_SCRIPTS:
            with self.subTest(script=name):
                text = _read_script(name)
                body = _main_body(text)
                calls = re.findall(r"^Assert-SafeElevatedScriptPath\b.*$", body, re.M)
                self.assertEqual(calls, ["Assert-SafeElevatedScriptPath -WarnOnly:($Action -eq 'Remove')"])
                # The log is required for Install only.
                self.assertEqual(body.count("    if ($Action -ne 'Remove') { throw }\n"), 1)
                self.assertIn('Write-StderrWarning "No log is written for this Remove: $logProblem"', body)
                check = _function_source(text, "Assert-SafeElevatedScriptPath")
                self.assertIn("    if ($WarnOnly) {\n        foreach ($problem in $problems) { Write-StderrWarning $problem }", check)
                self.assertTrue(check.rstrip("}\n ").endswith("throw ($problems -join ' ')"), check)
                # A volume without NTFS/ReFS permissions is a problem for Install, not a pass.
                self.assertRegex(check, r"if \(\$drive\.DriveFormat -notin @\('NTFS', 'ReFS'\)\) \{\n\s+\$problems\.Add\(")

    def test_kill_switch_remove_reports_rules_left_in_its_group(self):
        body = _main_body(_read_script("Manage-WindowsKillSwitch.ps1"))
        remove = _block(body, "    if ($Action -eq 'Remove') {", "    } else {")
        self.assertIn("$removed = @(Remove-OwnedRules $KnownNames)", remove)
        self.assertIn("$remaining = @($status.ForeignOrUnexpectedRules)", remove)
        left = _block(remove, "        if ($remaining.Count) {", "        } else {")
        self.assertIn("Status         = 'removed-other-rules-remain'", left)
        self.assertIn("RemainingRules = $remaining", left)
        self.assertIn("$exitCode = 2", left)
        self.assertTrue(body.rstrip().endswith("exit $exitCode"))

    def test_lan_dns_guard_install_never_deletes_rules_it_did_not_add(self):
        body = _main_body(_read_script("Manage-WindowsLanDnsGuard.ps1"))
        remove = _block(body, "    if ($Action -eq 'Remove') {", "    } else {")
        install = _block(body, "    } else {", "} catch {")
        rollback = _block(body, "} catch {", "} finally {")
        self.assertIn("$removed = @(Remove-OwnedRules -Names $KnownNames)", remove)
        self.assertEqual(body.count("Remove-OwnedRules"), 2, "only Remove and the rollback may delete rules")
        self.assertIn("[void](Remove-OwnedRules -Names $created)", rollback)
        self.assertNotIn("Remove-OwnedRules", install)
        self.assertNotIn("Remove-NetFirewallRule", install)
        # Earlier rules: same plan gives already-installed, anything else is refused untouched.
        existing = _block(install, "        if ($persisted.Count -or $active.Count) {", "        } else {")
        self.assertIn("throw 'Nothing was changed: LAN DNS Guard rules are already installed but differ", existing)
        self.assertIn("Status         = 'already-installed'", existing)
        # New rules: recorded before each is created (so a failure rolls them back), staged
        # disabled, read back, then enabled together.
        staged = install.split("        } else {", 1)[1]
        order = ["$created += $entry.Name", "New-NetFirewallRule -PolicyStore PersistentStore", "-Enabled False",
                 "if (-not (Test-RulesMatch @(Get-PolicySet 'PersistentStore') $plan $false)) {",
                 "Enable-NetFirewallRule -PolicyStore PersistentStore -Name $created"]
        positions = [staged.find(item) for item in order]
        self.assertNotIn(-1, positions, dict(zip(order, positions)))
        self.assertEqual(positions, sorted(positions))
        left = _block(remove, "        if ($remaining.Count) {", "        }")
        self.assertIn("$exitCode = 2", left)
        self.assertIn("Status         = if ($remaining.Count) { 'removed-other-rules-remain' } else { 'removed' }", remove)

    def test_status_and_preview_exit_codes(self):
        ks = _main_body(_read_script("Manage-WindowsKillSwitch.ps1"))
        lan = _main_body(_read_script("Manage-WindowsLanDnsGuard.ps1"))
        for label, body, mismatch in (("kill switch", ks, "if ($status.ConfigurationMatched -eq $false) { exit 2 }"),
                                      ("LAN DNS Guard", lan, "if ($matched -eq $false) { exit 2 }")):
            with self.subTest(script=label):
                status = _block(body, "if ($Action -eq 'Status') {", "}")
                preview = _block(body, "if ($Action -eq 'Preview') {", "}")
                self.assertEqual(status.rstrip().splitlines()[-2:], ["    " + mismatch, "    exit 0"])
                # exit, not return: "& .\script.ps1 ...; $LASTEXITCODE" shows the code only after exit.
                self.assertEqual(preview.rstrip().splitlines()[-1], "    exit 0")
                self.assertIsNone(re.search(r"^\s*return\b", body, re.M), "top-level return leaves $LASTEXITCODE unset")

    def test_dhcp_message_offers_a_way_out_that_works_with_all_physical_adapters(self):
        message = _function_source(_read_script("Manage-WindowsKillSwitch.ps1"), "Format-DhcpProblem")
        # With -IncludeAllPhysicalAdapters the adapter was not named, so "leave it out of
        # -InterfaceAlias" is not something the user can do.
        self.assertNotIn("leave it out of -InterfaceAlias", message)
        self.assertIn("select the adapters with -InterfaceAlias without it (instead of -IncludeAllPhysicalAdapters)", message)
        doc = (SCRIPTS / "WINDOWS-KILL-SWITCH.md").read_text(encoding="utf-8")
        self.assertIn("或者改用 `-InterfaceAlias` 不选它", doc)

    def test_proxy_state_probe_uses_the_narrowed_family(self):
        text = _read_script("Test-ProxyState.ps1")
        body = _main_body(text)
        self.assertIn("$probeFamily = [string]$familyDecision.Effective", body)
        calls = re.findall(r"Invoke-HTTPSProbe\b[^\n]*", body)
        self.assertEqual(calls, ["Invoke-HTTPSProbe -Url $target.Url -Family $probeFamily"])
        probe = _function_source(text, "Invoke-HTTPSProbe")
        self.assertIn("'ipv4' { '--ipv4 ' }", probe)
        self.assertIn("'ipv6' { '--ipv6 ' }", probe)
        self.assertIn("$familyOption + '-- \"' + $Url.AbsoluteUri + '\"'", probe)

    def test_proxy_state_never_counts_a_named_physical_adapter_as_a_tunnel(self):
        text = _read_script("Test-ProxyState.ps1")
        select = _function_source(text, "Select-NamedTunnelAdapter")
        # The physical check comes before the Up check, and only the last branch adds tunnels.
        physical = select.find("} elseif (@($found | Where-Object { $_.HardwareInterface -eq $true }).Count) {\n            $physical += $item")
        up = select.find("Where-Object { [string]$_.Status -eq 'Up' }).Count -eq 0")
        self.assertGreater(physical, 0)
        self.assertGreater(up, physical)
        self.assertEqual(select.count("$tunnel +="), 1)
        self.assertGreater(select.find("$tunnel +="), up)
        body = _main_body(text)
        self.assertIn("$namedSelection = Select-NamedTunnelAdapter -Adapter $adapterList -Name $TunnelInterfaceAlias", body)
        self.assertIn("$tunnelAdapters = @($namedSelection.Tunnel)", body)
        preflight = _block(body, "        if ($preflightStage) {", "        } else {")
        self.assertIn("            if ($namedProblem -and -not $AllowDirectWithoutTun) {\n                throw", preflight)
        self.assertIn("$tunnelFamilies = @(Get-TunnelRouteFamily -TunnelAdapter $tunnelAdapters)", body)

    def test_proxy_state_fake_ip_ranges_are_the_kits(self):
        import ipaddress
        import refresh_allowlists
        text = _read_script("Test-ProxyState.ps1")
        self.assertEqual([str(n) for n in refresh_allowlists.FAKE_NETWORKS], ["198.18.0.0/15", "fc00::/18"])
        fake = _function_source(text, "Test-FakeIpAddress")
        self.assertIn("return ($b[0] -eq 198 -and ($b[1] -band 0xFE) -eq 18)", fake)
        self.assertIn("return ($b[0] -eq 0xFC -and $b[1] -eq 0 -and ($b[2] -band 0xC0) -eq 0)", fake)
        # The byte tests above, done the same way in Python, agree with the networks.
        for sample in FAKE_IP_SAMPLES:
            try:
                ip = ipaddress.ip_address(sample)
            except ValueError:
                continue
            b = ip.packed
            by_bytes = (b[0] == 198 and (b[1] & 0xFE) == 18) if ip.version == 4 else (
                b[0] == 0xFC and b[1] == 0 and (b[2] & 0xC0) == 0)
            self.assertEqual(by_bytes, any(ip in n for n in refresh_allowlists.FAKE_NETWORKS), sample)
        body = _main_body(text)
        self.assertIn("$fakeIpOnly = $Stage -in @('tun-down', 'client-down') -and $dnsState.FakeIpOnly", body)
        self.assertIn("$verdict = if ($fakeIpOnly) { 'inconclusive' } else { 'observed' }", body)

    def test_proxy_inventory_keeps_only_whole_client_folder_names(self):
        text = _read_script("Inspect-WindowsProxy.ps1")
        pattern = _ps_single_quoted(text, "clientFolderPattern")
        protect = _function_source(text, "Protect-LocalPath")
        self.assertIn("if ($clientNames.ContainsKey($parent) -or $parent -match $clientFolderPattern) {", protect)
        self.assertIn('return "$label\\...\\$($parts[-1])"', protect)
        self.assertNotIn("installedNamePattern", protect)
        for name in ("v2rayN", "V2RAYN", "Clash Verge", "Clash Verge Rev", "v2rayN 7.2.1", "Tailscale", "FlClash v0.8"):
            self.assertTrue(_client_folder_match(pattern, name), name)
        for name in ("v2rayN 张三公司专用", "Clash Verge 李四", "Tailscale 王五的电脑", "v2rayN-windows-64",
                     "v2rayN 7 张三", "张三 v2rayN", "v2rayN\u00a07.2", "v2rayN_backup"):
            self.assertFalse(_client_folder_match(pattern, name), name)

    def test_firewall_inventory_classifies_by_rule_group(self):
        text = _read_script("Inspect-WindowsFirewall.ps1")
        classify = _function_source(text, "Test-MicrosoftRuleGroup")
        patterns = [_ps_single_quoted(classify, name) for name in ("resourcePattern", "packagePattern", "groupNamePattern")]
        self.assertEqual(classify.rstrip("}\n ").splitlines()[-1].strip(),
                         "($Group -match $resourcePattern) -or ($Group -match $packagePattern) -or ($Group -match $groupNamePattern)")
        for group, expected in RULE_GROUP_CASES:
            with self.subTest(group=group):
                self.assertEqual(any(re.search(p, group) for p in patterns), expected)
        loop = _main_body(text)
        self.assertEqual(loop.count("Test-MicrosoftRuleGroup ([string]$rule.Group)"), 1)
        self.assertEqual(loop.count("$allowBreakdown.BuiltInOrMicrosoft += 1"), 1)
        self.assertNotIn("$nameText -match '(?i)(?:Microsoft", loop)


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

    def test_remove_completes_when_log_writes_and_flushes_fail(self):
        for script in MANAGEMENT_SCRIPTS:
            with self.subTest(script=script):
                command = """
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Action = 'Remove'
$Group = 'CPPEK-test-' + [Guid]::NewGuid().ToString('N')
$KnownNames = @('owned')
$logPath = 'simulated.jsonl'
$logWriter = [pscustomobject]@{}
$logWriter | Add-Member ScriptMethod WriteLine { throw 'simulated write failure' }
$logWriter | Add-Member ScriptMethod Dispose { throw 'simulated flush failure' }
function Remove-OwnedRules { param($Names) $Names }
function Get-GuardStatus { @{ PersistentRules = @(); ActiveRules = @(); ForeignOrUnexpectedRules = @() } }
function Get-PolicySet {}
"""
                source = _read_script(script)
                functions = re.findall(r"^function ([\w-]+GuardLog|Write-StderrWarning) \{", source, re.M)
                command += "\n".join(_function_source(source, name) for name in functions) + "\n"
                command += f"$source = Get-Content -Raw -LiteralPath '{script}'\n"
                command += ". ([scriptblock]::Create($source.Substring($source.IndexOf('$mutex = $null'))))\n"
                result = self.run_powershell(command)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["Status"], "removed")
                self.assertEqual(report.get("RemovedNames", report.get("RemovedRules")), ["owned"])
                self.assertIsNone(report["LogPath"])
                self.assertIn("simulated write failure", result.stderr)
                self.assertIn("simulated flush failure", result.stderr)

    def test_install_stops_when_required_log_cannot_be_written(self):
        for script in MANAGEMENT_SCRIPTS:
            with self.subTest(script=script):
                command = _extract_function_command(script, "Write-GuardLog") + """
$ErrorActionPreference = 'Stop'
$Action = 'Install'
$logPath = 'simulated.jsonl'
$logWriter = [pscustomobject]@{}
$logWriter | Add-Member ScriptMethod WriteLine { throw 'simulated write failure' }
Write-GuardLog 'started' @{}
"""
                result = self.run_powershell(command)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("simulated write failure", result.stderr)

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

    def test_proxy_state_named_tunnel_adapters_exclude_physical_ones(self):
        cases = [{"Names": names} for names, _ in NAMED_TUNNEL_CASES]
        command = (
            UTF8_OUTPUT
            + _extract_function_command("Test-ProxyState.ps1", "Select-NamedTunnelAdapter")
            + _extract_function_command("Test-ProxyState.ps1", "Format-NamedTunnelProblem")
            + "$adapters = ConvertFrom-Json '" + json.dumps(TUNNEL_ADAPTERS, ensure_ascii=True) + "'\n"
            + "$cases = ConvertFrom-Json '" + json.dumps(cases, ensure_ascii=True) + "'\n"
            + """$out = @(foreach ($case in $cases) {
    $selection = Select-NamedTunnelAdapter -Adapter @($adapters) -Name ([string[]]@($case.Names))
    [pscustomobject]@{
        Tunnel = @($selection.Tunnel | ForEach-Object { [int]$_.ifIndex })
        Missing = @($selection.Missing); NotUp = @($selection.NotUp); Physical = @($selection.Physical)
        Message = [string](Format-NamedTunnelProblem $selection)
        PhysicalOnly = [string](Format-NamedTunnelProblem $selection -PhysicalOnly)
    }
})
ConvertTo-Json -InputObject $out -Depth 4 -Compress
"""
        )
        result = self.run_powershell(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        for (names, expected), item in zip(NAMED_TUNNEL_CASES, json.loads(result.stdout)):
            with self.subTest(names=names):
                got = tuple(_as_list(item[key]) for key in ("Tunnel", "Missing", "NotUp", "Physical"))
                self.assertEqual(got, expected)
                tunnels, missing, not_up, physical = expected
                if physical:
                    self.assertIn("physical adapter", item["Message"])
                    self.assertIn("physical adapter", item["PhysicalOnly"])
                for name in missing + not_up:
                    self.assertIn(f"'{name}'", item["Message"])
                    self.assertNotIn(f"'{name}'", item["PhysicalOnly"])
                if not (missing or not_up or physical):
                    self.assertEqual(item["Message"], "")

    def test_proxy_state_fake_ip_cache_makes_no_connection_inconclusive(self):
        import ipaddress
        import refresh_allowlists
        command = (
            UTF8_OUTPUT
            + _extract_function_command("Test-ProxyState.ps1", "Test-FakeIpAddress")
            + _extract_function_command("Test-ProxyState.ps1", "Test-FakeIpOnlyCache")
            + "$samples = ConvertFrom-Json '" + json.dumps(FAKE_IP_SAMPLES) + "'\n"
            + "$caches = ConvertFrom-Json '" + json.dumps([{"Entries": e} for e, _ in FAKE_IP_CACHE_CASES]) + "'\n"
            + """$out = [pscustomobject]@{
    Addresses = @(foreach ($sample in $samples) { [bool](Test-FakeIpAddress ([string]$sample)) })
    Caches = @(foreach ($cache in $caches) { [bool](Test-FakeIpOnlyCache -Entry @($cache.Entries)) })
}
ConvertTo-Json -InputObject $out -Compress
"""
        )
        result = self.run_powershell(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        got = json.loads(result.stdout)

        def expected_fake(sample):
            try:
                ip = ipaddress.ip_address(sample)
            except ValueError:
                return False
            return any(ip in network for network in refresh_allowlists.FAKE_NETWORKS)

        self.assertEqual(_as_list(got["Addresses"]), [expected_fake(s) for s in FAKE_IP_SAMPLES])
        self.assertEqual(_as_list(got["Caches"]), [expected for _, expected in FAKE_IP_CACHE_CASES])

    def test_firewall_rule_group_classification(self):
        groups = [group for group, _ in RULE_GROUP_CASES]
        command = (
            UTF8_OUTPUT
            + _extract_function_command("Inspect-WindowsFirewall.ps1", "Test-MicrosoftRuleGroup")
            + "$groups = ConvertFrom-Json '" + json.dumps(groups).replace("'", "''") + "'\n"
            + "ConvertTo-Json -InputObject @(foreach ($g in $groups) { [bool](Test-MicrosoftRuleGroup ([string]$g)) }) -Compress\n"
        )
        result = self.run_powershell(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(_as_list(json.loads(result.stdout)), [expected for _, expected in RULE_GROUP_CASES])

    def test_proxy_inventory_path_masking(self):
        text = _read_script("Inspect-WindowsProxy.ps1")
        client_names = dict(re.findall(r"^    '([^']+)'\s+= '([^']+)'$", text, re.M))
        self.assertIn("v2rayn", client_names)
        command = (
            UTF8_OUTPUT
            + _extract_function_command("Inspect-WindowsProxy.ps1", "Protect-LocalPath")
            + "$clientFolderPattern = '" + _ps_single_quoted(text, "clientFolderPattern").replace("'", "''") + "'\n"
            + "$clientNames = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)\n"
            + "foreach ($p in (ConvertFrom-Json '" + json.dumps(client_names, ensure_ascii=True) + "').PSObject.Properties) { $clientNames[$p.Name] = $p.Value }\n"
            + "$pathsToMask = [ordered]@{}\n"
            + "$folders = ConvertFrom-Json '" + json.dumps([{"Path": a, "Label": b} for a, b in PROFILE_FOLDERS], ensure_ascii=True) + "'\n"
            + "foreach ($p in $folders) { $pathsToMask[[string]$p.Path] = [string]$p.Label }\n"
            + "$paths = ConvertFrom-Json '" + json.dumps([path for path, _ in MASK_CASES], ensure_ascii=True) + "'\n"
            + "ConvertTo-Json -InputObject @(foreach ($path in $paths) { [string](Protect-LocalPath ([string]$path)) }) -Compress\n"
        )
        result = self.run_powershell(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(_as_list(json.loads(result.stdout)), [expected for _, expected in MASK_CASES])

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
