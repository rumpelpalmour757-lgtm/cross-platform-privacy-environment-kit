#Requires -Version 5.1
<#
.SYNOPSIS
Manage a persistent, outbound Windows Firewall guard for explicit physical uplinks.
.DESCRIPTION
Preview generates a rule plan natively in PowerShell without invoking external interpreters
or writing settings. Install and Remove require an elevated, local Windows console and write a
private, redacted installation log. Install refuses to run from a directory that unprivileged
shared groups can change, or from a volume without NTFS/ReFS permissions; Remove only warns
about the location (and runs without a log if none can be written), so that it can always take
the rules away again. Status observes managed policy. Only separate fault probes and filter
events can establish that a tested connection was blocked.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Preview', 'Install', 'Status', 'Remove')]
    [string]$Action,

    [string[]]$InterfaceAlias,
    [switch]$IncludeAllPhysicalAdapters,
    [switch]$AllowUncoveredPhysicalAdapters,
    [string]$UpstreamAddress,
    [int]$UpstreamPort,
    [ValidateSet('TCP', 'UDP')]
    [string]$UpstreamProtocol = 'TCP',
    [string[]]$DhcpServer,
    [string]$LogDirectory = $env:LOCALAPPDATA
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Group = 'CPPEK-KillSwitch-v1'
$Owner = 'Cross-platform privacy environment kit: managed uplink guard v1'
$NonTcpUdpProtocols = @(
    [pscustomobject]@{ Suffix = 'ExceptionProtoICMPv4'; Protocol = 'ICMPv4' }
    [pscustomobject]@{ Suffix = 'ExceptionProtoIGMP'; Protocol = '2' }
    [pscustomobject]@{ Suffix = 'ExceptionProtoIPv4Encap'; Protocol = '4' }
    [pscustomobject]@{ Suffix = 'ExceptionProtoIPv6Encap'; Protocol = '41' }
    [pscustomobject]@{ Suffix = 'ExceptionProtoGRE'; Protocol = '47' }
    [pscustomobject]@{ Suffix = 'ExceptionProtoESP'; Protocol = '50' }
    [pscustomobject]@{ Suffix = 'ExceptionProtoAH'; Protocol = '51' }
    [pscustomobject]@{ Suffix = 'ExceptionProtoSCTP'; Protocol = '132' }
)
$KnownNames = @(
    'IPv4OtherAddresses', 'IPv6', 'UpstreamOtherTransport', 'UpstreamOtherPorts',
    'ExceptionProtoICMPv4', 'ExceptionProtoIGMP', 'ExceptionProtoIPv4Encap', 'ExceptionProtoIPv6Encap',
    'ExceptionProtoGRE', 'ExceptionProtoESP', 'ExceptionProtoAH', 'ExceptionProtoSCTP',
    'DhcpTcp', 'DhcpOtherRemotePorts', 'DhcpOtherLocalPorts'
) | ForEach-Object { "$Group-$_" }

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this script in Windows PowerShell 5.1 or newer on the target computer.'
}
try {
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
} catch {
    # Output may not be attached to a console.
}

function Write-StderrWarning {
    # Warnings go to stderr, so that the JSON on stdout stays parseable.
    param([string]$Message)
    [Console]::Error.WriteLine("WARNING: $Message")
}

function ConvertTo-IPv4UInt32 {
    param([string]$Value)
    $ip = $null
    if (
        [string]::IsNullOrWhiteSpace($Value) -or
        $Value -notmatch '\A\d{1,3}(?:\.\d{1,3}){3}\z' -or
        -not [Net.IPAddress]::TryParse($Value, [ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $ip.ToString() -cne $Value
    ) {
        throw 'Use a literal IPv4 address.'
    }
    $bytes = $ip.GetAddressBytes()
    ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]
}

function ConvertFrom-IPv4UInt32 {
    param([uint32]$Value)
    $b0 = ($Value -shr 24) -band 0xFF
    $b1 = ($Value -shr 16) -band 0xFF
    $b2 = ($Value -shr 8) -band 0xFF
    $b3 = $Value -band 0xFF
    "$b0.$b1.$b2.$b3"
}

function Test-PrivateIPv4UInt32 {
    param([uint32]$Value)
    # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    (($Value -band 0xFF000000L) -eq 0x0A000000L) -or
    (($Value -band 0xFFF00000L) -eq 0xAC100000L) -or
    (($Value -band 0xFFFF0000L) -eq 0xC0A80000L)
}

function Test-AllowedUpstreamIPv4UInt32 {
    param([uint32]$Value)
    if (Test-PrivateIPv4UInt32 $Value) { return $true }
    # Reject unspecified, CGNAT, loopback, link-local, IETF protocol, TEST-NETs, benchmark, multicast, reserved/broadcast.
    if (
        (($Value -band 0xFF000000L) -eq 0x00000000L) -or # 0.0.0.0/8
        (($Value -band 0xFFC00000L) -eq 0x64400000L) -or # 100.64.0.0/10
        (($Value -band 0xFF000000L) -eq 0x7F000000L) -or # 127.0.0.0/8
        (($Value -band 0xFFFF0000L) -eq 0xA9FE0000L) -or # 169.254.0.0/16
        (($Value -band 0xFFFFFF00L) -eq 0xC0000000L) -or # 192.0.0.0/24
        (($Value -band 0xFFFFFF00L) -eq 0xC0000200L) -or # 192.0.2.0/24
        (($Value -band 0xFFFE0000L) -eq 0xC6120000L) -or # 198.18.0.0/15
        (($Value -band 0xFFFFFF00L) -eq 0xC6336400L) -or # 198.51.100.0/24
        (($Value -band 0xFFFFFF00L) -eq 0xCB007100L) -or # 203.0.113.0/24
        (($Value -band 0xF0000000L) -eq 0xE0000000L) -or # 224.0.0.0/4 multicast
        (($Value -band 0xF0000000L) -eq 0xF0000000L)     # 240.0.0.0/4 reserved & 255.255.255.255
    ) {
        return $false
    }
    $true
}

function Get-ComplementRanges {
    param([int64]$Start, [int64]$End, [int64[]]$Exclusions, [switch]$AsIPv4)
    $result = New-Object 'System.Collections.Generic.List[string]'
    $lower = $Start
    foreach ($value in ($Exclusions | Sort-Object -Unique)) {
        if ($lower -lt $value) {
            $hi = $value - 1
            if ($AsIPv4) {
                $loStr = ConvertFrom-IPv4UInt32 ([uint32]$lower)
                $hiStr = ConvertFrom-IPv4UInt32 ([uint32]$hi)
                $result.Add($(if ($lower -eq $hi) { $loStr } else { "$loStr-$hiStr" }))
            } else {
                $result.Add($(if ($lower -eq $hi) { "$lower" } else { "$lower-$hi" }))
            }
        }
        $lower = $value + 1
    }
    if ($lower -le $End) {
        if ($AsIPv4) {
            $loStr = ConvertFrom-IPv4UInt32 ([uint32]$lower)
            $hiStr = ConvertFrom-IPv4UInt32 ([uint32]$End)
            $result.Add($(if ($lower -eq $End) { $loStr } else { "$loStr-$hiStr" }))
        } else {
            $result.Add($(if ($lower -eq $End) { "$lower" } else { "$lower-$End" }))
        }
    }
    @($result.ToArray())
}

function New-PlanRule {
    param(
        [string]$Suffix,
        [string[]]$Addresses,
        [string]$Protocol = 'Any',
        [string[]]$RemotePorts = @(),
        [string[]]$LocalPorts = @()
    )
    [pscustomobject][ordered]@{
        Name            = "$Group-$Suffix"
        RemoteAddresses = @($Addresses)
        Protocol        = $Protocol
        RemotePorts     = @($RemotePorts)
        LocalPorts      = @($LocalPorts)
    }
}

function Test-LiteralInterfaceAlias {
    # The same rules as build_kill_switch.py and build_lan_dns_guard.py: 1-128 characters, no
    # surrounding white space, no leading '-', not "Any", none of * ? [ ] ` " \, and only
    # characters Python's str.isprintable() accepts (no control, format, private-use, unassigned
    # or unpaired surrogate code points, and no separator other than the ASCII space).
    param([string]$Alias)
    if ($null -eq $Alias -or $Alias.Length -lt 1 -or $Alias.Length -gt 128 -or
        $Alias -cne $Alias.Trim() -or $Alias.StartsWith('-') -or
        $Alias.Equals('any', [StringComparison]::OrdinalIgnoreCase) -or
        $Alias.IndexOfAny([char[]]'*?[]`"\') -ge 0) {
        return $false
    }
    for ($i = 0; $i -lt $Alias.Length; $i++) {
        $category = [string][Globalization.CharUnicodeInfo]::GetUnicodeCategory($Alias, $i)
        if ($category -in @('Control', 'Format', 'Surrogate', 'PrivateUse', 'OtherNotAssigned', 'LineSeparator', 'ParagraphSeparator')) {
            return $false
        }
        if ($category -eq 'SpaceSeparator' -and $Alias[$i] -ne [char]' ') { return $false }
        if ([char]::IsHighSurrogate($Alias[$i])) { $i++ }
    }
    $true
}

function Format-AliasForMessage {
    # Quote an adapter name for an error message, with invisible characters written as \uXXXX.
    param([string]$Alias)
    if ($null -eq $Alias) { return '<none>' }
    $text = -join @(foreach ($ch in $Alias.ToCharArray()) {
        $category = [string][Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch)
        if ($ch -ne [char]' ' -and $category -in @('Control', 'Format', 'Surrogate', 'PrivateUse', 'OtherNotAssigned', 'LineSeparator', 'ParagraphSeparator', 'SpaceSeparator')) {
            '\u{0:X4}' -f [int]$ch
        } else {
            [string]$ch
        }
    })
    "'$text'"
}

function Get-KitPhysicalAdapter {
    # One meaning of "physical adapter" for -IncludeAllPhysicalAdapters, for checking the selected
    # names and for the coverage check: the adapters whose HardwareInterface property is true.
    @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.HardwareInterface -eq $true })
}

function New-RulePlan {
    $candidateAliases = @()
    if ($InterfaceAlias) {
        $explicitSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($item in $InterfaceAlias) {
            if (-not (Test-LiteralInterfaceAlias $item)) {
                throw "Use literal interface aliases without wildcards or control characters: $(Format-AliasForMessage $item)."
            }
            if (-not $explicitSeen.Add($item)) {
                throw "Interface aliases must be unique: $(Format-AliasForMessage $item) is given twice."
            }
        }
    }
    if ($IncludeAllPhysicalAdapters) {
        $detected = @(Get-KitPhysicalAdapter | ForEach-Object { [string]$_.Name })
        $candidateAliases += $detected
    }
    if ($InterfaceAlias) {
        # -InterfaceAlias and -IncludeAllPhysicalAdapters together are merged.
        foreach ($item in $InterfaceAlias) {
            if ($candidateAliases -notcontains $item) { $candidateAliases += $item }
        }
    }
    if (-not $candidateAliases -or -not $UpstreamAddress -or $UpstreamPort -lt 1 -or $UpstreamPort -gt 65535) {
        throw 'Supply InterfaceAlias (or -IncludeAllPhysicalAdapters), a literal UpstreamAddress and UpstreamPort (1-65535).'
    }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($alias in $candidateAliases) {
        if (-not (Test-LiteralInterfaceAlias $alias)) {
            throw "Use literal interface aliases without wildcards or control characters: $(Format-AliasForMessage $alias)."
        }
        if (-not $seen.Add($alias)) {
            throw "Interface aliases must be unique: $(Format-AliasForMessage $alias)."
        }
    }
    # Ordinal order of the lower-cased names, like sorted(key=str.casefold) in build_kill_switch.py.
    # Sort-Object would follow the current culture (for example pinyin order on Chinese Windows).
    $sortedAliases = [string[]]@($candidateAliases)
    $sortKeys = [string[]]@($sortedAliases | ForEach-Object { $_.ToLowerInvariant() })
    [Array]::Sort($sortKeys, $sortedAliases, [StringComparer]::Ordinal)

    $upstreamInt = ConvertTo-IPv4UInt32 $UpstreamAddress
    if (-not (Test-AllowedUpstreamIPv4UInt32 $upstreamInt)) {
        throw 'Use a public or RFC 1918 unicast IPv4 address for the upstream.'
    }
    $upstreamProto = $UpstreamProtocol.ToUpperInvariant()
    if ($upstreamProto -cnotin @('TCP', 'UDP')) {
        throw 'Use TCP or UDP for the upstream protocol.'
    }

    $dhcpInts = @()
    if ($DhcpServer) {
        foreach ($server in $DhcpServer) {
            $srvInt = ConvertTo-IPv4UInt32 $server
            if (-not (Test-PrivateIPv4UInt32 $srvInt)) {
                throw 'DHCP servers must be literal RFC 1918 IPv4 addresses.'
            }
            if ($srvInt -eq $upstreamInt) {
                throw 'The upstream and a DHCP server cannot share an address. This layout is not supported: give the adapter a static IP address and install without -DhcpServer.'
            }
            $dhcpInts += [int64]$srvInt
        }
        $dhcpInts = @($dhcpInts | Sort-Object -Unique)
    }

    $dhcpAddressInts = @(if ($dhcpInts.Count) { $dhcpInts + [int64]0xFFFFFFFFL })
    $exceptionInts = @((@([int64]$upstreamInt) + $dhcpAddressInts) | Sort-Object -Unique)
    $ipv4Other = Get-ComplementRanges -Start 0 -End 4294967295L -Exclusions $exceptionInts -AsIPv4
    $upstreamStr = ConvertFrom-IPv4UInt32 $upstreamInt
    $exceptionAddressStrings = @($exceptionInts | ForEach-Object { ConvertFrom-IPv4UInt32 ([uint32]$_) })
    $otherTransport = if ($upstreamProto -ceq 'TCP') { 'UDP' } else { 'TCP' }
    $otherPorts = Get-ComplementRanges -Start 0 -End 65535 -Exclusions @([int64]$UpstreamPort)

    $rules = New-Object 'System.Collections.Generic.List[object]'
    $rules.Add((New-PlanRule -Suffix 'IPv4OtherAddresses' -Addresses $ipv4Other))
    $rules.Add((New-PlanRule -Suffix 'IPv6' -Addresses @('::/0')))
    $rules.Add((New-PlanRule -Suffix 'UpstreamOtherTransport' -Addresses @($upstreamStr) -Protocol $otherTransport))
    $rules.Add((New-PlanRule -Suffix 'UpstreamOtherPorts' -Addresses @($upstreamStr) -Protocol $upstreamProto -RemotePorts $otherPorts))
    foreach ($protoEntry in $NonTcpUdpProtocols) {
        $rules.Add((New-PlanRule -Suffix $protoEntry.Suffix -Addresses $exceptionAddressStrings -Protocol $protoEntry.Protocol))
    }
    if ($dhcpAddressInts.Count) {
        $dhcpStrings = @($dhcpAddressInts | ForEach-Object { ConvertFrom-IPv4UInt32 ([uint32]$_) })
        $rules.Add((New-PlanRule -Suffix 'DhcpTcp' -Addresses $dhcpStrings -Protocol 'TCP'))
        $rules.Add((New-PlanRule -Suffix 'DhcpOtherRemotePorts' -Addresses $dhcpStrings -Protocol 'UDP' -RemotePorts (Get-ComplementRanges -Start 0 -End 65535 -Exclusions @(67))))
        $rules.Add((New-PlanRule -Suffix 'DhcpOtherLocalPorts' -Addresses $dhcpStrings -Protocol 'UDP' -RemotePorts @('67') -LocalPorts (Get-ComplementRanges -Start 0 -End 65535 -Exclusions @(68))))
    }

    [pscustomobject][ordered]@{
        SchemaVersion    = 2
        InterfaceAliases = $sortedAliases
        UpstreamAddress  = $upstreamStr
        UpstreamPort     = $UpstreamPort
        UpstreamProtocol = $upstreamProto
        DhcpServers      = @($dhcpInts | ForEach-Object { ConvertFrom-IPv4UInt32 ([uint32]$_) })
        Rules            = @($rules.ToArray())
    }
}

function Get-DhcpCheck {
    # Adapters with DHCP enabled, and adapters whose IPv4 settings cannot be read (a disabled
    # adapter has none). Either kind needs -DhcpServer: once such an adapter is up with DHCP, its
    # lease requests would be blocked.
    param([string[]]$Aliases)
    $enabled = New-Object 'System.Collections.Generic.List[string]'
    $unknown = New-Object 'System.Collections.Generic.List[string]'
    foreach ($alias in $Aliases) {
        $ipInterface = @(Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        if ($ipInterface.Count -eq 0) {
            $unknown.Add($alias)
        } elseif (@($ipInterface | Where-Object { [string]$_.Dhcp -eq 'Enabled' }).Count) {
            $enabled.Add($alias)
        }
    }
    [pscustomobject]@{ Enabled = @($enabled.ToArray()); Unknown = @($unknown.ToArray()) }
}

$DhcpGuidance = 'Find the DHCP server with: Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object DHCPEnabled | Select-Object Description, DHCPServer (or "ipconfig /all"), then pass it with -DhcpServer.'

function Format-DhcpProblem {
    param($Check)
    $parts = @()
    if (@($Check.Enabled).Count) {
        $parts += "DHCP is enabled on $((@($Check.Enabled) | ForEach-Object { Format-AliasForMessage $_ }) -join ', ') but no -DhcpServer was given; lease renewal would be blocked and the network could drop."
    }
    if (@($Check.Unknown).Count) {
        $parts += "The DHCP setting of $((@($Check.Unknown) | ForEach-Object { Format-AliasForMessage $_ }) -join ', ') could not be read (the adapter is disabled, or IPv4 is not bound to it); if it is later enabled with DHCP, its lease requests would be blocked. Enable it and run Preview again, select the adapters with -InterfaceAlias without it (instead of -IncludeAllPhysicalAdapters), or pass -DhcpServer."
    }
    "$($parts -join ' ') $DhcpGuidance"
}

function Assert-UnlinkedLocalDirectory {
    param([string]$Path, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]') {
        throw "$Label must be an existing, absolute local Windows directory."
    }
    $full = [IO.Path]::GetFullPath($Path)
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ([string]$drive.DriveType -notin @('Fixed', 'Removable', 'Ram')) {
        throw "$Label must be on a local drive."
    }
    if (-not [IO.Directory]::Exists($full)) {
        throw "$Label does not exist: $full"
    }
    $ancestors = @()
    for ($dir = [IO.DirectoryInfo]::new($full); $null -ne $dir; $dir = $dir.Parent) {
        $ancestors = @($dir) + $ancestors
    }
    foreach ($dir in $ancestors) {
        $attr = [IO.File]::GetAttributes($dir.FullName)
        if (($attr -band [IO.FileAttributes]::ReparsePoint) -or -not ($attr -band [IO.FileAttributes]::Directory)) {
            throw "$Label must be a real directory without redirected parents: '$($dir.FullName)' has the reparse-point attribute (a symbolic link, a junction, or a cloud-synced folder such as OneDrive). Use a local folder that is neither linked nor synced."
        }
    }
    $full
}

function Get-SharedWriteGrant {
    # Which allow entries let a shared, unprivileged group change a file, or add, rename or delete
    # files in a directory? Read and execute rights pass (for example the Users entry on
    # C:\Program Files). Kept free of outside state: test_kill_switch_powershell.py runs it with
    # synthetic entries and checks that both management scripts carry the same text.
    param([object[]]$Rule)
    $groupNames = @{
        'S-1-1-0'      = 'Everyone'
        'S-1-5-4'      = 'INTERACTIVE'
        'S-1-5-11'     = 'Authenticated Users'
        'S-1-5-32-545' = 'Users'
        'S-1-5-32-546' = 'Guests'
    }
    # WriteData, AppendData, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles, WriteAttributes,
    # Delete, ChangePermissions and TakeOwnership (0x000D0156 = 852310), plus GENERIC_ALL and
    # GENERIC_WRITE. Write, Modify and FullControl all contain one of these bits.
    $changeRights = [long]0x000D0156 -bor [long]0x10000000 -bor [long]0x40000000
    @(foreach ($entry in @($Rule)) {
        if ($null -eq $entry) { continue }
        if ([string]$entry.AccessControlType -ne 'Allow') { continue }
        # Inherit-only entries apply to items created later inside a directory, not to the item itself.
        if (([int]$entry.PropagationFlags -band 2) -ne 0) { continue }
        $sid = [string]$entry.IdentityReference
        if (-not $groupNames.ContainsKey($sid)) { continue }
        $rights = ([long]$entry.FileSystemRights) -band 0xFFFFFFFFL
        if (($rights -band $changeRights) -ne 0) {
            [pscustomobject]@{ Group = $groupNames[$sid]; Sid = $sid; Rights = [string]$entry.FileSystemRights }
        }
    })
}

function Assert-SafeElevatedScriptPath {
    # Install refuses to run elevated from a location that other local users could change. Remove
    # only warns: if the script had been altered, this check would be gone too, so stopping Remove
    # here protects nothing and only keeps the network blocked.
    param([switch]$WarnOnly)
    if (-not $PSCommandPath) { return }
    $problems = New-Object 'System.Collections.Generic.List[string]'
    try {
        $scriptDir = Assert-UnlinkedLocalDirectory -Path (Split-Path -Parent $PSCommandPath) -Label 'Script directory'
        $attr = [IO.File]::GetAttributes($PSCommandPath)
        if (($attr -band [IO.FileAttributes]::ReparsePoint) -or ($attr -band [IO.FileAttributes]::Directory)) {
            $problems.Add('Manage-WindowsKillSwitch.ps1 must be a regular local file without links.')
        }
        $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($scriptDir))
        if ($drive.DriveFormat -notin @('NTFS', 'ReFS')) {
            $problems.Add("The script directory is on a $($drive.DriveFormat) volume, which has no file permissions, so any local user could change these scripts. Copy the kit to a private folder on an NTFS drive, for example under your user profile.")
        } else {
            foreach ($itemPath in @($scriptDir, $PSCommandPath)) {
                $acl = Get-Acl -LiteralPath $itemPath -ErrorAction Stop
                $entries = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
                foreach ($grant in @(Get-SharedWriteGrant -Rule $entries)) {
                    $problems.Add("$($grant.Group) ($($grant.Sid)) may change '$itemPath' (rights: $($grant.Rights)). Move this kit into a folder that only administrators and your own account can change, for example a subfolder of your user profile or of C:\Program Files.")
                }
            }
        }
    } catch {
        $problems.Add($_.Exception.Message)
    }
    if ($problems.Count -eq 0) { return }
    if ($WarnOnly) {
        foreach ($problem in $problems) { Write-StderrWarning $problem }
        Write-StderrWarning 'Continuing, because Remove only deletes rules that this kit created. Move the kit before the next Install.'
        return
    }
    throw ($problems -join ' ')
}

function Set-PrivateFileAcl {
    param([string]$FilePath, [Security.Principal.SecurityIdentifier]$OperatorSid)
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($FilePath))
    if ($drive.DriveFormat -notin @('NTFS', 'ReFS')) { return }
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544', $OperatorSid.Value)) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $FilePath -AclObject $acl -ErrorAction Stop
}

function Get-RedactedPlanSummary {
    param($Plan)
    if ($null -eq $Plan) { return $null }
    [pscustomobject][ordered]@{
        SchemaVersion    = $Plan.SchemaVersion
        InterfaceCount   = @($Plan.InterfaceAliases).Count
        UpstreamAddress  = '[redacted]'
        UpstreamPort     = $Plan.UpstreamPort
        UpstreamProtocol = $Plan.UpstreamProtocol
        DhcpServerCount  = @($Plan.DhcpServers).Count
        RuleCount        = @($Plan.Rules).Count
        RuleNames        = @($Plan.Rules | ForEach-Object { $_.Name })
    }
}

function Get-PolicySet {
    param([string]$Store)
    @(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop | Where-Object {
        $_.Name -in $KnownNames -or $_.Group -eq $Group
    })
}

function Test-OwnedRule {
    param($Rule)
    $Rule.Name -cin $KnownNames -and $Rule.Group -ceq $Group -and $Rule.Description -ceq $Owner
}

function Test-SameSet {
    param($Left, $Right)
    $l = @($Left | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    $r = @($Right | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    if ($l.Count -ne $r.Count) { return $false }
    for ($i = 0; $i -lt $l.Count; $i++) {
        if ($l[$i] -cne $r[$i]) { return $false }
    }
    $true
}

function Normalize-RemoteAddress {
    param([string]$Value)
    switch -Regex ($Value.Trim().ToLowerInvariant()) {
        '^(.+)/(32|255\.255\.255\.255)$' { return $Matches[1] }
        '^(::|0:0:0:0:0:0:0:0)-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff$' { return '::/0' }
        '^(0:0:0:0:0:0:0:0)/0$' { return '::/0' }
        default { return $Value.Trim().ToLowerInvariant() }
    }
}

function Normalize-Protocol {
    param([string]$Value)
    switch ($Value.Trim().ToUpperInvariant()) {
        '1' { 'ICMPv4' }
        'ICMPV4' { 'ICMPv4' }
        '6' { 'TCP' }
        'TCP' { 'TCP' }
        '17' { 'UDP' }
        'UDP' { 'UDP' }
        '256' { 'Any' }
        'ANY' { 'Any' }
        default { $Value.Trim() }
    }
}

function Test-Any {
    param($Value)
    @($Value | Where-Object { $_ -and [string]$_ -ne 'Any' }).Count -eq 0
}

function Test-RulesMatch {
    param($Actual, $Plan, [bool]$Enabled)
    if (@($Actual).Count -ne @($Plan.Rules).Count) { return $false }
    foreach ($entry in $Plan.Rules) {
        $matched = @($Actual | Where-Object { $_.Name -ceq $entry.Name })
        if ($matched.Count -ne 1) { return $false }
        $rule = $matched[0]
        if (-not (Test-OwnedRule $rule) -or [string]$rule.Direction -ne 'Outbound' -or
            [string]$rule.Action -ne 'Block' -or [string]$rule.Profile -ne 'Any' -or
            (([string]$rule.Enabled -eq 'True') -ne $Enabled)) {
            return $false
        }

        $addresses = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
        $ports = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
        $interfaces = $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
        $types = $rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
        $application = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
        $service = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
        $protocol = Normalize-Protocol ([string]$ports.Protocol)
        $local = if (@($entry.LocalPorts).Count) { $entry.LocalPorts } else { 'Any' }
        $remote = if (@($entry.RemotePorts).Count) { $entry.RemotePorts } else { 'Any' }
        $actualAddresses = @($addresses.RemoteAddress | ForEach-Object { Normalize-RemoteAddress $_ })
        if ($protocol -cne $entry.Protocol -or
            -not (Test-SameSet $ports.LocalPort $local) -or
            -not (Test-SameSet $ports.RemotePort $remote) -or
            -not (Test-SameSet $actualAddresses $entry.RemoteAddresses) -or
            -not (Test-SameSet $interfaces.InterfaceAlias $Plan.InterfaceAliases) -or
            -not (Test-Any $addresses.LocalAddress) -or -not (Test-Any $types.InterfaceType) -or
            -not (Test-Any $application.Program) -or -not (Test-Any $service.Service)) {
            return $false
        }
        $package = $application.PSObject.Properties['Package']
        if ($null -ne $package -and -not (Test-Any $package.Value)) { return $false }
    }
    $true
}

function Get-GuardPrerequisites {
    param($Plan)
    $windowsServices = @(Get-Service -Name BFE, MpsSvc -ErrorAction Stop)
    if ($windowsServices.Count -ne 2 -or @($windowsServices | Where-Object { $_.Status -ne 'Running' }).Count) {
        throw 'The Base Filtering Engine and Windows Firewall services must be running.'
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if (-not (Test-SameSet @($profiles.Name) @('Domain', 'Private', 'Public'))) {
        throw 'Could not verify the three effective firewall profiles.'
    }
    foreach ($firewallProfile in $profiles) {
        if ([string]$firewallProfile.Enabled -ne 'True' -or [string]$firewallProfile.AllowLocalFirewallRules -eq 'False') {
            throw 'All profiles must have Windows Firewall and local rule merging enabled.'
        }
        foreach ($disabled in @($firewallProfile.DisabledInterfaceAliases | Where-Object { $_ -and $_ -ne 'NotConfigured' })) {
            foreach ($alias in $Plan.InterfaceAliases) {
                if ($disabled -eq 'Any' -or $alias -like $disabled) {
                    throw "The $($firewallProfile.Name) profile excludes the selected adapter $(Format-AliasForMessage $alias) from Windows Firewall."
                }
            }
        }
    }
    $allAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $physical = @($allAdapters | Where-Object { $_.HardwareInterface -eq $true })
    foreach ($alias in $Plan.InterfaceAliases) {
        if (@($physical | Where-Object { $_.Name -eq $alias }).Count -ne 1) {
            throw "The selected physical adapter could not be identified: $alias. Only adapters whose HardwareInterface property is True can be protected; check with: Get-NetAdapter -IncludeHidden | Select-Object Name, HardwareInterface, Status"
        }
    }
    $otherActivePhysical = @($physical | Where-Object {
        $_.Status -eq 'Up' -and $_.Name -notin $Plan.InterfaceAliases
    } | ForEach-Object { $_.Name })

    $tunnelRegex = '(?i)(?:^|[\s_.-])(?:u?tun\d*|wintun\d*|wireguard|tailscale|sing[-_]?box|mihomo|clash)(?:$|[\s_.-])'
    $virtualBridges = @($allAdapters | Where-Object {
        $_.HardwareInterface -ne $true -and $_.Status -eq 'Up' -and
        $_.Name -notin $Plan.InterfaceAliases -and
        "$($_.Name) $($_.InterfaceDescription)" -notmatch $tunnelRegex
    } | ForEach-Object { $_.Name })

    [pscustomobject]@{
        Profiles = @($profiles.Name)
        PhysicalAdapters = @($physical | Where-Object { $_.Name -in $Plan.InterfaceAliases } |
            Select-Object Name, InterfaceIndex, Status)
        OtherActivePhysicalAdapters = $otherActivePhysical
        ActiveVirtualNonTunnelAdapters = $virtualBridges
        AllActivePhysicalCovered = ($otherActivePhysical.Count -eq 0)
    }
}

function Write-VirtualAdapterWarning {
    param($Prerequisites)
    if ($null -eq $Prerequisites) { return }
    $names = @($Prerequisites.ActiveVirtualNonTunnelAdapters)
    if ($names.Count) {
        Write-StderrWarning "Connected virtual adapters are outside this guard: $(($names | ForEach-Object { Format-AliasForMessage $_ }) -join ', '). Whether traffic that leaves through them (a Hyper-V external switch, VM NAT, hotspot sharing) is blocked has not been tested; do not treat it as protected."
    }
}

function Write-GuardLog {
    param([string]$Event, $Data)
    if ($null -eq $logWriter -or $null -eq $logPath) { return }
    try {
        $logWriter.WriteLine(([ordered]@{ Utc = [DateTime]::UtcNow.ToString('o'); Event = $Event; Action = $Action; Data = $Data } |
            ConvertTo-Json -Depth 8 -Compress))
    } catch {
        if ($Action -ne 'Remove') { throw }
        $script:logPath = $null
        Write-StderrWarning "Remove continues with an incomplete log: $($_.Exception.Message)"
    }
}

function Close-GuardLog {
    param($Stream)
    if ($null -eq $Stream) { return }
    try {
        $Stream.Dispose()
    } catch {
        if ($Action -ne 'Remove') { throw }
        Write-StderrWarning "Could not close the Remove log: $($_.Exception.Message)"
    }
}

function Remove-OwnedRules {
    param([string[]]$Names)
    $removed = @()
    foreach ($rule in @(Get-PolicySet 'PersistentStore')) {
        if ($rule.Name -cin $Names -and (Test-OwnedRule $rule)) {
            Remove-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -ErrorAction Stop
            $removed += $rule.Name
        }
    }
    $removed
}

function Get-GuardStatus {
    param($Plan)

    $persisted = @(Get-PolicySet 'PersistentStore')
    $active = @(Get-PolicySet 'ActiveStore')
    $bootTime = $null
    try {
        $system = Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime -ErrorAction Stop
        $bootTime = $system.LastBootUpTime.ToUniversalTime().ToString('o')
    } catch {
        # Boot time is supplementary evidence.
    }

    $prerequisites = $null
    $matched = $null
    if ($null -ne $Plan) {
        $prerequisites = Get-GuardPrerequisites $Plan
        $coverageOk = $AllowUncoveredPhysicalAdapters.IsPresent -or $prerequisites.AllActivePhysicalCovered
        $matched = $coverageOk -and (Test-RulesMatch $persisted $Plan $true) -and (Test-RulesMatch $active $Plan $true)
    }
    [pscustomobject]@{
        Status = 'policy-observed'
        ObservedAtUtc = [DateTime]::UtcNow.ToString('o')
        BootTimeUtc = $bootTime
        PersistentRules = @($persisted | Where-Object { Test-OwnedRule $_ } | Select-Object Name, Enabled, Direction, Action)
        ActiveRules = @($active | Where-Object { Test-OwnedRule $_ } | Select-Object Name, Enabled, Direction, Action)
        ForeignOrUnexpectedRules = @($persisted + $active | Where-Object { -not (Test-OwnedRule $_) } |
            ForEach-Object { $_.Name } | Sort-Object -Unique)
        ConfigurationMatched = $matched
        Prerequisites = $prerequisites
        EffectiveBlockVerified = $false
    }
}

if ($Action -eq 'Preview') {
    $plan = New-RulePlan
    if (-not $DhcpServer) {
        $dhcpCheck = Get-DhcpCheck $plan.InterfaceAliases
        if (@($dhcpCheck.Enabled).Count -or @($dhcpCheck.Unknown).Count) {
            Write-StderrWarning "$(Format-DhcpProblem $dhcpCheck) Install will refuse to continue until this is resolved."
        }
    }
    $plan | ConvertTo-Json -Depth 8
    # exit, not return: "& .\Manage-WindowsKillSwitch.ps1 ...; $LASTEXITCODE" then shows 0, as with LAN DNS Guard.
    exit 0
}

Import-Module NetSecurity -ErrorAction Stop
if ($Action -eq 'Status') {
    $plan = $null
    if (
        $PSBoundParameters.ContainsKey('InterfaceAlias') -or $IncludeAllPhysicalAdapters -or
        $PSBoundParameters.ContainsKey('UpstreamAddress') -or $PSBoundParameters.ContainsKey('UpstreamPort') -or
        $PSBoundParameters.ContainsKey('UpstreamProtocol') -or $PSBoundParameters.ContainsKey('DhcpServer')
    ) {
        $plan = New-RulePlan
    }
    $status = Get-GuardStatus $plan
    $status | ConvertTo-Json -Depth 8
    Write-VirtualAdapterWarning $status.Prerequisites
    if ($status.ConfigurationMatched -eq $false) { exit 2 }
    exit 0
}

$operatorSid = $null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open an elevated PowerShell console on the local Windows computer.'
    }
    $operatorSid = $identity.User
} finally {
    $identity.Dispose()
}

Assert-SafeElevatedScriptPath -WarnOnly:($Action -eq 'Remove')
$plan = if ($Action -eq 'Install') { New-RulePlan } else { $null }

# Install needs its private log. Remove carries on without one, so that a broken log location
# cannot keep the network blocked.
$logPath = $null
$logStream = $null
$logWriter = $null
try {
    $logDir = Assert-UnlinkedLocalDirectory -Path $LogDirectory -Label 'LogDirectory'
    $logName = 'CPPEK-KillSwitch-{0}-{1}.jsonl' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), [Guid]::NewGuid().ToString('N')
    $logPath = Join-Path $logDir $logName
    $logStream = [IO.File]::Open($logPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    Set-PrivateFileAcl -FilePath $logPath -OperatorSid $operatorSid
    $logWriter = [IO.StreamWriter]::new($logStream, [Text.UTF8Encoding]::new($false))
    $logWriter.AutoFlush = $true
} catch {
    $logProblem = $_.Exception.Message
    Close-GuardLog $logStream
    $logStream = $null
    $logWriter = $null
    if ($Action -ne 'Remove') { throw }
    Write-StderrWarning "No log is written for this Remove: $logProblem"
    $logPath = $null
}

$mutex = $null
$ownsMutex = $false
$created = @()
$exitCode = 0
try {
    Write-GuardLog 'started' @{ PolicyGroup = $Group; HostVersion = [Environment]::OSVersion.Version.ToString() }
    $mutex = [Threading.Mutex]::new($false, "Global\$Group")
    try {
        $ownsMutex = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
        $ownsMutex = $true
    }
    if (-not $ownsMutex) { throw 'Another operation is already managing these rules.' }

    if ($Action -eq 'Remove') {
        $removed = @(Remove-OwnedRules $KnownNames)
        $status = Get-GuardStatus $null
        $ownedLeft = @(@($status.PersistentRules) + @($status.ActiveRules) | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
        if ($ownedLeft.Count) {
            throw "Some rules created by this kit remain visible after Remove: $($ownedLeft -join ', '). Inspect Status and retry Remove locally."
        }
        $remaining = @($status.ForeignOrUnexpectedRules)
        if ($remaining.Count) {
            # Rules with this group or these names whose name, group or description differs from what
            # this script creates (for example a description edited in wf.msc). They may still block
            # traffic, so this is not reported as "removed".
            Write-GuardLog 'removed-other-rules-remain' @{ RemovedRuleCount = $removed.Count; Rules = $removed; RemainingRuleCount = $remaining.Count }
            [pscustomobject][ordered]@{
                Status         = 'removed-other-rules-remain'
                RemovedRules   = $removed
                RemainingRules = $remaining
                NextStep       = "These rules use the group $Group or the names of this kit, but were not created by this script exactly as listed, so Remove left them in place. They may still block traffic. Check them in wf.msc (Outbound Rules, Filter by Group) or with Get-NetFirewallRule, and delete the ones you recognise with Remove-NetFirewallRule -PolicyStore PersistentStore -Name <name>. See WINDOWS-KILL-SWITCH.md."
                LogPath        = $logPath
            } | ConvertTo-Json -Depth 5
            $exitCode = 2
        } else {
            Write-GuardLog 'removed' @{ RemovedRuleCount = $removed.Count; Rules = $removed }
            [pscustomobject]@{ Status = 'removed'; RemovedRules = $removed; LogPath = $logPath } | ConvertTo-Json -Depth 5
        }
    } else {
        $prereq = Get-GuardPrerequisites $plan
        if (-not $AllowUncoveredPhysicalAdapters -and -not $prereq.AllActivePhysicalCovered) {
            throw "Uncovered active physical adapters detected ($($prereq.OtherActivePhysicalAdapters -join ', ')). Include all active physical adapters (or use -IncludeAllPhysicalAdapters) so traffic cannot bypass the guard."
        }
        if (-not $DhcpServer) {
            $dhcpCheck = Get-DhcpCheck $plan.InterfaceAliases
            if (@($dhcpCheck.Enabled).Count -or @($dhcpCheck.Unknown).Count) {
                throw (Format-DhcpProblem $dhcpCheck)
            }
        }
        Write-GuardLog 'preflight' @{
            Profiles = $prereq.Profiles
            SelectedAdapterCount = @($prereq.PhysicalAdapters).Count
            OtherActivePhysicalAdapterCount = @($prereq.OtherActivePhysicalAdapters).Count
            ActiveVirtualNonTunnelAdapterCount = @($prereq.ActiveVirtualNonTunnelAdapters).Count
        }
        Write-GuardLog 'planned' (Get-RedactedPlanSummary $plan)

        $persisted = @(Get-PolicySet 'PersistentStore')
        $active = @(Get-PolicySet 'ActiveStore')
        if (@($persisted).Count -or @($active).Count) {
            if (-not ((Test-RulesMatch $persisted $plan $true) -and (Test-RulesMatch $active $plan $true))) {
                throw 'The managed namespace already contains a different, incomplete, or foreign policy. Nothing was changed. To change adapters, upstream or DHCP servers, run -Action Remove first and then -Action Install with the new parameters (the guard is off between the two steps); run -Action Status to see what is there.'
            }
            $status = Get-GuardStatus $plan
            Write-GuardLog 'already-installed' @{ ConfigurationMatched = $status.ConfigurationMatched; RuleCount = @($status.ActiveRules).Count }
            [pscustomobject]@{ Status = 'already-installed'; LogPath = $logPath; Policy = $status } | ConvertTo-Json -Depth 8
            Write-VirtualAdapterWarning $status.Prerequisites
        } else {
            foreach ($entry in $plan.Rules) {
                $params = @{
                    PolicyStore = 'PersistentStore'; Name = $entry.Name; DisplayName = $entry.Name
                    Group = $Group; Description = $Owner; Enabled = 'False'; Direction = 'Outbound'
                    Action = 'Block'; Profile = 'Any'; InterfaceAlias = [string[]]$plan.InterfaceAliases
                    RemoteAddress = [string[]]$entry.RemoteAddresses
                }
                if ($entry.Protocol -ne 'Any') { $params.Protocol = $entry.Protocol }
                if (@($entry.RemotePorts).Count) { $params.RemotePort = [string[]]$entry.RemotePorts }
                if (@($entry.LocalPorts).Count) { $params.LocalPort = [string[]]$entry.LocalPorts }
                $created += $entry.Name
                New-NetFirewallRule @params -ErrorAction Stop | Out-Null
            }
            if (-not (Test-RulesMatch @(Get-PolicySet 'PersistentStore') $plan $false)) {
                throw 'The staged firewall filters differ from the plan.'
            }
            Write-GuardLog 'staged' @{ RuleNames = $created; Enabled = $false }
            Enable-NetFirewallRule -PolicyStore PersistentStore -Name $created -ErrorAction Stop | Out-Null

            $status = Get-GuardStatus $plan
            if ($status.ConfigurationMatched -ne $true) { throw 'The effective firewall filters differ from the plan.' }
            Write-GuardLog 'installed' @{ ConfigurationMatched = $status.ConfigurationMatched; RuleCount = @($status.ActiveRules).Count }
            [pscustomobject]@{ Status = 'installed'; LogPath = $logPath; Policy = $status } | ConvertTo-Json -Depth 8
            Write-VirtualAdapterWarning $status.Prerequisites
        }
    }
} catch {
    $original = $_
    $rollback = 'not-required'
    if ($created.Count) {
        # Take the rules of this attempt away before reporting the error, so that a failed Install
        # does not leave the network blocked.
        try {
            Remove-OwnedRules $created | Out-Null
            $remaining = @(Get-PolicySet 'PersistentStore') + @(Get-PolicySet 'ActiveStore')
            if (@($remaining | Where-Object { $_.Name -cin $created -and (Test-OwnedRule $_) }).Count) {
                throw 'Some rules created by this attempt remain visible.'
            }
            $rollback = 'completed'
        } catch {
            $rollback = 'incomplete-run-Remove-locally'
        }
    }
    try {
        Write-GuardLog 'failed' @{ Rollback = $rollback; ErrorType = $original.Exception.GetType().Name }
    } catch {
        # Report the log path and rollback finding even if the log disk failed.
    }
    $logText = if ($logPath) { $logPath } else { 'none' }
    if ($Action -eq 'Install') {
        throw "$($original.Exception.Message) Rollback: $rollback. Log: $logText"
    }
    throw "$($original.Exception.Message) Log: $logText"
} finally {
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
    if ($null -ne $logWriter) { Close-GuardLog $logWriter } else { Close-GuardLog $logStream }
}
exit $exitCode
