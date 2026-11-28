#Requires -Version 5.1
<#
.SYNOPSIS
Manage scoped outbound Windows Firewall rules blocking LAN/router port 53 DNS bypass on physical adapters.
.DESCRIPTION
Prevents processes from querying private/CGNAT/ULA/link-local router DNS (TCP/UDP 53) directly over
physical network interfaces when switching routers or hotspots, while leaving router admin (80/443),
DHCP (67/68), LAN sharing, loopback, and virtual TUN adapters unaffected.
Preview computes the rule plan natively in PowerShell without invoking external interpreters or
changing the host. Install and Remove require an elevated local Windows console and write a private
redacted log. Install refuses to run from a directory that unprivileged shared groups can change, or
from a volume without NTFS/ReFS permissions, exports a firewall policy backup (its SHA-256 is recorded,
not compared) before it adds rules, adds the rules disabled, and enables them only after they read
back as planned; it removes what it added when anything fails. Install only adds rules when none of
this kit's LAN DNS Guard rules exist: to change the adapters, run Remove first. Remove deletes the
rules this script created, reports any other rule left in its group, and only warns about the
script location (and runs without a log if none can be written).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Preview', 'Install', 'Status', 'Remove')]
    [string]$Action,

    [string[]]$InterfaceAlias,
    [switch]$IncludeAllPhysicalAdapters,
    [switch]$AllowUncoveredPhysicalAdapters,
    [string]$LogDirectory = $env:LOCALAPPDATA
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Group = 'CPPEK-LanDnsGuard-v1'
$Owner = 'Cross-platform privacy environment kit: physical-NIC LAN DNS port 53 guard v1'
$LanIPv4Prefixes = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10')
$LanIPv6Prefixes = @('fc00::/7', 'fe80::/10')
$KnownNames = @('IPv4-UDP53', 'IPv4-TCP53', 'IPv6-UDP53', 'IPv6-TCP53') | ForEach-Object { "$Group-$_" }

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

function ConvertTo-ValidatedInterfaceAliases {
    param([string[]]$Names)
    if (-not $Names -or $Names.Count -eq 0) {
        throw 'Supply at least one physical interface alias.'
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $clean = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in $Names) {
        if (-not (Test-LiteralInterfaceAlias $name)) {
            throw "Use literal interface aliases without wildcards or control characters: $(Format-AliasForMessage $name)."
        }
        if (-not $seen.Add($name)) {
            throw "Interface aliases must be unique: $(Format-AliasForMessage $name) is given twice."
        }
        $clean.Add($name)
    }
    # Ordinal order of the lower-cased names, like sorted(key=str.casefold) in build_lan_dns_guard.py.
    # Sort-Object would follow the current culture (for example pinyin order on Chinese Windows).
    $sorted = [string[]]$clean.ToArray()
    $sortKeys = [string[]]@($sorted | ForEach-Object { $_.ToLowerInvariant() })
    [Array]::Sort($sortKeys, $sorted, [StringComparer]::Ordinal)
    ,$sorted
}

function New-LanDnsGuardPlan {
    param([string[]]$Aliases)
    $validatedAliases = ConvertTo-ValidatedInterfaceAliases -Names $Aliases
    $rules = @(
        [pscustomobject][ordered]@{
            Name            = "$Group-IPv4-UDP53"
            RemoteAddresses = @($LanIPv4Prefixes)
            Protocol        = 'UDP'
            RemotePorts     = @('53')
            LocalPorts      = @()
        }
        [pscustomobject][ordered]@{
            Name            = "$Group-IPv4-TCP53"
            RemoteAddresses = @($LanIPv4Prefixes)
            Protocol        = 'TCP'
            RemotePorts     = @('53')
            LocalPorts      = @()
        }
        [pscustomobject][ordered]@{
            Name            = "$Group-IPv6-UDP53"
            RemoteAddresses = @($LanIPv6Prefixes)
            Protocol        = 'UDP'
            RemotePorts     = @('53')
            LocalPorts      = @()
        }
        [pscustomobject][ordered]@{
            Name            = "$Group-IPv6-TCP53"
            RemoteAddresses = @($LanIPv6Prefixes)
            Protocol        = 'TCP'
            RemotePorts     = @('53')
            LocalPorts      = @()
        }
    )
    [pscustomobject][ordered]@{
        SchemaVersion    = 1
        InterfaceAliases = @($validatedAliases)
        RuleCount        = $rules.Count
        Rules            = $rules
    }
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Install and Remove must run from an elevated local PowerShell console.'
        }
        $identity.User
    } finally {
        $identity.Dispose()
    }
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
    # here protects nothing and only keeps the rules in place.
    param([switch]$WarnOnly)
    if (-not $PSCommandPath) { return }
    $problems = New-Object 'System.Collections.Generic.List[string]'
    try {
        $scriptDir = Assert-UnlinkedLocalDirectory -Path (Split-Path -Parent $PSCommandPath) -Label 'Script directory'
        $attr = [IO.File]::GetAttributes($PSCommandPath)
        if (($attr -band [IO.FileAttributes]::ReparsePoint) -or ($attr -band [IO.FileAttributes]::Directory)) {
            $problems.Add('Manage-WindowsLanDnsGuard.ps1 must be a regular local file without links.')
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
    switch ($Value.Trim().ToLowerInvariant()) {
        '10.0.0.0/255.0.0.0'      { return '10.0.0.0/8' }
        '172.16.0.0/255.240.0.0'  { return '172.16.0.0/12' }
        '192.168.0.0/255.255.0.0' { return '192.168.0.0/16' }
        '100.64.0.0/255.192.0.0'  { return '100.64.0.0/10' }
        default                   { return $Value.Trim().ToLowerInvariant() }
    }
}

function Normalize-Protocol {
    param([string]$Value)
    switch ($Value.Trim().ToUpperInvariant()) {
        '6'   { 'TCP' }
        'TCP' { 'TCP' }
        '17'  { 'UDP' }
        'UDP' { 'UDP' }
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
        $actualAddresses = @($addresses.RemoteAddress | ForEach-Object { Normalize-RemoteAddress $_ })
        if ($protocol -cne $entry.Protocol -or
            -not (Test-Any $ports.LocalPort) -or
            -not (Test-SameSet $ports.RemotePort $entry.RemotePorts) -or
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
            throw "The selected physical adapter could not be identified: $alias. Only adapters whose HardwareInterface property is True can be selected; check with: Get-NetAdapter -IncludeHidden | Select-Object Name, HardwareInterface, Status"
        }
    }
    $otherActivePhysical = @($physical | Where-Object {
        $_.Status -eq 'Up' -and $_.Name -notin $Plan.InterfaceAliases
    } | ForEach-Object { $_.Name })
    [pscustomobject]@{
        Profiles                    = @($profiles.Name)
        PhysicalAdapterCount        = @($Plan.InterfaceAliases).Count
        OtherActivePhysicalAdapters = $otherActivePhysical
        AllActivePhysicalCovered    = ($otherActivePhysical.Count -eq 0)
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

function Write-GuardLog {
    param([string]$Event, $Data)
    if ($null -eq $logWriter -or $null -eq $logPath) { return }
    try {
        $logWriter.WriteLine(([ordered]@{ Utc = [DateTime]::UtcNow.ToString('o'); Event = $Event; Action = $Action; Data = $Data } |
            ConvertTo-Json -Depth 6 -Compress))
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

function Resolve-TargetAliases {
    if ($IncludeAllPhysicalAdapters) {
        if ($InterfaceAlias -and $InterfaceAlias.Count -gt 0) {
            throw 'Use either -InterfaceAlias or -IncludeAllPhysicalAdapters, not both.'
        }
        $discovered = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
            Where-Object { $_.HardwareInterface -eq $true } |
            ForEach-Object { [string]$_.Name })
        if ($discovered.Count -eq 0) {
            throw 'No physical network adapters were detected on this host.'
        }
        return ,$discovered
    }
    ,$InterfaceAlias
}

$plan = $null
if ($Action -in @('Preview', 'Install') -or ($Action -eq 'Status' -and ($IncludeAllPhysicalAdapters -or ($InterfaceAlias -and $InterfaceAlias.Count -gt 0)))) {
    $resolvedAliases = Resolve-TargetAliases
    $plan = New-LanDnsGuardPlan -Aliases $resolvedAliases
}

if ($Action -eq 'Preview') {
    $plan | ConvertTo-Json -Depth 6
    exit 0
}

if ($Action -eq 'Status') {
    $persisted = @(Get-PolicySet 'PersistentStore')
    $active = @(Get-PolicySet 'ActiveStore')
    $matched = $null
    $prereq = $null
    if ($null -ne $plan) {
        $prereq = Get-GuardPrerequisites -Plan $plan
        $coverageOk = $AllowUncoveredPhysicalAdapters.IsPresent -or $prereq.AllActivePhysicalCovered
        $matched = $coverageOk -and (Test-RulesMatch $persisted $plan $true) -and (Test-RulesMatch $active $plan $true)
    }
    [pscustomobject][ordered]@{
        ObservedAtUtc            = [DateTime]::UtcNow.ToString('o')
        Group                    = $Group
        PersistedCount           = $persisted.Count
        ActiveCount              = $active.Count
        PersistedNames           = @($persisted | ForEach-Object { $_.Name } | Sort-Object)
        ActiveNames              = @($active | ForEach-Object { $_.Name } | Sort-Object)
        ForeignOrUnexpectedRules = @(@($persisted) + @($active) | Where-Object { -not (Test-OwnedRule $_) } |
            ForEach-Object { $_.Name } | Sort-Object -Unique)
        MatchedPlan              = $matched
        AllActivePhysicalCovered = if ($null -ne $prereq) { $prereq.AllActivePhysicalCovered } else { $null }
    } | ConvertTo-Json -Depth 5
    # Like the kill switch: exit code 2 when a plan was given and the rules do not match it.
    if ($matched -eq $false) { exit 2 }
    exit 0
}

$operatorSid = Assert-Elevated
Assert-SafeElevatedScriptPath -WarnOnly:($Action -eq 'Remove')

# Install needs its private log. Remove carries on without one, so that a broken log location
# cannot keep the rules in place.
$logPath = $null
$fileStream = $null
$logWriter = $null
$safeLogDir = $null
$stamp = '{0}-{1}' -f [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), [Guid]::NewGuid().ToString('N')
try {
    $safeLogDir = Assert-UnlinkedLocalDirectory -Path $LogDirectory -Label 'LogDirectory'
    $logPath = Join-Path $safeLogDir "CPPEK-LanDnsGuard-$stamp.jsonl"
    $fileStream = [IO.File]::Open($logPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    Set-PrivateFileAcl -FilePath $logPath -OperatorSid $operatorSid
    $logWriter = [IO.StreamWriter]::new($fileStream, [Text.UTF8Encoding]::new($false))
    $logWriter.AutoFlush = $true
} catch {
    $logProblem = $_.Exception.Message
    Close-GuardLog $fileStream
    $fileStream = $null
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
    Write-GuardLog 'started' @{ PolicyGroup = $Group }
    $mutex = [Threading.Mutex]::new($false, "Global\$Group")
    try {
        $ownsMutex = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
        $ownsMutex = $true
    }
    if (-not $ownsMutex) { throw 'Another operation is already managing these rules.' }

    if ($Action -eq 'Remove') {
        $removed = @(Remove-OwnedRules -Names $KnownNames)
        $persisted = @(Get-PolicySet 'PersistentStore')
        $active = @(Get-PolicySet 'ActiveStore')
        $ownedLeft = @(@($persisted) + @($active) | Where-Object { Test-OwnedRule $_ } | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
        if ($ownedLeft.Count) {
            throw "Some rules created by this kit remain visible after Remove: $($ownedLeft -join ', '). Run Status and retry Remove locally."
        }
        # Rules left in the group, or with these names, that this script did not create exactly as
        # listed (for example a description edited in wf.msc). They are left alone and reported.
        $remaining = @(@($persisted) + @($active) | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
        $result = [ordered]@{
            Status         = if ($remaining.Count) { 'removed-other-rules-remain' } else { 'removed' }
            Action         = 'Remove'
            Group          = $Group
            RemovedCount   = $removed.Count
            RemovedNames   = $removed
            RemainingRules = $remaining
        }
        if ($remaining.Count) {
            $result.NextStep = "These rules use the group $Group or the names of this kit, but were not created by this script exactly as listed, so Remove left them in place. They may still block DNS. Check them in wf.msc (Outbound Rules, Filter by Group) or with Get-NetFirewallRule, and delete the ones you recognise with Remove-NetFirewallRule -PolicyStore PersistentStore -Name <name>. See WINDOWS-KILL-SWITCH.md."
            $exitCode = 2
        }
        Write-GuardLog $result.Status @{ RemovedCount = $removed.Count; RemainingCount = $remaining.Count }
        $result.LogPath = $logPath
        [pscustomobject]$result | ConvertTo-Json -Depth 4
    } else {
        $prereq = Get-GuardPrerequisites -Plan $plan
        if (-not $prereq.AllActivePhysicalCovered -and -not $AllowUncoveredPhysicalAdapters) {
            throw "At least one active physical adapter is not covered ($($prereq.OtherActivePhysicalAdapters -join ', ')). Pass -IncludeAllPhysicalAdapters or -AllowUncoveredPhysicalAdapters."
        }
        $persisted = @(Get-PolicySet 'PersistentStore')
        $active = @(Get-PolicySet 'ActiveStore')
        $foreign = @(@($persisted) + @($active) | Where-Object { -not (Test-OwnedRule $_) } | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
        if ($foreign.Count) {
            throw "Nothing was changed: these firewall rules share this rule group or these rule names but were not created by this script: $($foreign -join ', '). Inspect them (see WINDOWS-KILL-SWITCH.md) before installing."
        }
        if ($persisted.Count -or $active.Count) {
            # Rules from an earlier Install: never deleted here, so a failed Install cannot leave the
            # host with fewer rules than before.
            if (-not ((Test-RulesMatch $persisted $plan $true) -and (Test-RulesMatch $active $plan $true))) {
                throw 'Nothing was changed: LAN DNS Guard rules are already installed but differ from this plan (other adapters, disabled, or edited). To change the adapters, run -Action Remove first, then -Action Install with the new parameters.'
            }
            Write-GuardLog 'already-installed' @{ InterfaceCount = @($plan.InterfaceAliases).Count; RuleCount = @($plan.Rules).Count }
            [pscustomobject][ordered]@{
                Status         = 'already-installed'
                Action         = 'Install'
                Group          = $Group
                InterfaceCount = @($plan.InterfaceAliases).Count
                RuleCount      = @($plan.Rules).Count
                LogPath        = $logPath
                Verified       = $true
            } | ConvertTo-Json -Depth 4
        } else {
            $backupPath = Join-Path $safeLogDir "CPPEK-LanDnsGuard-before-$stamp.wfw"
            $netsh = Join-Path ([Environment]::SystemDirectory) 'netsh.exe'
            & $netsh advfirewall export $backupPath | Out-Null
            if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($backupPath)) {
                throw 'Failed to export Windows Firewall backup before Install.'
            }
            Set-PrivateFileAcl -FilePath $backupPath -OperatorSid $operatorSid
            $backupHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash
            Write-GuardLog 'backup' @{ BackupSha256 = $backupHash }

            # Stage all four rules disabled, check them, then enable them together.
            foreach ($entry in $plan.Rules) {
                $created += $entry.Name
                New-NetFirewallRule -PolicyStore PersistentStore `
                    -Name $entry.Name `
                    -DisplayName $entry.Name `
                    -Group $Group `
                    -Description $Owner `
                    -Direction Outbound `
                    -Action Block `
                    -Enabled False `
                    -Profile Any `
                    -InterfaceAlias $plan.InterfaceAliases `
                    -Protocol $entry.Protocol `
                    -RemotePort $entry.RemotePorts `
                    -RemoteAddress $entry.RemoteAddresses `
                    -ErrorAction Stop | Out-Null
            }
            if (-not (Test-RulesMatch @(Get-PolicySet 'PersistentStore') $plan $false)) {
                throw 'The staged firewall rules differ from the plan.'
            }
            Write-GuardLog 'staged' @{ RuleNames = $created; Enabled = $false }
            Enable-NetFirewallRule -PolicyStore PersistentStore -Name $created -ErrorAction Stop | Out-Null

            $persisted = @(Get-PolicySet 'PersistentStore')
            $active = @(Get-PolicySet 'ActiveStore')
            if (-not (Test-RulesMatch $persisted $plan $true) -or -not (Test-RulesMatch $active $plan $true)) {
                throw 'Verification after enabling the rules failed.'
            }
            Write-GuardLog 'installed' @{
                InterfaceCount = @($plan.InterfaceAliases).Count
                RuleCount      = @($plan.Rules).Count
                BackupSha256   = $backupHash
            }
            [pscustomobject][ordered]@{
                Status         = 'installed'
                Action         = 'Install'
                Group          = $Group
                InterfaceCount = @($plan.InterfaceAliases).Count
                RuleCount      = @($plan.Rules).Count
                BackupPath     = $backupPath
                BackupSha256   = $backupHash
                LogPath        = $logPath
                Verified       = $true
            } | ConvertTo-Json -Depth 4
        }
    }
} catch {
    $original = $_
    $rollback = $null
    if ($created.Count) {
        # Take away what this attempt added before reporting the error.
        try {
            [void](Remove-OwnedRules -Names $created)
            $left = @(@(Get-PolicySet 'PersistentStore') + @(Get-PolicySet 'ActiveStore') |
                Where-Object { $_.Name -cin $created -and (Test-OwnedRule $_) })
            if ($left.Count) { throw 'Some rules created by this attempt remain visible.' }
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
    if ($null -ne $rollback) {
        throw "$($original.Exception.Message) Rollback of the rules added by this attempt: $rollback (Install only adds rules when none exist, so no earlier rules were removed). Log: $logText"
    }
    throw "$($original.Exception.Message) Log: $logText"
} finally {
    if ($ownsMutex) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
    if ($null -ne $logWriter) { Close-GuardLog $logWriter } else { Close-GuardLog $fileStream }
}
exit $exitCode
