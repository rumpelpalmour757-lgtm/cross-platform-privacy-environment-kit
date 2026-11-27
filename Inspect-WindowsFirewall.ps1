#requires -Version 5.1
<#
.SYNOPSIS
Summarizes effective Windows Firewall policy without changing it.

.DESCRIPTION
Returns JSON. Uses local queries only and omits network names, addresses,
rule names, application paths, and logs. Observed settings and rule counts
alone cannot prove that traffic is blocked when a tunnel goes down.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Inspect-WindowsFirewall.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'Run this inventory on the target Windows computer.'
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom
try {
    [Console]::OutputEncoding = $utf8NoBom
} catch {
    # Ignore if stdout is not attached to a console handle.
}

$warnings = New-Object 'System.Collections.Generic.List[string]'

function Invoke-LocalFirewallProbe {
    param([string]$Label, [scriptblock]$Body)

    try {
        & $Body
    } catch {
        $message = "$Label unavailable"
        if (-not $warnings.Contains($message)) {
            $warnings.Add($message)
        }
    }
}

$profiles = @(Invoke-LocalFirewallProbe 'ActiveStore firewall profiles' {
    Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
        Sort-Object -Property Name |
        ForEach-Object {
            [pscustomobject]@{
                Profile               = [string]$_.Name
                Enabled               = [string]$_.Enabled
                DefaultInboundAction  = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
                AllowLocalRules       = [string]$_.AllowLocalFirewallRules
                LogBlocked            = [string]$_.LogBlocked
            }
        }
})

$services = @(
    foreach ($serviceName in @('BFE', 'MpsSvc')) {
        $service = Invoke-LocalFirewallProbe "Service $serviceName" {
            Get-Service -Name $serviceName -ErrorAction Stop
        }
        [pscustomobject]@{
            Service = $serviceName
            Status  = if ($null -eq $service) { 'Unavailable' } else { [string]$service.Status }
        }
    }
)

$networkCategories = @(Invoke-LocalFirewallProbe 'Network connection categories' {
    try {
        Get-NetConnectionProfile -ErrorAction Stop |
            Group-Object -Property NetworkCategory -NoElement |
            Sort-Object -Property Name |
            ForEach-Object {
                [pscustomobject]@{ Category = $_.Name; Connections = $_.Count }
            }
    } catch {
        if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound -or
            $_.FullyQualifiedErrorId -notin @('CmdletizationQuery_NotFound,Get-NetConnectionProfile')) {
            throw
        }
    }
})

$outboundRules = Invoke-LocalFirewallProbe 'ActiveStore outbound rules' {
    $counts = [ordered]@{ Allow = 0; Block = 0; Other = 0 }
    $allowBreakdown = [ordered]@{ BuiltInOrMicrosoft = 0; OtherThirdPartyOrCustom = 0 }
    $port53BlockCount = 0
    $msixClaudeAllowCount = 0
    try {
        Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { [string]$_.Direction -eq 'Outbound' -and [string]$_.Enabled -eq 'True' } |
            ForEach-Object {
                $rule = $_
                switch ([string]$rule.Action) {
                    'Allow' {
                        $counts.Allow += 1
                        $nameText = "$($rule.Name) $($rule.DisplayName) $($rule.Group)"
                        $ruleGroup = [string]$rule.Group
                        # Judge "Microsoft" by the rule group only: built-in rules use resource strings such
                        # as @FirewallAPI.dll,-25000 or @%SystemRoot%\..., Microsoft packages use
                        # @{Microsoft.*}, and Microsoft apps name groups like "Microsoft Edge". Matching words
                        # anywhere in the name counted rules such as "Clash for Windows" or "WPS Office".
                        if ($ruleGroup -match '(?i)^@(?:\{Microsoft\.|%(?:SystemRoot|windir)%\\|[a-z]:\\windows\\|[a-z0-9_.-]+\.(?:dll|exe|mui),)' -or
                            $ruleGroup -match '(?i)^(?:Microsoft|Windows|Core Networking)\b') {
                            $allowBreakdown.BuiltInOrMicrosoft += 1
                        } else {
                            $allowBreakdown.OtherThirdPartyOrCustom += 1
                        }
                        if ($nameText -match '(?i)\b(?:Claude|Cowork)') {
                            $msixClaudeAllowCount += 1
                        }
                    }
                    'Block' {
                        $counts.Block += 1
                        try {
                            $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
                            if (@($portFilter.RemotePort) -contains '53') {
                                $port53BlockCount += 1
                            }
                        } catch {
                            # Ignore port filter lookup failures on individual rules.
                        }
                    }
                    default { $counts.Other += 1 }
                }
            }
    } catch {
        if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound -or
            $_.FullyQualifiedErrorId -notin @('CmdletizationQuery_NotFound,Get-NetFirewallRule')) {
            throw
        }
    }
    [pscustomobject]@{
        Counts                  = [pscustomobject]$counts
        AllowBreakdown          = [pscustomobject]$allowBreakdown
        Port53OutboundBlockCount = $port53BlockCount
        MsixClaudeAllowCount    = $msixClaudeAllowCount
    }
}

if ($null -ne $outboundRules -and $outboundRules.MsixClaudeAllowCount -gt 0) {
    $warnings.Add('Detected enabled Outbound Allow firewall rules whose name, display name or group contains the word Claude or Cowork (for example MSIX package rules); explicit Allow overrides DefaultOutboundAction=Block when TUN disconnects.')
}

[pscustomobject]@{
    ObservedAtUtc                   = [datetime]::UtcNow.ToString('o')
    ActiveStoreProfiles             = $profiles
    FirewallServices                = $services
    CurrentNetworkCategories        = $networkCategories
    EnabledOutboundRuleCounts       = if ($null -ne $outboundRules) { $outboundRules.Counts } else { $null }
    EnabledOutboundAllowBreakdown   = if ($null -ne $outboundRules) { $outboundRules.AllowBreakdown } else { $null }
    LanDnsPort53OutboundBlockCount  = if ($null -ne $outboundRules) { $outboundRules.Port53OutboundBlockCount } else { $null }
    MsixClaudeOutboundAllowCount    = if ($null -ne $outboundRules) { $outboundRules.MsixClaudeAllowCount } else { $null }
    Warnings                        = @($warnings.ToArray())
    EvidenceLimits                  = @(
        'Counts cover enabled outbound rules in ActiveStore across all profiles. Individual rules can have additional conditions.'
        'An unset or NotConfigured action is not a verified allow or block result.'
        'Allow breakdown is a heuristic on the rule group (Windows resource strings, Microsoft packages, groups starting with Microsoft, Windows or Core Networking) and does not expose paths or rule names; rules without such a group count as third-party or custom. Review third-party allow rules locally.'
        'MsixClaudeOutboundAllowCount counts every enabled outbound allow rule whose name, display name or group contains the word Claude or Cowork, MSIX or not.'
        'LanDnsPort53OutboundBlockCount counts enabled outbound block rules with remote port 53, whatever their addresses and adapters.'
        'This inventory sends no traffic and cannot verify whether tunnel failure blocks subsequent connections.'
    )
} | ConvertTo-Json -Depth 5
