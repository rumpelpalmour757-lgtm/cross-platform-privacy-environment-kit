#Requires -Version 5.1
<#
.SYNOPSIS
Observe HTTPS connectivity at an operator-selected Windows proxy stage.
.DESCRIPTION
Run in a non-elevated terminal. This script never changes the network or prepares
an outage. Because the probe disables curl proxy use (--noproxy "*") to follow
OS system routing, running it in -Stage normal without an active TUN/tunnel route
would bypass System Proxy and expose your real IP to ProbeUrl. Therefore, in the
normal and upstream-unreachable stages the script first checks for a default route
on a tunnel adapter and refuses to send a probe without one (unless explicitly
overridden via -AllowDirectWithoutTun). The check is per address family: with the
default -AddressFamily auto, curl is limited to the families the tunnel has default
routes for (an IPv4-only TUN means an IPv4-only probe), so a native IPv6 route on the
physical adapter cannot carry the probe. Route metrics are not compared.
Tunnel adapters are recognised by name; pass -TunnelInterfaceAlias to name them. A named
adapter whose HardwareInterface property is True (Wi-Fi, Ethernet) never counts as a tunnel:
in the normal and upstream-unreachable stages naming one, or a name that is missing or not Up,
stops the script before any probe unless -AllowDirectWithoutTun is given.
In the tun-down and client-down stages, "no connection" counts as observed only when the system
DNS cache did not hold fake-ip addresses alone (198.18.0.0/15, fc00::/18) for the probe host:
such an address cannot be reached once TUN is off, with or without a kill switch.
.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-ProxyState.ps1 -Stage normal -AsJson
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('normal', 'upstream-unreachable', 'tun-down', 'client-down')]
    [string] $Stage,

    [uri] $ProbeUrl = 'https://example.com/',

    [uri] $DirectUrl,

    [ValidateSet('auto', 'ipv4', 'ipv6')]
    [string] $AddressFamily = 'auto',

    [string[]] $TunnelInterfaceAlias,

    [ValidateRange(3, 60)]
    [int] $TimeoutSeconds = 12,

    [switch] $AllowDirectWithoutTun,

    [switch] $AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this script in a non-elevated Windows terminal.'
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom
try {
    [Console]::OutputEncoding = $utf8NoBom
} catch {
    # Ignore if stdout is not attached to a console handle.
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    if ($identity.IsSystem -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this test as an ordinary user in a non-elevated terminal.'
    }
} finally {
    $identity.Dispose()
}

$curlPath = Join-Path ([Environment]::SystemDirectory) 'curl.exe'
if (-not (Test-Path -LiteralPath $curlPath -PathType Leaf)) {
    throw 'Windows system curl.exe was not found. No network probes were sent.'
}

function Test-NonPublicIpHost {
    param([string] $HostName)
    $clean = $HostName.Trim('[', ']')
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($clean, [ref] $ip)) {
        return $false
    }
    if ([Net.IPAddress]::IsLoopback($ip)) { return $true }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $ip.GetAddressBytes()
        $val = ([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3]
        return (
            (($val -band 0xFF000000L) -eq 0x00000000L) -or # 0.0.0.0/8
            (($val -band 0xFF000000L) -eq 0x0A000000L) -or # 10.0.0.0/8
            (($val -band 0xFFC00000L) -eq 0x64400000L) -or # 100.64.0.0/10
            (($val -band 0xFF000000L) -eq 0x7F000000L) -or # 127.0.0.0/8
            (($val -band 0xFFFF0000L) -eq 0xA9FE0000L) -or # 169.254.0.0/16
            (($val -band 0xFFF00000L) -eq 0xAC100000L) -or # 172.16.0.0/12
            (($val -band 0xFFFF0000L) -eq 0xC0A80000L) -or # 192.168.0.0/16
            (($val -band 0xFFFE0000L) -eq 0xC6120000L) -or # 198.18.0.0/15
            (($val -band 0xF0000000L) -eq 0xE0000000L) -or # 224.0.0.0/4
            (($val -band 0xF0000000L) -eq 0xF0000000L)     # 240.0.0.0/4
        )
    }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        return (
            $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.IsIPv6Multicast -or
            (($ip.GetAddressBytes()[0] -band 0xFE) -eq 0xFC) -or
            $ip.Equals([Net.IPAddress]::IPv6None)
        )
    }
    return $true
}

function Assert-ProbeUrl {
    param([uri] $Url)

    if (
        -not $Url.IsAbsoluteUri -or $Url.Scheme -ne 'https' -or
        [string]::IsNullOrWhiteSpace($Url.Host) -or $Url.UserInfo -or
        $Url.Query -or $Url.Fragment -or $Url.IsLoopback -or
        (Test-NonPublicIpHost $Url.IdnHost) -or
        $Url.AbsoluteUri.Length -gt 2048 -or $Url.AbsoluteUri -match '["\s\\\x00-\x1F\x7F]'
    ) {
        throw 'Use a public HTTPS probe URL without private IP literals, credentials, a query, or a fragment.'
    }
}

function Select-NamedTunnelAdapter {
    # Which of the adapters named with -TunnelInterfaceAlias count as tunnels. Kept free of outside
    # state: test_kill_switch_powershell.py runs it with synthetic adapters. An adapter whose
    # HardwareInterface property is True is a physical adapter (Wi-Fi, Ethernet) and never counts:
    # its default route goes straight out, so counting it would let the probe show the test site
    # the real address. Names that match no adapter, or only adapters that are not Up, are listed.
    param([object[]] $Adapter, [string[]] $Name)
    $tunnel = @()
    $missing = @()
    $notUp = @()
    $physical = @()
    foreach ($item in @($Name)) {
        $found = @($Adapter | Where-Object { $null -ne $_ -and [string]$_.Name -eq $item })
        if ($found.Count -eq 0) {
            $missing += $item
        } elseif (@($found | Where-Object { $_.HardwareInterface -eq $true }).Count) {
            $physical += $item
        } elseif (@($found | Where-Object { [string]$_.Status -eq 'Up' }).Count -eq 0) {
            $notUp += $item
        } else {
            $tunnel += @($found | Where-Object { [string]$_.Status -eq 'Up' })
        }
    }
    [pscustomobject] @{ Tunnel = @($tunnel); Missing = @($missing); NotUp = @($notUp); Physical = @($physical) }
}

function Format-NamedTunnelProblem {
    param($Selection, [switch] $PhysicalOnly)
    $parts = @()
    if (@($Selection.Physical).Count) {
        $parts += "-TunnelInterfaceAlias names a physical adapter (HardwareInterface is True), not a tunnel: $((@($Selection.Physical) | ForEach-Object { "'$_'" }) -join ', '). Its default route goes straight out with your real IP. Name only the virtual adapter that the proxy client creates for TUN mode (see Get-NetAdapter -IncludeHidden | Select-Object Name, InterfaceDescription, Status, HardwareInterface)."
    }
    if (-not $PhysicalOnly) {
        if (@($Selection.Missing).Count) {
            $parts += "-TunnelInterfaceAlias names no adapter on this computer: $((@($Selection.Missing) | ForEach-Object { "'$_'" }) -join ', ')."
        }
        if (@($Selection.NotUp).Count) {
            $parts += "-TunnelInterfaceAlias names an adapter that is not Up: $((@($Selection.NotUp) | ForEach-Object { "'$_'" }) -join ', '). Is TUN mode on?"
        }
    }
    $parts -join ' '
}

function Get-TunnelRouteFamily {
    # Address families ('ipv4', 'ipv6') for which one of the given tunnel adapters carries a default route.
    param([object[]] $TunnelAdapter)
    $tunnelIndexes = @($TunnelAdapter | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_.ifIndex })
    if ($tunnelIndexes.Count -eq 0) { return }
    try {
        $tunnelRoutes = @(
            Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { ([int]$_.InterfaceIndex) -in $tunnelIndexes }
        )
        if (@($tunnelRoutes | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1') }).Count) { 'ipv4' }
        if (@($tunnelRoutes | Where-Object { $_.DestinationPrefix -in @('::/0', '::/1', '8000::/1', '2000::/3') }).Count) { 'ipv6' }
    } catch {
        return
    }
}

function Resolve-ProbeAddressFamily {
    # Which address family to probe, and whether the tunnel preflight passes. Kept free of outside
    # state: test_kill_switch_powershell.py runs it with synthetic inputs. In the stages that need
    # a tunnel route, "auto" narrows to the families the tunnel has default routes for: with an
    # IPv4-only TUN, an unrestricted curl could reach an AAAA address over the physical adapter's
    # native IPv6 route and show the test site the real address.
    param([string] $Requested, [string] $Stage, [string[]] $TunnelFamilies)
    $families = @($TunnelFamilies | Where-Object { $_ })
    $hasIPv4 = $families -contains 'ipv4'
    $hasIPv6 = $families -contains 'ipv6'
    if ($Requested -in @('ipv4', 'ipv6')) {
        return [pscustomobject] @{ Effective = $Requested; TunnelRouteDetected = ($families -contains $Requested) }
    }
    if ($Stage -notin @('normal', 'upstream-unreachable') -or ($hasIPv4 -and $hasIPv6)) {
        return [pscustomobject] @{ Effective = 'auto'; TunnelRouteDetected = ($hasIPv4 -or $hasIPv6) }
    }
    if ($hasIPv4) { return [pscustomobject] @{ Effective = 'ipv4'; TunnelRouteDetected = $true } }
    if ($hasIPv6) { return [pscustomobject] @{ Effective = 'ipv6'; TunnelRouteDetected = $true } }
    [pscustomobject] @{ Effective = 'auto'; TunnelRouteDetected = $false }
}

function Test-FakeIpAddress {
    # The ranges TUN clients answer from in fake-ip mode (the same as refresh_allowlists.py):
    # 198.18.0.0/15 and fc00::/18. Kept free of outside state: test_kill_switch_powershell.py runs it.
    param([string] $Address)
    $ip = $null
    if (-not [Net.IPAddress]::TryParse(([string]$Address).Trim(), [ref] $ip)) { return $false }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        return ($b[0] -eq 198 -and ($b[1] -band 0xFE) -eq 18)
    }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        return ($b[0] -eq 0xFC -and $b[1] -eq 0 -and ($b[2] -band 0xC0) -eq 0)
    }
    $false
}

function Test-FakeIpOnlyCache {
    # True when the A/AAAA records among the given DNS cache entries (Get-DnsClientCache objects:
    # Type 1 or 28, the address in Data) are all fake-ip addresses. Without any readable address
    # it is false, and the verdict stays as before. Kept free of outside state for the tests.
    param([object[]] $Entry)
    $addresses = @(@($Entry) | Where-Object { $null -ne $_ -and ([int]$_.Type) -in @(1, 28) } |
        ForEach-Object { ([string]$_.Data).Trim() } | Where-Object { $_ })
    $readable = @($addresses | Where-Object { $parsed = $null; [Net.IPAddress]::TryParse($_, [ref] $parsed) })
    if ($readable.Count -eq 0) { return $false }
    @($readable | Where-Object { -not (Test-FakeIpAddress $_) }).Count -eq 0
}

function Get-DnsCacheState {
    # Cached: the system DNS cache has any entry for the host (as before). FakeIpOnly: every cached
    # address for it is a fake-ip address, which cannot be reached once TUN is off, kill switch or
    # not, so "no connection" in tun-down or client-down then proves nothing.
    param([string] $HostName)
    try {
        $entries = @(Get-DnsClientCache -Name $HostName -ErrorAction SilentlyContinue)
    } catch {
        return [pscustomobject] @{ Cached = $false; FakeIpOnly = $false }
    }
    $fakeOnly = $false
    try {
        $fakeOnly = Test-FakeIpOnlyCache -Entry $entries
    } catch {
        $fakeOnly = $false
    }
    [pscustomobject] @{ Cached = ($entries.Count -gt 0); FakeIpOnly = [bool]$fakeOnly }
}

function Invoke-HTTPSProbe {
    param([uri] $Url, [string] $Family)

    $processInfo = New-Object Diagnostics.ProcessStartInfo
    $processInfo.FileName = $curlPath
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true

    foreach ($name in @($processInfo.EnvironmentVariables.Keys)) {
        if ($name -match '^(all|https?|ftp|no)_proxy$|^(SSLKEYLOGFILE|QLOGDIR)$') {
            $processInfo.EnvironmentVariables.Remove([string] $name)
        }
    }

    $connectTimeout = [Math]::Min($TimeoutSeconds, 8)
    $familyOption = switch ($Family) {
        'ipv4' { '--ipv4 ' }
        'ipv6' { '--ipv6 ' }
        default { '' }
    }

    $processInfo.Arguments = (
        '-q --noproxy "*" --proto "=https" --globoff --head --silent --show-error ' +
        "--connect-timeout $connectTimeout --max-time $TimeoutSeconds " +
        '--output NUL --write-out "http=%{http_code};tcp=%{time_connect};total=%{time_total}" ' +
        $familyOption + '-- "' + $Url.AbsoluteUri + '"'
    )

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $processInfo
    $started = $false
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $observation = [ordered] @{
        CurlExitCode = $null
        HttpStatus = $null
        TcpConnectSeconds = $null
        CurlTotalSeconds = $null
        WallMilliseconds = $null
        State = 'probe-process-error'
    }

    try {
        $started = $process.Start()
        if (-not $started) {
            return [pscustomobject] $observation
        }

        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(($TimeoutSeconds + 3) * 1000)) {
            try {
                $process.Kill()
                [void] $process.WaitForExit(1000)
            } catch [InvalidOperationException] {
            }
            $observation.WallMilliseconds = $timer.ElapsedMilliseconds
            $observation.State = 'supervisor-timeout'
            return [pscustomobject] $observation
        }

        $observation.CurlExitCode = $process.ExitCode
        $observation.WallMilliseconds = $timer.ElapsedMilliseconds
        $streams = [Threading.Tasks.Task[]] @($stdout, $stderr)
        if (-not [Threading.Tasks.Task]::WaitAll($streams, 1000)) {
            $observation.State = 'output-timeout'
            return [pscustomobject] $observation
        }

        if ($stdout.Result.Trim() -notmatch '^http=(\d{3});tcp=(\d+(?:[.,]\d+)?);total=(\d+(?:[.,]\d+)?)$') {
            $observation.State = 'unparsed-curl-output'
            return [pscustomobject] $observation
        }

        $culture = [Globalization.CultureInfo]::InvariantCulture
        $observation.HttpStatus = [int] $Matches[1]
        $observation.TcpConnectSeconds = [decimal]::Parse($Matches[2].Replace(',', '.'), $culture)
        $observation.CurlTotalSeconds = [decimal]::Parse($Matches[3].Replace(',', '.'), $culture)

        if ($observation.HttpStatus -ge 100) {
            $observation.State = 'https-response'
        } elseif ($observation.TcpConnectSeconds -gt 0) {
            $observation.State = 'tcp-connected-no-https-response'
        } elseif ($observation.CurlExitCode -eq 6) {
            $observation.State = 'name-resolution-failed'
        } elseif ($observation.CurlExitCode -in @(7, 28)) {
            $observation.State = 'no-connection-observed'
        } else {
            $observation.State = 'other-curl-error'
        }
    } catch {
        $observation.WallMilliseconds = $timer.ElapsedMilliseconds
        $observation.State = 'probe-process-error'
    } finally {
        if ($started -and -not $process.HasExited) {
            try {
                $process.Kill()
            } catch [InvalidOperationException] {
            }
        }
        $process.Dispose()
    }

    [pscustomobject] $observation
}

Assert-ProbeUrl -Url $ProbeUrl
if ($null -ne $DirectUrl) {
    Assert-ProbeUrl -Url $DirectUrl
    if ($DirectUrl.AbsoluteUri -eq $ProbeUrl.AbsoluteUri) {
        throw 'Choose distinct URLs for the primary and direct probes.'
    }
}

$preflightStage = $Stage -in @('normal', 'upstream-unreachable')
$adapterList = $null
try {
    $adapterList = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
} catch {
    # No adapter list means no tunnel route: the preflight below refuses to probe.
    $adapterList = $null
}
$tunnelAdapters = @()
if ($TunnelInterfaceAlias) {
    if ($null -ne $adapterList) {
        $namedSelection = Select-NamedTunnelAdapter -Adapter $adapterList -Name $TunnelInterfaceAlias
        $tunnelAdapters = @($namedSelection.Tunnel)
        if ($preflightStage) {
            $namedProblem = Format-NamedTunnelProblem $namedSelection
            if ($namedProblem -and -not $AllowDirectWithoutTun) {
                throw "$namedProblem No probe was sent."
            }
        } else {
            # In tun-down and client-down a named tunnel adapter is expected to be gone or down.
            $namedProblem = Format-NamedTunnelProblem $namedSelection -PhysicalOnly
        }
        if ($namedProblem) {
            [Console]::Error.WriteLine("WARNING: $namedProblem These names are not counted as tunnel adapters.")
        }
    }
} elseif ($null -ne $adapterList) {
    $tunnelPattern = '(?i)(?:^|[\s_.-])(?:u?tun\d*|wintun\d*|wireguard|tailscale|sing[-_]?box|mihomo|clash)(?:$|[\s_.-])'
    $tunnelAdapters = @($adapterList | Where-Object {
        $_.Status -eq 'Up' -and "$($_.Name) $($_.InterfaceDescription)" -match $tunnelPattern
    })
}
$tunnelFamilies = @(Get-TunnelRouteFamily -TunnelAdapter $tunnelAdapters)
$familyDecision = Resolve-ProbeAddressFamily -Requested $AddressFamily -Stage $Stage -TunnelFamilies $tunnelFamilies
$tunnelRouteActive = [bool]$familyDecision.TunnelRouteDetected
$probeFamily = [string]$familyDecision.Effective
if ($preflightStage -and -not $tunnelRouteActive -and -not $AllowDirectWithoutTun) {
    $detectedText = if ($tunnelFamilies.Count) { $tunnelFamilies -join ' and ' } else { 'none' }
    throw (
        "No active TUN/tunnel default route was detected for the address family to probe ($AddressFamily; tunnel default routes found: $detectedText). " +
        'Because this script disables curl proxy use (--noproxy "*"), ' +
        'running it with only a System HTTP/SOCKS Proxy would connect directly using your real IP. ' +
        'Enable TUN mode first; if the proxy client''s virtual tunnel adapter was not recognised, name it with -TunnelInterfaceAlias ' +
        '(not Wi-Fi or Ethernet: physical adapters are refused); ' +
        'or pass -AllowDirectWithoutTun if a direct probe is intentional.'
    )
}

$targets = @([pscustomobject] @{ Role = 'primary'; Url = $ProbeUrl })
if ($null -ne $DirectUrl) {
    $targets += [pscustomobject] @{ Role = 'operator-designated-direct'; Url = $DirectUrl }
}

$results = @(
    foreach ($target in $targets) {
        $expectResponse = $Stage -eq 'normal' -or (
            $Stage -eq 'upstream-unreachable' -and $target.Role -eq 'operator-designated-direct'
        )
        $dnsState = Get-DnsCacheState -HostName $target.Url.IdnHost
        $sampledUtc = [DateTime]::UtcNow.ToString('o')
        $probe = Invoke-HTTPSProbe -Url $target.Url -Family $probeFamily
        $hasConnection = $probe.State -in @('https-response', 'tcp-connected-no-https-response')
        if ($expectResponse) {
            $verdict = if ($probe.State -eq 'https-response') { 'observed' } else { 'not-observed' }
        } elseif ($hasConnection) {
            $verdict = 'unexpected-connectivity'
        } elseif ($probe.State -eq 'no-connection-observed') {
            # With TUN off, a fake-ip address from the cache is unreachable whether or not a kill
            # switch blocks anything, so that "no connection" is not evidence of a block.
            $fakeIpOnly = $Stage -in @('tun-down', 'client-down') -and $dnsState.FakeIpOnly
            $verdict = if ($fakeIpOnly) { 'inconclusive' } else { 'observed' }
        } else {
            $verdict = 'inconclusive'
        }

        [pscustomobject] [ordered] @{
            Stage = $Stage
            SampledUtc = $sampledUtc
            Role = $target.Role
            Host = $target.Url.IdnHost
            AddressFamily = $probeFamily
            DnsCachedBeforeProbe = $dnsState.Cached
            DnsCacheFakeIpOnly = $dnsState.FakeIpOnly
            Expected = if ($expectResponse) { 'https-response' } else { 'no-connection-observed' }
            Observation = $probe.State
            CurlExitCode = $probe.CurlExitCode
            HttpStatus = $probe.HttpStatus
            TcpConnectSeconds = $probe.TcpConnectSeconds
            CurlTotalSeconds = $probe.CurlTotalSeconds
            WallMilliseconds = $probe.WallMilliseconds
            Verdict = $verdict
        }
    }
)

$needsReview = @($results | Where-Object { $_.Verdict -ne 'observed' }).Count -gt 0
$report = [pscustomobject] [ordered] @{
    Stage = $Stage
    TunnelRouteDetected = $tunnelRouteActive
    TunnelRouteFamilies = @($tunnelFamilies)
    TunnelDetection = if ($TunnelInterfaceAlias) { 'operator-named-adapters' } else { 'adapter-name-pattern' }
    RequestedAddressFamily = $AddressFamily
    ProbedAddressFamily = $probeFamily
    DirectRouteProbeIncluded = $null -ne $DirectUrl
    Coverage = 'One curl HEAD attempt per URL with curl proxy use disabled, limited to ProbedAddressFamily (auto means both IPv4 and IPv6). In the normal and upstream-unreachable stages the preflight requires a tunnel default route for that family unless overridden; route metrics and more specific routes on other adapters are not compared. In the tun-down and client-down stages, no connection while the DNS cache held only fake-ip addresses (198.18.0.0/15, fc00::/18) for the host is inconclusive. DNS transport, firewall block attribution, and other applications require separate verification.'
    ObservationsMatchStage = -not $needsReview
    Probes = $results
}

if ($AsJson) {
    $report | ConvertTo-Json -Depth 5
} else {
    $report
}
if ($needsReview) { exit 2 }
exit 0
