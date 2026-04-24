#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    NextLayerSec Control-Plane Assessor
    Read-only M365 security assessment instrument.

.DESCRIPTION
    Invoke-NLSAssessment is a strictly read-only assessment tool.
    It connects to Exchange Online and Microsoft Graph, collects
    security policy configuration and sign-in telemetry, scores
    findings against the NextLayerSec baseline, and produces a
    structured markdown assessment report.

    No tenant configuration changes are made at any point.

    Execution modes:
      -Quick        Skips sign-in log telemetry collection. Faster run.
      -Full         Full collection including CA telemetry (default).
      -NoTelemetry  Alias for -Quick. Explicit operator intent.
      -RedactSensitiveData  Scrubs UPNs, GUIDs, and IPs from output artifacts.

.PARAMETER UserPrincipalName
    Admin UPN used to authenticate to Exchange Online and Microsoft Graph.

.PARAMETER SkipConnect
    Skip connection step if already connected to Exchange Online and Graph.

.PARAMETER Quick
    Run inventory-only mode. Skips sign-in log telemetry.

.PARAMETER NoTelemetry
    Explicitly skip telemetry collection. Same as -Quick.

.PARAMETER NoGraph
    Skip Microsoft Graph entirely. Runs Exchange Online checks only.
    No Graph modules required. No browser consent prompt.
    Best for quick tenant assessments or environments where Graph access
    is not available. Conditional Access checks will be marked NotCollected.

.PARAMETER NIST
    Include NIST SP 800-53 Rev 5 citations in assessment output.
    Scoring engine defaults to NIST when no framework flag is passed.

.PARAMETER CIS
    Include CIS Controls v8.1 citations in assessment output.

.PARAMETER HIPAA
    Include HIPAA Security Rule current enforceable rule citations (45 CFR 164.312).

.PARAMETER HIPAAProposed
    Include HIPAA NPRM December 2024 proposed rule citations.
    Use alongside -HIPAA to produce a dual-state gap analysis showing
    current compliance posture and exposure against the incoming mandatory standard.
    Expected final rule: May 2026.

.PARAMETER RedactSensitiveData
    Scrub UPNs, GUIDs, and IP addresses from all output files.
    Use when sharing artifacts externally or with clients.

.EXAMPLE
    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com

.EXAMPLE
    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph

.EXAMPLE
    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -Quick -RedactSensitiveData

.EXAMPLE
    .\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph -RedactSensitiveData

.EXAMPLE
    .\Invoke-NLSAssessment.ps1 -SkipConnect -NoTelemetry

.NOTES
    Author:   NextLayerSec
    Version:  1.2.0 -- Framework switches wired: -NIST, -CIS, -HIPAA, -HIPAAProposed
    Requires: ExchangeOnlineManagement (always)
              Microsoft.Graph.Authentication (Full/Quick mode only)
              Microsoft.Graph.Identity.SignIns (Full mode only)
    License:  CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/

    Graph scopes required (when not using -NoGraph):
      Policy.Read.ConditionalAccess
      AuditLog.Read.All (Full mode only)
      Directory.Read.All
#>

[CmdletBinding(DefaultParameterSetName = 'Full')]
param (
    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [switch]$SkipConnect,

    [Parameter(ParameterSetName = 'Quick')]
    [switch]$Quick,

    [Parameter(ParameterSetName = 'Full')]
    [switch]$Full,

    [Parameter(Mandatory = $false)]
    [switch]$NoTelemetry,

    [Parameter(Mandatory = $false)]
    [switch]$NoGraph,

    # ── Framework routing flags ───────────────────────────────
    # Pass one or more to include framework citations in output.
    # Scoring engine defaults to NIST when no framework flag is passed.
    [Parameter(Mandatory = $false)]
    [switch]$NIST,

    [Parameter(Mandatory = $false)]
    [switch]$CIS,

    [Parameter(Mandatory = $false)]
    [switch]$HIPAA,

    [Parameter(Mandatory = $false)]
    [switch]$HIPAAProposed,
    # ─────────────────────────────────────────────────────────

    [Parameter(Mandatory = $false)]
    [switch]$RedactSensitiveData,

    # ── v2 flags (stubbed) ────────────────────────────────────
    [Parameter(Mandatory = $false)]
    [switch]$OpenReport    # v2 -- auto-open AssessmentSummary.md on completion
    # ─────────────────────────────────────────────────────────
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ─────────────────────────────────────────────
# Hard Runtime Safeguard Banner
# ─────────────────────────────────────────────

Write-Host ''
Write-Host '================================================================' -ForegroundColor DarkRed
Write-Host ' READ-ONLY ASSESSMENT INSTRUMENT' -ForegroundColor Red
Write-Host ' - No tenant configuration changes will be made.' -ForegroundColor Gray
Write-Host ' - Results depend on RBAC, licensing, and API visibility.' -ForegroundColor Gray
Write-Host ' - Missing telemetry is NOT equivalent to missing policy.' -ForegroundColor Gray
Write-Host ' - Do not run against production tenants without authorization.' -ForegroundColor Gray
Write-Host '================================================================' -ForegroundColor DarkRed
Write-Host ''

# ─────────────────────────────────────────────
# Operator Mode Resolution
# ─────────────────────────────────────────────

$runTelemetry = -not ($Quick -or $NoTelemetry -or $NoGraph)
$runGraph     = -not $NoGraph
$runRedaction = [bool]$RedactSensitiveData

Write-Host '[*] Execution Mode: ' -NoNewline -ForegroundColor Cyan
if ($NoGraph) {
    Write-Host 'EXCHANGE ONLY (No Graph) ' -NoNewline -ForegroundColor Yellow
} elseif ($Quick -or $NoTelemetry) {
    Write-Host 'QUICK (No Telemetry) ' -NoNewline -ForegroundColor Yellow
} else {
    Write-Host 'FULL ' -NoNewline -ForegroundColor Green
}
if ($runRedaction) { Write-Host '| REDACTED OUTPUT ' -NoNewline -ForegroundColor Magenta }
Write-Host ''

Write-Host '[*] Frameworks: ' -NoNewline -ForegroundColor Cyan
$activeFrameworks = @()
if (-not ($NIST -or $CIS -or $HIPAA -or $HIPAAProposed)) {
    $activeFrameworks += 'NIST (default)'
} else {
    if ($NIST)          { $activeFrameworks += 'NIST' }
    if ($CIS)           { $activeFrameworks += 'CIS' }
    if ($HIPAA)         { $activeFrameworks += 'HIPAA Current' }
    if ($HIPAAProposed) { $activeFrameworks += 'HIPAA Proposed' }
}
Write-Host ($activeFrameworks -join ', ') -ForegroundColor White
Write-Host ''

# ─────────────────────────────────────────────
# Prerequisite Validation
# ─────────────────────────────────────────────

Write-Host '[-] Validating prerequisites...' -ForegroundColor DarkGray

$requiredModules = @('ExchangeOnlineManagement')
if ($runGraph) {
    $requiredModules += 'Microsoft.Graph.Authentication'
    if ($runTelemetry) {
        $requiredModules += 'Microsoft.Graph.Identity.SignIns'
    }
}

$missingModules = foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) { $mod }
}

if ($missingModules) {
    Write-Host "[!] Missing required modules: $($missingModules -join ', ')" -ForegroundColor Red
    Write-Host ''
    Write-Host '    Install missing modules with:' -ForegroundColor Gray
    foreach ($mod in $missingModules) {
        Write-Host "    Install-Module -Name $mod -Scope CurrentUser -Force" -ForegroundColor Gray
    }
    Write-Host ''
    exit 1
}

Write-Host '  [+] All required modules present' -ForegroundColor Green

# ─────────────────────────────────────────────
# Module Loading
# ─────────────────────────────────────────────

$scriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$modulesDir = Join-Path $scriptDir 'Modules'

if (-not (Test-Path $modulesDir)) {
    Write-Host "[!] Modules directory not found at: $modulesDir" -ForegroundColor Red
    exit 1
}

$moduleFiles = Get-ChildItem -Path $modulesDir -Filter '*.psm1' -ErrorAction Stop
if ($moduleFiles.Count -eq 0) {
    Write-Host "[!] No .psm1 files found in Modules directory" -ForegroundColor Red
    exit 1
}

foreach ($mod in $moduleFiles) {
    try {
        Import-Module $mod.FullName -Force -ErrorAction Stop
        Write-Host "  [+] Loaded: $($mod.Name)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [!] Failed to load module $($mod.Name): $_" -ForegroundColor Red
        exit 1
    }
}

# ─────────────────────────────────────────────
# Output Directory Setup
# ─────────────────────────────────────────────

$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$outDir    = Join-Path $scriptDir "output\$timestamp"

try {
    New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    Write-Host "  [+] Output directory: $outDir" -ForegroundColor DarkGray
} catch {
    Write-Host "[!] Failed to create output directory: $_" -ForegroundColor Red
    exit 1
}

# ─────────────────────────────────────────────
# Connection Bootstrap
# ─────────────────────────────────────────────

if (-not $SkipConnect) {
    $upn = if ($UserPrincipalName) { $UserPrincipalName } else { Read-Host 'Enter Admin UPN' }

    Write-Host ''
    Write-Host '[-] Establishing read-only connections...' -ForegroundColor DarkGray

    try {
        Connect-ExchangeOnline -UserPrincipalName $upn -ShowBanner:$false -ErrorAction Stop
        Write-Host '  [+] Exchange Online connected' -ForegroundColor Green
    } catch {
        Write-Host "  [!] Exchange Online connection failed: $_" -ForegroundColor Red
        exit 1
    }

    if ($runGraph) {
        # Minimal scoped Graph permissions
        $graphScopes = @(
            'Policy.Read.ConditionalAccess',
            'Directory.Read.All'
        )
        if ($runTelemetry) {
            $graphScopes += 'AuditLog.Read.All'
        }

        try {
            Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop
            Write-Host '  [+] Microsoft Graph connected' -ForegroundColor Green
        } catch {
            Write-Host "  [!] Microsoft Graph connection failed: $_" -ForegroundColor Red
            Write-Host '      Conditional Access checks will be unavailable.' -ForegroundColor Yellow
            # Non-fatal -- continue without Graph
        }
    } else {
        Write-Host '  [!] Graph skipped (-NoGraph). Exchange Online only.' -ForegroundColor Yellow
    }
}

Write-Host ''

# ─────────────────────────────────────────────
# Data Collection
# ─────────────────────────────────────────────

Write-Host '[-] Collecting Exchange Online policies...' -ForegroundColor DarkGray
$exchangeResults = Get-NLSExchangePolicies -Redact $runRedaction

$caResults = @{}
$caTelemetryResults = @{}

if ($runGraph) {
    Write-Host '[-] Collecting Conditional Access policies...' -ForegroundColor DarkGray
    $caResults = Get-NLSConditionalAccessPolicies -Redact $runRedaction

    if ($runTelemetry) {
        Write-Host '[-] Collecting Conditional Access telemetry (sign-in logs)...' -ForegroundColor DarkGray
        $caTelemetryResults = Get-NLSConditionalAccessTelemetry -Redact $runRedaction
    } else {
        Register-NLSCoverage -ControlFamily 'ConditionalAccessTelemetry' `
            -Status 'NotCollected' `
            -Reason 'Operator specified -Quick or -NoTelemetry'
        Write-Host '  [!] Telemetry collection skipped (Quick/NoTelemetry mode)' -ForegroundColor Yellow
    }
} else {
    Register-NLSCoverage -ControlFamily 'ConditionalAccess' `
        -Status 'NotCollected' `
        -Reason 'Operator specified -NoGraph. Run without -NoGraph to include CA policy checks.'
    Register-NLSCoverage -ControlFamily 'ConditionalAccessTelemetry' `
        -Status 'NotCollected' `
        -Reason 'Operator specified -NoGraph.'
    Write-Host '  [!] Conditional Access checks skipped (-NoGraph mode)' -ForegroundColor Yellow
}

Write-Host '[-] Collecting metadata...' -ForegroundColor DarkGray
$metadata = Get-NLSMetadata -Redact $runRedaction

Write-Host ''

# ─────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────

Write-Host '[-] Applying scoring model...' -ForegroundColor DarkGray

$allResults = @{
    ExchangePolicies            = $exchangeResults
    ConditionalAccess           = $caResults
    ConditionalAccessTelemetry  = $caTelemetryResults
}

$scoringParams = @{
    Results = $allResults
    Redact  = $runRedaction
}

# Pass framework switches if specified by operator
# Scoring engine defaults -NIST to $true -- only override when explicitly passed
if ($PSBoundParameters.ContainsKey('NIST'))          { $scoringParams.NIST          = $NIST.IsPresent }
if ($PSBoundParameters.ContainsKey('CIS'))           { $scoringParams.CIS           = $CIS.IsPresent }
if ($PSBoundParameters.ContainsKey('HIPAA'))         { $scoringParams.HIPAA         = $HIPAA.IsPresent }
if ($PSBoundParameters.ContainsKey('HIPAAProposed')) { $scoringParams.HIPAAProposed = $HIPAAProposed.IsPresent }

$scoredResults = Invoke-NLSScoringModel @scoringParams

Write-Host ''

# ─────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────

Write-Host '[-] Generating assessment artifacts...' -ForegroundColor DarkGray

$summaryPath    = Join-Path $outDir 'AssessmentSummary.md'
$exceptionsPath = Join-Path $outDir 'Exceptions.md'

Publish-NLSAssessmentSummary `
    -ScoredResults $scoredResults `
    -Metadata $metadata `
    -Coverage (Get-NLSCoverageMap) `
    -OutputPath $summaryPath `
    -Redact $runRedaction

$exceptions = Get-NLSExceptions
if ($null -eq $exceptions) { $exceptions = @() }
Publish-NLSExceptionsList `
    -Exceptions $exceptions `
    -OutputPath $exceptionsPath `
    -Redact $runRedaction

# ─────────────────────────────────────────────
# Summary Output
# ─────────────────────────────────────────────

$s = $scoredResults.Summary

Write-Host ''
Write-Host '================================================================' -ForegroundColor DarkGray
Write-Host '  Assessment Complete' -ForegroundColor White
Write-Host '================================================================' -ForegroundColor DarkGray
Write-Host "  Satisfied  $($s.Satisfied)" -ForegroundColor Green
Write-Host "  Partial    $($s.Partial)"   -ForegroundColor $(if ($s.Partial -gt 0)   { 'Yellow' } else { 'Green' })
Write-Host "  Gap        $($s.Gap)"       -ForegroundColor $(if ($s.Gap -gt 0)       { 'Red' }    else { 'Green' })
Write-Host "  Total      $($s.Total)"     -ForegroundColor White
Write-Host ''
Write-Host "  Artifacts: $outDir" -ForegroundColor Cyan
Write-Host ''

# Auto-open report if -OpenReport flag passed
if ($OpenReport) {
    $reportFile = Join-Path $outDir 'AssessmentSummary.md'
    if (Test-Path $reportFile) {
        Write-Host '[-] Opening assessment report...' -ForegroundColor DarkGray
        Start-Process $reportFile
    }
}

# ─────────────────────────────────────────────
# Disconnect
# ─────────────────────────────────────────────

if (-not $SkipConnect) {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        if ($runGraph) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
        Write-Host '[-] Sessions disconnected.' -ForegroundColor DarkGray
    } catch {
        # Sessions may have already closed
    }
}

Write-Host ''
