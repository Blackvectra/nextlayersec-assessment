#
# NLS.Reporting.psm1
# NextLayerSec Assessment Framework -- Reporting Module
# Generates markdown assessment summary and exceptions list
#
# Author:  NextLayerSec
# Version: 1.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Publish-NLSAssessmentSummary {
    <#
    .SYNOPSIS
        Generates the assessment summary markdown report.
    .DESCRIPTION
        Produces a structured markdown document containing:
        - Assessment metadata
        - Executive summary with finding counts by severity
        - Coverage map
        - Findings organized by control family and severity
        - Exceptions encountered during collection
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ScoredResults,

        [Parameter(Mandatory = $true)]
        [hashtable]$Metadata,

        [Parameter(Mandatory = $true)]
        [hashtable]$Coverage,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [bool]$Redact = $false
    )

    $findings = $ScoredResults.Findings
    $summary  = $ScoredResults.Summary
    $sb       = [System.Text.StringBuilder]::new()

    # ── Header ───────────────────────────────────────────────
    [void]$sb.AppendLine('# NextLayerSec M365 Security Assessment')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> Read-only assessment. No tenant configuration changes were made.')
    [void]$sb.AppendLine('> Missing telemetry is NOT equivalent to missing policy.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── Metadata ─────────────────────────────────────────────
    [void]$sb.AppendLine('## Assessment Metadata')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("| Field | Value |")
    [void]$sb.AppendLine("|---|---|")
    [void]$sb.AppendLine("| Execution Time (UTC) | $($Metadata.ExecutionTimeUTC) |")
    [void]$sb.AppendLine("| Operator | $($Metadata.AuthContext) |")
    [void]$sb.AppendLine("| EXO Module Version | $($Metadata.ModuleVersions.ExchangeOnlineManagement) |")
    [void]$sb.AppendLine("| Graph Module Version | $($Metadata.ModuleVersions.MicrosoftGraphAuthentication) |")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── Executive Summary ────────────────────────────────────
    [void]$sb.AppendLine('## Executive Summary')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| State | Count |')
    [void]$sb.AppendLine('|---|:---:|')
    [void]$sb.AppendLine("| Gap | $($summary.Gap) |")
    [void]$sb.AppendLine("| Partial | $($summary.Partial) |")
    [void]$sb.AppendLine("| Satisfied | $($summary.Satisfied) |")
    [void]$sb.AppendLine("| **Total Checks** | **$($summary.Total)** |")
    [void]$sb.AppendLine('')

    if ($summary.Gap -gt 0) {
        [void]$sb.AppendLine("> **$($summary.Gap) gap(s) identified. Review findings below for remediation steps.**")
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── Coverage Map ─────────────────────────────────────────
    [void]$sb.AppendLine('## Collection Coverage')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Control Family | Status | Notes |')
    [void]$sb.AppendLine('|---|:---:|---|')

    foreach ($key in $Coverage.Keys) {
        $entry = $Coverage[$key]
        $statusIcon = switch ($entry.Status) {
            'Collected'    { 'Collected' }
            'Partial'      { 'Partial' }
            'NotCollected' { 'Not Collected' }
            'Unsupported'  { 'Unsupported' }
            default        { $entry.Status }
        }
        $reason = if ($entry.Reason) { $entry.Reason } else { '' }
        [void]$sb.AppendLine("| $key | $statusIcon | $reason |")
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── Findings by Severity ─────────────────────────────────
    [void]$sb.AppendLine('## Findings')
    [void]$sb.AppendLine('')

    $severityOrder = @('Critical', 'High', 'Medium', 'Low', 'Pass')

    foreach ($sev in $severityOrder) {
        $sevFindings = $findings | Where-Object { $_.Severity -eq $sev }
        if (-not $sevFindings) { continue }

        [void]$sb.AppendLine("### $sev")
        [void]$sb.AppendLine('')

        # Group by Category property
        $categories = $sevFindings | Group-Object -Property Category
        foreach ($category in $categories) {
            [void]$sb.AppendLine("#### $($category.Name)")
            [void]$sb.AppendLine('')

            foreach ($finding in $category.Group) {
                # Use Title property from state-aware scoring engine
                [void]$sb.AppendLine("**$($finding.Title)**")
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine($finding.Detail)

                # Inject framework citations if present
                $frameworks = @()
                if ($finding.NIST_SP800_53_r5) { $frameworks += "**NIST:** $($finding.NIST_SP800_53_r5)" }
                if ($finding.CIS_v8_1)         { $frameworks += "**CIS:** $($finding.CIS_v8_1)" }
                if ($finding.HIPAA_Current)    { $frameworks += "**HIPAA (Current):** $($finding.HIPAA_Current)" }
                if ($finding.HIPAA_Proposed)   { $frameworks += "**HIPAA (Proposed):** $($finding.HIPAA_Proposed)" }

                if ($frameworks.Count -gt 0) {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine('> *Frameworks: ' + ($frameworks -join ' | ') + '*')
                }

                if ($finding.Remediation -and $sev -ne 'Pass') {
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine("*Remediation:* $($finding.Remediation)")
                }
                [void]$sb.AppendLine('')
            }
        }
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    # ── Footer ───────────────────────────────────────────────
    [void]$sb.AppendLine('*Assessment performed by NextLayerSec -- nextlayersec.io*')
    [void]$sb.AppendLine('*Read-only instrument. Results reflect visible telemetry at time of assessment.*')

    # Write output
    Export-NLSSafeMarkdown -Content $sb.ToString() -OutPath $OutputPath -Redact $Redact

    Write-Host "  [+] Assessment summary written to: $OutputPath" -ForegroundColor Green
}

function Publish-NLSExceptionsList {
    <#
    .SYNOPSIS
        Generates the exceptions markdown report.
    .DESCRIPTION
        Documents all non-fatal exceptions encountered during collection.
        Helps analysts distinguish between controls that passed, controls
        that failed, and controls that could not be assessed due to
        permissions, licensing, or API errors.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [array]$Exceptions = @(),

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [bool]$Redact = $false
    )

    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.AppendLine('# NextLayerSec Assessment -- Collection Exceptions')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('> Exceptions are non-fatal errors encountered during data collection.')
    [void]$sb.AppendLine('> An exception does not mean a control failed -- it means the control could not be assessed.')
    [void]$sb.AppendLine('> Review each exception to determine whether a permissions or licensing gap exists.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')

    if ($Exceptions.Count -eq 0) {
        [void]$sb.AppendLine('No exceptions encountered during collection.')
    } else {
        [void]$sb.AppendLine("**Total exceptions: $($Exceptions.Count)**")
        [void]$sb.AppendLine('')

        foreach ($ex in $Exceptions) {
            [void]$sb.AppendLine("### $($ex.Source)")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Time (UTC):** $($ex.Timestamp)")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Message:** $($ex.Message)")
            [void]$sb.AppendLine('')
            if ($ex.ErrorDetails) {
                [void]$sb.AppendLine('**Error Details:**')
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('```')
                [void]$sb.AppendLine($ex.ErrorDetails)
                [void]$sb.AppendLine('```')
                [void]$sb.AppendLine('')
            }
        }
    }

    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('*NextLayerSec -- nextlayersec.io*')

    Export-NLSSafeMarkdown -Content $sb.ToString() -OutPath $OutputPath -Redact $Redact

    Write-Host "  [+] Exceptions list written to: $OutputPath" -ForegroundColor Green
}

Export-ModuleMember -Function Publish-NLSAssessmentSummary, Publish-NLSExceptionsList
