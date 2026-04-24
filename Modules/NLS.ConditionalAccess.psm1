#
# NLS.ConditionalAccess.psm1
# NextLayerSec Assessment Framework -- Conditional Access Collector
# Collects CA policies and sign-in log telemetry via Microsoft Graph
#
# Author:  NextLayerSec
# Version: 1.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Get-NLSConditionalAccessPolicies {
    <#
    .SYNOPSIS
        Collects Conditional Access policy configuration via Microsoft Graph.
    .DESCRIPTION
        Read-only collection of all CA policies including state, conditions,
        grant controls, and session controls. Flags high-risk gaps including
        report-only policies, missing MFA grant controls, and legacy auth
        exclusions.
    #>
    param(
        [bool]$Redact = $false
    )

    $results = [ordered]@{}

    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

        $policyResults = foreach ($policy in $policies) {
            # Determine MFA enforcement
            $hasMfaGrant = $false
            if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls) {
                $hasMfaGrant = $policy.GrantControls.BuiltInControls -contains 'mfa'
            }

            # Detect legacy auth targeting
            $targetsLegacyAuth = $false
            if ($policy.Conditions.ClientAppTypes) {
                $legacyTypes = @('exchangeActiveSync', 'other')
                $targetsLegacyAuth = ($policy.Conditions.ClientAppTypes | Where-Object { $legacyTypes -contains $_ }).Count -gt 0
            }

            # Detect all users scope
            $targetsAllUsers = $false
            if ($policy.Conditions.Users.IncludeUsers) {
                $targetsAllUsers = $policy.Conditions.Users.IncludeUsers -contains 'All'
            }

            [ordered]@{
                DisplayName        = $policy.DisplayName
                State              = $policy.State
                IsEnabled          = ($policy.State -eq 'enabled')
                IsReportOnly       = ($policy.State -eq 'enabledForReportingButNotEnforced')
                HasMfaGrant        = $hasMfaGrant
                TargetsAllUsers    = $targetsAllUsers
                TargetsLegacyAuth  = $targetsLegacyAuth
                GrantControls      = if ($policy.GrantControls) { $policy.GrantControls.BuiltInControls -join ', ' } else { 'None' }
                Operator           = if ($policy.GrantControls) { $policy.GrantControls.Operator } else { $null }
            }
        }

        # Summary counts
        $enabledCount    = ($policyResults | Where-Object { $_.IsEnabled }).Count
        $reportOnlyCount = ($policyResults | Where-Object { $_.IsReportOnly }).Count
        $disabledCount   = ($policyResults | Where-Object { -not $_.IsEnabled -and -not $_.IsReportOnly }).Count
        $mfaPolicies     = ($policyResults | Where-Object { $_.HasMfaGrant -and $_.IsEnabled }).Count
        $legacyBlocking  = ($policyResults | Where-Object { $_.TargetsLegacyAuth -and $_.IsEnabled }).Count

        $results['ConditionalAccess'] = [ordered]@{
            TotalPolicies       = $policies.Count
            EnabledCount        = $enabledCount
            ReportOnlyCount     = $reportOnlyCount
            DisabledCount       = $disabledCount
            MfaEnforcingCount   = $mfaPolicies
            LegacyAuthBlocking  = $legacyBlocking
            Policies            = @($policyResults)
        }

        Register-NLSCoverage -ControlFamily 'ConditionalAccess' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSConditionalAccessPolicies' -Message 'Failed to retrieve CA policies from Graph' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'ConditionalAccess' -Status 'Partial' -Reason $_.Exception.Message
        $results['ConditionalAccess'] = $null
    }

    return $results
}

function Get-NLSConditionalAccessTelemetry {
    <#
    .SYNOPSIS
        Collects sign-in log telemetry to surface CA policy hit rates.
    .DESCRIPTION
        Queries the last 48 hours of sign-in logs via Graph API.
        Surfaces failure patterns, MFA challenge rates, and
        legacy authentication sign-in attempts.
        Requires AuditLog.Read.All scope.
    #>
    param(
        [bool]$Redact = $false
    )

    $results = [ordered]@{}

    try {
        # Last 48 hours
        $cutoff = (Get-Date).ToUniversalTime().AddHours(-48).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter = "createdDateTime ge $cutoff"

        $signIns = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop

        # Legacy auth attempts
        $legacyAttempts = $signIns | Where-Object {
            $_.ClientAppUsed -in @('Exchange ActiveSync', 'IMAP4', 'MAPI', 'POP3', 'SMTP', 'Other clients')
        }

        # MFA challenges
        $mfaChallenged = $signIns | Where-Object {
            $_.AuthenticationRequirement -eq 'multiFactorAuthentication'
        }

        # Failures
        $failures = $signIns | Where-Object { $_.Status.ErrorCode -ne 0 }

        $results['ConditionalAccessTelemetry'] = [ordered]@{
            WindowHours          = 48
            TotalSignIns         = $signIns.Count
            LegacyAuthAttempts   = $legacyAttempts.Count
            MfaChallenged        = $mfaChallenged.Count
            FailedSignIns        = $failures.Count
            Note                 = 'Sign-in log data is sampled. Results reflect visible telemetry only.'
        }

        Register-NLSCoverage -ControlFamily 'ConditionalAccessTelemetry' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSConditionalAccessTelemetry' -Message 'Failed to retrieve sign-in logs from Graph' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'ConditionalAccessTelemetry' -Status 'Partial' -Reason $_.Exception.Message
        $results['ConditionalAccessTelemetry'] = $null
    }

    return $results
}

Export-ModuleMember -Function Get-NLSConditionalAccessPolicies, Get-NLSConditionalAccessTelemetry
