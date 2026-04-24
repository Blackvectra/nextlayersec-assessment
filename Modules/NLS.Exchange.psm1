#
# NLS.Exchange.psm1
# NextLayerSec Assessment Framework -- Exchange Online Collector
# Collects Exchange Online security policy configuration read-only
#
# Author:  NextLayerSec
# Version: 1.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Get-NLSExchangePolicies {
    <#
    .SYNOPSIS
        Collects Exchange Online security policy configuration.
    .DESCRIPTION
        Read-only collection of authentication policies, transport config,
        remote domain settings, CAS mailbox protocols, mailbox auditing,
        outbound spam policies, Defender for Office 365 policies, and DKIM.
        All data returned as an ordered hashtable for scoring and reporting.
    #>
    param(
        [bool]$Redact = $false
    )

    $results = [ordered]@{}

    # ── Authentication Policies ──────────────────────────────
    try {
        $authPolicies = Get-AuthenticationPolicy -ErrorAction Stop
        $orgConfig    = Get-OrganizationConfig -ErrorAction Stop

        $policyResults = foreach ($policy in $authPolicies) {
            $basicAuthProps = $policy | Select-Object -Property AllowBasicAuth* |
                Select-Object -ExpandProperty PSObject |
                Select-Object -ExpandProperty Properties

            $failures = $basicAuthProps | Where-Object { $_.Value -eq $true }

            [ordered]@{
                PolicyName    = $policy.Name
                AllFailures   = if ($failures) { $failures.Name -join ', ' } else { $null }
                FullyHardened = ($null -eq $failures -or $failures.Count -eq 0)
            }
        }

        $results['AuthenticationPolicies'] = [ordered]@{
            Policies           = @($policyResults)
            OrgDefaultPolicy   = $orgConfig.DefaultAuthenticationPolicy
            OrgDefaultSet      = ($null -ne $orgConfig.DefaultAuthenticationPolicy -and $orgConfig.DefaultAuthenticationPolicy -ne '')
        }

        Register-NLSCoverage -ControlFamily 'AuthenticationPolicies' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:AuthPolicy' -Message 'Failed to retrieve authentication policies' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'AuthenticationPolicies' -Status 'Partial' -Reason $_.Exception.Message
        $results['AuthenticationPolicies'] = $null
    }

    # ── SMTP Client Auth ─────────────────────────────────────
    try {
        $transportConfig = Get-TransportConfig -ErrorAction Stop
        $results['SmtpClientAuth'] = [ordered]@{
            Disabled = $transportConfig.SmtpClientAuthenticationDisabled
        }
        Register-NLSCoverage -ControlFamily 'SmtpClientAuth' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:TransportConfig' -Message 'Failed to retrieve transport config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'SmtpClientAuth' -Status 'Partial' -Reason $_.Exception.Message
        $results['SmtpClientAuth'] = $null
    }

    # ── External Forwarding ──────────────────────────────────
    try {
        $remoteDomain = Get-RemoteDomain Default -ErrorAction Stop
        $forwardingMailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop |
            Where-Object { $_.ForwardingAddress -ne $null -or $_.ForwardingSmtpAddress -ne $null }

        $results['ExternalForwarding'] = [ordered]@{
            AutoForwardDisabled      = ($remoteDomain.AutoForwardEnabled -eq $false)
            MailboxesWithForwarding  = $forwardingMailboxes.Count
            ForwardingMailboxList    = if ($forwardingMailboxes.Count -gt 0) {
                @($forwardingMailboxes | ForEach-Object {
                    $addr = if ($Redact) { '[REDACTED_UPN]' } else { $_.UserPrincipalName }
                    $fwd  = if ($Redact) { '[REDACTED]' } else { "$($_.ForwardingSmtpAddress)$($_.ForwardingAddress)" }
                    "$addr -> $fwd"
                })
            } else { @() }
        }
        Register-NLSCoverage -ControlFamily 'ExternalForwarding' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:Forwarding' -Message 'Failed to retrieve forwarding config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'ExternalForwarding' -Status 'Partial' -Reason $_.Exception.Message
        $results['ExternalForwarding'] = $null
    }

    # ── Mailbox Protocol Hardening ───────────────────────────
    try {
        $casMailboxes = Get-CasMailbox -ResultSize Unlimited -ErrorAction Stop
        $results['MailboxProtocols'] = [ordered]@{
            TotalMailboxes   = $casMailboxes.Count
            PopEnabledCount  = ($casMailboxes | Where-Object { $_.PopEnabled }).Count
            ImapEnabledCount = ($casMailboxes | Where-Object { $_.ImapEnabled }).Count
        }
        Register-NLSCoverage -ControlFamily 'MailboxProtocols' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:CasMailbox' -Message 'Failed to retrieve CAS mailbox config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'MailboxProtocols' -Status 'Partial' -Reason $_.Exception.Message
        $results['MailboxProtocols'] = $null
    }

    # ── Mailbox Auditing ─────────────────────────────────────
    try {
        $adminAuditConfig = Get-AdminAuditLogConfig -ErrorAction Stop
        $mailboxes        = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop

        $auditDisabled   = ($mailboxes | Where-Object { $_.AuditEnabled -eq $false }).Count
        $shortRetention  = ($mailboxes | Where-Object { $_.AuditLogAgeLimit -lt [TimeSpan]::FromDays(90) }).Count

        $results['MailboxAuditing'] = [ordered]@{
            UnifiedAuditLogEnabled   = $adminAuditConfig.UnifiedAuditLogIngestionEnabled
            MailboxesAuditDisabled   = $auditDisabled
            MailboxesShortRetention  = $shortRetention
        }
        Register-NLSCoverage -ControlFamily 'MailboxAuditing' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:Auditing' -Message 'Failed to retrieve audit config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'MailboxAuditing' -Status 'Partial' -Reason $_.Exception.Message
        $results['MailboxAuditing'] = $null
    }

    # ── Outbound Spam ────────────────────────────────────────
    try {
        $spamPolicy = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop |
            Where-Object { $_.IsDefault -eq $true }
        if (-not $spamPolicy) {
            $spamPolicy = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop |
                Select-Object -First 1
        }

        $results['OutboundSpam'] = [ordered]@{
            NotifyEnabled    = $spamPolicy.NotifyOutboundSpam
            NotifyRecipients = if ($Redact) {
                if ($spamPolicy.NotifyOutboundSpamRecipients) { '[REDACTED]' } else { $null }
            } else {
                $spamPolicy.NotifyOutboundSpamRecipients -join ', '
            }
        }
        Register-NLSCoverage -ControlFamily 'OutboundSpam' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:OutboundSpam' -Message 'Failed to retrieve outbound spam policy' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'OutboundSpam' -Status 'Partial' -Reason $_.Exception.Message
        $results['OutboundSpam'] = $null
    }

    # ── Defender for Office 365 ──────────────────────────────
    try {
        $safeAttach  = Get-SafeAttachmentPolicy -ErrorAction Stop
        $safeLinks   = Get-SafeLinksPolicy -ErrorAction Stop
        $antiPhish   = Get-AntiPhishPolicy -ErrorAction Stop
        $contentFilt = Get-HostedContentFilterPolicy -ErrorAction Stop
        $atpPolicy   = Get-AtpPolicyForO365 -ErrorAction Stop

        $results['DefenderO365'] = [ordered]@{
            SafeAttachmentBlockEnabled = ($safeAttach | Where-Object { $_.Action -eq 'Block' -and $_.Enable -eq $true }).Count -gt 0
            SafeLinksEnabled           = ($safeLinks | Where-Object { $_.IsEnabled -eq $true -or $_.Enabled -eq $true }).Count -gt 0
            AntiPhishEnabled           = ($antiPhish | Where-Object { $_.Enabled -eq $true }).Count -gt 0
            MailboxIntelligenceEnabled = ($antiPhish | Where-Object { $_.EnableMailboxIntelligence -eq $true }).Count -gt 0
            ZapSpamEnabled             = ($contentFilt | Where-Object { $_.SpamZapEnabled -eq $true }).Count -gt 0
            ZapPhishEnabled            = ($contentFilt | Where-Object { $_.PhishZapEnabled -eq $true }).Count -gt 0
            ATPForSPOTeamsODB          = $atpPolicy.EnableATPForSPOTeamsODB
        }
        Register-NLSCoverage -ControlFamily 'DefenderO365' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:Defender' -Message 'Failed to retrieve Defender for O365 policies' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'DefenderO365' -Status 'Partial' -Reason $_.Exception.Message
        $results['DefenderO365'] = $null
    }

    # ── DKIM ─────────────────────────────────────────────────
    try {
        $dkimConfigs = Get-DkimSigningConfig -ErrorAction Stop
        $results['DKIM'] = [ordered]@{
            Domains = @($dkimConfigs | ForEach-Object {
                [ordered]@{
                    Domain  = $_.Domain
                    Enabled = $_.Enabled
                    Status  = $_.Status
                }
            })
        }
        Register-NLSCoverage -ControlFamily 'DKIM' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:DKIM' -Message 'Failed to retrieve DKIM config' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'DKIM' -Status 'Partial' -Reason $_.Exception.Message
        $results['DKIM'] = $null
    }

    # ── DNSSEC ───────────────────────────────────────────────
    try {
        $acceptedDomains = Get-AcceptedDomain -ErrorAction Stop
        $dnssecResults = foreach ($domain in $acceptedDomains) {
            try {
                $dnssec = Get-DnssecStatusForVerifiedDomain -DomainName $domain.DomainName -ErrorAction Stop
                [ordered]@{
                    Domain  = $domain.DomainName
                    Enabled = ($dnssec.DnssecFeatureStatus -eq 'Enabled')
                    Status  = $dnssec.DnssecFeatureStatus
                }
            } catch {
                Register-NLSException -Source 'Get-NLSExchangePolicies:DNSSEC' -Message "DNSSEC check failed for $($domain.DomainName)" -ErrorDetails $_.Exception.Message
                [ordered]@{
                    Domain  = $domain.DomainName
                    Enabled = $false
                    Status  = 'CheckFailed'
                }
            }
        }
        $results['DNSSEC'] = [ordered]@{ Domains = @($dnssecResults) }
        Register-NLSCoverage -ControlFamily 'DNSSEC' -Status 'Collected'
    } catch {
        Register-NLSException -Source 'Get-NLSExchangePolicies:DNSSEC' -Message 'Failed to retrieve accepted domains for DNSSEC check' -ErrorDetails $_.Exception.Message
        Register-NLSCoverage -ControlFamily 'DNSSEC' -Status 'Partial' -Reason $_.Exception.Message
        $results['DNSSEC'] = $null
    }

    return $results
}

Export-ModuleMember -Function Get-NLSExchangePolicies
