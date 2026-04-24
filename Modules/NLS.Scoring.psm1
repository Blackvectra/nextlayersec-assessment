#
# NLS.Scoring.psm1
# NextLayerSec Assessment Framework -- Scoring Engine
#
# Logic only. No compliance data.
# Imports framework mappings from NLS.FrameworkDictionary.psm1 at runtime.
# To update framework citations edit NLS.FrameworkDictionary.psm1 only.
#
# Author:  NextLayerSec
# Version: 1.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

function Invoke-NLSScoringModel {
    <#
    .SYNOPSIS
        Scores collected tenant data and maps findings to compliance frameworks.
    .DESCRIPTION
        Evaluates each control against collected tenant data.
        Determines state (Satisfied / Partial / Gap) per control.
        Maps state to requested framework citations from NLS.FrameworkDictionary.
        Returns structured findings for the reporting module.
    .PARAMETER Results
        Hashtable of collected data from NLS.Exchange and NLS.ConditionalAccess modules.
    .PARAMETER Redact
        Scrub sensitive data from finding output.
    .PARAMETER NIST
        Include NIST SP 800-53 Rev 5 citations. Default true.
    .PARAMETER CIS
        Include CIS Controls v8.1 citations.
    .PARAMETER HIPAA
        Include HIPAA Security Rule current enforceable rule citations.
    .PARAMETER HIPAAProposed
        Include HIPAA NPRM December 2024 proposed rule citations.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Results,

        [bool]$Redact        = $false,
        [bool]$NIST          = $true,
        [bool]$CIS           = $false,
        [bool]$HIPAA         = $false,
        [bool]$HIPAAProposed = $false
    )

    # Verify dictionary is loaded
    $dict = Get-NLSFrameworkDictionary
    if (-not $dict) {
        throw 'NLS.FrameworkDictionary module not loaded. Ensure NLS.FrameworkDictionary.psm1 is in the Modules directory.'
    }

    $findings = [System.Collections.Generic.List[hashtable]]::new()

    # ─────────────────────────────────────────────
    # Helper: Add finding with framework citations
    # ─────────────────────────────────────────────
    function Add-Finding {
        param(
            [string]$ControlId,
            [ValidateSet('Satisfied', 'Partial', 'Gap')]
            [string]$State,
            [string]$Detail,
            [string]$Remediation = ''
        )

        $entry = $dict[$ControlId]
        if (-not $entry) {
            Register-NLSException -Source 'Invoke-NLSScoringModel' `
                -Message "ControlId '$ControlId' not found in framework dictionary" `
                -ErrorDetails 'Check NLS.FrameworkDictionary.psm1 for missing entry'
            return
        }

        $finding = [ordered]@{
            ControlId   = $ControlId
            Title       = $entry.Title
            Category    = $entry.Category
            State       = $State
            Severity    = switch ($State) {
                'Satisfied' { 'Pass' }
                'Partial'   { 'Medium' }
                'Gap'       { 'High' }
            }
            Detail      = $Detail
            Remediation = $Remediation
        }

        # Attach framework citations for requested frameworks
        if ($NIST -and $entry.NIST -and $entry.NIST[$State]) {
            $finding['NIST_SP800_53_r5'] = $entry.NIST[$State].Citation
            $finding['NIST_Requirement'] = $entry.NIST[$State].Requirement
            $finding['NIST_Detail']      = $entry.NIST[$State].Detail
        }
        if ($CIS -and $entry.CIS -and $entry.CIS[$State]) {
            $finding['CIS_v8_1']         = $entry.CIS[$State].Citation
            $finding['CIS_Requirement']  = $entry.CIS[$State].Requirement
            $finding['CIS_Detail']       = $entry.CIS[$State].Detail
        }
        if ($HIPAA -and $entry.HIPAA -and $entry.HIPAA[$State]) {
            $finding['HIPAA_Current']    = $entry.HIPAA[$State].Citation
            $finding['HIPAA_Req']        = $entry.HIPAA[$State].Requirement
            $finding['HIPAA_Detail']     = $entry.HIPAA[$State].Detail
        }
        if ($HIPAAProposed -and $entry.HIPAAProposed -and $entry.HIPAAProposed[$State]) {
            $finding['HIPAA_Proposed']     = $entry.HIPAAProposed[$State].Citation
            $finding['HIPAA_Proposed_Req'] = $entry.HIPAAProposed[$State].Requirement
            $finding['HIPAA_Proposed_Detail'] = $entry.HIPAAProposed[$State].Detail
        }

        $findings.Add($finding)
    }

    # ─────────────────────────────────────────────
    # Authentication Policies
    # ─────────────────────────────────────────────
    $authData = $Results['ExchangePolicies']['AuthenticationPolicies']
    if ($authData) {
        if (-not $authData.OrgDefaultSet) {
            Add-Finding -ControlId 'AdminMFA' -State 'Partial' `
                -Detail 'No organization default authentication policy set. New users may not inherit MFA or legacy auth restrictions.' `
                -Remediation 'Run Set-OrganizationConfig -DefaultAuthenticationPolicy <PolicyName>'
        }
        foreach ($policy in $authData.Policies) {
            if ($policy.FullyHardened) {
                Add-Finding -ControlId 'LegacyAuth' -State 'Satisfied' `
                    -Detail "Policy [$($policy.PolicyName)]: All basic authentication protocols blocked."
            } else {
                Add-Finding -ControlId 'LegacyAuth' -State 'Gap' `
                    -Detail "Policy [$($policy.PolicyName)]: Basic auth still enabled on: $($policy.AllFailures)" `
                    -Remediation 'Set all AllowBasicAuth* parameters to $false via Set-AuthenticationPolicy'
            }
        }
    }

    # ─────────────────────────────────────────────
    # SMTP Client Authentication
    # ─────────────────────────────────────────────
    $smtpData = $Results['ExchangePolicies']['SmtpClientAuth']
    if ($smtpData) {
        if ($smtpData.Disabled) {
            Add-Finding -ControlId 'SmtpClientAuth' -State 'Satisfied' `
                -Detail 'SMTP client authentication disabled tenant-wide.'
        } else {
            Add-Finding -ControlId 'SmtpClientAuth' -State 'Gap' `
                -Detail 'SMTP client authentication is enabled. Legacy relay and credential exposure risk.' `
                -Remediation 'Run Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
        }
    }

    # ─────────────────────────────────────────────
    # External Mail Forwarding
    # ─────────────────────────────────────────────
    $fwdData = $Results['ExchangePolicies']['ExternalForwarding']
    if ($fwdData) {
        if ($fwdData.AutoForwardDisabled -and $fwdData.MailboxesWithForwarding -eq 0) {
            Add-Finding -ControlId 'ExternalForwarding' -State 'Satisfied' `
                -Detail 'External auto-forwarding disabled. No mailboxes with active forwarding addresses.'
        } elseif ($fwdData.AutoForwardDisabled -and $fwdData.MailboxesWithForwarding -gt 0) {
            Add-Finding -ControlId 'ExternalForwarding' -State 'Partial' `
                -Detail "Auto-forward policy disabled but $($fwdData.MailboxesWithForwarding) mailbox(es) have active forwarding addresses." `
                -Remediation 'Audit and remove unauthorized forwarding addresses on affected mailboxes'
        } else {
            Add-Finding -ControlId 'ExternalForwarding' -State 'Gap' `
                -Detail 'External auto-forwarding is enabled. High exfiltration risk.' `
                -Remediation 'Run Set-RemoteDomain Default -AutoForwardEnabled $false'
        }
    }

    # ─────────────────────────────────────────────
    # Mailbox Protocol Hardening
    # ─────────────────────────────────────────────
    $protoData = $Results['ExchangePolicies']['MailboxProtocols']
    if ($protoData) {
        if ($protoData.PopEnabledCount -eq 0) {
            Add-Finding -ControlId 'PopEnabled' -State 'Satisfied' `
                -Detail "POP3 disabled on all $($protoData.TotalMailboxes) mailboxes."
        } else {
            Add-Finding -ControlId 'PopEnabled' -State 'Gap' `
                -Detail "$($protoData.PopEnabledCount) of $($protoData.TotalMailboxes) mailboxes have POP3 enabled." `
                -Remediation 'Run Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -PopEnabled $false'
        }

        if ($protoData.ImapEnabledCount -eq 0) {
            Add-Finding -ControlId 'ImapEnabled' -State 'Satisfied' `
                -Detail "IMAP disabled on all $($protoData.TotalMailboxes) mailboxes."
        } else {
            Add-Finding -ControlId 'ImapEnabled' -State 'Gap' `
                -Detail "$($protoData.ImapEnabledCount) of $($protoData.TotalMailboxes) mailboxes have IMAP enabled." `
                -Remediation 'Run Get-CasMailbox -ResultSize Unlimited | Set-CasMailbox -ImapEnabled $false'
        }
    }

    # ─────────────────────────────────────────────
    # Mailbox Auditing
    # ─────────────────────────────────────────────
    $auditData = $Results['ExchangePolicies']['MailboxAuditing']
    if ($auditData) {
        if ($auditData.UnifiedAuditLogEnabled) {
            Add-Finding -ControlId 'UnifiedAuditLog' -State 'Satisfied' `
                -Detail 'Unified audit logging enabled.'
        } else {
            Add-Finding -ControlId 'UnifiedAuditLog' -State 'Gap' `
                -Detail 'Unified audit logging is disabled.' `
                -Remediation 'Enable via Microsoft Purview compliance portal'
        }

        if ($auditData.MailboxesAuditDisabled -eq 0) {
            Add-Finding -ControlId 'MailboxAudit' -State 'Satisfied' `
                -Detail 'Mailbox auditing enabled on all mailboxes.'
        } elseif ($auditData.MailboxesAuditDisabled -gt 0 -and $auditData.MailboxesAuditDisabled -lt 5) {
            Add-Finding -ControlId 'MailboxAudit' -State 'Partial' `
                -Detail "$($auditData.MailboxesAuditDisabled) mailbox(es) have auditing disabled." `
                -Remediation 'Run Set-Mailbox -Identity <mbx> -AuditEnabled $true for affected mailboxes'
        } else {
            Add-Finding -ControlId 'MailboxAudit' -State 'Gap' `
                -Detail "$($auditData.MailboxesAuditDisabled) mailbox(es) have auditing disabled." `
                -Remediation 'Run Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true'
        }
    }

    # ─────────────────────────────────────────────
    # Outbound Spam
    # ─────────────────────────────────────────────
    $spamData = $Results['ExchangePolicies']['OutboundSpam']
    if ($spamData) {
        if ($spamData.NotifyEnabled -and $spamData.NotifyRecipients) {
            Add-Finding -ControlId 'OutboundSpam' -State 'Satisfied' `
                -Detail 'Outbound spam notification enabled with recipient configured.'
        } elseif ($spamData.NotifyEnabled -and -not $spamData.NotifyRecipients) {
            Add-Finding -ControlId 'OutboundSpam' -State 'Partial' `
                -Detail 'Outbound spam notification enabled but no recipient configured. Alerts will not be delivered.' `
                -Remediation 'Run Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpamRecipients admin@yourdomain.com'
        } else {
            Add-Finding -ControlId 'OutboundSpam' -State 'Gap' `
                -Detail 'Outbound spam notification disabled. Compromised account detection gap.' `
                -Remediation 'Run Set-HostedOutboundSpamFilterPolicy -NotifyOutboundSpam $true'
        }
    }

    # ─────────────────────────────────────────────
    # Defender for Office 365
    # ─────────────────────────────────────────────
    $defData = $Results['ExchangePolicies']['DefenderO365']
    if ($defData) {
        $defChecks = @(
            @{ Id = 'SafeAttachments';     Val = $defData.SafeAttachmentBlockEnabled
               Rem = 'Enable Safe Attachments policy with Block action in Microsoft Defender portal' }
            @{ Id = 'SafeLinks';           Val = $defData.SafeLinksEnabled
               Rem = 'Enable Safe Links policy in Microsoft Defender portal' }
            @{ Id = 'AntiPhish';           Val = $defData.AntiPhishEnabled
               Rem = 'Enable anti-phishing policy in Microsoft Defender portal' }
            @{ Id = 'MailboxIntelligence'; Val = $defData.MailboxIntelligenceEnabled
               Rem = 'Enable mailbox intelligence in anti-phishing policy settings' }
            @{ Id = 'ZAPSpam';             Val = $defData.ZapSpamEnabled
               Rem = 'Enable ZAP for spam in hosted content filter policy' }
            @{ Id = 'ZAPPhish';            Val = $defData.ZapPhishEnabled
               Rem = 'Enable ZAP for phishing in hosted content filter policy' }
            @{ Id = 'ATPSPOTeams';         Val = $defData.ATPForSPOTeamsODB
               Rem = 'Enable ATP for SharePoint, Teams, and OneDrive in Microsoft Defender portal' }
        )

        foreach ($check in $defChecks) {
            if ($check.Val) {
                Add-Finding -ControlId $check.Id -State 'Satisfied' `
                    -Detail "$($dict[$check.Id].Title) is enabled."
            } else {
                Add-Finding -ControlId $check.Id -State 'Gap' `
                    -Detail "$($dict[$check.Id].Title) is not enabled." `
                    -Remediation $check.Rem
            }
        }
    }

    # ─────────────────────────────────────────────
    # DKIM
    # ─────────────────────────────────────────────
    $dkimData = $Results['ExchangePolicies']['DKIM']
    if ($dkimData) {
        $dkimDisabled = @($dkimData.Domains | Where-Object { -not $_.Enabled })
        if ($dkimDisabled.Count -eq 0) {
            Add-Finding -ControlId 'DKIM' -State 'Satisfied' `
                -Detail "DKIM signing enabled on all $($dkimData.Domains.Count) domain(s)."
        } elseif ($dkimDisabled.Count -lt $dkimData.Domains.Count) {
            Add-Finding -ControlId 'DKIM' -State 'Partial' `
                -Detail "$($dkimDisabled.Count) domain(s) have DKIM signing disabled: $($dkimDisabled.Domain -join ', ')" `
                -Remediation 'Run Enable-DkimSigningConfig -Identity <domain> for each affected domain'
        } else {
            Add-Finding -ControlId 'DKIM' -State 'Gap' `
                -Detail 'DKIM signing disabled on all domains.' `
                -Remediation 'Run Enable-DkimSigningConfig -Identity <domain> for each accepted domain'
        }
    }

    # ─────────────────────────────────────────────
    # DNSSEC
    # ─────────────────────────────────────────────
    $dnssecData = $Results['ExchangePolicies']['DNSSEC']
    if ($dnssecData) {
        $dnssecDisabled = @($dnssecData.Domains | Where-Object { -not $_.Enabled })
        if ($dnssecDisabled.Count -eq 0) {
            Add-Finding -ControlId 'DNSSEC' -State 'Satisfied' `
                -Detail "DNSSEC enabled on all $($dnssecData.Domains.Count) domain(s)."
        } elseif ($dnssecDisabled.Count -lt $dnssecData.Domains.Count) {
            Add-Finding -ControlId 'DNSSEC' -State 'Partial' `
                -Detail "$($dnssecDisabled.Count) domain(s) without DNSSEC: $($dnssecDisabled.Domain -join ', ')" `
                -Remediation 'Run Enable-DnssecForVerifiedDomain -DomainName <domain> then update MX to p-v1.mx.microsoft endpoint'
        } else {
            Add-Finding -ControlId 'DNSSEC' -State 'Gap' `
                -Detail 'DNSSEC not enabled on any domains.' `
                -Remediation 'Run Enable-DnssecForVerifiedDomain -DomainName <domain> for each accepted domain'
        }
    }

    # ─────────────────────────────────────────────
    # Conditional Access
    # ─────────────────────────────────────────────
    $caData = $Results['ConditionalAccess']['ConditionalAccess']
    if ($caData) {
        if ($caData.MfaEnforcingCount -gt 0 -and $caData.ReportOnlyCount -eq 0) {
            Add-Finding -ControlId 'AdminMFA' -State 'Satisfied' `
                -Detail "$($caData.MfaEnforcingCount) Conditional Access policy/policies enforcing MFA as a grant control."
            Add-Finding -ControlId 'CAPolicy' -State 'Satisfied' `
                -Detail "$($caData.EnabledCount) CA policy/policies in enforcement mode. $($caData.MfaEnforcingCount) enforce MFA."
        } elseif ($caData.ReportOnlyCount -gt 0 -and $caData.MfaEnforcingCount -gt 0) {
            Add-Finding -ControlId 'CAPolicy' -State 'Partial' `
                -Detail "$($caData.ReportOnlyCount) CA policy/policies in report-only mode. Not enforcing access control decisions." `
                -Remediation 'Review report-only policies and enable those that are production-ready'
        } else {
            Add-Finding -ControlId 'AdminMFA' -State 'Gap' `
                -Detail 'No enabled Conditional Access policy enforces MFA as a grant control.' `
                -Remediation 'Create or enable a CA policy requiring MFA for all users and all cloud apps'
            Add-Finding -ControlId 'CAPolicy' -State 'Gap' `
                -Detail 'No Conditional Access policies in enabled enforcement mode.' `
                -Remediation 'Review and enable CA policies. At minimum enforce MFA and block legacy authentication.'
        }

        if ($caData.LegacyAuthBlocking -gt 0) {
            Add-Finding -ControlId 'LegacyAuth' -State 'Satisfied' `
                -Detail "$($caData.LegacyAuthBlocking) CA policy/policies actively blocking legacy authentication clients."
        }
    }

    # ─────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────
    $satisfied = ($findings | Where-Object { $_.State -eq 'Satisfied' }).Count
    $partial   = ($findings | Where-Object { $_.State -eq 'Partial' }).Count
    $gap       = ($findings | Where-Object { $_.State -eq 'Gap' }).Count

    return [ordered]@{
        Findings  = $findings
        Summary   = [ordered]@{
            Satisfied = $satisfied
            Partial   = $partial
            Gap       = $gap
            Total     = $findings.Count
        }
        Frameworks = [ordered]@{
            NIST          = $NIST
            CIS           = $CIS
            HIPAA         = $HIPAA
            HIPAAProposed = $HIPAAProposed
        }
        DictionaryVersion = Get-NLSDictionaryVersion
    }
}

Export-ModuleMember -Function Invoke-NLSScoringModel
