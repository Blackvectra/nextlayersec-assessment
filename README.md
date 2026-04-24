# NextLayerSec M365 Assessment Framework

> Read-only M365 security assessment instrument for Exchange Online and Entra ID.
> Maps findings to NIST SP 800-53 Rev 5, CIS Controls v8.1, HIPAA current rule,
> and HIPAA NPRM proposed rule with state-aware citations.
> Designed for MSP and consulting engagements against M365 Business Premium tenants.

[![License](https://img.shields.io/badge/License-CC%20BY--ND%204.0-blue?style=flat-square)](https://creativecommons.org/licenses/by-nd/4.0/)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square)](https://github.com/PowerShell/PowerShell)
[![Read Only](https://img.shields.io/badge/Mode-Read--Only-00c853?style=flat-square)]()
[![Frameworks](https://img.shields.io/badge/Frameworks-NIST%20%7C%20CIS%20%7C%20HIPAA-orange?style=flat-square)]()

---

## Overview

`Invoke-NLSAssessment` is a precision read-only assessment instrument. It connects to Exchange Online and Microsoft Graph, collects security policy configuration and sign-in telemetry, scores findings against the NextLayerSec baseline, and produces structured markdown artifacts mapped to authoritative compliance frameworks.

**No tenant configuration changes are made at any point.**

Each finding is state-aware — returning Satisfied, Partial, or Gap — with citations mapped to the specific control that requires or recommends the configuration. This produces a deliverable suitable for client reporting, audit evidence, and compliance gap analysis.

---

## What It Checks

### Exchange Online
- Legacy authentication policy configuration and org default assignment
- SMTP client authentication status
- External auto-forwarding controls
- Mailbox protocol hardening (POP, IMAP)
- Mailbox auditing and unified audit log status
- Outbound spam notification
- Defender for Office 365 (Safe Attachments, Safe Links, Anti-Phishing, ZAP, ATP)
- DKIM signing configuration per domain
- DNSSEC status per domain

### Conditional Access (Microsoft Graph)
- All CA policy states — enabled, report-only, disabled
- MFA enforcement as a grant control
- Legacy authentication blocking
- Report-only policy detection
- Sign-in log telemetry — legacy auth attempts, MFA challenge rate, failures (Full mode)

---

## Framework Mapping

Each finding is mapped across up to four compliance frameworks depending on operator switches passed at runtime.

| Framework | Version | Switch |
|---|---|---|
| NIST SP 800-53 | Rev 5 Release 5.2.0 | `-NIST` |
| CIS Controls | v8.1 June 2024 | `-CIS` |
| HIPAA Security Rule | 45 CFR 164.312 current enforceable rule | `-HIPAA` |
| HIPAA Security Rule NPRM | December 27 2024 proposed rule | `-HIPAAProposed` |

### HIPAA NPRM Note

The December 2024 NPRM proposes eliminating the required/addressable distinction across all implementation specifications. Expected final rule: May 2026 with a 240-day compliance window.

Running `-HIPAA -HIPAAProposed` together produces a dual-state gap analysis showing current compliance posture alongside exposure against the incoming mandatory standard. This is the recommended configuration for healthcare client engagements.

### Finding States

Each control returns one of three states:

| State | Meaning |
|---|---|
| Satisfied | Control is enabled and enforced. Citation shows what is satisfied. |
| Partial | Control exists but is not fully enforced. Citation shows what is not yet met. |
| Gap | Control is missing or disabled. Citation shows what is required. |

---

## Architecture

```
nextlayersec-assessment/
|
|-- Invoke-NLSAssessment.ps1           # Orchestrator -- run this
|
|-- Modules/
|   |-- NLS.Core.psm1                  # Output safety, coverage tracking, exceptions
|   |-- NLS.Exchange.psm1              # Exchange Online collector
|   |-- NLS.ConditionalAccess.psm1     # Graph CA policy + telemetry collector
|   |-- NLS.FrameworkDictionary.psm1   # 228 state-aware compliance citations (data only)
|   |-- NLS.Scoring.psm1               # Scoring engine (logic only, imports dictionary)
|   `-- NLS.Reporting.psm1             # Markdown report generation
|
|-- output/
|   `-- <timestamp>/
|       |-- AssessmentSummary.md       # Full findings report with framework citations
|       `-- Exceptions.md             # Collection exceptions log
|
|-- README.md
`-- .gitignore
```

### Data and Logic Separation

`NLS.FrameworkDictionary.psm1` contains only compliance mapping data — no execution logic. When a framework releases a new version, only this file changes. The scoring engine, orchestrator, and reporting module are untouched.

Update procedure when framework versions change:
1. Open `NLS.FrameworkDictionary.psm1`
2. Find affected ControlId entries
3. Update Citation, Detail, and Requirement fields
4. Update `DictionaryVersion` at bottom of file
5. Commit and tag release

---

## Requirements

### Modules

```powershell
# Required for all modes
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force

# Required for Full mode (CA telemetry)
Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
```

### Permissions

| Scope | Required For |
|---|---|
| Exchange Admin or Global Admin | Exchange Online collection |
| `Policy.Read.ConditionalAccess` | CA policy collection |
| `Directory.Read.All` | Graph directory access |
| `AuditLog.Read.All` | Sign-in log telemetry (Full mode only) |

### Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Usage

### Exchange Only — No Graph Setup Required

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph
```

Runs all Exchange Online checks. No Graph modules required. No browser consent prompt. Recommended for initial triage and quick tenant assessments.

### Full Assessment

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com
```

Runs all checks including Conditional Access policies and sign-in log telemetry. Requires `AuditLog.Read.All`.

### NIST Assessment

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph -NIST
```

Default framework. NIST SP 800-53 Rev 5 citations included in all findings.

### HIPAA Engagement — Dual State Gap Analysis

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NoGraph -HIPAA -HIPAAProposed -RedactSensitiveData
```

Produces findings mapped to both the current enforceable HIPAA Security Rule and the incoming NPRM proposed rule. Shows where the client stands today and what becomes mandatory under the final rule. Recommended for all healthcare client engagements.

### Full Framework Stack

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -NIST -CIS -HIPAA -HIPAAProposed
```

All four frameworks included in every finding.

### Redacted Output

```powershell
.\Invoke-NLSAssessment.ps1 -UserPrincipalName admin@contoso.com -RedactSensitiveData
```

Scrubs UPNs, GUIDs, and IP addresses from all output files before writing to disk. Use for any artifacts leaving your workstation or shared with clients.

### Skip Connection

```powershell
.\Invoke-NLSAssessment.ps1 -SkipConnect
```

Skips connection step if already connected to Exchange Online and Graph.

---

## Output

All artifacts written to `output\<timestamp>\` relative to the script directory.

| File | Contents |
|---|---|
| `AssessmentSummary.md` | Full findings report with state, severity, framework citations, and remediation |
| `Exceptions.md` | Non-fatal collection errors — permissions gaps, licensing limits, API failures |

### Sample Finding Output

```markdown
### Gap

#### Identity

**Block legacy authentication protocols**

Policy [DefaultPolicy]: Basic auth still enabled on: AllowBasicAuthImap

> *Frameworks: **NIST:** IA-2(6), CM-7 | **HIPAA (Current):** §164.312(a)(2)(i), §164.312(d) | **HIPAA (Proposed):** §164.312(a)(2)(i), §164.312(d), §164.312(a)(2)(ix)*

*Remediation:* Set all AllowBasicAuth* parameters to $false via Set-AuthenticationPolicy
```

---

## Coverage Map

The assessment summary includes a coverage map distinguishing between:

| Status | Meaning |
|---|---|
| Collected | Data retrieved and scored successfully |
| Partial | Data retrieved but incomplete — permissions or licensing gap |
| NotCollected | Operator skipped via `-Quick`, `-NoTelemetry`, or `-NoGraph` |
| Unsupported | Tenant licensing does not support this control |

**Missing telemetry is not equivalent to a missing policy.** The exceptions log documents all collection failures with source, message, and error detail.

---

## Operational Notes

- Always run from a dedicated admin account — not your primary user account
- Use `-RedactSensitiveData` for any artifacts leaving your workstation
- The `output\` directory is gitignored — do not commit assessment artifacts
- Run `-NoGraph -Quick` for initial triage. Run full mode for formal engagement documentation.
- First run against a new tenant will prompt for Graph consent in a browser window

---

## Framework Dictionary Versions

| Framework | Version Mapped | Last Updated |
|---|---|---|
| NIST SP 800-53 | Rev 5 Release 5.2.0 | 2026-04-23 |
| CIS Controls | v8.1 June 2024 | 2026-04-23 |
| HIPAA Security Rule | 45 CFR 164.312 current enforceable | 2026-04-23 |
| HIPAA NPRM | December 27 2024 proposed rule | 2026-04-23 |

---

## Related

- [nextlayersec-email-security](https://github.com/Blackvectra/nextlayersec-email-security) -- Full email security stack documentation, deployment guides, and DNS record templates

---

## License

CC BY-ND 4.0 -- See [LICENSE](LICENSE) for details.

---

<div align="center">

**[NextLayerSec](https://nextlayersec.io)** &nbsp;|&nbsp;
**[LinkedIn](https://linkedin.com/company/nextlayersec)** &nbsp;|&nbsp;
**[GitHub](https://github.com/Blackvectra)**

*Cybersecurity consulting for organizations that take security seriously.*

</div>
