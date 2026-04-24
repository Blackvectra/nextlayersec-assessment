#
# NLS.Core.psm1
# NextLayerSec Assessment Framework -- Core Module
# Output safety, coverage tracking, exception handling
#
# Author:  NextLayerSec
# Version: 1.0.0
# License: CC BY-ND 4.0 -- https://creativecommons.org/licenses/by-nd/4.0/
#

$script:Exceptions = @()
$script:CoverageMap = [ordered]@{}

# ─────────────────────────────────────────────
# Output Safety
# ─────────────────────────────────────────────

function Export-NLSSafeMarkdown {
    <#
    .SYNOPSIS
        Writes a markdown string to disk with optional redaction.
    .DESCRIPTION
        All markdown output passes through this function.
        When -Redact is true, scrubs UPNs, GUIDs, and IP addresses
        from the content before writing to disk.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$OutPath,

        [bool]$Redact = $false
    )

    if ($Redact) {
        # Scrub email addresses and UPNs
        $Content = $Content -replace '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[REDACTED_UPN]'
        # Scrub standard GUIDs
        $Content = $Content -replace '[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '[REDACTED_ID]'
        # Scrub IPv4 addresses
        $Content = $Content -replace '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[REDACTED_IP]'
    }

    $Content | Out-File -FilePath $OutPath -Encoding utf8 -Force
}

# ─────────────────────────────────────────────
# Coverage Tracking
# ─────────────────────────────────────────────

function Register-NLSCoverage {
    <#
    .SYNOPSIS
        Registers the collection status of a control family.
    .DESCRIPTION
        Differentiates between a control not found vs a control not checked.
        Collected  -- data retrieved successfully
        Partial    -- data retrieved but incomplete (e.g. licensing gap)
        NotCollected -- operator skipped or flag excluded this check
        Unsupported  -- tenant licensing does not support this control
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlFamily,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Collected', 'Partial', 'NotCollected', 'Unsupported')]
        [string]$Status,

        [string]$Reason = ''
    )

    $script:CoverageMap[$ControlFamily] = [ordered]@{
        Status = $Status
        Reason = $Reason
    }
}

function Get-NLSCoverageMap {
    return $script:CoverageMap
}

# ─────────────────────────────────────────────
# Exception Handling
# ─────────────────────────────────────────────

function Register-NLSException {
    <#
    .SYNOPSIS
        Logs a non-fatal exception encountered during collection.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$ErrorDetails = ''
    )

    $script:Exceptions += [ordered]@{
        Timestamp    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        Source       = $Source
        Message      = $Message
        ErrorDetails = $ErrorDetails
    }
}

function Get-NLSExceptions {
    return $script:Exceptions
}

# ─────────────────────────────────────────────
# Metadata
# ─────────────────────────────────────────────

function Get-NLSMetadata {
    <#
    .SYNOPSIS
        Collects assessment run metadata -- operator, timing, module versions.
    #>
    param(
        [bool]$Redact = $false
    )

    $mgContext = Get-MgContext -ErrorAction SilentlyContinue
    $exoModule = Get-Module ExchangeOnlineManagement -ListAvailable |
        Sort-Object Version -Descending |
        Select-Object -First 1
    $graphModule = Get-Module Microsoft.Graph.Authentication -ListAvailable |
        Sort-Object Version -Descending |
        Select-Object -First 1

    $upn = if ($mgContext) { $mgContext.Account } else { 'Unknown' }
    if ($Redact -and $upn -ne 'Unknown') { $upn = '[REDACTED_ADMIN_UPN]' }

    [ordered]@{
        ExecutionTimeUTC = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        AuthContext      = $upn
        GraphScopes      = if ($mgContext) { ($mgContext.Scopes -join ', ') } else { $null }
        ModuleVersions   = [ordered]@{
            ExchangeOnlineManagement     = if ($exoModule) { $exoModule.Version.ToString() } else { 'Not found' }
            MicrosoftGraphAuthentication = if ($graphModule) { $graphModule.Version.ToString() } else { 'Not found' }
        }
    }
}

Export-ModuleMember -Function `
    Export-NLSSafeMarkdown, `
    Register-NLSCoverage, `
    Get-NLSCoverageMap, `
    Register-NLSException, `
    Get-NLSExceptions, `
    Get-NLSMetadata
