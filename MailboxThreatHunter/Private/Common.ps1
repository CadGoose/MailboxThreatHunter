function Get-PV {
    # Safe nested property access under StrictMode. Note: returns arrays unrolled; wrap callers in @().
    param($Object, [string] $Path, $Default = $null)
    $cur = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $cur) { return $Default }
        if ($cur -is [System.Collections.IDictionary]) { $cur = $cur[$part] }
        elseif ($cur.PSObject.Properties.Name -contains $part) { $cur = $cur.$part }
        else { return $Default }
    }
    if ($null -eq $cur) { return $Default }
    return $cur
}

function Get-EmailAddress {
    # Pull SMTP addresses out of Exchange-style strings: '"Bob" [SMTP:bob@x.com]', 'smtp:bob@x.com', 'bob@x.com'.
    param([object[]] $Value)
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        foreach ($m in [regex]::Matches([string]$v, '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')) { $m.Value.ToLowerInvariant() }
    }
}

function Test-ExternalAddress {
    param([string] $Address, [string[]] $AcceptedDomains)
    if (-not $Address -or -not $AcceptedDomains) { return [bool]$Address }
    $domain = ($Address -split '@')[-1].ToLowerInvariant()
    -not ($AcceptedDomains | Where-Object { $domain -eq $_.ToLowerInvariant() -or $domain.EndsWith('.' + $_.ToLowerInvariant()) })
}

function New-MTHFinding {
    param(
        [Parameter(Mandatory)][string] $Mailbox,
        [Parameter(Mandatory)][string] $Category,
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][int] $Score,
        [string] $Detail = '',
        [string[]] $Evidence = @(),
        [string] $Technique = ''
    )
    $sev = if ($Score -ge 8) { 'High' } elseif ($Score -ge 4) { 'Medium' } else { 'Low' }
    [pscustomobject]@{
        PSTypeName = 'MailboxThreatHunter.Finding'
        Mailbox    = $Mailbox.ToLowerInvariant()
        Severity   = $sev
        Score      = $Score
        Category   = $Category
        Title      = $Title
        Detail     = $Detail
        Evidence   = @($Evidence)
        Technique  = $Technique
    }
}

$script:BecKeywords = @(
    'invoice', 'payment', 'wire', 'transfer', 'bank', 'remittance', 'ach', 'swift', 'iban', 'payroll', 'direct deposit',
    'w-2', 'w2', 'urgent', 'hacked', 'phish', 'phishing', 'suspicious', 'fraud', 'compromised', 'security', 'helpdesk', 'it support'
)
$script:HiddenFolders = @('RSS Feeds', 'RSS Subscriptions', 'Conversation History', 'Archive', 'Junk Email', 'Deleted Items', 'Notes', 'Sync Issues')
$script:MailScopes = @(
    'Mail.Read', 'Mail.ReadBasic', 'Mail.ReadWrite', 'Mail.Send', 'MailboxSettings.ReadWrite', 'EWS.AccessAsUser.All',
    'IMAP.AccessAsUser.All', 'POP.AccessAsUser.All', 'SMTP.Send', 'full_access_as_app', 'full_access_as_user'
)
