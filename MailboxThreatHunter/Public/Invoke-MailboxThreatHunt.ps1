function Invoke-MailboxThreatHunt {
    <#
    .SYNOPSIS
        Hunts for business email compromise indicators across Exchange Online mailboxes.

    .DESCRIPTION
        Read-only. Looks for:
          - inbox rules that hide, delete or forward mail (BEC keywords, RSS/Archive folders, obfuscated names)
          - mailbox-level forwarding to external domains
          - FullAccess / SendAs delegation
          - OAuth apps with delegated mail scopes (unverified publishers weighted higher)
          - recent MFA / security-info registrations and deletions
        Findings are scored per mailbox: 12+ = "Likely compromised", 6-11 = "Investigate", otherwise "Review".

        Online: Connect-ExchangeOnline (View-Only Recipients / View-Only Configuration is enough) and optionally
        Connect-MgGraph -Scopes Directory.Read.All,AuditLog.Read.All first.
        Offline: -InputPath a folder created by Export-MailboxThreatData or the bundled samples.

    .PARAMETER UserPrincipalName
        Limit the hunt to specific mailboxes (fast triage of a reported user).

    .PARAMETER AcceptedDomain
        Your domains; anything else counts as external. Read from Get-AcceptedDomain when online.

    .EXAMPLE
        Invoke-MailboxThreatHunt -InputPath ./samples/contoso -OutputPath ./hunt.html

    .EXAMPLE
        Connect-ExchangeOnline; Connect-MgGraph -Scopes Directory.Read.All,AuditLog.Read.All
        Invoke-MailboxThreatHunt -UserPrincipalName cfo@contoso.com -OutputPath ./cfo.html
    #>
    [CmdletBinding()]
    [OutputType('MailboxThreatHunter.Finding')]
    param(
        [string] $InputPath,
        [string[]] $UserPrincipalName,
        [string[]] $AcceptedDomain,
        [int] $LookbackDays = 14,
        [string] $OutputPath,
        [string] $CsvPath
    )

    if ($InputPath) {
        if (-not (Test-Path $InputPath -PathType Container)) { throw "Input folder not found: $InputPath" }
        $data = Read-MTHOffline -Path $InputPath
    }
    else {
        $data = Get-MTHOnline -UserPrincipalName $UserPrincipalName -LookbackDays $LookbackDays
    }
    $domains = @($AcceptedDomain) + @($data.acceptedDomains) | Where-Object { $_ } | Select-Object -Unique
    if (-not $domains) { Write-Warning 'No accepted domains known: every forwarding address will be treated as external. Pass -AcceptedDomain.' }

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $script:MTHRules) {
        $params = @{ Data = $data }
        if ((Get-Command $rule).Parameters.ContainsKey('AcceptedDomains')) { $params.AcceptedDomains = $domains }
        if ((Get-Command $rule).Parameters.ContainsKey('LookbackDays')) { $params.LookbackDays = $LookbackDays }
        if ((Get-Command $rule).Parameters.ContainsKey('Now') -and $InputPath) {
            $latest = @($data.authMethodChanges | ForEach-Object { Get-PV $_ 'activityDateTime' $null } | Where-Object { $_ } |
                    ForEach-Object { ([datetime]$_).ToUniversalTime() } | Sort-Object -Descending) | Select-Object -First 1
            if ($latest) { $params.Now = $latest }
        }
        foreach ($f in @(& $rule @params)) { if ($f) { $findings.Add($f) } }
    }
    if ($UserPrincipalName) {
        $wanted = $UserPrincipalName | ForEach-Object { $_.ToLowerInvariant() }
        $findings = [System.Collections.Generic.List[object]]@($findings | Where-Object { $_.Mailbox -in $wanted -or $_.Mailbox -eq '(all users)' })
    }

    $summary = @($findings | Group-Object Mailbox | ForEach-Object {
            $score = ($_.Group | Measure-Object Score -Sum).Sum
            [pscustomobject]@{ Mailbox = $_.Name; Score = $score; Verdict = (Get-MTHVerdict $score); Findings = $_.Count }
        } | Sort-Object Score -Descending)

    if ($OutputPath) {
        ConvertTo-MTHHtml -Findings $findings -Summary $summary -Title 'Mailbox threat hunt' | Set-Content -Path $OutputPath -Encoding utf8
        Write-Information "HTML report: $OutputPath" -InformationAction Continue
    }
    if ($CsvPath) {
        $findings | Select-Object Mailbox, Severity, Score, Category, Title, Detail, Technique, @{ n = 'Evidence'; e = { $_.Evidence -join ' | ' } } |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8
        Write-Information "CSV: $CsvPath" -InformationAction Continue
    }
    foreach ($s in $summary) {
        Write-Information ("{0,-45} {1,-20} score {2}" -f $s.Mailbox, $s.Verdict, $s.Score) -InformationAction Continue
    }
    $findings | Sort-Object Score -Descending
}

function Export-MailboxThreatData {
    <#
    .SYNOPSIS
        Collects hunt data to JSON so it can be analysed offline, shared with an IR team, or kept as evidence.
    .EXAMPLE
        Export-MailboxThreatData -Path ./cases/2026-11-cfo -UserPrincipalName cfo@contoso.com
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path, [string[]] $UserPrincipalName, [int] $LookbackDays = 14)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $data = Get-MTHOnline -UserPrincipalName $UserPrincipalName -LookbackDays $LookbackDays
    foreach ($k in $data.Keys) {
        ConvertTo-Json -InputObject @($data[$k]) -Depth 10 | Set-Content -Path (Join-Path $Path "$k.json") -Encoding utf8
    }
    Get-ChildItem -Path $Path -Filter '*.json'
}
