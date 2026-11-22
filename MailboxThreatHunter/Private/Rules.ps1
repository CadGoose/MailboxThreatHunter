# Hunting rules. Each takes the data hashtable (+ accepted domains) and emits findings. No writes, ever.

function Get-MTHRuleOwner {
    param($Rule)
    $owner = Get-PV $Rule 'MailboxOwnerId' (Get-PV $Rule 'Mailbox' '')
    if (-not $owner) {
        $id = [string](Get-PV $Rule 'Identity' '')
        if ($id -match '^(.+?)\\') { $owner = $Matches[1] }
    }
    [string]$owner
}

function Find-SuspiciousInboxRule {
    param($Data, [string[]] $AcceptedDomains)
    foreach ($r in @(Get-PV $Data 'inboxRules' @())) {
        $owner = Get-MTHRuleOwner $r
        $name = [string](Get-PV $r 'Name' '')
        $score = 0
        $why = [System.Collections.Generic.List[string]]::new()

        if ((Get-PV $r 'DeleteMessage' $false) -or (Get-PV $r 'SoftDeleteMessage' $false)) { $score += 3; $why.Add('deletes matching mail') }
        if (Get-PV $r 'MarkAsRead' $false) { $score += 1; $why.Add('marks as read') }
        $move = [string](Get-PV $r 'MoveToFolder' '')
        $hidden = $script:HiddenFolders | Where-Object { $move -like "*$_*" }
        if ($hidden) { $score += 3; $why.Add("moves to '$move'") }
        elseif ($move) { $why.Add("moves to '$move'") }

        $fwd = @(Get-EmailAddress @(Get-PV $r 'ForwardTo' @()) + @(Get-PV $r 'ForwardAsAttachmentTo' @()) + @(Get-PV $r 'RedirectTo' @()))
        $external = @($fwd | Where-Object { Test-ExternalAddress $_ $AcceptedDomains })
        if ($external) { $score += 6; $why.Add("forwards externally to $($external -join ', ')") }
        elseif ($fwd) { $score += 1; $why.Add("forwards to $($fwd -join ', ')") }

        $words = (@(Get-PV $r 'SubjectContainsWords' @()) + @(Get-PV $r 'SubjectOrBodyContainsWords' @()) + @(Get-PV $r 'BodyContainsWords' @()) |
                ForEach-Object { [string]$_ }) -join ' '
        $kw = @($script:BecKeywords | Where-Object { $words -match "(?i)\b$([regex]::Escape($_))\b" })
        if ($kw) { $score += 2; $why.Add("keywords: $($kw -join ', ')") }
        $from = @(Get-PV $r 'FromAddressContainsWords' @()) + @(Get-PV $r 'From' @())
        if ($from -and ($score -ge 3)) { $score += 1; $why.Add("targets sender(s): $(($from | ForEach-Object { [string]$_ }) -join ', ')") }
        if ($name.Trim().Length -le 2 -or $name -match '^[\.\s,;:\-_]+$') { $score += 2; $why.Add("obfuscated rule name '$name'") }
        if ((Get-PV $r 'StopProcessingRules' $false) -and $score -ge 3) { $score += 1; $why.Add('stops further rule processing') }
        if (-not (Get-PV $r 'Enabled' $true)) { $score = [math]::Max(0, $score - 2); $why.Add('rule is disabled') }

        if ($score -ge 3) {
            New-MTHFinding -Mailbox $owner -Category 'Inbox rule' -Title "Suspicious inbox rule '$name'" -Score $score `
                -Detail (($why -join '; ') + '.') -Evidence @("Identity: $(Get-PV $r 'Identity' $name)", "Description: $((Get-PV $r 'Description' '') -replace '\s+', ' ')") `
                -Technique 'T1564.008'
        }
    }
}

function Find-MailboxForwarding {
    param($Data, [string[]] $AcceptedDomains)
    foreach ($m in @(Get-PV $Data 'mailboxes' @())) {
        $upn = [string](Get-PV $m 'UserPrincipalName' (Get-PV $m 'PrimarySmtpAddress' ''))
        $smtp = @(Get-EmailAddress @(Get-PV $m 'ForwardingSmtpAddress' $null))
        $keep = [bool](Get-PV $m 'DeliverToMailboxAndForward' $false)
        foreach ($a in $smtp) {
            if (Test-ExternalAddress $a $AcceptedDomains) {
                New-MTHFinding -Mailbox $upn -Category 'Forwarding' -Title 'Mailbox forwards to an external address' -Score 8 `
                    -Detail "All mail is forwarded to $a$(if ($keep) { ' (copy kept, so the user notices nothing)' } else { ' and NOT kept in the mailbox' })." `
                    -Evidence @("ForwardingSmtpAddress: $(Get-PV $m 'ForwardingSmtpAddress' '')", "DeliverToMailboxAndForward: $keep") -Technique 'T1114.003'
            }
        }
        $internal = [string](Get-PV $m 'ForwardingAddress' '')
        if ($internal) {
            New-MTHFinding -Mailbox $upn -Category 'Forwarding' -Title 'Mailbox forwards to another recipient' -Score 2 `
                -Detail "Forwarding to recipient object '$internal'. Confirm it is expected (and that the recipient is not a mail contact pointing outside)." -Technique 'T1114.003'
        }
    }
}

function Find-MailboxDelegation {
    param($Data)
    $skip = '^(NT AUTHORITY\\|S-1-5-|.*\\Discovery Management|.*\\Organization Management|.*\\Exchange )'
    foreach ($p in @(Get-PV $Data 'mailboxPermissions' @())) {
        $user = [string](Get-PV $p 'User' (Get-PV $p 'Trustee' ''))
        if (-not $user -or $user -match $skip -or (Get-PV $p 'IsInherited' $false) -or (Get-PV $p 'Deny' $false)) { continue }
        $rights = @(Get-PV $p 'AccessRights' @()) -join ','
        if ($rights -notmatch 'FullAccess') { continue }
        New-MTHFinding -Mailbox ([string](Get-PV $p 'Identity' '')) -Category 'Delegation' -Title 'FullAccess granted to another account' -Score 4 `
            -Detail "$user can open and read this mailbox." -Evidence @("AccessRights: $rights") -Technique 'T1098.002'
    }
    foreach ($p in @(Get-PV $Data 'recipientPermissions' @())) {
        $trustee = [string](Get-PV $p 'Trustee' '')
        if (-not $trustee -or $trustee -match $skip) { continue }
        if ((@(Get-PV $p 'AccessRights' @()) -join ',') -notmatch 'SendAs') { continue }
        New-MTHFinding -Mailbox ([string](Get-PV $p 'Identity' '')) -Category 'Delegation' -Title 'SendAs granted to another account' -Score 4 `
            -Detail "$trustee can send mail as this mailbox." -Technique 'T1098.002'
    }
}

function Find-RiskyOAuthGrant {
    param($Data)
    $sps = @{}
    foreach ($sp in @(Get-PV $Data 'servicePrincipals' @())) { $sps[[string]$sp.id] = $sp }
    $users = @{}
    foreach ($u in @(Get-PV $Data 'users' @())) { $users[[string]$u.id] = [string]$u.userPrincipalName }
    foreach ($g in @(Get-PV $Data 'oauthGrants' @())) {
        $scopes = @(([string](Get-PV $g 'scope' '')) -split '\s+' | Where-Object { $_ })
        $mail = @($scopes | Where-Object { $_ -in $script:MailScopes })
        if (-not $mail) { continue }
        $sp = $sps[[string](Get-PV $g 'clientId' '')]
        $app = Get-PV $sp 'displayName' (Get-PV $g 'clientId' 'unknown app')
        $verified = Get-PV $sp 'verifiedPublisher.displayName' $null
        $score = 4 + $(if (-not $verified) { 3 } else { 0 }) + $(if ($mail -match 'Send|ReadWrite') { 1 } else { 0 })
        $consent = [string](Get-PV $g 'consentType' '')
        $who = if ($consent -eq 'AllPrincipals') { '(all users)' } else { $users[[string](Get-PV $g 'principalId' '')] ?? [string](Get-PV $g 'principalId' '') }
        New-MTHFinding -Mailbox $who -Category 'OAuth consent' -Title "App '$app' can access mail" -Score $score `
            -Detail "Delegated scopes: $($mail -join ', '). Publisher: $(if ($verified) { "verified ($verified)" } else { 'UNVERIFIED' }). Consent: $consent." `
            -Evidence @("clientId: $(Get-PV $g 'clientId' '')", "All scopes: $($scopes -join ' ')") -Technique 'T1528'
    }
}

function Find-AuthMethodChange {
    param($Data, [int] $LookbackDays = 14, [datetime] $Now = [datetime]::MinValue)
    # Offline data is judged relative to its newest event so saved cases and samples don't go stale.
    if ($Now -eq [datetime]::MinValue) { $Now = (Get-Date).ToUniversalTime() }
    $since = $Now.ToUniversalTime().AddDays(-$LookbackDays)
    $events = @(Get-PV $Data 'authMethodChanges' @()) | Where-Object {
        $t = Get-PV $_ 'activityDateTime' $null
        $null -eq $t -or ([datetime]$t).ToUniversalTime() -ge $since
    }
    foreach ($grp in ($events | Group-Object { [string](Get-PV $_ 'targetUserPrincipalName' (Get-PV $_ 'userPrincipalName' '')) })) {
        $acts = @($grp.Group | ForEach-Object { "$(Get-PV $_ 'activityDateTime' '') $(Get-PV $_ 'activityDisplayName' '') from $(Get-PV $_ 'ipAddress' '?')" })
        $deleted = @($grp.Group | Where-Object { (Get-PV $_ 'activityDisplayName' '') -match 'deleted' })
        $score = 3 + [math]::Min(3, $grp.Count - 1) + $(if ($deleted) { 2 } else { 0 })
        New-MTHFinding -Mailbox $grp.Name -Category 'MFA methods' -Title 'Recent MFA / security-info changes' -Score $score `
            -Detail "$($grp.Count) security-info change(s) in the last $LookbackDays days$(if ($deleted) { ', including a deletion' }). Attackers register their own authenticator to keep access." `
            -Evidence $acts -Technique 'T1098.005'
    }
}

$script:MTHRules = @('Find-SuspiciousInboxRule', 'Find-MailboxForwarding', 'Find-MailboxDelegation', 'Find-RiskyOAuthGrant', 'Find-AuthMethodChange')
