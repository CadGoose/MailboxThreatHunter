BeforeDiscovery {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'MailboxThreatHunter/MailboxThreatHunter.psd1') -Force
}

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $root 'MailboxThreatHunter/MailboxThreatHunter.psd1') -Force
    $script:Sample = Join-Path $root 'samples/contoso'
}

Describe 'Module' {
    It 'exports the public functions' {
        (Get-Command -Module MailboxThreatHunter).Name | Sort-Object |
            Should -Be @('Export-MailboxThreatData', 'Get-MTHIncidentChecklist', 'Invoke-MailboxThreatHunt')
    }
}

Describe 'Sample tenant hunt' {
    BeforeAll {
        $script:F = @(Invoke-MailboxThreatHunt -InputPath $script:Sample -InformationAction SilentlyContinue 6>$null)
        $script:ByBox = $script:F | Group-Object Mailbox -AsHashTable -AsString
    }
    It 'flags the CFO hidden-folder BEC rule as High' {
        $r = $script:F | Where-Object { $_.Mailbox -eq 'cfo@contoso.example' -and $_.Category -eq 'Inbox rule' }
        $r.Severity | Should -Be 'High'
        $r.Detail | Should -Match 'RSS Feeds'
        $r.Detail | Should -Match 'invoice'
        $r.Detail | Should -Match "obfuscated rule name '\.\.'"
    }
    It 'ignores the benign newsletter rule and internal forward' {
        $script:F.Title | Should -Not -Contain "Suspicious inbox rule 'Newsletters'"
        $script:ByBox.ContainsKey('sales.lead@contoso.example') | Should -BeFalse
    }
    It 'flags external mailbox forwarding' {
        ($script:F | Where-Object { $_.Mailbox -eq 'ap.clerk@contoso.example' -and $_.Category -eq 'Forwarding' }).Detail | Should -Match 'copy kept'
    }
    It 'flags external forwarding inside a rule' {
        ($script:F | Where-Object Title -EQ "Suspicious inbox rule 'Vendor sync'").Detail | Should -Match 'forwards externally'
    }
    It 'skips SELF and inherited permissions' {
        @($script:F | Where-Object Category -EQ 'Delegation').Count | Should -Be 2
    }
    It 'weights the unverified OAuth app above the verified one' {
        $mailsync = $script:F | Where-Object Title -Like "*MailSync Pro*"
        $crm = $script:F | Where-Object Title -Like "*Acme CRM*"
        $mailsync.Mailbox | Should -Be 'cfo@contoso.example'
        $mailsync.Score | Should -BeGreaterThan $crm.Score
        $crm.Mailbox | Should -Be '(all users)'
    }
    It 'does not report Teams (no mail scopes)' { $script:F.Title | Should -Not -Contain "App 'Microsoft Teams' can access mail" }
    It 'reports recent MFA changes but not old ones' {
        ($script:F | Where-Object Category -EQ 'MFA methods').Mailbox | Should -Be 'cfo@contoso.example'
    }
    It 'returns findings sorted by score' {
        $script:F[0].Score | Should -BeGreaterOrEqual $script:F[-1].Score
    }
    It 'filters to one mailbox with -UserPrincipalName' {
        $one = @(Invoke-MailboxThreatHunt -InputPath $script:Sample -UserPrincipalName 'AP.Clerk@contoso.example' 6>$null)
        # Tenant-wide app consents stay in scope: they can read the triaged mailbox too.
        ($one.Mailbox | Select-Object -Unique | Sort-Object) | Should -Be @('(all users)', 'ap.clerk@contoso.example')
    }
    It 'writes HTML and CSV reports' {
        $h = Join-Path $TestDrive 'r.html'; $c = Join-Path $TestDrive 'r.csv'
        Invoke-MailboxThreatHunt -InputPath $script:Sample -OutputPath $h -CsvPath $c 6>$null | Out-Null
        Get-Content -Raw $h | Should -Match 'Likely compromised'
        (Import-Csv $c).Count | Should -Be $script:F.Count
    }
}

Describe 'Rule logic' {
    InModuleScope MailboxThreatHunter {
        It 'treats subdomains of accepted domains as internal' {
            Test-ExternalAddress 'a@mail.contoso.example' @('contoso.example') | Should -BeFalse
            Test-ExternalAddress 'a@contoso.example.evil.test' @('contoso.example') | Should -BeTrue
        }
        It 'extracts addresses from Exchange recipient strings' {
            @(Get-EmailAddress '"Bob" [SMTP:Bob@Fabrikam.example]', 'smtp:x@y.example') | Should -Be @('bob@fabrikam.example', 'x@y.example')
        }
        It 'a disabled rule scores lower' {
            $base = @{ Name = 'x'; Mailbox = 'u@c.example'; DeleteMessage = $true; SubjectOrBodyContainsWords = @('invoice') }
            $on = Find-SuspiciousInboxRule -Data @{ inboxRules = @([pscustomobject]($base + @{ Enabled = $true })) } -AcceptedDomains 'c.example'
            $off = Find-SuspiciousInboxRule -Data @{ inboxRules = @([pscustomobject]($base + @{ Enabled = $false })) } -AcceptedDomains 'c.example'
            $on.Score | Should -BeGreaterThan $off.Score
        }
        It 'keyword match is whole-word (no "achievement" -> "ach")' {
            $r = [pscustomobject]@{ Name = 'Awards'; Mailbox = 'u@c.example'; MoveToFolder = 'Awards'; SubjectContainsWords = @('achievement') }
            @(Find-SuspiciousInboxRule -Data @{ inboxRules = @($r) } -AcceptedDomains 'c.example').Count | Should -Be 0
        }
        It 'derives the owner from Identity when Mailbox is missing' {
            $r = [pscustomobject]@{ Name = '.'; Identity = 'victim@c.example\.'; DeleteMessage = $true }
            (Find-SuspiciousInboxRule -Data @{ inboxRules = @($r) }).Mailbox | Should -Be 'victim@c.example'
        }
        It 'maps scores to verdicts' {
            Get-MTHVerdict 12 | Should -Be 'Likely compromised'
            Get-MTHVerdict 6 | Should -Be 'Investigate'
            Get-MTHVerdict 2 | Should -Be 'Review'
        }
        It 'HTML-encodes attacker-controlled rule names' {
            $f = New-MTHFinding -Mailbox 'u@c.example' -Category 'Inbox rule' -Title "Suspicious inbox rule '<img src=x onerror=alert(1)>'" -Score 9
            $html = ConvertTo-MTHHtml -Findings @($f) -Summary @([pscustomobject]@{ Mailbox = 'u@c.example'; Score = 9; Verdict = 'Investigate' }) -Title 't'
            $html | Should -Not -Match '<img src=x'
        }
    }
}

Describe 'Incident checklist' {
    It 'includes containment commands for the user and executes nothing' {
        $c = Get-MTHIncidentChecklist -UserPrincipalName 'cfo@contoso.example'
        ($c -join "`n") | Should -Match "Revoke-MgUserSignInSession -UserId 'cfo@contoso.example'"
        ($c -join "`n") | Should -Match 'ForwardingSmtpAddress \$null'
    }
}

Describe 'Online collection (Exchange + Graph mocked)' {
    It 'uses only read cmdlets and GET requests' {
        InModuleScope MailboxThreatHunter {
            function Get-EXOMailbox { param($Identity, $ResultSize, $RecipientTypeDetails, $Properties) }
            function Get-InboxRule { param($Mailbox, $ErrorAction) }
            function Get-EXOMailboxPermission { param($Identity, $ErrorAction) }
            function Get-EXORecipientPermission { param($Identity, $ErrorAction) }
            function Get-AcceptedDomain { }
            function Invoke-MgGraphRequest { param($Method, $Uri, $OutputType, $ErrorAction) }
            Mock Get-EXOMailbox { [pscustomobject]@{ UserPrincipalName = 'u@c.example'; PrimarySmtpAddress = 'u@c.example'; ForwardingSmtpAddress = 'smtp:x@evil.test'; ForwardingAddress = $null; DeliverToMailboxAndForward = $true } }
            Mock Get-InboxRule { [pscustomobject]@{ Name = '.'; Identity = 'u\.'; DeleteMessage = $true; SubjectContainsWords = @('invoice') } }
            Mock Get-EXOMailboxPermission { }
            Mock Get-EXORecipientPermission { }
            Mock Get-AcceptedDomain { [pscustomobject]@{ DomainName = 'c.example' } }
            Mock Invoke-MgGraphRequest { @{ value = @() } }
            $data = Get-MTHOnline
            $data.mailboxes.Count | Should -Be 1
            $data.inboxRules[0].Mailbox | Should -Be 'u@c.example'
            $data.acceptedDomains | Should -Be @('c.example')
            Should -Invoke Invoke-MgGraphRequest -ParameterFilter { $Method -ne 'GET' } -Times 0 -Exactly
        }
    }
}
