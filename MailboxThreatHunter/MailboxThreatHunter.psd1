@{
    RootModule        = 'MailboxThreatHunter.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'e6f056eb-dd31-4bdf-9201-0590145ffa97'
    Author            = 'George Mkahail'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 George Mkahail. MIT License.'
    Description       = 'Business email compromise (BEC) triage for Exchange Online: suspicious inbox rules, external forwarding, mailbox delegation, risky OAuth consents and recent MFA method changes, scored per mailbox with an incident-response checklist. Read-only.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @('Invoke-MailboxThreatHunt', 'Export-MailboxThreatData', 'Get-MTHIncidentChecklist')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('ExchangeOnline', 'BEC', 'IncidentResponse', 'InboxRules', 'Microsoft365', 'Security', 'DFIR', 'BlueTeam')
            LicenseUri   = 'https://github.com/CadGoose/MailboxThreatHunter/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/CadGoose/MailboxThreatHunter'
            ReleaseNotes = 'Initial release.'
        }
    }
}
