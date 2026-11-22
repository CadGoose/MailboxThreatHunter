$script:MTHDatasets = @('mailboxes', 'inboxRules', 'mailboxPermissions', 'recipientPermissions', 'oauthGrants', 'servicePrincipals', 'users', 'authMethodChanges', 'acceptedDomains')

function ConvertTo-MTHObject {
    param([Parameter(ValueFromPipeline)] $InputObject)
    process { if ($null -ne $InputObject) { $InputObject | ConvertTo-Json -Depth 10 -Compress -WarningAction SilentlyContinue | ConvertFrom-Json -Depth 10 } }
}

function Read-MTHOffline {
    param([Parameter(Mandatory)][string] $Path)
    $data = @{}
    foreach ($name in $script:MTHDatasets) {
        $file = Join-Path $Path "$name.json"
        if (Test-Path $file) {
            $raw = Get-Content -Raw $file | ConvertFrom-Json -Depth 20
            $data[$name] = if ($raw -isnot [array] -and $raw.PSObject.Properties.Name -contains 'value') { @($raw.value) } else { @($raw) }
        }
        else { $data[$name] = @() }
    }
    $data
}

function Get-MTHOnline {
    <# Collects from Exchange Online (Get-*) and Microsoft Graph (GET). Each source is optional. #>
    [CmdletBinding()]
    param([string[]] $UserPrincipalName, [int] $LookbackDays = 14)
    $data = @{}
    foreach ($n in $script:MTHDatasets) { $data[$n] = @() }

    if (Get-Command Get-EXOMailbox -ErrorAction SilentlyContinue) {
        $mbx = if ($UserPrincipalName) { $UserPrincipalName | ForEach-Object { Get-EXOMailbox -Identity $_ -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward } }
        else { Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward }
        $data.mailboxes = @($mbx | Select-Object UserPrincipalName, PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward | ConvertTo-MTHObject)
        $i = 0
        $rules = foreach ($m in $data.mailboxes) {
            $i++
            Write-Progress -Activity 'Reading inbox rules' -Status $m.UserPrincipalName -PercentComplete (100 * $i / [math]::Max(1, $data.mailboxes.Count))
            Get-InboxRule -Mailbox $m.UserPrincipalName -ErrorAction SilentlyContinue |
                Select-Object Name, Identity, MailboxOwnerId, Enabled, Description, DeleteMessage, SoftDeleteMessage, MarkAsRead, MoveToFolder,
                ForwardTo, ForwardAsAttachmentTo, RedirectTo, SubjectContainsWords, SubjectOrBodyContainsWords, BodyContainsWords,
                FromAddressContainsWords, From, StopProcessingRules |
                ForEach-Object { $_ | Add-Member -NotePropertyName Mailbox -NotePropertyValue $m.UserPrincipalName -PassThru -Force }
        }
        Write-Progress -Activity 'Reading inbox rules' -Completed
        $data.inboxRules = @($rules | ConvertTo-MTHObject)
        $data.mailboxPermissions = @($data.mailboxes | ForEach-Object { Get-EXOMailboxPermission -Identity $_.UserPrincipalName -ErrorAction SilentlyContinue } |
                Select-Object Identity, User, AccessRights, IsInherited, Deny | ConvertTo-MTHObject)
        $data.recipientPermissions = @($data.mailboxes | ForEach-Object { Get-EXORecipientPermission -Identity $_.UserPrincipalName -ErrorAction SilentlyContinue } |
                Select-Object Identity, Trustee, AccessRights | ConvertTo-MTHObject)
        if (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue) {
            $data.acceptedDomains = @(Get-AcceptedDomain | ForEach-Object { [string]$_.DomainName })
        }
    }
    else { Write-Warning 'Not connected to Exchange Online (Connect-ExchangeOnline): inbox rules, forwarding and delegation are skipped.' }

    if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
        $get = {
            param($uri)
            $next = $uri
            while ($next) {
                $r = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable -ErrorAction Stop
                foreach ($v in @($r['value'])) { $v | ConvertTo-MTHObject }
                $next = $r['@odata.nextLink']
            }
        }
        try {
            $data.oauthGrants = @(& $get '/v1.0/oauth2PermissionGrants')
            $ids = @($data.oauthGrants | ForEach-Object clientId | Select-Object -Unique)
            $data.servicePrincipals = @($ids | ForEach-Object { Invoke-MgGraphRequest -Method GET -Uri "/v1.0/servicePrincipals/$($_)?`$select=id,displayName,appId,verifiedPublisher" -OutputType Hashtable | ConvertTo-MTHObject })
            $pids = @($data.oauthGrants | Where-Object { $_.principalId } | ForEach-Object principalId | Select-Object -Unique)
            $data.users = @($pids | ForEach-Object { Invoke-MgGraphRequest -Method GET -Uri "/v1.0/users/$($_)?`$select=id,userPrincipalName" -OutputType Hashtable | ConvertTo-MTHObject })
        }
        catch { Write-Warning "OAuth grants unavailable: $($_.Exception.Message)" }
        try {
            $since = (Get-Date).ToUniversalTime().AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $filter = [uri]::EscapeDataString("loggedByService eq 'Authentication Methods' and activityDateTime ge $since")
            $data.authMethodChanges = @(& $get "/v1.0/auditLogs/directoryAudits?`$filter=$filter" | ForEach-Object {
                    [pscustomobject]@{
                        activityDateTime        = $_.activityDateTime
                        activityDisplayName     = $_.activityDisplayName
                        targetUserPrincipalName = (Get-PV (@($_.targetResources)[0]) 'userPrincipalName' '')
                        ipAddress               = (Get-PV $_ 'initiatedBy.user.ipAddress' '')
                    }
                })
        }
        catch { Write-Warning "Directory audits unavailable: $($_.Exception.Message)" }
    }
    else { Write-Warning 'Not connected to Microsoft Graph (Connect-MgGraph): OAuth consent and MFA-change checks are skipped.' }
    $data
}
