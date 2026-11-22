function Get-MTHIncidentChecklist {
    <#
    .SYNOPSIS
        Prints a BEC containment checklist with the exact commands for one mailbox.
    .DESCRIPTION
        This function only returns text. Nothing is executed - review and run each step deliberately.
    .EXAMPLE
        Get-MTHIncidentChecklist -UserPrincipalName cfo@contoso.com
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string] $UserPrincipalName)
    $u = $UserPrincipalName
    @(
        "# BEC containment checklist for $u (review before running anything)"
        ''
        '## 1. Contain'
        "Revoke-MgUserSignInSession -UserId '$u'                     # kill refresh tokens / sessions"
        "Update-MgUser -UserId '$u' -AccountEnabled:`$false           # if takeover is confirmed"
        '# Reset the password out-of-band and require MFA re-registration (Entra > user > Authentication methods)'
        ''
        '## 2. Remove persistence'
        "Get-InboxRule -Mailbox '$u' | Format-List Name,Description    # export first, then Remove-InboxRule the malicious ones"
        "Set-Mailbox -Identity '$u' -ForwardingSmtpAddress `$null -ForwardingAddress `$null -DeliverToMailboxAndForward `$false"
        "Get-EXOMailboxPermission -Identity '$u' | Where-Object { -not `$_.IsInherited }   # remove unexpected FullAccess"
        "Get-MgUserAuthenticationMethod -UserId '$u'                 # delete authenticator/phone the user did not add"
        '# Revoke unknown OAuth grants: Get-MgOauth2PermissionGrant -Filter "principalId eq ''<user-object-id>''"'
        ''
        '## 3. Scope'
        "Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date) -UserIds '$u' -ResultSize 5000"
        '# Sign-in logs: filter user, look for new countries / IPs / legacy clients (see entra-signin-analyzer)'
        '# Message trace: mail SENT by the user since first suspicious sign-in (invoice/payment-change requests to clients?)'
        '# MailItemsAccessed (E5/Audit Premium) to determine what was read'
        ''
        '## 4. Notify and recover'
        '# Warn finance / recent correspondents about fraudulent payment-change requests'
        '# Recall or follow up on any outbound fraudulent mail; contact the bank immediately for wires'
        '# Document timeline, IOCs (IPs, rule names, app IDs) and add detections (kql-detection-library KDL-0015/0016)'
    )
}
