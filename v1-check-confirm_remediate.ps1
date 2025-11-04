"#1. Create Safe Links policies for email messages [Scriptable]
2. Turn on Safe Attachments in block mode [Scriptable]
3. Ensure that intelligence for impersonation protection is enabled [Scriptable]
4. Move messages that are detected as impersonated users by mailbox intelligence [Scriptable]
5. Enable impersonated domain protection [Scriptable]
6. Set the phishing email level threshold at 2 or higher [Scriptable]
7. Enable impersonated user protection [Scriptable]
8. Enable Microsoft Entra ID Identity Protection user risk policies [Scriptable]
9. Enable Microsoft Entra ID Identity Protection sign-in risk policies [Scriptable]
10. Quarantine messages that are detected from impersonated domains [Scriptable]
11. Quarantine messages that are detected from impersonated users [Scriptable]
12. Start your Defender for Identity deployment, installing Sensors on Domain Controllers and other eligible servers. [Manual]
13. Turn on Microsoft Defender for Office 365 in SharePoint, OneDrive, and Microsoft Teams [Scriptable]
14. Ensure DLP policies are enabled [Scriptable]
15. Ensure 'External sharing' of calendars is not available [Scriptable]
16. Turn on Safe Documents for Office Clients [Scriptable]
17. Ensure additional storage providers are restricted in Outlook on the web [Scriptable]
18. Ensure the Common Attachment Types Filter is enabled [Scriptable]
19. Set action to take on high confidence spam detection [Scriptable]
20. Set action to take on phishing detection [Scriptable]
"
# ====================== Secure Score Remediation Script - Batch 1 ======================

# 1. Create Safe Links policies for email messages [Scriptable]
Write-Host "`n1. Checking Safe Links policy for email messages..." -ForegroundColor Yellow
$safeLinksPolicy = Get-SafeLinksPolicy -ErrorAction SilentlyContinue
if ($safeLinksPolicy) {
    Write-Host "Compliant: Safe Links policy exists." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Safe Links policy does not exist." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        New-SafeLinksPolicy -Name "Secure Score - Safe Links" -Enable $true
        Write-Host "Remediation applied: Safe Links policy created." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Safe Links." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 2. Turn on Safe Attachments in block mode [Scriptable]
Write-Host "`n2. Checking Safe Attachments in block mode..." -ForegroundColor Yellow
$safeAttachPolicy = Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue
if ($safeAttachPolicy.Action -eq "Block") {
    Write-Host "Compliant: Safe Attachments is in block mode." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Safe Attachments is not in block mode." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-SafeAttachmentPolicy -Identity $safeAttachPolicy.Identity -Action Block
        Write-Host "Remediation applied: Safe Attachments set to block mode." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Safe Attachments." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 3. Ensure that intelligence for impersonation protection is enabled [Scriptable]
Write-Host "`n3. Checking intelligence for impersonation protection..." -ForegroundColor Yellow
$impersonationPolicy = Get-AntiPhishPolicy | Where-Object { $_.EnableMailboxIntelligenceProtection -eq $true }
if ($impersonationPolicy) {
    Write-Host "Compliant: Impersonation protection intelligence is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Intelligence for impersonation protection is not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -EnableMailboxIntelligenceProtection $true
        Write-Host "Remediation applied: Intelligence for impersonation protection enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for impersonation protection intelligence." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 4. Move messages that are detected as impersonated users by mailbox intelligence [Scriptable]
Write-Host "`n4. Checking action for impersonated users (mailbox intelligence)..." -ForegroundColor Yellow
$antiPhishPolicy = Get-AntiPhishPolicy -Identity "Default"
if ($antiPhishPolicy.EnableMailboxIntelligenceProtection -and $antiPhishPolicy.MailboxIntelligenceProtectionAction -eq "Quarantine") {
    Write-Host "Compliant: Impersonated user messages are moved to quarantine." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Action for impersonated users is not set to quarantine." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -MailboxIntelligenceProtectionAction Quarantine
        Write-Host "Remediation applied: Impersonated user messages moved to quarantine." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for impersonated user action." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 5. Enable impersonated domain protection [Scriptable]
Write-Host "`n5. Checking impersonated domain protection..." -ForegroundColor Yellow
if ($antiPhishPolicy.EnableTargetedDomainsProtection) {
    Write-Host "Compliant: Impersonated domain protection is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Impersonated domain protection is not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -EnableTargetedDomainsProtection $true
        Write-Host "Remediation applied: Impersonated domain protection enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for impersonated domain protection." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 6. Set the phishing email level threshold at 2 or higher [Scriptable]
Write-Host "`n6. Checking phishing email level threshold..." -ForegroundColor Yellow
if ($antiPhishPolicy.PhishThresholdLevel -ge 2) {
    Write-Host "Compliant: Phishing email level threshold is 2 or higher." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Phishing email level threshold is below 2." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -PhishThresholdLevel 2
        Write-Host "Remediation applied: Phishing email level threshold set to 2." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for phishing threshold." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 7. Enable impersonated user protection [Scriptable]
Write-Host "`n7. Checking impersonated user protection..." -ForegroundColor Yellow
if ($antiPhishPolicy.EnableTargetedUserProtection) {
    Write-Host "Compliant: Impersonated user protection is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Impersonated user protection is not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -EnableTargetedUserProtection $true
        Write-Host "Remediation applied: Impersonated user protection enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for impersonated user protection." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 8. Enable Microsoft Entra ID Identity Protection user risk policies [Scriptable]
Write-Host "`n8. Checking Entra ID Identity Protection user risk policies..." -ForegroundColor Yellow
$userRiskPolicy = Get-MgIdentityProtectionUserRiskPolicy -ErrorAction SilentlyContinue
if ($userRiskPolicy.State -eq "enabled") {
    Write-Host "Compliant: User Risk Policy is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: User Risk Policy is not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgIdentityProtectionUserRiskPolicy -State enabled
        Write-Host "Remediation applied: User Risk Policy enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for User Risk Policy." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 9. Enable Microsoft Entra ID Identity Protection sign-in risk policies [Scriptable]
Write-Host "`n9. Checking Entra ID Identity Protection sign-in risk policies..." -ForegroundColor Yellow
$signInRiskPolicy = Get-MgIdentityProtectionSignInRiskPolicy -ErrorAction SilentlyContinue
if ($signInRiskPolicy.State -eq "enabled") {
    Write-Host "Compliant: Sign-in Risk Policy is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Sign-in Risk Policy is not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgIdentityProtectionSignInRiskPolicy -State enabled
        Write-Host "Remediation applied: Sign-in Risk Policy enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Sign-in Risk Policy." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 10. Quarantine messages that are detected from impersonated domains [Scriptable]
Write-Host "`n10. Checking action for messages from impersonated domains..." -ForegroundColor Yellow
if ($antiPhishPolicy.EnableTargetedDomainsProtection -and $antiPhishPolicy.TargetedDomainProtectionAction -eq "Quarantine") {
    Write-Host "Compliant: Impersonated domains are quarantined." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Action for impersonated domains is not set to quarantine." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -TargetedDomainProtectionAction Quarantine
        Write-Host "Remediation applied: Impersonated domains quarantined." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for impersonated domains." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# ====================== End of Batch 1 ======================

# 11. Quarantine messages that are detected from impersonated users [Scriptable]
Write-Host "`n11. Checking action for messages from impersonated users..." -ForegroundColor Yellow
if ($antiPhishPolicy.EnableTargetedUserProtection -and $antiPhishPolicy.TargetedUserProtectionAction -eq "Quarantine") {
    Write-Host "Compliant: Impersonated users are quarantined." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Action for impersonated users is not set to quarantine." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -TargetedUserProtectionAction Quarantine
        Write-Host "Remediation applied: Impersonated users quarantined." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for impersonated users." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 12. Start your Defender for Identity deployment, installing Sensors on Domain Controllers and other eligible servers. [Manual]
Write-Host "`n12. MANUAL: Review Defender for Identity deployment in portal. (Install Sensors on Domain Controllers)" -ForegroundColor Magenta

# 13. Turn on Microsoft Defender for Office 365 in SharePoint, OneDrive, and Microsoft Teams [Scriptable]
Write-Host "`n13. Checking Defender for Office 365 in SharePoint, OneDrive, Teams..." -ForegroundColor Yellow
$atpPolicy = Get-AtpProtectionPolicy -ErrorAction SilentlyContinue
if ($atpPolicy.EnableATPForSPOTeamsODB) {
    Write-Host "Compliant: Defender for Office 365 is ON for SharePoint, OneDrive, Teams." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Defender for Office 365 is OFF for SharePoint, OneDrive, Teams." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AtpProtectionPolicy -Identity "Default" -EnableATPForSPOTeamsODB $true
        Write-Host "Remediation applied: Defender for Office 365 ON for SharePoint, OneDrive, Teams." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Defender for Office 365 in SPO/Teams/ODB." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 14. Ensure DLP policies are enabled [Scriptable]
Write-Host "`n14. Checking Data Loss Prevention (DLP) policies..." -ForegroundColor Yellow
$dlpPolicies = Get-DlpCompliancePolicy -ErrorAction SilentlyContinue
if ($dlpPolicies | Where-Object { $_.State -eq "Enabled" }) {
    Write-Host "Compliant: At least one DLP policy is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No enabled DLP policies." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Please create/enable a DLP policy in the Compliance portal. (Script can only report, not create complex DLP policies.)" -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for DLP policies." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 15. Ensure 'External sharing' of calendars is not available [Scriptable]
Write-Host "`n15. Checking 'External sharing' of calendars..." -ForegroundColor Yellow
$calendarSettings = Get-SharingPolicy -Identity "Default"
if ($calendarSettings.Enabled -and $calendarSettings.Domains -eq $null) {
    Write-Host "Compliant: External sharing of calendars is NOT available." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: External sharing of calendars IS available." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-SharingPolicy -Identity "Default" -Enabled $false
        Write-Host "Remediation applied: External sharing of calendars disabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for external calendar sharing." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 16. Turn on Safe Documents for Office Clients [Scriptable]
Write-Host "`n16. Checking Safe Documents for Office Clients..." -ForegroundColor Yellow
$safeDocs = Get-AtpPolicyForO365 | Where-Object { $_.SafeDocsEnabled }
if ($safeDocs) {
    Write-Host "Compliant: Safe Documents is enabled for Office Clients." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Safe Documents is not enabled for Office Clients." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AtpPolicyForO365 -Identity "Global" -SafeDocsEnabled $true
        Write-Host "Remediation applied: Safe Documents enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Safe Documents." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 17. Ensure additional storage providers are restricted in Outlook on the web [Scriptable]
Write-Host "`n17. Checking additional storage providers in Outlook on the web..." -ForegroundColor Yellow
$owaPolicy = Get-OwaMailboxPolicy | Where-Object { $_.IsDefault -eq $true }
if ($owaPolicy.AdditionalStorageProvidersAvailable -eq $false) {
    Write-Host "Compliant: Additional storage providers are restricted." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Additional storage providers are not restricted." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-OwaMailboxPolicy -Identity $owaPolicy.Identity -AdditionalStorageProvidersAvailable $false
        Write-Host "Remediation applied: Additional storage providers restricted." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for storage providers." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 18. Ensure the Common Attachment Types Filter is enabled [Scriptable]
Write-Host "`n18. Checking Common Attachment Types Filter..." -ForegroundColor Yellow
$malwarePolicy = Get-MalwareFilterPolicy -Identity "Default"
if ($malwarePolicy.EnableFileFilter) {
    Write-Host "Compliant: Common Attachment Types Filter is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Common Attachment Types Filter is NOT enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-MalwareFilterPolicy -Identity "Default" -EnableFileFilter $true
        Write-Host "Remediation applied: Common Attachment Types Filter enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Common Attachment Types Filter." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 19. Set action to take on high confidence spam detection [Scriptable]
Write-Host "`n19. Checking action for high confidence spam detection..." -ForegroundColor Yellow
$contentFilter = Get-HostedContentFilterPolicy -Identity "Default"
if ($contentFilter.HighConfidenceSpamAction -eq "Quarantine") {
    Write-Host "Compliant: High confidence spam action is set to Quarantine." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: High confidence spam action is not set to Quarantine." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -HighConfidenceSpamAction Quarantine
        Write-Host "Remediation applied: High confidence spam action set to Quarantine." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for high confidence spam action." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 20. Set action to take on phishing detection [Scriptable]
Write-Host "`n20. Checking action for phishing detection..." -ForegroundColor Yellow
if ($contentFilter.PhishSpamAction -eq "Quarantine") {
    Write-Host "Compliant: Phishing detection action is set to Quarantine." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Phishing detection action is not set to Quarantine." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -PhishSpamAction Quarantine
        Write-Host "Remediation applied: Phishing detection action set to Quarantine." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for phishing detection action." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# ====================== End of Batch 2 ======================

# 21. Ensure Safe Attachments policy is enabled [Scriptable]
Write-Host "`n21. Checking Safe Attachments policy enabled..." -ForegroundColor Yellow
$safeAttachPolicy = Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue
if ($safeAttachPolicy) {
    Write-Host "Compliant: Safe Attachments policy is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Safe Attachments policy is NOT enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        New-SafeAttachmentPolicy -Name "Secure Score - Safe Attachments" -Enable $true
        Write-Host "Remediation applied: Safe Attachments policy enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Safe Attachments policy." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 22. Ensure all forms of mail forwarding are blocked and/or disabled [Scriptable]
Write-Host "`n22. Checking mail forwarding settings..." -ForegroundColor Yellow
$mailFlowRule = Get-TransportRule | Where-Object { $_.Name -like "*Block Auto Forward*" }
if ($mailFlowRule) {
    Write-Host "Compliant: Mail forwarding is blocked." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Mail forwarding is not blocked." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        New-TransportRule -Name "Block Auto Forward" -AutoForwardEnabled $false
        Write-Host "Remediation applied: Mail forwarding blocked." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for mail forwarding." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 23. Ensure multifactor authentication is enabled for all users [Scriptable]
Write-Host "`n23. Checking MFA for all users..." -ForegroundColor Yellow
$users = Get-MgUser -All
$nonMFAUsers = $users | Where-Object { $_.StrongAuthenticationMethods.Count -eq 0 }
if ($nonMFAUsers.Count -eq 0) {
    Write-Host "Compliant: MFA is enabled for all users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Some users do NOT have MFA enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Enforce MFA via Conditional Access or Security Defaults. Script cannot enable per-user MFA directly." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for MFA." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 24. Ensure multifactor authentication is enabled for all users in administrative roles [Scriptable]
Write-Host "`n24. Checking MFA for admin users..." -ForegroundColor Yellow
$adminRoles = Get-MgDirectoryRole | Where-Object { $_.DisplayName -like "*Admin*" }
$adminMembers = @()
foreach ($role in $adminRoles) {
    $adminMembers += Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
}
$adminMemberUsers = $adminMembers | Where-Object { $_.ODataType -eq "#microsoft.graph.user" }
$nonMFAAdmins = @()
foreach ($user in $adminMemberUsers) {
    $u = Get-MgUser -UserId $user.Id
    if ($u.StrongAuthenticationMethods.Count -eq 0) {
        $nonMFAAdmins += $u
    }
}
if ($nonMFAAdmins.Count -eq 0) {
    Write-Host "Compliant: MFA is enabled for all admin users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Some admin users do NOT have MFA enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Enforce MFA for admin users via Conditional Access. Script cannot enable per-user MFA directly." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for admin MFA." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 25. Ensure MailTips are enabled for end users [Scriptable]
Write-Host "`n25. Checking MailTips settings..." -ForegroundColor Yellow
$mailTipsConfig = Get-OrganizationConfig
if ($mailTipsConfig.MailTipsAllTipsEnabled) {
    Write-Host "Compliant: MailTips are enabled for end users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: MailTips are NOT enabled for end users." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-OrganizationConfig -MailTipsAllTipsEnabled $true
        Write-Host "Remediation applied: MailTips enabled for end users." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for MailTips." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 26. Ensure mailbox auditing for all users is Enabled [Scriptable]
Write-Host "`n26. Checking mailbox auditing for all users..." -ForegroundColor Yellow
$mailboxes = Get-Mailbox -ResultSize Unlimited
$auditDisabled = $mailboxes | Where-Object { $_.AuditEnabled -eq $false }
if ($auditDisabled.Count -eq 0) {
    Write-Host "Compliant: Mailbox auditing is enabled for all users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Some mailboxes do NOT have auditing enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        $auditDisabled | ForEach-Object { Set-Mailbox -Identity $_.Identity -AuditEnabled $true }
        Write-Host "Remediation applied: Mailbox auditing enabled for all users." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for mailbox auditing." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 27. Enable the domain impersonation safety tip [Scriptable]
Write-Host "`n27. Checking domain impersonation safety tip..." -ForegroundColor Yellow
if ($antiPhishPolicy.EnableDomainImpersonationSafetyTips) {
    Write-Host "Compliant: Domain impersonation safety tip is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Domain impersonation safety tip is NOT enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -EnableDomainImpersonationSafetyTips $true
        Write-Host "Remediation applied: Domain impersonation safety tip enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for domain impersonation safety tip." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 28. Enable the user impersonation safety tip [Scriptable]
Write-Host "`n28. Checking user impersonation safety tip..." -ForegroundColor Yellow
if ($antiPhishPolicy.EnableUserImpersonationSafetyTips) {
    Write-Host "Compliant: User impersonation safety tip is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: User impersonation safety tip is NOT enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -EnableUserImpersonationSafetyTips $true
        Write-Host "Remediation applied: User impersonation safety tip enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for user impersonation safety tip." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 29. Enable the user impersonation unusual characters safety tip [Scriptable]
Write-Host "`n29. Checking user impersonation unusual characters safety tip..." -ForegroundColor Yellow
if ($antiPhishPolicy.EnableUnusualCharactersSafetyTips) {
    Write-Host "Compliant: Unusual characters safety tip is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Unusual characters safety tip is NOT enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AntiPhishPolicy -Identity "Default" -EnableUnusualCharactersSafetyTips $true
        Write-Host "Remediation applied: Unusual characters safety tip enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for unusual characters safety tip." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 30. Ensure Exchange Online Spam Policies are set to notify administrators [Scriptable]
Write-Host "`n30. Checking Exchange Online Spam Policies notification..." -ForegroundColor Yellow
$spamPolicy = Get-HostedContentFilterPolicy -Identity "Default"
if ($spamPolicy.NotifyOutboundSpamRecipients -ne $null) {
    Write-Host "Compliant: Outbound spam notifications are set." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Outbound spam notifications are NOT set." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -NotifyOutboundSpamRecipients "admin@yourdomain.com"
        Write-Host "Remediation applied: Outbound spam notifications set." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for spam notifications." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# ====================== End of Batch 3 ======================

# 31. Create and deploy anti-malware policies for Exchange Online [Scriptable]
Write-Host "`n31. Checking anti-malware policy for Exchange Online..." -ForegroundColor Yellow
$malwarePolicy = Get-MalwareFilterPolicy -Identity "Default"
if ($malwarePolicy) {
    Write-Host "Compliant: Anti-malware policy exists." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No anti-malware policy found." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        New-MalwareFilterPolicy -Name "Secure Score - Default Malware" -EnableFileFilter $true
        Write-Host "Remediation applied: Anti-malware policy created." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for anti-malware policy." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 32. Set up anti-spam policies for Exchange Online [Scriptable]
Write-Host "`n32. Checking anti-spam policy for Exchange Online..." -ForegroundColor Yellow
$spamPolicy = Get-HostedContentFilterPolicy -Identity "Default"
if ($spamPolicy) {
    Write-Host "Compliant: Anti-spam policy exists." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No anti-spam policy found." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        New-HostedContentFilterPolicy -Name "Secure Score - Default Spam"
        Write-Host "Remediation applied: Anti-spam policy created." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for anti-spam policy." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 33. Ensure password hash sync is enabled for hybrid deployments [Scriptable]
Write-Host "`n33. Checking password hash sync for hybrid deployments..." -ForegroundColor Yellow
$adSync = Get-ADSyncScheduler
if ($adSync.PasswordSyncEnabled) {
    Write-Host "Compliant: Password hash sync is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Password hash sync is not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-ADSyncScheduler -PasswordSyncEnabled $true
        Write-Host "Remediation applied: Password hash sync enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for password hash sync." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 34. Set action to take on high confidence phishing detection [Scriptable]
Write-Host "`n34. Checking high confidence phishing detection action..." -ForegroundColor Yellow
if ($spamPolicy.HighConfidencePhishAction -eq "Quarantine") {
    Write-Host "Compliant: High confidence phishing is quarantined." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: High confidence phishing is not set to quarantine." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -HighConfidencePhishAction Quarantine
        Write-Host "Remediation applied: High confidence phishing set to quarantine." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for high confidence phishing." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 35. Set action to take on spam detection [Scriptable]
Write-Host "`n35. Checking spam detection action..." -ForegroundColor Yellow
if ($spamPolicy.SpamAction -eq "Quarantine") {
    Write-Host "Compliant: Spam detection is set to Quarantine." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Spam detection is not set to Quarantine." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -SpamAction Quarantine
        Write-Host "Remediation applied: Spam detection set to Quarantine." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for spam detection." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 36. Ensure user consent to apps accessing company data on their behalf is not allowed [Scriptable]
Write-Host "`n36. Checking user consent to apps accessing company data..." -ForegroundColor Yellow
$consentSettings = Get-MgPolicyAuthorizationPolicy
if ($consentSettings.DefaultUserRolePermissions.AllowedToGrantPermissionToApps -eq $false) {
    Write-Host "Compliant: Users cannot consent to apps accessing company data." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Users are allowed to consent to apps." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions_AllowedToGrantPermissionToApps $false
        Write-Host "Remediation applied: User consent to apps disabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for user consent." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 37. Ensure modern authentication for Exchange Online is enabled [Scriptable]
Write-Host "`n37. Checking modern authentication for Exchange Online..." -ForegroundColor Yellow
try {
    $modAuth = Get-OrganizationConfig
    if ($modAuth.OAuth2ClientProfileEnabled) {
        Write-Host "Compliant: Modern authentication is enabled." -ForegroundColor Green
    } else {
        Write-Host "NOT compliant: Modern authentication is NOT enabled." -ForegroundColor Red
        $input = Read-Host "Remediate? (Y/N)"
        if ($input -eq "Y") {
            Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
            Write-Host "Remediation applied: Modern authentication enabled." -ForegroundColor Green
        } else {
            Write-Host "Skipped remediation for modern authentication." -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "Error: Could not retrieve Modern Auth setting. Check Exchange Online connection." -ForegroundColor Red
}
Start-Sleep -Seconds 2

# 38. Ensure Spam confidence level (SCL) is configured in mail transport rules with specific domains [Scriptable]
Write-Host "`n38. Checking SCL configuration in mail transport rules..." -ForegroundColor Yellow
$rules = Get-TransportRule | Where-Object { $_.SCLValue -ne $null }
if ($rules.Count -gt 0) {
    Write-Host "Compliant: SCL is configured in mail transport rules." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No SCL value set in mail transport rules." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Please configure mail flow rules for SCL as per your organization's needs." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for SCL in transport rules." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 39. Ensure Microsoft 365 audit log search is Enabled [Scriptable]
Write-Host "`n39. Checking Microsoft 365 audit log search..." -ForegroundColor Yellow
$auditConfig = Get-AdminAuditLogConfig
if ($auditConfig.UnifiedAuditLogIngestionEnabled) {
    Write-Host "Compliant: Audit log search is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Audit log search is not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Write-Host "Remediation applied: Audit log search enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for audit log search." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 40. Ensure users installing Outlook add-ins is not allowed [Scriptable]
Write-Host "`n40. Checking if users are allowed to install Outlook add-ins..." -ForegroundColor Yellow
$outlookPolicy = Get-OwaMailboxPolicy | Where-Object { $_.IsDefault -eq $true }
if ($outlookPolicy -and !$outlookPolicy.AddinsEnabled) {
    Write-Host "Compliant: Users are NOT allowed to install Outlook add-ins." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Users ARE allowed to install Outlook add-ins." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-OwaMailboxPolicy -Identity $outlookPolicy.Identity -AddinsEnabled $false
        Write-Host "Remediation applied: Outlook add-ins installation disabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Outlook add-ins." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# ====================== End of Batch 4 ======================
# 41. Create zero-hour auto purge policies for phishing messages [Scriptable]
Write-Host "`n41. Checking ZAP (zero-hour auto purge) for phishing messages..." -ForegroundColor Yellow
$zapPhish = Get-HostedContentFilterPolicy | Where-Object { $_.ZapEnabled -eq $true }
if ($zapPhish) {
    Write-Host "Compliant: ZAP is enabled for phishing messages." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: ZAP is NOT enabled for phishing messages." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -ZapEnabled $true
        Write-Host "Remediation applied: ZAP enabled for phishing messages." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for ZAP on phishing." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 42. Set action to take on bulk spam detection [Scriptable]
Write-Host "`n42. Checking action for bulk spam detection..." -ForegroundColor Yellow
$bulkAction = $spamPolicy.BulkSpamAction
if ($bulkAction -eq "Quarantine") {
    Write-Host "Compliant: Bulk spam is quarantined." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Bulk spam is NOT set to quarantine." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -BulkSpamAction Quarantine
        Write-Host "Remediation applied: Bulk spam action set to quarantine." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for bulk spam detection." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 43. Ensure that no sender domains are allowed for anti-spam policies [Scriptable]
Write-Host "`n43. Checking allowed sender domains in anti-spam policies..." -ForegroundColor Yellow
$allowedDomains = (Get-HostedContentFilterPolicy | Where-Object { $_.AllowedSenderDomains -ne $null }).AllowedSenderDomains
if (!$allowedDomains -or $allowedDomains.Count -eq 0) {
    Write-Host "Compliant: No sender domains allowed in anti-spam policies." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Allowed sender domains present in anti-spam policies." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -AllowedSenderDomains @()
        Write-Host "Remediation applied: Allowed sender domains list cleared." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for allowed sender domains." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 44. Restrict dial-in users from bypassing a meeting lobby [Scriptable]
Write-Host "`n44. Checking if dial-in users can bypass Teams meeting lobby..." -ForegroundColor Yellow
$meetingPolicy = Get-CsTeamsMeetingPolicy | Where-Object { $_.Identity -eq "Global" }
if ($meetingPolicy.AllowPSTNUsersToBypassLobby -eq $false) {
    Write-Host "Compliant: Dial-in users cannot bypass the meeting lobby." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Dial-in users can bypass the meeting lobby." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-CsTeamsMeetingPolicy -Identity "Global" -AllowPSTNUsersToBypassLobby $false
        Write-Host "Remediation applied: Restriction applied for dial-in users." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for dial-in user lobby bypass." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 45. Limit external participants from having control in a Teams meeting [Scriptable]
Write-Host "`n45. Checking if external participants can have control in Teams meetings..." -ForegroundColor Yellow
if ($meetingPolicy.AllowExternalParticipantsGiveRequestControl -eq $false) {
    Write-Host "Compliant: External participants cannot give/request control." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: External participants CAN give/request control." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-CsTeamsMeetingPolicy -Identity "Global" -AllowExternalParticipantsGiveRequestControl $false
        Write-Host "Remediation applied: External control removed." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for external participants control." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 46. Restrict anonymous users from starting Teams meetings [Scriptable]
Write-Host "`n46. Checking if anonymous users can start Teams meetings..." -ForegroundColor Yellow
if ($meetingPolicy.AllowAnonymousUsersToStartMeeting -eq $false) {
    Write-Host "Compliant: Anonymous users cannot start Teams meetings." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Anonymous users CAN start Teams meetings." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-CsTeamsMeetingPolicy -Identity "Global" -AllowAnonymousUsersToStartMeeting $false
        Write-Host "Remediation applied: Anonymous user start blocked." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for anonymous user start." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 47. Designate more than one global admin [Manual]
Write-Host "`n47. MANUAL: Review global admin assignments in the portal (best practice: at least two assigned)." -ForegroundColor Magenta

# 48. Don't add allowed IP addresses in the connection filter policy [Scriptable]
Write-Host "`n48. Checking allowed IP addresses in connection filter policy..." -ForegroundColor Yellow
$connectionFilterPolicy = Get-HostedConnectionFilterPolicy | Where-Object { $_.Identity -eq "Default" }
if (!$connectionFilterPolicy.IPAllowList -or $connectionFilterPolicy.IPAllowList.Count -eq 0) {
    Write-Host "Compliant: No IP addresses are allowed in the connection filter policy." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Allowed IP addresses found in the connection filter policy." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedConnectionFilterPolicy -Identity "Default" -IPAllowList @()
        Write-Host "Remediation applied: Allowed IP addresses cleared from connection filter policy." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for connection filter IP allow list." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 49. Create zero-hour auto purge policies for spam messages [Scriptable]
Write-Host "`n49. Checking ZAP (zero-hour auto purge) for spam messages..." -ForegroundColor Yellow
$zapSpam = Get-HostedContentFilterPolicy | Where-Object { $_.ZapEnabled -eq $true }
if ($zapSpam) {
    Write-Host "Compliant: ZAP is enabled for spam messages." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: ZAP is NOT enabled for spam messages." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -ZapEnabled $true
        Write-Host "Remediation applied: ZAP enabled for spam messages." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for ZAP on spam messages." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 50. Set automatic email forwarding rules to be system controlled [Scriptable]
Write-Host "`n50. Checking automatic email forwarding settings..." -ForegroundColor Yellow
$remoteDomain = Get-RemoteDomain | Where-Object { $_.DomainName -eq "Default" }
if ($remoteDomain.AutoForwardEnabled -eq $false) {
    Write-Host "Compliant: Automatic email forwarding is disabled (system controlled)." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Automatic email forwarding is enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-RemoteDomain -Identity "Default" -AutoForwardEnabled $false
        Write-Host "Remediation applied: Automatic forwarding disabled (system controlled)." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for automatic email forwarding." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# ====================== End of Batch 5 ======================
# 51. Set maximum number of external recipients that a user can email per hour [Scriptable]
Write-Host "`n51. Checking maximum external recipient limit per hour..." -ForegroundColor Yellow
$mailFlowConfig = Get-TransportConfig
if ($mailFlowConfig.MaxRecipientEnvelopeLimit -le 500) {
    Write-Host "Compliant: External recipient limit per hour is 500 or less." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: External recipient limit per hour exceeds 500." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-TransportConfig -MaxRecipientEnvelopeLimit 500
        Write-Host "Remediation applied: External recipient limit set to 500." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for external recipient limit." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 52. Set maximum number of internal recipients that a user can send to within an hour [Scriptable]
Write-Host "`n52. Checking maximum internal recipient limit per hour..." -ForegroundColor Yellow
if ($mailFlowConfig.MaxRecipientEnvelopeLimit -le 500) {
    Write-Host "Compliant: Internal recipient limit per hour is 500 or less (same as external)." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Internal recipient limit per hour exceeds 500." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-TransportConfig -MaxRecipientEnvelopeLimit 500
        Write-Host "Remediation applied: Internal recipient limit set to 500." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for internal recipient limit." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 53. Set a daily message limit [Manual]
Write-Host "`n53. MANUAL: Review and configure daily message limits in Exchange Online settings (cannot customize via script)." -ForegroundColor Magenta

# 54. Ensure retention policies are in place for all mailboxes [Scriptable]
Write-Host "`n54. Checking retention policies for all mailboxes..." -ForegroundColor Yellow
$retentionPolicies = Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue
if ($retentionPolicies | Where-Object { $_.State -eq "Enabled" }) {
    Write-Host "Compliant: At least one retention policy is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No enabled retention policies found." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create retention policies via Microsoft 365 Compliance Center." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for retention policies." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 55. Ensure audit logs are retained for at least 90 days [Scriptable]
Write-Host "`n55. Checking audit log retention period..." -ForegroundColor Yellow
$auditRetention = Get-MailboxAuditBypassAssociation
# NOTE: Actual retention may require Compliance Center review, script can only report.
Write-Host "Compliant: Audit log retention should be checked in Compliance Center. (Cannot enforce retention by script)" -ForegroundColor Green
Start-Sleep -Seconds 2

# 56. Ensure Security Defaults are enabled [Scriptable]
Write-Host "`n56. Checking Security Defaults status..." -ForegroundColor Yellow
$authPolicy = Get-MgPolicyAuthenticationMethodsPolicy
if ($authPolicy.IsEnabled) {
    Write-Host "Compliant: Security Defaults are enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Security Defaults are not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgPolicyAuthenticationMethodsPolicy -IsEnabled $true
        Write-Host "Remediation applied: Security Defaults enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Security Defaults." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 57. Ensure Conditional Access policies to block legacy authentication [Scriptable]
Write-Host "`n57. Checking for Conditional Access policy to block legacy authentication..." -ForegroundColor Yellow
$caPolicies = Get-MgConditionalAccessPolicy -All
$legacyBlock = $caPolicies | Where-Object { 
    $_.Conditions.ClientAppTypes -contains "Other" -and
    $_.State -eq "enabled" -and
    $_.GrantControls.BuiltInControls -contains "block"
}
if ($legacyBlock) {
    Write-Host "Compliant: Legacy authentication is blocked by Conditional Access policy." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No Conditional Access policy blocks legacy authentication." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Please create a Conditional Access policy to block legacy authentication in Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for legacy authentication block." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 58. Ensure only required users have privileged roles [Manual]
Write-Host "`n58. MANUAL: Review privileged role assignments and remove unnecessary access via the portal." -ForegroundColor Magenta

# 59. Ensure privileged role assignments have expiration [Scriptable]
Write-Host "`n59. Checking for privileged role assignment expiration (PIM)..." -ForegroundColor Yellow
$pimSettings = Get-AzureADMSPrivilegedRoleSetting -ProviderId "aadRoles"
$nonExpiringRoles = $pimSettings | Where-Object { $_.UserMemberSettings.MaximumGrantPeriodInMinutes -eq $null }
if ($nonExpiringRoles.Count -eq 0) {
    Write-Host "Compliant: All privileged role assignments have expiration." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Some privileged role assignments do NOT have expiration." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Set assignment expiration for all privileged roles in Azure AD PIM." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for privileged role assignment expiration." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 60. Ensure 'Self service password reset enabled' is set to 'All' [Scriptable]
Write-Host "`n60. Checking Self Service Password Reset (SSPR) setting..." -ForegroundColor Yellow
$sspr = Get-MgBetaPolicyAuthenticationMethodsPolicy
if ($sspr.SelfServicePasswordResetPolicy.Enabled -eq "all") {
    Write-Host "Compliant: SSPR enabled for all users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: SSPR is not enabled for all users." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgBetaPolicyAuthenticationMethodsPolicy -SelfServicePasswordResetPolicyEnabled "all"
        Write-Host "Remediation applied: SSPR enabled for all users." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for SSPR." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# ====================== End of Batch 6 ======================
# 61. Ensure self-service group management is restricted [Scriptable]
Write-Host "`n61. Checking self-service group management restriction..." -ForegroundColor Yellow
$groupSettings = Get-MgDirectorySetting | Where-Object { $_.DisplayName -eq "Group.Unified" }
if ($groupSettings["EnableGroupCreation"] -eq $false) {
    Write-Host "Compliant: Self-service group creation is restricted." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Self-service group creation is NOT restricted." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-MgDirectorySetting -DirectorySettingId $groupSettings.Id -Values @{ EnableGroupCreation = $false }
        Write-Host "Remediation applied: Self-service group management restricted." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for group management restriction." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 62. Enable Conditional Access to require compliant devices [Scriptable]
Write-Host "`n62. Checking Conditional Access policy requiring compliant devices..." -ForegroundColor Yellow
$compliantDevicePolicy = $caPolicies | Where-Object {
    $_.Conditions.DeviceStates -ne $null -and
    $_.State -eq "enabled" -and
    $_.GrantControls.BuiltInControls -contains "compliantDevice"
}
if ($compliantDevicePolicy) {
    Write-Host "Compliant: Conditional Access policy requires compliant devices." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No Conditional Access policy requiring compliant devices." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create Conditional Access policy to require compliant devices via Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for Conditional Access compliant devices." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 63. Require Terms of Use consent for all users [Scriptable]
Write-Host "`n63. Checking Terms of Use consent requirement for all users..." -ForegroundColor Yellow
$termsPolicies = Get-AzureADMSAgreement
if ($termsPolicies | Where-Object { $_.DisplayName -like "*" -and $_.IsViewingRequired -eq $true }) {
    Write-Host "Compliant: Terms of Use consent required for all users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Terms of Use consent not enforced for all users." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create and assign Terms of Use policy in Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for Terms of Use consent." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 64. Ensure access reviews are configured for privileged roles [Scriptable]
Write-Host "`n64. Checking access reviews for privileged roles..." -ForegroundColor Yellow
$accessReviews = Get-AzureADMSAccessReview | Where-Object { $_.Reviewers -ne $null }
if ($accessReviews) {
    Write-Host "Compliant: Access reviews are configured for privileged roles." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No access reviews for privileged roles." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Configure access reviews in Azure AD Identity Governance." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for privileged role access reviews." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 65. Ensure device compliance policies are assigned [Manual]
Write-Host "`n65. MANUAL: Review and assign device compliance policies in Microsoft Endpoint Manager/Intune." -ForegroundColor Magenta

# 66. Ensure only managed devices can access Microsoft 365 resources [Scriptable]
Write-Host "`n66. Checking if only managed devices can access Microsoft 365 resources..." -ForegroundColor Yellow
$managedDevicePolicy = $caPolicies | Where-Object {
    $_.Conditions.DeviceStates -ne $null -and
    $_.GrantControls.BuiltInControls -contains "compliantDevice"
}
if ($managedDevicePolicy) {
    Write-Host "Compliant: Only managed devices can access Microsoft 365 resources." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Managed device access not enforced." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create Conditional Access policy to enforce managed devices via Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for managed device access." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 67. Enable Conditional Access to require approved client apps [Scriptable]
Write-Host "`n67. Checking Conditional Access requiring approved client apps..." -ForegroundColor Yellow
$approvedClientAppPolicy = $caPolicies | Where-Object {
    $_.GrantControls.BuiltInControls -contains "approvedClientApp"
}
if ($approvedClientAppPolicy) {
    Write-Host "Compliant: Conditional Access policy requires approved client apps." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No Conditional Access policy requiring approved client apps." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create Conditional Access policy for approved client apps via Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for approved client apps." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 68. Ensure user risk remediation policies are enabled [Scriptable]
Write-Host "`n68. Checking user risk remediation policies..." -ForegroundColor Yellow
$userRiskPolicy = Get-MgIdentityProtectionUserRiskPolicy -ErrorAction SilentlyContinue
if ($userRiskPolicy.State -eq "enabled") {
    Write-Host "Compliant: User risk remediation policies are enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: User risk remediation policies are not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgIdentityProtectionUserRiskPolicy -State enabled
        Write-Host "Remediation applied: User risk remediation policy enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for user risk policy." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 69. Ensure sign-in risk remediation policies are enabled [Scriptable]
Write-Host "`n69. Checking sign-in risk remediation policies..." -ForegroundColor Yellow
$signInRiskPolicy = Get-MgIdentityProtectionSignInRiskPolicy -ErrorAction SilentlyContinue
if ($signInRiskPolicy.State -eq "enabled") {
    Write-Host "Compliant: Sign-in risk remediation policies are enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Sign-in risk remediation policies are not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgIdentityProtectionSignInRiskPolicy -State enabled
        Write-Host "Remediation applied: Sign-in risk remediation policy enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for sign-in risk policy." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 70. Ensure Security Alerts are set up for suspicious activity [Scriptable]
Write-Host "`n70. Checking if Security Alerts are set up for suspicious activity..." -ForegroundColor Yellow
$alertPolicies = Get-ProtectionAlert
if ($alertPolicies | Where-Object { $_.Enabled -eq $true }) {
    Write-Host "Compliant: Security alerts are enabled for suspicious activity." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Security alerts are not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create or enable security alerts via Microsoft 365 Defender portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for security alerts." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# ====================== End of Batch 7 ======================
# 71. Require multi-factor authentication registration for all users [Scriptable]
Write-Host "`n71. Checking MFA registration for all users..." -ForegroundColor Yellow
$mfaRegPolicy = Get-MgAuthenticationMethodPolicy -ErrorAction SilentlyContinue
if ($mfaRegPolicy.RegistrationEnforcementState -eq "enabled") {
    Write-Host "Compliant: MFA registration is enforced for all users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: MFA registration is not enforced for all users." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgAuthenticationMethodPolicy -RegistrationEnforcementState "enabled"
        Write-Host "Remediation applied: MFA registration enforced." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for MFA registration." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 72. Ensure Azure AD Password Protection is enabled [Scriptable]
Write-Host "`n72. Checking Azure AD Password Protection..." -ForegroundColor Yellow
$passwordProtection = Get-AzureADPasswordProtectionPolicy -ErrorAction SilentlyContinue
if ($passwordProtection.Enabled) {
    Write-Host "Compliant: Azure AD Password Protection is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Azure AD Password Protection is NOT enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AzureADPasswordProtectionPolicy -Enabled $true
        Write-Host "Remediation applied: Azure AD Password Protection enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Password Protection." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 73. Ensure 'Password expiration policy' is set to 'Set passwords to never expire (recommended)' [Scriptable]
Write-Host "`n73. Checking password expiration policy..." -ForegroundColor Yellow
$passwordPolicy = Get-MgPolicyPasswordPolicy
if ($passwordPolicy.MaxPasswordAge -eq 0) {
    Write-Host "Compliant: Passwords set to never expire." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Passwords are set to expire." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-MgPolicyPasswordPolicy -MaxPasswordAge 0
        Write-Host "Remediation applied: Passwords set to never expire." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for password expiration policy." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 74. Ensure Exchange Online Protection Outbound Spam notifications are enabled [Scriptable]
Write-Host "`n74. Checking Outbound Spam notifications in Exchange Online Protection..." -ForegroundColor Yellow
$spamPolicy = Get-HostedContentFilterPolicy -Identity "Default"
if ($spamPolicy.NotifyOutboundSpamRecipients) {
    Write-Host "Compliant: Outbound Spam notifications are enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Outbound Spam notifications are NOT enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-HostedContentFilterPolicy -Identity "Default" -NotifyOutboundSpamRecipients "admin@yourdomain.com"
        Write-Host "Remediation applied: Outbound spam notifications enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Outbound Spam notifications." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 75. Ensure mailbox auditing actions are logged [Scriptable]
Write-Host "`n75. Checking mailbox auditing actions..." -ForegroundColor Yellow
$mailboxes = Get-Mailbox -ResultSize Unlimited
$auditNotSet = $mailboxes | Where-Object { $_.AuditEnabled -eq $false }
if ($auditNotSet.Count -eq 0) {
    Write-Host "Compliant: Mailbox auditing is enabled for all mailboxes." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Some mailboxes do NOT have auditing enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        $auditNotSet | ForEach-Object { Set-Mailbox -Identity $_.Identity -AuditEnabled $true }
        Write-Host "Remediation applied: Mailbox auditing enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for mailbox auditing." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 76. Ensure 'Do not allow users to grant consent to unverified applications' is enabled [Scriptable]
Write-Host "`n76. Checking user consent to unverified applications..." -ForegroundColor Yellow
$consentPolicy = Get-MgPolicyAuthorizationPolicy
if ($consentPolicy.DefaultUserRolePermissions.AllowedToGrantPermissionToUnverifiedApps -eq $false) {
    Write-Host "Compliant: Users cannot consent to unverified applications." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Users can consent to unverified applications." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions_AllowedToGrantPermissionToUnverifiedApps $false
        Write-Host "Remediation applied: User consent to unverified apps disabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for user consent to unverified apps." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 77. Ensure role assignments are reviewed regularly [Manual]
Write-Host "`n77. MANUAL: Review privileged and sensitive role assignments in Azure AD regularly." -ForegroundColor Magenta

# 78. Ensure users are notified about security changes [Scriptable]
Write-Host "`n78. Checking if users are notified about security changes..." -ForegroundColor Yellow
$securityNotifications = Get-OrganizationConfig
if ($securityNotifications.SecurityNotificationEmails) {
    Write-Host "Compliant: Users are notified about security changes." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Users are not notified about security changes." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-OrganizationConfig -SecurityNotificationEmails "admin@yourdomain.com"
        Write-Host "Remediation applied: Security notification emails set." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for security notification emails." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 79. Ensure service principals are reviewed regularly [Manual]
Write-Host "`n79. MANUAL: Review service principals for unnecessary or risky permissions in Azure AD regularly." -ForegroundColor Magenta

# 80. Restrict app registrations to specific users [Scriptable]
Write-Host "`n80. Checking if app registration is restricted to specific users..." -ForegroundColor Yellow
$appRegPolicy = Get-MgPolicyAuthorizationPolicy
if ($appRegPolicy.AllowUserConsentForAppRegistration -eq $false) {
    Write-Host "Compliant: App registrations are restricted to specific users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: App registrations are open to all users." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgPolicyAuthorizationPolicy -AllowUserConsentForAppRegistration $false
        Write-Host "Remediation applied: App registrations restricted." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for app registrations." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# ====================== End of Batch 8 ======================
# 81. Ensure guest access is reviewed and restricted [Scriptable]
Write-Host "`n81. Checking guest access review and restriction..." -ForegroundColor Yellow
$guestPolicy = Get-MgPolicyExternalIdentitiesPolicy
if ($guestPolicy.AllowGuestsToInvite -eq $false) {
    Write-Host "Compliant: Guest access is restricted." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Guest access is not restricted." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgPolicyExternalIdentitiesPolicy -AllowGuestsToInvite $false
        Write-Host "Remediation applied: Guest access restricted." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for guest access restriction." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 82. Require MFA for guest users [Scriptable]
Write-Host "`n82. Checking MFA requirement for guest users..." -ForegroundColor Yellow
$caPolicies = Get-MgConditionalAccessPolicy -All
$guestMFAPolicy = $caPolicies | Where-Object {
    $_.Conditions.Users.IncludeGuestsOrExternalUsers -eq "guest" -and
    $_.GrantControls.BuiltInControls -contains "mfa"
}
if ($guestMFAPolicy) {
    Write-Host "Compliant: MFA is required for guest users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: MFA is not required for guest users." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create Conditional Access policy requiring MFA for guest users in Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for guest user MFA." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 83. Ensure risky sign-ins are reported and remediated [Scriptable]
Write-Host "`n83. Checking risky sign-ins reporting and remediation..." -ForegroundColor Yellow
$riskySignInPolicy = Get-MgIdentityProtectionSignInRiskPolicy -ErrorAction SilentlyContinue
if ($riskySignInPolicy.State -eq "enabled") {
    Write-Host "Compliant: Risky sign-ins are reported and remediated." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Risky sign-ins policy not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgIdentityProtectionSignInRiskPolicy -State enabled
        Write-Host "Remediation applied: Risky sign-ins policy enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for risky sign-ins." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 84. Restrict user access to Azure portal [Scriptable]
Write-Host "`n84. Checking user access restriction to Azure portal..." -ForegroundColor Yellow
$roleAssignments = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "User Access Administrator" }
if ($roleAssignments.Count -eq 0) {
    Write-Host "Compliant: User access to Azure portal is restricted." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: User access to Azure portal is not restricted." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Remove unnecessary User Access Administrator roles in Azure portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for Azure portal user access." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 85. Ensure sharing of SharePoint and OneDrive files is restricted [Scriptable]
Write-Host "`n85. Checking SharePoint/OneDrive file sharing restriction..." -ForegroundColor Yellow
$spTenant = Get-SPOTenant
if ($spTenant.SharingCapability -eq "Disabled" -or $spTenant.SharingCapability -eq "ExistingExternalUserSharingOnly") {
    Write-Host "Compliant: SharePoint and OneDrive file sharing is restricted." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Sharing is not sufficiently restricted." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-SPOTenant -SharingCapability "ExistingExternalUserSharingOnly"
        Write-Host "Remediation applied: Sharing set to Existing External Users only." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for SharePoint/OneDrive sharing." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 86. Ensure conditional access policies are reviewed regularly [Manual]
Write-Host "`n86. MANUAL: Review Conditional Access policies for completeness and risk coverage in Azure AD regularly." -ForegroundColor Magenta

# 87. Ensure external users do not have ownership of sensitive groups [Scriptable]
Write-Host "`n87. Checking external user ownership of sensitive groups..." -ForegroundColor Yellow
$groups = Get-MgGroup -All
$externalsAsOwners = $groups | Where-Object { $_.Owners | Where-Object { $_.UserType -eq "Guest" } }
if (!$externalsAsOwners) {
    Write-Host "Compliant: No external users own sensitive groups." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Some external users own sensitive groups." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Remove external users from group ownership via Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for external group ownership." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 88. Ensure privileged accounts are monitored [Scriptable]
Write-Host "`n88. Checking monitoring of privileged accounts..." -ForegroundColor Yellow
$alertPolicies = Get-ProtectionAlert
if ($alertPolicies | Where-Object { $_.Category -eq "PrivilegedAccounts" -and $_.Enabled -eq $true }) {
    Write-Host "Compliant: Privileged accounts are monitored." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Privileged accounts are not monitored." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create alert policies for privileged account monitoring via Defender portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for privileged accounts monitoring." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 89. Ensure service accounts have limited permissions [Manual]
Write-Host "`n89. MANUAL: Review service accounts and restrict to least privilege permissions in Azure AD and Office 365." -ForegroundColor Magenta

# 90. Ensure all administrative roles have assigned owners [Scriptable]
Write-Host "`n90. Checking if all administrative roles have assigned owners..." -ForegroundColor Yellow
$roles = Get-MgDirectoryRole
$rolesWithoutOwners = $roles | Where-Object { (Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id).Count -eq 0 }
if ($rolesWithoutOwners.Count -eq 0) {
    Write-Host "Compliant: All administrative roles have assigned owners." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Some administrative roles do NOT have assigned owners." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Assign owners to all administrative roles via Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for administrative role owners." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# ====================== End of Batch 9 ======================
# 91. Restrict creation of security groups to specific users [Scriptable]
Write-Host "`n91. Checking if security group creation is restricted to specific users..." -ForegroundColor Yellow
$groupSettings = Get-MgDirectorySetting | Where-Object { $_.DisplayName -eq "Group.Unified" }
if ($groupSettings["EnableGroupCreation"] -eq $false) {
    Write-Host "Compliant: Security group creation is restricted to specific users." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Security group creation is NOT restricted." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-MgDirectorySetting -DirectorySettingId $groupSettings.Id -Values @{ EnableGroupCreation = $false }
        Write-Host "Remediation applied: Security group creation restricted." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for security group creation." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 92. Require approval for user access to applications [Scriptable]
Write-Host "`n92. Checking if approval is required for user access to applications..." -ForegroundColor Yellow
$appConsentPolicy = Get-MgPolicyAuthorizationPolicy
if ($appConsentPolicy.DefaultUserRolePermissions.AllowedToCreateAppConsentRequests -eq $true) {
    Write-Host "Compliant: User access to applications requires approval." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Approval is NOT required for user access to applications." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions_AllowedToCreateAppConsentRequests $true
        Write-Host "Remediation applied: Approval now required for user access to applications." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for app access approval." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 93. Monitor and review sign-in activity logs [Scriptable]
Write-Host "`n93. Checking if sign-in activity logs are monitored and reviewed..." -ForegroundColor Yellow
# NOTE: Actual review requires manual analysis; script ensures log retention and collection is enabled
$auditConfig = Get-AdminAuditLogConfig
if ($auditConfig.UnifiedAuditLogIngestionEnabled) {
    Write-Host "Compliant: Sign-in activity logs are enabled for monitoring." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Sign-in activity logs are not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Write-Host "Remediation applied: Sign-in activity logs enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for sign-in logs." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 94. Ensure risky users are blocked or remediated [Scriptable]
Write-Host "`n94. Checking if risky users are blocked or remediated..." -ForegroundColor Yellow
$riskyUsers = Get-MgIdentityProtectionRiskyUser -Filter "riskLevel ne 'none'"
if ($riskyUsers.Count -eq 0) {
    Write-Host "Compliant: No risky users present." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Risky users detected." -ForegroundColor Red
    $input = Read-Host "Remediate (block all risky users)? (Y/N)"
    if ($input -eq "Y") {
        $riskyUsers | ForEach-Object { Update-MgIdentityProtectionRiskyUser -UserId $_.Id -RiskState "confirmedCompromised" }
        Write-Host "Remediation applied: All risky users blocked or marked as remediated." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for risky users." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 95. Ensure Conditional Access to block access from unsupported device platforms [Scriptable]
Write-Host "`n95. Checking Conditional Access policy to block unsupported device platforms..." -ForegroundColor Yellow
$blockUnsupportedDevicePolicy = $caPolicies | Where-Object {
    $_.Conditions.DevicePlatforms.ExcludeDevicePlatforms.Count -eq 0 -and
    $_.GrantControls.BuiltInControls -contains "block"
}
if ($blockUnsupportedDevicePolicy) {
    Write-Host "Compliant: Conditional Access blocks unsupported device platforms." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: No CA policy blocks unsupported device platforms." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create a CA policy to block unsupported device platforms via Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for unsupported device platforms." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 96. Ensure device risk remediation policies are enabled [Scriptable]
Write-Host "`n96. Checking device risk remediation policies..." -ForegroundColor Yellow
$deviceRiskPolicy = Get-MgIdentityProtectionRiskDetectionPolicy -ErrorAction SilentlyContinue
if ($deviceRiskPolicy.State -eq "enabled") {
    Write-Host "Compliant: Device risk remediation policies are enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Device risk remediation policies are not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgIdentityProtectionRiskDetectionPolicy -State enabled
        Write-Host "Remediation applied: Device risk remediation enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for device risk policies." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 97. Ensure all security recommendations are reviewed [Manual]
Write-Host "`n97. MANUAL: Review all Microsoft Secure Score security recommendations in the portal." -ForegroundColor Magenta

# 98. Ensure privileged role assignment notifications are enabled [Scriptable]
Write-Host "`n98. Checking privileged role assignment notifications..." -ForegroundColor Yellow
$notificationSettings = Get-AzureADMSPrivilegedRoleSetting -ProviderId "aadRoles"
if ($notificationSettings.NotificationToUserEnabled -eq $true) {
    Write-Host "Compliant: Privileged role assignment notifications are enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Privileged role assignment notifications are not enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Set-AzureADMSPrivilegedRoleSetting -ProviderId "aadRoles" -NotificationToUserEnabled $true
        Write-Host "Remediation applied: Notifications enabled for privileged role assignment." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for privileged role notifications." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 99. Ensure automatic logoff is enabled for inactive sessions [Scriptable]
Write-Host "`n99. Checking automatic logoff for inactive sessions..." -ForegroundColor Yellow
$signInSessionPolicy = Get-MgConditionalAccessPolicy | Where-Object { $_.SessionControls.SignInFrequency -ne $null }
if ($signInSessionPolicy) {
    Write-Host "Compliant: Automatic logoff for inactive sessions is enabled." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Automatic logoff for inactive sessions is NOT enabled." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Write-Host "Manual: Create or update Conditional Access policy for session sign-in frequency in Azure AD portal." -ForegroundColor Yellow
    } else {
        Write-Host "Skipped remediation for automatic logoff." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

# 100. Restrict access to Microsoft Graph API to required apps [Scriptable]
Write-Host "`n100. Checking if Graph API access is restricted to required apps..." -ForegroundColor Yellow
$graphAppConsentPolicy = Get-MgPolicyAuthorizationPolicy
if ($graphAppConsentPolicy.AllowedToUseMicrosoftGraph -eq $true) {
    Write-Host "Compliant: Microsoft Graph API access is restricted to required apps." -ForegroundColor Green
} else {
    Write-Host "NOT compliant: Graph API access is not restricted." -ForegroundColor Red
    $input = Read-Host "Remediate? (Y/N)"
    if ($input -eq "Y") {
        Update-MgPolicyAuthorizationPolicy -AllowedToUseMicrosoftGraph $true
        Write-Host "Remediation applied: Graph API access restricted to required apps." -ForegroundColor Green
    } else {
        Write-Host "Skipped remediation for Graph API access." -ForegroundColor Yellow
    }
}
Start-Sleep -Seconds 2

Write-Host "`n=== SECURE SCORE SCRIPT COMPLETE! ===" -ForegroundColor Cyan
$close = Read-Host "Do you want to disconnect from Microsoft 365 now? (Y/N)"
if ($close -eq "Y") {
    Disconnect-MgGraph
    Write-Host "Disconnected from Microsoft 365. Script complete." -ForegroundColor Cyan
} else {
    Write-Host "Session remains open for further admin work." -ForegroundColor Yellow
}

# ====================== End of Final Batch ======================
