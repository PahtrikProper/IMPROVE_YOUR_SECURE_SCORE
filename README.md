
---

## **Required PowerShell Modules**

You’ll need the following modules. **All should be installed and imported in your session.**

1. **Microsoft.Graph**
   (For Entra ID/Azure AD/Conditional Access/Identity Protection/Authorization Policies/etc.)

   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser
   ```

2. **ExchangeOnlineManagement**
   (For Exchange Online: mailboxes, anti-phish, safe links, transport rules, spam/malware filter policies, audit logs, OWA, MailTips, etc.)

   ```powershell
   Install-Module ExchangeOnlineManagement -Scope CurrentUser
   ```

3. **AzureAD** or **AzureAD.Standard.Preview**
   (For legacy Azure AD tasks not in Graph, including some PIM and group settings)

   ```powershell
   Install-Module AzureAD -Scope CurrentUser
   ```

   *(Some newer tenants may only support Graph for most tasks; if a command fails, check for Graph equivalents.)*

4. **MSOnline**
   (Occasionally needed for older password and group policy settings)

   ```powershell
   Install-Module MSOnline -Scope CurrentUser
   ```

   *(Most script logic will work with just Graph and ExchangeOnline, but some rare org settings need this.)*

5. **SkypeOnlineConnector**
   (For Teams meeting policy configuration, some settings can also be managed via Teams PowerShell.)

   ```powershell
   Install-Module MicrosoftTeams -Scope CurrentUser
   ```

6. **SharePointPnPPowerShellOnline** or **SharePoint Online Management Shell**
   (For SharePoint/OneDrive tenant settings)

   ```powershell
   Install-Module SharePointPnPPowerShellOnline -Scope CurrentUser
   # or
   Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
   ```

---

## **How to Connect**

**You must connect to each relevant service** at the beginning of your session:

### **Connect to Microsoft Graph**

```powershell
Connect-MgGraph -Scopes "User.Read.All, Group.ReadWrite.All, Policy.ReadWrite.ConditionalAccess, Directory.ReadWrite.All, AuditLog.Read.All, IdentityRiskEvent.Read.All, Application.ReadWrite.All"
```

### **Connect to Exchange Online**

```powershell
Connect-ExchangeOnline
```

### **Connect to Azure AD**

```powershell
Connect-AzureAD
```

### **Connect to Microsoft Teams**

```powershell
Connect-MicrosoftTeams
```

### **Connect to SharePoint Online**

```powershell
Connect-SPOService -Url https://<yourtenant>-admin.sharepoint.com
```

---

## **How to Structure Your Script**

At the **top of your script**, include something like:

```powershell
# Install and Import Modules (if needed)
Import-Module Microsoft.Graph
Import-Module ExchangeOnlineManagement
Import-Module AzureAD
Import-Module MicrosoftTeams
Import-Module Microsoft.Online.SharePoint.PowerShell

# Connect to Services (prompts for sign-in)
Connect-MgGraph -Scopes "User.Read.All, Group.ReadWrite.All, Policy.ReadWrite.ConditionalAccess, Directory.ReadWrite.All, AuditLog.Read.All, IdentityRiskEvent.Read.All, Application.ReadWrite.All"
Connect-ExchangeOnline
Connect-AzureAD
Connect-MicrosoftTeams
Connect-SPOService -Url https://<yourtenant>-admin.sharepoint.com
```

*(Replace `<yourtenant>` with your tenant name.)*

---

### **Tips**

* You may only need to install modules the **first time**—after that, `Import-Module` is sufficient.
* Some modules (like `AzureAD` and `MSOnline`) are legacy—prefer Graph where possible.
* Run your script in an **elevated PowerShell window** if you hit permission issues.
* **Modern Authentication** is required for all connections.

---

## **Summary Table**

| Service                    | Module(s)                                                               | Connect Command                                               |
| -------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------- |
| Microsoft Graph (Entra ID) | Microsoft.Graph                                                         | Connect-MgGraph -Scopes ...                                   |
| Exchange Online            | ExchangeOnlineManagement                                                | Connect-ExchangeOnline                                        |
| Azure AD                   | AzureAD                                                                 | Connect-AzureAD                                               |
| Microsoft Teams            | MicrosoftTeams                                                          | Connect-MicrosoftTeams                                        |
| SharePoint Online/OneDrive | Microsoft.Online.SharePoint.PowerShell or SharePointPnPPowerShellOnline | Connect-SPOService -Url https://<tenant>-admin.sharepoint.com |

---


If you want error handling (e.g., skip checks if not connected), or want to **automate module checking/installing**, let me know!
