# Active Directory Practice Drills

Hands-on exercises to build fluency with Active Directory administration, investigation, and security. Each drill follows:
1. **DO** — Perform a task on ADDC01 or Target-PC
2. **VERIFY** — Confirm what you did using PowerShell or ADUC
3. **UNDERSTAND** — Answer questions to build analyst thinking

> All PowerShell commands run on **ADDC01** unless stated otherwise.
> Open **PowerShell as Administrator** and import the AD module: `Import-Module ActiveDirectory`

---

## Level 1: AD Administration Basics (Know Your Domain)

### Drill 1.1 — List All Domain Users

**DO:** Run this PowerShell command:
```powershell
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled
```

**VERIFY:** Cross-check the output with **Active Directory Users and Computers** (ADUC). Open Server Manager → Tools → ADUC. Browse the OUs.

**UNDERSTAND:**
- How many users are in your domain?
- Which are enabled vs disabled?
- What OU is each user in?

---

### Drill 1.2 — Get Detailed User Info

**DO:** Look up Jenny Smith's full account details:
```powershell
Get-ADUser -Identity jsmith -Properties *
```

**VERIFY:** In ADUC, right-click jsmith → Properties. Compare each tab to the PowerShell output.

**UNDERSTAND:**
- When was the account created?
- When was the password last set?
- When was the last logon?
- Is the password set to expire?
- What groups is Jenny a member of?

<details>
<summary>Bonus: Get just the fields a SOC analyst cares about</summary>

```powershell
Get-ADUser -Identity jsmith -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, LockedOut, Enabled, MemberOf |
Select-Object Name, SamAccountName, Enabled, LockedOut, PasswordNeverExpires, PasswordLastSet, LastLogonDate, MemberOf
```
</details>

---

### Drill 1.3 — List All Groups and Their Members

**DO:** List all groups:
```powershell
Get-ADGroup -Filter * | Select-Object Name, GroupCategory, GroupScope
```

Then check who is in Domain Admins:
```powershell
Get-ADGroupMember "Domain Admins" | Select-Object Name, SamAccountName
```

**VERIFY:** In ADUC, navigate to the Users container. Right-click Domain Admins → Properties → Members tab.

**UNDERSTAND:**
- Who has Domain Admin privileges?
- What's the difference between a Security group and a Distribution group?
- What's the difference between Global, Domain Local, and Universal scope?

---

### Drill 1.4 — List All Computers in the Domain

**DO:**
```powershell
Get-ADComputer -Filter * -Properties LastLogonDate, OperatingSystem |
Select-Object Name, OperatingSystem, LastLogonDate, Enabled
```

**UNDERSTAND:**
- How many computers are joined to the domain?
- What operating systems are they running?
- Are any computers showing a stale LastLogonDate (haven't checked in recently)?

---

### Drill 1.5 — Check Account Lockout Status

**DO:** Find any locked-out accounts:
```powershell
Search-ADAccount -LockedOut
```

If none are locked, lock one intentionally by trying to log into Target-PC as jsmith with wrong passwords multiple times. Then run the command again.

**VERIFY:** In ADUC, find jsmith → Properties → Account tab. You should see the "Unlock account" checkbox is available.

**DO (Unlock):**
```powershell
Unlock-ADAccount -Identity jsmith
```

**UNDERSTAND:**
- How many failed attempts trigger a lockout? (Check with `Get-ADDefaultDomainPasswordPolicy`)
- How long does the lockout last?
- Why do SOC analysts need to know this?

---

## Level 2: AD Security Investigation (SOC Analyst Tasks)

### Drill 2.1 — Find Accounts with "Password Never Expires"

**DO:**
```powershell
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires |
Select-Object Name, SamAccountName, PasswordNeverExpires
```

**UNDERSTAND:**
- Are any accounts set to never expire their password?
- Why is this a security risk?
- In a real SOC, what would you recommend to remediate this?

---

### Drill 2.2 — Find Stale Accounts (Not Logged In Recently)

**DO:** Find users who haven't logged in within the last 30 days:
```powershell
$CutoffDate = (Get-Date).AddDays(-30)
Get-ADUser -Filter * -Properties LastLogonDate |
Where-Object { $_.LastLogonDate -lt $CutoffDate -and $_.Enabled -eq $true } |
Select-Object Name, SamAccountName, LastLogonDate
```

**UNDERSTAND:**
- Why are stale accounts dangerous?
- What should be done with accounts that haven't been used in 90+ days?
- How could an attacker exploit a stale account?

---

### Drill 2.3 — Audit Privileged Group Membership

**DO:** Check every sensitive group:
```powershell
$PrivGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators")

foreach ($group in $PrivGroups) {
    Write-Host "`n=== $group ===" -ForegroundColor Yellow
    Get-ADGroupMember $group -ErrorAction SilentlyContinue | Select-Object Name, SamAccountName
}
```

**UNDERSTAND:**
- How many accounts have elevated privileges?
- Should any of them be removed?
- What's the principle of least privilege, and does your domain follow it?
- What damage could a compromised Domain Admin account do?

---

### Drill 2.4 — Check Domain Password Policy

**DO:**
```powershell
Get-ADDefaultDomainPasswordPolicy
```

**UNDERSTAND:**
- What is the minimum password length?
- How often must passwords be changed?
- Is password complexity enabled?
- What is the lockout threshold and duration?
- How does this compare to NIST 800-63B recommendations? (Hint: NIST now recommends longer passwords over complexity, and no forced rotation)

---

### Drill 2.5 — Investigate a Specific User's Logon History

**DO:** Find all logon events for tsmith on the domain controller:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 100 |
Where-Object { $_.Message -match "tsmith" } |
Select-Object TimeCreated, Id, Message | Format-List
```

**UNDERSTAND:**
- When did tsmith last log on?
- What Logon Type was used? (2=interactive, 3=network, 10=RDP)
- From what workstation/IP did they log on?

---

## Level 3: AD Management Tasks (Build Skills)

### Drill 3.1 — Create a New User

**DO:** Create a test user via PowerShell:
```powershell
New-ADUser -Name "Test User" -SamAccountName "testuser" -UserPrincipalName "testuser@mydfir.local" -Path "OU=IT,DC=mydfir,DC=local" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Enabled $true
```

**VERIFY:**
```powershell
Get-ADUser -Identity testuser -Properties Created, MemberOf
```

Also check ADUC — the user should appear in the IT OU.

**UNDERSTAND:**
- What fields are required to create a user?
- What is a UPN (User Principal Name)?
- What does the `-Path` parameter control?

**CLEANUP:**
```powershell
Remove-ADUser -Identity testuser -Confirm:$false
```

---

### Drill 3.2 — Create an OU and Move Users

**DO:** Create a new OU:
```powershell
New-ADOrganizationalUnit -Name "Contractors" -Path "DC=mydfir,DC=local"
```

Create a user in that OU:
```powershell
New-ADUser -Name "Contractor One" -SamAccountName "contractor1" -Path "OU=Contractors,DC=mydfir,DC=local" -AccountPassword (ConvertTo-SecureString "C0ntract0r!" -AsPlainText -Force) -Enabled $true
```

**VERIFY:**
```powershell
Get-ADUser -Filter * -SearchBase "OU=Contractors,DC=mydfir,DC=local"
```

**UNDERSTAND:**
- What is an OU used for?
- How do OUs relate to Group Policy?
- When would you create a separate OU for contractors vs regular employees?

**CLEANUP:**
```powershell
Remove-ADUser -Identity contractor1 -Confirm:$false
Remove-ADOrganizationalUnit -Identity "OU=Contractors,DC=mydfir,DC=local" -Recursive -Confirm:$false
```

---

### Drill 3.3 — Create and Link a Group Policy Object

**DO:** Create a GPO that sets a login banner:

1. Open **Group Policy Management** (Server Manager → Tools → Group Policy Management)
2. Right-click your domain (mydfir.local) → **Create a GPO in this domain**
3. Name it: `Login Banner`
4. Right-click the new GPO → **Edit**
5. Navigate to: Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options
6. Find: **Interactive logon: Message title for users attempting to log on** → Set to: `MYDFIR Lab - Authorized Access Only`
7. Find: **Interactive logon: Message text for users attempting to log on** → Set to: `This system is for authorized users only. All activity is monitored.`
8. Close the editor
9. The GPO is linked to the domain — it will apply to all computers

**VERIFY:** On Target-PC, force a policy update:
```cmd
gpupdate /force
```

Lock the workstation and try to log back in — you should see the banner.

**UNDERSTAND:**
- What is a GPO?
- What's the difference between Computer Configuration and User Configuration?
- How long before a GPO takes effect without `gpupdate /force`?
- Why would a SOC team care about GPOs?

---

### Drill 3.4 — Add a User to a Group

**DO:** Add jsmith to the Domain Admins group (we'll remove it right after):
```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members jsmith
```

**VERIFY:**
```powershell
Get-ADGroupMember "Domain Admins" | Select-Object Name
```

**Now check Splunk** — this should generate Event ID 4728 or 4732:
```spl
index=endpoint EventCode=4728 OR EventCode=4732 earliest=-5m
```

**REMOVE IMMEDIATELY:**
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members jsmith -Confirm:$false
```

**UNDERSTAND:**
- What Event ID is generated when a user is added to a security group?
- Why is monitoring Domain Admins membership critical for SOC?
- How would you set up an alert for this in Splunk?

---

## Level 4: Security Hardening (Defend the Domain)

### Drill 4.1 — Enable Advanced Audit Policies

**DO:** Check current audit policy:
```cmd
auditpol /get /category:*
```

Enable recommended audit settings for SOC visibility:
```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

**VERIFY:**
```cmd
auditpol /get /category:"Logon/Logoff"
auditpol /get /category:"Account Management"
```

**UNDERSTAND:**
- What's the difference between basic and advanced audit policies?
- Why do you need "failure" auditing enabled?
- Which audit category detects Kerberoasting? (Directory Service Access)

---

### Drill 4.2 — Disable LLMNR (Common Hardening Step)

LLMNR is a name resolution protocol that attackers abuse for credential theft (Responder attacks).

**DO:** Create a GPO to disable it:

1. Group Policy Management → Create a GPO: `Disable LLMNR`
2. Edit → Computer Configuration → Administrative Templates → Network → DNS Client
3. **Turn off multicast name resolution** → Enabled
4. Link to domain

**VERIFY:** On Target-PC after `gpupdate /force`:
```cmd
gpresult /r | findstr "LLMNR"
```

**UNDERSTAND:**
- What is LLMNR?
- How do attackers exploit it? (Hint: Responder tool)
- What's the modern alternative? (DNS)

---

### Drill 4.3 — Review Domain Controller Security Logs

**DO:** Check for recent authentication anomalies on ADDC01:

```powershell
# Failed logons on the DC itself
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 20 |
Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[19].Value}} |
Format-Table -AutoSize

# Kerberos ticket requests (look for Kerberoasting)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} -MaxEvents 20 |
Select-Object TimeCreated, @{N='User';E={$_.Properties[0].Value}}, @{N='Service';E={$_.Properties[2].Value}} |
Format-Table -AutoSize

# Privileged group changes
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4728,4732,4756} -MaxEvents 20 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, @{N='Group';E={$_.Properties[2].Value}}, @{N='User';E={$_.Properties[0].Value}} |
Format-Table -AutoSize
```

**UNDERSTAND:**
- Are there any failed logon attempts on the DC? From where?
- Are there Kerberos ticket requests that look unusual?
- Has anyone been added to privileged groups recently?

---

## PowerShell AD Command Reference

| What You Want | Command |
|---------------|---------|
| List all users | `Get-ADUser -Filter *` |
| Get user details | `Get-ADUser -Identity username -Properties *` |
| Find locked accounts | `Search-ADAccount -LockedOut` |
| Unlock account | `Unlock-ADAccount -Identity username` |
| Reset password | `Set-ADAccountPassword -Identity username -Reset -NewPassword (ConvertTo-SecureString "NewP@ss!" -AsPlainText -Force)` |
| List all groups | `Get-ADGroup -Filter *` |
| Get group members | `Get-ADGroupMember "Group Name"` |
| Add to group | `Add-ADGroupMember -Identity "Group" -Members username` |
| Remove from group | `Remove-ADGroupMember -Identity "Group" -Members username` |
| List all computers | `Get-ADComputer -Filter *` |
| List all OUs | `Get-ADOrganizationalUnit -Filter *` |
| Check password policy | `Get-ADDefaultDomainPasswordPolicy` |
| Find stale users | `Get-ADUser -Filter * -Properties LastLogonDate \| Where {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}` |
| Find password never expires | `Get-ADUser -Filter {PasswordNeverExpires -eq $true}` |
| Force GP update (remote) | `Invoke-GPUpdate -Computer "Target-PC" -Force` |
| Search AD for text | `Get-ADUser -Filter {Name -like "*smith*"}` |

---

## Key Concepts to Know for SOC Interviews

| Concept | What It Is | Why SOC Cares |
|---------|-----------|---------------|
| **Kerberos** | AD's authentication protocol using tickets (TGT, TGS) | Kerberoasting, Golden/Silver Ticket attacks |
| **NTLM** | Legacy authentication using password hashes | Pass-the-Hash attacks |
| **LDAP** | Protocol for querying AD (port 389/636) | Enumeration, credential harvesting |
| **Group Policy (GPO)** | Centralized configuration management | Hardening, attack surface reduction |
| **Organizational Unit (OU)** | Container for organizing AD objects | GPO targeting, delegation |
| **Domain Admins** | Highest privilege group in a domain | #1 target for attackers |
| **KRBTGT** | Account used to encrypt Kerberos tickets | Golden Ticket attack uses this |
| **Service Account** | Account running services (often with SPNs) | Kerberoasting target |
| **SPN** | Service Principal Name — identifies a service | Kerberoasting enumeration |
| **LAPS** | Local Administrator Password Solution | Prevents lateral movement via shared local admin passwords |

---

## Recommended Next Steps

After completing these drills:

1. **Populate your domain** with realistic data using [BadBlood](https://github.com/davidprowe/BadBlood) — gives you hundreds of users/groups to audit
2. **Run PingCastle** against your DC for a security health report — then fix every finding
3. **TryHackMe rooms:** Active Directory Hardening, Investigating Windows
4. **CyberDefenders:** Blue team CTF challenges with AD investigation scenarios
5. **Study:** [AD Attack & Defense guide](https://github.com/infosecn1nja/AD-Attack-Defense) — the canonical resource
