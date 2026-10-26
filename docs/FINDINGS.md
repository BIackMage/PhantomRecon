# What the findings mean

Generated from the check catalog of Phantom Recon 1.0.0. Do not edit by hand; run `PhantomReconCli.exe --findings-md docs/FINDINGS.md` instead.

Each check below says what it looks at, why it matters, how to fix it and how to undo the fix. Commands marked elevated need a PowerShell or Command Prompt opened with Run as administrator.

Severity drives the hardening score: Critical counts 10, High 6, Medium 3, Low 1.

## Malware protection

### Antivirus real-time protection

- Check id: `def.realtime`
- Severity: Critical
- MITRE ATT&CK: T1562.001 Disable or Modify Tools
- CIS Controls v8: 10.1, 10.2
- CIS Windows Benchmark: Turn off real-time protection: Disabled

Real-time protection scans files as they are opened and downloaded. With it off, malware runs unchecked. Turning it off is one of the first things malware does.

**How to fix**

    Windows Security > Virus and threat protection > Manage settings > Real-time protection = On. Or elevated PowerShell:
      Set-MpPreference -DisableRealtimeMonitoring $false
    If another antivirus product is installed, Microsoft Defender steps back on purpose. Make sure that product is on and up to date.

**How to undo**

    Set-MpPreference -DisableRealtimeMonitoring $true   (temporary troubleshooting only)

### Tamper Protection

- Check id: `def.tamper`
- Severity: High
- MITRE ATT&CK: T1562.001 Disable or Modify Tools
- CIS Controls v8: 10.1

Tamper Protection stops programs, including malware running as administrator, from switching Microsoft Defender off or weakening its settings.

**How to fix**

    Windows Security > Virus and threat protection > Manage settings > Tamper Protection = On.
    It cannot be switched on from a script. That is on purpose.

**How to undo**

    Same switch, Off.

### Cloud-delivered protection

- Check id: `def.cloud`
- Severity: Medium
- MITRE ATT&CK: T1562.001 Disable or Modify Tools
- CIS Controls v8: 10.1
- CIS Windows Benchmark: Join Microsoft MAPS: Enabled

Cloud protection lets Microsoft Defender ask Microsoft about files it has not seen before. Most new malware is caught this way within seconds, long before a definition update arrives.

**How to fix**

    Windows Security > Virus and threat protection > Manage settings > Cloud-delivered protection = On. Or elevated PowerShell:
      Set-MpPreference -MAPSReporting Advanced

**How to undo**

    Set-MpPreference -MAPSReporting Disabled

### Antivirus definitions age

- Check id: `def.signatures`
- Severity: Medium
- MITRE ATT&CK: T1562.001 Disable or Modify Tools
- CIS Controls v8: 10.2

Microsoft Defender gets new malware definitions several times a day. Old definitions mean recent malware is invisible to it. This usually means Windows Update or Defender updates are blocked.

**How to fix**

    Elevated PowerShell:
      Update-MpSignature
    If that fails, check that Windows Update works and that no policy blocks Defender updates.

**How to undo**

    No undo needed.

### Antivirus exclusions

- Check id: `def.exclusions`
- Severity: High
- MITRE ATT&CK: T1562.001 Disable or Modify Tools
- CIS Controls v8: 10.1

An exclusion tells Microsoft Defender never to scan a folder, file type or process. Attackers add exclusions for their own folders so their tools are never looked at. Every exclusion should be one you added on purpose.

**How to fix**

    Remove each exclusion you do not recognise (elevated PowerShell):
      Remove-MpPreference -ExclusionPath 'C:\the\path'
      Remove-MpPreference -ExclusionExtension '.ext'
      Remove-MpPreference -ExclusionProcess 'name.exe'
    Then run a full scan:
      Start-MpScan -ScanType FullScan

**How to undo**

    Add-MpPreference -ExclusionPath 'C:\the\path'   (same pattern for -ExclusionExtension and -ExclusionProcess)

### Attack Surface Reduction rules

- Check id: `def.asr`
- Severity: Medium
- CIS Controls v8: 10.5
- CIS Windows Benchmark: Configure Attack Surface Reduction rules: Enabled

Attack Surface Reduction rules block the tricks malware uses most: Office starting other programs, scripts launching downloaded programs, credential theft from lsass.exe. They are off by default.

**How to fix**

    Start with the rule that blocks credential theft from LSASS. It almost never breaks anything (elevated PowerShell):
      Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
    For other rules, use AuditMode first and read Event Viewer > Microsoft > Windows > Windows Defender > Operational, event 1122, before you enable them.

**How to undo**

    Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Disabled

### SmartScreen for apps and files

- Check id: `def.smartscreen`
- Severity: Medium
- MITRE ATT&CK: T1204.002 Malicious File
- CIS Controls v8: 10.1
- CIS Windows Benchmark: Configure Windows Defender SmartScreen: Enabled: Warn and prevent bypass

SmartScreen warns before you run a downloaded program that few people have run before. It catches a lot of fresh malware that antivirus has not seen yet.

**How to fix**

    Windows Security > App and browser control > Reputation-based protection > Check apps and files = On.

**How to undo**

    Same switch, Off.

### Controlled folder access

- Check id: `def.cfa`
- Severity: Low
- MITRE ATT&CK: T1486 Data Encrypted for Impact
- CIS Controls v8: 10.5

Controlled folder access lets only trusted programs change files in Documents, Pictures and other protected folders. It is strong protection against ransomware. It can block legitimate programs until you allow them.

**How to fix**

    Windows Security > Virus and threat protection > Ransomware protection > Controlled folder access = On. Or:
      Set-MpPreference -EnableControlledFolderAccess Enabled
    Try -EnableControlledFolderAccess AuditMode first to see what it would block.

**How to undo**

    Set-MpPreference -EnableControlledFolderAccess Disabled

## Updates and software

### Windows Update

- Check id: `wu.status`
- Severity: High
- CIS Controls v8: 7.3
- CIS Windows Benchmark: Configure Automatic Updates: Enabled

Most attacks use bugs that already have a fix. Windows Update applies those fixes. If it is stopped, blocked by policy or waiting on a reboot, the PC stays open to known attacks.

**How to fix**

    Settings > Windows Update > Check for updates. Install everything, then restart.
    If updates are disabled by policy and you did not do that on purpose (elevated PowerShell):
      Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate

**How to undo**

    Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type DWord

### Outdated or end-of-life software

- Check id: `sw.outdated`
- Severity: High
- MITRE ATT&CK: T1203 Exploitation for Client Execution
- CIS Controls v8: 7.4, 2.2

Old versions of everyday programs have published bugs that attackers use, often by sending a file the program opens. End-of-life programs never get fixes at all. The version table in this tool was last reviewed in October 2026.

**How to fix**

    Update each program listed from its official site, or update everything winget knows about:
      winget upgrade --all
    Uninstall anything end-of-life (Flash, Silverlight, QuickTime for Windows) and anything you no longer use.

**How to undo**

    Reinstall the older version from the vendor's archive (not recommended).

## Platform hardening

### Drive encryption (BitLocker)

- Check id: `hard.bitlocker`
- Severity: High
- MITRE ATT&CK: T1005 Data from Local System
- CIS Controls v8: 3.6

Without drive encryption, anyone who takes the PC or its disk can read every file and copy saved passwords. No Windows password is needed. BitLocker encrypts the whole drive and unlocks it with the PC's TPM chip.

**How to fix**

    Settings > Privacy and security > Device encryption (Home) or Control Panel > BitLocker Drive Encryption (Pro). Or elevated PowerShell:
      Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -TpmProtector
      Add-BitLockerKeyProtector -MountPoint C: -RecoveryPasswordProtector
      (Get-BitLockerVolume -MountPoint C:).KeyProtector
    Write down or save the recovery password from the last command somewhere off this PC before you reboot.

**How to undo**

    Disable-BitLocker -MountPoint C:

### TPM security chip

- Check id: `hard.tpm`
- Severity: Low
- CIS Controls v8: 4.1

The TPM is a small security chip that holds keys for BitLocker, Windows Hello and Credential Guard. Windows 11 requires TPM 2.0. Without one, those protections are weaker or not available.

**How to fix**

    Most PCs built since 2016 have a TPM that may be switched off in the firmware. Reboot into the UEFI setup and look for TPM, PTT (Intel) or fTPM (AMD), and enable it.

**How to undo**

    Disable it in the same firmware menu. Suspend BitLocker first (Suspend-BitLocker -MountPoint C:) or you will need the recovery key.

### Secure Boot

- Check id: `hard.secureboot`
- Severity: Medium
- MITRE ATT&CK: T1542.003 Bootkit
- CIS Controls v8: 4.1

Secure Boot lets the firmware start only boot code signed by trusted vendors. It blocks bootkits: malware that loads before Windows and hides from everything that starts after it.

**How to fix**

    Reboot into the UEFI firmware setup, find Secure Boot (often under Boot or Security) and enable it.
    The disk must use GPT and the PC must boot in UEFI mode, not Legacy or CSM.

**How to undo**

    Disable Secure Boot in the same menu.

### User Account Control

- Check id: `hard.uac`
- Severity: High
- MITRE ATT&CK: T1548.002 Bypass User Account Control
- CIS Controls v8: 4.1, 5.4
- CIS Windows Benchmark: User Account Control: Run all administrators in Admin Approval Mode: Enabled

User Account Control makes even administrator accounts run with normal rights until you approve a prompt. With UAC off or set to never notify, every program you start, including a malicious download, silently gets full admin rights.

**How to fix**

    Control Panel > User Accounts > Change User Account Control settings > the default level or higher. Or elevated PowerShell (reboot after changing EnableLUA):
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 5
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1

**How to undo**

    Move the slider back in the same Control Panel screen.

### AutoPlay and AutoRun

- Check id: `hard.autoplay`
- Severity: Medium
- MITRE ATT&CK: T1091 Replication Through Removable Media
- CIS Controls v8: 10.3
- CIS Windows Benchmark: Turn off Autoplay: Enabled: All drives

AutoPlay and AutoRun act on a USB stick or disc as soon as it is inserted. That has long been a way for malware to jump between PCs on removable media.

**How to fix**

    Elevated PowerShell:
      New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -Value 1 -Type DWord

**How to undo**

    Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun,NoAutorun

### Windows Script Host

- Check id: `hard.wsh`
- Severity: Low
- MITRE ATT&CK: T1059.005 Visual Basic, T1059.007 JavaScript
- CIS Controls v8: 2.7

Windows Script Host runs .vbs and .js files when you double-click them. Few people need that today, and email attachments with those extensions are a common way malware starts.

**How to fix**

    If nothing on this PC uses .vbs or .js scripts (some company login scripts do), elevated PowerShell:
      New-Item 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Force | Out-Null
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 0 -Type DWord

**How to undo**

    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 1 -Type DWord

### PowerShell 2.0 engine

- Check id: `hard.psv2`
- Severity: Medium
- MITRE ATT&CK: T1059.001 PowerShell
- CIS Controls v8: 2.7, 4.8

PowerShell 2.0 predates script logging and AMSI malware scanning. Anyone who runs powershell.exe -Version 2 skips both. Windows 11 24H2 removed it; older builds still ship it.

**How to fix**

    Elevated PowerShell:
      Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart

**How to undo**

    Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

### Office macros

- Check id: `hard.macros`
- Severity: Medium
- MITRE ATT&CK: T1204.002 Malicious File, T1137 Office Application Startup
- CIS Controls v8: 2.7
- CIS Windows Benchmark: Block macros from running in Office files from the Internet: Enabled

Office macros are small programs inside documents. Documents from the internet with macros were the most common way into company networks for years. Current Office blocks macros in downloaded files; no setting should undo that.

**How to fix**

    Never use 'Enable all macros'. Per user: File > Options > Trust Center > Trust Center Settings > Macro Settings > Disable all macros with notification.
    With Group Policy (Office templates): User Configuration > Microsoft Office > Security Settings > Trust Center > Block macros from running in Office files from the internet = Enabled.

**How to undo**

    Change the same Trust Center setting back.

## Credential protection

### LSA protection

- Check id: `lsa.ppl`
- Severity: High
- MITRE ATT&CK: T1003.001 LSASS Memory
- CIS Controls v8: 4.1
- CIS Windows Benchmark: Configure LSASS to run as a protected process: Enabled with UEFI Lock

LSA protection runs lsass.exe, the process that holds login secrets, as a protected process. Only code signed by Microsoft can then read its memory, which blocks most credential-dumping tools.

**How to fix**

    Elevated PowerShell, then reboot:
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
    Some old smart card drivers and plug-ins fail to load with it. Events 3065 and 3066 in Microsoft-Windows-CodeIntegrity/Operational show anything blocked.

**How to undo**

    Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL   (then reboot)

### Credential Guard

- Check id: `lsa.credguard`
- Severity: Medium
- MITRE ATT&CK: T1003.001 LSASS Memory
- CIS Controls v8: 4.1
- CIS Windows Benchmark: Turn On Virtualization Based Security: Enabled

Credential Guard keeps Windows login secrets in an isolated part of memory (LsaIso.exe) that malware running as administrator cannot read. Without it, credential-dumping tools can copy password hashes and tickets out of memory.

**How to fix**

    Needs Windows Enterprise or Education (some recent Windows 11 builds turn it on by default) and virtualization enabled in the firmware.
    Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security = Enabled, Credential Guard Configuration = Enabled without lock. Reboot.

**How to undo**

    Set the same policy to Disabled and reboot.

### Guest account

- Check id: `acct.guest`
- Severity: Medium
- MITRE ATT&CK: T1078.001 Default Accounts
- CIS Controls v8: 4.7
- CIS Windows Benchmark: Accounts: Guest account status: Disabled

The built-in Guest account allows local logons without a password of your choosing. It should be off on every PC.

**How to fix**

    Elevated PowerShell:
      Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Disable-LocalUser

**How to undo**

    Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Enable-LocalUser

### Built-in Administrator account

- Check id: `acct.admin`
- Severity: Low
- MITRE ATT&CK: T1078.001 Default Accounts
- CIS Controls v8: 4.7
- CIS Windows Benchmark: Accounts: Administrator account status: Disabled

Every Windows PC has an Administrator account with the same well-known identifier (RID 500). It is not locked out by failed logons, so attackers guess its password first. It should be disabled, and renamed if you keep it.

**How to fix**

    Elevated PowerShell:
      Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Disable-LocalUser
    To rename it instead:
      Rename-LocalUser -SID (Get-LocalUser | Where-Object { $_.SID -like '*-500' }).SID -NewName 'NewName'

**How to undo**

    Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Enable-LocalUser

### Local accounts

- Check id: `acct.local`
- Severity: Medium
- MITRE ATT&CK: T1078.003 Local Accounts
- CIS Controls v8: 5.1, 5.3, 5.4

Every local account is a way into the PC. Enabled accounts nobody uses, accounts that do not need a password, and too many administrators all make it easier to get in.

**How to fix**

    Disable accounts nobody uses:
      Disable-LocalUser -Name 'name'
    Require a password:
      net user name /passwordreq:yes
    Take admin rights away from people who do not need them:
      Remove-LocalGroupMember -SID S-1-5-32-544 -Member 'name'
    Use a normal account day to day and an admin account only for admin work.

**How to undo**

    Enable-LocalUser -Name 'name'
    Add-LocalGroupMember -SID S-1-5-32-544 -Member 'name'

### Password and lockout policy

- Check id: `acct.passwordpolicy`
- Severity: High
- MITRE ATT&CK: T1110 Brute Force
- CIS Controls v8: 5.2
- CIS Windows Benchmark: Minimum password length: 14 or more characters; Account lockout threshold: 5 or fewer invalid logon attempts, but not 0

Local password rules decide how hard a password is to guess and whether a guesser gets locked out. With no lockout, anyone at the keyboard or on the network can try passwords forever. Microsoft account sign-ins and PINs are not governed by these local rules.

**How to fix**

    Elevated Command Prompt:
      net accounts /minpwlen:14 /lockoutthreshold:5 /lockoutwindow:15 /lockoutduration:15
    Domain-joined PCs take these from the domain policy instead.

**How to undo**

    net accounts /minpwlen:<old> /lockoutthreshold:<old>   (the old values are in this report's evidence)

## Services and privileges

### Unquoted service paths

- Check id: `svc.unquoted`
- Severity: High
- MITRE ATT&CK: T1574.009 Path Interception by Unquoted Path
- CIS Controls v8: 4.1

A service is a program Windows starts automatically, often with full SYSTEM rights. If the path to the program has a space and no quotes, Windows tries it piece by piece: for C:\Program Files\Acme App\svc.exe it first tries C:\Program.exe. Anyone who can write a file there gets it run as SYSTEM.

**How to fix**

    Back up the key, then put quotes around the program part of ImagePath:
      reg export "HKLM\SYSTEM\CurrentControlSet\Services\ServiceName" service-backup.reg
      regedit > HKLM\SYSTEM\CurrentControlSet\Services\ServiceName > ImagePath
    Change C:\Program Files\Acme App\svc.exe -arg to "C:\Program Files\Acme App\svc.exe" -arg.
    Tell the vendor too. This is their bug.

**How to undo**

    reg import service-backup.reg

### Service programs normal users can change

- Check id: `svc.writable`
- Severity: Critical
- MITRE ATT&CK: T1574.010 Services File Permissions Weakness
- CIS Controls v8: 4.1, 3.3

These services run a program file that ordinary users are allowed to overwrite. Replace the file and the next service start runs your code with the service's rights, usually SYSTEM. Any program running as a normal user can do it.

**How to fix**

    Save the current permissions, then remove write access for Users, Authenticated Users and Everyone (elevated PowerShell):
      icacls "C:\path\to\service.exe" /save acl-backup.txt
      icacls "C:\path\to\service.exe" /inheritance:d
      icacls "C:\path\to\service.exe" /remove:g "*S-1-5-32-545" "*S-1-5-11" "*S-1-1-0"
    Then update or reinstall the program so the vendor sets correct permissions.

**How to undo**

    icacls "C:\path\to" /restore acl-backup.txt

### AlwaysInstallElevated

- Check id: `msi.alwayselevated`
- Severity: Critical
- MITRE ATT&CK: T1218.007 Msiexec, T1548 Abuse Elevation Control Mechanism
- CIS Controls v8: 4.1
- CIS Windows Benchmark: Always install with elevated privileges: Disabled

When this policy is on in both HKLM and HKCU, any user can install any .msi package with SYSTEM rights. That is a one-step route from a normal account to full control.

**How to fix**

    Elevated PowerShell:
      Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
      Remove-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    If Group Policy sets it, change the policy too: Administrative Templates > Windows Components > Windows Installer > Always install with elevated privileges = Disabled.

**How to undo**

    Set-ItemProperty on both keys with -Name AlwaysInstallElevated -Value 1 -Type DWord. Only if you understand the risk.

### Folders where a planted DLL would load

- Check id: `dll.hijack`
- Severity: High
- MITRE ATT&CK: T1574.001 DLL Search Order Hijacking
- CIS Controls v8: 4.1

When a program loads a DLL by name, Windows searches its own folder first, then system folders, then every folder in the system PATH. If a normal user can write to one of those folders, they can drop a DLL with the expected name and it runs inside the program. For a service running as SYSTEM that is privilege escalation. This check covers service program folders and system PATH folders. It does not test each application for missing DLLs.

**How to fix**

    Save permissions, then remove write access for normal users on each folder listed (elevated PowerShell):
      icacls "C:\the\folder" /save acl-backup.txt
      icacls "C:\the\folder" /inheritance:d
      icacls "C:\the\folder" /remove:g "*S-1-5-32-545" "*S-1-5-11" "*S-1-1-0"
    For PATH folders you do not need, remove them in System Properties > Environment Variables > System variables > Path.

**How to undo**

    icacls "C:\the" /restore acl-backup.txt

### Leftover Windows setup files

- Check id: `files.unattend`
- Severity: High
- MITRE ATT&CK: T1552.001 Credentials In Files
- CIS Controls v8: 4.1

Automated Windows installs use answer files such as unattend.xml. They often contain the local administrator password, sometimes only base64 encoded. Anyone who can read the file can read the password.

**How to fix**

    Open each file listed. If it has a <Password> or <AdministratorPassword> block, change that account's password, then delete the file:
      Remove-Item 'C:\Windows\Panther\unattend.xml'
    Keep an offline copy if your deployment team needs it.

**How to undo**

    Restore the file from your offline copy.

### Passwords in Group Policy Preference files

- Check id: `gpp.cpassword`
- Severity: Critical
- MITRE ATT&CK: T1552.006 Group Policy Preferences
- CIS Controls v8: 4.1

Older Group Policy Preferences could set passwords and stored them in SYSVOL as a cpassword value. Microsoft published the key used to encrypt them, so any domain user can decrypt them. The files stay readable to every domain user until someone deletes them.

**How to fix**

    Change every password that appears in the files listed. Then remove the password from the preference item (or delete the item) in Group Policy Management.
    MS14-025 stops new ones from being created but does not remove old ones. Use Windows LAPS for local admin passwords instead.

**How to undo**

    No undo. Treat the old passwords as public.

### Print Spooler

- Check id: `svc.spooler`
- Severity: Medium
- MITRE ATT&CK: T1068 Exploitation for Privilege Escalation
- CIS Controls v8: 4.8
- CIS Windows Benchmark: Limits print driver installation to Administrators: Enabled

The Print Spooler runs as SYSTEM and has had serious bugs (PrintNightmare). A PC with no printers does not need it. A PC that prints should let only administrators install printer drivers.

**How to fix**

    No printers (elevated PowerShell):
      Stop-Service Spooler
      Set-Service Spooler -StartupType Disabled
    With printers, restrict driver installs:
      New-Item 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Force | Out-Null
      Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name RestrictDriverInstallationToAdministrators -Value 1 -Type DWord

**How to undo**

    Set-Service Spooler -StartupType Automatic
    Start-Service Spooler

## Network exposure

### Windows Firewall

- Check id: `fw.profiles`
- Severity: High
- MITRE ATT&CK: T1562.004 Disable or Modify System Firewall
- CIS Controls v8: 4.4, 4.5
- CIS Windows Benchmark: Windows Firewall: Domain, Private, Public: Firewall state: On (recommended)

Windows Firewall blocks unsolicited inbound connections. It has three profiles: Domain (work network), Private (home) and Public (cafe, hotel). Each should be on, and inbound connections should default to Block.

**How to fix**

    Elevated PowerShell:
      Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block

**How to undo**

    Set-NetFirewallProfile -Profile <name> -Enabled False   (not recommended)

### Programs listening on the network

- Check id: `net.listening`
- Severity: Medium
- MITRE ATT&CK: T1210 Exploitation of Remote Services
- CIS Controls v8: 4.4, 4.8

A listening program waits for other computers to connect to it. Each one is a door. Doors opened by unsigned programs, or by programs running from user folders, are the ones to look at first.

**How to fix**

    For each program you do not recognise or need: uninstall it, or turn off its network feature in its own settings.
    Then make sure the firewall blocks it: Windows Security > Firewall and network protection > Allow an app through firewall, and untick it.

**How to undo**

    Reinstall the program, or tick it again in Allow an app through firewall.

### LLMNR name lookups

- Check id: `net.llmnr`
- Severity: High
- MITRE ATT&CK: T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay
- CIS Controls v8: 4.8
- CIS Windows Benchmark: Turn off multicast name resolution: Enabled

When DNS cannot find a name, Windows shouts the question to the whole local network with LLMNR. Any device can answer "that is me", and the PC then sends it a login attempt with a password hash that can be cracked or relayed.

**How to fix**

    Elevated PowerShell:
      New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
      Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord
    Or Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled.

**How to undo**

    Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast

### NetBIOS name lookups

- Check id: `net.nbtns`
- Severity: High
- MITRE ATT&CK: T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay
- CIS Controls v8: 4.8

NetBIOS name service is the older cousin of LLMNR. It broadcasts name lookups to the local network and trusts whoever answers, with the same password-hash leak.

**How to fix**

    Elevated PowerShell, all adapters:
      Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty $_.PSPath -Name NetbiosOptions -Value 2 }
    Or per adapter: adapter properties > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP. Very old shares that only resolve by NetBIOS name will stop resolving.

**How to undo**

    Same command with -Value 0 (use the DHCP server's setting).

### Multicast DNS

- Check id: `net.mdns`
- Severity: Medium
- MITRE ATT&CK: T1557 Adversary-in-the-Middle
- CIS Controls v8: 4.8

Multicast DNS answers name questions on the local network without a server. Like LLMNR it trusts any reply, which lets a device on the same network pose as another.

**How to fix**

    Elevated PowerShell, then reboot:
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS -Value 0 -Type DWord
    Some casting and printer discovery features use mDNS. Test them after the change.

**How to undo**

    Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS

### SMB signing

- Check id: `net.smbsigning`
- Severity: High
- MITRE ATT&CK: T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay
- CIS Controls v8: 3.10
- CIS Windows Benchmark: Microsoft network client: Digitally sign communications (always): Enabled

SMB is Windows file sharing. Signing proves each message came from the real server. Without required signing, an attacker who tricks this PC into connecting can relay its login to another server and act as this user there.

**How to fix**

    Elevated PowerShell:
      Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

**How to undo**

    Set-SmbClientConfiguration -RequireSecuritySignature $false -Force

### SMB version 1

- Check id: `net.smbv1`
- Severity: High
- MITRE ATT&CK: T1210 Exploitation of Remote Services
- CIS Controls v8: 4.8
- CIS Windows Benchmark: Configure SMB v1 client driver: Disable driver; Configure SMB v1 server: Disabled

SMB version 1 is the 30-year-old file sharing protocol that WannaCry and NotPetya spread through. Nothing current needs it. Windows 10 1709 and later remove it by default, but upgrades can keep it.

**How to fix**

    Elevated PowerShell, then reboot:
      Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Very old NAS boxes and scanners that only speak SMB1 will stop working. Update or replace them.

**How to undo**

    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All

### Remote Desktop

- Check id: `net.rdp`
- Severity: Medium
- MITRE ATT&CK: T1021.001 Remote Desktop Protocol
- CIS Controls v8: 4.8
- CIS Windows Benchmark: Require user authentication for remote connections by using Network Level Authentication: Enabled

Remote Desktop lets someone log in to this PC over the network. If you do not use it, it is a door left open. If you do, Network Level Authentication (NLA) should be required so the login happens before a session is created.

**How to fix**

    Not needed: Settings > System > Remote Desktop > Off.
    Needed: require NLA (elevated PowerShell):
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
    Never expose port 3389 directly to the internet.

**How to undo**

    Settings > System > Remote Desktop > On. NLA off: the same command with -Value 0.

### Windows Remote Management

- Check id: `net.winrm`
- Severity: Medium
- MITRE ATT&CK: T1021.006 Windows Remote Management
- CIS Controls v8: 4.8

Windows Remote Management lets administrators run commands on this PC remotely (PowerShell remoting). It is useful in managed networks and a way to move between PCs everywhere else.

**How to fix**

    If nobody manages this PC remotely (elevated PowerShell):
      Disable-PSRemoting -Force
      Remove-Item -Path WSMan:\Localhost\listener\* -Recurse
      Stop-Service WinRM
      Set-Service WinRM -StartupType Manual

**How to undo**

    Enable-PSRemoting -Force

### Remote Registry service

- Check id: `net.remoteregistry`
- Severity: Medium
- MITRE ATT&CK: T1112 Modify Registry
- CIS Controls v8: 4.8

The Remote Registry service lets other computers read and change this PC's registry over the network. Windows 10 and 11 ship with it disabled.

**How to fix**

    Elevated PowerShell:
      Stop-Service RemoteRegistry
      Set-Service RemoteRegistry -StartupType Disabled

**How to undo**

    Set-Service RemoteRegistry -StartupType Manual

### Automatic proxy detection (WPAD)

- Check id: `net.wpad`
- Severity: Medium
- MITRE ATT&CK: T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay, T1090.001 Internal Proxy
- CIS Controls v8: 4.8

Automatic proxy detection makes the PC look for proxy settings on the local network. Anyone who answers that lookup can route web traffic through themselves and capture logins.

**How to fix**

    Settings > Network and internet > Proxy > Automatically detect settings = Off.
    If your organization relies on WPAD, use a fixed setup script address instead.

**How to undo**

    Turn Automatically detect settings back On.

### Hosts file redirects

- Check id: `net.hosts`
- Severity: Medium
- MITRE ATT&CK: T1562.001 Disable or Modify Tools
- CIS Controls v8: 9.2

The hosts file overrides DNS on this PC. Malware edits it to send security and update sites nowhere, or to send banking sites to a fake copy. Developers also use it for test setups, which is harmless.

**How to fix**

    Open Notepad as administrator, open C:\Windows\System32\drivers\etc\hosts, and delete the lines you did not add. Then:
      ipconfig /flushdns

**How to undo**

    Add the lines back to the same file.

### DNS servers

- Check id: `net.dns`
- Severity: Low
- CIS Controls v8: 9.2

DNS turns names into addresses. Whoever runs your DNS server can send you anywhere. Malware such as DNSChanger set static DNS servers on infected PCs. A static DNS server you did not choose is worth a second look.

**How to fix**

    Check each server listed. If you did not set it: Settings > Network and internet > your adapter > DNS server assignment > Automatic (DHCP).
    For filtering and encryption, choose a well-known resolver and turn on DNS over HTTPS in the same screen.

**How to undo**

    Set the DNS servers back in the same screen.

### Trusted root certificates

- Check id: `cert.roots`
- Severity: Medium
- MITRE ATT&CK: T1553.004 Install Root Certificate
- CIS Controls v8: 3.10

Root certificates decide which secure (HTTPS) sites and signed programs your PC trusts. A root you did not install lets whoever holds its key read your encrypted web traffic or make their programs look signed. Some adware and interception tools add one. Company PCs and some antivirus products add their own on purpose.

**How to fix**

    Open certlm.msc (computer) and certmgr.msc (your account), go to Trusted Root Certification Authorities > Certificates, and look up each root listed by its thumbprint.
    Export a root before you remove it: right-click > All Tasks > Export. Then delete it, or in elevated PowerShell:
      Remove-Item Cert:\LocalMachine\Root\<thumbprint>
    If a program you use installed it on purpose (antivirus web filtering, a company proxy), keep it.

**How to undo**

    Import the exported file: right-click Certificates > All Tasks > Import, or elevated PowerShell:
      Import-Certificate -FilePath root.cer -CertStoreLocation Cert:\LocalMachine\Root

## Persistence

### Autostart locations

- Check id: `persist.sweep`
- Severity: High
- MITRE ATT&CK: T1547 Boot or Logon Autostart Execution, T1546 Event Triggered Execution, T1543.003 Windows Service, T1137 Office Application Startup, T1176 Browser Extensions

Windows has dozens of places where a program can register to start on its own: Run keys, the Startup folder, Winlogon, Image File Execution Options, AppInit DLLs, WMI event subscriptions, LSA packages, print monitors, shell extensions, COM registrations, Office add-ins, browser extensions and services. Malware uses the obscure ones because nobody looks there. This check lists every entry, flags the risky ones, and marks entries that are new since the last audit.

**How to fix**

    Find out what each flagged program is before you remove anything. Unsigned programs in user folders, IFEO debuggers, WMI command consumers and unknown LSA packages are rarely legitimate.
    Remove a Run key entry:
      Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'EntryName'
    For the deeper locations, Microsoft Sysinternals Autoruns can disable an entry without deleting it.

**How to undo**

    Export the key before removing anything:
      reg export "<key>" backup.reg
    Import it to undo:
      reg import backup.reg

### Scheduled tasks

- Check id: `persist.tasks`
- Severity: High
- MITRE ATT&CK: T1053.005 Scheduled Task

Scheduled tasks start programs at logon, at boot or on a timer. Malware uses them to come back after a reboot. Tasks that run a program from a user folder, run an encoded or downloading command, or point at a file that no longer exists deserve a look.

**How to fix**

    Open Task Scheduler (taskschd.msc), find the task by the path shown and check its Actions tab. If you do not recognise it: right-click > Export (keeps a copy), then right-click > Disable.
    Delete it once you are sure:
      Unregister-ScheduledTask -TaskPath '\folder\' -TaskName 'name' -Confirm:$false

**How to undo**

    A disabled task: right-click > Enable. A deleted task: Task Scheduler > Import Task and pick the exported XML.

## Running programs

### Running programs

- Check id: `proc.image`
- Severity: High
- MITRE ATT&CK: T1036.005 Match Legitimate Name or Location, T1204.002 Malicious File
- CIS Controls v8: 2.5

Every running program was started from a file. Programs running from Temp or Downloads, programs with a Windows system name in the wrong folder, programs started by Office, and programs not in your baseline are the usual signs that something unexpected is running.

**How to fix**

    For each program listed, right-click it in Task Manager > Open file location and check what it is.
    If you do not trust it: end it, remove its autostart entry (see Autostart locations), delete the file, and run a full antivirus scan.

**How to undo**

    Restore a file from the antivirus quarantine if it was removed by mistake.

## Logging and audit

### Audit policy

- Check id: `audit.subcategories`
- Severity: High
- MITRE ATT&CK: T1562.002 Disable Windows Event Logging
- CIS Controls v8: 8.2, 8.5
- CIS Windows Benchmark: Advanced Audit Policy Configuration (the subcategories listed in the evidence)

The audit policy decides which security events Windows records at all: logons, new processes, account and group changes, use of powerful privileges. If a category is off, nothing about it is ever written, and an investigation has nothing to work with.

**How to fix**

    Elevated Command Prompt, one line per subcategory the evidence lists (GUIDs work in every Windows language), for example:
      auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable
      auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
    Also record the command line of new processes:
      reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

**How to undo**

    auditpol /set /subcategory:{GUID} /success:disable /failure:disable

### Event log size and channels

- Check id: `audit.policy`
- Severity: Medium
- MITRE ATT&CK: T1562.002 Disable Windows Event Logging
- CIS Controls v8: 8.2, 8.3
- CIS Windows Benchmark: Security: Specify the maximum log file size (KB): 196,608 or greater

Windows writes security events to the Security log. If that log is small it overwrites itself within hours, and the record of an intrusion is gone before anyone looks.

**How to fix**

    Elevated PowerShell:
      wevtutil sl Security /ms:209715200
      wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true /ms:104857600
    That sets the Security log to 200 MB and turns on the PowerShell operational log at 100 MB.

**How to undo**

    wevtutil sl Security /ms:20971520

### PowerShell logging

- Check id: `ps.logging`
- Severity: Medium
- MITRE ATT&CK: T1059.001 PowerShell
- CIS Controls v8: 8.2, 8.8
- CIS Windows Benchmark: Turn on PowerShell Script Block Logging: Enabled

Most modern attacks use PowerShell at some point. Script block logging records the code that actually ran, even when it was obfuscated, so you can find out later what happened. Module logging records the commands.

**How to fix**

    Elevated PowerShell:
      New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
      Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord
      New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force | Out-Null
      Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -Value 1 -Type DWord
      Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*'
    Logs land in Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational.

**How to undo**

    Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Recurse

