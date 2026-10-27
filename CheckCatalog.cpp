#include "pch.h"
#include "CheckCatalog.h"

#include "AttackMapping.h"
#include "CheckScripts.h"
#include "Version.h"

#include <sstream>

// Category names
static const wchar_t* const CAT_SERVICES  = L"Services and privileges";
static const wchar_t* const CAT_CREDS     = L"Credential protection";
static const wchar_t* const CAT_NETWORK   = L"Network exposure";
static const wchar_t* const CAT_MALWARE   = L"Malware protection";
static const wchar_t* const CAT_PLATFORM  = L"Platform hardening";
static const wchar_t* const CAT_LOGGING   = L"Logging and audit";
static const wchar_t* const CAT_PERSIST   = L"Persistence";
static const wchar_t* const CAT_UPDATES   = L"Updates and software";
static const wchar_t* const CAT_RUNNING   = L"Running programs";
static const wchar_t* const CAT_EVENTS    = L"Recent activity";

const std::vector<std::wstring>& GetCheckCategories()
{
    // Recent activity comes last: it reports what happened, not how the PC is set up.
    static const std::vector<std::wstring> categories = {
        CAT_MALWARE, CAT_UPDATES, CAT_PLATFORM, CAT_CREDS, CAT_SERVICES,
        CAT_NETWORK, CAT_PERSIST, CAT_RUNNING, CAT_LOGGING, CAT_EVENTS,
    };
    return categories;
}

static std::vector<CheckInfo> BuildCatalog()
{
    std::vector<CheckInfo> c;
    auto add = [&c](CheckInfo info) { c.push_back(std::move(info)); };

    // ------------------------------------------------------------------ Malware protection
    add({ L"def.realtime", L"Antivirus real-time protection", CAT_MALWARE, Severity::Critical,
        { L"T1562.001" }, { L"10.1", L"10.2" }, L"Turn off real-time protection: Disabled",
        L"Real-time protection scans files as they are opened and downloaded. With it off, malware runs unchecked. "
        L"Turning it off is one of the first things malware does.",
        LR"~(Windows Security > Virus and threat protection > Manage settings > Real-time protection = On. Or elevated PowerShell:
  Set-MpPreference -DisableRealtimeMonitoring $false
If another antivirus product is installed, Microsoft Defender steps back on purpose. Make sure that product is on and up to date.)~",
        LR"~(Set-MpPreference -DisableRealtimeMonitoring $true   (temporary troubleshooting only))~" });

    add({ L"def.tamper", L"Tamper Protection", CAT_MALWARE, Severity::High,
        { L"T1562.001" }, { L"10.1" }, L"",
        L"Tamper Protection stops programs, including malware running as administrator, from switching Microsoft Defender off "
        L"or weakening its settings.",
        LR"~(Windows Security > Virus and threat protection > Manage settings > Tamper Protection = On.
It cannot be switched on from a script. That is on purpose.)~",
        LR"~(Same switch, Off.)~" });

    add({ L"def.cloud", L"Cloud-delivered protection", CAT_MALWARE, Severity::Medium,
        { L"T1562.001" }, { L"10.1" }, L"Join Microsoft MAPS: Enabled",
        L"Cloud protection lets Microsoft Defender ask Microsoft about files it has not seen before. Most new malware is caught "
        L"this way within seconds, long before a definition update arrives.",
        LR"~(Windows Security > Virus and threat protection > Manage settings > Cloud-delivered protection = On. Or elevated PowerShell:
  Set-MpPreference -MAPSReporting Advanced)~",
        LR"~(Set-MpPreference -MAPSReporting Disabled)~" });

    add({ L"def.signatures", L"Antivirus definitions age", CAT_MALWARE, Severity::Medium,
        { L"T1562.001" }, { L"10.2" }, L"",
        L"Microsoft Defender gets new malware definitions several times a day. Old definitions mean recent malware is invisible "
        L"to it. This usually means Windows Update or Defender updates are blocked.",
        LR"~(Elevated PowerShell:
  Update-MpSignature
If that fails, check that Windows Update works and that no policy blocks Defender updates.)~",
        LR"~(No undo needed.)~" });

    add({ L"def.exclusions", L"Antivirus exclusions", CAT_MALWARE, Severity::High,
        { L"T1562.001" }, { L"10.1" }, L"",
        L"An exclusion tells Microsoft Defender never to scan a folder, file type or process. Attackers add exclusions for their "
        L"own folders so their tools are never looked at. Every exclusion should be one you added on purpose.",
        LR"~(Remove each exclusion you do not recognise (elevated PowerShell):
  Remove-MpPreference -ExclusionPath 'C:\the\path'
  Remove-MpPreference -ExclusionExtension '.ext'
  Remove-MpPreference -ExclusionProcess 'name.exe'
Then run a full scan:
  Start-MpScan -ScanType FullScan)~",
        LR"~(Add-MpPreference -ExclusionPath 'C:\the\path'   (same pattern for -ExclusionExtension and -ExclusionProcess))~" });

    add({ L"def.asr", L"Attack Surface Reduction rules", CAT_MALWARE, Severity::Medium,
        {}, { L"10.5" }, L"Configure Attack Surface Reduction rules: Enabled",
        L"Attack Surface Reduction rules block the tricks malware uses most: Office starting other programs, scripts launching "
        L"downloaded programs, credential theft from lsass.exe. They are off by default.",
        LR"~(Start with the rule that blocks credential theft from LSASS. It almost never breaks anything (elevated PowerShell):
  Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
For other rules, use AuditMode first and read Event Viewer > Microsoft > Windows > Windows Defender > Operational, event 1122, before you enable them.)~",
        LR"~(Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Disabled)~" });

    add({ L"def.smartscreen", L"SmartScreen for apps and files", CAT_MALWARE, Severity::Medium,
        { L"T1204.002" }, { L"10.1" }, L"Configure Windows Defender SmartScreen: Enabled: Warn and prevent bypass",
        L"SmartScreen warns before you run a downloaded program that few people have run before. It catches a lot of fresh "
        L"malware that antivirus has not seen yet.",
        LR"~(Windows Security > App and browser control > Reputation-based protection > Check apps and files = On.)~",
        LR"~(Same switch, Off.)~" });

    add({ L"def.cfa", L"Controlled folder access", CAT_MALWARE, Severity::Low,
        { L"T1486" }, { L"10.5" }, L"",
        L"Controlled folder access lets only trusted programs change files in Documents, Pictures and other protected folders. "
        L"It is strong protection against ransomware. It can block legitimate programs until you allow them.",
        LR"~(Windows Security > Virus and threat protection > Ransomware protection > Controlled folder access = On. Or:
  Set-MpPreference -EnableControlledFolderAccess Enabled
Try -EnableControlledFolderAccess AuditMode first to see what it would block.)~",
        LR"~(Set-MpPreference -EnableControlledFolderAccess Disabled)~" });

    // ------------------------------------------------------------------ Updates and software
    add({ L"wu.status", L"Windows Update", CAT_UPDATES, Severity::High,
        {}, { L"7.3" }, L"Configure Automatic Updates: Enabled",
        L"Most attacks use bugs that already have a fix. Windows Update applies those fixes. If it is stopped, blocked by policy "
        L"or waiting on a reboot, the PC stays open to known attacks.",
        LR"~(Settings > Windows Update > Check for updates. Install everything, then restart.
If updates are disabled by policy and you did not do that on purpose (elevated PowerShell):
  Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate)~",
        LR"~(Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type DWord)~" });

    add({ L"wu.paused", L"Windows Update paused or deferred", CAT_UPDATES, Severity::Medium,
        {}, { L"7.3" }, L"Select when Quality Updates are received: Enabled: 0 days",
        L"While Windows Update is paused, or holds quality updates back, the monthly fixes (security fixes included) do not "
        L"install, so holes that are already public stay open on this PC. Updates can be paused from Settings for up to five "
        L"weeks, and Group Policy can pause them or hold quality updates back for up to 30 days after release. People often "
        L"pause updates to avoid a restart at a bad moment and then forget. This check warns when quality updates are paused "
        L"until a later date, or deferred by more than 7 days. Pausing or deferring only feature updates (the yearly new "
        L"version of Windows) is fine and only described. It reads the pause dates the Settings app stores and the Windows "
        L"Update Group Policy values; settings pushed by a management service (MDM, such as Intune) are not read. The "
        L"Windows Update check covers the service, the last install and a pending restart.",
        LR"~(Settings > Windows Update > Resume updates. Then Check for updates, install everything and restart.
If Group Policy pauses or defers quality updates: Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage updates offered from Windows Update (Windows Update for Business on older Windows 10) > Select when Quality Updates are received = Not Configured, or Enabled with 7 days or fewer and no pause start date. Then run gpupdate /force.
A company PC gets these settings from its IT department: ask them before you change them.)~",
        LR"~(Settings > Windows Update > Pause updates, and choose how long. Group Policy: set Select when Quality Updates are received back to what the evidence showed.)~" });

    add({ L"sw.outdated", L"Outdated or end-of-life software", CAT_UPDATES, Severity::High,
        { L"T1203" }, { L"7.4", L"2.2" }, L"",
        L"Old versions of everyday programs have published bugs that attackers use, often by sending a file the program opens. "
        L"End-of-life programs never get fixes at all. The version table in this tool was last reviewed in October 2026.",
        LR"~(Update each program listed from its official site, or update everything winget knows about:
  winget upgrade --all
Uninstall anything end-of-life (Flash, Silverlight, QuickTime for Windows) and anything you no longer use.)~",
        LR"~(Reinstall the older version from the vendor's archive (not recommended).)~" });

    // ------------------------------------------------------------------ Platform hardening
    add({ L"hard.bitlocker", L"Drive encryption (BitLocker)", CAT_PLATFORM, Severity::High,
        { L"T1005" }, { L"3.6" }, L"",
        L"Without drive encryption, anyone who takes the PC or its disk can read every file and copy saved passwords. No Windows "
        L"password is needed. BitLocker encrypts the whole drive and unlocks it with the PC's TPM chip.",
        LR"~(Settings > Privacy and security > Device encryption (Home) or Control Panel > BitLocker Drive Encryption (Pro). Or elevated PowerShell:
  Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -TpmProtector
  Add-BitLockerKeyProtector -MountPoint C: -RecoveryPasswordProtector
  (Get-BitLockerVolume -MountPoint C:).KeyProtector
Write down or save the recovery password from the last command somewhere off this PC before you reboot.)~",
        LR"~(Disable-BitLocker -MountPoint C:)~" });

    add({ L"hard.tpm", L"TPM security chip", CAT_PLATFORM, Severity::Low,
        {}, { L"4.1" }, L"",
        L"The TPM is a small security chip that holds keys for BitLocker, Windows Hello and Credential Guard. Windows 11 requires "
        L"TPM 2.0. Without one, those protections are weaker or not available.",
        LR"~(Most PCs built since 2016 have a TPM that may be switched off in the firmware. Reboot into the UEFI setup and look for TPM, PTT (Intel) or fTPM (AMD), and enable it.)~",
        LR"~(Disable it in the same firmware menu. Suspend BitLocker first (Suspend-BitLocker -MountPoint C:) or you will need the recovery key.)~" });

    add({ L"hard.secureboot", L"Secure Boot", CAT_PLATFORM, Severity::Medium,
        { L"T1542.003" }, { L"4.1" }, L"",
        L"Secure Boot lets the firmware start only boot code signed by trusted vendors. It blocks bootkits: malware that loads "
        L"before Windows and hides from everything that starts after it.",
        LR"~(Reboot into the UEFI firmware setup, find Secure Boot (often under Boot or Security) and enable it.
The disk must use GPT and the PC must boot in UEFI mode, not Legacy or CSM.)~",
        LR"~(Disable Secure Boot in the same menu.)~" });

    add({ L"hard.uac", L"User Account Control", CAT_PLATFORM, Severity::High,
        { L"T1548.002" }, { L"4.1", L"5.4" }, L"User Account Control: Run all administrators in Admin Approval Mode: Enabled",
        L"User Account Control makes even administrator accounts run with normal rights until you approve a prompt. With UAC off "
        L"or set to never notify, every program you start, including a malicious download, silently gets full admin rights.",
        LR"~(Control Panel > User Accounts > Change User Account Control settings > the default level or higher. Or elevated PowerShell (reboot after changing EnableLUA):
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 5
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1)~",
        LR"~(Move the slider back in the same Control Panel screen.)~" });

    add({ L"hard.autoplay", L"AutoPlay and AutoRun", CAT_PLATFORM, Severity::Medium,
        { L"T1091" }, { L"10.3" }, L"Turn off Autoplay: Enabled: All drives",
        L"AutoPlay and AutoRun act on a USB stick or disc as soon as it is inserted. That has long been a way for malware to jump "
        L"between PCs on removable media.",
        LR"~(Elevated PowerShell:
  if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) { New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null }
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -Value 1 -Type DWord)~",
        LR"~(Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun,NoAutorun)~" });

    add({ L"hard.wsh", L"Windows Script Host", CAT_PLATFORM, Severity::Low,
        { L"T1059.005", L"T1059.007" }, { L"2.7" }, L"",
        L"Windows Script Host runs .vbs and .js files when you double-click them. Few people need that today, and email "
        L"attachments with those extensions are a common way malware starts.",
        LR"~(If nothing on this PC uses .vbs or .js scripts (some company login scripts do), elevated PowerShell:
  if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings')) { New-Item 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Force | Out-Null }
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 0 -Type DWord)~",
        LR"~(Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 1 -Type DWord)~" });

    add({ L"hard.psv2", L"PowerShell 2.0 engine", CAT_PLATFORM, Severity::Medium,
        { L"T1059.001" }, { L"2.7", L"4.8" }, L"",
        L"PowerShell 2.0 predates script logging and AMSI malware scanning. Anyone who runs powershell.exe -Version 2 skips both. "
        L"Windows 11 24H2 removed it; older builds still ship it.",
        LR"~(Elevated PowerShell:
  Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart)~",
        LR"~(Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root)~" });

    add({ L"hard.macros", L"Office macros", CAT_PLATFORM, Severity::Medium,
        { L"T1204.002", L"T1137" }, { L"2.7" }, L"Block macros from running in Office files from the Internet: Enabled",
        L"Office macros are small programs inside documents. Documents from the internet with macros were the most common way "
        L"into company networks for years. Current Office blocks macros in downloaded files; no setting should undo that.",
        LR"~(Never use 'Enable all macros'. Per user: File > Options > Trust Center > Trust Center Settings > Macro Settings > Disable all macros with notification.
With Group Policy (Office templates): User Configuration > Microsoft Office > Security Settings > Trust Center > Block macros from running in Office files from the internet = Enabled.)~",
        LR"~(Change the same Trust Center setting back.)~" });

    add({ L"hard.hvci", L"Memory integrity (core isolation)", CAT_PLATFORM, Severity::Medium,
        { L"T1068" }, { L"10.5" },
        L"Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity: Enabled with UEFI lock",
        L"Memory integrity (hypervisor-protected code integrity, HVCI) uses the processor's virtualization features to check "
        L"drivers and kernel code before they run, in a part of memory Windows itself cannot change. Malware with administrator "
        L"rights then cannot load unsigned kernel code or patch the kernel in memory. It needs virtualization switched on in "
        L"the firmware. An incompatible driver blocks it: Windows leaves memory integrity off, or stops it at the next start, "
        L"and names the driver in Windows Security.",
        LR"~(Windows Security > Device security > Core isolation details > Memory integrity = On, then restart.
If Windows lists incompatible drivers there, update or uninstall those drivers first (the list names each .sys file and its publisher). Memory integrity stays off while one is installed.
If memory integrity is on but not running, restart. If it still does not run, check that virtualization (Intel VT-x or AMD-V / SVM) is enabled in the UEFI firmware setup.
Or elevated PowerShell, then restart:
  if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity')) { New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Force | Out-Null }
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -Value 1 -Type DWord)~",
        LR"~(Windows Security > Device security > Core isolation details > Memory integrity = Off, then restart. Or elevated PowerShell, then restart:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -Value 0 -Type DWord
If Group Policy turned it on (Device Guard > Turn On Virtualization Based Security), set that policy back instead.)~" });

    add({ L"hard.driverblocklist", L"Vulnerable driver block list", CAT_PLATFORM, Severity::Medium,
        { L"T1068", L"T1562.001" }, { L"10.5" }, L"",
        L"Some signed drivers from hardware and software vendors have known security holes. Because they are validly signed, "
        L"Windows would load them, and malware that already has administrator rights installs one to reach the kernel, often "
        L"to switch security software off. Microsoft keeps a list of these drivers; with the block list on, Windows refuses "
        L"to load them. It is on by default on Windows 11 22H2 and later, and whenever memory integrity, Smart App Control or "
        L"S mode is on.",
        LR"~(Windows Security > Device security > Core isolation details > Microsoft Vulnerable Driver Blocklist = On, then restart. Or elevated PowerShell, then restart:
  if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config')) { New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Force | Out-Null }
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable -Value 1 -Type DWord
If a device stops working afterwards, its driver is on the list: get a current driver from the vendor.)~",
        LR"~(Same switch, Off, then restart. Or elevated PowerShell, then restart:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable -Value 0 -Type DWord)~" });

    add({ L"hard.smartapp", L"Smart App Control", CAT_PLATFORM, Severity::Low,
        { L"T1204.002" }, { L"2.5" }, L"",
        L"Smart App Control (Windows 11 22H2 and later) blocks programs that are neither signed by a trusted publisher nor known "
        L"to be safe by Microsoft's cloud service. A new Windows 11 install starts it in evaluation mode, where it watches "
        L"without blocking and then turns itself on or off. Most PCs end up with it off, and once it is off Windows only "
        L"offers it again after a reset or a clean install. That is why this check counts for little in the score.",
        LR"~(Windows Security > App and browser control > Smart App Control settings.
In evaluation mode you can choose On there now.
When it is Off, the switch cannot be turned back On: Windows offers Smart App Control again only after a reset (Settings > System > Recovery > Reset this PC) or a clean install of Windows 11. A reset removes your installed apps, and your files too unless you choose Keep my files, so back up first. A reset is rarely worth it for this alone; Microsoft Defender, SmartScreen and the other checks here still protect the PC.)~",
        LR"~(Windows Security > App and browser control > Smart App Control settings > Off. Turning it off cannot be undone without a reset.)~" });

    add({ L"hard.exploitprot", L"System exploit protection", CAT_PLATFORM, Severity::Medium,
        { L"T1203", L"T1068" }, { L"10.5" }, L"Enable Structured Exception Handling Overwrite Protection (SEHOP): Enabled",
        L"Windows has system-wide defences that make a bug in a program much harder to turn into running code: Data Execution "
        L"Prevention (DEP) stops code from running out of data memory, SEHOP blocks a classic way of hijacking a program's "
        L"error handling, address space layout randomization (ASLR) puts code at unpredictable addresses, and Control Flow "
        L"Guard (CFG) checks where indirect calls go. They are on by default; a setting that turns one off for the whole "
        L"system weakens every program. This check reads the system DEP policy, the SEHOP registry value, and the bottom-up "
        L"ASLR, high-entropy ASLR and CFG fields of the system mitigation settings. Mandatory ASLR and per-program settings "
        L"are not judged.",
        LR"~(Save the current settings first (elevated PowerShell):
  Get-ProcessMitigation -RegistryConfigFilePath exploit-backup.xml
Windows Security > App and browser control > Exploit protection settings > System settings: set Control flow guard (CFG), Data Execution Prevention (DEP), Randomize memory allocations (Bottom-up ASLR), High-entropy ASLR and Validate exception chains (SEHOP) to Use default (On). Restart.
Or elevated PowerShell, then restart:
  Set-ProcessMitigation -System -Enable DEP,SEHOP,BottomUp,HighEntropy,CFG
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name DisableExceptionChainValidation -Value 0 -Type DWord
If the system DEP policy is AlwaysOff, it is a boot setting (elevated Command Prompt, then restart; if the drive uses BitLocker, run Suspend-BitLocker -MountPoint C: -RebootCount 1 first):
  bcdedit /set {current} nx OptIn)~",
        LR"~(Restore the saved settings (elevated PowerShell, then restart):
  Set-ProcessMitigation -PolicyFilePath exploit-backup.xml
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name DisableExceptionChainValidation -Value 1 -Type DWord   (only if it was 1 before)
  bcdedit /set {current} nx AlwaysOff   (only if it was AlwaysOff before; not recommended))~" });

    add({ L"backup.restore", L"System Restore for the system drive", CAT_PLATFORM, Severity::Low,
        { L"T1490" }, {}, L"",
        L"System Restore keeps restore points: snapshots of Windows system files, drivers, installed programs and the registry. "
        L"After a bad driver, update or program install it can put Windows back the way it was. Ransomware and other malware "
        L"turn it off and delete restore points so a PC cannot be rolled back. Restore points are not a backup of your personal "
        L"files: they do not keep documents and photos, and they live on the same drive, so a failed or stolen drive takes them "
        L"along. Keep a real backup as well (File History, OneDrive or an external drive). Which drives are protected can only "
        L"be read with administrator rights.",
        LR"~(System Properties > System Protection (Win+R, SystemPropertiesProtection) > select the system drive (C:) > Configure > Turn on system protection, Max Usage 5 to 10 percent > OK. Or elevated PowerShell:
  Enable-ComputerRestore -Drive 'C:\'
If Group Policy turned it off (Computer Configuration > Administrative Templates > System > System Restore > Turn off System Restore), set that policy to Not Configured.)~",
        LR"~(Same screen > Configure > Disable system protection (this deletes the drive's restore points). Or elevated PowerShell:
  Disable-ComputerRestore -Drive 'C:\')~" });

    add({ L"hard.sudo", L"sudo for Windows in inline mode", CAT_PLATFORM, Severity::Low,
        {}, { L"4.1" }, L"",
        L"Windows 11 24H2 and later include sudo, which runs one command as administrator from a normal console window after "
        L"the usual UAC prompt. It is off by default and has three modes. In a new window (forceNewWindow) runs the elevated "
        L"command in a console of its own. With input closed (disableInput) runs it in the same window but lets it read no "
        L"keyboard input. Inline (normal) runs it in the same window with full input and output, like sudo on Linux. "
        L"Microsoft describes inline as the riskiest mode: other programs running without administrator rights that are "
        L"attached to the same console window could interact with the elevated program. This check warns for inline and "
        L"passes for the other modes or sudo off. It reads the mode from the registry, lowered to a Group Policy limit when "
        L"one is set, and is N/A on Windows builds without sudo.",
        LR"~(Settings > System > Advanced (For developers on some builds) > Enable sudo > Configure how sudo runs = In a new window, or turn Enable sudo off. Or elevated PowerShell:
  sudo config --enable forceNewWindow
To turn sudo off instead:
  sudo config --enable disable)~",
        LR"~(Same setting, Inline. Or elevated PowerShell:
  sudo config --enable normal)~" });

    // ------------------------------------------------------------------ Credential protection
    add({ L"lsa.ppl", L"LSA protection", CAT_CREDS, Severity::High,
        { L"T1003.001" }, { L"4.1" }, L"Configure LSASS to run as a protected process: Enabled with UEFI Lock",
        L"LSA protection runs lsass.exe, the process that holds login secrets, as a protected process. Only code signed by "
        L"Microsoft can then read its memory, which blocks most credential-dumping tools.",
        LR"~(Windows 11 22H2 and later, elevated PowerShell, then reboot:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 2 -Type DWord
Value 2 turns protection on without the UEFI lock, so the undo below works.
Value 1 (older Windows 10, and the CIS "UEFI Lock" setting) also stores the setting in a UEFI variable on PCs with Secure Boot. After that, deleting the registry value no longer turns protection off; only Microsoft's LSA Protected Process Opt-out tool (LSAPPLConfig.efi) does. Use value 1 only if you want that lock.
Some old smart card drivers and plug-ins fail to load with it. Events 3065 and 3066 in Microsoft-Windows-CodeIntegrity/Operational show anything blocked.)~",
        LR"~(For RunAsPPL=2 (elevated PowerShell, then reboot):
  Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL
If RunAsPPL was 1 on a PC with Secure Boot, the UEFI variable keeps protection on after that. Remove it with Microsoft's LSA Protected Process Opt-out tool (LSAPPLConfig.efi), following "Configure added LSA protection" on Microsoft Learn.)~" });

    add({ L"lsa.credguard", L"Credential Guard", CAT_CREDS, Severity::Medium,
        { L"T1003.001" }, { L"4.1" }, L"Turn On Virtualization Based Security: Enabled",
        L"Credential Guard keeps Windows login secrets in an isolated part of memory (LsaIso.exe) that malware running as "
        L"administrator cannot read. Without it, credential-dumping tools can copy password hashes and tickets out of memory.",
        LR"~(Needs Windows Enterprise or Education (some recent Windows 11 builds turn it on by default) and virtualization enabled in the firmware.
Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security = Enabled, Credential Guard Configuration = Enabled without lock. Reboot.)~",
        LR"~(Set the same policy to Disabled and reboot.)~" });

    add({ L"cred.wdigest", L"WDigest keeps sign-in passwords in memory", CAT_CREDS, Severity::High,
        { L"T1003.001", L"T1112" }, { L"4.1" }, L"WDigest Authentication (disabling may require KB2871997): Disabled",
        L"With UseLogonCredential set to 1, Windows keeps the password of everyone who signs in to this PC in memory in a form "
        L"that can be turned back into the password itself. The setting belongs to WDigest, an old sign-in method for web "
        L"sites and servers that almost nothing uses today. Malware that later gets administrator rights could then collect "
        L"those passwords. That is why malware often switches this setting on, and why a 1 that nobody here set is a warning "
        L"sign. On Windows 8.1, Windows Server 2012 R2 and later the setting is off when the value is missing, and 0 turns it "
        L"off explicitly. Passwords already kept stay in memory until each account signs out, so sign out or restart after "
        L"the fix. This check only reads the setting; it never looks at memory.",
        LR"~(Elevated PowerShell, then sign out and back in (or restart):
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord
Deleting the value works as well on Windows 8.1 and later:
  Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential
Or Group Policy (the MS Security Guide template): WDigest Authentication = Disabled.
If you did not turn it on yourself, run a full scan (Start-MpScan -ScanType FullScan) and change the passwords of the accounts that signed in to this PC since.)~",
        LR"~(By hand, and only if an old program truly needs WDigest (elevated PowerShell, then sign out and back in; not recommended):
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 1 -Type DWord)~" });

    add({ L"cred.ntlm", L"Old sign-in protocols (LM and NTLM)", CAT_CREDS, Severity::High,
        { L"T1557.001", L"T1110.002", L"T1003.002" }, { L"4.1", L"3.10" },
        L"Network security: LAN Manager authentication level: Send NTLMv2 response only. Refuse LM & NTLM; Network security: Do not store LAN Manager hash value on next password change: Enabled; Network security: Minimum session security for NTLM SSP based (including secure RPC) clients and servers: Require NTLMv2 session security, Require 128-bit encryption",
        L"When this PC signs in to another computer without Kerberos (in a workgroup, with a local account, or whenever Kerberos "
        L"is not available), Windows proves the password with a challenge and an answer instead of sending it. The oldest "
        L"answers, LAN Manager (LM) and NTLMv1, are weak: anyone who captures one on the network, or tricks the PC into sending "
        L"one, can crack it or turn it back into the password hash. NTLMv2 answers are much harder to attack. "
        L"LmCompatibilityLevel decides which answers this PC sends (0 to 2 still send LM or NTLMv1, 3 and higher only NTLMv2) "
        L"and, at 4 and 5, which ones it refuses when other computers sign in to it; 5 refuses both, as the CIS benchmark "
        L"asks, so 3 and 4 are a warning here. Not set means 3. NoLMHash = 1 keeps Windows from storing an LM hash of new "
        L"passwords, which can be cracked in minutes; not set means 1. NtlmMinClientSec and NtlmMinServerSec set the least "
        L"protection the connection gets after sign-in: 128-bit encryption and NTLMv2 session security (537395200 sets both). "
        L"Not set means 128-bit only. Very old devices, such as NAS boxes, printers and scanners from before about 2008, may "
        L"only speak LM or NTLMv1 and stop working after the change.",
        LR"~(Elevated PowerShell, then restart:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1 -Type DWord
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NtlmMinClientSec -Value 537395200 -Type DWord
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NtlmMinServerSec -Value 537395200 -Type DWord
Or Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM, and both Minimum session security for NTLM SSP settings = Require NTLMv2 session security, Require 128-bit encryption.
Very old devices (NAS boxes, printers, scanners) that only speak LM or NTLMv1 may stop working: update their firmware, or use level 3 until they are replaced. An LM hash that is already stored goes away the next time that password is changed.)~",
        LR"~(Set each value back to what the evidence showed before the fix (elevated PowerShell, then restart), for example:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 3 -Type DWord
A value the evidence showed as not set: remove it to get the Windows default back:
  Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel
  Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NtlmMinClientSec,NtlmMinServerSec)~" });

    add({ L"acct.guest", L"Guest account", CAT_CREDS, Severity::Medium,
        { L"T1078.001" }, { L"4.7" }, L"Accounts: Guest account status: Disabled",
        L"The built-in Guest account allows local logons without a password of your choosing. It should be off on every PC.",
        LR"~(Elevated PowerShell:
  Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Disable-LocalUser)~",
        LR"~(Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Enable-LocalUser)~" });

    add({ L"acct.admin", L"Built-in Administrator account", CAT_CREDS, Severity::Low,
        { L"T1078.001" }, { L"4.7" }, L"Accounts: Administrator account status: Disabled",
        L"Every Windows PC has an Administrator account with the same well-known identifier (RID 500). It is not locked out by "
        L"failed logons, so attackers guess its password first. It should be disabled, and renamed if you keep it.",
        LR"~(Elevated PowerShell:
  Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Disable-LocalUser
To rename it instead:
  Rename-LocalUser -SID (Get-LocalUser | Where-Object { $_.SID -like '*-500' }).SID -NewName 'NewName')~",
        LR"~(Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Enable-LocalUser)~" });

    add({ L"acct.local", L"Local accounts", CAT_CREDS, Severity::Medium,
        { L"T1078.003" }, { L"5.1", L"5.3", L"5.4" }, L"",
        L"Every local account is a way into the PC. Enabled accounts nobody uses, accounts that do not need a password, and too "
        L"many administrators all make it easier to get in.",
        LR"~(Disable accounts nobody uses:
  Disable-LocalUser -Name 'name'
Require a password:
  net user name /passwordreq:yes
Take admin rights away from people who do not need them:
  Remove-LocalGroupMember -SID S-1-5-32-544 -Member 'name'
Use a normal account day to day and an admin account only for admin work.)~",
        LR"~(Enable-LocalUser -Name 'name'
Add-LocalGroupMember -SID S-1-5-32-544 -Member 'name')~" });

    add({ L"acct.passwordpolicy", L"Password and lockout policy", CAT_CREDS, Severity::High,
        { L"T1110" }, { L"5.2" }, L"Minimum password length: 14 or more characters; Account lockout threshold: 5 or fewer invalid logon attempts, but not 0",
        L"Local password rules decide how hard a password is to guess and whether a guesser gets locked out. With no lockout, "
        L"anyone at the keyboard or on the network can try passwords forever. Microsoft account sign-ins and PINs are not "
        L"governed by these local rules.",
        LR"~(Elevated Command Prompt:
  net accounts /minpwlen:14 /lockoutthreshold:5 /lockoutwindow:15 /lockoutduration:15
Domain-joined PCs take these from the domain policy instead.)~",
        LR"~(net accounts /minpwlen:<old> /lockoutthreshold:<old>   (the old values are in this report's evidence))~" });

    add({ L"cred.cachedlogons", L"Cached domain sign-ins", CAT_CREDS, Severity::Low,
        { L"T1003.005" }, { L"4.1" },
        L"Interactive logon: Number of previous logons to cache (in case domain controller is not available): 4 or fewer logon(s)",
        L"On a PC joined to an Active Directory domain, Windows keeps a protected copy (a hash) of the last domain accounts "
        L"that signed in, so they can sign in again while the PC cannot reach a domain controller: on a train, at home, during "
        L"a network outage. Each copy is something an intruder with administrator rights on this PC could try to crack to "
        L"learn that account's password. CachedLogonsCount sets how many are kept; the Windows default is 10. 4 or fewer is "
        L"enough for most PCs. It is a trade-off: laptops used away from the company network need at least 1 or 2, or their "
        L"users cannot sign in there, and 0 suits only desktops that never leave it. PCs that are not joined to a domain "
        L"(home PCs, and Microsoft Entra joined PCs without a domain) keep no cached domain sign-ins, so the check is N/A there.",
        LR"~(Elevated PowerShell (takes effect at the next sign-in):
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value '4' -Type String
Or Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Number of previous logons to cache (in case domain controller is not available) = 4. On a domain the IT department usually sets this for every PC.
Laptops used away from the office need at least 1 or 2.)~",
        LR"~(Elevated PowerShell (10 is the Windows default; use the number the evidence showed):
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value '10' -Type String)~" });

    add({ L"acct.autologon", L"Automatic sign-in", CAT_CREDS, Severity::High,
        { L"T1552.002" }, { L"4.1" }, L"MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended): Disabled",
        L"With automatic sign-in, Windows opens an account's desktop at start-up without asking for a password, so anyone who "
        L"switches the PC on, or takes it, is signed in. The password it uses is stored either in the registry value "
        L"DefaultPassword, in plain text that every user and program on this PC can read, or encrypted as an LSA secret (what "
        L"netplwiz and the Sysinternals Autologon tool use). Plain text fails this check; the encrypted form still means the "
        L"PC asks nobody to sign in, so it is a warning. Kiosk and lab PCs sometimes need automatic sign-in: use an account "
        L"without administrator rights or personal data for that. This check only looks at whether DefaultPassword exists; "
        L"it never reads, keeps or shows the password. The account name is shown in the evidence and hidden with the other "
        L"names when you hide names in a report.",
        LR"~(Win+R, netplwiz, tick Users must enter a user name and password to use this computer, OK. That also removes the encrypted password. If the box is missing, first turn off Settings > Accounts > Sign-in options > For improved security, only allow Windows Hello sign-in.
Or elevated PowerShell:
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value '0'
  Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue
If a plain-text DefaultPassword was stored, change that account's password as well: anyone on this PC could have read it.)~",
        LR"~(By hand: Win+R, netplwiz, untick Users must enter a user name and password to use this computer, OK, and type the account's password when asked. Windows then stores it encrypted, not in plain text.)~" });

    add({ L"acct.screenlock", L"Screen lock when away", CAT_CREDS, Severity::Medium,
        {}, { L"4.3" }, L"Interactive logon: Machine inactivity limit: 900 or fewer second(s), but not 0",
        L"If the PC stays unlocked when you walk away, anyone who sits down can use your account, read your mail and approve "
        L"prompts as you. Windows can lock on its own after a time without input: through the machine inactivity limit (a "
        L"security policy for every user) or a screen saver that asks for the password on resume. This check passes when either "
        L"locks within 15 minutes. Sleep also locks the PC when Windows asks for sign-in on wake; this check does not read power "
        L"plans, so a PC that sleeps quickly and asks for sign-in on wake is safer than a WARNING here suggests. Windows+L locks "
        L"the PC at once.",
        LR"~(For this user: Settings > Personalization > Lock screen > Screen saver: choose a screen saver, set Wait to 15 minutes or less and tick On resume, display logon screen.
For every user (elevated PowerShell; takes effect after a restart):
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900 -Type DWord
Also: Settings > Accounts > Sign-in options > If you've been away, when should Windows require you to sign in again? = When PC wakes up from sleep.)~",
        LR"~(Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs   (then restart)
Screen saver: set it back to (None) in the same Settings screen.)~" });

    // ------------------------------------------------------------------ Services and privileges
    add({ L"svc.unquoted", L"Unquoted service paths", CAT_SERVICES, Severity::High,
        { L"T1574.009" }, { L"4.1" }, L"",
        L"A service is a program Windows starts automatically, often with full SYSTEM rights. If the path to the program has a "
        L"space and no quotes, Windows tries it piece by piece: for C:\\Program Files\\Acme App\\svc.exe it first tries "
        L"C:\\Program.exe. Anyone who can write a file there gets it run as SYSTEM.",
        LR"~(Back up the key, then put quotes around the program part of ImagePath:
  reg export "HKLM\SYSTEM\CurrentControlSet\Services\ServiceName" service-backup.reg
  regedit > HKLM\SYSTEM\CurrentControlSet\Services\ServiceName > ImagePath
Change C:\Program Files\Acme App\svc.exe -arg to "C:\Program Files\Acme App\svc.exe" -arg.
Tell the vendor too. This is their bug.)~",
        LR"~(reg import service-backup.reg)~" });

    add({ L"svc.writable", L"Service programs normal users can change", CAT_SERVICES, Severity::Critical,
        { L"T1574.010" }, { L"4.1", L"3.3" }, L"",
        L"These services run a program file that ordinary users are allowed to overwrite. Replace the file and the next service "
        L"start runs your code with the service's rights, usually SYSTEM. Any program running as a normal user can do it.",
        LR"~(Save the current permissions, then cut the group the evidence names down to read and run (elevated PowerShell):
  icacls "C:\path\to\service.exe" /save acl-backup.txt
  icacls "C:\path\to\service.exe" /inheritance:d
  icacls "C:\path\to\service.exe" /grant:r "*S-1-5-11:(RX)"
/grant:r replaces everything that group was granted with read and run, so the service and its users can still start the program. Use the SID of the group the evidence names: *S-1-5-11 Authenticated Users, *S-1-5-32-545 Users, *S-1-1-0 Everyone, *S-1-5-4 INTERACTIVE. Run the audit again; repeat for any other group it then names.
Then update or reinstall the program so the vendor sets correct permissions.)~",
        LR"~(Restore the saved permissions (elevated PowerShell; the backup holds the file name, so name its folder):
  icacls "C:\path\to" /restore acl-backup.txt)~" });

    add({ L"svc.drivers", L"Driver services with a missing, unsigned or changeable file", CAT_SERVICES, Severity::High,
        { L"T1543.003", L"T1574.010" }, { L"4.1", L"2.5" }, L"",
        L"Drivers run inside the Windows kernel, with more power than any program. Each one is registered as a driver service "
        L"that names its file. A file that is not validly signed may have been changed, or built to slip past checks. If "
        L"normal users can change the file or its folder, a program running as a normal user can swap in its own code, which "
        L"Windows then loads into the kernel. A missing file means the entry is a leftover, and a file someone puts at that "
        L"path later would load. Boot and system start drivers load before almost anything else, so they are listed first. "
        L"This check reads each driver service's settings from the Service Control Manager and checks its file. It never "
        L"starts, stops or changes a driver, and it does not list the drivers loaded in memory. Disabled driver services are "
        L"not judged, because they cannot load until an administrator changes them.",
        LR"~(For each driver listed, find out what installed it: the file's Properties > Digital Signatures and Details tabs, or elevated PowerShell:
  Get-CimInstance Win32_SystemDriver -Filter "Name='DriverName'" | Format-List Name, PathName, StartMode, State
  Get-AuthenticodeSignature 'C:\path\to\driver.sys'
A device or program you still use: update or reinstall it from the vendor, which puts back a signed driver with the right permissions.
A leftover you do not need: back up its key, then disable the driver service (elevated PowerShell) and restart:
  reg export "HKLM\SYSTEM\CurrentControlSet\Services\DriverName" driver-backup.reg
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DriverName' -Name Start -Value 4 -Type DWord
Do not disable a boot or system start driver you cannot identify: Windows may not start without it. Ask the PC maker or the vendor first.
A file or folder normal users can change: save the permissions, then cut the group the evidence names down to read and run (elevated PowerShell):
  icacls "C:\the\folder" /save acl-backup.txt
  icacls "C:\the\folder" /inheritance:d
  icacls "C:\the\folder" /grant:r "*S-1-5-11:(OI)(CI)(RX)"
Use the SID of the group the evidence names: *S-1-5-11 Authenticated Users, *S-1-5-32-545 Users, *S-1-1-0 Everyone, *S-1-5-4 INTERACTIVE.)~",
        LR"~(Put the start type back (elevated PowerShell; 0 Boot, 1 System, 2 Automatic, 3 Manual, as the evidence showed), then restart:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DriverName' -Name Start -Value 3 -Type DWord
Or restore the whole key: reg import driver-backup.reg
Permissions (elevated PowerShell; the backup holds the folder name, so name its parent):
  icacls "C:\the" /restore acl-backup.txt)~" });

    add({ L"msi.alwayselevated", L"AlwaysInstallElevated", CAT_SERVICES, Severity::Critical,
        { L"T1218.007", L"T1548" }, { L"4.1" }, L"Always install with elevated privileges: Disabled",
        L"When this policy is on in both HKLM and HKCU, any user can install any .msi package with SYSTEM rights. That is a "
        L"one-step route from a normal account to full control.",
        LR"~(Elevated PowerShell:
  Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
  Remove-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
If Group Policy sets it, change the policy too: Administrative Templates > Windows Components > Windows Installer > Always install with elevated privileges = Disabled.)~",
        LR"~(Set-ItemProperty on both keys with -Name AlwaysInstallElevated -Value 1 -Type DWord. Only if you understand the risk.)~" });

    add({ L"dll.hijack", L"Folders where a planted DLL would load", CAT_SERVICES, Severity::High,
        { L"T1574.001" }, { L"4.1" }, L"",
        L"When a program loads a DLL by name, Windows searches its own folder first, then system folders, then every folder in "
        L"the system PATH. If a normal user can write to one of those folders, they can drop a DLL with the expected name and "
        L"it runs inside the program with the program's rights. This check covers the folders of services, the folders of "
        L"programs running right now as SYSTEM or administrator (with the DLLs each one loads that a copy there would "
        L"replace), and system PATH folders. Run it as administrator so it can see every running program.",
        LR"~(Save permissions, then cut the group the evidence names down to read and run on each folder listed (elevated PowerShell):
  icacls "C:\the\folder" /save acl-backup.txt
  icacls "C:\the\folder" /inheritance:d
  icacls "C:\the\folder" /grant:r "*S-1-5-11:(OI)(CI)(RX)"
/grant:r replaces everything that group was granted with read and run for the folder and everything in it, so the programs there keep working for normal users. Use the SID of the group the evidence names: *S-1-5-11 Authenticated Users, *S-1-5-32-545 Users, *S-1-1-0 Everyone, *S-1-5-4 INTERACTIVE. Run the audit again; repeat for any other group it then names.
If the evidence names your own account, the folder is one of yours (AppData, Downloads): move the program to C:\Program Files or take the folder out of PATH instead of changing permissions.
For PATH folders you do not need, remove them in System Properties > Environment Variables > System variables > Path.)~",
        LR"~(Restore the saved permissions (elevated PowerShell; the backup holds the folder name, so name its parent):
  icacls "C:\the" /restore acl-backup.txt)~" });

    add({ L"files.unattend", L"Leftover Windows setup files", CAT_SERVICES, Severity::High,
        { L"T1552.001" }, { L"4.1" }, L"",
        L"Automated Windows installs use answer files such as unattend.xml. They often contain the local administrator password, "
        L"sometimes only base64 encoded. Anyone who can read the file can read the password.",
        LR"~(Open each file listed. If it has a <Password> or <AdministratorPassword> block, change that account's password, then delete the file:
  Remove-Item 'C:\Windows\Panther\unattend.xml'
Keep an offline copy if your deployment team needs it.)~",
        LR"~(Restore the file from your offline copy.)~" });

    add({ L"gpp.cpassword", L"Passwords in Group Policy Preference files", CAT_SERVICES, Severity::Critical,
        { L"T1552.006" }, { L"4.1" }, L"",
        L"Older Group Policy Preferences could set passwords and stored them in SYSVOL as a cpassword value. Microsoft published "
        L"the key used to encrypt them, so any domain user can decrypt them. The files stay readable to every domain user until "
        L"someone deletes them.",
        LR"~(Change every password that appears in the files listed. Then remove the password from the preference item (or delete the item) in Group Policy Management.
MS14-025 stops new ones from being created but does not remove old ones. Use Windows LAPS for local admin passwords instead.)~",
        LR"~(No undo. Treat the old passwords as public.)~" });

    add({ L"svc.spooler", L"Print Spooler", CAT_SERVICES, Severity::Medium,
        { L"T1068" }, { L"4.8" }, L"Limits print driver installation to Administrators: Enabled",
        L"The Print Spooler runs as SYSTEM and has had serious bugs (PrintNightmare). A PC with no printers does not need it. "
        L"A PC that prints should let only administrators install printer drivers.",
        LR"~(No printers (elevated PowerShell):
  Stop-Service Spooler
  Set-Service Spooler -StartupType Disabled
With printers, restrict driver installs:
  if (-not (Test-Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint')) { New-Item 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Force | Out-Null }
  Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name RestrictDriverInstallationToAdministrators -Value 1 -Type DWord)~",
        LR"~(Set-Service Spooler -StartupType Automatic
Start-Service Spooler)~" });

    // ------------------------------------------------------------------ Network exposure
    add({ L"fw.profiles", L"Windows Firewall", CAT_NETWORK, Severity::High,
        { L"T1562.004" }, { L"4.4", L"4.5" }, L"Windows Firewall: Domain, Private, Public: Firewall state: On (recommended)",
        L"Windows Firewall blocks unsolicited inbound connections. It has three profiles: Domain (work network), Private (home) "
        L"and Public (cafe, hotel). Each should be on, and inbound connections should default to Block.",
        LR"~(Elevated PowerShell:
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block)~",
        LR"~(Set-NetFirewallProfile -Profile <name> -Enabled False   (not recommended))~" });

    add({ L"fw.rules", L"Inbound firewall rules open on public networks", CAT_NETWORK, Severity::Medium,
        { L"T1210" }, { L"4.4", L"4.5" }, L"",
        L"A firewall rule that allows inbound connections lets other computers reach a program on this PC. A rule for the "
        L"Public profile that accepts any remote address applies in cafes, hotels, airports and every other network Windows "
        L"treats as public, where anyone nearby can connect. Programs add such rules when they are installed, or when someone "
        L"ticks Public networks in the firewall prompt, and many are never needed again. A rule for a program in a folder "
        L"normal users can change, or where downloads and temporary files land, is listed first: whatever replaced that "
        L"program would get the same open door. Those rules, and rules that allow everything, make this a WARNING and are "
        L"the ones the fix plan turns off; the others are listed as INFO for review and do not lower the score. Windows' own rule groups (their group name is a Windows resource such as "
        L"@FirewallAPI.dll,-25000) and Store app rules are managed by Windows and limited to one program, service or port, so "
        L"they are skipped unless they allow everything. Rules limited to certain remote addresses, or to Private and Domain "
        L"networks only, are not listed. The rules are read through the Windows Firewall API; nothing is changed.",
        LR"~(For each rule you do not need on public networks, turn it off: Windows Defender Firewall with Advanced Security (wf.msc) > Inbound Rules > the rule > Disable Rule. Or keep it for home networks only: the rule's Properties > Advanced > untick Public.
Or elevated PowerShell, by the rule's unique name (the first command shows it):
  Get-NetFirewallRule -DisplayName 'Rule name' | Format-Table Name, DisplayName, Profile, Enabled
  Disable-NetFirewallRule -Name 'unique name'
A rule for a program in Downloads, Temp or another folder normal users can change: reinstall the program into C:\Program Files, then allow it again for Private networks only if it needs that.)~",
        LR"~(wf.msc > Inbound Rules > the rule > Enable Rule. Or elevated PowerShell:
  Enable-NetFirewallRule -Name 'unique name')~" });

    add({ L"net.listening", L"Programs listening on the network", CAT_NETWORK, Severity::Medium,
        { L"T1210" }, { L"4.4", L"4.8" }, L"",
        L"A listening program waits for other computers to connect to it. Each one is a door. Doors opened by unsigned programs, "
        L"or by programs running from user folders, are the ones to look at first.",
        LR"~(For each program you do not recognise or need: uninstall it, or turn off its network feature in its own settings.
Then make sure the firewall blocks it: Windows Security > Firewall and network protection > Allow an app through firewall, and untick it.)~",
        LR"~(Reinstall the program, or tick it again in Allow an app through firewall.)~" });

    add({ L"net.llmnr", L"LLMNR name lookups", CAT_NETWORK, Severity::High,
        { L"T1557.001" }, { L"4.8" }, L"Turn off multicast name resolution: Enabled",
        L"When DNS cannot find a name, Windows shouts the question to the whole local network with LLMNR. Any device can answer "
        L"\"that is me\", and the PC then sends it a login attempt with a password hash that can be cracked or relayed.",
        LR"~(Elevated PowerShell:
  if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient')) { New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null }
  Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord
Or Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled.)~",
        LR"~(Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast)~" });

    add({ L"net.nbtns", L"NetBIOS name lookups", CAT_NETWORK, Severity::High,
        { L"T1557.001" }, { L"4.8" }, L"",
        L"NetBIOS name service is the older cousin of LLMNR. It broadcasts name lookups to the local network and trusts whoever "
        L"answers, with the same password-hash leak.",
        LR"~(Elevated PowerShell, all adapters:
  Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty $_.PSPath -Name NetbiosOptions -Value 2 }
Or per adapter: adapter properties > IPv4 > Advanced > WINS > Disable NetBIOS over TCP/IP. Very old shares that only resolve by NetBIOS name will stop resolving.)~",
        LR"~(Same command with -Value 0 (use the DHCP server's setting).)~" });

    add({ L"net.mdns", L"Multicast DNS", CAT_NETWORK, Severity::Medium,
        { L"T1557" }, { L"4.8" }, L"",
        L"Multicast DNS answers name questions on the local network without a server. Like LLMNR it trusts any reply, which "
        L"lets a device on the same network pose as another.",
        LR"~(Elevated PowerShell, then reboot:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS -Value 0 -Type DWord
Some casting and printer discovery features use mDNS. Test them after the change.)~",
        LR"~(Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS)~" });

    add({ L"net.smbsigning", L"SMB signing", CAT_NETWORK, Severity::High,
        { L"T1557.001" }, { L"3.10" }, L"Microsoft network client: Digitally sign communications (always): Enabled",
        L"SMB is Windows file sharing. Signing proves each message came from the real server. Without required signing, an "
        L"attacker who tricks this PC into connecting can relay its login to another server and act as this user there.",
        LR"~(Elevated PowerShell:
  Set-SmbClientConfiguration -RequireSecuritySignature $true -Force)~",
        LR"~(Set-SmbClientConfiguration -RequireSecuritySignature $false -Force)~" });

    add({ L"net.smbv1", L"SMB version 1", CAT_NETWORK, Severity::High,
        { L"T1210" }, { L"4.8" }, L"Configure SMB v1 client driver: Disable driver; Configure SMB v1 server: Disabled",
        L"SMB version 1 is the 30-year-old file sharing protocol that WannaCry and NotPetya spread through. Nothing current needs "
        L"it. Windows 10 1709 and later remove it by default, but upgrades can keep it.",
        LR"~(Elevated PowerShell, then reboot:
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Very old NAS boxes and scanners that only speak SMB1 will stop working. Update or replace them.)~",
        LR"~(Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All)~" });

    add({ L"net.shares", L"Shared folders others can change", CAT_NETWORK, Severity::High,
        { L"T1080" }, { L"3.3" }, L"",
        L"A shared folder can be opened from other computers on the network. Windows checks two lists before it lets anyone "
        L"change a file there: the share's own permissions and the folder's NTFS permissions, and the stricter one wins. When "
        L"both let Everyone, Authenticated Users, Users or Guest change files, any account on the network, and with guest "
        L"access anyone at all, can add, change or delete files in it. Ransomware on another PC then encrypts the share too, "
        L"and a program or document kept there can be swapped for a harmful one that others open. Windows' own administrative "
        L"shares (C$, ADMIN$, IPC$, print$) are skipped: only administrators can use them. Only each share's top folder is "
        L"checked, not every folder inside it. A share with no stored permissions counts as open to Everyone. As a normal user "
        L"the share list is read from the registry, and a share whose permissions cannot be read is reported as not judged.",
        LR"~(If nobody needs to change files there over the network, make the share read-only for that group: right-click the folder > Properties > Sharing > Advanced Sharing > Permissions, select the group the evidence names and untick Full Control and Change. Or elevated PowerShell (the share name and group from the evidence):
  Revoke-SmbShareAccess -Name 'ShareName' -AccountName 'Everyone' -Force
  Grant-SmbShareAccess -Name 'ShareName' -AccountName 'Everyone' -AccessRight Read -Force
If some people do need to change files, give Change to their own accounts instead of a broad group:
  Grant-SmbShareAccess -Name 'ShareName' -AccountName 'PC\name' -AccessRight Change -Force
If the folder does not need to be shared at all:
  Remove-SmbShare -Name 'ShareName' -Force)~",
        LR"~(Give the group back the right the evidence showed, Full or Change (elevated PowerShell):
  Revoke-SmbShareAccess -Name 'ShareName' -AccountName 'Everyone' -Force
  Grant-SmbShareAccess -Name 'ShareName' -AccountName 'Everyone' -AccessRight Full -Force
A removed share:
  New-SmbShare -Name 'ShareName' -Path 'C:\the\folder' -FullAccess 'Everyone')~" });

    add({ L"net.smbguest", L"Guest and anonymous file sharing access", CAT_NETWORK, Severity::Medium,
        { L"T1557", L"T1135" }, { L"4.1", L"3.3" },
        L"Enable insecure guest logons: Disabled; Network access: Restrict anonymous access to Named Pipes and Shares: Enabled",
        L"Insecure guest logons let this PC open another computer's shared folders without an account, as a guest. Guest "
        L"connections cannot be signed, so a device on the network that pretends to be that file server can hand this PC "
        L"harmful files or read what it sends, and Windows does not warn. Windows turns guest logons off by default on Server "
        L"2019 and later and on Enterprise and Education since Windows 10 1709, and on Pro since Windows 11 24H2; Home still "
        L"allows them. This check reads the Group Policy and the local AllowInsecureGuestAuth values and, when neither is set, "
        L"decides from the Windows edition and build. It also looks at this PC as a file server: RestrictNullSessAccess = 0 "
        L"lets anyone on the network connect without signing in and list shares and named pipes, and NullSessionShares names "
        L"shares anyone may open without signing in. A NAS box that only offers guest access stops working once guest logons "
        L"are off: give it an account instead.",
        LR"~(Elevated PowerShell (the second line takes effect after a restart):
  Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RestrictNullSessAccess -Value 1 -Type DWord
If Group Policy allows guest logons, change the policy as well: Computer Configuration > Administrative Templates > Network > Lanman Workstation > Enable insecure guest logons = Disabled.
Shares listed under NullSessionShares: remove them from that value (regedit, HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters > NullSessionShares) unless a device truly needs anonymous access.
A NAS that only offers guest access: create an account on it and connect with that account.)~",
        LR"~(Only what the evidence showed before the fix (elevated PowerShell):
  Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RestrictNullSessAccess -Value 0 -Type DWord)~" });

    add({ L"net.rdp", L"Remote Desktop", CAT_NETWORK, Severity::Medium,
        { L"T1021.001" }, { L"4.8" }, L"Require user authentication for remote connections by using Network Level Authentication: Enabled",
        L"Remote Desktop lets someone log in to this PC over the network. If you do not use it, it is a door left open. If you "
        L"do, Network Level Authentication (NLA) should be required so the login happens before a session is created.",
        LR"~(Not needed: Settings > System > Remote Desktop > Off.
Needed: require NLA (elevated PowerShell):
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
Never expose port 3389 directly to the internet.)~",
        LR"~(Settings > System > Remote Desktop > On. NLA off: the same command with -Value 0.)~" });

    add({ L"net.remoteassist", L"Remote Assistance", CAT_NETWORK, Severity::Medium,
        { L"T1219" }, { L"4.8" }, L"Configure Offer Remote Assistance: Disabled; Configure Solicited Remote Assistance: Disabled",
        L"Remote Assistance (msra.exe) lets someone you invite see your screen and, when allowed, take control of the mouse "
        L"and keyboard. It is a support feature, and a favourite of \"tech support\" scammers: a caller who claims to be from "
        L"Microsoft, a bank or an internet provider talks the person at the PC into sending an invitation, then takes over. "
        L"Windows allows invitations, with control, unless someone turns that off. Offers of help nobody asked for "
        L"(unsolicited Remote Assistance) can only be turned on by Group Policy, for the helpers it names. This check warns "
        L"when an invited helper may take control, or when unsolicited offers are allowed; Remote Assistance that is off, "
        L"or that only lets a helper view the screen, passes. A missing setting is read as the Windows default (on). Quick "
        L"Assist, a separate app, is not judged.",
        LR"~(System Properties > Remote (Win+R, SystemPropertiesRemote) > untick Allow Remote Assistance connections to this computer > OK. To keep it for help you ask for, view only: Advanced > untick Allow this computer to be controlled remotely. Or elevated PowerShell:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0 -Type DWord
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowFullControl -Value 0 -Type DWord
If Group Policy turns it on: Computer Configuration > Administrative Templates > System > Remote Assistance > Configure Offer Remote Assistance = Disabled, and Configure Solicited Remote Assistance = Disabled.
Never send an invitation, or let anyone connect, because someone who called you asks for it.)~",
        LR"~(Tick the same boxes again. Or elevated PowerShell:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 1 -Type DWord
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowFullControl -Value 1 -Type DWord)~" });

    add({ L"net.winrm", L"Windows Remote Management", CAT_NETWORK, Severity::Medium,
        { L"T1021.006" }, { L"4.8" }, L"",
        L"Windows Remote Management lets administrators run commands on this PC remotely (PowerShell remoting). It is useful in "
        L"managed networks and a way to move between PCs everywhere else.",
        LR"~(If nobody manages this PC remotely (elevated PowerShell):
  Disable-PSRemoting -Force
  Remove-Item -Path WSMan:\Localhost\listener\* -Recurse
  Stop-Service WinRM
  Set-Service WinRM -StartupType Manual)~",
        LR"~(Enable-PSRemoting -Force)~" });

    add({ L"net.remoteregistry", L"Remote Registry service", CAT_NETWORK, Severity::Medium,
        { L"T1112" }, { L"4.8" }, L"",
        L"The Remote Registry service lets other computers read and change this PC's registry over the network. Windows 10 and "
        L"11 ship with it disabled.",
        LR"~(Elevated PowerShell:
  Stop-Service RemoteRegistry
  Set-Service RemoteRegistry -StartupType Disabled)~",
        LR"~(Set-Service RemoteRegistry -StartupType Manual)~" });

    add({ L"net.wpad", L"Automatic proxy detection (WPAD)", CAT_NETWORK, Severity::Medium,
        { L"T1557.001", L"T1090.001" }, { L"4.8" }, L"",
        L"Automatic proxy detection makes the PC look for proxy settings on the local network. Anyone who answers that lookup "
        L"can route web traffic through themselves and capture logins.",
        LR"~(Settings > Network and internet > Proxy > Automatically detect settings = Off.
If your organization relies on WPAD, use a fixed setup script address instead.)~",
        LR"~(Turn Automatically detect settings back On.)~" });

    add({ L"net.wifiopen", L"Open Wi-Fi networks that connect automatically", CAT_NETWORK, Severity::Medium,
        { L"T1557" }, {}, L"",
        L"A saved Wi-Fi network without a password (an open network, as in many cafes, hotels and airports) is recognised only "
        L"by its name. If it is set to connect automatically, the PC joins any network that uses that name, including one set "
        L"up nearby to watch or change the traffic. Turning off automatic connection for open networks, or forgetting them, "
        L"stops that. Networks with a WPA2 or WPA3 password and Enhanced Open (OWE) networks are not listed. This check never "
        L"reads Wi-Fi passwords.",
        LR"~(For each network listed (Command Prompt; elevated if the network is saved for all users):
  netsh wlan set profileparameter name="<name>" connectionmode=manual
Or in Settings > Network and internet > Wi-Fi > Manage known networks > the network: untick Connect automatically when in range, or Forget it. From the command line:
  netsh wlan delete profile name="<name>")~",
        LR"~(netsh wlan set profileparameter name="<name>" connectionmode=auto
A forgotten network: connect to it again from the Wi-Fi list.)~" });

    add({ L"net.hosts", L"Hosts file redirects", CAT_NETWORK, Severity::Medium,
        { L"T1562.001" }, { L"9.2" }, L"",
        L"The hosts file overrides DNS on this PC. Malware edits it to send security and update sites nowhere, or to send banking "
        L"sites to a fake copy. Developers also use it for test setups, which is harmless. Malware can also point Windows at a "
        L"different hosts folder through the DataBasePath registry value; the evidence names the file that was read.",
        LR"~(Open Notepad as administrator, open the hosts file named in the evidence (normally C:\Windows\System32\drivers\etc\hosts), and delete the lines you did not add. Then:
  ipconfig /flushdns)~",
        LR"~(Add the lines back to the same file.)~" });

    add({ L"net.dns", L"DNS servers", CAT_NETWORK, Severity::Low,
        {}, { L"9.2" }, L"",
        L"DNS turns names into addresses. Whoever runs your DNS server can send you anywhere. Malware such as DNSChanger set "
        L"static DNS servers on infected PCs. A static DNS server you did not choose is worth a second look.",
        LR"~(Check each server listed. If you did not set it: Settings > Network and internet > your adapter > DNS server assignment > Automatic (DHCP).
For filtering and encryption, choose a well-known resolver and turn on DNS over HTTPS in the same screen.)~",
        LR"~(Set the DNS servers back in the same screen.)~" });

    add({ L"net.doh", L"DNS over HTTPS", CAT_NETWORK, Severity::Info,
        {}, { L"3.10" }, L"Configure DNS over HTTPS (DoH) name resolution: Enabled: Allow DoH",
        L"DNS turns names such as example.com into addresses. Plain DNS travels unencrypted, so others on the same network, "
        L"for example on public Wi-Fi or whoever runs that network, can see which names this PC looks up and could answer "
        L"with a wrong address. DNS over HTTPS (DoH) encrypts the lookups between this PC and its DNS server. It does not "
        L"hide the lookups from that DNS server, it does not hide which addresses the PC then connects to (the internet "
        L"provider still sees those), and it does not help when the DNS server itself cannot be trusted. Plenty of safe "
        L"setups use plain DNS to a home router or a company DNS server, so this check never warns: it reports the DoH Group "
        L"Policy, Windows' automatic DoH setting and each adapter's DoH setting as INFO, and its Info severity counts for "
        L"nothing in the hardening score. The evidence shows each adapter's raw DohFlags value; the Settings app can also "
        L"allow a fallback to plain DNS when DoH does not answer. The DNS servers check lists the servers themselves.",
        LR"~(Settings > Network and internet > Wi-Fi or Ethernet > the adapter's Hardware properties > DNS server assignment > Edit > Manual. Turn on IPv4 (and IPv6 if used), enter the DNS servers, set DNS over HTTPS = On (automatic template), and turn Fallback to plaintext off for encrypted lookups only.
The automatic template works for the public servers Windows knows (the evidence counts them); for another server choose On (manual template) and type its DoH address.
A company PC gets its DNS settings from its IT department.)~",
        LR"~(Same screen > DNS over HTTPS = Off, or DNS server assignment > Edit > Automatic (DHCP).)~" });

    add({ L"cert.roots", L"Trusted root certificates", CAT_NETWORK, Severity::Medium,
        { L"T1553.004" }, { L"3.10" }, L"",
        L"Root certificates decide which secure (HTTPS) sites and signed programs your PC trusts. A root you did not install "
        L"lets whoever holds its key read your encrypted web traffic or make their programs look signed. Some adware and "
        L"interception tools add one. Company PCs and some antivirus products add their own on purpose.",
        LR"~(Open certlm.msc (computer) and certmgr.msc (your account), go to Trusted Root Certification Authorities > Certificates, and look up each root listed by its thumbprint.
Export a root before you remove it: right-click > All Tasks > Export. Then delete it, or in elevated PowerShell:
  Remove-Item Cert:\LocalMachine\Root\<thumbprint>
If a program you use installed it on purpose (antivirus web filtering, a company proxy), keep it.)~",
        LR"~(Import the exported file: right-click Certificates > All Tasks > Import, or elevated PowerShell:
  Import-Certificate -FilePath root.cer -CertStoreLocation Cert:\LocalMachine\Root)~" });

    // ------------------------------------------------------------------ Persistence
    add({ L"persist.sweep", L"Autostart locations", CAT_PERSIST, Severity::High,
        { L"T1547", L"T1546", L"T1543.003", L"T1137", L"T1176" }, {}, L"",
        L"Windows has dozens of places where a program can register to start on its own: Run keys, the Startup folder, Winlogon, "
        L"Image File Execution Options, AppInit DLLs, WMI event subscriptions, LSA packages, print monitors, shell extensions, "
        L"COM registrations, Office add-ins, browser extensions and services. Malware uses the obscure ones because nobody "
        L"looks there. This check lists every entry, flags the risky ones, and marks entries that are new since the last audit.",
        LR"~(Find out what each flagged program is before you remove anything. Unsigned programs in user folders, IFEO debuggers, WMI command consumers and unknown LSA packages are rarely legitimate.
Remove a Run key entry:
  Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'EntryName'
For the deeper locations, Microsoft Sysinternals Autoruns can disable an entry without deleting it.)~",
        LR"~(Export the key before removing anything:
  reg export "<key>" backup.reg
Import it to undo:
  reg import backup.reg)~" });

    add({ L"persist.tasks", L"Scheduled tasks", CAT_PERSIST, Severity::High,
        { L"T1053.005" }, {}, L"",
        L"Scheduled tasks start programs at logon, at boot or on a timer. Malware uses them to come back after a reboot. Tasks "
        L"that run a program from a user folder, run an encoded or downloading command, or point at a file that no longer "
        L"exists deserve a look. Tasks this account cannot read are listed by name; run as administrator to check what they "
        L"run. A task file that Task Scheduler hides even from an administrator is a known way to hide a task.",
        LR"~(Open Task Scheduler (taskschd.msc), find the task by the path shown and check its Actions tab. If you do not recognise it: right-click > Export (keeps a copy), then right-click > Disable.
Delete it once you are sure:
  Unregister-ScheduledTask -TaskPath '\folder\' -TaskName 'name' -Confirm:$false)~",
        LR"~(A disabled task: right-click > Enable. A deleted task: Task Scheduler > Import Task and pick the exported XML.)~" });

    // ------------------------------------------------------------------ Running programs
    add({ L"proc.image", L"Running programs", CAT_RUNNING, Severity::High,
        { L"T1036.005", L"T1204.002" }, { L"2.5" }, L"",
        L"Every running program was started from a file. Programs running from Temp or Downloads, programs with a Windows system "
        L"name in the wrong folder, programs started by Office, and programs not in your baseline are the usual signs that "
        L"something unexpected is running.",
        LR"~(For each program listed, right-click it in Task Manager > Open file location and check what it is.
If you do not trust it: end it, remove its autostart entry (see Autostart locations), delete the file, and run a full antivirus scan.)~",
        LR"~(Restore a file from the antivirus quarantine if it was removed by mistake.)~" });

    // ------------------------------------------------------------------ Logging and audit
    add({ L"audit.subcategories", L"Audit policy", CAT_LOGGING, Severity::High,
        { L"T1562.002" }, { L"8.2", L"8.5" }, L"Advanced Audit Policy Configuration (the subcategories listed in the evidence)",
        L"The audit policy decides which security events Windows records at all: logons, new processes, account and group "
        L"changes, use of powerful privileges. If a category is off, nothing about it is ever written, and an investigation "
        L"has nothing to work with.",
        LR"~(Elevated Command Prompt, one line per subcategory the evidence lists (GUIDs work in every Windows language), for example:
  auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable
  auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
Also record the command line of new processes:
  reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f)~",
        LR"~(auditpol /set /subcategory:{GUID} /success:disable /failure:disable)~" });

    add({ L"audit.policy", L"Event log size and channels", CAT_LOGGING, Severity::Medium,
        { L"T1562.002" }, { L"8.2", L"8.3" }, L"Security: Specify the maximum log file size (KB): 196,608 or greater",
        L"Windows writes security events to the Security log. If that log is small it overwrites itself within hours, and the "
        L"record of an intrusion is gone before anyone looks.",
        LR"~(Elevated PowerShell:
  wevtutil sl Security /ms:209715200
  wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true /ms:104857600
That sets the Security log to 200 MB and turns on the PowerShell operational log at 100 MB.)~",
        LR"~(wevtutil sl Security /ms:20971520
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:15728640
These are the Windows default sizes (20 MB and 15 MB).)~" });

    add({ L"ps.logging", L"PowerShell logging", CAT_LOGGING, Severity::Medium,
        { L"T1059.001" }, { L"8.2", L"8.8" }, L"Turn on PowerShell Script Block Logging: Enabled",
        L"Most modern attacks use PowerShell at some point. Script block logging records the code that actually ran, even when "
        L"it was obfuscated, so you can find out later what happened. Module logging records the commands.",
        LR"~(Elevated PowerShell:
  if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging')) { New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null }
  Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord
  if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames')) { New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force | Out-Null }
  Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -Value 1 -Type DWord
  Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*'
Logs land in Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational.)~",
        LR"~(Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Recurse)~" });

    // ------------------------------------------------------------------ Recent activity
    // These read this PC's own event logs and report what happened lately. They
    // describe events, not settings, so they are not scored (the last field).
    add({ L"events.logcleared", L"Event logs cleared", CAT_EVENTS, Severity::High,
        { L"T1070.001" }, { L"8.11" }, L"",
        L"Windows records when an event log is cleared: event 1102 in the Security log, and event 104 in the System log for "
        L"any other log. Administrators sometimes clear logs on purpose, for example while fixing a problem or before handing "
        L"a PC over. Malware and intruders clear them to hide what they did. This check reports the clears of the last 30 days "
        L"and the account that cleared the log when the event names one. Reading the Security log needs administrator rights; "
        L"without them only the System log is checked. It reports events, not a setting, so it does not change the hardening score.",
        LR"~(Find out who cleared the log and why. Event Viewer (eventvwr.msc) > Windows Logs > Security, filter on event 1102, and Windows Logs > System, filter on event 104. Or PowerShell (elevated for the Security log):
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 20 | Format-List TimeCreated, Message
  Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Eventlog'; Id=104} -MaxEvents 20 | Format-List TimeCreated, Message
If nobody you know cleared it, treat the PC as possibly compromised: run a full scan (Start-MpScan -ScanType FullScan) and change the passwords of the accounts used on it.
Make the Security log big enough that it never needs clearing (see Event log size and channels).)~",
        LR"~(Nothing to undo: this check only reads the event logs. A cleared log cannot be brought back, except from a backup or a copy kept on another system.)~",
        false });

    add({ L"events.newservices", L"Services installed recently", CAT_EVENTS, Severity::Medium,
        { L"T1543.003" }, { L"8.11" }, L"",
        L"A service is a program Windows starts on its own, usually with full SYSTEM rights. Event 7045 in the System log "
        L"records every new service and driver. Installers add services all the time, so most entries are expected. A new "
        L"service whose program sits in a user folder (Temp, Downloads), in a folder normal users can change, is not validly "
        L"signed, is already gone, or is a command shell running an encoded or downloading command is a common sign of "
        L"malware, or of a remote administration tool someone ran on this PC. This check lists the services installed in the "
        L"last 14 days with program and start type, and flags those. A service removed again together with its program from "
        L"Program Files (an uninstall, or a Store app update) is listed but not flagged. Command line arguments are never "
        L"shown, because they can hold passwords. It reports events, not a setting, so it does not change the hardening score.",
        LR"~(For each service marked worth a look, find out what installed it (elevated PowerShell):
  Get-CimInstance Win32_Service -Filter "Name='ServiceName'" | Format-List Name, PathName, StartMode, State, StartName
  Get-AuthenticodeSignature 'C:\path\to\program.exe'
If you do not recognise it, back up its key, stop and disable it, and scan its program:
  reg export "HKLM\SYSTEM\CurrentControlSet\Services\ServiceName" service-backup.reg
  Stop-Service -Name 'ServiceName'
  Set-Service -Name 'ServiceName' -StartupType Disabled
  Start-MpScan -ScanType CustomScan -ScanPath 'C:\path\to\program.exe'
Delete it once you are sure nothing needs it:
  sc.exe delete ServiceName)~",
        LR"~(A disabled service (elevated PowerShell; use the start type the evidence showed):
  Set-Service -Name 'ServiceName' -StartupType Automatic
  Start-Service -Name 'ServiceName'
A deleted service: reg import service-backup.reg, then restart the PC.)~",
        false });

    add({ L"events.newaccounts", L"Accounts created or made administrator", CAT_EVENTS, Severity::High,
        { L"T1136.001", L"T1098" }, { L"8.11", L"5.1" }, L"",
        L"Event 4720 in the Security log records a new local account, and event 4732 a member added to a local group; this "
        L"check reports the additions to the Administrators group. Someone who gets into a PC often creates an account, or "
        L"makes an existing one an administrator, so they can come back. Setting up the PC or a new user also does this, so "
        L"compare each entry with what you did in the last 30 days. Reading the Security log needs administrator rights. It "
        L"reports events, not a setting, so it does not change the hardening score.",
        LR"~(Check each account listed (elevated PowerShell):
  Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet
  Get-LocalGroupMember -SID S-1-5-32-544
If you did not create the account or make it an administrator, disable it and take the rights away:
  Disable-LocalUser -Name 'name'
  Remove-LocalGroupMember -SID S-1-5-32-544 -Member 'name'
Then change the passwords of the other administrator accounts and run a full scan (Start-MpScan -ScanType FullScan).)~",
        LR"~(Enable-LocalUser -Name 'name'
Add-LocalGroupMember -SID S-1-5-32-544 -Member 'name')~",
        false });

    add({ L"events.failedlogons", L"Failed sign-ins and lockouts", CAT_EVENTS, Severity::Medium,
        { L"T1110" }, { L"8.11" }, L"",
        L"Event 4625 in the Security log records every failed sign-in, and event 4740 an account locked out after too many. "
        L"A few failures are typing mistakes. Many failures in a short time, failures over the network or through Remote "
        L"Desktop, or failures for account names nobody uses mean someone is guessing passwords. This check counts the "
        L"failures of the last 7 days and warns at 20 or more, or at any lockout, with the account names tried most and the "
        L"sign-in types. Reading the Security log needs administrator rights. It reports events, not a setting, so it does "
        L"not change the hardening score.",
        LR"~(See when and from where the attempts came (elevated PowerShell):
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-7)} | ForEach-Object { $e = $_; $d = @{}; ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }; [pscustomobject]@{ Time = $e.TimeCreated; Account = $d['TargetUserName']; Type = $d['LogonType']; From = $d['IpAddress'] } } | Format-Table
Attempts over the network (type 3) or Remote Desktop (type 10) from addresses you do not know: turn off Remote Desktop if you do not use it (see Remote Desktop) and make sure it is not reachable from the internet.
Use long passwords, and set a lockout policy (see Password and lockout policy) so a guesser is stopped after a few tries.)~",
        LR"~(Nothing to undo: this check only reads the event logs. Each change suggested above has its undo in its own check.)~",
        false });

    add({ L"events.defender", L"Microsoft Defender detections", CAT_EVENTS, Severity::High,
        { L"T1562.001" }, { L"8.11", L"10.1" }, L"",
        L"Microsoft Defender writes to its own log: event 1116 when it finds a threat, 1117 when it acts on it (quarantine, "
        L"remove), and 5001 when real-time protection is turned off, by a person, a policy, another antivirus product or "
        L"malware. A threat that was cleaned is good news, but it shows something harmful reached this PC, and it is worth "
        L"knowing how. Only file and program names are shown: command lines are cut to the program, because they can hold "
        L"passwords. When another antivirus product is in charge the log may not exist, and the check is N/A. It reports "
        L"events, not a setting, so it does not change the hardening score.",
        LR"~(Review each detection in Windows Security > Virus and threat protection > Protection history. Or PowerShell:
  Get-MpThreatDetection | Format-List InitialDetectionTime, ThreatID, ActionSuccess, Resources
Then run a full scan:
  Start-MpScan -ScanType FullScan
If real-time protection was turned off and you did not do it, turn it back on (elevated PowerShell) and find out what turned it off:
  Set-MpPreference -DisableRealtimeMonitoring $false
Think about where each detected file came from (a download, a USB stick, an email attachment) so it does not come back.)~",
        LR"~(Nothing to undo: this check only reads the event logs. A file quarantined by mistake can be restored in Windows Security > Protection history > the entry > Actions > Restore.)~",
        false });

    return c;
}

const std::vector<CheckInfo>& GetCheckCatalog()
{
    static const std::vector<CheckInfo> catalog = [] {
        std::vector<CheckInfo> rows = BuildCatalog();
        AttachCheckScripts(rows);   // fixScript, undoScript and their traits (CheckScripts.cpp)
        return rows;
    }();
    return catalog;
}

const CheckInfo* FindCheckInfo(const std::wstring& id)
{
    for (const CheckInfo& info : GetCheckCatalog()) {
        if (info.id == id) return &info;
    }
    return nullptr;
}

std::wstring SeverityName(Severity severity)
{
    switch (severity) {
    case Severity::Critical: return L"Critical";
    case Severity::High:     return L"High";
    case Severity::Medium:   return L"Medium";
    case Severity::Low:      return L"Low";
    default:                 return L"Info";
    }
}

int SeverityWeight(Severity severity)
{
    switch (severity) {
    case Severity::Critical: return 10;
    case Severity::High:     return 6;
    case Severity::Medium:   return 3;
    case Severity::Low:      return 1;
    default:                 return 0;
    }
}

static std::wstring IndentBlock(const std::wstring& text)
{
    std::wstring out = L"    ";
    for (wchar_t c : text) {
        out += c;
        if (c == L'\n') out += L"    ";
    }
    return out;
}

std::wstring BuildFindingsMarkdown()
{
    std::wstringstream md;
    md << L"# What the findings mean\n\n";
    md << L"Generated from the check catalog of " << PHANTOMRECON_NAME_W << L" " << PHANTOMRECON_VERSION_W
       << L". Do not edit by hand; run `PhantomReconCli.exe --findings-md docs/FINDINGS.md` instead.\n\n";
    md << L"Each check below says what it looks at, why it matters, how to fix it and how to undo the fix. "
       << L"Commands marked elevated need a PowerShell or Command Prompt opened with Run as administrator.\n\n";
    md << L"Severity drives the hardening score: Critical counts 10, High 6, Medium 3, Low 1, Info 0 "
       << L"(an Info check only describes a setting). "
       << L"Checks marked not scored (Recent activity) report events from this PC's logs rather than a setting, "
       << L"and never change the score.\n\n";

    for (const std::wstring& category : GetCheckCategories()) {
        md << L"## " << category << L"\n\n";
        for (const CheckInfo& info : GetCheckCatalog()) {
            if (info.category != category) continue;
            md << L"### " << info.title << L"\n\n";
            md << L"- Check id: `" << info.id << L"`\n";
            md << L"- Severity: " << SeverityName(info.severity) << L"\n";
            if (!info.scored) md << L"- Hardening score: not scored (it reports events, not a setting)\n";
            if (!info.attack.empty()) {
                md << L"- MITRE ATT&CK: ";
                for (size_t i = 0; i < info.attack.size(); ++i) {
                    if (i > 0) md << L", ";
                    md << info.attack[i] << L" " << AttackTechniqueName(info.attack[i]);
                }
                md << L"\n";
            }
            if (!info.cisControls.empty()) {
                md << L"- CIS Controls v8: ";
                for (size_t i = 0; i < info.cisControls.size(); ++i) {
                    if (i > 0) md << L", ";
                    md << info.cisControls[i];
                }
                md << L"\n";
            }
            if (!info.cisBenchmark.empty()) {
                md << L"- CIS Windows Benchmark: " << info.cisBenchmark << L"\n";
            }
            md << L"\n" << info.explanation << L"\n\n";
            md << L"**How to fix**\n\n" << IndentBlock(info.fix) << L"\n\n";
            md << L"**How to undo**\n\n" << IndentBlock(info.undo) << L"\n\n";
        }
    }
    return md.str();
}
