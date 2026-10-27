#include "pch.h"
#include "CheckScripts.h"

#include <windows.h>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[CheckScripts] " + msg + L"\n").c_str());
}

// Raw strings keep registry paths readable; each line is one statement.
const std::vector<CheckScript>& GetCheckScripts()
{
    static const std::vector<CheckScript> scripts = {
        // ------------------------------------------------------------------ Malware protection
        { L"def.realtime",
          L"Set-MpPreference -DisableRealtimeMonitoring $false",
          L"",
          false, true, false,
          L"If another antivirus program is installed, Microsoft Defender steps back on purpose and this step fails. Then make sure that program is on and up to date.",
          L"" },
        { L"def.cloud",
          L"Set-MpPreference -MAPSReporting Advanced",
          L"Set-MpPreference -MAPSReporting Disabled",
          false, true, false, L"", L"" },
        { L"def.signatures",
          L"Update-MpSignature",
          L"",
          false, true, false,
          L"If this fails, check that Windows Update works and that no policy blocks Defender updates.",
          L"" },
        { L"def.asr",
          L"Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled",
          L"Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Disabled",
          false, true, false,
          L"This turns on one rule only: the one that blocks credential theft from LSASS. Try other rules in AuditMode first.",
          L"" },
        { L"def.cfa",
          L"Set-MpPreference -EnableControlledFolderAccess Enabled",
          L"Set-MpPreference -EnableControlledFolderAccess Disabled",
          false, true, false,
          L"It can block programs you use until you allow them. To see first what it would block, skip this step and run Set-MpPreference -EnableControlledFolderAccess AuditMode.",
          L"" },

        // ------------------------------------------------------------------ Platform hardening
        { L"hard.uac",
          LR"~(Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 5
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Value 1)~",
          L"",
          false, true, true, L"", L"" },
        { L"hard.autoplay",
          LR"~(New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -Value 1 -Type DWord)~",
          LR"~(Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun,NoAutorun)~",
          false, true, false, L"", L"" },
        { L"hard.wsh",
          LR"~(New-Item 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 0 -Type DWord)~",
          LR"~(Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -Value 1 -Type DWord)~",
          false, true, false,
          L"Skip this step if anything on this PC uses .vbs or .js scripts (some company login scripts do).",
          L"" },
        { L"hard.psv2",
          L"Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
          L"Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
          false, true, true, L"", L"" },
        { L"hard.hvci",
          LR"~(New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Force | Out-Null
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -Value 1 -Type DWord)~",
          LR"~(Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled -Value 0 -Type DWord)~",
          false, true, true,
          L"If Windows Security > Device security > Core isolation details lists incompatible drivers, update or remove them first: memory integrity stays off while one is installed.",
          L"If Group Policy turned memory integrity on, set that policy back instead." },
        { L"hard.driverblocklist",
          LR"~(New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Force | Out-Null
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable -Value 1 -Type DWord)~",
          LR"~(Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable -Value 0 -Type DWord)~",
          false, true, true,
          L"If a device stops working after the restart, its driver is on the list: get a current driver from the vendor.",
          L"" },
        { L"backup.restore",
          L"Enable-ComputerRestore -Drive ($env:SystemDrive + '\\')",
          L"Disable-ComputerRestore -Drive ($env:SystemDrive + '\\')",
          false, true, false,
          L"If Group Policy turned System Restore off, set that policy (System > System Restore > Turn off System Restore) to Not Configured as well.",
          L"This deletes the system drive's restore points." },

        // ------------------------------------------------------------------ Credential protection
        { L"lsa.ppl",
          LR"~(Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 2 -Type DWord)~",
          LR"~(Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL)~",
          false, true, true,
          L"Some old smart card drivers and plug-ins fail to load with it. Events 3065 and 3066 in Microsoft-Windows-CodeIntegrity/Operational show anything blocked.",
          L"" },
        { L"acct.guest",
          L"Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Disable-LocalUser",
          L"Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Enable-LocalUser",
          false, true, false, L"", L"" },
        { L"acct.admin",
          L"Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Disable-LocalUser",
          L"Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Enable-LocalUser",
          false, true, false,
          L"Make sure you can sign in with another administrator account before you apply this step.",
          L"" },
        { L"acct.passwordpolicy",
          L"net accounts /minpwlen:14 /lockoutthreshold:5 /lockoutwindow:15 /lockoutduration:15",
          L"",
          false, true, false,
          L"Domain-joined PCs take these settings from the domain policy instead.",
          L"" },
        { L"acct.screenlock",
          LR"~(Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -Value 900 -Type DWord)~",
          LR"~(Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs)~",
          false, true, true,
          L"This sets the 15-minute limit for every user of this PC.",
          L"" },
        { L"acct.autologon",
          LR"~(Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value '0'
Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue)~",
          L"",
          false, true, false,
          L"Windows asks for a password at the next start. A password netplwiz keeps encrypted stays stored until you tick Users must enter a user name and password in netplwiz. If a plain-text password was stored, change it as well.",
          L"" },
        { L"cred.ntlm",
          LR"~(Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1 -Type DWord
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NtlmMinClientSec -Value 537395200 -Type DWord
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name NtlmMinServerSec -Value 537395200 -Type DWord)~",
          L"",
          false, true, true,
          L"Very old devices (NAS boxes, printers, scanners) that only speak LM or NTLMv1 may stop working after the restart.",
          L"" },

        // ------------------------------------------------------------------ Services and privileges
        { L"msi.alwayselevated",
          LR"~(Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Remove-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)~",
          L"",
          false, true, false,
          L"If Group Policy sets it, change the policy too: Windows Installer > Always install with elevated privileges = Disabled.",
          L"" },

        // ------------------------------------------------------------------ Network exposure
        { L"fw.profiles",
          L"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block",
          L"",
          false, true, false, L"", L"" },
        { L"net.llmnr",
          LR"~(New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord)~",
          LR"~(Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast)~",
          false, true, false, L"", L"" },
        { L"net.nbtns",
          LR"~(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty $_.PSPath -Name NetbiosOptions -Value 2 })~",
          LR"~(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { Set-ItemProperty $_.PSPath -Name NetbiosOptions -Value 0 })~",
          false, true, false,
          L"Very old shares that only resolve by NetBIOS name will stop resolving.",
          L"" },
        { L"net.mdns",
          LR"~(Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS -Value 0 -Type DWord)~",
          LR"~(Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS)~",
          false, true, true,
          L"Some casting and printer discovery features use mDNS. Test them after the restart.",
          L"" },
        { L"net.smbsigning",
          L"Set-SmbClientConfiguration -RequireSecuritySignature $true -Force",
          L"Set-SmbClientConfiguration -RequireSecuritySignature $false -Force",
          false, true, false, L"", L"" },
        { L"net.smbv1",
          L"Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
          L"Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart",
          false, true, true,
          L"Very old NAS boxes and scanners that only speak SMB1 will stop working. Update or replace them.",
          L"" },
        { L"net.winrm",
          LR"~(Disable-PSRemoting -Force
Remove-Item -Path WSMan:\Localhost\listener\* -Recurse
Stop-Service WinRM
Set-Service WinRM -StartupType Manual)~",
          L"Enable-PSRemoting -Force",
          false, true, false,
          L"Skip this step if anyone manages this PC remotely (PowerShell remoting or company management tools).",
          L"" },
        { L"net.remoteregistry",
          LR"~(Stop-Service RemoteRegistry
Set-Service RemoteRegistry -StartupType Disabled)~",
          L"Set-Service RemoteRegistry -StartupType Manual",
          false, true, false, L"", L"" },
        { L"net.wifiopen",
          L"netsh wlan set profileparameter ('name=' + $target) connectionmode=manual",
          L"netsh wlan set profileparameter ('name=' + $target) connectionmode=auto",
          true, true, false,
          L"The networks stay saved; Windows only stops joining them on its own. Networks saved for all users need an elevated PowerShell.",
          L"" },
        // Target: "share|SID|Full" or "share|SID|Change" (ShareFixTargets in HostRules.cpp).
        // The SID is turned into this PC's own name for the account, so the commands
        // work in every Windows language.
        { L"net.shares",
          LR"~($parts = $target -split '\|'
$account = (New-Object System.Security.Principal.SecurityIdentifier($parts[1])).Translate([System.Security.Principal.NTAccount]).Value
Revoke-SmbShareAccess -Name $parts[0] -AccountName $account -Force | Out-Null
Grant-SmbShareAccess -Name $parts[0] -AccountName $account -AccessRight Read -Force | Out-Null)~",
          LR"~($parts = $target -split '\|'
$account = (New-Object System.Security.Principal.SecurityIdentifier($parts[1])).Translate([System.Security.Principal.NTAccount]).Value
Revoke-SmbShareAccess -Name $parts[0] -AccountName $account -Force | Out-Null
Grant-SmbShareAccess -Name $parts[0] -AccountName $account -AccessRight $parts[2] -Force | Out-Null)~",
          true, true, false,
          L"Each target is a share, the group that could change files in it, and that group's old right. The group keeps Read, so computers that only open files there keep working.",
          L"Each group gets back the right it had on that share (Full or Change)." },
        { L"net.smbguest",
          LR"~(Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RestrictNullSessAccess -Value 1 -Type DWord)~",
          L"",
          false, true, true,
          L"A NAS box that only offers guest access stops working: give it an account. If Group Policy allows guest logons, change that policy too (Lanman Workstation > Enable insecure guest logons = Disabled).",
          L"" },
        { L"fw.rules",
          L"Disable-NetFirewallRule -Name $target",
          L"Enable-NetFirewallRule -Name $target",
          true, true, false,
          L"Each line turns one rule off by its unique name; nothing is deleted. A program that has to accept connections on public networks stops receiving them.",
          L"" },

        // ------------------------------------------------------------------ Logging and audit
        { L"audit.policy",
          LR"~(wevtutil sl Security /ms:209715200
wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true /ms:104857600)~",
          L"wevtutil sl Security /ms:20971520",
          false, true, false,
          L"This sets the Security log to 200 MB and turns on the PowerShell operational log at 100 MB.",
          L"" },
        { L"ps.logging",
          LR"~(New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -Value 1 -Type DWord
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*')~",
          LR"~(Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Recurse)~",
          false, true, false, L"", L"" },
    };
    return scripts;
}

void AttachCheckScripts(std::vector<CheckInfo>& catalog)
{
    int attached = 0;
    for (const CheckScript& s : GetCheckScripts()) {
        bool found = false;
        for (CheckInfo& info : catalog) {
            if (info.id != s.id) continue;
            info.fixScript = s.fixScript;
            info.undoScript = s.undoScript;
            info.scriptPerTarget = s.perTarget;
            info.scriptNeedsAdmin = s.needsAdmin;
            info.scriptNeedsRestart = s.needsRestart;
            info.fixScriptNote = s.fixNote;
            info.undoScriptNote = s.undoNote;
            found = true;
            ++attached;
            break;
        }
        if (!found) DebugLog(std::wstring(L"No catalog row for script entry ") + s.id);
    }
    DebugLog(L"Scripts attached to " + std::to_wstring(attached) + L" of " + std::to_wstring(catalog.size()) + L" checks");
}
