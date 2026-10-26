#include "pch.h"
#include "SecurityChecksExtra.h"

#include <windows.h>
#include <sstream>
#include <vector>
#include <algorithm>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[SecurityChecksExtra] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// Helper: read a string from the registry
// ---------------------------------------------------------------------------
static std::wstring ReadRegStringValue(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return L"";

    DWORD dataType = 0;
    DWORD dataSize = 0;
    RegQueryValueExW(hKey, valueName, NULL, &dataType, NULL, &dataSize);

    if (dataSize == 0 || (dataType != REG_SZ && dataType != REG_EXPAND_SZ)) {
        RegCloseKey(hKey);
        return L"";
    }

    std::vector<wchar_t> buffer(dataSize / sizeof(wchar_t) + 1, L'\0');
    RegQueryValueExW(hKey, valueName, NULL, &dataType, reinterpret_cast<BYTE*>(buffer.data()), &dataSize);
    RegCloseKey(hKey);
    return std::wstring(buffer.data());
}

// ---------------------------------------------------------------------------
// Helper: read a DWORD from the registry
// ---------------------------------------------------------------------------
static bool ReadRegDwordValue(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD& outValue)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD type = 0;
    DWORD size = sizeof(DWORD);
    LONG result = RegQueryValueExW(hKey, valueName, NULL, &type, reinterpret_cast<BYTE*>(&outValue), &size);
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS && type == REG_DWORD);
}


// ---------------------------------------------------------------------------
// Helper: enumerate Run key entries
// ---------------------------------------------------------------------------
static int EnumerateRunKey(HKEY hRoot, const wchar_t* subKey, std::wstringstream& details)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;

    int count = 0;
    DWORD index = 0;
    wchar_t valueName[512];
    DWORD valueNameLen = 512;
    BYTE valueData[2048];
    DWORD valueDataLen = sizeof(valueData);
    DWORD type = 0;

    while (RegEnumValueW(hKey, index, valueName, &valueNameLen, NULL,
        &type, valueData, &valueDataLen) == ERROR_SUCCESS)
    {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            count++;
            details << L"  " << valueName << L" = "
                    << reinterpret_cast<wchar_t*>(valueData) << L"\n";
        }
        index++;
        valueNameLen = 512;
        valueDataLen = sizeof(valueData);
    }

    RegCloseKey(hKey);
    return count;
}


// ---------------------------------------------------------------------------
// Check: Startup Programs
// ---------------------------------------------------------------------------
SecurityCheckResult CheckStartupPrograms()
{
    DebugLog(L"Checking startup programs");

    SecurityCheckResult result;
    result.name = L"Startup Programs";
    result.status = L"INFO";

    int totalEntries = 0;
    std::wstringstream details;

    // HKLM Run keys
    details << L"HKLM\\...\\Run:\n";
    totalEntries += EnumerateRunKey(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", details);

    details << L"HKLM\\...\\RunOnce:\n";
    totalEntries += EnumerateRunKey(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", details);

    // HKCU Run keys
    details << L"HKCU\\...\\Run:\n";
    totalEntries += EnumerateRunKey(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", details);

    details << L"HKCU\\...\\RunOnce:\n";
    totalEntries += EnumerateRunKey(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", details);

    // WoW6432Node (32-bit on 64-bit)
    details << L"HKLM\\...\\WoW6432Node\\...\\Run:\n";
    totalEntries += EnumerateRunKey(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\WoW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", details);

    // Check common Startup folders
    wchar_t startupPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startupPath))) {
        WIN32_FIND_DATAW fd;
        std::wstring searchPath = std::wstring(startupPath) + L"\\*";
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            details << L"User Startup Folder:\n";
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    totalEntries++;
                    details << L"  " << fd.cFileName << L"\n";
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, startupPath))) {
        WIN32_FIND_DATAW fd;
        std::wstring searchPath = std::wstring(startupPath) + L"\\*";
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            details << L"All Users Startup Folder:\n";
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    totalEntries++;
                    details << L"  " << fd.cFileName << L"\n";
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    result.detail = std::to_wstring(totalEntries) + L" startup entries found.\n" + details.str();

    if (totalEntries > 20) {
        result.status = L"WARNING";
        result.detail = L"High number of startup entries (" + std::to_wstring(totalEntries)
            + L") — review for unauthorized persistence.\n" + details.str();
    }

    DebugLog((L"Found " + std::to_wstring(totalEntries) + L" startup entries").c_str());
    return result;
}


// ---------------------------------------------------------------------------
// Check: Scheduled Tasks (via schtasks command)
// ---------------------------------------------------------------------------
SecurityCheckResult CheckScheduledTasks()
{
    DebugLog(L"Checking scheduled tasks");

    SecurityCheckResult result;
    result.name = L"Scheduled Tasks";
    result.status = L"INFO";

    // Use the Task Scheduler COM API via registry for a lightweight check.
    // Look for tasks in the Tasks registry key that are suspicious.
    // Also enumerate the \Windows\System32\Tasks folder for non-Microsoft tasks.

    std::wstringstream details;
    int suspiciousCount = 0;

    // Enumerate task files in the Tasks folder
    const wchar_t* taskDirs[] = {
        L"C:\\Windows\\System32\\Tasks",
    };

    for (const wchar_t* taskDir : taskDirs) {
        WIN32_FIND_DATAW fd;
        std::wstring searchPath = std::wstring(taskDir) + L"\\*";
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        int taskCount = 0;
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            // Skip known Microsoft task folders
            std::wstring name = fd.cFileName;
            std::wstring lowerName = name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

            if (lowerName == L"microsoft") continue;

            // Flag non-directory task files at the root (unusual)
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                taskCount++;
                // Check for suspicious characteristics
                bool suspicious = false;
                if (lowerName.find(L"update") == std::wstring::npos &&
                    lowerName.find(L"google") == std::wstring::npos &&
                    lowerName.find(L"adobe") == std::wstring::npos &&
                    lowerName.find(L"onedrive") == std::wstring::npos &&
                    lowerName.find(L"dropbox") == std::wstring::npos)
                {
                    // Not a commonly known task name — flag for review
                    suspiciousCount++;
                    suspicious = true;
                }

                details << L"  " << (suspicious ? L"[REVIEW] " : L"") << name << L"\n";
            }
            else {
                // It's a subfolder (task group) — count but don't enumerate recursively
                details << L"  [Folder] " << name << L"\n";
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);

        details << L"  (" << taskCount << L" root-level tasks)\n";
    }

    if (suspiciousCount > 0) {
        result.status = L"WARNING";
        result.detail = std::to_wstring(suspiciousCount)
            + L" non-standard scheduled task(s) found — review for persistence:\n" + details.str();
    }
    else {
        result.detail = L"No suspicious scheduled tasks found.\n" + details.str();
    }

    DebugLog((L"Found " + std::to_wstring(suspiciousCount) + L" suspicious tasks").c_str());
    return result;
}


// ---------------------------------------------------------------------------
// Check: PowerShell Execution Policy & Logging
// ---------------------------------------------------------------------------
SecurityCheckResult CheckPowerShellPolicy()
{
    DebugLog(L"Checking PowerShell policy");

    SecurityCheckResult result;
    result.name = L"PowerShell Security";
    result.status = L"PASS";

    std::wstringstream details;
    bool hasIssue = false;

    // Check execution policy (HKLM)
    std::wstring execPolicy = ReadRegStringValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",
        L"ExecutionPolicy");

    if (execPolicy.empty()) {
        execPolicy = L"Not configured (defaults to Restricted)";
    }

    std::wstring lowerPolicy = execPolicy;
    std::transform(lowerPolicy.begin(), lowerPolicy.end(), lowerPolicy.begin(), ::towlower);

    if (lowerPolicy == L"unrestricted" || lowerPolicy == L"bypass") {
        hasIssue = true;
        details << L"Execution Policy: " << execPolicy << L" (DANGEROUS — allows any script)\n";
    }
    else {
        details << L"Execution Policy: " << execPolicy << L"\n";
    }

    // Check Script Block Logging
    DWORD scriptBlockLogging = 0;
    bool sblFound = ReadRegDwordValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        L"EnableScriptBlockLogging", scriptBlockLogging);

    if (sblFound && scriptBlockLogging == 1) {
        details << L"Script Block Logging: Enabled (good)\n";
    }
    else {
        hasIssue = true;
        details << L"Script Block Logging: NOT enabled (recommend enabling for forensics)\n";
    }

    // Check Module Logging
    DWORD moduleLogging = 0;
    bool mlFound = ReadRegDwordValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
        L"EnableModuleLogging", moduleLogging);

    if (mlFound && moduleLogging == 1) {
        details << L"Module Logging: Enabled (good)\n";
    }
    else {
        hasIssue = true;
        details << L"Module Logging: NOT enabled (recommend enabling)\n";
    }

    // Check Transcription
    DWORD transcription = 0;
    bool trFound = ReadRegDwordValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
        L"EnableTranscripting", transcription);

    if (trFound && transcription == 1) {
        details << L"Transcription: Enabled (good)\n";
    }
    else {
        details << L"Transcription: Not enabled (optional but recommended)\n";
    }

    // Check Constrained Language Mode
    DWORD clm = 0;
    bool clmFound = ReadRegDwordValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds",
        L"ConsolePrompting", clm);

    // Check for __PSLockdownPolicy env var (indicates WDAC/CLM)
    wchar_t lockdownEnv[16] = {};
    DWORD envLen = GetEnvironmentVariableW(L"__PSLockdownPolicy", lockdownEnv, 16);
    if (envLen > 0 && wcscmp(lockdownEnv, L"4") == 0) {
        details << L"Constrained Language Mode: Active (WDAC enforced)\n";
    }
    else {
        details << L"Constrained Language Mode: Not enforced\n";
    }

    if (hasIssue) {
        result.status = L"WARNING";
    }
    result.detail = details.str();

    DebugLog(L"PowerShell policy check complete");
    return result;
}


// ---------------------------------------------------------------------------
// Check: Windows Firewall Status
// ---------------------------------------------------------------------------
SecurityCheckResult CheckWindowsFirewall()
{
    DebugLog(L"Checking Windows Firewall");

    SecurityCheckResult result;
    result.name = L"Windows Firewall";
    result.status = L"PASS";

    std::wstringstream details;
    bool anyDisabled = false;

    struct FirewallProfile {
        const wchar_t* name;
        const wchar_t* regKey;
    };

    FirewallProfile profiles[] = {
        { L"Domain",  L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile" },
        { L"Private", L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" },
        { L"Public",  L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile" },
    };

    for (const auto& profile : profiles) {
        DWORD enabled = 0;
        bool found = ReadRegDwordValue(HKEY_LOCAL_MACHINE, profile.regKey, L"EnableFirewall", enabled);

        if (found && enabled == 1) {
            details << profile.name << L" Profile: Enabled\n";
        }
        else {
            anyDisabled = true;
            details << profile.name << L" Profile: DISABLED\n";
        }
    }

    if (anyDisabled) {
        result.status = L"FAIL";
        result.detail = L"One or more firewall profiles are disabled:\n" + details.str();
    }
    else {
        result.detail = L"All firewall profiles are enabled.\n" + details.str();
    }

    DebugLog(L"Firewall check complete");
    return result;
}


// ---------------------------------------------------------------------------
// Check: Audit Policy Configuration
// ---------------------------------------------------------------------------
SecurityCheckResult CheckAuditPolicy()
{
    DebugLog(L"Checking audit policy");

    SecurityCheckResult result;
    result.name = L"Audit Policy";
    result.status = L"PASS";

    std::wstringstream details;
    bool hasGap = false;

    // Check key audit categories via registry
    // HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security
    // Also check advanced audit policy via:
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit

    struct AuditCheck {
        const wchar_t* name;
        const wchar_t* subKey;
        const wchar_t* valueName;
        DWORD expectedMin;  // minimum acceptable value
    };

    // Basic audit policy (classic):
    // HKLM\SECURITY\Policy\PolAdtEv (not directly readable without special privileges)
    // Instead, check if key events are at least configured

    // Check if advanced audit policy is in use
    DWORD scenoApply = 0;
    bool advancedAudit = ReadRegDwordValue(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"SCENoApplyLegacyAuditPolicy", scenoApply);

    if (advancedAudit && scenoApply == 1) {
        details << L"Advanced Audit Policy: In use (good)\n";
    }
    else {
        details << L"Advanced Audit Policy: NOT in use (using legacy audit policy)\n";
    }

    // Check if Security event log has reasonable size
    DWORD maxLogSize = 0;
    bool logSizeFound = ReadRegDwordValue(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security",
        L"MaxSize", maxLogSize);

    if (logSizeFound) {
        DWORD maxLogMB = maxLogSize / (1024 * 1024);
        if (maxLogMB < 64) {
            hasGap = true;
            details << L"Security Event Log Max Size: " << maxLogMB
                    << L" MB (recommend >= 64 MB)\n";
        }
        else {
            details << L"Security Event Log Max Size: " << maxLogMB << L" MB\n";
        }
    }

    // Check crash-on-audit-fail (CrashOnAuditFail)
    DWORD crashOnFail = 0;
    ReadRegDwordValue(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"CrashOnAuditFail", crashOnFail);
    details << L"CrashOnAuditFail: " << (crashOnFail ? L"Enabled" : L"Disabled") << L"\n";

    // Check if PowerShell operational log is enabled
    DWORD psLogEnabled = 0;
    bool psLogFound = ReadRegDwordValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-PowerShell/Operational",
        L"Enabled", psLogEnabled);

    if (psLogFound && psLogEnabled == 1) {
        details << L"PowerShell Operational Log: Enabled\n";
    }
    else {
        hasGap = true;
        details << L"PowerShell Operational Log: NOT enabled\n";
    }

    if (hasGap) {
        result.status = L"WARNING";
        result.detail = L"Audit policy gaps detected:\n" + details.str();
    }
    else {
        result.detail = L"Audit policy configuration looks reasonable.\n" + details.str();
    }

    DebugLog(L"Audit policy check complete");
    return result;
}


// ---------------------------------------------------------------------------
// Check: Windows Update Status
// ---------------------------------------------------------------------------
SecurityCheckResult CheckWindowsUpdateStatus()
{
    DebugLog(L"Checking Windows Update status");

    SecurityCheckResult result;
    result.name = L"Windows Update";
    result.status = L"PASS";

    std::wstringstream details;

    // Check if the Windows Update service is running
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hService = OpenServiceW(hSCM, L"wuauserv", SERVICE_QUERY_STATUS);
        if (hService) {
            SERVICE_STATUS_PROCESS ssp = {};
            DWORD bytesNeeded = 0;
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&ssp), sizeof(ssp), &bytesNeeded))
            {
                if (ssp.dwCurrentState == SERVICE_RUNNING) {
                    details << L"Windows Update Service: Running\n";
                }
                else if (ssp.dwCurrentState == SERVICE_STOPPED) {
                    details << L"Windows Update Service: Stopped\n";
                    result.status = L"WARNING";
                }
                else {
                    details << L"Windows Update Service: State=" << ssp.dwCurrentState << L"\n";
                }
            }
            CloseServiceHandle(hService);
        }
        else {
            details << L"Windows Update Service: Could not query\n";
        }
        CloseServiceHandle(hSCM);
    }

    // Check last successful update time via registry
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install
    std::wstring lastInstallTime = ReadRegStringValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install",
        L"LastSuccessTime");

    if (!lastInstallTime.empty()) {
        details << L"Last Successful Install: " << lastInstallTime << L"\n";
    }
    else {
        details << L"Last Successful Install: Unknown\n";
    }

    // Check if automatic updates are enabled
    DWORD auOptions = 0;
    bool auFound = ReadRegDwordValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
        L"NoAutoUpdate", auOptions);

    if (auFound && auOptions == 1) {
        result.status = L"FAIL";
        details << L"Automatic Updates: DISABLED by policy\n";
    }
    else {
        details << L"Automatic Updates: Enabled (or not overridden by policy)\n";
    }

    // Check pending reboot for updates
    HKEY hRebootKey = NULL;
    bool pendingReboot = false;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired",
        0, KEY_READ, &hRebootKey) == ERROR_SUCCESS)
    {
        pendingReboot = true;
        RegCloseKey(hRebootKey);
    }

    if (pendingReboot) {
        details << L"Pending Reboot: YES (updates awaiting restart)\n";
        if (result.status == L"PASS") result.status = L"WARNING";
    }
    else {
        details << L"Pending Reboot: No\n";
    }

    result.detail = details.str();

    DebugLog(L"Windows Update check complete");
    return result;
}
