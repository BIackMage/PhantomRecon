#include "pch.h"
#include "SecurityChecks.h"
#include "SecurityChecksExtra.h"

#include <windows.h>
#include <sstream>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <tlhelp32.h>
#include <Shlwapi.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")


// ---------------------------------------------------------------------------
// Helper: read a DWORD from the registry. Returns false if key/value missing.
// ---------------------------------------------------------------------------
static bool ReadRegDword(HKEY hRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD& outValue)
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
// Helper: extract the executable path from a service ImagePath string.
// Handles quoted paths and paths with arguments.
// ---------------------------------------------------------------------------
static std::wstring ExtractExePath(const std::wstring& imagePath)
{
    if (imagePath.empty()) return L"";

    std::wstring path = imagePath;

    // If quoted, extract the quoted portion
    if (path[0] == L'"') {
        size_t endQuote = path.find(L'"', 1);
        if (endQuote != std::wstring::npos) {
            return path.substr(1, endQuote - 1);
        }
        return path.substr(1); // malformed, missing closing quote
    }

    // Not quoted: take everything up to the first space that precedes a valid extension,
    // or if that fails, take up to the first .exe/.dll/.sys we find + the extension.
    // Simple heuristic: find first ".exe" / ".sys" / ".dll" occurrence and cut there.
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    const wchar_t* exts[] = { L".exe", L".sys", L".dll" };
    for (const wchar_t* ext : exts) {
        size_t pos = lower.find(ext);
        if (pos != std::wstring::npos) {
            return path.substr(0, pos + wcslen(ext));
        }
    }

    // Fallback: up to first space
    size_t spacePos = path.find(L' ');
    if (spacePos != std::wstring::npos)
        return path.substr(0, spacePos);

    return path;
}


// ---------------------------------------------------------------------------
// Check: Unquoted service paths
// ---------------------------------------------------------------------------

SecurityCheckResult CheckUnquotedServicePaths()
{
    SecurityCheckResult result;
    result.name = L"Unquoted Service Paths";
    result.status = L"PASS";

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        result.status = L"ERROR";
        result.detail = L"Could not open Service Control Manager (need admin?)";
        return result;
    }

    DWORD bytesNeeded = 0;
    DWORD serviceCount = 0;
    DWORD resumeHandle = 0;

    // First call to get required buffer size
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &serviceCount, &resumeHandle, NULL);

    std::vector<BYTE> buffer(bytesNeeded);
    LPENUM_SERVICE_STATUS_PROCESSW pServices =
        reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer.data(), bytesNeeded, &bytesNeeded,
        &serviceCount, &resumeHandle, NULL))
    {
        CloseServiceHandle(hSCM);
        result.status = L"ERROR";
        result.detail = L"EnumServicesStatusEx failed: " + std::to_wstring(GetLastError());
        return result;
    }

    int foundCount = 0;
    std::wstringstream details;

    for (DWORD i = 0; i < serviceCount; i++) {
        SC_HANDLE hService = OpenServiceW(hSCM, pServices[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hService) continue;

        DWORD configSize = 0;
        QueryServiceConfigW(hService, NULL, 0, &configSize);

        std::vector<BYTE> configBuf(configSize);
        LPQUERY_SERVICE_CONFIGW pConfig =
            reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuf.data());

        if (QueryServiceConfigW(hService, pConfig, configSize, &configSize) && pConfig->lpBinaryPathName) {
            std::wstring imagePath = pConfig->lpBinaryPathName;

            // Skip paths that start with a quote (already quoted)
            // Skip kernel drivers (\SystemRoot, system32\drivers patterns)
            if (!imagePath.empty() && imagePath[0] != L'"') {
                // Check if the unquoted path has spaces before the exe
                std::wstring exePath = ExtractExePath(imagePath);

                if (exePath.find(L' ') != std::wstring::npos) {
                    foundCount++;
                    details << L"  [" << pServices[i].lpServiceName << L"] "
                            << imagePath << L"\n";
                }
            }
        }

        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCM);

    if (foundCount > 0) {
        result.status = L"FAIL";
        result.detail = std::to_wstring(foundCount) + L" service(s) with unquoted paths containing spaces:\n"
            + details.str();
    }
    else {
        result.detail = L"No unquoted service paths with spaces found.";
    }

    return result;
}


// ---------------------------------------------------------------------------
// Check: Writable service executables
// ---------------------------------------------------------------------------

SecurityCheckResult CheckWritableServiceExes()
{
    SecurityCheckResult result;
    result.name = L"Writable Service Executables";
    result.status = L"PASS";

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        result.status = L"ERROR";
        result.detail = L"Could not open Service Control Manager";
        return result;
    }

    DWORD bytesNeeded = 0;
    DWORD serviceCount = 0;
    DWORD resumeHandle = 0;

    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &serviceCount, &resumeHandle, NULL);

    std::vector<BYTE> buffer(bytesNeeded);
    LPENUM_SERVICE_STATUS_PROCESSW pServices =
        reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer.data(), bytesNeeded, &bytesNeeded,
        &serviceCount, &resumeHandle, NULL))
    {
        CloseServiceHandle(hSCM);
        result.status = L"ERROR";
        result.detail = L"EnumServicesStatusEx failed";
        return result;
    }

    int foundCount = 0;
    std::wstringstream details;

    for (DWORD i = 0; i < serviceCount; i++) {
        SC_HANDLE hService = OpenServiceW(hSCM, pServices[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hService) continue;

        DWORD configSize = 0;
        QueryServiceConfigW(hService, NULL, 0, &configSize);

        std::vector<BYTE> configBuf(configSize);
        LPQUERY_SERVICE_CONFIGW pConfig =
            reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configBuf.data());

        if (QueryServiceConfigW(hService, pConfig, configSize, &configSize) && pConfig->lpBinaryPathName) {
            std::wstring exePath = ExtractExePath(pConfig->lpBinaryPathName);

            if (!exePath.empty() && PathFileExistsW(exePath.c_str())) {
                // Try to open for write access — if it succeeds, it's writable
                HANDLE hFile = CreateFileW(exePath.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);

                if (hFile != INVALID_HANDLE_VALUE) {
                    CloseHandle(hFile);
                    foundCount++;
                    details << L"  [" << pServices[i].lpServiceName << L"] "
                            << exePath << L"\n";
                }
            }
        }

        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCM);

    if (foundCount > 0) {
        result.status = L"FAIL";
        result.detail = std::to_wstring(foundCount) + L" service executable(s) writable by current user:\n"
            + details.str();
    }
    else {
        result.detail = L"No writable service executables found.";
    }

    return result;
}


// ---------------------------------------------------------------------------
// Check: AlwaysInstallElevated
// ---------------------------------------------------------------------------

SecurityCheckResult CheckAlwaysInstallElevated()
{
    SecurityCheckResult result;
    result.name = L"AlwaysInstallElevated";
    result.status = L"PASS";

    DWORD hklmValue = 0;
    DWORD hkcuValue = 0;
    bool hklmFound = ReadRegDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", L"AlwaysInstallElevated", hklmValue);
    bool hkcuFound = ReadRegDword(HKEY_CURRENT_USER,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", L"AlwaysInstallElevated", hkcuValue);

    // Both must be set to 1 for the vulnerability to be exploitable
    if (hklmFound && hkcuFound && hklmValue == 1 && hkcuValue == 1) {
        result.status = L"FAIL";
        result.detail = L"HKLM and HKCU AlwaysInstallElevated both set to 1. "
                        L"Any user can install MSI packages with SYSTEM privileges.";
    }
    else if ((hklmFound && hklmValue == 1) || (hkcuFound && hkcuValue == 1)) {
        result.status = L"WARNING";
        result.detail = L"AlwaysInstallElevated set in one hive but not both. "
                        L"HKLM=" + std::to_wstring(hklmFound ? hklmValue : 0) +
                        L" HKCU=" + std::to_wstring(hkcuFound ? hkcuValue : 0);
    }
    else {
        result.detail = L"AlwaysInstallElevated not set (good).";
    }

    return result;
}


// ---------------------------------------------------------------------------
// Check: Unattended install files
// ---------------------------------------------------------------------------

SecurityCheckResult CheckUnattendedInstallFiles()
{
    SecurityCheckResult result;
    result.name = L"Unattended Install Files";
    result.status = L"PASS";

    // Common paths where unattended / sysprep files may contain cleartext credentials
    const wchar_t* searchPaths[] = {
        L"C:\\unattend.xml",
        L"C:\\unattend.txt",
        L"C:\\Windows\\Panther\\unattend.xml",
        L"C:\\Windows\\Panther\\Unattend\\unattend.xml",
        L"C:\\Windows\\Panther\\unattended.xml",
        L"C:\\Windows\\System32\\sysprep\\sysprep.xml",
        L"C:\\Windows\\System32\\sysprep\\sysprep.inf",
        L"C:\\Windows\\System32\\sysprep\\unattend.xml",
        L"C:\\Windows\\system32\\sysprep.inf",
        L"C:\\Windows\\inf\\autoUnattend.xml",
        L"C:\\Windows\\Setup\\Scripts\\unattend.xml",
    };

    int foundCount = 0;
    std::wstringstream details;

    for (const wchar_t* path : searchPaths) {
        if (PathFileExistsW(path)) {
            foundCount++;
            details << L"  " << path << L"\n";
        }
    }

    if (foundCount > 0) {
        result.status = L"WARNING";
        result.detail = std::to_wstring(foundCount)
            + L" unattended install file(s) found (may contain credentials):\n"
            + details.str();
    }
    else {
        result.detail = L"No unattended install files found.";
    }

    return result;
}


// ---------------------------------------------------------------------------
// Check: Credential Guard (LsaIso.exe)
// ---------------------------------------------------------------------------

SecurityCheckResult CheckCredentialGuard()
{
    SecurityCheckResult result;
    result.name = L"Credential Guard (LsaIso)";
    result.status = L"WARNING";

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        result.status = L"ERROR";
        result.detail = L"Could not enumerate processes.";
        return result;
    }

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(PROCESSENTRY32W);

    bool found = false;
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring exeName = pe.szExeFile;
            // Case-insensitive compare
            std::transform(exeName.begin(), exeName.end(), exeName.begin(), ::towlower);
            if (exeName == L"lsaiso.exe") {
                found = true;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    if (found) {
        result.status = L"PASS";
        result.detail = L"LsaIso.exe is running — Credential Guard is active. "
                        L"Protects against credential-dumping tools (e.g. Mimikatz).";
    }
    else {
        result.detail = L"LsaIso.exe NOT found — Credential Guard is not active. "
                        L"System may be vulnerable to credential-dumping attacks.";
    }

    return result;
}


// ---------------------------------------------------------------------------
// Check: LLMNR
// ---------------------------------------------------------------------------

SecurityCheckResult CheckLLMNR()
{
    SecurityCheckResult result;
    result.name = L"LLMNR";

    DWORD value = 0;
    bool found = ReadRegDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
        L"EnableMulticast", value);

    if (found && value == 0) {
        result.status = L"PASS";
        result.detail = L"LLMNR is disabled via group policy (EnableMulticast=0).";
    }
    else if (found) {
        result.status = L"FAIL";
        result.detail = L"LLMNR is explicitly enabled (EnableMulticast="
            + std::to_wstring(value) + L"). Vulnerable to poisoning attacks.";
    }
    else {
        result.status = L"FAIL";
        result.detail = L"LLMNR policy not configured (defaults to enabled). "
                        L"Vulnerable to LLMNR poisoning / relay attacks.";
    }

    return result;
}


// ---------------------------------------------------------------------------
// Check: NBT-NS (NetBIOS Name Service)
// ---------------------------------------------------------------------------

SecurityCheckResult CheckNBTNS()
{
    SecurityCheckResult result;
    result.name = L"NetBIOS (NBT-NS)";
    result.status = L"PASS";

    // NBT-NS is configured per network adapter under:
    // HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}
    //   NetbiosOptions: 0=default(DHCP), 1=enabled, 2=disabled

    HKEY hInterfacesKey = NULL;
    LONG openResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces",
        0, KEY_READ, &hInterfacesKey);

    if (openResult != ERROR_SUCCESS) {
        result.status = L"ERROR";
        result.detail = L"Could not read NetBT interfaces registry key.";
        return result;
    }

    int enabledCount = 0;
    int disabledCount = 0;
    int totalAdapters = 0;
    std::wstringstream details;

    wchar_t subKeyName[256];
    DWORD subKeyNameLen = 256;
    DWORD index = 0;

    while (RegEnumKeyExW(hInterfacesKey, index, subKeyName, &subKeyNameLen,
        NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        totalAdapters++;
        std::wstring fullPath = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\") + subKeyName;

        DWORD nbOption = 0;
        bool found = ReadRegDword(HKEY_LOCAL_MACHINE, fullPath.c_str(), L"NetbiosOptions", nbOption);

        if (found && nbOption == 2) {
            disabledCount++;
        }
        else {
            enabledCount++;
            details << L"  " << subKeyName << L" (NetbiosOptions="
                    << (found ? std::to_wstring(nbOption) : L"not set") << L")\n";
        }

        subKeyNameLen = 256;
        index++;
    }

    RegCloseKey(hInterfacesKey);

    if (enabledCount > 0) {
        result.status = L"FAIL";
        result.detail = std::to_wstring(enabledCount) + L"/" + std::to_wstring(totalAdapters)
            + L" adapter(s) have NBT-NS enabled (vulnerable to poisoning):\n" + details.str();
    }
    else {
        result.detail = L"NBT-NS disabled on all " + std::to_wstring(totalAdapters) + L" adapter(s).";
    }

    return result;
}


// ---------------------------------------------------------------------------
// Check: mDNS
// ---------------------------------------------------------------------------

SecurityCheckResult CheckMDNS()
{
    SecurityCheckResult result;
    result.name = L"mDNS";

    DWORD value = 0;
    bool found = ReadRegDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters",
        L"EnableMDNS", value);

    if (found && value == 0) {
        result.status = L"PASS";
        result.detail = L"mDNS is disabled (EnableMDNS=0).";
    }
    else if (found) {
        result.status = L"FAIL";
        result.detail = L"mDNS is enabled (EnableMDNS=" + std::to_wstring(value)
            + L"). May be vulnerable to poisoning.";
    }
    else {
        result.status = L"FAIL";
        result.detail = L"mDNS setting not configured (defaults to enabled on Win10+). "
                        L"May be vulnerable to multicast DNS poisoning.";
    }

    return result;
}


// ---------------------------------------------------------------------------
// Check: SMB Signing (client-side)
// ---------------------------------------------------------------------------

SecurityCheckResult CheckSMBSigning()
{
    SecurityCheckResult result;
    result.name = L"SMB Signing (Client)";

    DWORD value = 0;
    bool found = ReadRegDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
        L"RequireSecuritySignature", value);

    if (found && value == 1) {
        result.status = L"PASS";
        result.detail = L"SMB signing is required on the client (RequireSecuritySignature=1). "
                        L"Protects against relay attacks.";
    }
    else {
        result.status = L"FAIL";

        DWORD enableValue = 0;
        bool enableFound = ReadRegDword(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
            L"EnableSecuritySignature", enableValue);

        if (enableFound && enableValue == 1) {
            result.detail = L"SMB signing is enabled but NOT required (client will sign if server requests). "
                            L"Vulnerable to downgrade / relay attacks.";
        }
        else {
            result.detail = L"SMB signing is not required on the client. "
                            L"Vulnerable to NTLM relay attacks.";
        }
    }

    return result;
}


// ---------------------------------------------------------------------------
// Check: Proxy Auto-Detect (WPAD)
// ---------------------------------------------------------------------------

SecurityCheckResult CheckProxyAutoDetect()
{
    SecurityCheckResult result;
    result.name = L"Proxy Auto-Detect (WPAD)";

    // Internet Settings -> Connections -> DefaultConnectionSettings
    // Byte 8 (offset 8) contains flags:
    //   bit 0x08 = auto-detect enabled
    // Also check the simpler ProxyEnable / AutoDetect values
    HKEY hKey = NULL;
    LONG openResult = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0, KEY_READ, &hKey);

    if (openResult != ERROR_SUCCESS) {
        result.status = L"ERROR";
        result.detail = L"Could not read Internet Settings registry key.";
        return result;
    }

    // Check the WinHTTP auto-proxy settings via the Connections subkey
    HKEY hConnKey = NULL;
    bool autoDetectOn = false;

    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections",
        0, KEY_READ, &hConnKey) == ERROR_SUCCESS)
    {
        BYTE connSettings[256] = {};
        DWORD connSize = sizeof(connSettings);
        DWORD connType = 0;

        if (RegQueryValueExW(hConnKey, L"DefaultConnectionSettings", NULL, &connType,
            connSettings, &connSize) == ERROR_SUCCESS && connSize > 8)
        {
            // Byte at index 8 has the flags
            if (connSettings[8] & 0x08) {
                autoDetectOn = true;
            }
        }

        RegCloseKey(hConnKey);
    }

    RegCloseKey(hKey);

    if (autoDetectOn) {
        result.status = L"FAIL";
        result.detail = L"Proxy auto-detect (WPAD) is enabled. "
                        L"Vulnerable to WPAD poisoning attacks on the local network. "
                        L"Recommend disabling auto-detect and configuring proxy explicitly.";
    }
    else {
        result.status = L"PASS";
        result.detail = L"Proxy auto-detect (WPAD) is not enabled.";
    }

    return result;
}


// ---------------------------------------------------------------------------
// Run all checks
// ---------------------------------------------------------------------------

std::vector<SecurityCheckResult> RunAllSecurityChecks()
{
    std::vector<SecurityCheckResult> results;

    results.push_back(CheckUnquotedServicePaths());
    results.push_back(CheckWritableServiceExes());
    results.push_back(CheckAlwaysInstallElevated());
    results.push_back(CheckUnattendedInstallFiles());
    results.push_back(CheckCredentialGuard());
    results.push_back(CheckLLMNR());
    results.push_back(CheckNBTNS());
    results.push_back(CheckMDNS());
    results.push_back(CheckSMBSigning());
    results.push_back(CheckProxyAutoDetect());

    // Phase 1.5 additional checks
    results.push_back(CheckStartupPrograms());
    results.push_back(CheckScheduledTasks());
    results.push_back(CheckPowerShellPolicy());
    results.push_back(CheckWindowsFirewall());
    results.push_back(CheckAuditPolicy());
    results.push_back(CheckWindowsUpdateStatus());

    return results;
}


// ---------------------------------------------------------------------------
// Compact UI summary
// ---------------------------------------------------------------------------

std::wstring GetSecuritySummary(const std::vector<SecurityCheckResult>& results)
{
    int passCount = 0;
    int failCount = 0;
    int warnCount = 0;
    int errCount = 0;

    std::wstringstream ss;
    ss << L"--- Security Audit ---\n";

    for (const auto& r : results) {
        std::wstring icon;
        if (r.status == L"PASS")         { icon = L"[OK]  "; passCount++; }
        else if (r.status == L"FAIL")    { icon = L"[FAIL]"; failCount++; }
        else if (r.status == L"WARNING") { icon = L"[WARN]"; warnCount++; }
        else                             { icon = L"[ERR] "; errCount++;  }

        ss << icon << L" " << r.name << L"\n";
    }

    ss << L"\nTotal: " << passCount << L" pass, "
       << failCount << L" fail, "
       << warnCount << L" warn, "
       << errCount << L" err";

    return ss.str();
}


// ---------------------------------------------------------------------------
// Full report to file
// ---------------------------------------------------------------------------

void WriteSecurityReport(const std::wstring& outputPath,
                         const std::vector<SecurityCheckResult>& results)
{
    std::wofstream file(outputPath);
    if (!file.is_open()) return;

    file << L"=== Phantom Recon Security Audit Report ===" << std::endl;
    file << L"=========================================" << std::endl << std::endl;

    for (const auto& r : results) {
        file << L"CHECK: " << r.name << std::endl;
        file << L"STATUS: " << r.status << std::endl;
        file << L"DETAIL: " << r.detail << std::endl;
        file << L"-----------------------------------------" << std::endl;
    }

    file.close();
}
