#include "pch.h"
#include "SecurityChecks.h"

#include "AppPaths.h"
#include "AuditRules.h"
#include "CheckCatalog.h"
#include "DeviceGuard.h"
#include "RegUtil.h"
#include "ServiceUtil.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <windows.h>
#include <tlhelp32.h>
#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SecurityChecks] " + msg + L"\n").c_str());
}

SecurityCheckResult MakeCheckResult(const std::wstring& id)
{
    SecurityCheckResult r;
    r.id = id;
    const CheckInfo* info = FindCheckInfo(id);
    r.name = info ? info->title : id;
    r.status = CHECK_INFO;
    return r;
}

// ---------------------------------------------------------------------------
// Unquoted service paths
// ---------------------------------------------------------------------------
SecurityCheckResult CheckUnquotedServicePaths()
{
    SecurityCheckResult result = MakeCheckResult(L"svc.unquoted");
    std::wstring error;
    std::vector<ServiceInfo> services = EnumerateServices(&error);
    if (services.empty() && !error.empty()) {
        result.status = CHECK_ERROR;
        result.detail = error;
        return result;
    }

    std::wstringstream details;
    int found = 0;
    for (const ServiceInfo& s : services) {
        std::wstring raw = TrimW(s.binaryPathRaw);
        if (raw.empty() || raw[0] == L'"') continue;
        // Only the program part matters: "C:\Program Files\x.exe -k" is unsafe,
        // "C:\Windows\x.exe -k netsvcs" is not.
        std::wstring lower = ToLowerW(raw);
        size_t exeEnd = std::wstring::npos;
        const wchar_t* exts[] = { L".exe", L".sys", L".dll" };
        for (const wchar_t* ext : exts) {
            size_t pos = lower.find(ext);
            if (pos != std::wstring::npos && (exeEnd == std::wstring::npos || pos < exeEnd)) exeEnd = pos + wcslen(ext);
        }
        std::wstring programPart = exeEnd != std::wstring::npos ? raw.substr(0, exeEnd) : raw;
        if (programPart.find(L' ') == std::wstring::npos) continue;
        if (StartsWithI(programPart, L"\\SystemRoot\\") || StartsWithI(programPart, L"system32\\")) continue;

        found++;
        details << L"  [" << s.name << L"] " << raw << L"\n";
    }

    if (found > 0) {
        result.status = CHECK_FAIL;
        result.detail = std::to_wstring(found) + L" service(s) with an unquoted path containing spaces:\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"No unquoted service paths with spaces found (" + std::to_wstring(services.size()) + L" services checked).";
    }
    return result;
}

// ---------------------------------------------------------------------------
// Service programs writable by low-privilege users
// ---------------------------------------------------------------------------
SecurityCheckResult CheckWritableServiceExes()
{
    SecurityCheckResult result = MakeCheckResult(L"svc.writable");
    std::wstring error;
    std::vector<ServiceInfo> services = EnumerateServices(&error);
    if (services.empty() && !error.empty()) {
        result.status = CHECK_ERROR;
        result.detail = error;
        return result;
    }

    std::wstringstream details;
    int found = 0;
    for (const ServiceInfo& s : services) {
        if (s.startType == SERVICE_DISABLED) continue;
        if (s.exePath.empty() || !FileExists(s.exePath)) continue;
        // Store app folders are locked down by Windows as a whole, whatever the
        // individual file permissions say.
        if (IsPackagedAppPath(s.exePath)) continue;
        std::wstring who;
        if (LowPrivilegeWritable(s.exePath, false, &who)) {
            found++;
            details << L"  [" << s.name << L"] " << s.exePath << L"  (writable by " << who
                    << L", runs as " << (s.account.empty() ? L"LocalSystem" : s.account) << L")\n";
        }
    }

    if (found > 0) {
        result.status = CHECK_FAIL;
        result.detail = std::to_wstring(found) + L" service program(s) can be changed by normal users:\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"No service program is writable by normal users.";
    }
    return result;
}

// ---------------------------------------------------------------------------
// AlwaysInstallElevated
// ---------------------------------------------------------------------------
SecurityCheckResult CheckAlwaysInstallElevated()
{
    SecurityCheckResult result = MakeCheckResult(L"msi.alwayselevated");
    const wchar_t* key = L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";
    DWORD hklm = 0, hkcu = 0;
    bool hklmFound = RegReadDword(HKEY_LOCAL_MACHINE, key, L"AlwaysInstallElevated", hklm);
    bool hkcuFound = RegReadDword(HKEY_CURRENT_USER, key, L"AlwaysInstallElevated", hkcu);

    if (hklmFound && hkcuFound && hklm == 1 && hkcu == 1) {
        result.status = CHECK_FAIL;
        result.detail = L"HKLM and HKCU AlwaysInstallElevated are both 1. Any user can install MSI packages as SYSTEM.";
    }
    else if ((hklmFound && hklm == 1) || (hkcuFound && hkcu == 1)) {
        result.status = CHECK_WARNING;
        result.detail = L"AlwaysInstallElevated is set in one hive but not both (HKLM=" +
            std::to_wstring(hklmFound ? hklm : 0) + L", HKCU=" + std::to_wstring(hkcuFound ? hkcu : 0) +
            L"). Not exploitable yet; one more change makes it so.";
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"AlwaysInstallElevated is not set.";
    }
    return result;
}

// ---------------------------------------------------------------------------
// Unattended install files
// ---------------------------------------------------------------------------
SecurityCheckResult CheckUnattendedInstallFiles()
{
    SecurityCheckResult result = MakeCheckResult(L"files.unattend");
    std::wstring windir = ExpandEnvironment(L"%SystemRoot%");
    std::wstring sysdrive = ExpandEnvironment(L"%SystemDrive%");
    const std::vector<std::wstring> paths = {
        sysdrive + L"\\unattend.xml",
        sysdrive + L"\\unattend.txt",
        sysdrive + L"\\autounattend.xml",
        windir + L"\\Panther\\unattend.xml",
        windir + L"\\Panther\\Unattend\\unattend.xml",
        windir + L"\\Panther\\unattended.xml",
        windir + L"\\Panther\\autounattend.xml",
        windir + L"\\System32\\sysprep\\sysprep.xml",
        windir + L"\\System32\\sysprep\\sysprep.inf",
        windir + L"\\System32\\sysprep\\unattend.xml",
        windir + L"\\System32\\sysprep\\Panther\\unattend.xml",
        windir + L"\\system32\\sysprep.inf",
        windir + L"\\inf\\autoUnattend.xml",
        windir + L"\\Setup\\Scripts\\unattend.xml",
    };

    std::wstringstream details;
    int found = 0;
    for (const std::wstring& p : paths) {
        if (FileExists(p)) {
            found++;
            details << L"  " << p << L"\n";
        }
    }
    if (found > 0) {
        result.status = CHECK_WARNING;
        result.detail = std::to_wstring(found) + L" setup answer file(s) found (may contain passwords):\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"No setup answer files found in the usual places.";
    }
    return result;
}

// ---------------------------------------------------------------------------
// Credential Guard
// ---------------------------------------------------------------------------
SecurityCheckResult CheckCredentialGuard()
{
    SecurityCheckResult result = MakeCheckResult(L"lsa.credguard");

    // Preferred: ask Device Guard which security services are running
    // (shared with the memory integrity check, DeviceGuard.cpp).
    DeviceGuardStatus deviceGuard = ReadDeviceGuardStatus();
    bool wmiKnows = deviceGuard.ok;
    bool running = wmiKnows && DeviceGuardHas(deviceGuard.running, kDeviceGuardCredentialGuard);
    int vbsStatus = deviceGuard.vbsStatus;

    // Fallback and confirmation: LsaIso.exe is the Credential Guard process.
    bool lsaIso = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"lsaiso.exe") == 0) {
                    lsaIso = true;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    // When Device Guard answers, it decides: LsaIso.exe also runs for other
    // virtualization-based features (seen on Windows 11 Home with memory integrity
    // on), so on its own it is only a fallback for PCs where WMI cannot be asked.
    std::wstring edition = RegReadString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"EditionID");
    EditionSupport support = CredentialGuardEditionSupport(edition);
    DebugLog(L"Credential Guard: WMI " + std::wstring(wmiKnows ? L"answered" : L"unavailable") + L", running " +
             (running ? L"yes" : L"no") + L", LsaIso " + (lsaIso ? L"yes" : L"no") + L", edition " + edition);

    if (running || (!wmiKnows && lsaIso)) {
        result.status = CHECK_PASS;
        result.detail = L"Credential Guard is running" +
            std::wstring(running ? L" (Device Guard reports it)." : L" (LsaIso.exe present).");
    }
    else if (support == EditionSupport::NotSupported) {
        result.status = CHECK_NA;
        result.detail = L"This Windows edition (" + edition + L") cannot run Credential Guard; it needs Enterprise, Education "
            L"or Pro Education. Nothing to change here.";
    }
    else {
        result.status = CHECK_WARNING;
        result.detail = L"Credential Guard is not running.";
        if (wmiKnows) {
            const wchar_t* vbs = vbsStatus == 2 ? L"running" : vbsStatus == 1 ? L"enabled but not running" : L"off";
            result.detail += std::wstring(L" Virtualization-based security is ") + vbs + L".";
        }
        if (!edition.empty()) result.detail += L" Windows edition: " + edition + L".";
    }
    return result;
}

// ---------------------------------------------------------------------------
// LLMNR
// ---------------------------------------------------------------------------
SecurityCheckResult CheckLLMNR()
{
    SecurityCheckResult result = MakeCheckResult(L"net.llmnr");
    DWORD value = 0;
    bool found = RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"EnableMulticast", value);
    if (found && value == 0) {
        result.status = CHECK_PASS;
        result.detail = L"LLMNR is turned off by policy (EnableMulticast=0).";
    }
    else if (found) {
        result.status = CHECK_FAIL;
        result.detail = L"LLMNR is explicitly on (EnableMulticast=" + std::to_wstring(value) + L").";
    }
    else {
        result.status = CHECK_FAIL;
        result.detail = L"LLMNR policy is not set, so LLMNR is on (the Windows default).";
    }
    return result;
}

// ---------------------------------------------------------------------------
// NBT-NS
// ---------------------------------------------------------------------------
SecurityCheckResult CheckNBTNS()
{
    SecurityCheckResult result = MakeCheckResult(L"net.nbtns");
    const std::wstring base = L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces";
    std::vector<std::wstring> adapters = RegEnumSubKeys(HKEY_LOCAL_MACHINE, base);
    if (adapters.empty()) {
        if (!RegKeyExists(HKEY_LOCAL_MACHINE, base)) {
            result.status = CHECK_PASS;
            result.detail = L"NetBIOS over TCP/IP is not installed.";
        }
        else {
            result.status = CHECK_PASS;
            result.detail = L"No network adapters are bound to NetBIOS.";
        }
        return result;
    }

    int enabled = 0;
    std::wstringstream details;
    for (const std::wstring& adapter : adapters) {
        DWORD option = 0;
        bool found = RegReadDword(HKEY_LOCAL_MACHINE, base + L"\\" + adapter, L"NetbiosOptions", option);
        if (!(found && option == 2)) {
            enabled++;
            details << L"  " << adapter << L" (NetbiosOptions=" << (found ? std::to_wstring(option) : L"not set") << L")\n";
        }
    }
    if (enabled > 0) {
        result.status = CHECK_FAIL;
        result.detail = std::to_wstring(enabled) + L" of " + std::to_wstring(adapters.size()) +
            L" adapter(s) have NetBIOS name lookups on:\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"NetBIOS is off on all " + std::to_wstring(adapters.size()) + L" adapter(s).";
    }
    return result;
}

// ---------------------------------------------------------------------------
// mDNS
// ---------------------------------------------------------------------------
SecurityCheckResult CheckMDNS()
{
    SecurityCheckResult result = MakeCheckResult(L"net.mdns");
    DWORD value = 0;
    bool found = RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", L"EnableMDNS", value);
    if (found && value == 0) {
        result.status = CHECK_PASS;
        result.detail = L"mDNS is off (EnableMDNS=0).";
    }
    else if (found) {
        result.status = CHECK_FAIL;
        result.detail = L"mDNS is on (EnableMDNS=" + std::to_wstring(value) + L").";
    }
    else {
        result.status = CHECK_FAIL;
        result.detail = L"mDNS is not configured, so it is on (the Windows 10 and 11 default).";
    }
    return result;
}

// ---------------------------------------------------------------------------
// SMB signing (client)
// ---------------------------------------------------------------------------
SecurityCheckResult CheckSMBSigning()
{
    SecurityCheckResult result = MakeCheckResult(L"net.smbsigning");
    const wchar_t* key = L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters";
    DWORD required = 0;
    bool found = RegReadDword(HKEY_LOCAL_MACHINE, key, L"RequireSecuritySignature", required);
    if (found && required == 1) {
        result.status = CHECK_PASS;
        result.detail = L"The SMB client requires signing (RequireSecuritySignature=1).";
        return result;
    }
    result.status = CHECK_FAIL;
    DWORD enabled = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE, key, L"EnableSecuritySignature", enabled) && enabled == 1) {
        result.detail = L"The SMB client signs when the server asks, but does not require it. A relay can strip it.";
    }
    else {
        result.detail = L"The SMB client does not require signing.";
    }
    return result;
}

// ---------------------------------------------------------------------------
// WPAD
// ---------------------------------------------------------------------------
SecurityCheckResult CheckProxyAutoDetect()
{
    SecurityCheckResult result = MakeCheckResult(L"net.wpad");
    std::vector<BYTE> settings;
    bool autoDetect = false;
    bool known = RegReadBinary(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections",
        L"DefaultConnectionSettings", settings);
    if (known && settings.size() > 8) {
        autoDetect = (settings[8] & 0x08) != 0;
    }
    DWORD policyOff = 0;
    bool servicePolicy = RegReadDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\WinHttpAutoProxySvc", L"Start", policyOff) && policyOff == 4;

    bool saved = known && settings.size() > 8;
    result.status = WpadStatus(saved, autoDetect, servicePolicy);
    if (!saved) {
        result.detail = L"This user has no saved connection settings, so Windows uses its default: automatically detect "
            L"settings is on.";
        if (servicePolicy) result.detail += L" The WinHTTP auto-proxy service is disabled.";
    }
    else if (autoDetect && !servicePolicy) {
        result.detail = L"Automatically detect settings is on for this user.";
    }
    else if (autoDetect) {
        result.detail = L"Automatically detect settings is on, but the WinHTTP auto-proxy service is disabled.";
    }
    else {
        result.detail = L"Automatic proxy detection is off.";
    }
    DebugLog(L"WPAD: " + result.status);
    return result;
}
