#include "pch.h"
#include "SecurityChecksPlatform.h"

#include "AppPaths.h"
#include "DeviceGuard.h"
#include "PlatformRules.h"
#include "RegUtil.h"
#include "SystemInfo.h"
#include "TextUtils.h"

#include <windows.h>
#include <VersionHelpers.h>
#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SecurityChecksPlatform] " + msg + L"\n").c_str());
}

static OptionalDword ReadOptionalDword(HKEY root, const std::wstring& key, const std::wstring& value)
{
    OptionalDword o;
    o.set = RegReadDword(root, key, value, o.value);
    return o;
}

// A key that exists but this account may not open. A missing key is readable: it
// simply holds nothing.
static bool KeyReadable(HKEY root, const std::wstring& key)
{
    return RegOpenStatus(root, key) != ERROR_ACCESS_DENIED;
}

static const wchar_t* const kHvciKey = L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";
static const wchar_t* const kCiConfigKey = L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config";
static const wchar_t* const kCiPolicyKey = L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy";

static HvciFacts ReadHvciFacts()
{
    HvciFacts facts;
    facts.registryEnabled = ReadOptionalDword(HKEY_LOCAL_MACHINE, kHvciKey, L"Enabled");
    DeviceGuardStatus dg = ReadDeviceGuardStatus();
    facts.wmiOk = dg.ok;
    facts.wmiConfigured = dg.ok && DeviceGuardHas(dg.configured, kDeviceGuardMemoryIntegrity);
    facts.wmiRunning = dg.ok && DeviceGuardHas(dg.running, kDeviceGuardMemoryIntegrity);
    return facts;
}

static SmartAppControlFacts ReadSmartAppControlFacts()
{
    SmartAppControlFacts facts;
    facts.build = GetWindowsBuildNumber();
    facts.isServer = IsWindowsServer();
    facts.keyReadable = KeyReadable(HKEY_LOCAL_MACHINE, kCiPolicyKey);
    facts.state = ReadOptionalDword(HKEY_LOCAL_MACHINE, kCiPolicyKey, L"VerifiedAndReputablePolicyState");
    return facts;
}

// ---------------------------------------------------------------------------
// Memory integrity (hypervisor-protected code integrity)
// ---------------------------------------------------------------------------
SecurityCheckResult CheckMemoryIntegrity()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.hvci");
    HvciFacts facts = ReadHvciFacts();
    std::wstring text;
    result.status = HvciStatus(facts, &text);
    result.detail = text + L"\nConfigured in the registry (Enabled): " +
        (facts.registryEnabled.set ? std::to_wstring(facts.registryEnabled.value) : std::wstring(L"not set")) +
        L"\nDevice Guard: " + (facts.wmiOk ? std::wstring(facts.wmiConfigured ? L"configured" : L"not configured") +
                                             (facts.wmiRunning ? L", running" : L", not running")
                                           : std::wstring(L"did not answer"));
    DebugLog(L"Memory integrity -> " + result.status);
    return result;
}

// ---------------------------------------------------------------------------
// Microsoft vulnerable driver block list
// ---------------------------------------------------------------------------
SecurityCheckResult CheckDriverBlocklist()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.driverblocklist");
    DriverBlocklistFacts facts;
    facts.build = GetWindowsBuildNumber();
    facts.isServer = IsWindowsServer();
    facts.keyReadable = KeyReadable(HKEY_LOCAL_MACHINE, kCiConfigKey);
    facts.enabled = ReadOptionalDword(HKEY_LOCAL_MACHINE, kCiConfigKey, L"VulnerableDriverBlocklistEnable");
    HvciFacts hvci = ReadHvciFacts();
    facts.hvciRunning = hvci.wmiOk && hvci.wmiRunning;
    SmartAppControlFacts sac = ReadSmartAppControlFacts();
    facts.smartAppControlOn = !sac.isServer && sac.build >= kWindows11_22H2Build && sac.state.set && sac.state.value == 1;

    std::wstring text;
    result.status = DriverBlocklistStatus(facts, &text);
    result.detail = text + L"\nVulnerableDriverBlocklistEnable: " +
        (facts.enabled.set ? std::to_wstring(facts.enabled.value) : std::wstring(L"not set")) +
        L"\nMemory integrity running: " + (facts.hvciRunning ? L"yes" : L"no") +
        L"\nSmart App Control on: " + (facts.smartAppControlOn ? L"yes" : L"no") +
        L"\n" + GetWindowsVersionText();
    DebugLog(L"Driver block list -> " + result.status);
    return result;
}

// ---------------------------------------------------------------------------
// Smart App Control
// ---------------------------------------------------------------------------
SecurityCheckResult CheckSmartAppControl()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.smartapp");
    SmartAppControlFacts facts = ReadSmartAppControlFacts();
    std::wstring text;
    result.status = SmartAppControlStatus(facts, &text);
    result.detail = text;
    if (facts.state.set) result.detail += L"\nVerifiedAndReputablePolicyState: " + std::to_wstring(facts.state.value);
    DebugLog(L"Smart App Control -> " + result.status);
    return result;
}

// ---------------------------------------------------------------------------
// System exploit protection: DEP, SEHOP, ASLR, CFG
// ---------------------------------------------------------------------------
SecurityCheckResult CheckExploitProtection()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.exploitprot");
    const wchar_t* kernelKey = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";
    ExploitProtectionFacts facts;
    DEP_SYSTEM_POLICY_TYPE dep = GetSystemDEPPolicy();
    facts.depPolicy = (dep >= DEPPolicyAlwaysOff && dep <= DEPPolicyOptOut) ? static_cast<int>(dep) : -1;
    facts.sehopDisabled = ReadOptionalDword(HKEY_LOCAL_MACHINE, kernelKey, L"DisableExceptionChainValidation");

    // REG_BINARY (16 or 24 bytes) or REG_QWORD; the first 64 bits hold the fields read here.
    std::vector<BYTE> raw;
    if (RegReadBinary(HKEY_LOCAL_MACHINE, kernelKey, L"MitigationOptions", raw) && raw.size() >= 4) {
        facts.mitigationsSet = true;
        unsigned long long value = 0;
        size_t n = raw.size() < 8 ? raw.size() : 8;
        for (size_t i = 0; i < n; ++i) value |= static_cast<unsigned long long>(raw[i]) << (8 * i);
        facts.mitigationOptions = value;
    }

    std::vector<std::wstring> lines;
    result.status = ExploitProtectionStatus(facts, &lines);
    std::wstring head = result.status == CHECK_FAIL ? L"Data Execution Prevention is switched off for the whole system." :
                        result.status == CHECK_WARNING ? L"A system-wide exploit protection is switched off or could not be read." :
                        L"System-wide exploit protections are on.";
    result.detail = head + L"\n" + JoinW(lines, L"\n") +
        L"\nMandatory ASLR and per-program overrides are not judged; SEHOP is read from DisableExceptionChainValidation only.";
    DebugLog(L"Exploit protection -> " + result.status);
    return result;
}

// ---------------------------------------------------------------------------
// Screen lock when nobody is at the PC
// ---------------------------------------------------------------------------
static ScreenSaverValues ReadScreenSaverValues(const std::wstring& key)
{
    ScreenSaverValues v;
    v.active = RegReadString(HKEY_CURRENT_USER, key, L"ScreenSaveActive");
    v.secure = RegReadString(HKEY_CURRENT_USER, key, L"ScreenSaverIsSecure");
    v.timeout = RegReadString(HKEY_CURRENT_USER, key, L"ScreenSaveTimeOut");
    v.exe = RegReadString(HKEY_CURRENT_USER, key, L"SCRNSAVE.EXE");
    return v;
}

SecurityCheckResult CheckScreenLock()
{
    SecurityCheckResult result = MakeCheckResult(L"acct.screenlock");
    ScreenLockFacts facts;
    facts.inactivitySecs = ReadOptionalDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"InactivityTimeoutSecs");
    facts.user = ReadScreenSaverValues(L"Control Panel\\Desktop");
    facts.policy = ReadScreenSaverValues(L"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop");

    std::vector<std::wstring> lines;
    result.status = ScreenLockStatus(facts, &lines);
    result.detail = (result.status == CHECK_PASS ? std::wstring(L"The PC locks itself within 15 minutes when nobody uses it.")
                                                 : std::wstring(L"Nothing this check reads locks the PC within 15 minutes "
                                                                L"when nobody uses it.")) +
        L"\n" + JoinW(lines, L"\n") +
        L"\nSleep with sign-in on wake also locks the PC; power plans are not read here.";
    DebugLog(L"Screen lock -> " + result.status);
    return result;
}

// ---------------------------------------------------------------------------
// System Restore for the system drive
// ---------------------------------------------------------------------------
SecurityCheckResult CheckSystemRestore()
{
    SecurityCheckResult result = MakeCheckResult(L"backup.restore");
    SystemRestoreFacts facts;
    facts.isServer = IsWindowsServer();
    facts.policyDisable = ReadOptionalDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore", L"DisableSR");
    const wchar_t* srKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore";
    facts.legacyDisable = ReadOptionalDword(HKEY_LOCAL_MACHINE, srKey, L"DisableSR");
    facts.sessionInterval = ReadOptionalDword(HKEY_LOCAL_MACHINE, srKey, L"RPSessionInterval");

    facts.systemDrive = ExpandEnvironment(L"%SystemDrive%");
    if (facts.systemDrive.empty() || facts.systemDrive[0] == L'%') facts.systemDrive = L"C:";
    wchar_t volume[MAX_PATH] = {};
    if (GetVolumeNameForVolumeMountPointW((facts.systemDrive + L"\\").c_str(), volume, MAX_PATH)) facts.systemVolume = volume;

    // System Protection keeps its list of protected volumes here. Only administrators
    // may read the key.
    const wchar_t* clientsKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SPP\\Clients";
    const wchar_t* systemRestoreClient = L"{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}";
    LONG open = RegOpenStatus(HKEY_LOCAL_MACHINE, clientsKey);
    facts.clientsReadable = open == ERROR_SUCCESS || open == ERROR_FILE_NOT_FOUND;
    if (open == ERROR_SUCCESS) {
        facts.clientsValueSet = RegValueExists(HKEY_LOCAL_MACHINE, clientsKey, systemRestoreClient);
        facts.protectedVolumes = RegReadMultiString(HKEY_LOCAL_MACHINE, clientsKey, systemRestoreClient);
    }

    std::wstring text;
    result.status = SystemRestoreStatus(facts, &text);
    result.detail = text;
    if (facts.clientsValueSet) {
        result.detail += L"\nProtected volumes: " + std::to_wstring(facts.protectedVolumes.size());
        size_t shown = 0;
        for (const std::wstring& v : facts.protectedVolumes) {
            if (++shown > 20) break;
            result.detail += L"\n  " + v;
        }
    }
    if (result.status == CHECK_WARNING) result.detail += L"\nRestore points are not a backup of personal files.";
    DebugLog(L"System Restore -> " + result.status + L" (SPP open status " + std::to_wstring(open) + L")");
    return result;
}
