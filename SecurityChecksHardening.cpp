#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "RegUtil.h"
#include "ServiceUtil.h"
#include "SystemInfo.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <windows.h>
#include <shobjidl.h>
#include <propsys.h>
#include <propvarutil.h>
#include <tbs.h>
#include <winspool.h>
#include <mutex>
#include <sstream>

#pragma comment(lib, "tbs.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// ---------------------------------------------------------------------------
// Optional features (SMB1, PowerShell 2.0, .NET 3.5), read once per minute
// ---------------------------------------------------------------------------
struct FeatureCache {
    std::mutex mutex;
    ULONGLONG  takenAt = 0;
    bool       ok = false;
    std::map<std::wstring, int> states;   // feature name (lowercase) -> InstallState (1 on, 2 off, 3 absent)
};

static bool OptionalFeatureState(const std::wstring& name, int& state)
{
    static FeatureCache cache;
    std::lock_guard<std::mutex> lock(cache.mutex);
    ULONGLONG now = GetTickCount64();
    if (cache.takenAt == 0 || now - cache.takenAt > 60000) {
        cache.states.clear();
        WmiResult r = WmiQuery(L"ROOT\\CIMV2",
            L"SELECT Name, InstallState FROM Win32_OptionalFeature WHERE Name='SMB1Protocol' OR Name='SMB1Protocol-Client' "
            L"OR Name='SMB1Protocol-Server' OR Name='MicrosoftWindowsPowerShellV2Root' OR Name='MicrosoftWindowsPowerShellV2' "
            L"OR Name='NetFx3'",
            { L"Name", L"InstallState" });
        cache.ok = r.ok;
        for (const WmiRow& row : r.rows) {
            auto n = row.find(L"Name");
            auto s = row.find(L"InstallState");
            if (n != row.end() && s != row.end()) cache.states[ToLowerW(n->second)] = _wtoi(s->second.c_str());
        }
        cache.takenAt = now;
    }
    auto it = cache.states.find(ToLowerW(name));
    if (it == cache.states.end()) return false;
    state = it->second;
    return true;
}

// ---------------------------------------------------------------------------
// BitLocker
// ---------------------------------------------------------------------------
// PKEY_Volume_BitLockerProtection: {9A93244D-A7AD-4FF8-9B99-45EE4CC09AF6}, 100
static const PROPERTYKEY kBitLockerProtection = {
    { 0x9A93244D, 0xA7AD, 0x4FF8, { 0x9B, 0x99, 0x45, 0xEE, 0x4C, 0xC0, 0x9A, 0xF6 } }, 100
};

static bool ShellBitLockerState(const std::wstring& root, int& state)
{
    ComScope com;
    IShellItem2* item = NULL;
    if (FAILED(SHCreateItemFromParsingName(root.c_str(), NULL, IID_PPV_ARGS(&item))) || !item) return false;
    PROPVARIANT pv;
    PropVariantInit(&pv);
    bool ok = false;
    if (SUCCEEDED(item->GetProperty(kBitLockerProtection, &pv))) {
        if (pv.vt == VT_I4) { state = pv.lVal; ok = true; }
        else if (pv.vt == VT_UI4) { state = static_cast<int>(pv.ulVal); ok = true; }
        else if (pv.vt == VT_EMPTY) { state = 0; ok = true; }
    }
    PropVariantClear(&pv);
    item->Release();
    return ok;
}

SecurityCheckResult CheckBitLocker()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.bitlocker");
    std::wstring systemDrive = ExpandEnvironment(L"%SystemDrive%");
    if (systemDrive.empty() || systemDrive[0] == L'%') systemDrive = L"C:";

    WmiResult r = WmiQuery(L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption",
        L"SELECT DriveLetter, ProtectionStatus, ConversionStatus FROM Win32_EncryptableVolume",
        { L"DriveLetter", L"ProtectionStatus", L"ConversionStatus" });
    if (r.ok && !r.rows.empty()) {
        std::wstringstream details;
        bool systemProtected = false;
        bool systemFound = false;
        for (const WmiRow& row : r.rows) {
            auto letter = row.find(L"DriveLetter");
            if (letter == row.end() || letter->second.empty()) continue;
            int protection = _wtoi(row.count(L"ProtectionStatus") ? row.at(L"ProtectionStatus").c_str() : L"0");
            int conversion = _wtoi(row.count(L"ConversionStatus") ? row.at(L"ConversionStatus").c_str() : L"0");
            const wchar_t* conv = conversion == 0 ? L"decrypted" : conversion == 1 ? L"encrypted" :
                                  conversion == 2 ? L"encrypting" : conversion == 3 ? L"decrypting" : L"paused";
            details << L"  " << letter->second << L" protection " << (protection == 1 ? L"ON" : L"off") << L", " << conv << L"\n";
            if (EqualsI(letter->second, systemDrive)) {
                systemFound = true;
                systemProtected = protection == 1;
            }
        }
        if (systemFound && systemProtected) {
            result.status = CHECK_PASS;
            result.detail = L"The system drive " + systemDrive + L" is encrypted and protected.\n" + details.str();
        }
        else {
            result.status = CHECK_FAIL;
            result.detail = L"The system drive " + systemDrive + L" is not protected by BitLocker.\n" + details.str();
        }
        return result;
    }

    // Without admin rights the WMI class is off limits; Explorer's property is not.
    int state = 0;
    if (ShellBitLockerState(systemDrive + L"\\", state)) {
        switch (state) {
        case 1:
            result.status = CHECK_PASS;
            result.detail = L"BitLocker is on for " + systemDrive + L" (read from Explorer; run as administrator for detail).";
            break;
        case 0:
        case 2:
            result.status = CHECK_FAIL;
            result.detail = L"BitLocker is off for " + systemDrive + L".";
            break;
        default:
            result.status = CHECK_WARNING;
            result.detail = L"BitLocker for " + systemDrive + L" reports state code " + std::to_wstring(state) +
                L" (encrypting, decrypting or suspended). Run as administrator for detail.";
            break;
        }
        return result;
    }

    result.status = CHECK_ERROR;
    result.detail = L"BitLocker state could not be read (" + r.error + L"). Run as administrator.";
    return result;
}

// ---------------------------------------------------------------------------
// TPM
// ---------------------------------------------------------------------------
SecurityCheckResult CheckTpm()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.tpm");
    TPM_DEVICE_INFO info = {};
    TBS_RESULT rc = Tbsi_GetDeviceInfo(sizeof(info), &info);
    if (rc == TBS_SUCCESS) {
        if (info.tpmVersion == TPM_VERSION_20) {
            result.status = CHECK_PASS;
            result.detail = L"TPM 2.0 present and available.";
        }
        else if (info.tpmVersion == TPM_VERSION_12) {
            result.status = CHECK_WARNING;
            result.detail = L"TPM 1.2 present. Windows 11 and some protections need TPM 2.0.";
        }
        else {
            result.status = CHECK_WARNING;
            result.detail = L"TPM present, version code " + std::to_wstring(info.tpmVersion) + L".";
        }
        return result;
    }
    if (rc == TBS_E_TPM_NOT_FOUND || rc == TBS_E_SERVICE_NOT_RUNNING) {
        result.status = CHECK_FAIL;
        result.detail = L"No TPM was found, or it is switched off in the firmware.";
        return result;
    }
    wchar_t buf[64];
    swprintf_s(buf, L"TPM state could not be read (TBS 0x%08X).", static_cast<unsigned int>(rc));
    result.status = CHECK_ERROR;
    result.detail = buf;
    return result;
}

// ---------------------------------------------------------------------------
// Secure Boot
// ---------------------------------------------------------------------------
SecurityCheckResult CheckSecureBoot()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.secureboot");
    FIRMWARE_TYPE firmware = FirmwareTypeUnknown;
    GetFirmwareType(&firmware);
    if (firmware == FirmwareTypeBios) {
        result.status = CHECK_FAIL;
        result.detail = L"The PC boots in legacy BIOS mode. Secure Boot needs UEFI mode.";
        return result;
    }
    DWORD enabled = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", L"UEFISecureBootEnabled", enabled)) {
        result.status = enabled == 1 ? CHECK_PASS : CHECK_FAIL;
        result.detail = enabled == 1 ? L"Secure Boot is on." : L"Secure Boot is off (UEFI firmware, but not enforcing).";
        return result;
    }
    result.status = CHECK_WARNING;
    result.detail = L"Secure Boot state is not recorded; the firmware may not support it.";
    return result;
}

// ---------------------------------------------------------------------------
// UAC
// ---------------------------------------------------------------------------
SecurityCheckResult CheckUac()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.uac");
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    DWORD lua = 1, consent = 5, secureDesktop = 1;
    RegReadDword(HKEY_LOCAL_MACHINE, key, L"EnableLUA", lua);
    RegReadDword(HKEY_LOCAL_MACHINE, key, L"ConsentPromptBehaviorAdmin", consent);
    RegReadDword(HKEY_LOCAL_MACHINE, key, L"PromptOnSecureDesktop", secureDesktop);

    const wchar_t* consentText =
        consent == 0 ? L"elevate without prompting" :
        consent == 1 ? L"ask for credentials on the secure desktop" :
        consent == 2 ? L"always notify on the secure desktop" :
        consent == 3 ? L"ask for credentials" :
        consent == 4 ? L"ask for consent" :
        consent == 5 ? L"ask for consent for non-Windows programs (default)" : L"unknown";
    std::wstring details = L"EnableLUA=" + std::to_wstring(lua) + L", admin prompt: " + consentText +
        L", secure desktop: " + (secureDesktop ? L"yes" : L"no");

    if (lua == 0) {
        result.status = CHECK_FAIL;
        result.detail = L"User Account Control is OFF. Every admin program runs elevated silently.\n" + details;
    }
    else if (consent == 0) {
        result.status = CHECK_FAIL;
        result.detail = L"UAC elevates administrators without asking.\n" + details;
    }
    else if (!secureDesktop) {
        result.status = CHECK_WARNING;
        result.detail = L"UAC prompts appear on the normal desktop, where other programs can interfere with them.\n" + details;
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"User Account Control is on.\n" + details;
    }
    return result;
}

// ---------------------------------------------------------------------------
// AutoPlay / AutoRun
// ---------------------------------------------------------------------------
SecurityCheckResult CheckAutoPlay()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.autoplay");
    const wchar_t* polKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
    DWORD hklmTypes = 0, hkcuTypes = 0, noAutorun = 0, disableAutoplay = 0;
    bool hklmSet = RegReadDword(HKEY_LOCAL_MACHINE, polKey, L"NoDriveTypeAutoRun", hklmTypes);
    bool hkcuSet = RegReadDword(HKEY_CURRENT_USER, polKey, L"NoDriveTypeAutoRun", hkcuTypes);
    RegReadDword(HKEY_LOCAL_MACHINE, polKey, L"NoAutorun", noAutorun);
    RegReadDword(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers",
        L"DisableAutoplay", disableAutoplay);

    bool allDrivesOff = (hklmSet && (hklmTypes & 0xFF) == 0xFF) || (hkcuSet && (hkcuTypes & 0xFF) == 0xFF);
    std::wstring details = L"NoDriveTypeAutoRun HKLM=" + (hklmSet ? std::to_wstring(hklmTypes) : std::wstring(L"not set")) +
        L", HKCU=" + (hkcuSet ? std::to_wstring(hkcuTypes) : std::wstring(L"not set")) +
        L"; NoAutorun=" + std::to_wstring(noAutorun) + L"; AutoPlay off for this user=" + (disableAutoplay ? L"yes" : L"no");

    if (allDrivesOff || disableAutoplay == 1) {
        result.status = CHECK_PASS;
        result.detail = L"AutoPlay is off.\n" + details;
    }
    else {
        result.status = CHECK_WARNING;
        result.detail = L"AutoPlay can act on inserted USB sticks and discs.\n" + details;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Windows Script Host
// ---------------------------------------------------------------------------
SecurityCheckResult CheckWindowsScriptHost()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.wsh");
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows Script Host\\Settings";
    DWORD hklm = 1, hkcu = 1;
    bool hklmSet = RegReadDword(HKEY_LOCAL_MACHINE, key, L"Enabled", hklm);
    bool hkcuSet = RegReadDword(HKEY_CURRENT_USER, key, L"Enabled", hkcu);
    if ((hklmSet && hklm == 0) || (hkcuSet && hkcu == 0)) {
        result.status = CHECK_PASS;
        result.detail = L"Windows Script Host is disabled.";
    }
    else {
        result.status = CHECK_WARNING;
        result.detail = L"Windows Script Host is enabled (the Windows default). Double-clicking a .vbs or .js file runs it.";
    }
    return result;
}

// ---------------------------------------------------------------------------
// PowerShell 2.0
// ---------------------------------------------------------------------------
SecurityCheckResult CheckPowerShellV2()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.psv2");
    int root = 0, engine = 0, netfx3 = 0;
    bool haveRoot = OptionalFeatureState(L"MicrosoftWindowsPowerShellV2Root", root);
    bool haveEngine = OptionalFeatureState(L"MicrosoftWindowsPowerShellV2", engine);
    OptionalFeatureState(L"NetFx3", netfx3);

    if (!haveRoot && !haveEngine) {
        // Feature not present in this build (Windows 11 24H2 and later removed it)
        bool engineFiles = RegKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine") &&
            RegReadString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine", L"PowerShellVersion").rfind(L"2.", 0) == 0;
        result.status = engineFiles ? CHECK_WARNING : CHECK_PASS;
        result.detail = engineFiles ? L"The PowerShell 2.0 engine is registered." : L"PowerShell 2.0 is not available on this Windows build.";
        return result;
    }
    bool enabled = (root == 1) || (engine == 1);
    if (!enabled) {
        result.status = CHECK_PASS;
        result.detail = L"PowerShell 2.0 is disabled.";
    }
    else if (netfx3 == 1) {
        result.status = CHECK_FAIL;
        result.detail = L"PowerShell 2.0 is enabled and .NET 3.5 is installed, so powershell -Version 2 works and skips logging and AMSI.";
    }
    else {
        result.status = CHECK_WARNING;
        result.detail = L"PowerShell 2.0 is enabled. It cannot start until .NET 3.5 is installed, but it should be removed.";
    }
    return result;
}

// ---------------------------------------------------------------------------
// Office macros
// ---------------------------------------------------------------------------
SecurityCheckResult CheckOfficeMacros()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.macros");
    const wchar_t* versions[] = { L"16.0", L"15.0", L"14.0" };
    const wchar_t* apps[] = { L"Word", L"Excel", L"PowerPoint" };

    bool officeFound = RegKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration");
    for (const wchar_t* v : versions) {
        if (RegKeyExists(HKEY_CURRENT_USER, std::wstring(L"Software\\Microsoft\\Office\\") + v + L"\\Common")) officeFound = true;
        if (RegKeyExists(HKEY_LOCAL_MACHINE, std::wstring(L"SOFTWARE\\Microsoft\\Office\\") + v + L"\\Common\\InstallRoot")) officeFound = true;
    }
    if (!officeFound) {
        result.status = CHECK_NA;
        result.detail = L"Microsoft Office was not found.";
        return result;
    }

    std::wstringstream details;
    bool enableAll = false;
    bool internetBlockPolicy = false;
    for (const wchar_t* v : versions) {
        for (const wchar_t* app : apps) {
            std::wstring policyKey = std::wstring(L"Software\\Policies\\Microsoft\\Office\\") + v + L"\\" + app + L"\\Security";
            std::wstring userKey = std::wstring(L"Software\\Microsoft\\Office\\") + v + L"\\" + app + L"\\Security";
            DWORD vba = 0;
            bool policyVba = RegReadDword(HKEY_CURRENT_USER, policyKey, L"VBAWarnings", vba);
            if (!policyVba) RegReadDword(HKEY_CURRENT_USER, userKey, L"VBAWarnings", vba);
            if (policyVba || vba != 0) {
                const wchar_t* text = vba == 1 ? L"ENABLE ALL MACROS" : vba == 2 ? L"disable with notification" :
                                      vba == 3 ? L"disable except digitally signed" : vba == 4 ? L"disable all" : L"default";
                details << L"  " << app << L" " << v << L": " << text << (policyVba ? L" (policy)" : L"") << L"\n";
                if (vba == 1) enableAll = true;
            }
            DWORD block = 0;
            if (RegReadDword(HKEY_CURRENT_USER, policyKey, L"blockcontentexecutionfrominternet", block) && block == 1) {
                internetBlockPolicy = true;
            }
        }
    }

    if (enableAll) {
        result.status = CHECK_FAIL;
        result.detail = L"An Office app is set to enable all macros.\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = std::wstring(L"No Office app enables all macros. ") +
            (internetBlockPolicy ? L"Internet macros are blocked by policy." : L"Current Office blocks macros in downloaded files by default.") +
            (details.str().empty() ? L"" : L"\n" + details.str());
    }
    return result;
}

// ---------------------------------------------------------------------------
// LSA protection
// ---------------------------------------------------------------------------
SecurityCheckResult CheckLsaProtection()
{
    SecurityCheckResult result = MakeCheckResult(L"lsa.ppl");
    DWORD ppl = 0;
    bool set = RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", ppl);
    DWORD pplBoot = 0;
    RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPLBoot", pplBoot);
    if (set && (ppl == 1 || ppl == 2)) {
        result.status = CHECK_PASS;
        result.detail = L"LSA protection is on (RunAsPPL=" + std::to_wstring(ppl) + (ppl == 1 ? L", locked by UEFI)." : L", without UEFI lock).");
    }
    else if (pplBoot == 2) {
        result.status = CHECK_PASS;
        result.detail = L"LSA protection is on through RunAsPPLBoot.";
    }
    else {
        result.status = CHECK_FAIL;
        result.detail = set ? L"LSA protection is off (RunAsPPL=" + std::to_wstring(ppl) + L")." : std::wstring(L"LSA protection is not configured.");
    }
    return result;
}

// ---------------------------------------------------------------------------
// SMB version 1
// ---------------------------------------------------------------------------
SecurityCheckResult CheckSmbV1()
{
    SecurityCheckResult result = MakeCheckResult(L"net.smbv1");
    std::wstringstream details;
    bool on = false;

    int feature = 0;
    if (OptionalFeatureState(L"SMB1Protocol", feature)) {
        details << L"SMB1Protocol feature: " << (feature == 1 ? L"Enabled" : feature == 2 ? L"Disabled" : L"Not present") << L"\n";
        if (feature == 1) on = true;
    }

    DWORD start = 4;
    bool clientDriver = RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\mrxsmb10", L"Start", start);
    details << L"SMB1 client driver (mrxsmb10): " << (clientDriver ? (start == 4 ? L"disabled" : L"ENABLED") : L"not installed") << L"\n";
    if (clientDriver && start != 4) on = true;

    DWORD server = 1;
    bool serverSet = RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SMB1", server);
    bool srvDriver = RegKeyExists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\srv");
    bool serverOn = srvDriver && !(serverSet && server == 0);
    details << L"SMB1 server: " << (serverOn ? L"ENABLED" : L"disabled") << L"\n";
    if (serverOn) on = true;

    result.status = on ? CHECK_FAIL : CHECK_PASS;
    result.detail = (on ? L"SMB version 1 is available.\n" : L"SMB version 1 is off.\n") + details.str();
    return result;
}

// ---------------------------------------------------------------------------
// Remote Desktop
// ---------------------------------------------------------------------------
SecurityCheckResult CheckRemoteDesktop()
{
    SecurityCheckResult result = MakeCheckResult(L"net.rdp");
    DWORD deny = 1;
    RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections", deny);
    if (deny == 1) {
        result.status = CHECK_PASS;
        result.detail = L"Remote Desktop is off.";
        return result;
    }
    const wchar_t* tcp = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp";
    DWORD nla = 0, port = 3389;
    RegReadDword(HKEY_LOCAL_MACHINE, tcp, L"UserAuthentication", nla);
    RegReadDword(HKEY_LOCAL_MACHINE, tcp, L"PortNumber", port);
    std::wstring details = L"Port " + std::to_wstring(port) + L", Network Level Authentication " + (nla == 1 ? L"required" : L"NOT required");
    if (nla != 1) {
        result.status = CHECK_FAIL;
        result.detail = L"Remote Desktop is on without Network Level Authentication.\n" + details;
    }
    else {
        result.status = CHECK_WARNING;
        result.detail = L"Remote Desktop is on. Turn it off if you do not use it.\n" + details;
    }
    return result;
}

// ---------------------------------------------------------------------------
// WinRM
// ---------------------------------------------------------------------------
SecurityCheckResult CheckWinRm()
{
    SecurityCheckResult result = MakeCheckResult(L"net.winrm");
    ServiceInfo s;
    if (!QueryServiceByName(L"WinRM", s)) {
        result.status = CHECK_PASS;
        result.detail = L"The WinRM service is not installed.";
        return result;
    }
    std::vector<std::wstring> listeners = RegEnumSubKeys(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN\\Listener");
    std::wstring details = L"Service " + ServiceStateName(s.state) + L", start type " + ServiceStartTypeName(s.startType) +
        L", " + std::to_wstring(listeners.size()) + L" listener(s)";
    for (const std::wstring& l : listeners) details += L"\n  " + l;

    if (s.state == SERVICE_RUNNING && !listeners.empty()) {
        result.status = CHECK_WARNING;
        result.detail = L"WinRM is running and accepting remote connections.\n" + details;
    }
    else if (s.startType == SERVICE_AUTO_START && !listeners.empty()) {
        result.status = CHECK_WARNING;
        result.detail = L"WinRM starts automatically and has listeners configured.\n" + details;
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"WinRM is not accepting remote connections.\n" + details;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Remote Registry
// ---------------------------------------------------------------------------
SecurityCheckResult CheckRemoteRegistry()
{
    SecurityCheckResult result = MakeCheckResult(L"net.remoteregistry");
    ServiceInfo s;
    if (!QueryServiceByName(L"RemoteRegistry", s)) {
        result.status = CHECK_PASS;
        result.detail = L"The Remote Registry service is not installed.";
        return result;
    }
    std::wstring details = L"Service " + ServiceStateName(s.state) + L", start type " + ServiceStartTypeName(s.startType);
    if (s.state == SERVICE_RUNNING || s.startType == SERVICE_AUTO_START) {
        result.status = CHECK_WARNING;
        result.detail = L"Remote Registry is running or set to start automatically.\n" + details;
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"Remote Registry is not running.\n" + details;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Print Spooler
// ---------------------------------------------------------------------------
static std::vector<std::wstring> PhysicalPrinters()
{
    std::vector<std::wstring> out;
    DWORD needed = 0, returned = 0;
    EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2, NULL, 0, &needed, &returned);
    if (needed == 0) return out;
    std::vector<BYTE> buffer(needed);
    if (!EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, NULL, 2, buffer.data(), needed, &needed, &returned)) return out;
    PRINTER_INFO_2W* printers = reinterpret_cast<PRINTER_INFO_2W*>(buffer.data());
    for (DWORD i = 0; i < returned; ++i) {
        std::wstring name = printers[i].pPrinterName ? printers[i].pPrinterName : L"";
        std::wstring port = printers[i].pPortName ? printers[i].pPortName : L"";
        bool virtualPrinter = ContainsI(name, L"Microsoft Print to PDF") || ContainsI(name, L"XPS Document Writer") ||
            ContainsI(name, L"OneNote") || EqualsI(name, L"Fax") || EqualsI(port, L"PORTPROMPT:") || EqualsI(port, L"nul:") ||
            EqualsI(port, L"SHRFAX:");
        if (!virtualPrinter) out.push_back(name);
    }
    return out;
}

SecurityCheckResult CheckPrintSpooler()
{
    SecurityCheckResult result = MakeCheckResult(L"svc.spooler");
    ServiceInfo s;
    if (!QueryServiceByName(L"Spooler", s)) {
        result.status = CHECK_PASS;
        result.detail = L"The Print Spooler service is not installed.";
        return result;
    }
    if (s.state != SERVICE_RUNNING && s.startType == SERVICE_DISABLED) {
        result.status = CHECK_PASS;
        result.detail = L"The Print Spooler is disabled.";
        return result;
    }

    std::vector<std::wstring> printers = PhysicalPrinters();
    DWORD restrict = 0;
    bool restricted = RegReadDword(HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint",
        L"RestrictDriverInstallationToAdministrators", restrict) ? restrict == 1 : true;   // default on since Aug 2021 updates
    std::wstring details = L"Service " + ServiceStateName(s.state) + L", " + std::to_wstring(printers.size()) + L" physical printer(s)";
    for (const std::wstring& p : printers) details += L"\n  " + p;
    details += std::wstring(L"\nDriver installation limited to administrators: ") + (restricted ? L"yes" : L"NO");

    if (!restricted) {
        result.status = CHECK_FAIL;
        result.detail = L"Non-administrators can install printer drivers.\n" + details;
    }
    else if (printers.empty() && s.state == SERVICE_RUNNING) {
        result.status = CHECK_WARNING;
        result.detail = L"The Print Spooler runs but there are no printers.\n" + details;
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"The Print Spooler is needed for the printers listed and driver installs are restricted.\n" + details;
    }
    return result;
}
