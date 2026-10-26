#include "pch.h"
#include "SecurityCheckModules.h"

#include "RegUtil.h"
#include "ServiceUtil.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <windows.h>
#include <netfw.h>
#include <sstream>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SecurityChecksExtra] " + msg + L"\n").c_str());
}

// ---------------------------------------------------------------------------
// PowerShell logging and execution policy
// ---------------------------------------------------------------------------
SecurityCheckResult CheckPowerShellLogging()
{
    SecurityCheckResult result = MakeCheckResult(L"ps.logging");
    std::wstringstream details;
    bool missingCore = false;

    std::wstring policy = RegReadString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", L"ExecutionPolicy");
    std::wstring local = RegReadString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"ExecutionPolicy");
    std::wstring effective = !policy.empty() ? policy + L" (Group Policy)" : (!local.empty() ? local : L"Not set (Restricted on clients)");
    details << L"Execution policy: " << effective << L"\n";
    bool permissive = EqualsI(policy, L"Unrestricted") || EqualsI(policy, L"Bypass") ||
                      (policy.empty() && (EqualsI(local, L"Unrestricted") || EqualsI(local, L"Bypass")));
    if (permissive) details << L"  Execution policy lets any script run (it is not a security boundary, but it removes a speed bump)\n";

    DWORD sbl = 0;
    bool sblOn = RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        L"EnableScriptBlockLogging", sbl) && sbl == 1;
    details << L"Script block logging: " << (sblOn ? L"On" : L"Off") << L"\n";
    if (!sblOn) missingCore = true;

    DWORD ml = 0;
    bool mlOn = RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
        L"EnableModuleLogging", ml) && ml == 1;
    details << L"Module logging: " << (mlOn ? L"On" : L"Off") << L"\n";

    DWORD tr = 0;
    bool trOn = RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
        L"EnableTranscripting", tr) && tr == 1;
    details << L"Transcription: " << (trOn ? L"On" : L"Off");
    if (trOn) {
        std::wstring dir = RegReadString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
            L"OutputDirectory");
        details << L" (output folder: " << (dir.empty() ? L"each user's Documents folder" : dir) << L")";
    }
    details << L"\n";

    wchar_t lockdown[16] = {};
    DWORD envLen = GetEnvironmentVariableW(L"__PSLockdownPolicy", lockdown, 16);
    details << L"Constrained Language Mode: " << ((envLen > 0 && wcscmp(lockdown, L"4") == 0) ? L"Enforced" : L"Not enforced") << L"\n";

    if (missingCore || !mlOn) {
        result.status = CHECK_WARNING;
        result.detail = L"PowerShell activity is not fully recorded.\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"PowerShell script block and module logging are on.\n" + details.str();
    }
    return result;
}

// ---------------------------------------------------------------------------
// Windows Firewall
// ---------------------------------------------------------------------------
struct FirewallProfileState {
    const wchar_t* name;
    NET_FW_PROFILE_TYPE2 type;
    bool known = false;
    bool enabled = false;
    bool blockInbound = true;
    int  inboundAllowRules = 0;
};

static bool ReadFirewallViaCom(FirewallProfileState* profiles, size_t count, int& totalRules, std::wstring& error)
{
    ComScope com;
    if (!com.Ok()) {
        error = L"COM unavailable";
        return false;
    }
    INetFwPolicy2* policy = NULL;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(&policy));
    if (FAILED(hr) || !policy) {
        error = L"Firewall API unavailable";
        return false;
    }

    for (size_t i = 0; i < count; ++i) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        if (SUCCEEDED(policy->get_FirewallEnabled(profiles[i].type, &enabled))) {
            profiles[i].known = true;
            profiles[i].enabled = enabled == VARIANT_TRUE;
        }
        NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
        if (SUCCEEDED(policy->get_DefaultInboundAction(profiles[i].type, &action))) {
            profiles[i].blockInbound = action == NET_FW_ACTION_BLOCK;
        }
    }

    INetFwRules* rules = NULL;
    if (SUCCEEDED(policy->get_Rules(&rules)) && rules) {
        long n = 0;
        rules->get_Count(&n);
        totalRules = n;
        IUnknown* enumUnknown = NULL;
        if (SUCCEEDED(rules->get__NewEnum(&enumUnknown)) && enumUnknown) {
            IEnumVARIANT* e = NULL;
            if (SUCCEEDED(enumUnknown->QueryInterface(__uuidof(IEnumVARIANT), reinterpret_cast<void**>(&e))) && e) {
                VARIANT v;
                VariantInit(&v);
                ULONG fetched = 0;
                while (e->Next(1, &v, &fetched) == S_OK && fetched == 1) {
                    if (v.vt == VT_DISPATCH && v.pdispVal) {
                        INetFwRule* rule = NULL;
                        if (SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&rule))) && rule) {
                            VARIANT_BOOL ruleEnabled = VARIANT_FALSE;
                            NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_OUT;
                            NET_FW_ACTION act = NET_FW_ACTION_BLOCK;
                            long profileMask = 0;
                            rule->get_Enabled(&ruleEnabled);
                            rule->get_Direction(&dir);
                            rule->get_Action(&act);
                            rule->get_Profiles(&profileMask);
                            if (ruleEnabled == VARIANT_TRUE && dir == NET_FW_RULE_DIR_IN && act == NET_FW_ACTION_ALLOW) {
                                for (size_t i = 0; i < count; ++i) {
                                    if (profileMask & profiles[i].type) profiles[i].inboundAllowRules++;
                                }
                            }
                            rule->Release();
                        }
                    }
                    VariantClear(&v);
                }
                e->Release();
            }
            enumUnknown->Release();
        }
        rules->Release();
    }
    policy->Release();
    return true;
}

SecurityCheckResult CheckWindowsFirewall()
{
    SecurityCheckResult result = MakeCheckResult(L"fw.profiles");
    FirewallProfileState profiles[] = {
        { L"Domain",  NET_FW_PROFILE2_DOMAIN },
        { L"Private", NET_FW_PROFILE2_PRIVATE },
        { L"Public",  NET_FW_PROFILE2_PUBLIC },
    };
    int totalRules = 0;
    std::wstring error;
    bool viaCom = ReadFirewallViaCom(profiles, 3, totalRules, error);

    if (!viaCom) {
        // Registry fallback for the on/off state
        const wchar_t* keys[] = {
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
        };
        for (int i = 0; i < 3; ++i) {
            DWORD v = 0;
            profiles[i].known = RegReadDword(HKEY_LOCAL_MACHINE, keys[i], L"EnableFirewall", v);
            profiles[i].enabled = profiles[i].known && v == 1;
            DWORD inbound = 1;
            if (RegReadDword(HKEY_LOCAL_MACHINE, keys[i], L"DefaultInboundAction", inbound)) {
                profiles[i].blockInbound = inbound == 1;
            }
        }
    }

    std::wstringstream details;
    bool anyOff = false;
    bool anyAllowInbound = false;
    for (const FirewallProfileState& p : profiles) {
        details << p.name << L": " << (p.enabled ? L"On" : L"OFF")
                << L", inbound default " << (p.blockInbound ? L"Block" : L"ALLOW");
        if (viaCom) details << L", " << p.inboundAllowRules << L" enabled inbound allow rule(s)";
        details << L"\n";
        if (!p.enabled) anyOff = true;
        if (!p.blockInbound) anyAllowInbound = true;
    }
    if (viaCom) details << L"Total rules: " << totalRules << L"\n";
    else details << L"(" << error << L"; read from the registry, rule counts not available)\n";

    if (anyOff) {
        result.status = CHECK_FAIL;
        result.detail = L"At least one firewall profile is off.\n" + details.str();
    }
    else if (anyAllowInbound) {
        result.status = CHECK_FAIL;
        result.detail = L"A firewall profile allows inbound connections by default.\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"All three firewall profiles are on and block inbound by default.\n" + details.str();
    }
    DebugLog(L"Firewall: " + result.status);
    return result;
}

// ---------------------------------------------------------------------------
// Event log size and channels
// ---------------------------------------------------------------------------
SecurityCheckResult CheckEventLogSettings()
{
    SecurityCheckResult result = MakeCheckResult(L"audit.policy");
    std::wstringstream details;
    bool gap = false;

    DWORD noLegacy = 0;
    bool advanced = RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        L"SCENoApplyLegacyAuditPolicy", noLegacy) && noLegacy == 1;
    details << L"Advanced audit policy forced: " << (advanced ? L"Yes" : L"No (legacy categories can override it)") << L"\n";

    DWORD maxSize = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security", L"MaxSize", maxSize)) {
        DWORD mb = maxSize / (1024 * 1024);
        details << L"Security log maximum size: " << mb << L" MB";
        if (mb < 192) {
            gap = true;
            details << L" (recommended 192 MB or more)";
        }
        details << L"\n";
    }
    else {
        details << L"Security log maximum size: default (20 MB)\n";
        gap = true;
    }

    DWORD crash = 0;
    RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"CrashOnAuditFail", crash);
    details << L"CrashOnAuditFail: " << (crash ? L"On" : L"Off") << L"\n";

    DWORD psEnabled = 0;
    bool psLog = RegReadDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-PowerShell/Operational",
        L"Enabled", psEnabled) && psEnabled == 1;
    details << L"PowerShell operational log: " << (psLog ? L"On" : L"Off") << L"\n";
    if (!psLog) gap = true;

    DWORD cmdLine = 0;
    bool cmdLineOn = RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
        L"ProcessCreationIncludeCmdLine_Enabled", cmdLine) && cmdLine == 1;
    details << L"Command line in process creation events: " << (cmdLineOn ? L"On" : L"Off") << L"\n";

    if (gap) {
        result.status = CHECK_WARNING;
        result.detail = L"Logs are too small or a useful channel is off.\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"Event log sizes and channels look reasonable.\n" + details.str();
    }
    return result;
}

// ---------------------------------------------------------------------------
// Windows Update
// ---------------------------------------------------------------------------
SecurityCheckResult CheckWindowsUpdateStatus()
{
    SecurityCheckResult result = MakeCheckResult(L"wu.status");
    result.status = CHECK_PASS;
    std::wstringstream details;

    ServiceInfo wu;
    if (QueryServiceByName(L"wuauserv", wu)) {
        details << L"Windows Update service: " << ServiceStateName(wu.state) << L", start type " << ServiceStartTypeName(wu.startType) << L"\n";
        if (wu.startType == SERVICE_DISABLED) {
            result.status = CHECK_FAIL;
            details << L"  The service is disabled, so no updates can install.\n";
        }
    }
    else {
        details << L"Windows Update service: could not be queried\n";
    }

    std::wstring lastInstall = RegReadString(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install", L"LastSuccessTime");
    details << L"Last successful install (legacy key): " << (lastInstall.empty() ? L"not recorded" : lastInstall) << L"\n";

    // Newer builds record update history in WMI-visible hotfix data.
    WmiResult hotfix = WmiQuery(L"ROOT\\CIMV2", L"SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering", { L"HotFixID", L"InstalledOn" });
    if (hotfix.ok && !hotfix.rows.empty()) {
        std::wstring newest;
        long long newestKey = 0;
        for (const WmiRow& row : hotfix.rows) {
            auto it = row.find(L"InstalledOn");
            if (it == row.end()) continue;
            // InstalledOn is M/D/YYYY
            std::vector<std::wstring> parts = SplitW(it->second, L'/');
            if (parts.size() != 3) continue;
            long long key = _wtoi(parts[2].c_str()) * 10000LL + _wtoi(parts[0].c_str()) * 100LL + _wtoi(parts[1].c_str());
            if (key > newestKey) {
                newestKey = key;
                newest = it->second;
            }
        }
        if (newestKey > 0) {
            details << L"Most recent installed update: " << newest << L" (" << hotfix.rows.size() << L" updates listed)\n";
            SYSTEMTIME now;
            GetLocalTime(&now);
            long long nowMonths = now.wYear * 12LL + now.wMonth;
            long long thenMonths = (newestKey / 10000) * 12 + (newestKey / 100) % 100;
            if (nowMonths - thenMonths >= 3) {
                if (result.status == CHECK_PASS) result.status = CHECK_WARNING;
                details << L"  No update has installed for " << (nowMonths - thenMonths) << L" months.\n";
            }
        }
    }

    DWORD noAuto = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", L"NoAutoUpdate", noAuto) && noAuto == 1) {
        result.status = CHECK_FAIL;
        details << L"Automatic updates: DISABLED by policy\n";
    }
    else {
        details << L"Automatic updates: not disabled by policy\n";
    }

    std::wstring wsus = RegReadString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", L"WUServer");
    details << L"Update source: " << (wsus.empty() ? L"Windows Update (Microsoft)" : L"WSUS server " + wsus) << L"\n";

    if (RegKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired")) {
        details << L"Pending reboot: YES (updates are waiting for a restart)\n";
        if (result.status == CHECK_PASS) result.status = CHECK_WARNING;
    }
    else {
        details << L"Pending reboot: No\n";
    }

    result.detail = details.str();
    return result;
}
