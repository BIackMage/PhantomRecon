#include "pch.h"
#include "SecurityCheckModules.h"

#include "RegUtil.h"
#include "SystemInfo.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <windows.h>
#include <mutex>
#include <sstream>

// ---------------------------------------------------------------------------
// One read of Defender's state, shared by every Defender check in an audit.
// Cached for 60 seconds (process-wide singleton, see CLAUDE.md).
// ---------------------------------------------------------------------------
struct DefenderSnapshot {
    bool         statusOk = false;      // MSFT_MpComputerStatus answered
    bool         prefsOk = false;       // MSFT_MpPreference answered
    std::wstring error;
    WmiRow       status;
    WmiRow       prefs;
    std::vector<std::wstring> otherAntivirus;   // from Security Center
    bool         defenderPassive = false;
};

struct DefenderCache {
    std::mutex       mutex;
    ULONGLONG        takenAt = 0;
    DefenderSnapshot snapshot;
};

static DefenderSnapshot ReadDefender()
{
    DefenderSnapshot s;
    WmiResult status = WmiQuery(L"ROOT\\Microsoft\\Windows\\Defender",
        L"SELECT * FROM MSFT_MpComputerStatus",
        { L"AMServiceEnabled", L"AntivirusEnabled", L"RealTimeProtectionEnabled", L"BehaviorMonitorEnabled",
          L"IoavProtectionEnabled", L"OnAccessProtectionEnabled", L"IsTamperProtected", L"AntivirusSignatureAge",
          L"AntivirusSignatureLastUpdated", L"AMRunningMode", L"AntivirusSignatureVersion" });
    if (status.ok && !status.rows.empty()) {
        s.statusOk = true;
        s.status = status.rows[0];
        std::wstring mode = s.status[L"AMRunningMode"];
        s.defenderPassive = ContainsI(mode, L"Passive") || ContainsI(mode, L"EDR Block");
    }
    else {
        s.error = status.error;
    }

    WmiResult prefs = WmiQuery(L"ROOT\\Microsoft\\Windows\\Defender",
        L"SELECT * FROM MSFT_MpPreference",
        { L"ExclusionPath", L"ExclusionExtension", L"ExclusionProcess", L"ExclusionIpAddress", L"MAPSReporting",
          L"SubmitSamplesConsent", L"EnableControlledFolderAccess", L"AttackSurfaceReductionRules_Ids",
          L"AttackSurfaceReductionRules_Actions", L"PUAProtection", L"DisableRealtimeMonitoring" });
    if (prefs.ok && !prefs.rows.empty()) {
        s.prefsOk = true;
        s.prefs = prefs.rows[0];
    }

    WmiResult av = WmiQuery(L"ROOT\\SecurityCenter2", L"SELECT displayName, productState FROM AntiVirusProduct",
        { L"displayName", L"productState" });
    if (av.ok) {
        for (const WmiRow& row : av.rows) {
            auto it = row.find(L"displayName");
            if (it == row.end()) continue;
            if (ContainsI(it->second, L"Windows Defender") || ContainsI(it->second, L"Microsoft Defender")) continue;
            // productState bits 12-15: 0x1 = on. Only list products that are switched on.
            auto st = row.find(L"productState");
            unsigned long state = st != row.end() ? std::wcstoul(st->second.c_str(), nullptr, 10) : 0;
            bool on = ((state >> 12) & 0xF) == 0x1;
            s.otherAntivirus.push_back(it->second + (on ? L" (on)" : L" (off)"));
        }
    }
    return s;
}

static DefenderSnapshot GetDefender()
{
    static DefenderCache cache;
    std::lock_guard<std::mutex> lock(cache.mutex);
    ULONGLONG now = GetTickCount64();
    if (cache.takenAt == 0 || now - cache.takenAt > 60000) {
        cache.snapshot = ReadDefender();
        cache.takenAt = now;
    }
    return cache.snapshot;
}

static bool IsTrue(const WmiRow& row, const wchar_t* key)
{
    auto it = row.find(key);
    return it != row.end() && (EqualsI(it->second, L"True") || it->second == L"1");
}

static bool HasValue(const WmiRow& row, const wchar_t* key)
{
    auto it = row.find(key);
    return it != row.end() && !it->second.empty();
}

static std::wstring Value(const WmiRow& row, const wchar_t* key)
{
    auto it = row.find(key);
    return it == row.end() ? L"" : it->second;
}

static bool OtherAvActive(const DefenderSnapshot& d)
{
    for (const std::wstring& av : d.otherAntivirus) {
        if (EndsWithI(av, L"(on)")) return true;
    }
    return false;
}

// When another antivirus product is active, Defender checks report on that
// product's presence instead of failing.
static bool ReportThirdParty(SecurityCheckResult& result, const DefenderSnapshot& d)
{
    if ((!d.statusOk || d.defenderPassive) && OtherAvActive(d)) {
        result.status = CHECK_NA;
        result.detail = L"Microsoft Defender is not the active antivirus. Active product(s): " + JoinW(d.otherAntivirus, L", ") +
            L". Check the same setting in that product.";
        return true;
    }
    return false;
}

static bool ReportUnavailable(SecurityCheckResult& result, const DefenderSnapshot& d)
{
    if (!d.statusOk) {
        result.status = CHECK_ERROR;
        result.detail = L"Microsoft Defender status could not be read: " + d.error;
        if (!d.otherAntivirus.empty()) result.detail += L" Security Center lists: " + JoinW(d.otherAntivirus, L", ");
        return true;
    }
    return false;
}

SecurityCheckResult CheckDefenderRealtime()
{
    SecurityCheckResult result = MakeCheckResult(L"def.realtime");
    DefenderSnapshot d = GetDefender();
    if (ReportThirdParty(result, d)) {
        result.status = CHECK_PASS;   // another product is on: real-time protection is present
        return result;
    }
    if (ReportUnavailable(result, d)) {
        if (d.otherAntivirus.empty()) result.status = CHECK_FAIL;
        return result;
    }
    std::wstringstream details;
    details << L"Antivirus enabled: " << (IsTrue(d.status, L"AntivirusEnabled") ? L"Yes" : L"No") << L"\n";
    details << L"Real-time protection: " << (IsTrue(d.status, L"RealTimeProtectionEnabled") ? L"On" : L"OFF") << L"\n";
    details << L"Behavior monitoring: " << (IsTrue(d.status, L"BehaviorMonitorEnabled") ? L"On" : L"Off") << L"\n";
    details << L"Download scanning (IOAV): " << (IsTrue(d.status, L"IoavProtectionEnabled") ? L"On" : L"Off") << L"\n";
    details << L"Running mode: " << Value(d.status, L"AMRunningMode") << L"\n";

    bool ok = IsTrue(d.status, L"AntivirusEnabled") && IsTrue(d.status, L"RealTimeProtectionEnabled");
    result.status = ok ? CHECK_PASS : CHECK_FAIL;
    result.detail = (ok ? L"Real-time protection is on.\n" : L"Real-time protection is OFF.\n") + details.str();
    return result;
}

SecurityCheckResult CheckDefenderTamper()
{
    SecurityCheckResult result = MakeCheckResult(L"def.tamper");
    DefenderSnapshot d = GetDefender();
    if (ReportThirdParty(result, d)) return result;
    if (ReportUnavailable(result, d)) return result;

    if (HasValue(d.status, L"IsTamperProtected")) {
        bool on = IsTrue(d.status, L"IsTamperProtected");
        result.status = on ? CHECK_PASS : CHECK_FAIL;
        result.detail = on ? L"Tamper Protection is on." : L"Tamper Protection is OFF.";
        return result;
    }
    DWORD value = 0;
    if (RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Features", L"TamperProtection", value)) {
        bool on = (value & 0x1) != 0 && value != 4;
        result.status = on ? CHECK_PASS : CHECK_FAIL;
        result.detail = std::wstring(on ? L"Tamper Protection is on" : L"Tamper Protection is OFF") +
            L" (registry TamperProtection=" + std::to_wstring(value) + L").";
        return result;
    }
    result.status = CHECK_WARNING;
    result.detail = L"Tamper Protection state could not be determined.";
    return result;
}

SecurityCheckResult CheckDefenderCloud()
{
    SecurityCheckResult result = MakeCheckResult(L"def.cloud");
    DefenderSnapshot d = GetDefender();
    if (ReportThirdParty(result, d)) return result;
    if (ReportUnavailable(result, d)) return result;
    if (!d.prefsOk) {
        result.status = CHECK_ERROR;
        result.detail = L"Defender preferences could not be read.";
        return result;
    }
    int maps = _wtoi(Value(d.prefs, L"MAPSReporting").c_str());
    int submit = _wtoi(Value(d.prefs, L"SubmitSamplesConsent").c_str());
    const wchar_t* mapsText = maps == 0 ? L"Off" : maps == 1 ? L"Basic" : L"Advanced";
    const wchar_t* submitText = submit == 0 ? L"Always prompt" : submit == 1 ? L"Send safe samples" :
                                submit == 2 ? L"Never send" : L"Send all samples";
    result.detail = std::wstring(L"Cloud protection (MAPS): ") + mapsText + L"\nAutomatic sample submission: " + submitText;
    if (maps == 0) {
        result.status = CHECK_FAIL;
        result.detail = L"Cloud-delivered protection is OFF.\n" + result.detail;
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"Cloud-delivered protection is on.\n" + result.detail;
    }
    return result;
}

SecurityCheckResult CheckDefenderSignatures()
{
    SecurityCheckResult result = MakeCheckResult(L"def.signatures");
    DefenderSnapshot d = GetDefender();
    if (ReportThirdParty(result, d)) return result;
    if (ReportUnavailable(result, d)) return result;

    std::wstring ageText = Value(d.status, L"AntivirusSignatureAge");
    int age = _wtoi(ageText.c_str());
    result.detail = L"Definitions version " + Value(d.status, L"AntivirusSignatureVersion") + L", " +
        std::to_wstring(age) + L" day(s) old.";
    if (age > 7) result.status = CHECK_FAIL;
    else if (age > 2) result.status = CHECK_WARNING;
    else result.status = CHECK_PASS;
    return result;
}

SecurityCheckResult CheckDefenderExclusions()
{
    SecurityCheckResult result = MakeCheckResult(L"def.exclusions");
    DefenderSnapshot d = GetDefender();
    if (ReportThirdParty(result, d)) return result;
    if (ReportUnavailable(result, d)) return result;
    if (!d.prefsOk) {
        result.status = CHECK_ERROR;
        result.detail = L"Defender preferences could not be read.";
        return result;
    }

    std::wstringstream details;
    int count = 0;
    bool hidden = false;
    struct Kind { const wchar_t* key; const wchar_t* label; };
    const Kind kinds[] = {
        { L"ExclusionPath", L"Path" }, { L"ExclusionExtension", L"Extension" },
        { L"ExclusionProcess", L"Process" }, { L"ExclusionIpAddress", L"IP address" },
    };
    for (const Kind& k : kinds) {
        for (const std::wstring& v : SplitW(Value(d.prefs, k.key), L'\n')) {
            if (v.empty()) continue;
            if (ContainsI(v, L"Must be an administrator")) {
                hidden = true;
                continue;
            }
            count++;
            details << L"  " << k.label << L": " << v << L"\n";
        }
    }

    if (hidden && count == 0) {
        result.status = IsProcessElevated() ? CHECK_WARNING : CHECK_INFO;
        result.detail = L"Windows only shows Defender exclusions to administrators. Run Phantom Recon as administrator to check them.";
        return result;
    }
    if (count > 0) {
        result.status = CHECK_WARNING;
        result.detail = std::to_wstring(count) + L" exclusion(s) configured. Make sure you added each one on purpose:\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"No antivirus exclusions are configured.";
    }
    return result;
}

SecurityCheckResult CheckDefenderAsr()
{
    SecurityCheckResult result = MakeCheckResult(L"def.asr");
    DefenderSnapshot d = GetDefender();
    if (ReportThirdParty(result, d)) return result;
    if (ReportUnavailable(result, d)) return result;
    if (!d.prefsOk) {
        result.status = CHECK_ERROR;
        result.detail = L"Defender preferences could not be read.";
        return result;
    }

    std::vector<std::wstring> ids = SplitW(Value(d.prefs, L"AttackSurfaceReductionRules_Ids"), L'\n');
    std::vector<std::wstring> actions = SplitW(Value(d.prefs, L"AttackSurfaceReductionRules_Actions"), L'\n');
    int blocking = 0, auditing = 0, warning = 0;
    std::wstringstream details;
    for (size_t i = 0; i < ids.size(); ++i) {
        int action = i < actions.size() ? _wtoi(actions[i].c_str()) : 0;
        const wchar_t* label = action == 1 ? L"Block" : action == 2 ? L"Audit" : action == 6 ? L"Warn" : L"Off";
        if (action == 1) blocking++;
        else if (action == 2) auditing++;
        else if (action == 6) warning++;
        details << L"  " << ids[i] << L": " << label << L"\n";
    }

    if (blocking + warning > 0) {
        result.status = CHECK_PASS;
        result.detail = std::to_wstring(blocking) + L" rule(s) blocking, " + std::to_wstring(warning) + L" warning, " +
            std::to_wstring(auditing) + L" auditing.\n" + details.str();
    }
    else if (auditing > 0) {
        result.status = CHECK_WARNING;
        result.detail = L"Attack Surface Reduction rules are only auditing (" + std::to_wstring(auditing) + L"), none block.\n" + details.str();
    }
    else {
        result.status = CHECK_WARNING;
        result.detail = L"No Attack Surface Reduction rules are switched on.";
    }
    return result;
}

SecurityCheckResult CheckSmartScreen()
{
    SecurityCheckResult result = MakeCheckResult(L"def.smartscreen");
    DWORD policy = 1;
    bool policySet = RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"EnableSmartScreen", policy);
    std::wstring explorer = RegReadString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", L"SmartScreenEnabled");

    if (policySet && policy == 0) {
        result.status = CHECK_FAIL;
        result.detail = L"SmartScreen is turned off by Group Policy (EnableSmartScreen=0).";
    }
    else if (EqualsI(explorer, L"Off")) {
        result.status = CHECK_FAIL;
        result.detail = L"SmartScreen for apps and files is Off.";
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"SmartScreen for apps and files is on" +
            (explorer.empty() ? std::wstring(L" (Windows default).") : L" (" + explorer + L").");
    }
    return result;
}

SecurityCheckResult CheckControlledFolderAccess()
{
    SecurityCheckResult result = MakeCheckResult(L"def.cfa");
    DefenderSnapshot d = GetDefender();
    if (ReportThirdParty(result, d)) return result;
    if (ReportUnavailable(result, d)) return result;
    if (!d.prefsOk) {
        result.status = CHECK_ERROR;
        result.detail = L"Defender preferences could not be read.";
        return result;
    }
    int cfa = _wtoi(Value(d.prefs, L"EnableControlledFolderAccess").c_str());
    if (cfa == 1) {
        result.status = CHECK_PASS;
        result.detail = L"Controlled folder access is on.";
    }
    else if (cfa == 2) {
        result.status = CHECK_INFO;
        result.detail = L"Controlled folder access is in audit mode: it records what it would block.";
    }
    else {
        result.status = CHECK_WARNING;
        result.detail = L"Controlled folder access is off.";
    }
    return result;
}
