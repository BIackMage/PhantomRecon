#include "pch.h"
#include "PlatformRules.h"

#include "SecurityChecks.h"
#include "TextUtils.h"

#include <algorithm>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[PlatformRules] " + msg + L"\n").c_str());
}

// ---------------------------------------------------------------------------
// Memory integrity
// ---------------------------------------------------------------------------
std::wstring HvciStatus(const HvciFacts& facts, std::wstring* text)
{
    bool configured = (facts.registryEnabled.set && facts.registryEnabled.value == 1) || facts.wmiConfigured;
    std::wstring status;
    std::wstring t;
    if (facts.wmiOk && facts.wmiRunning) {
        status = CHECK_PASS;
        t = L"Memory integrity is running (Device Guard reports it).";
    }
    else if (configured && facts.wmiOk) {
        status = CHECK_WARNING;
        t = L"Memory integrity is turned on but not running. Either a restart is pending, or Windows found an incompatible "
            L"driver and left it off (Windows Security > Device security > Core isolation details lists such drivers).";
    }
    else if (configured) {
        status = CHECK_WARNING;
        t = L"Memory integrity is turned on in the registry, but Device Guard did not answer, so it cannot be confirmed "
            L"that it is running.";
    }
    else {
        status = CHECK_WARNING;
        t = facts.wmiOk ? L"Memory integrity is off."
                        : L"Memory integrity is not turned on in the registry, and Device Guard did not answer.";
    }
    if (text) *text = t;
    DebugLog(L"HVCI registry " + (facts.registryEnabled.set ? std::to_wstring(facts.registryEnabled.value) : std::wstring(L"not set")) +
             L", WMI " + (facts.wmiOk ? L"answered" : L"unavailable") + L", configured " + std::to_wstring(facts.wmiConfigured) +
             L", running " + std::to_wstring(facts.wmiRunning) + L" -> " + status);
    return status;
}

// ---------------------------------------------------------------------------
// Vulnerable driver block list
// ---------------------------------------------------------------------------
std::wstring DriverBlocklistStatus(const DriverBlocklistFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    bool defaultOn = !facts.isServer && facts.build >= kWindows11_22H2Build;
    if (!facts.keyReadable) {
        status = CHECK_NA;
        t = L"The code integrity settings (HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config) could not be read. "
            L"Run as administrator to read them.";
    }
    else if (facts.enabled.set && facts.enabled.value == 1) {
        status = CHECK_PASS;
        t = L"The Microsoft vulnerable driver block list is on (VulnerableDriverBlocklistEnable=1).";
    }
    else if (facts.enabled.set && facts.enabled.value == 0) {
        status = CHECK_WARNING;
        t = L"The Microsoft vulnerable driver block list is turned off (VulnerableDriverBlocklistEnable=0).";
        if (facts.hvciRunning) {
            t += L" Memory integrity is running, which also applies the list on recent Windows builds, but this check does "
                 L"not count on that while the switch itself is off.";
        }
    }
    else if (facts.enabled.set) {
        status = CHECK_WARNING;
        t = L"VulnerableDriverBlocklistEnable has an unexpected value (" + std::to_wstring(facts.enabled.value) +
            L"), so it is not known whether the block list is on.";
    }
    else if (defaultOn) {
        status = CHECK_PASS;
        t = L"The block list is not configured, so the Windows 11 22H2 and later default applies: on (build " +
            std::to_wstring(facts.build) + L").";
    }
    else if (facts.hvciRunning) {
        status = CHECK_PASS;
        t = L"The block list is not configured, and memory integrity is running, which applies it.";
    }
    else if (facts.smartAppControlOn) {
        status = CHECK_PASS;
        t = L"The block list is not configured, and Smart App Control is on, which applies it.";
    }
    else {
        status = CHECK_WARNING;
        t = L"The block list is not configured. On this Windows (build " + std::to_wstring(facts.build) +
            (facts.isServer ? L", Server" : L"") +
            L") it is only applied when memory integrity, Smart App Control or S mode is on, and neither memory integrity "
            L"nor Smart App Control is.";
    }
    if (text) *text = t;
    DebugLog(L"Driver block list " + (facts.enabled.set ? std::to_wstring(facts.enabled.value) : std::wstring(L"not set")) +
             L", build " + std::to_wstring(facts.build) + L", server " + std::to_wstring(facts.isServer) + L", HVCI " +
             std::to_wstring(facts.hvciRunning) + L", SAC " + std::to_wstring(facts.smartAppControlOn) + L" -> " + status);
    return status;
}

// ---------------------------------------------------------------------------
// Smart App Control
// ---------------------------------------------------------------------------
std::wstring SmartAppControlStatus(const SmartAppControlFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    if (facts.isServer) {
        status = CHECK_NA;
        t = L"Windows Server has no Smart App Control.";
    }
    else if (facts.build < kWindows11Build) {
        status = CHECK_NA;
        t = L"Smart App Control is a Windows 11 feature; this PC runs Windows 10 (build " + std::to_wstring(facts.build) + L").";
    }
    else if (facts.build < kWindows11_22H2Build) {
        status = CHECK_NA;
        t = L"Smart App Control came with Windows 11 22H2; this build (" + std::to_wstring(facts.build) + L") does not have it.";
    }
    else if (!facts.keyReadable) {
        status = CHECK_NA;
        t = L"The Smart App Control state (HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy) could not be read. "
            L"Run as administrator to read it.";
    }
    else if (!facts.state.set) {
        status = CHECK_NA;
        t = L"Windows has not recorded a Smart App Control state on this PC (VerifiedAndReputablePolicyState is missing), "
            L"so it cannot be judged.";
    }
    else if (facts.state.value == 1) {
        status = CHECK_PASS;
        t = L"Smart App Control is on.";
    }
    else if (facts.state.value == 2) {
        // Evaluation is the state a new install starts in. Nothing is misconfigured:
        // Windows watches how the PC is used and switches it on or off by itself.
        status = CHECK_PASS;
        t = L"Smart App Control is in evaluation mode: it watches without blocking, and Windows will turn it on or off by "
            L"itself. It does not protect yet; you can choose On now in Windows Security.";
    }
    else if (facts.state.value == 0) {
        status = CHECK_WARNING;
        t = L"Smart App Control is off. Windows can only turn it back on after a reset or a clean install.";
    }
    else {
        status = CHECK_WARNING;
        t = L"Smart App Control reports an unknown state (" + std::to_wstring(facts.state.value) + L").";
    }
    if (text) *text = t;
    DebugLog(L"Smart App Control state " + (facts.state.set ? std::to_wstring(facts.state.value) : std::wstring(L"not set")) +
             L", build " + std::to_wstring(facts.build) + L" -> " + status);
    return status;
}

// ---------------------------------------------------------------------------
// System exploit protection
// ---------------------------------------------------------------------------

// The fields read here, as documented in winnt.h. The asserts tie the shifts to the
// SDK's own masks, so a wrong shift cannot compile.
static const int kBottomUpAslrShift = 16;
static const int kHighEntropyAslrShift = 20;
static const int kControlFlowGuardShift = 40;
static_assert(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_MASK == (0x3ull << kBottomUpAslrShift), "bottom-up ASLR field");
static_assert(PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_MASK == (0x3ull << kHighEntropyAslrShift), "high-entropy ASLR field");
static_assert(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_MASK == (0x3ull << kControlFlowGuardShift), "CFG field");
static_assert(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF == (0x2ull << kBottomUpAslrShift), "always off is 2");

int MitigationField(unsigned long long options, int shift)
{
    if (shift < 0 || shift > 62) return 0;
    return static_cast<int>((options >> shift) & 0x3ull);
}

static const wchar_t* MitigationFieldText(int field)
{
    switch (field) {
    case 0:  return L"Windows default (on)";
    case 1:  return L"on";
    case 2:  return L"OFF";
    default: return L"reserved value, not judged";
    }
}

std::wstring ExploitProtectionStatus(const ExploitProtectionFacts& facts, std::vector<std::wstring>* lines)
{
    std::vector<std::wstring> l;
    bool fail = false;
    bool warn = false;

    switch (facts.depPolicy) {
    case 0:
        l.push_back(L"Data Execution Prevention (system policy): AlwaysOff. No program is protected.");
        fail = true;
        break;
    case 1:
        l.push_back(L"Data Execution Prevention (system policy): AlwaysOn.");
        break;
    case 2:
        l.push_back(L"Data Execution Prevention (system policy): OptIn (Windows system programs and programs that ask for it; "
                    L"the Windows client default).");
        break;
    case 3:
        l.push_back(L"Data Execution Prevention (system policy): OptOut (every program unless excluded).");
        break;
    default:
        l.push_back(L"Data Execution Prevention (system policy): could not be read (" + std::to_wstring(facts.depPolicy) + L").");
        warn = true;
        break;
    }

    if (facts.sehopDisabled.set && facts.sehopDisabled.value == 1) {
        l.push_back(L"SEHOP (validate exception chains): OFF (DisableExceptionChainValidation=1).");
        warn = true;
    }
    else if (facts.sehopDisabled.set && facts.sehopDisabled.value == 0) {
        l.push_back(L"SEHOP (validate exception chains): on (DisableExceptionChainValidation=0).");
    }
    else if (facts.sehopDisabled.set) {
        l.push_back(L"SEHOP (validate exception chains): DisableExceptionChainValidation=" +
                    std::to_wstring(facts.sehopDisabled.value) + L", not judged.");
    }
    else {
        l.push_back(L"SEHOP (validate exception chains): not configured, Windows default (on in Windows 10 and 11).");
    }

    if (!facts.mitigationsSet) {
        l.push_back(L"System mitigation settings (MitigationOptions): not set, so bottom-up ASLR, high-entropy ASLR and CFG "
                    L"use the Windows default (on).");
    }
    else {
        struct Field { const wchar_t* name; int shift; };
        const Field fields[] = {
            { L"Bottom-up ASLR (randomize memory allocations)", kBottomUpAslrShift },
            { L"High-entropy ASLR", kHighEntropyAslrShift },
            { L"Control Flow Guard (CFG)", kControlFlowGuardShift },
        };
        for (const Field& f : fields) {
            int value = MitigationField(facts.mitigationOptions, f.shift);
            l.push_back(std::wstring(f.name) + L": " + MitigationFieldText(value) + L".");
            if (value == 2) warn = true;
        }
    }

    std::wstring status = fail ? CHECK_FAIL : warn ? CHECK_WARNING : CHECK_PASS;
    if (lines) *lines = l;
    wchar_t hex[32];
    swprintf_s(hex, L"0x%016llX", facts.mitigationOptions);
    DebugLog(L"Exploit protection: DEP " + std::to_wstring(facts.depPolicy) + L", SEHOP disabled " +
             (facts.sehopDisabled.set ? std::to_wstring(facts.sehopDisabled.value) : std::wstring(L"not set")) +
             L", MitigationOptions " + (facts.mitigationsSet ? std::wstring(hex) : std::wstring(L"not set")) + L" -> " + status);
    return status;
}

// ---------------------------------------------------------------------------
// Screen lock
// ---------------------------------------------------------------------------
ScreenSaverValues EffectiveScreenSaver(const ScreenLockFacts& facts)
{
    auto pick = [](const std::wstring& policy, const std::wstring& user) {
        std::wstring p = TrimW(policy);
        return p.empty() ? TrimW(user) : p;
    };
    ScreenSaverValues v;
    v.active = pick(facts.policy.active, facts.user.active);
    v.secure = pick(facts.policy.secure, facts.user.secure);
    v.timeout = pick(facts.policy.timeout, facts.user.timeout);
    v.exe = pick(facts.policy.exe, facts.user.exe);
    return v;
}

long ParseScreenSaverSeconds(const std::wstring& textIn)
{
    std::wstring text = TrimW(textIn);
    if (text.empty() || text.size() > 9) return -1;
    for (wchar_t c : text) {
        if (c < L'0' || c > L'9') return -1;
    }
    return _wtol(text.c_str());
}

static const long kMaxLockSeconds = 900;

std::wstring ScreenLockStatus(const ScreenLockFacts& facts, std::vector<std::wstring>* lines)
{
    std::vector<std::wstring> l;
    bool inactivityOk = facts.inactivitySecs.set && facts.inactivitySecs.value >= 1 &&
                        facts.inactivitySecs.value <= static_cast<DWORD>(kMaxLockSeconds);
    if (!facts.inactivitySecs.set) {
        l.push_back(L"Machine inactivity limit (InactivityTimeoutSecs): not set.");
    }
    else if (facts.inactivitySecs.value == 0) {
        l.push_back(L"Machine inactivity limit (InactivityTimeoutSecs): 0, no limit.");
    }
    else {
        l.push_back(L"Machine inactivity limit (InactivityTimeoutSecs): " + std::to_wstring(facts.inactivitySecs.value) +
                    L" seconds" + (inactivityOk ? L"." : L", more than 15 minutes."));
    }

    ScreenSaverValues v = EffectiveScreenSaver(facts);
    auto source = [](const std::wstring& policy) { return TrimW(policy).empty() ? L"" : L" (Group Policy)"; };
    long seconds = ParseScreenSaverSeconds(v.timeout);
    bool active = v.active == L"1";
    bool secure = v.secure == L"1";
    bool chosen = !v.exe.empty();
    bool timeoutOk = seconds >= 1 && seconds <= kMaxLockSeconds;
    bool saverOk = active && secure && chosen && timeoutOk;

    l.push_back(std::wstring(L"Screen saver for this user: ") + (active ? L"on" : L"off") + source(facts.policy.active) +
                L", screen saver " + (chosen ? L"\"" + v.exe + L"\"" : std::wstring(L"none chosen")) + source(facts.policy.exe) +
                L", wait " + (seconds >= 0 ? std::to_wstring(seconds) + L" seconds" : std::wstring(L"not set")) +
                source(facts.policy.timeout) + L", password on resume " + (secure ? L"yes" : L"no") + source(facts.policy.secure) + L".");

    std::wstring status = (inactivityOk || saverOk) ? CHECK_PASS : CHECK_WARNING;
    if (lines) *lines = l;
    DebugLog(L"Screen lock: inactivity " + std::to_wstring(inactivityOk) + L", screen saver active " + std::to_wstring(active) +
             L", secure " + std::to_wstring(secure) + L", chosen " + std::to_wstring(chosen) + L", seconds " +
             std::to_wstring(seconds) + L" -> " + status);
    return status;
}

// ---------------------------------------------------------------------------
// System Restore
// ---------------------------------------------------------------------------
static std::wstring VolumeGuidPart(const std::wstring& path)
{
    std::wstring lower = ToLowerW(path);
    size_t start = lower.find(L"volume{");
    if (start == std::wstring::npos) return L"";
    size_t end = lower.find(L'}', start);
    if (end == std::wstring::npos) return L"";
    return lower.substr(start, end - start + 1);
}

bool RestoreListCoversVolume(const std::vector<std::wstring>& entries, const std::wstring& volumeGuidPath,
                             const std::wstring& driveLetter)
{
    std::wstring guid = VolumeGuidPart(volumeGuidPath);
    std::wstring letter = ToLowerW(TrimW(driveLetter));
    if (!letter.empty() && letter.back() == L'\\') letter.pop_back();
    if (!letter.empty() && letter.back() == L':') letter.pop_back();
    std::wstring letterTag = letter.size() == 1 ? L"(" + letter + L"%3a)" : L"";
    for (const std::wstring& entry : entries) {
        std::wstring lower = ToLowerW(entry);
        if (!guid.empty() && VolumeGuidPart(lower) == guid) return true;
        if (!letterTag.empty() && lower.find(letterTag) != std::wstring::npos) return true;
    }
    return false;
}

std::wstring SystemRestoreStatus(const SystemRestoreFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    std::wstring drive = facts.systemDrive.empty() ? std::wstring(L"the system drive") : facts.systemDrive;
    std::wstring hint;
    if (facts.sessionInterval.set) {
        hint = L" (RPSessionInterval=" + std::to_wstring(facts.sessionInterval.value) +
               (facts.sessionInterval.value == 1 ? L", which usually means at least one drive is protected)"
                                                 : L", which usually means no drive is protected)");
    }
    if (facts.isServer) {
        status = CHECK_NA;
        t = L"Windows Server has no System Restore.";
    }
    else if (facts.policyDisable.set && facts.policyDisable.value == 1) {
        status = CHECK_WARNING;
        t = L"System Restore is turned off by Group Policy (Turn off System Restore, DisableSR=1).";
    }
    else if (facts.legacyDisable.set && facts.legacyDisable.value == 1) {
        status = CHECK_WARNING;
        t = L"System Restore is turned off (DisableSR=1).";
    }
    else if (!facts.clientsReadable) {
        status = CHECK_NA;
        t = L"Which drives System Restore protects can only be read as administrator. Run as administrator to check " +
            drive + L"." + (hint.empty() ? L"" : L" Readable hint" + hint + L".");
    }
    else if (facts.clientsValueSet && RestoreListCoversVolume(facts.protectedVolumes, facts.systemVolume, facts.systemDrive)) {
        status = CHECK_PASS;
        t = L"System Restore protects " + drive + L".";
    }
    else if (facts.clientsValueSet) {
        status = CHECK_WARNING;
        t = L"System Restore is not on for " + drive + L" (" + std::to_wstring(facts.protectedVolumes.size()) +
            L" other volume(s) protected).";
    }
    else if (facts.sessionInterval.set && facts.sessionInterval.value == 1) {
        // The global switch says on but the per-drive list is missing: the two
        // sources disagree, so do not guess.
        status = CHECK_NA;
        t = L"System Restore reports itself on" + hint + L", but no drive list was found, so whether it protects " + drive +
            L" cannot be told.";
    }
    else {
        status = CHECK_WARNING;
        t = L"System Restore is not set up for any drive" + hint + L".";
    }
    if (text) *text = t;
    DebugLog(L"System Restore: readable " + std::to_wstring(facts.clientsReadable) + L", list " +
             std::to_wstring(facts.clientsValueSet) + L" with " + std::to_wstring(facts.protectedVolumes.size()) +
             L" entries -> " + status);
    return status;
}

// ---------------------------------------------------------------------------
// Open Wi-Fi networks
// ---------------------------------------------------------------------------

// Text of the first <tag>...</tag> at or after from, before limit. Lowercase, trimmed.
static bool ElementText(const std::wstring& xml, const std::wstring& tag, size_t from, size_t limit, std::wstring& out)
{
    std::wstring open = L"<" + tag + L">";
    std::wstring close = L"</" + tag + L">";
    size_t start = xml.find(open, from);
    if (start == std::wstring::npos || start >= limit) return false;
    start += open.size();
    size_t end = xml.find(close, start);
    if (end == std::wstring::npos || end > limit) return false;
    std::wstring value = TrimW(xml.substr(start, end - start));
    // Element text in this schema is a short keyword; anything else is not trusted.
    if (value.size() > 32 || value.find(L'<') != std::wstring::npos) return false;
    out = ToLowerW(value);
    return true;
}

WlanProfileSummary ParseWlanProfileXml(const std::wstring& xml)
{
    WlanProfileSummary s;
    size_t block = xml.find(L"<authEncryption>");
    if (block != std::wstring::npos) {
        size_t blockEnd = xml.find(L"</authEncryption>", block);
        if (blockEnd == std::wstring::npos) blockEnd = xml.size();
        std::wstring auth;
        if (ElementText(xml, L"authentication", block, blockEnd, auth)) {
            s.authentication = auth;
            s.parsed = true;
        }
        std::wstring enc;
        if (ElementText(xml, L"encryption", block, blockEnd, enc)) s.encryption = enc;
    }
    std::wstring mode;
    if (ElementText(xml, L"connectionMode", 0, xml.size(), mode)) {
        s.connectionMode = mode;
    }
    else {
        // The schema makes the element optional; Windows connects on its own then.
        s.connectionMode = L"auto";
        s.connectionModeMissing = true;
    }
    DebugLog(L"WLAN profile: parsed " + std::to_wstring(s.parsed) + L", authentication " + s.authentication +
             L", encryption " + s.encryption + L", connection " + s.connectionMode);
    return s;
}

bool IsOpenAutoConnectProfile(const WlanProfileSummary& profile)
{
    if (!profile.parsed) return false;
    // Open authentication with WEP still has a key; only "none" is a network without one.
    bool open = profile.authentication == L"open" && (profile.encryption == L"none" || profile.encryption.empty());
    return open && profile.connectionMode != L"manual";
}

std::wstring OpenWifiStatus(const WifiFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    if (!facts.serviceInstalled) {
        status = CHECK_NA;
        t = L"This PC has no WLAN AutoConfig service, so it has no Wi-Fi.";
    }
    else if (!facts.apiAvailable) {
        status = CHECK_NA;
        t = L"The Wi-Fi programming interface (wlanapi.dll) is not available on this PC.";
    }
    else if (!facts.serviceRunning) {
        status = CHECK_NA;
        t = L"The WLAN AutoConfig service is not running, so Wi-Fi is not in use.";
    }
    else if (facts.interfaces <= 0) {
        status = CHECK_NA;
        t = L"This PC has no Wi-Fi adapter.";
    }
    else if (!facts.openAutoProfiles.empty()) {
        status = CHECK_WARNING;
        t = std::to_wstring(facts.openAutoProfiles.size()) +
            L" saved Wi-Fi network(s) without a password connect automatically.";
    }
    else if (facts.profilesRead == 0 && facts.profilesUnreadable > 0) {
        status = CHECK_WARNING;
        t = L"None of the " + std::to_wstring(facts.profilesUnreadable) + L" saved Wi-Fi network(s) could be read.";
    }
    else {
        status = CHECK_PASS;
        t = L"No saved Wi-Fi network without a password connects automatically (" + std::to_wstring(facts.profilesRead) +
            L" network(s) checked).";
        if (facts.profilesUnreadable > 0) t += L" " + std::to_wstring(facts.profilesUnreadable) + L" could not be read.";
    }
    if (text) *text = t;
    DebugLog(L"Wi-Fi: interfaces " + std::to_wstring(facts.interfaces) + L", read " + std::to_wstring(facts.profilesRead) +
             L", unreadable " + std::to_wstring(facts.profilesUnreadable) + L", open auto " +
             std::to_wstring(facts.openAutoProfiles.size()) + L" -> " + status);
    return status;
}
