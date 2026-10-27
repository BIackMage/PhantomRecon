#include "pch.h"
#include "HygieneRules.h"

#include "SecurityChecks.h"
#include "TextUtils.h"

#include <cwctype>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[HygieneRules] " + msg + L"\n").c_str());
}

static std::wstring DwordText(const OptionalDword& v)
{
    return v.set ? std::to_wstring(v.value) : std::wstring(L"not set");
}

static std::wstring HexText(DWORD v)
{
    wchar_t buf[16];
    swprintf_s(buf, L"0x%X", v);
    return buf;
}

// ===========================================================================
// WDigest password caching
// ===========================================================================
std::wstring WDigestStatus(const WDigestFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    if (!facts.keyReadable) {
        status = CHECK_NA;
        t = L"The WDigest settings (HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest) could not be read. "
            L"Run as administrator to read them.";
    }
    else if (facts.useLogonCredential.set && facts.useLogonCredential.value != 0) {
        status = CHECK_FAIL;
        t = L"UseLogonCredential is " + std::to_wstring(facts.useLogonCredential.value) + L": Windows keeps the password of "
            L"everyone who signs in in memory in a readable form. Windows never sets this itself on Windows 8.1 and later; if "
            L"you did not set it on purpose, something else did.";
    }
    else if (facts.useLogonCredential.set) {
        status = CHECK_PASS;
        t = L"UseLogonCredential is 0: WDigest keeps no sign-in passwords in memory.";
    }
    else if (facts.build != 0 && facts.build < kWindows81Build) {
        status = CHECK_FAIL;
        t = L"UseLogonCredential is not set, and on this Windows version (build " + std::to_wstring(facts.build) +
            L", older than Windows 8.1) that means WDigest keeps sign-in passwords in memory. Set it to 0.";
    }
    else {
        status = CHECK_PASS;
        t = L"UseLogonCredential is not set: on Windows 8.1 and later that means WDigest keeps no sign-in passwords in memory.";
    }
    if (text) *text = t;
    DebugLog(L"WDigest: readable " + std::to_wstring(facts.keyReadable) + L", UseLogonCredential " +
             DwordText(facts.useLogonCredential) + L", build " + std::to_wstring(facts.build) + L" -> " + status);
    return status;
}

// ===========================================================================
// Windows Update paused or deferred
// ===========================================================================

// Days since 1970-01-01 for a date in the proleptic Gregorian calendar.
static long long DaysFromCivil(long long y, long long m, long long d)
{
    y -= m <= 2 ? 1 : 0;
    long long era = (y >= 0 ? y : y - 399) / 400;
    long long yoe = y - era * 400;
    long long mp = m > 2 ? m - 3 : m + 9;
    long long doy = (153 * mp + 2) / 5 + d - 1;
    long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static void CivilFromDays(long long z, long long& y, long long& m, long long& d)
{
    z += 719468;
    long long era = (z >= 0 ? z : z - 146096) / 146097;
    long long doe = z - era * 146097;
    long long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    long long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    long long mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y = yoe + era * 400 + (m <= 2 ? 1 : 0);
}

static bool IsLeapYear(long long y)
{
    return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static long long DaysInMonth(long long y, long long m)
{
    static const int days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (m == 2 && IsLeapYear(y)) return 29;
    return days[m - 1];
}

// Reads exactly count digits at pos.
static bool ReadDigits(const std::wstring& s, size_t& pos, size_t count, long long& out)
{
    if (pos + count > s.size()) return false;
    long long v = 0;
    for (size_t i = 0; i < count; ++i) {
        wchar_t c = s[pos + i];
        if (c < L'0' || c > L'9') return false;
        v = v * 10 + (c - L'0');
    }
    pos += count;
    out = v;
    return true;
}

static bool Expect(const std::wstring& s, size_t& pos, wchar_t c)
{
    if (pos >= s.size() || s[pos] != c) return false;
    ++pos;
    return true;
}

bool ParseIso8601Utc(const std::wstring& textIn, long long& unixSeconds)
{
    std::wstring s = TrimW(textIn);
    size_t pos = 0;
    long long y = 0, mo = 0, d = 0, h = 0, mi = 0, sec = 0;
    if (!ReadDigits(s, pos, 4, y) || !Expect(s, pos, L'-') || !ReadDigits(s, pos, 2, mo) || !Expect(s, pos, L'-') ||
        !ReadDigits(s, pos, 2, d)) {
        return false;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > DaysInMonth(y, mo)) return false;
    long long offsetSeconds = 0;
    if (pos < s.size()) {
        if (s[pos] != L'T' && s[pos] != L't' && s[pos] != L' ') return false;
        ++pos;
        if (!ReadDigits(s, pos, 2, h) || !Expect(s, pos, L':') || !ReadDigits(s, pos, 2, mi)) return false;
        if (pos < s.size() && s[pos] == L':') {
            ++pos;
            if (!ReadDigits(s, pos, 2, sec)) return false;
            if (pos < s.size() && (s[pos] == L'.' || s[pos] == L',')) {
                ++pos;
                size_t start = pos;
                while (pos < s.size() && s[pos] >= L'0' && s[pos] <= L'9') ++pos;
                if (pos == start) return false;
            }
        }
        if (h > 23 || mi > 59 || sec > 60) return false;
        if (pos < s.size()) {
            wchar_t zone = s[pos];
            if (zone == L'Z' || zone == L'z') {
                ++pos;
            }
            else if (zone == L'+' || zone == L'-') {
                ++pos;
                long long oh = 0, om = 0;
                if (!ReadDigits(s, pos, 2, oh)) return false;
                if (pos < s.size() && s[pos] == L':') ++pos;
                if (!ReadDigits(s, pos, 2, om)) return false;
                if (oh > 23 || om > 59) return false;
                offsetSeconds = (oh * 3600 + om * 60) * (zone == L'+' ? 1 : -1);
            }
            else {
                return false;
            }
        }
        if (pos != s.size()) return false;
    }
    unixSeconds = DaysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec - offsetSeconds;
    return true;
}

std::wstring FormatUtcDate(long long unixSeconds)
{
    long long days = unixSeconds >= 0 ? unixSeconds / 86400 : -((-unixSeconds + 86399) / 86400);
    long long rest = unixSeconds - days * 86400;
    long long y = 0, m = 0, d = 0;
    CivilFromDays(days, y, m, d);
    wchar_t buf[40];
    swprintf_s(buf, L"%04lld-%02lld-%02lld %02lld:%02lld UTC", y, m, d, rest / 3600, (rest % 3600) / 60);
    return buf;
}

// Whole days from now until then, rounded up (a pause ending in 3 hours is "1 day").
static long long DaysUntil(long long then, long long now)
{
    return then <= now ? 0 : (then - now + 86399) / 86400;
}

struct PauseRead {
    bool      present = false;
    bool      parsed = false;
    long long end = 0;
};

static PauseRead ReadPause(const std::wstring& text, long long addSeconds, const wchar_t* valueName, std::vector<std::wstring>& lines)
{
    PauseRead p;
    if (TrimW(text).empty()) return p;
    p.present = true;
    long long when = 0;
    if (!ParseIso8601Utc(text, when)) {
        lines.push_back(std::wstring(valueName) + L" is \"" + TrimW(text) + L"\", which this check cannot read as a date; it "
                        L"was not judged.");
        return p;
    }
    p.parsed = true;
    p.end = when + addSeconds;
    return p;
}

// The later of two pauses that were read.
static PauseRead Later(const PauseRead& a, const PauseRead& b)
{
    if (!a.parsed) return b.parsed ? b : a;
    if (!b.parsed) return a;
    return a.end >= b.end ? a : b;
}

std::wstring UpdatePauseStatus(const UpdatePauseFacts& facts, std::vector<std::wstring>* lines)
{
    std::vector<std::wstring> l;
    if (!facts.settingsReadable && !facts.policyReadable) {
        l.push_back(L"The Windows Update settings (HKLM\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings and the Windows Update "
                    L"policy key) could not be read. Run as administrator to read them.");
        if (lines) *lines = l;
        DebugLog(L"Update pause: keys unreadable -> N/A");
        return CHECK_NA;
    }
    bool warn = false;
    const long long now = facts.nowUnix;
    const long long policyPause = static_cast<long long>(kPolicyPauseDays) * 86400;

    // Settings > Windows Update > Pause updates writes all three values; the expiry time
    // pauses every update, the two end times one kind each.
    PauseRead expiry = ReadPause(facts.pauseUpdatesExpiry, 0, L"PauseUpdatesExpiryTime", l);
    PauseRead qualityEnd = ReadPause(facts.pauseQualityEnd, 0, L"PauseQualityUpdatesEndTime", l);
    PauseRead featureEnd = ReadPause(facts.pauseFeatureEnd, 0, L"PauseFeatureUpdatesEndTime", l);
    PauseRead quality = Later(expiry, qualityEnd);
    PauseRead feature = Later(expiry, featureEnd);
    if (quality.parsed && quality.end > now) {
        warn = true;
        l.push_back(L"Settings > Windows Update: updates, security updates included, are PAUSED until " + FormatUtcDate(quality.end) +
                    L", " + std::to_wstring(DaysUntil(quality.end, now)) + L" day(s) from now.");
    }
    else if (feature.parsed && feature.end > now) {
        l.push_back(L"Settings > Windows Update: feature updates are paused until " + FormatUtcDate(feature.end) +
                    L"; security updates are not paused. That alone is fine.");
    }
    else if (quality.parsed || feature.parsed) {
        PauseRead last = Later(quality, feature);
        l.push_back(L"Settings > Windows Update: a pause ended on " + FormatUtcDate(last.end) + L"; updates are not paused now.");
    }

    // Group Policy (Windows Update > Manage updates offered from Windows Update).
    PauseRead policyQuality = ReadPause(facts.policyPauseQualityStart, policyPause, L"PauseQualityUpdatesStartTime", l);
    if (policyQuality.parsed) {
        if (policyQuality.end > now) {
            warn = true;
            l.push_back(L"Group Policy PAUSES quality (security) updates until " + FormatUtcDate(policyQuality.end) + L", " +
                        std::to_wstring(DaysUntil(policyQuality.end, now)) + L" day(s) from now (PauseQualityUpdatesStartTime "
                        L"plus 35 days).");
        }
        else {
            l.push_back(L"A Group Policy pause of quality updates ended on " + FormatUtcDate(policyQuality.end) + L".");
        }
    }
    PauseRead policyFeature = ReadPause(facts.policyPauseFeatureStart, policyPause, L"PauseFeatureUpdatesStartTime", l);
    if (policyFeature.parsed && policyFeature.end > now) {
        l.push_back(L"Group Policy pauses feature updates until " + FormatUtcDate(policyFeature.end) + L". That alone is fine.");
    }

    bool qualityDeferred = facts.deferQuality.set && facts.deferQuality.value != 0;
    if (qualityDeferred) {
        DWORD days = facts.deferQualityDays.set ? facts.deferQualityDays.value : 0;
        if (days > kMaxQualityDeferralDays) {
            warn = true;
            l.push_back(L"Group Policy holds back quality (security) updates for " + std::to_wstring(days) + L" days after "
                        L"Microsoft releases them (DeferQualityUpdatesPeriodInDays). More than 7 days leaves known holes open.");
        }
        else {
            l.push_back(L"Group Policy holds back quality (security) updates for " + std::to_wstring(days) + L" day(s): 7 or "
                        L"fewer, which is fine.");
        }
    }
    bool featureDeferred = facts.deferFeature.set && facts.deferFeature.value != 0;
    if (featureDeferred) {
        DWORD days = facts.deferFeatureDays.set ? facts.deferFeatureDays.value : 0;
        l.push_back(L"Group Policy defers feature updates by " + std::to_wstring(days) + L" day(s). Feature updates bring new "
                    L"Windows versions; security fixes come as quality updates, so this alone is fine.");
    }

    if (l.empty()) l.push_back(L"Updates are not paused, and no Group Policy defers them.");
    if (!facts.settingsReadable) {
        l.push_back(L"The pause settings (HKLM\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings) could not be read; run as "
                    L"administrator to check them too.");
    }
    if (!facts.policyReadable) {
        l.push_back(L"The Windows Update policy key could not be read; run as administrator to check it too.");
    }

    std::wstring status = warn ? CHECK_WARNING : CHECK_PASS;
    if (lines) *lines = l;
    DebugLog(L"Update pause: quality pause " + std::to_wstring(quality.parsed && quality.end > now) + L", policy pause " +
             std::to_wstring(policyQuality.parsed && policyQuality.end > now) + L", defer quality " + DwordText(facts.deferQuality) +
             L"/" + DwordText(facts.deferQualityDays) + L", defer feature " + DwordText(facts.deferFeature) + L" -> " + status);
    return status;
}

// ===========================================================================
// Remote Assistance
// ===========================================================================
std::wstring RemoteAssistStatus(const RemoteAssistFacts& facts, std::vector<std::wstring>* lines)
{
    std::vector<std::wstring> l;
    if (!facts.programPresent) {
        l.push_back(L"Remote Assistance (msra.exe) is not installed on this PC, so nobody can connect through it.");
        if (lines) *lines = l;
        DebugLog(L"Remote Assistance: msra.exe missing -> N/A");
        return CHECK_NA;
    }
    bool unsolicited = facts.policyAllowUnsolicited.set && facts.policyAllowUnsolicited.value != 0;
    if (!facts.localReadable && !facts.policyAllowGetHelp.set && !unsolicited) {
        l.push_back(L"The Remote Assistance settings (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance) could not be "
                    L"read. Run as administrator to read them.");
        if (lines) *lines = l;
        DebugLog(L"Remote Assistance: key unreadable -> N/A");
        return CHECK_NA;
    }

    bool warn = false;
    bool solicited = true;
    std::wstring source;
    if (facts.policyAllowGetHelp.set) {
        solicited = facts.policyAllowGetHelp.value != 0;
        source = L" by Group Policy (fAllowToGetHelp=" + std::to_wstring(facts.policyAllowGetHelp.value) + L")";
    }
    else if (facts.localAllowGetHelp.set) {
        solicited = facts.localAllowGetHelp.value != 0;
        source = L" (fAllowToGetHelp=" + std::to_wstring(facts.localAllowGetHelp.value) + L")";
    }
    else {
        source = L", the Windows default (fAllowToGetHelp is not set)";
    }
    l.push_back(std::wstring(L"Invitations for help (Allow Remote Assistance connections to this computer): ") +
                (solicited ? L"allowed" : L"off") + source + L".");

    if (solicited) {
        bool control = true;
        std::wstring controlSource;
        if (facts.policyAllowGetHelp.set && facts.policyAllowFullControl.set) {
            control = facts.policyAllowFullControl.value != 0;
            controlSource = L" by Group Policy (fAllowFullControl=" + std::to_wstring(facts.policyAllowFullControl.value) + L")";
        }
        else if (facts.localAllowFullControl.set) {
            control = facts.localAllowFullControl.value != 0;
            controlSource = L" (fAllowFullControl=" + std::to_wstring(facts.localAllowFullControl.value) + L")";
        }
        else {
            controlSource = L", the Windows default (fAllowFullControl is not set)";
        }
        if (control) warn = true;
        l.push_back(std::wstring(L"A helper who is invited may ") +
                    (control ? L"TAKE CONTROL of this PC (mouse and keyboard)" : L"only view the screen") + controlSource + L".");
    }

    if (unsolicited) {
        warn = true;
        bool unsolicitedControl = !facts.policyUnsolicitedFullControl.set || facts.policyUnsolicitedFullControl.value != 0;
        l.push_back(std::wstring(L"Offers of help nobody asked for: ALLOWED by Group Policy (fAllowUnsolicited=1); the helpers "
                                 L"that policy names may connect without an invitation and ") +
                    (unsolicitedControl ? L"take control." : L"view the screen."));
    }
    else {
        l.push_back(L"Offers of help nobody asked for: not allowed (no Group Policy turns them on).");
    }

    std::wstring status = warn ? CHECK_WARNING : CHECK_PASS;
    if (lines) *lines = l;
    DebugLog(L"Remote Assistance: local " + DwordText(facts.localAllowGetHelp) + L"/" + DwordText(facts.localAllowFullControl) +
             L", policy " + DwordText(facts.policyAllowGetHelp) + L"/" + DwordText(facts.policyAllowFullControl) +
             L", unsolicited " + DwordText(facts.policyAllowUnsolicited) + L" -> " + status);
    return status;
}

// ===========================================================================
// Cached domain sign-ins
// ===========================================================================
int EffectiveCachedLogons(const CachedLogonsFacts& facts)
{
    if (!facts.valuePresent) return kDefaultCachedLogons;
    std::wstring t = TrimW(facts.cachedLogonsCount);
    if (t.empty() || t.size() > 3) return -1;
    int n = 0;
    for (wchar_t c : t) {
        if (c < L'0' || c > L'9') return -1;
        n = n * 10 + (c - L'0');
    }
    return n > 50 ? -1 : n;
}

std::wstring CachedLogonsStatus(const CachedLogonsFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    int n = EffectiveCachedLogons(facts);
    if (!facts.joinKnown) {
        status = CHECK_NA;
        t = L"Windows did not say whether this PC is joined to a domain, so cached domain sign-ins were not judged.";
    }
    else if (!facts.domainJoined) {
        status = CHECK_NA;
        t = L"This PC is not joined to an Active Directory domain, so Windows keeps no cached domain sign-ins. (Microsoft "
            L"accounts, local accounts and Microsoft Entra sign-ins are not governed by this setting.)";
    }
    else if (!facts.keyReadable) {
        status = CHECK_NA;
        t = L"The sign-in settings (HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon) could not be read. Run as "
            L"administrator to read them.";
    }
    else if (n < 0) {
        status = CHECK_WARNING;
        t = L"CachedLogonsCount is \"" + TrimW(facts.cachedLogonsCount) + L"\", not a whole number from 0 to 50, so how many "
            L"sign-ins Windows keeps is not known. Set it to 4 or fewer.";
    }
    else if (n > kMaxCachedLogons) {
        status = CHECK_WARNING;
        t = L"Windows keeps the last " + std::to_wstring(n) + L" domain sign-ins on this PC (CachedLogonsCount " +
            (facts.valuePresent ? L"is " + std::to_wstring(n) : std::wstring(L"is not set, the Windows default 10")) +
            L"), so that many accounts can sign in here while no domain controller can be reached. 4 or fewer is enough for "
            L"most PCs.";
    }
    else {
        status = CHECK_PASS;
        t = L"Windows keeps at most " + std::to_wstring(n) + L" domain sign-in(s) on this PC (CachedLogonsCount is " +
            std::to_wstring(n) + L").";
        if (n == 0) {
            t += L" With 0, nobody can sign in with a domain account while the PC is away from the company network.";
        }
    }
    if (text) *text = t;
    DebugLog(L"Cached logons: join known " + std::to_wstring(facts.joinKnown) + L", domain " + std::to_wstring(facts.domainJoined) +
             L", present " + std::to_wstring(facts.valuePresent) + L", count " + std::to_wstring(n) + L" -> " + status);
    return status;
}

// ===========================================================================
// Windows' built-in sudo
// ===========================================================================
DWORD EffectiveSudoMode(const SudoFacts& facts)
{
    DWORD mode = facts.enabled.set ? facts.enabled.value : kSudoOff;
    if (facts.policyMaximum.set && mode > facts.policyMaximum.value) mode = facts.policyMaximum.value;
    return mode;
}

std::wstring SudoModeName(DWORD mode)
{
    switch (mode) {
    case kSudoOff:         return L"off";
    case kSudoNewWindow:   return L"in a new window";
    case kSudoInputClosed: return L"with input closed";
    case kSudoInline:      return L"inline";
    default:               return L"an unknown mode (" + std::to_wstring(mode) + L")";
    }
}

std::wstring SudoStatus(const SudoFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    DWORD mode = EffectiveSudoMode(facts);
    if (!facts.available) {
        status = CHECK_NA;
        t = L"This Windows build has no built-in sudo (it came with Windows 11 24H2).";
    }
    else if (mode == kSudoInline) {
        status = CHECK_WARNING;
        t = L"sudo is on and runs inline (Enabled=3): an elevated command shares the normal console window with the programs "
            L"you run without administrator rights.";
    }
    else if (mode > kSudoInline) {
        status = CHECK_WARNING;
        t = L"sudo is set to " + SudoModeName(mode) + L", which is not a mode Windows defines. Choose In a new window or turn sudo off.";
    }
    else if (mode == kSudoOff) {
        status = CHECK_PASS;
        t = std::wstring(L"sudo is off") +
            (facts.enabled.set ? L" (Enabled=" + std::to_wstring(facts.enabled.value) + L")." : std::wstring(L" (Enabled is not set)."));
    }
    else {
        status = CHECK_PASS;
        t = L"sudo is on and runs " + SudoModeName(mode) + L" (Enabled=" + std::to_wstring(mode) + L"): an elevated command does "
            L"not share the console with programs running without administrator rights.";
    }
    if (facts.available && facts.policyMaximum.set) {
        t += L" Group Policy allows at most " + SudoModeName(facts.policyMaximum.value) + L".";
    }
    if (text) *text = t;
    DebugLog(L"sudo: available " + std::to_wstring(facts.available) + L", Enabled " + DwordText(facts.enabled) + L", policy " +
             DwordText(facts.policyMaximum) + L", mode " + std::to_wstring(mode) + L" -> " + status);
    return status;
}

// ===========================================================================
// DNS over HTTPS
// ===========================================================================
std::vector<std::wstring> DohServerLines(const std::vector<DohServerSetting>& servers)
{
    std::vector<std::wstring> out;
    for (const DohServerSetting& s : servers) {
        if (s.flags == 0) continue;
        std::wstring line = L"  " + s.adapter + L": " + s.server + (s.ipv6 ? L" (IPv6)" : L"") + L": on, ";
        if (!TrimW(s.dohTemplate).empty()) line += L"template set by hand " + TrimW(s.dohTemplate);
        else line += L"template from Windows' list of known servers";
        line += L" (DohFlags " + HexText(s.flags) + L")";
        out.push_back(line);
    }
    return out;
}

std::wstring DohStatus(const DohFacts& facts, std::wstring* text)
{
    std::vector<std::wstring> serverLines = DohServerLines(facts.servers);
    bool required = facts.policy.set && facts.policy.value == kDohPolicyRequire;
    bool prohibited = facts.policy.set && facts.policy.value == kDohPolicyProhibit;
    bool autoOn = facts.autoDoh.set && facts.autoDoh.value == 2;

    std::wstring head;
    if (required) {
        head = L"Group Policy requires DNS over HTTPS: name lookups are encrypted, and lookups to servers without it fail.";
    }
    else if (prohibited) {
        head = L"Group Policy blocks DNS over HTTPS: name lookups are sent as plain DNS.";
    }
    else if (!serverLines.empty()) {
        head = L"DNS over HTTPS is on for " + std::to_wstring(serverLines.size()) + L" DNS server setting(s) on this PC's adapters.";
    }
    else if (autoOn) {
        head = L"Windows uses DNS over HTTPS automatically for DNS servers it knows support it (EnableAutoDoh=2); no adapter "
               L"sets it by hand.";
    }
    else {
        head = L"Name lookups are sent as plain DNS. That is a normal setup on a trusted home or office network; on public "
               L"Wi-Fi others on the network can see or change them.";
    }

    std::vector<std::wstring> l;
    l.push_back(head);
    if (facts.policy.set) {
        std::wstring what = facts.policy.value == kDohPolicyRequire ? L"required" :
                            facts.policy.value == kDohPolicyAllow ? L"allowed" :
                            facts.policy.value == kDohPolicyProhibit ? L"prohibited" : L"set to a value Windows does not define";
        l.push_back(L"Group Policy (DoHPolicy=" + std::to_wstring(facts.policy.value) + L"): DNS over HTTPS " + what + L".");
    }
    else {
        l.push_back(L"Group Policy: no DNS over HTTPS policy is set.");
    }
    l.push_back(std::wstring(L"Automatic DNS over HTTPS for known servers (EnableAutoDoh): ") +
                (facts.autoDoh.set ? std::to_wstring(facts.autoDoh.value) + (autoOn ? L", on." : L", off.") : std::wstring(L"not set.")));
    if (!facts.interfacesRead) {
        l.push_back(L"The per-adapter DNS over HTTPS settings could not be read.");
    }
    else if (serverLines.empty()) {
        l.push_back(L"No adapter has DNS over HTTPS turned on for its DNS servers.");
    }
    else {
        l.push_back(L"Adapters with DNS over HTTPS on:");
        for (const std::wstring& s : serverLines) l.push_back(s);
    }
    l.push_back(L"Windows knows a DNS over HTTPS address for " + std::to_wstring(facts.knownServers) + L" public DNS server(s).");
    if (text) *text = JoinW(l, L"\n");
    DebugLog(L"DoH: policy " + DwordText(facts.policy) + L", auto " + DwordText(facts.autoDoh) + L", " +
             std::to_wstring(facts.servers.size()) + L" entries, " + std::to_wstring(serverLines.size()) + L" on, known " +
             std::to_wstring(facts.knownServers) + L" -> INFO");
    return CHECK_INFO;
}
