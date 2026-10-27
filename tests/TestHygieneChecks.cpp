// The third platform pack: WDigest password caching, paused or deferred Windows
// updates, Remote Assistance, cached domain sign-ins, Windows' built-in sudo and DNS
// over HTTPS. Verdicts are judged on crafted facts (HygieneRules.cpp); the real checks
// are only required to answer well on this PC.

#include "TestFramework.h"

#include "CheckCatalog.h"
#include "FixScript.h"
#include "HardeningScore.h"
#include "HygieneRules.h"
#include "SecurityCheckModules.h"
#include "TextUtils.h"

#include <windows.h>
#include <cstdio>

static OptionalDword Dw(DWORD v)
{
    OptionalDword o;
    o.set = true;
    o.value = v;
    return o;
}

static bool Has(const std::wstring& text, const wchar_t* part)
{
    return text.find(part) != std::wstring::npos;
}

static bool AnyHas(const std::vector<std::wstring>& lines, const wchar_t* part)
{
    for (const std::wstring& l : lines) {
        if (Has(l, part)) return true;
    }
    return false;
}

static const std::wstring kPass = CHECK_PASS;
static const std::wstring kWarn = CHECK_WARNING;
static const std::wstring kFail = CHECK_FAIL;
static const std::wstring kNa = CHECK_NA;
static const std::wstring kInfo = CHECK_INFO;

// ---------------------------------------------------------------------------
// cred.wdigest
// ---------------------------------------------------------------------------
TEST(Hygiene_WDigestVerdicts)
{
    std::wstring text;
    WDigestFacts modern;
    modern.build = 26100;
    CHECK_EQ(WDigestStatus(modern, &text), kPass);   // missing is the safe default
    CHECK(Has(text, L"not set"));

    WDigestFacts off = modern;
    off.useLogonCredential = Dw(0);
    CHECK_EQ(WDigestStatus(off, &text), kPass);
    CHECK(Has(text, L"is 0"));

    WDigestFacts on = modern;
    on.useLogonCredential = Dw(1);
    CHECK_EQ(WDigestStatus(on, &text), kFail);
    CHECK(Has(text, L"readable form"));
    on.useLogonCredential = Dw(2);   // any value but 0 counts as on
    CHECK_EQ(WDigestStatus(on, &text), kFail);

    // Before Windows 8.1 a missing value means the passwords are kept.
    WDigestFacts old;
    old.build = 7601;
    CHECK_EQ(WDigestStatus(old, &text), kFail);
    CHECK(Has(text, L"older than Windows 8.1"));
    old.build = kWindows81Build;
    CHECK_EQ(WDigestStatus(old, &text), kPass);
    WDigestFacts unknownBuild;   // the build could not be read: this program runs on Windows 10 and later
    CHECK_EQ(WDigestStatus(unknownBuild, &text), kPass);

    WDigestFacts closed = on;
    closed.keyReadable = false;
    CHECK_EQ(WDigestStatus(closed, &text), kNa);
    CHECK(Has(text, L"administrator"));
}

// ---------------------------------------------------------------------------
// wu.paused
// ---------------------------------------------------------------------------
static long long At(const wchar_t* iso)
{
    long long t = 0;
    if (!ParseIso8601Utc(iso, t)) tf::Fail(__FILE__, __LINE__, "test date does not parse: " + tf::Narrow(iso));
    return t;
}

TEST(Hygiene_IsoDates)
{
    long long t = -1;
    CHECK(ParseIso8601Utc(L"1970-01-01T00:00:00Z", t));
    CHECK_EQ(t, 0LL);
    CHECK(ParseIso8601Utc(L"2000-01-01T00:00:00Z", t));
    CHECK_EQ(t, 946684800LL);
    CHECK(ParseIso8601Utc(L"2000-01-01", t));
    CHECK_EQ(t, 946684800LL);
    CHECK(ParseIso8601Utc(L"  2000-01-01T01:00:00+01:00 ", t));
    CHECK_EQ(t, 946684800LL);
    CHECK(ParseIso8601Utc(L"1999-12-31T19:00:00-0500", t));
    CHECK_EQ(t, 946684800LL);
    CHECK(ParseIso8601Utc(L"2000-01-01 00:00:30.25Z", t));
    CHECK_EQ(t, 946684830LL);
    CHECK(ParseIso8601Utc(L"2000-01-01T00:01Z", t));
    CHECK_EQ(t, 946684860LL);
    CHECK(ParseIso8601Utc(L"2024-02-29T12:00:00Z", t));   // leap day
    CHECK_EQ(FormatUtcDate(t), std::wstring(L"2024-02-29 12:00 UTC"));
    CHECK(ParseIso8601Utc(L"2031-07-15T08:09:10Z", t));
    CHECK_EQ(FormatUtcDate(t), std::wstring(L"2031-07-15 08:09 UTC"));
    CHECK_EQ(FormatUtcDate(0), std::wstring(L"1970-01-01 00:00 UTC"));

    for (const wchar_t* bad : { L"", L"soon", L"2023-02-29", L"2026-13-01", L"2026-00-10", L"2026-04-31", L"2026-1-5",
                                L"2026-01-01T25:00:00Z", L"2026-01-01T10:60Z", L"2026-01-01X", L"2026-01-01T10:00:00Q",
                                L"2026-01-01T10:00:00.Z", L"2026/01/01" }) {
        long long ignored = 0;
        if (ParseIso8601Utc(bad, ignored)) tf::Fail(__FILE__, __LINE__, "accepted a bad date: " + tf::Narrow(bad));
    }
}

static UpdatePauseFacts PauseFacts()
{
    UpdatePauseFacts f;
    f.nowUnix = At(L"2031-03-01T12:00:00Z");
    return f;
}

TEST(Hygiene_UpdatePauseVerdicts)
{
    std::vector<std::wstring> lines;
    UpdatePauseFacts none = PauseFacts();
    CHECK_EQ(UpdatePauseStatus(none, &lines), kPass);
    REQUIRE(lines.size() == 1);
    CHECK(Has(lines[0], L"not paused"));

    // Settings > Windows Update > Pause updates, as that page writes it.
    UpdatePauseFacts paused = PauseFacts();
    paused.pauseUpdatesExpiry = L"2031-03-12T09:30:00Z";
    paused.pauseQualityEnd = L"2031-03-12T09:30:00Z";
    paused.pauseFeatureEnd = L"2031-03-12T09:30:00Z";
    CHECK_EQ(UpdatePauseStatus(paused, &lines), kWarn);
    CHECK(AnyHas(lines, L"PAUSED until 2031-03-12 09:30 UTC, 11 day(s) from now"));
    CHECK_EQ(lines.size(), static_cast<size_t>(1));   // one line for the one pause

    // Only the quality end time set is still a pause of security updates.
    UpdatePauseFacts qualityOnly = PauseFacts();
    qualityOnly.pauseQualityEnd = L"2031-03-02T00:00:00Z";
    CHECK_EQ(UpdatePauseStatus(qualityOnly, &lines), kWarn);
    CHECK(AnyHas(lines, L"1 day(s) from now"));

    // A pause that has run out.
    UpdatePauseFacts ended = paused;
    ended.nowUnix = At(L"2031-04-01T00:00:00Z");
    CHECK_EQ(UpdatePauseStatus(ended, &lines), kPass);
    CHECK(AnyHas(lines, L"ended on 2031-03-12"));

    // Feature updates alone may be paused or deferred.
    UpdatePauseFacts feature = PauseFacts();
    feature.pauseFeatureEnd = L"2031-03-20T00:00:00Z";
    CHECK_EQ(UpdatePauseStatus(feature, &lines), kPass);
    CHECK(AnyHas(lines, L"feature updates are paused"));
    CHECK(AnyHas(lines, L"alone is fine"));
    UpdatePauseFacts featureDefer = PauseFacts();
    featureDefer.deferFeature = Dw(1);
    featureDefer.deferFeatureDays = Dw(365);
    CHECK_EQ(UpdatePauseStatus(featureDefer, &lines), kPass);
    CHECK(AnyHas(lines, L"365 day(s)"));
    UpdatePauseFacts featurePolicyPause = PauseFacts();
    featurePolicyPause.policyPauseFeatureStart = L"2031-02-20";
    CHECK_EQ(UpdatePauseStatus(featurePolicyPause, &lines), kPass);
    CHECK(AnyHas(lines, L"pauses feature updates"));

    // Group Policy deferral of quality updates: more than 7 days is a warning.
    UpdatePauseFacts defer = PauseFacts();
    defer.deferQuality = Dw(1);
    defer.deferQualityDays = Dw(14);
    CHECK_EQ(UpdatePauseStatus(defer, &lines), kWarn);
    CHECK(AnyHas(lines, L"for 14 days"));
    defer.deferQualityDays = Dw(7);
    CHECK_EQ(UpdatePauseStatus(defer, &lines), kPass);
    CHECK(AnyHas(lines, L"7 or fewer"));
    defer.deferQuality = Dw(0);   // the policy is off: the period alone does nothing
    defer.deferQualityDays = Dw(30);
    CHECK_EQ(UpdatePauseStatus(defer, &lines), kPass);

    // Group Policy pause: 35 days from its start date.
    UpdatePauseFacts policyPause = PauseFacts();
    policyPause.policyPauseQualityStart = L"2031-02-10";
    CHECK_EQ(UpdatePauseStatus(policyPause, &lines), kWarn);
    CHECK(AnyHas(lines, L"PAUSES quality (security) updates until 2031-03-17"));
    policyPause.policyPauseQualityStart = L"2031-01-01";
    CHECK_EQ(UpdatePauseStatus(policyPause, &lines), kPass);
    CHECK(AnyHas(lines, L"ended on 2031-02-05"));

    // A value that is not a date is said and not judged.
    UpdatePauseFacts odd = PauseFacts();
    odd.pauseUpdatesExpiry = L"next Tuesday";
    CHECK_EQ(UpdatePauseStatus(odd, &lines), kPass);
    CHECK(AnyHas(lines, L"cannot read as a date"));

    // Keys a normal user cannot open.
    UpdatePauseFacts closed = PauseFacts();
    closed.settingsReadable = false;
    closed.policyReadable = false;
    CHECK_EQ(UpdatePauseStatus(closed, &lines), kNa);
    CHECK(AnyHas(lines, L"administrator"));
    UpdatePauseFacts halfClosed = paused;
    halfClosed.policyReadable = false;
    CHECK_EQ(UpdatePauseStatus(halfClosed, &lines), kWarn);
    CHECK(AnyHas(lines, L"policy key could not be read"));
}

// ---------------------------------------------------------------------------
// net.remoteassist
// ---------------------------------------------------------------------------
TEST(Hygiene_RemoteAssistVerdicts)
{
    std::vector<std::wstring> lines;
    RemoteAssistFacts defaults;   // nothing set: invitations with control, the Windows default
    CHECK_EQ(RemoteAssistStatus(defaults, &lines), kWarn);
    CHECK(AnyHas(lines, L"Windows default"));
    CHECK(AnyHas(lines, L"TAKE CONTROL"));

    RemoteAssistFacts local;
    local.localAllowGetHelp = Dw(1);
    local.localAllowFullControl = Dw(1);
    CHECK_EQ(RemoteAssistStatus(local, &lines), kWarn);
    local.localAllowFullControl = Dw(0);
    CHECK_EQ(RemoteAssistStatus(local, &lines), kPass);
    CHECK(AnyHas(lines, L"only view the screen"));
    local.localAllowGetHelp = Dw(0);
    local.localAllowFullControl = Dw(1);   // control does not matter while invitations are off
    CHECK_EQ(RemoteAssistStatus(local, &lines), kPass);
    CHECK(AnyHas(lines, L"off (fAllowToGetHelp=0)"));

    // Group Policy wins over the local values.
    RemoteAssistFacts policyOff;
    policyOff.localAllowGetHelp = Dw(1);
    policyOff.localAllowFullControl = Dw(1);
    policyOff.policyAllowGetHelp = Dw(0);
    CHECK_EQ(RemoteAssistStatus(policyOff, &lines), kPass);
    CHECK(AnyHas(lines, L"by Group Policy"));
    RemoteAssistFacts policyViewOnly = policyOff;
    policyViewOnly.policyAllowGetHelp = Dw(1);
    policyViewOnly.policyAllowFullControl = Dw(0);
    CHECK_EQ(RemoteAssistStatus(policyViewOnly, &lines), kPass);
    RemoteAssistFacts policyOn;
    policyOn.localAllowGetHelp = Dw(0);
    policyOn.policyAllowGetHelp = Dw(1);
    policyOn.policyAllowFullControl = Dw(1);
    CHECK_EQ(RemoteAssistStatus(policyOn, &lines), kWarn);

    // Unsolicited offers.
    RemoteAssistFacts offers;
    offers.localAllowGetHelp = Dw(0);
    offers.policyAllowUnsolicited = Dw(1);
    offers.policyUnsolicitedFullControl = Dw(0);
    CHECK_EQ(RemoteAssistStatus(offers, &lines), kWarn);
    CHECK(AnyHas(lines, L"nobody asked for: ALLOWED"));
    CHECK(AnyHas(lines, L"view the screen."));
    offers.policyAllowUnsolicited = Dw(0);
    CHECK_EQ(RemoteAssistStatus(offers, &lines), kPass);

    RemoteAssistFacts missing = defaults;
    missing.programPresent = false;
    CHECK_EQ(RemoteAssistStatus(missing, &lines), kNa);
    RemoteAssistFacts closed;
    closed.localReadable = false;
    CHECK_EQ(RemoteAssistStatus(closed, &lines), kNa);
    CHECK(AnyHas(lines, L"administrator"));
    closed.policyAllowGetHelp = Dw(0);   // the policy alone decides
    CHECK_EQ(RemoteAssistStatus(closed, &lines), kPass);
}

// ---------------------------------------------------------------------------
// cred.cachedlogons
// ---------------------------------------------------------------------------
static CachedLogonsFacts Joined(const wchar_t* count)
{
    CachedLogonsFacts f;
    f.joinKnown = true;
    f.domainJoined = true;
    if (count) {
        f.valuePresent = true;
        f.cachedLogonsCount = count;
    }
    return f;
}

TEST(Hygiene_CachedLogonsVerdicts)
{
    std::wstring text;
    CHECK_EQ(EffectiveCachedLogons(Joined(nullptr)), kDefaultCachedLogons);
    CHECK_EQ(EffectiveCachedLogons(Joined(L" 2 ")), 2);
    CHECK_EQ(EffectiveCachedLogons(Joined(L"50")), 50);
    CHECK_EQ(EffectiveCachedLogons(Joined(L"51")), -1);
    CHECK_EQ(EffectiveCachedLogons(Joined(L"-1")), -1);
    CHECK_EQ(EffectiveCachedLogons(Joined(L"")), -1);

    CHECK_EQ(CachedLogonsStatus(Joined(nullptr), &text), kWarn);
    CHECK(Has(text, L"Windows default 10"));
    CHECK_EQ(CachedLogonsStatus(Joined(L"10"), &text), kWarn);
    CHECK(Has(text, L"last 10"));
    CHECK_EQ(CachedLogonsStatus(Joined(L"5"), &text), kWarn);
    CHECK_EQ(CachedLogonsStatus(Joined(L"4"), &text), kPass);
    CHECK_EQ(CachedLogonsStatus(Joined(L"1"), &text), kPass);
    CHECK_EQ(CachedLogonsStatus(Joined(L"0"), &text), kPass);
    CHECK(Has(text, L"away from the company network"));
    CHECK_EQ(CachedLogonsStatus(Joined(L"ten"), &text), kWarn);
    CHECK(Has(text, L"not a whole number"));

    CachedLogonsFacts home;
    home.joinKnown = true;
    CHECK_EQ(CachedLogonsStatus(home, &text), kNa);
    CHECK(Has(text, L"not joined"));
    CachedLogonsFacts unknown;
    CHECK_EQ(CachedLogonsStatus(unknown, &text), kNa);
    CachedLogonsFacts closed = Joined(L"10");
    closed.keyReadable = false;
    CHECK_EQ(CachedLogonsStatus(closed, &text), kNa);
    CHECK(Has(text, L"administrator"));
}

// ---------------------------------------------------------------------------
// hard.sudo
// ---------------------------------------------------------------------------
TEST(Hygiene_SudoVerdicts)
{
    std::wstring text;
    SudoFacts none;
    CHECK_EQ(SudoStatus(none, &text), kNa);
    CHECK(Has(text, L"no built-in sudo"));

    SudoFacts off;
    off.available = true;
    CHECK_EQ(SudoStatus(off, &text), kPass);
    CHECK(Has(text, L"not set"));
    off.enabled = Dw(kSudoOff);
    CHECK_EQ(SudoStatus(off, &text), kPass);

    SudoFacts window = off;
    window.enabled = Dw(kSudoNewWindow);
    CHECK_EQ(SudoStatus(window, &text), kPass);
    CHECK(Has(text, L"in a new window"));
    SudoFacts closedInput = off;
    closedInput.enabled = Dw(kSudoInputClosed);
    CHECK_EQ(SudoStatus(closedInput, &text), kPass);
    CHECK(Has(text, L"with input closed"));

    SudoFacts inl = off;
    inl.enabled = Dw(kSudoInline);
    CHECK_EQ(SudoStatus(inl, &text), kWarn);
    CHECK(Has(text, L"inline"));
    SudoFacts strange = off;
    strange.enabled = Dw(9);
    CHECK_EQ(SudoStatus(strange, &text), kWarn);
    CHECK(Has(text, L"unknown mode (9)"));

    // A Group Policy limit lowers the mode.
    SudoFacts limited = inl;
    limited.policyMaximum = Dw(kSudoNewWindow);
    CHECK_EQ(EffectiveSudoMode(limited), kSudoNewWindow);
    CHECK_EQ(SudoStatus(limited, &text), kPass);
    CHECK(Has(text, L"Group Policy allows at most in a new window"));
    limited.policyMaximum = Dw(kSudoInline);
    CHECK_EQ(SudoStatus(limited, &text), kWarn);
}

// ---------------------------------------------------------------------------
// net.doh
// ---------------------------------------------------------------------------
static DohServerSetting DohServer(const wchar_t* adapter, const wchar_t* server, DWORD flags, const wchar_t* tmpl = L"")
{
    DohServerSetting s;
    s.adapter = adapter;
    s.server = server;
    s.flags = flags;
    s.dohTemplate = tmpl;
    return s;
}

TEST(Hygiene_DohVerdicts)
{
    std::wstring text;
    DohFacts plain;
    plain.interfacesRead = true;
    plain.knownServers = 13;
    CHECK_EQ(DohStatus(plain, &text), kInfo);   // never a FAIL or WARNING
    CHECK(Has(text, L"plain DNS"));
    CHECK(Has(text, L"No adapter has DNS over HTTPS"));
    CHECK(Has(text, L"13 public DNS server(s)"));

    DohFacts on = plain;
    on.servers.push_back(DohServer(L"Wi-Fi", L"192.0.2.53", 1));
    on.servers.push_back(DohServer(L"Wi-Fi", L"192.0.2.54", 0));   // off: not listed
    DohServerSetting v6 = DohServer(L"Ethernet 2", L"2001:db8::53", 2, L"https://dns.example.test/dns-query");
    v6.ipv6 = true;
    on.servers.push_back(v6);
    CHECK_EQ(DohStatus(on, &text), kInfo);
    CHECK(Has(text, L"on for 2 DNS server setting(s)"));
    CHECK(Has(text, L"Wi-Fi: 192.0.2.53: on, template from Windows' list of known servers (DohFlags 0x1)"));
    CHECK(Has(text, L"Ethernet 2: 2001:db8::53 (IPv6): on, template set by hand https://dns.example.test/dns-query"));
    CHECK(!Has(text, L"192.0.2.54"));
    CHECK_EQ(DohServerLines(on.servers).size(), static_cast<size_t>(2));

    DohFacts required = plain;
    required.policy = Dw(kDohPolicyRequire);
    CHECK_EQ(DohStatus(required, &text), kInfo);
    CHECK(Has(text, L"requires DNS over HTTPS"));
    CHECK(Has(text, L"DoHPolicy=3"));
    DohFacts prohibited = plain;
    prohibited.policy = Dw(kDohPolicyProhibit);
    DohStatus(prohibited, &text);
    CHECK(Has(text, L"blocks DNS over HTTPS"));
    DohFacts allowed = plain;
    allowed.policy = Dw(kDohPolicyAllow);
    DohStatus(allowed, &text);
    CHECK(Has(text, L"DNS over HTTPS allowed"));

    DohFacts automatic = plain;
    automatic.autoDoh = Dw(2);
    DohStatus(automatic, &text);
    CHECK(Has(text, L"automatically"));
    CHECK(Has(text, L"(EnableAutoDoh): 2, on."));

    DohFacts unread;   // the per-adapter key could not be read
    CHECK_EQ(DohStatus(unread, &text), kInfo);
    CHECK(Has(text, L"could not be read"));
}

// ---------------------------------------------------------------------------
// Catalog rows, the score and the fix plan
// ---------------------------------------------------------------------------
static const wchar_t* const kHygieneIds[] = { L"cred.wdigest", L"wu.paused", L"net.remoteassist", L"cred.cachedlogons",
                                              L"hard.sudo", L"net.doh" };

TEST(Hygiene_CatalogAndScripts)
{
    for (const wchar_t* id : kHygieneIds) {
        const CheckInfo* info = FindCheckInfo(id);
        if (!info) {
            tf::Fail(__FILE__, __LINE__, "no catalog row for " + tf::Narrow(id));
            continue;
        }
        if (!info->scored) tf::Fail(__FILE__, __LINE__, tf::Narrow(id) + " is not scored");
        if (info->scriptPerTarget) tf::Fail(__FILE__, __LINE__, tf::Narrow(id) + " should not name targets");
    }
    const CheckInfo* wdigest = FindCheckInfo(L"cred.wdigest");
    const CheckInfo* paused = FindCheckInfo(L"wu.paused");
    const CheckInfo* assist = FindCheckInfo(L"net.remoteassist");
    const CheckInfo* cached = FindCheckInfo(L"cred.cachedlogons");
    const CheckInfo* sudo = FindCheckInfo(L"hard.sudo");
    const CheckInfo* doh = FindCheckInfo(L"net.doh");
    REQUIRE(wdigest && paused && assist && cached && sudo && doh);

    CHECK(wdigest->severity == Severity::High);
    CHECK(paused->severity == Severity::Medium);
    CHECK(assist->severity == Severity::Medium);
    CHECK(cached->severity == Severity::Low);
    CHECK(sudo->severity == Severity::Low);
    CHECK(doh->severity == Severity::Info);
    CHECK_EQ(wdigest->category, std::wstring(L"Credential protection"));
    CHECK_EQ(paused->category, std::wstring(L"Updates and software"));
    CHECK_EQ(assist->category, std::wstring(L"Network exposure"));
    CHECK_EQ(cached->category, std::wstring(L"Credential protection"));
    CHECK_EQ(sudo->category, std::wstring(L"Platform hardening"));
    CHECK_EQ(doh->category, std::wstring(L"Network exposure"));

    // Exact commands where the fix is one; the undo of WDigest is by hand.
    CHECK(Has(wdigest->fixScript, L"-Name UseLogonCredential -Value 0 -Type DWord"));
    CHECK(wdigest->undoScript.empty());
    CHECK(wdigest->scriptNeedsRestart);
    CHECK(Has(wdigest->explanation, L"never looks at memory"));
    CHECK(Has(assist->fixScript, L"-Name fAllowToGetHelp -Value 0"));
    CHECK(Has(assist->undoScript, L"-Name fAllowToGetHelp -Value 1"));
    CHECK(Has(assist->explanation, L"tech support"));
    CHECK(Has(cached->fixScript, L"-Name CachedLogonsCount -Value '4' -Type String"));
    CHECK(Has(cached->undoScript, L"-Value '10'"));
    CHECK(Has(cached->explanation, L"at least 1 or 2"));
    CHECK_EQ(sudo->fixScript, std::wstring(L"sudo config --enable forceNewWindow"));
    CHECK_EQ(sudo->undoScript, std::wstring(L"sudo config --enable normal"));
    // A Settings button or a Settings page: done by hand.
    CHECK(paused->fixScript.empty());
    CHECK(Has(paused->fix, L"Resume updates"));
    CHECK(doh->fixScript.empty());
    CHECK(Has(doh->explanation, L"does not hide"));
}

TEST(Hygiene_InfoSeverityDoesNotMoveTheScore)
{
    CHECK_EQ(SeverityWeight(Severity::Info), 0);
    SecurityCheckResult high = MakeCheckResult(L"cred.wdigest");
    high.status = CHECK_FAIL;
    SecurityCheckResult doh = MakeCheckResult(L"net.doh");
    for (const wchar_t* status : { CHECK_INFO, CHECK_PASS, CHECK_WARNING, CHECK_FAIL }) {
        doh.status = status;
        HardeningScore s = ComputeHardeningScore({ high, doh });
        if (s.counted != 1 || s.score != 0) tf::Fail(__FILE__, __LINE__, "net.doh moved the score with " + tf::Narrow(status));
    }
}

TEST(Hygiene_FixPlanSteps)
{
    SecurityCheckResult wdigest = MakeCheckResult(L"cred.wdigest");
    wdigest.status = CHECK_FAIL;
    wdigest.detail = L"UseLogonCredential is 1.";
    SecurityCheckResult paused = MakeCheckResult(L"wu.paused");
    paused.status = CHECK_WARNING;
    paused.detail = L"Security updates are held back on this PC.\nSettings > Windows Update: updates are PAUSED until 2031-03-12.";
    SecurityCheckResult sudo = MakeCheckResult(L"hard.sudo");
    sudo.status = CHECK_WARNING;
    SecurityCheckResult doh = MakeCheckResult(L"net.doh");
    doh.status = CHECK_INFO;   // INFO is never a step

    std::vector<FixStep> steps = BuildFixSteps({ sudo, paused, doh, wdigest }, false, false);
    REQUIRE(steps.size() == 3);
    CHECK_EQ(steps[0].checkId, std::wstring(L"cred.wdigest"));   // High first
    CHECK(steps[0].kind == FixStepKind::Command);
    REQUIRE(steps[0].commands.size() == 1);
    CHECK(Has(steps[0].commands[0], L"UseLogonCredential -Value 0"));
    CHECK(steps[0].needsRestart);
    CHECK_EQ(steps[1].checkId, std::wstring(L"wu.paused"));
    CHECK(steps[1].kind == FixStepKind::Manual);
    CHECK(AnyHas(steps[1].evidence, L"PAUSED until 2031-03-12"));
    CHECK_EQ(steps[2].checkId, std::wstring(L"hard.sudo"));
    CHECK(steps[2].kind == FixStepKind::Command);

    // Undo: reverse order; WDigest has no undo command, so it is done by hand.
    std::vector<FixStep> undo = BuildFixSteps({ sudo, paused, doh, wdigest }, true, false);
    REQUIRE(undo.size() == 3);
    CHECK_EQ(undo[0].checkId, std::wstring(L"hard.sudo"));
    REQUIRE(!undo[0].commands.empty());
    CHECK_EQ(undo[0].commands[0], std::wstring(L"sudo config --enable normal"));
    CHECK(undo[2].kind == FixStepKind::Manual);
    CHECK(AnyHas(undo[2].instructions, L"By hand"));

    // Hidden names change nothing here: no step names anything on this PC.
    std::vector<FixStep> redacted = BuildFixSteps({ wdigest }, false, true);
    REQUIRE(redacted.size() == 1);
    CHECK(redacted[0].kind == FixStepKind::Command);
}

// ---------------------------------------------------------------------------
// The real checks on this PC: a verdict or N/A with a reason, never ERROR
// ---------------------------------------------------------------------------
TEST(Hygiene_ChecksRunHere)
{
    std::vector<SecurityCheckResult> results = {
        CheckWDigest(), CheckUpdatePause(), CheckRemoteAssistance(), CheckCachedLogons(), CheckSudo(), CheckDnsOverHttps(),
    };
    REQUIRE(results.size() == sizeof(kHygieneIds) / sizeof(kHygieneIds[0]));
    for (size_t i = 0; i < results.size(); ++i) {
        const SecurityCheckResult& r = results[i];
        std::printf("    note: %s -> %s\n", tf::Narrow(r.id).c_str(), tf::Narrow(r.status).c_str());
        CHECK_EQ(r.id, std::wstring(kHygieneIds[i]));
        if (r.status == CHECK_ERROR) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " returned ERROR: " + tf::Narrow(r.detail));
        if (r.detail.empty()) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " has no detail");
        if (r.detail.size() > 20000) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " does not cap its evidence");
        if (!r.targets.empty()) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " names targets");
    }
    CHECK_EQ(results[5].status, kInfo);   // DNS over HTTPS only describes
    CHECK(results[2].status != kFail);    // Remote Assistance warns at most
    CHECK(results[3].status != kFail);
    CHECK(results[4].status != kFail);
}
