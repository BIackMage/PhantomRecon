// The platform checks: memory integrity, vulnerable driver block list, Smart App
// Control, system exploit protection, screen lock, System Restore and open Wi-Fi.
// Verdicts are judged on crafted facts (PlatformRules.cpp); the real checks are only
// required to answer well on this PC.

#include "TestFramework.h"

#include "../CheckCatalog.h"
#include "../DeviceGuard.h"
#include "../PlatformRules.h"
#include "../Redactor.h"
#include "../SecurityCheckModules.h"

#include <windows.h>
#include <cstdio>

static OptionalDword Dw(DWORD v)
{
    OptionalDword o;
    o.set = true;
    o.value = v;
    return o;
}

static const std::wstring kPass = CHECK_PASS;
static const std::wstring kWarn = CHECK_WARNING;
static const std::wstring kFail = CHECK_FAIL;
static const std::wstring kNa = CHECK_NA;

// ---------------------------------------------------------------------------
// Device Guard lists (shared with Credential Guard)
// ---------------------------------------------------------------------------
TEST(Platform_DeviceGuardList)
{
    std::vector<int> list = ParseDeviceGuardList(L"2\n7");
    REQUIRE(list.size() == 2);
    CHECK_EQ(list[0], 2);
    CHECK_EQ(list[1], 7);
    CHECK(DeviceGuardHas(list, kDeviceGuardMemoryIntegrity));
    CHECK(!DeviceGuardHas(list, kDeviceGuardCredentialGuard));
    CHECK(ParseDeviceGuardList(L"").empty());
    CHECK_EQ(ParseDeviceGuardList(L"1\nx\n 2 ").size(), static_cast<size_t>(2));   // junk skipped, spaces trimmed
    CHECK(!DeviceGuardHas(ParseDeviceGuardList(L"12"), 2));                         // 12 is not 2
}

// ---------------------------------------------------------------------------
// hard.hvci
// ---------------------------------------------------------------------------
TEST(Platform_HvciVerdicts)
{
    std::wstring text;
    HvciFacts running;
    running.registryEnabled = Dw(1);
    running.wmiOk = true;
    running.wmiConfigured = true;
    running.wmiRunning = true;
    CHECK_EQ(HvciStatus(running, &text), kPass);

    // Turned on, not running: reboot pending or an incompatible driver.
    HvciFacts pending = running;
    pending.wmiRunning = false;
    CHECK_EQ(HvciStatus(pending, &text), kWarn);
    CHECK(text.find(L"incompatible") != std::wstring::npos);
    CHECK(text.find(L"restart") != std::wstring::npos);

    HvciFacts pendingByPolicy;   // configured through Group Policy only: WMI says so, registry does not
    pendingByPolicy.wmiOk = true;
    pendingByPolicy.wmiConfigured = true;
    CHECK_EQ(HvciStatus(pendingByPolicy, &text), kWarn);
    CHECK(text.find(L"not running") != std::wstring::npos);

    HvciFacts off;
    off.wmiOk = true;
    off.registryEnabled = Dw(0);
    CHECK_EQ(HvciStatus(off, &text), kWarn);
    CHECK(text.find(L"off") != std::wstring::npos);

    // Device Guard does not answer: never PASS, never ERROR.
    HvciFacts unknownOn;
    unknownOn.registryEnabled = Dw(1);
    CHECK_EQ(HvciStatus(unknownOn, &text), kWarn);
    CHECK(text.find(L"cannot be confirmed") != std::wstring::npos);
    HvciFacts unknownOff;
    CHECK_EQ(HvciStatus(unknownOff, &text), kWarn);
    CHECK(text.find(L"did not answer") != std::wstring::npos);

    // A "running" flag without a WMI answer is not trusted.
    HvciFacts bogus;
    bogus.wmiRunning = true;
    CHECK(HvciStatus(bogus, nullptr) != kPass);
}

// ---------------------------------------------------------------------------
// hard.driverblocklist
// ---------------------------------------------------------------------------
TEST(Platform_DriverBlocklistVerdicts)
{
    std::wstring text;
    DriverBlocklistFacts on;
    on.build = 19045;
    on.enabled = Dw(1);
    CHECK_EQ(DriverBlocklistStatus(on, &text), kPass);

    DriverBlocklistFacts off = on;
    off.build = 26100;
    off.enabled = Dw(0);
    CHECK_EQ(DriverBlocklistStatus(off, &text), kWarn);   // an explicit 0 beats the default
    off.hvciRunning = true;
    CHECK_EQ(DriverBlocklistStatus(off, &text), kWarn);
    CHECK(text.find(L"Memory integrity is running") != std::wstring::npos);

    // Not configured: the default depends on the build and on what else is on.
    DriverBlocklistFacts missing;
    missing.build = 22621;
    CHECK_EQ(DriverBlocklistStatus(missing, &text), kPass);
    CHECK(text.find(L"default") != std::wstring::npos);
    missing.build = 22000;   // Windows 11 21H2
    CHECK_EQ(DriverBlocklistStatus(missing, &text), kWarn);
    missing.build = 19045;   // Windows 10 22H2
    CHECK_EQ(DriverBlocklistStatus(missing, &text), kWarn);
    missing.hvciRunning = true;
    CHECK_EQ(DriverBlocklistStatus(missing, &text), kPass);
    missing.hvciRunning = false;
    missing.smartAppControlOn = true;
    CHECK_EQ(DriverBlocklistStatus(missing, &text), kPass);

    DriverBlocklistFacts server;   // Server 2025 shares a build number with Windows 11 24H2
    server.build = 26100;
    server.isServer = true;
    CHECK_EQ(DriverBlocklistStatus(server, &text), kWarn);

    DriverBlocklistFacts odd;
    odd.build = 26100;
    odd.enabled = Dw(7);
    CHECK_EQ(DriverBlocklistStatus(odd, &text), kWarn);

    DriverBlocklistFacts unreadable;   // the non-admin case if the key were closed
    unreadable.keyReadable = false;
    unreadable.enabled = Dw(1);
    CHECK_EQ(DriverBlocklistStatus(unreadable, &text), kNa);
    CHECK(text.find(L"administrator") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// hard.smartapp
// ---------------------------------------------------------------------------
TEST(Platform_SmartAppControlVerdicts)
{
    std::wstring text;
    SmartAppControlFacts f;
    f.build = 26100;
    f.state = Dw(1);
    CHECK_EQ(SmartAppControlStatus(f, &text), kPass);
    f.state = Dw(0);
    CHECK_EQ(SmartAppControlStatus(f, &text), kWarn);
    CHECK(text.find(L"reset") != std::wstring::npos);
    f.state = Dw(2);   // evaluation: PASS with a note that it does not protect yet
    CHECK_EQ(SmartAppControlStatus(f, &text), kPass);
    CHECK(text.find(L"evaluation") != std::wstring::npos);
    CHECK(text.find(L"does not protect yet") != std::wstring::npos);
    f.state = Dw(5);
    CHECK_EQ(SmartAppControlStatus(f, &text), kWarn);

    SmartAppControlFacts missing;
    missing.build = 22631;
    CHECK_EQ(SmartAppControlStatus(missing, &text), kNa);

    SmartAppControlFacts win10;
    win10.build = 19045;
    win10.state = Dw(0);
    CHECK_EQ(SmartAppControlStatus(win10, &text), kNa);
    CHECK(text.find(L"Windows 10") != std::wstring::npos);

    SmartAppControlFacts win11first;
    win11first.build = 22000;
    CHECK_EQ(SmartAppControlStatus(win11first, &text), kNa);

    SmartAppControlFacts server;
    server.build = 26100;
    server.isServer = true;
    server.state = Dw(0);
    CHECK_EQ(SmartAppControlStatus(server, &text), kNa);

    SmartAppControlFacts closed;
    closed.build = 26100;
    closed.keyReadable = false;
    CHECK_EQ(SmartAppControlStatus(closed, &text), kNa);
    CHECK(text.find(L"administrator") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// hard.exploitprot
// ---------------------------------------------------------------------------
TEST(Platform_ExploitProtectionVerdicts)
{
    // The documented 2-bit fields: 0 default, 1 on, 2 off.
    CHECK_EQ(MitigationField(0, 16), 0);
    CHECK_EQ(MitigationField(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF, 16), 2);
    CHECK_EQ(MitigationField(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON, 16), 1);
    CHECK_EQ(MitigationField(PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_OFF, 20), 2);
    CHECK_EQ(MitigationField(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF, 40), 2);
    CHECK_EQ(MitigationField(PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON, 16), 0);   // another field

    std::vector<std::wstring> lines;
    ExploitProtectionFacts good;
    good.depPolicy = 2;   // OptIn, the client default
    CHECK_EQ(ExploitProtectionStatus(good, &lines), kPass);
    CHECK_EQ(lines.size(), static_cast<size_t>(3));
    good.depPolicy = 3;
    good.sehopDisabled = Dw(0);
    good.mitigationsSet = true;
    good.mitigationOptions = PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON;   // mandatory ASLR: not judged
    CHECK_EQ(ExploitProtectionStatus(good, &lines), kPass);
    CHECK_EQ(lines.size(), static_cast<size_t>(5));

    ExploitProtectionFacts depOff;
    depOff.depPolicy = 0;
    CHECK_EQ(ExploitProtectionStatus(depOff, &lines), kFail);
    CHECK(lines[0].find(L"AlwaysOff") != std::wstring::npos);

    ExploitProtectionFacts sehopOff;
    sehopOff.depPolicy = 1;
    sehopOff.sehopDisabled = Dw(1);
    CHECK_EQ(ExploitProtectionStatus(sehopOff, &lines), kWarn);

    const unsigned long long switchedOff[] = {
        static_cast<unsigned long long>(PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF),
        static_cast<unsigned long long>(PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_OFF),
        static_cast<unsigned long long>(PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF),
    };
    for (unsigned long long off : switchedOff) {
        ExploitProtectionFacts f;
        f.depPolicy = 2;
        f.mitigationsSet = true;
        f.mitigationOptions = off;
        if (ExploitProtectionStatus(f, &lines) != kWarn) tf::Fail(__FILE__, __LINE__, "a field switched off is not a warning");
    }

    // DEP off outweighs everything else.
    ExploitProtectionFacts both = depOff;
    both.sehopDisabled = Dw(1);
    CHECK_EQ(ExploitProtectionStatus(both, &lines), kFail);

    // DEP policy unknown: a warning that says so, not a pass.
    ExploitProtectionFacts unknown;
    CHECK_EQ(ExploitProtectionStatus(unknown, &lines), kWarn);
    CHECK(lines[0].find(L"could not be read") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// acct.screenlock
// ---------------------------------------------------------------------------
static ScreenSaverValues Saver(const wchar_t* active, const wchar_t* secure, const wchar_t* timeout, const wchar_t* exe)
{
    ScreenSaverValues v;
    v.active = active;
    v.secure = secure;
    v.timeout = timeout;
    v.exe = exe;
    return v;
}

TEST(Platform_ScreenLockVerdicts)
{
    std::vector<std::wstring> lines;
    CHECK_EQ(ParseScreenSaverSeconds(L" 600 "), 600L);
    CHECK_EQ(ParseScreenSaverSeconds(L""), -1L);
    CHECK_EQ(ParseScreenSaverSeconds(L"10m"), -1L);

    ScreenLockFacts machine;
    machine.inactivitySecs = Dw(900);
    CHECK_EQ(ScreenLockStatus(machine, &lines), kPass);
    machine.inactivitySecs = Dw(901);
    CHECK_EQ(ScreenLockStatus(machine, &lines), kWarn);
    machine.inactivitySecs = Dw(0);   // 0 means no limit
    CHECK_EQ(ScreenLockStatus(machine, &lines), kWarn);

    ScreenLockFacts saver;
    saver.user = Saver(L"1", L"1", L"600", L"C:\\Windows\\system32\\scrnsave.scr");
    CHECK_EQ(ScreenLockStatus(saver, &lines), kPass);

    // The Windows default on many PCs: active, no screen saver chosen, no password.
    ScreenLockFacts defaults;
    defaults.user = Saver(L"1", L"0", L"60", L"");
    CHECK_EQ(ScreenLockStatus(defaults, &lines), kWarn);
    REQUIRE(lines.size() == 2);
    CHECK(lines[0].find(L"not set") != std::wstring::npos);
    CHECK(lines[1].find(L"none chosen") != std::wstring::npos);

    ScreenLockFacts noPassword = saver;
    noPassword.user.secure = L"0";
    CHECK_EQ(ScreenLockStatus(noPassword, &lines), kWarn);
    ScreenLockFacts slow = saver;
    slow.user.timeout = L"1800";
    CHECK_EQ(ScreenLockStatus(slow, &lines), kWarn);

    // Group Policy copies win over the user's values, both ways.
    ScreenLockFacts policyOff = saver;
    policyOff.policy.secure = L"0";
    CHECK_EQ(ScreenLockStatus(policyOff, &lines), kWarn);
    CHECK(lines[1].find(L"(Group Policy)") != std::wstring::npos);
    ScreenLockFacts policyOn = defaults;
    policyOn.policy = Saver(L"1", L"1", L"900", L"scrnsave.scr");
    CHECK_EQ(ScreenLockStatus(policyOn, &lines), kPass);
    CHECK_EQ(EffectiveScreenSaver(policyOn).timeout, std::wstring(L"900"));

    // Nothing readable or set at all.
    ScreenLockFacts nothing;
    CHECK_EQ(ScreenLockStatus(nothing, &lines), kWarn);
}

// ---------------------------------------------------------------------------
// backup.restore
// ---------------------------------------------------------------------------
TEST(Platform_SystemRestoreVerdicts)
{
    const std::wstring volume = L"\\\\?\\Volume{1a48a56a-a914-41a9-9ffb-69b6429e570c}\\";
    std::vector<std::wstring> list = { L"\\\\?\\Volume{1A48A56A-A914-41A9-9FFB-69B6429E570C}\\:(C%3A)" };
    CHECK(RestoreListCoversVolume(list, volume, L"C:"));
    CHECK(RestoreListCoversVolume({ L"\\\\?\\Volume{ffff}\\:(C%3A)" }, L"", L"C:"));   // by letter when the GUID is unknown
    CHECK(!RestoreListCoversVolume({ L"\\\\?\\Volume{ffff}\\:(D%3A)" }, volume, L"C:"));
    CHECK(!RestoreListCoversVolume({}, volume, L"C:"));

    std::wstring text;
    SystemRestoreFacts admin;
    admin.clientsReadable = true;
    admin.clientsValueSet = true;
    admin.protectedVolumes = list;
    admin.systemVolume = volume;
    admin.systemDrive = L"C:";
    CHECK_EQ(SystemRestoreStatus(admin, &text), kPass);

    SystemRestoreFacts otherDrive = admin;
    otherDrive.protectedVolumes = { L"\\\\?\\Volume{0000}\\:(D%3A)" };
    CHECK_EQ(SystemRestoreStatus(otherDrive, &text), kWarn);
    CHECK(text.find(L"not on for C:") != std::wstring::npos);

    SystemRestoreFacts policy = admin;   // Group Policy off beats the drive list
    policy.policyDisable = Dw(1);
    CHECK_EQ(SystemRestoreStatus(policy, &text), kWarn);
    CHECK(text.find(L"Group Policy") != std::wstring::npos);

    SystemRestoreFacts neverSet = admin;
    neverSet.clientsValueSet = false;
    neverSet.protectedVolumes.clear();
    CHECK_EQ(SystemRestoreStatus(neverSet, &text), kWarn);
    neverSet.sessionInterval = Dw(1);   // the sources disagree: no guess
    CHECK_EQ(SystemRestoreStatus(neverSet, &text), kNa);

    // A normal user cannot read the drive list: N/A with the reason.
    SystemRestoreFacts user;
    user.systemDrive = L"C:";
    user.sessionInterval = Dw(1);
    CHECK_EQ(SystemRestoreStatus(user, &text), kNa);
    CHECK(text.find(L"administrator") != std::wstring::npos);
    user.policyDisable = Dw(1);   // but a policy that turns it off is readable by anyone
    CHECK_EQ(SystemRestoreStatus(user, &text), kWarn);

    SystemRestoreFacts server = admin;
    server.isServer = true;
    CHECK_EQ(SystemRestoreStatus(server, &text), kNa);
}

// ---------------------------------------------------------------------------
// net.wifiopen
// ---------------------------------------------------------------------------
static std::wstring Profile(const wchar_t* auth, const wchar_t* enc, const wchar_t* mode, const wchar_t* extra = L"")
{
    std::wstring xml = L"<?xml version=\"1.0\"?>\r\n<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">"
                       L"<name>Cafe Guest</name><SSIDConfig><SSID><name>Cafe Guest</name></SSID></SSIDConfig>"
                       L"<connectionType>ESS</connectionType>";
    if (mode) xml += std::wstring(L"<connectionMode>") + mode + L"</connectionMode>";
    xml += std::wstring(L"<MSM><security><authEncryption><authentication>") + auth + L"</authentication><encryption>" + enc +
           L"</encryption><useOneX>false</useOneX></authEncryption>" + extra + L"</security></MSM></WLANProfile>";
    return xml;
}

TEST(Platform_WifiProfileParsing)
{
    WlanProfileSummary open = ParseWlanProfileXml(Profile(L"open", L"none", L"auto"));
    CHECK(open.parsed);
    CHECK_EQ(open.authentication, std::wstring(L"open"));
    CHECK_EQ(open.encryption, std::wstring(L"none"));
    CHECK_EQ(open.connectionMode, std::wstring(L"auto"));
    CHECK(IsOpenAutoConnectProfile(open));

    CHECK(!IsOpenAutoConnectProfile(ParseWlanProfileXml(Profile(L"open", L"none", L"manual"))));
    CHECK(!IsOpenAutoConnectProfile(ParseWlanProfileXml(Profile(L"open", L"WEP", L"auto"))));   // open auth with a WEP key
    CHECK(!IsOpenAutoConnectProfile(ParseWlanProfileXml(Profile(L"OWE", L"AES", L"auto"))));    // Enhanced Open is encrypted

    // A missing connectionMode means Windows connects on its own.
    WlanProfileSummary noMode = ParseWlanProfileXml(Profile(L"open", L"none", nullptr));
    CHECK(noMode.connectionModeMissing);
    CHECK(IsOpenAutoConnectProfile(noMode));

    // A secured profile with key material: parsed, not open, and the key goes nowhere.
    const wchar_t* key = L"01000000D08C9DDF0115D1118C7A00C04FC297EB0100000012345678SECRETSECRET";
    std::wstring secured = Profile(L"WPA2PSK", L"AES", L"auto",
        (std::wstring(L"<sharedKey><keyType>passPhrase</keyType><protected>true</protected><keyMaterial>") + key +
         L"</keyMaterial></sharedKey>").c_str());
    WlanProfileSummary s = ParseWlanProfileXml(secured);
    CHECK(s.parsed);
    CHECK_EQ(s.authentication, std::wstring(L"wpa2psk"));
    CHECK(!IsOpenAutoConnectProfile(s));
    for (const std::wstring* field : { &s.authentication, &s.encryption, &s.connectionMode }) {
        CHECK(field->find(L"secret") == std::wstring::npos);
        CHECK(field->size() <= 32);
    }

    // Broken XML is not parsed and never counts as open.
    WlanProfileSummary broken = ParseWlanProfileXml(L"<WLANProfile><authentication>open</authentication>");
    CHECK(!broken.parsed);
    CHECK(!IsOpenAutoConnectProfile(broken));
    CHECK(!ParseWlanProfileXml(L"").parsed);
}

TEST(Platform_OpenWifiVerdicts)
{
    std::wstring text;
    WifiFacts f;
    f.serviceInstalled = true;
    f.apiAvailable = true;
    f.serviceRunning = true;
    f.interfaces = 1;
    f.profilesRead = 3;
    CHECK_EQ(OpenWifiStatus(f, &text), kPass);
    f.openAutoProfiles = { L"Cafe Guest" };
    CHECK_EQ(OpenWifiStatus(f, &text), kWarn);

    WifiFacts unreadable = f;
    unreadable.openAutoProfiles.clear();
    unreadable.profilesRead = 0;
    unreadable.profilesUnreadable = 2;
    CHECK_EQ(OpenWifiStatus(unreadable, &text), kWarn);

    WifiFacts noAdapter = f;
    noAdapter.interfaces = 0;
    CHECK_EQ(OpenWifiStatus(noAdapter, &text), kNa);
    WifiFacts stopped = f;
    stopped.serviceRunning = false;
    CHECK_EQ(OpenWifiStatus(stopped, &text), kNa);
    CHECK(text.find(L"not running") != std::wstring::npos);
    WifiFacts noService;
    CHECK_EQ(OpenWifiStatus(noService, &text), kNa);
    WifiFacts noApi = f;
    noApi.apiAvailable = false;
    CHECK_EQ(OpenWifiStatus(noApi, &text), kNa);
}

// Network names are not user names: the redactor leaves them alone, and still hides
// a user name wherever it appears.
TEST(Platform_WifiNamesAndRedactor)
{
    RedactionTerms terms;
    terms.userName = L"alice";
    terms.computerName = L"ALICE-PC";
    std::wstring detail = L"1 saved Wi-Fi network(s) without a password connect automatically.\n  \"Cafe Guest\" (open, connects automatically)\n";
    CHECK_EQ(RedactText(detail, terms), detail);
    std::wstring named = L"  \"alice hotspot\" (open, connects automatically)\n";
    CHECK_EQ(RedactText(named, terms), std::wstring(L"  \"<user> hotspot\" (open, connects automatically)\n"));
}

// ---------------------------------------------------------------------------
// Catalog text promises
// ---------------------------------------------------------------------------
TEST(Platform_CatalogTexts)
{
    for (const wchar_t* id : { L"hard.hvci", L"hard.driverblocklist", L"hard.smartapp", L"hard.exploitprot", L"acct.screenlock",
                               L"backup.restore", L"net.wifiopen" }) {
        if (!FindCheckInfo(id)) tf::Fail(__FILE__, __LINE__, "no catalog row for " + tf::Narrow(id));
    }
    const CheckInfo* hvci = FindCheckInfo(L"hard.hvci");
    const CheckInfo* sac = FindCheckInfo(L"hard.smartapp");
    const CheckInfo* exploit = FindCheckInfo(L"hard.exploitprot");
    const CheckInfo* restore = FindCheckInfo(L"backup.restore");
    const CheckInfo* wifi = FindCheckInfo(L"net.wifiopen");
    const CheckInfo* lock = FindCheckInfo(L"acct.screenlock");
    REQUIRE(hvci && sac && exploit && restore && wifi && lock);
    CHECK(hvci->fix.find(L"Core isolation") != std::wstring::npos);
    CHECK(hvci->explanation.find(L"incompatible driver") != std::wstring::npos);
    CHECK(sac->severity == Severity::Low);
    CHECK(sac->fix.find(L"Reset this PC") != std::wstring::npos);
    CHECK(exploit->fix.find(L"Set-ProcessMitigation -System") != std::wstring::npos);
    CHECK(exploit->undo.find(L"Set-ProcessMitigation -PolicyFilePath") != std::wstring::npos);
    CHECK(restore->explanation.find(L"not a backup of your personal") != std::wstring::npos);
    CHECK(restore->fix.find(L"Configure") != std::wstring::npos);
    CHECK(wifi->fix.find(L"connectionmode=manual") != std::wstring::npos);
    CHECK(wifi->undo.find(L"connectionmode=auto") != std::wstring::npos);
    CHECK(lock->explanation.find(L"power") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// The real checks on this PC: a verdict or N/A with a reason, never ERROR
// ---------------------------------------------------------------------------
TEST(Platform_ChecksRunHere)
{
    std::vector<SecurityCheckResult> results = {
        CheckMemoryIntegrity(), CheckDriverBlocklist(), CheckSmartAppControl(), CheckExploitProtection(),
        CheckScreenLock(), CheckSystemRestore(), CheckOpenWifi(),
    };
    for (const SecurityCheckResult& r : results) {
        std::printf("    note: %s -> %s\n", tf::Narrow(r.id).c_str(), tf::Narrow(r.status).c_str());
        if (r.status == CHECK_ERROR) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " returned ERROR: " + tf::Narrow(r.detail));
        if (r.detail.empty()) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " has no detail");
        if (!FindCheckInfo(r.id)) tf::Fail(__FILE__, __LINE__, "unknown id " + tf::Narrow(r.id));
        if (r.detail.find(L"keyMaterial") != std::wstring::npos) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " shows key material");
    }
    // Credential Guard still reads Device Guard through the shared helper.
    SecurityCheckResult cg = CheckCredentialGuard();
    CHECK(cg.status != CHECK_ERROR);
}
