// Fixes from the 2026-10-26 review, group 3 (audit checks A): Defender, hardening,
// accounts, logging, firewall, WMI, registry and the check catalog.

#include "TestFramework.h"

#include "AuditRules.h"
#include "CheckCatalog.h"
#include "CheckHelpers.h"
#include "RegUtil.h"
#include "SecurityCheckModules.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <windows.h>
#include <oleauto.h>
#include <tbs.h>
#include <wbemidl.h>

#include <algorithm>
#include <cstdio>
#include <set>

// ---------------------------------------------------------------------------
// C11: encoded PowerShell in every spelling PowerShell accepts
// ---------------------------------------------------------------------------
TEST(FixAudit_EncodedPowerShellShortForms)
{
    std::wstring reason;
    const wchar_t* encoded[] = {
        L"powershell -e SQBFAFgAIAAoAE4AZQB3AA==",
        L"powershell.exe -en SQBFAFgAIAAoAE4AZQB3AA==",
        L"powershell -enco SQBFAFgAIAAoAE4AZQB3AA==",
        L"powershell /enc SQBFAFgAIAAoAE4AZQB3AA==",
        L"powershell -ec SQBFAFgAIAAoAE4AZQB3AA==",
        L"pwsh -EncodedC SQBFAFgAIAAoAE4AZQB3AA==",
        L"powershell \x2013" L"enc SQBFAFgAIAAoAE4AZQB3AA==",          // en dash
        L"powershell --encodedcommand SQBFAFgAIAAoAE4AZQB3AA==",
        L"cmd /c p^owershell -NoP -W 1 -e SQBFAFgAIAAoAE4AZQB3AA==",    // caret escaping
        L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nop -e SQBFAFgA",
        L"\"C:\\Tools\\launcher.exe\" -enc SQBFAFgAIAAoAE4AZQB3AA==",   // long form counts anywhere
        L"runner.exe -e SQBFAFgAIAAoAE4AZQB3AA==",                      // short form, base64 follows
    };
    for (const wchar_t* c : encoded) {
        reason.clear();
        int s = CommandLineSuspicion(c, &reason);
        if (s != 2) tf::Fail(__FILE__, __LINE__, "not flagged as encoded: " + tf::Narrow(c));
        else CHECK_EQ(reason, std::wstring(L"encoded PowerShell command"));
    }

    const wchar_t* clean[] = {
        L"node.exe -e console.log(1)",
        L"xcopy /e C:\\src D:\\dst",
        L"certutil -encode in.txt out.b64",
        L"powershell -NoProfile -Command Select-String -e foo C:\\x.txt",   // -e belongs to the script
        L"powershell -ExecutionPolicy Bypass -File C:\\x.ps1 -e AAAAAAAAAAAA",
        L"\"C:\\Program Files\\App\\app.exe\" --background",
        L"perl -e print",
    };
    for (const wchar_t* c : clean) {
        if (CommandLineSuspicion(c, &reason) >= 2) tf::Fail(__FILE__, __LINE__, "false encoded flag: " + tf::Narrow(c));
    }
    // The old spellings still count.
    CHECK_EQ(CommandLineSuspicion(L"powershell -EncodedCommand AAAA", &reason), 2);
    CHECK_EQ(CommandLineSuspicion(L"powershell.exe -NoProfile -EncodedCommand SQBFAFgA", &reason), 2);
}

// ---------------------------------------------------------------------------
// C13: FileZilla Server and Office components
// ---------------------------------------------------------------------------
static InstalledProgram Program(const wchar_t* name, const wchar_t* version)
{
    InstalledProgram p;
    p.displayName = name;
    p.displayVersion = version;
    return p;
}

static bool Flags(const InstalledProgram& p)
{
    return !FindOutdatedSoftware({ p }, GetBuiltInSoftwareRules()).empty();
}

TEST(FixAudit_SoftwareRulesFileZillaAndOffice)
{
    CHECK(!Flags(Program(L"FileZilla Server", L"1.8.2")));
    CHECK(!Flags(Program(L"FileZilla Server 1.8.2", L"")));
    CHECK(Flags(Program(L"FileZilla 3.66.5", L"3.66.5")));
    CHECK(Flags(Program(L"FileZilla 3.66.5", L"")));              // version read from the name
    CHECK(!Flags(Program(L"FileZilla 3.68.1", L"")));
    CHECK(!Flags(Program(L"FileZilla 3.67.0", L"3.67.0")));
    CHECK(Flags(Program(L"FileZilla Client 3.60.0", L"3.60.0")));
    CHECK(Flags(Program(L"FileZilla Pro 3.66.0", L"3.66.0")));

    // Real suite names are flagged...
    CHECK(Flags(Program(L"Microsoft Office Professional Plus 2016", L"16.0.4266.1001")));
    CHECK(Flags(Program(L"Microsoft Office Professional 2019 - en-us", L"16.0.10417.20030")));
    CHECK(Flags(Program(L"Microsoft Office Home and Student 2019 - en-us", L"16.0.10417.20030")));
    CHECK(Flags(Program(L"Microsoft Office Home and Business 2016 - de-de", L"16.0.4266.1001")));
    CHECK(Flags(Program(L"Microsoft Office Standard 2013", L"15.0.4569.1506")));
    CHECK(Flags(Program(L"Microsoft Office Starter 2010 - English", L"14.0.4763.1000")));
    CHECK(Flags(Program(L"microsoft office professional plus 2010", L"")));
    // ...their parts and current Office are not.
    CHECK(!Flags(Program(L"Microsoft Office Proofing Tools 2016 - English", L"16.0.4266.1001")));
    CHECK(!Flags(Program(L"Microsoft Office 64-bit Components 2016", L"16.0.4266.1001")));
    CHECK(!Flags(Program(L"Microsoft Office Shared MUI (English) 2016", L"16.0.4266.1001")));
    CHECK(!Flags(Program(L"Microsoft Office OSM UX MUI (English) 2016", L"16.0.4266.1001")));
    CHECK(!Flags(Program(L"Microsoft 365 Apps for enterprise - en-us", L"16.0.19127.20000")));
    CHECK(!Flags(Program(L"Microsoft Office Professional Plus 2024 - en-us", L"16.0.17932.20000")));

    // Patterns in a user rule file work the same way; plain names stay prefixes.
    std::vector<SoftwareRule> mine = ParseSoftwareRules(L"Acme * Viewer|5.0|old\r\nBeta Tool||end of life\r\n");
    REQUIRE(mine.size() == 2);
    CHECK_EQ(FindOutdatedSoftware({ Program(L"Acme Image Viewer", L"4.2") }, mine).size(), static_cast<size_t>(1));
    CHECK_EQ(FindOutdatedSoftware({ Program(L"Acme Image Viewer", L"5.1") }, mine).size(), static_cast<size_t>(0));
    CHECK_EQ(FindOutdatedSoftware({ Program(L"Acme Image Viewer Plugin", L"1.0") }, mine).size(), static_cast<size_t>(0));
    CHECK_EQ(FindOutdatedSoftware({ Program(L"Beta Tool Pro", L"9") }, mine).size(), static_cast<size_t>(1));
}

// ---------------------------------------------------------------------------
// A13, A14: fix texts
// ---------------------------------------------------------------------------
TEST(FixAudit_CatalogFixTextsKeepReadAccess)
{
    const CheckInfo* svc = FindCheckInfo(L"svc.writable");
    const CheckInfo* dll = FindCheckInfo(L"dll.hijack");
    REQUIRE(svc != nullptr && dll != nullptr);
    for (const CheckInfo* info : { svc, dll }) {
        std::string id = tf::Narrow(info->id);
        // /remove:g drops read and run access as well as write.
        if (info->fix.find(L"/remove:g") != std::wstring::npos) tf::Fail(__FILE__, __LINE__, id + " still removes all access");
        CHECK(info->fix.find(L"/save acl-backup.txt") != std::wstring::npos);
        CHECK(info->fix.find(L"/inheritance:d") != std::wstring::npos);
        CHECK(info->fix.find(L"/grant:r") != std::wstring::npos);
        CHECK(info->undo.find(L"/restore acl-backup.txt") != std::wstring::npos);
    }
    CHECK(svc->fix.find(L"\"*S-1-5-11:(RX)\"") != std::wstring::npos);            // a file: no inheritance flags
    CHECK(dll->fix.find(L"\"*S-1-5-11:(OI)(CI)(RX)\"") != std::wstring::npos);    // a folder: children too

    const CheckInfo* ppl = FindCheckInfo(L"lsa.ppl");
    REQUIRE(ppl != nullptr);
    CHECK(ppl->fix.find(L"-Name RunAsPPL -Value 2 -Type DWord") != std::wstring::npos);
    CHECK(ppl->fix.find(L"-Value 1 -Type DWord") == std::wstring::npos);          // the UEFI-locked value is not the command
    CHECK(ppl->fix.find(L"LSAPPLConfig.efi") != std::wstring::npos);
    CHECK(ppl->undo.find(L"LSAPPLConfig.efi") != std::wstring::npos);
    CHECK(ppl->undo.find(L"Remove-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// C15, G2: Defender with another antivirus, in passive mode, or unreadable
// ---------------------------------------------------------------------------
static DefenderFacts Facts(bool statusOk, const wchar_t* mode, bool securityCenterOk, bool otherOn)
{
    DefenderFacts f;
    f.statusOk = statusOk;
    f.runningMode = mode;
    f.securityCenterOk = securityCenterOk;
    f.otherProductOn = otherOn;
    return f;
}

TEST(FixAudit_DefenderNotPrimary)
{
    CHECK(IsDefenderPrimaryMode(L"Normal"));
    CHECK(IsDefenderPrimaryMode(L""));
    CHECK(!IsDefenderPrimaryMode(L"Passive Mode"));
    CHECK(!IsDefenderPrimaryMode(L"SxS Passive Mode"));
    CHECK(!IsDefenderPrimaryMode(L"EDR Block Mode"));
    CHECK(!IsDefenderPrimaryMode(L"Not running"));

    // Defender in charge: judge its own settings.
    DefenderFacts normal = Facts(true, L"Normal", true, false);
    CHECK(ClassifyDefender(normal) == DefenderSituation::Primary);
    CHECK(DefenderRealtimeStatus(normal).empty());
    CHECK(DefenderSettingStatus(normal).empty());

    // Another antivirus is on and Defender says "Not running": was a FAIL.
    DefenderFacts other = Facts(true, L"Not running", true, true);
    CHECK(ClassifyDefender(other) == DefenderSituation::OtherProduct);
    CHECK_EQ(DefenderRealtimeStatus(other), std::wstring(CHECK_PASS));
    CHECK_EQ(DefenderSettingStatus(other), std::wstring(CHECK_NA));
    CHECK_EQ(DefenderRealtimeStatus(Facts(true, L"Passive Mode", true, true)), std::wstring(CHECK_PASS));
    CHECK_EQ(DefenderRealtimeStatus(Facts(false, L"", true, true)), std::wstring(CHECK_PASS));

    // Server with another antivirus: Defender passive, no Security Center to ask.
    DefenderFacts server = Facts(true, L"Passive Mode", false, false);
    CHECK(ClassifyDefender(server) == DefenderSituation::PassiveNoProduct);
    CHECK_EQ(DefenderRealtimeStatus(server), std::wstring(CHECK_WARNING));
    CHECK_EQ(DefenderSettingStatus(server), std::wstring(CHECK_NA));

    // No Defender data at all (the CI runner case): N/A for settings, never ERROR.
    DefenderFacts noData = Facts(false, L"", false, false);
    CHECK(ClassifyDefender(noData) == DefenderSituation::Unreadable);
    CHECK_EQ(DefenderSettingStatus(noData), std::wstring(CHECK_NA));
    CHECK_EQ(DefenderRealtimeStatus(noData), std::wstring(CHECK_WARNING));

    // A client where Security Center answers and nothing is on: no protection.
    CHECK_EQ(DefenderRealtimeStatus(Facts(false, L"", true, false)), std::wstring(CHECK_FAIL));
    CHECK_EQ(DefenderRealtimeStatus(Facts(true, L"Not running", true, false)), std::wstring(CHECK_FAIL));

    // Security Center productState: bits 12-15 = 1 means on.
    CHECK(SecurityCenterProductOn(397568));    // 0x61100
    CHECK(SecurityCenterProductOn(266240));    // 0x41000
    CHECK(!SecurityCenterProductOn(393472));   // 0x60100
    CHECK(!SecurityCenterProductOn(0));
}

// On this PC the Defender checks give a verdict or N/A, never ERROR.
TEST(FixAudit_DefenderChecksNeverError)
{
    std::vector<SecurityCheckResult> results = {
        CheckDefenderRealtime(), CheckDefenderTamper(), CheckDefenderCloud(), CheckDefenderSignatures(),
        CheckDefenderExclusions(), CheckDefenderAsr(), CheckControlledFolderAccess(),
    };
    for (const SecurityCheckResult& r : results) {
        if (r.status == CHECK_ERROR) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " returned ERROR: " + tf::Narrow(r.detail));
        if (r.detail.empty()) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " has no detail");
        if (r.status == CHECK_NA && r.detail.find(L"not judged") == std::wstring::npos &&
            r.detail.find(L"could not be read") == std::wstring::npos) {
            tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " is N/A without a reason: " + tf::Narrow(r.detail));
        }
    }
}

// ---------------------------------------------------------------------------
// Section H: controlled folder access modes, UAC secure desktop
// ---------------------------------------------------------------------------
TEST(FixAudit_ControlledFolderAccessModes)
{
    std::wstring text;
    CHECK_EQ(ControlledFolderAccessStatus(0, &text), std::wstring(CHECK_WARNING));
    CHECK(text.find(L"off") != std::wstring::npos);
    CHECK_EQ(ControlledFolderAccessStatus(1, &text), std::wstring(CHECK_PASS));
    CHECK_EQ(ControlledFolderAccessStatus(2, &text), std::wstring(CHECK_INFO));
    CHECK(text.find(L"audit") != std::wstring::npos);
    // Modes 3 and 4 were shown as "off".
    CHECK_EQ(ControlledFolderAccessStatus(3, &text), std::wstring(CHECK_WARNING));
    CHECK(text.find(L"disk sectors") != std::wstring::npos && text.find(L"is off") == std::wstring::npos);
    CHECK_EQ(ControlledFolderAccessStatus(4, &text), std::wstring(CHECK_WARNING));
    CHECK(text.find(L"audits") != std::wstring::npos && text.find(L"is off") == std::wstring::npos);
    CHECK_EQ(ControlledFolderAccessStatus(9, &text), std::wstring(CHECK_WARNING));
    CHECK(text.find(L"unknown mode (9)") != std::wstring::npos);
}

TEST(FixAudit_UacSecureDesktop)
{
    CHECK(UacUsesSecureDesktop(1, 0));    // credentials on the secure desktop
    CHECK(UacUsesSecureDesktop(2, 0));    // consent on the secure desktop
    CHECK(UacUsesSecureDesktop(5, 1));
    CHECK(!UacUsesSecureDesktop(5, 0));
    CHECK(!UacUsesSecureDesktop(4, 0));
    CHECK(!UacUsesSecureDesktop(3, 0));
}

// ---------------------------------------------------------------------------
// Section H: TPM service stopped
// ---------------------------------------------------------------------------
TEST(FixAudit_TpmServiceStoppedIsNotNoTpm)
{
    CHECK(ClassifyTbsResult(TBS_SUCCESS) == TbsOutcome::Present);
    CHECK(ClassifyTbsResult(static_cast<TBS_RESULT>(TBS_E_TPM_NOT_FOUND)) == TbsOutcome::NoTpm);
    CHECK(ClassifyTbsResult(static_cast<TBS_RESULT>(TBS_E_SERVICE_NOT_RUNNING)) == TbsOutcome::ServiceUnavailable);
    CHECK(ClassifyTbsResult(static_cast<TBS_RESULT>(TBS_E_SERVICE_DISABLED)) == TbsOutcome::ServiceUnavailable);
    CHECK(ClassifyTbsResult(static_cast<TBS_RESULT>(TBS_E_SERVICE_START_PENDING)) == TbsOutcome::ServiceUnavailable);
    CHECK(ClassifyTbsResult(static_cast<TBS_RESULT>(TBS_E_INTERNAL_ERROR)) == TbsOutcome::Error);
    CHECK_EQ(TpmStatusWithoutTbs(1), std::wstring(CHECK_WARNING));    // a TPM device exists
    CHECK_EQ(TpmStatusWithoutTbs(-1), std::wstring(CHECK_WARNING));   // cannot tell
    CHECK_EQ(TpmStatusWithoutTbs(0), std::wstring(CHECK_FAIL));       // driver sees none

    SecurityCheckResult tpm = CheckTpm();
    CHECK(tpm.status != CHECK_ERROR || tpm.detail.find(L"TBS 0x") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// C22: Credential Guard on Home and Pro
// ---------------------------------------------------------------------------
TEST(FixAudit_CredentialGuardEditions)
{
    for (const wchar_t* e : { L"Core", L"CoreN", L"CoreSingleLanguage", L"CoreCountrySpecific", L"Professional",
                              L"ProfessionalN", L"ProfessionalSingleLanguage" }) {
        if (CredentialGuardEditionSupport(e) != EditionSupport::NotSupported) {
            tf::Fail(__FILE__, __LINE__, "should not support Credential Guard: " + tf::Narrow(e));
        }
    }
    for (const wchar_t* e : { L"Enterprise", L"EnterpriseN", L"EnterpriseS", L"Education", L"EducationN",
                              L"ProfessionalEducation", L"ServerStandard", L"ServerDatacenter", L"IoTEnterprise" }) {
        if (CredentialGuardEditionSupport(e) != EditionSupport::Supported) {
            tf::Fail(__FILE__, __LINE__, "should support Credential Guard: " + tf::Narrow(e));
        }
    }
    CHECK(CredentialGuardEditionSupport(L"ProfessionalWorkstation") == EditionSupport::Unknown);
    CHECK(CredentialGuardEditionSupport(L"") == EditionSupport::Unknown);
    CHECK(CredentialGuardEditionSupport(L"SomethingNew") == EditionSupport::Unknown);

    // On this PC: an edition that cannot run it never gets a WARNING.
    std::wstring edition = RegReadString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"EditionID");
    SecurityCheckResult r = CheckCredentialGuard();
    std::printf("    note: edition %s, Credential Guard %s\n", tf::Narrow(edition).c_str(), tf::Narrow(r.status).c_str());
    CHECK(r.status != CHECK_ERROR);
    if (CredentialGuardEditionSupport(edition) == EditionSupport::NotSupported) {
        CHECK(r.status != CHECK_WARNING);
        if (r.status == CHECK_NA) CHECK(r.detail.find(edition) != std::wstring::npos);
    }
}

// ---------------------------------------------------------------------------
// Section H: missing WPAD value
// ---------------------------------------------------------------------------
TEST(FixAudit_WpadMissingValueIsNotPass)
{
    CHECK_EQ(WpadStatus(false, false, false), std::wstring(CHECK_WARNING));   // was PASS
    CHECK_EQ(WpadStatus(false, false, true), std::wstring(CHECK_WARNING));
    CHECK_EQ(WpadStatus(true, true, false), std::wstring(CHECK_FAIL));
    CHECK_EQ(WpadStatus(true, true, true), std::wstring(CHECK_WARNING));
    CHECK_EQ(WpadStatus(true, false, false), std::wstring(CHECK_PASS));
}

// ---------------------------------------------------------------------------
// C18: security log size without admin rights, and from Group Policy
// ---------------------------------------------------------------------------
TEST(FixAudit_SecurityLogSize)
{
    LogSizeFacts none;
    CHECK(!EffectiveSecurityLogSize(none).known);   // was reported as "20 MB"

    LogSizeFacts channel;
    channel.channelKnown = true;
    channel.channelBytes = 20971520;
    LogSize s = EffectiveSecurityLogSize(channel);
    CHECK(s.known);
    CHECK_EQ(s.bytes, 20971520ull);
    CHECK_EQ(s.source, std::wstring(L"log settings"));

    LogSizeFacts policy = channel;
    policy.policyKb.set = true;
    policy.policyKb.value = 196608;   // KB, as the policy stores it
    policy.legacyBytes.set = true;
    policy.legacyBytes.value = 1048576;
    s = EffectiveSecurityLogSize(policy);
    CHECK_EQ(s.bytes, 196608ull * 1024ull);
    CHECK_EQ(s.source, std::wstring(L"Group Policy"));

    LogSizeFacts legacy;
    legacy.legacyBytes.set = true;
    legacy.legacyBytes.value = 209715200;
    s = EffectiveSecurityLogSize(legacy);
    CHECK(s.known);
    CHECK_EQ(s.bytes, 209715200ull);
    CHECK_EQ(s.source, std::wstring(L"registry"));

    // On this PC the size comes from a real source, never the old "default (20 MB)" guess.
    SecurityCheckResult r = CheckEventLogSettings();
    CHECK(r.detail.find(L"default (20 MB)") == std::wstring::npos);
    CHECK(r.detail.find(L"Security log maximum size: ") != std::wstring::npos);
    CHECK(r.detail.find(L"MB (from ") != std::wstring::npos || r.detail.find(L"could not be read") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// C19: Remote Desktop settings from Group Policy
// ---------------------------------------------------------------------------
static OptionalDword Set(DWORD v)
{
    OptionalDword o;
    o.set = true;
    o.value = v;
    return o;
}

TEST(FixAudit_RdpGroupPolicyWins)
{
    RdpFacts none;
    RdpState s = EffectiveRdp(none);
    CHECK(!s.enabled);

    RdpFacts localOn;
    localOn.localDeny = Set(0);
    localOn.localNla = Set(1);
    s = EffectiveRdp(localOn);
    CHECK(s.enabled && !s.enabledByPolicy && s.nlaRequired && !s.nlaByPolicy);

    RdpFacts policyOn;            // local says off, policy allows it
    policyOn.localDeny = Set(1);
    policyOn.policyDeny = Set(0);
    policyOn.localNla = Set(1);
    policyOn.policyNla = Set(0);  // and policy turns NLA off
    s = EffectiveRdp(policyOn);
    CHECK(s.enabled && s.enabledByPolicy);
    CHECK(!s.nlaRequired && s.nlaByPolicy);

    RdpFacts policyOff;           // local says on, policy denies it
    policyOff.localDeny = Set(0);
    policyOff.policyDeny = Set(1);
    s = EffectiveRdp(policyOff);
    CHECK(!s.enabled && s.enabledByPolicy);

    SecurityCheckResult r = CheckRemoteDesktop();
    CHECK(r.status == CHECK_PASS || r.status == CHECK_WARNING || r.status == CHECK_FAIL);
}

// ---------------------------------------------------------------------------
// C17: WinRM listeners that cannot be read
// ---------------------------------------------------------------------------
TEST(FixAudit_WinRmUnreadableListeners)
{
    CHECK_EQ(WinRmStatus(true, false, -1, false), std::wstring(CHECK_WARNING));   // was PASS
    CHECK_EQ(WinRmStatus(false, true, -1, false), std::wstring(CHECK_WARNING));
    CHECK_EQ(WinRmStatus(false, false, -1, false), std::wstring(CHECK_PASS));     // stopped, manual: nothing listens
    CHECK_EQ(WinRmStatus(true, false, 0, false), std::wstring(CHECK_PASS));
    CHECK_EQ(WinRmStatus(true, false, 0, true), std::wstring(CHECK_WARNING));     // policy creates listeners
    CHECK_EQ(WinRmStatus(false, true, 2, false), std::wstring(CHECK_WARNING));

    // RegOpenStatus tells "missing" from "not allowed". HKLM\SECURITY is closed even to administrators.
    CHECK_EQ(RegOpenStatus(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion"), static_cast<LONG>(ERROR_SUCCESS));
    CHECK_EQ(RegOpenStatus(HKEY_LOCAL_MACHINE, L"SOFTWARE\\PhantomRecon-no-such-key-6c1f"), static_cast<LONG>(ERROR_FILE_NOT_FOUND));
    CHECK_EQ(RegOpenStatus(HKEY_LOCAL_MACHINE, L"SECURITY"), static_cast<LONG>(ERROR_ACCESS_DENIED));

    SecurityCheckResult r = CheckWinRm();
    CHECK(r.status != CHECK_ERROR);
    CHECK(!r.detail.empty());
}

// ---------------------------------------------------------------------------
// C20: localized built-in Administrator names
// ---------------------------------------------------------------------------
TEST(FixAudit_AdministratorDefaultNames)
{
    CHECK(IsDefaultAdministratorName(L"Administrator", L"Administrators"));
    CHECK(IsDefaultAdministratorName(L"ADMINISTRATOR", L""));
    CHECK(IsDefaultAdministratorName(L"Administrateur", L""));
    CHECK(IsDefaultAdministratorName(L"Administrador", L""));
    CHECK(IsDefaultAdministratorName(L"Amministratore", L""));
    CHECK(IsDefaultAdministratorName(L"Administrat\x00f6r", L""));
    CHECK(IsDefaultAdministratorName(L"J\x00e4rjestelm\x00e4nvalvoja", L""));
    CHECK(IsDefaultAdministratorName(L"\x0410\x0434\x043c\x0438\x043d\x0438\x0441\x0442\x0440\x0430\x0442\x043e\x0440", L""));
    // Unknown languages: the group is the plural of the account.
    CHECK(IsDefaultAdministratorName(L"Verwalter", L"Verwalters"));
    // Renamed accounts.
    CHECK(!IsDefaultAdministratorName(L"Admin", L"Administrators"));
    CHECK(!IsDefaultAdministratorName(L"HelpDesk", L"Administrators"));
    CHECK(!IsDefaultAdministratorName(L"Admin", L"Administrateurs"));
    CHECK(!IsDefaultAdministratorName(L"", L"Administrators"));

    SecurityCheckResult r = CheckBuiltinAdministrator();
    CHECK(r.status != CHECK_ERROR);
}

// ---------------------------------------------------------------------------
// C16: third-party firewall
// ---------------------------------------------------------------------------
TEST(FixAudit_ThirdPartyFirewall)
{
    CHECK_EQ(FirewallStatus(true, false, true), std::wstring(CHECK_NA));    // was FAIL
    CHECK_EQ(FirewallStatus(false, true, true), std::wstring(CHECK_NA));
    CHECK_EQ(FirewallStatus(true, false, false), std::wstring(CHECK_FAIL));
    CHECK_EQ(FirewallStatus(false, true, false), std::wstring(CHECK_FAIL));
    CHECK_EQ(FirewallStatus(false, false, true), std::wstring(CHECK_PASS));
    CHECK_EQ(FirewallStatus(false, false, false), std::wstring(CHECK_PASS));

    SecurityCheckResult r = CheckWindowsFirewall();
    CHECK(r.status != CHECK_ERROR);
}

// ---------------------------------------------------------------------------
// Section H: REG_QWORD values
// ---------------------------------------------------------------------------
// Removes the scratch key and, when nothing else is left in it, its parent, so the
// test leaves the user's registry as it found it.
static const wchar_t* const kTestRegParent = L"Software\\PhantomReconTests";

struct TestRegKey {
    std::wstring path;
    explicit TestRegKey(const std::wstring& p) : path(p) {}
    ~TestRegKey()
    {
        RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str());
        RegDeleteKeyW(HKEY_CURRENT_USER, path.c_str());
        RegDeleteKeyW(HKEY_CURRENT_USER, kTestRegParent);   // fails harmlessly if not empty
    }
};

TEST(FixAudit_RegReadDwordTakesQword)
{
    std::wstring path = std::wstring(kTestRegParent) + L"\\Qword" + std::to_wstring(GetCurrentProcessId());
    TestRegKey guard(path);
    HKEY key = NULL;
    REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &key, NULL) == ERROR_SUCCESS);
    ULONGLONG q = 0x100000005ull;
    DWORD d = 7;
    const wchar_t text[] = L"x";
    RegSetValueExW(key, L"Q", 0, REG_QWORD, reinterpret_cast<const BYTE*>(&q), sizeof(q));
    RegSetValueExW(key, L"D", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&d), sizeof(d));
    RegSetValueExW(key, L"S", 0, REG_SZ, reinterpret_cast<const BYTE*>(text), sizeof(text));
    RegCloseKey(key);

    DWORD out = 0;
    CHECK(RegReadDword(HKEY_CURRENT_USER, path, L"Q", out));   // the QWORD branch could never run before
    CHECK_EQ(out, static_cast<DWORD>(5));
    out = 0;
    CHECK(RegReadDword(HKEY_CURRENT_USER, path, L"D", out));
    CHECK_EQ(out, static_cast<DWORD>(7));
    CHECK(!RegReadDword(HKEY_CURRENT_USER, path, L"S", out));
    CHECK(!RegReadDword(HKEY_CURRENT_USER, path, L"Missing", out));
}

// Runs after the test above (tests run in file order): nothing may be left behind.
TEST(FixAudit_RegTestLeavesNoKey)
{
    CHECK_EQ(RegOpenStatus(HKEY_CURRENT_USER, kTestRegParent), static_cast<LONG>(ERROR_FILE_NOT_FOUND));
}

// ---------------------------------------------------------------------------
// C21: a WMI timeout is not "no rows, success"
// ---------------------------------------------------------------------------
TEST(FixAudit_WmiTimeoutIsNotSuccess)
{
    WmiResult r;
    r.ok = true;
    CHECK(!WmiAcceptNextResult(WBEM_S_TIMEDOUT, 0, L"SELECT * FROM Slow", r));
    CHECK(!r.ok);
    CHECK(r.timedOut);
    CHECK(r.error.find(L"timed out") != std::wstring::npos);

    WmiResult partial;
    partial.ok = true;
    partial.rows.push_back(WmiRow());
    CHECK(!WmiAcceptNextResult(WBEM_S_TIMEDOUT, 0, L"SELECT * FROM Slow", partial));
    CHECK(!partial.ok);                      // incomplete, even with rows
    CHECK_EQ(partial.rows.size(), static_cast<size_t>(1));

    WmiResult end;
    end.ok = true;
    CHECK(!WmiAcceptNextResult(WBEM_S_FALSE, 0, L"q", end));   // normal end of rows
    CHECK(end.ok);
    CHECK(!end.timedOut);

    WmiResult row;
    row.ok = true;
    CHECK(WmiAcceptNextResult(WBEM_S_NO_ERROR, 1, L"q", row));
    CHECK(row.ok);

    WmiResult failed;
    failed.ok = true;
    CHECK(!WmiAcceptNextResult(WBEM_E_FAILED, 0, L"q", failed));
    CHECK(!failed.ok);

    // A real query still works end to end.
    WmiResult os = WmiQuery(L"ROOT\\CIMV2", L"SELECT Caption FROM Win32_OperatingSystem", { L"Caption" });
    CHECK(os.ok);
    CHECK(!os.timedOut);
    CHECK_EQ(os.rows.size(), static_cast<size_t>(1));
}

// ---------------------------------------------------------------------------
// I7: arrays of interface pointers keep their references
// ---------------------------------------------------------------------------
struct CountingUnknown : public IUnknown {
    LONG refs = 1;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (riid == IID_IUnknown) {
            *ppv = static_cast<IUnknown*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(++refs); }
    ULONG STDMETHODCALLTYPE Release() override { return static_cast<ULONG>(--refs); }   // lives on the stack
};

TEST(FixAudit_WmiArrayOfInterfacesKeepsReference)
{
    CountingUnknown a, b;
    SAFEARRAY* sa = SafeArrayCreateVector(VT_UNKNOWN, 0, 2);
    REQUIRE(sa != nullptr);
    LONG i0 = 0, i1 = 1;
    REQUIRE(SUCCEEDED(SafeArrayPutElement(sa, &i0, static_cast<IUnknown*>(&a))));
    REQUIRE(SUCCEEDED(SafeArrayPutElement(sa, &i1, static_cast<IUnknown*>(&b))));
    CHECK_EQ(a.refs, 2L);   // ours plus the array's

    VARIANT v;
    VariantInit(&v);
    v.vt = VT_ARRAY | VT_UNKNOWN;
    v.parray = sa;
    WmiVariantToText(v);
    WmiVariantToText(v);
    // SafeArrayGetElement gives a copy with its own reference, which VariantClear
    // releases: the array's reference is untouched.
    CHECK_EQ(a.refs, 2L);
    CHECK_EQ(b.refs, 2L);
    SafeArrayDestroy(sa);
    CHECK_EQ(a.refs, 1L);
    CHECK_EQ(b.refs, 1L);

    // Plain element types still convert.
    SAFEARRAY* ints = SafeArrayCreateVector(VT_I4, 0, 2);
    REQUIRE(ints != nullptr);
    LONG one = 1, two = 2;
    SafeArrayPutElement(ints, &i0, &one);
    SafeArrayPutElement(ints, &i1, &two);
    VARIANT vi;
    VariantInit(&vi);
    vi.vt = VT_ARRAY | VT_I4;
    vi.parray = ints;
    CHECK_EQ(WmiVariantToText(vi), std::wstring(L"1\n2"));
    SafeArrayDestroy(ints);

    SAFEARRAY* bools = SafeArrayCreateVector(VT_BOOL, 0, 2);
    REQUIRE(bools != nullptr);
    VARIANT_BOOL t = VARIANT_TRUE, f = VARIANT_FALSE;
    SafeArrayPutElement(bools, &i0, &t);
    SafeArrayPutElement(bools, &i1, &f);
    VARIANT vb;
    VariantInit(&vb);
    vb.vt = VT_ARRAY | VT_BOOL;
    vb.parray = bools;
    CHECK_EQ(WmiVariantToText(vb), std::wstring(L"True\nFalse"));
    SafeArrayDestroy(bools);

    SAFEARRAY* strings = SafeArrayCreateVector(VT_BSTR, 0, 2);
    REQUIRE(strings != nullptr);
    BSTR s0 = SysAllocString(L"alpha");
    BSTR s1 = SysAllocString(L"beta");
    SafeArrayPutElement(strings, &i0, s0);
    SafeArrayPutElement(strings, &i1, s1);
    SysFreeString(s0);
    SysFreeString(s1);
    VARIANT vs;
    VariantInit(&vs);
    vs.vt = VT_ARRAY | VT_BSTR;
    vs.parray = strings;
    CHECK_EQ(WmiVariantToText(vs), std::wstring(L"alpha\nbeta"));
    SafeArrayDestroy(strings);

    // DECIMAL elements are wider than the slot the raw read uses: skipped, no overrun.
    SAFEARRAY* decimals = SafeArrayCreateVector(VT_DECIMAL, 0, 2);
    REQUIRE(decimals != nullptr);
    VARIANT vd;
    VariantInit(&vd);
    vd.vt = VT_ARRAY | VT_DECIMAL;
    vd.parray = decimals;
    CHECK_EQ(WmiVariantToText(vd), std::wstring());
    SafeArrayDestroy(decimals);
}

// ---------------------------------------------------------------------------
// G3: every check function has a catalog row, in the raw function list
// ---------------------------------------------------------------------------
TEST(FixAudit_CheckFunctionIdsMatchCatalog)
{
    std::vector<std::wstring> functions = GetCheckFunctionIds();
    std::set<std::wstring> functionSet(functions.begin(), functions.end());
    CHECK_EQ(functionSet.size(), functions.size());
    std::set<std::wstring> catalogSet;
    for (const CheckInfo& info : GetCheckCatalog()) catalogSet.insert(info.id);
    for (const std::wstring& id : functionSet) {
        if (catalogSet.find(id) == catalogSet.end()) tf::Fail(__FILE__, __LINE__, "function without catalog row: " + tf::Narrow(id));
    }
    for (const std::wstring& id : catalogSet) {
        if (functionSet.find(id) == functionSet.end()) tf::Fail(__FILE__, __LINE__, "catalog row without function: " + tf::Narrow(id));
    }
    CHECK_EQ(GetRegisteredChecks().size(), catalogSet.size());
}

// ---------------------------------------------------------------------------
// The changed checks on this PC: well-formed answers, none ERROR
// ---------------------------------------------------------------------------
TEST(FixAudit_ChangedChecksRunHere)
{
    std::vector<SecurityCheckResult> results = {
        CheckUac(), CheckLsaProtection(), CheckProxyAutoDetect(), CheckCredentialGuard(), CheckEventLogSettings(),
        CheckWindowsFirewall(), CheckRemoteDesktop(), CheckWinRm(), CheckBuiltinAdministrator(), CheckTpm(),
    };
    for (const SecurityCheckResult& r : results) {
        std::printf("    note: %s -> %s\n", tf::Narrow(r.id).c_str(), tf::Narrow(r.status).c_str());
        if (r.status == CHECK_ERROR) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " returned ERROR: " + tf::Narrow(r.detail));
        if (r.detail.empty()) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " has no detail");
        if (!FindCheckInfo(r.id)) tf::Fail(__FILE__, __LINE__, "unknown id " + tf::Narrow(r.id));
    }
}
