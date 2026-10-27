// The second platform pack: shared folders, SMB guest and anonymous access, inbound
// firewall rules on public networks, automatic sign-in, NTLM settings and driver
// services. Verdicts are judged on crafted facts (HostRules.cpp); the real checks are
// only required to answer well on this PC.

#include "TestFramework.h"

#include "CheckCatalog.h"
#include "FixScript.h"
#include "HostRules.h"
#include "Redactor.h"
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

static const std::wstring kPass = CHECK_PASS;
static const std::wstring kWarn = CHECK_WARNING;
static const std::wstring kFail = CHECK_FAIL;
static const std::wstring kNa = CHECK_NA;

// ---------------------------------------------------------------------------
// net.shares
// ---------------------------------------------------------------------------
static ShareAce Ace(AccountKind who, bool allow, DWORD mask, const wchar_t* sid)
{
    ShareAce a;
    a.who = who;
    a.allow = allow;
    a.mask = mask;
    a.sid = sid;
    return a;
}

static const DWORD kShareRead = 0x001200A9;     // what the Read box stores
static const DWORD kShareChange = 0x001301BF;   // Change
static const DWORD kShareFull = 0x001F01FF;     // Full Control

static SharePermissions Perms(std::vector<ShareAce> aces)
{
    SharePermissions p;
    p.known = true;
    p.aces = std::move(aces);
    return p;
}

TEST(Host_AdminSharesAreSkipped)
{
    CHECK(IsDefaultAdminShare(L"C$", 0));
    CHECK(IsDefaultAdminShare(L"d$", 0));
    CHECK(IsDefaultAdminShare(L"ADMIN$", 0));
    CHECK(IsDefaultAdminShare(L"IPC$", 3));
    CHECK(IsDefaultAdminShare(L"print$", 0));
    CHECK(IsDefaultAdminShare(L"Anything", kShareTypeSpecial));
    CHECK(!IsDefaultAdminShare(L"Data$", 0));      // a hidden share a person made
    CHECK(!IsDefaultAdminShare(L"Users", 0));
    CHECK(!IsDefaultAdminShare(L"CC$", 0));
    CHECK(IsDiskShare(0));
    CHECK(IsDiskShare(kShareTypeSpecial));
    CHECK(!IsDiskShare(1));   // printer
    CHECK(!IsDiskShare(3));   // IPC
}

TEST(Host_ShareChangeGrants)
{
    // Everyone Full Control, as on this PC's own shares.
    std::vector<ShareGrant> g = BroadShareChangeGrants(Perms({ Ace(AccountKind::Everyone, true, kShareFull, L"S-1-1-0") }));
    REQUIRE(g.size() == 1);
    CHECK(g[0].who == AccountKind::Everyone);
    CHECK(g[0].full);
    CHECK_EQ(g[0].sid, std::wstring(L"S-1-1-0"));

    // Read only, and administrators only: nothing broad can change files.
    CHECK(BroadShareChangeGrants(Perms({ Ace(AccountKind::Everyone, true, kShareRead, L"S-1-1-0") })).empty());
    CHECK(BroadShareChangeGrants(Perms({ Ace(AccountKind::Other, true, kShareFull, L"S-1-5-32-544") })).empty());

    // Change, not Full.
    g = BroadShareChangeGrants(Perms({ Ace(AccountKind::AuthenticatedUsers, true, kShareChange, L"S-1-5-11") }));
    REQUIRE(g.size() == 1);
    CHECK(!g[0].full);

    // Every broad group that can change is listed, not only the first one.
    g = BroadShareChangeGrants(Perms({ Ace(AccountKind::Everyone, true, kShareFull, L"S-1-1-0"),
                                       Ace(AccountKind::Users, true, kShareChange, L"S-1-5-32-545"),
                                       Ace(AccountKind::Other, true, kShareFull, L"S-1-5-32-544") }));
    CHECK_EQ(g.size(), static_cast<size_t>(2));

    // A deny before the allow wins; a deny after it does not take away what was granted.
    CHECK(BroadShareChangeGrants(Perms({ Ace(AccountKind::Everyone, false, FILE_WRITE_DATA | FILE_APPEND_DATA, L"S-1-1-0"),
                                         Ace(AccountKind::Users, true, kShareChange, L"S-1-5-32-545") })).empty());
    CHECK_EQ(BroadShareChangeGrants(Perms({ Ace(AccountKind::Users, true, kShareChange, L"S-1-5-32-545"),
                                            Ace(AccountKind::Everyone, false, kShareFull, L"S-1-1-0") })).size(),
             static_cast<size_t>(1));

    // Generic rights stored by a program are mapped.
    CHECK_EQ(BroadShareChangeGrants(Perms({ Ace(AccountKind::Everyone, true, GENERIC_WRITE, L"S-1-1-0") })).size(), static_cast<size_t>(1));
    g = BroadShareChangeGrants(Perms({ Ace(AccountKind::Everyone, true, GENERIC_ALL, L"S-1-1-0") }));
    REQUIRE(g.size() == 1);
    CHECK(g[0].full);

    // Guest logons: the Guests group and the Guest account count.
    CHECK_EQ(BroadShareChangeGrants(Perms({ Ace(AccountKind::Guests, true, kShareChange, L"S-1-5-32-546") })).size(), static_cast<size_t>(1));
    CHECK_EQ(BroadShareChangeGrants(Perms({ Ace(AccountKind::GuestAccount, true, kShareFull, L"S-1-5-21-1-2-3-501") })).size(),
             static_cast<size_t>(1));

    // No DACL: no share-level limit, so Everyone Full Control.
    SharePermissions open;
    open.known = true;
    open.noDacl = true;
    g = BroadShareChangeGrants(open);
    REQUIRE(g.size() == 1);
    CHECK(g[0].who == AccountKind::Everyone && g[0].full);

    // Unknown permissions grant nothing on their own.
    SharePermissions unknown;
    CHECK(BroadShareChangeGrants(unknown).empty());
}

static ShareFacts Share(const wchar_t* name, const wchar_t* path, SharePermissions perms, bool folderKnown, bool folderWritable,
                        const wchar_t* who = L"Everyone")
{
    ShareFacts s;
    s.name = name;
    s.path = path;
    s.permissions = std::move(perms);
    s.folderKnown = folderKnown;
    s.folderWritable = folderWritable;
    s.folderWho = who;
    return s;
}

static SharesFacts RunningServer()
{
    SharesFacts f;
    f.serverInstalled = true;
    f.serverRunning = true;
    f.listed = true;
    f.source = L"test";
    return f;
}

TEST(Host_SharesVerdicts)
{
    std::wstring text;
    SharesFacts f = RunningServer();
    f.shares.push_back(Share(L"C$", L"C:\\", Perms({ Ace(AccountKind::Other, true, kShareFull, L"S-1-5-32-544") }), true, false));
    f.shares[0].type = kShareTypeSpecial;
    f.shares.push_back(Share(L"Users", L"C:\\Users", Perms({ Ace(AccountKind::Everyone, true, kShareFull, L"S-1-1-0") }), true, false));
    f.shares.push_back(Share(L"Photos", L"D:\\Photos", Perms({ Ace(AccountKind::Everyone, true, kShareRead, L"S-1-1-0") }), true, true));

    // Good: the folder or the share keeps normal users from changing files.
    ShareJudgement j = JudgeShares(f);
    CHECK_EQ(j.checked, 2);
    CHECK_EQ(j.skippedAdmin, 1);
    CHECK_EQ(SharesStatus(f, j, &text), kPass);
    CHECK(Has(text, L"None of the 2"));

    // Bad: both lists let a broad group change files.
    f.shares.push_back(Share(L"Drop Box", L"E:\\", Perms({ Ace(AccountKind::Everyone, true, kShareFull, L"S-1-1-0"),
                                                            Ace(AccountKind::AuthenticatedUsers, true, kShareChange, L"S-1-5-11") }),
                             true, true, L"NT AUTHORITY\\Authenticated Users"));
    j = JudgeShares(f);
    REQUIRE(j.findings.size() == 1);
    CHECK_EQ(SharesStatus(f, j, &text), kWarn);
    CHECK(Has(text, L"\"Drop Box\" (E:\\)"));
    CHECK(Has(text, L"Everyone (Full Control)"));
    CHECK(Has(text, L"Authenticated Users (Change)"));
    std::vector<std::wstring> targets = ShareFixTargets(j.findings);
    REQUIRE(targets.size() == 2);
    CHECK_EQ(targets[0], std::wstring(L"Drop Box|S-1-1-0|Full"));
    CHECK_EQ(targets[1], std::wstring(L"Drop Box|S-1-5-11|Change"));

    // Unknown (a normal user who cannot read the share's permissions): N/A with the reason,
    // unless the folder alone keeps normal users out.
    SharesFacts user = RunningServer();
    user.shares.push_back(Share(L"Team", L"D:\\Team", SharePermissions(), true, true));
    j = JudgeShares(user);
    CHECK_EQ(SharesStatus(user, j, &text), kNa);
    CHECK(Has(text, L"administrator"));
    user.shares[0].folderWritable = false;
    j = JudgeShares(user);
    CHECK_EQ(SharesStatus(user, j, &text), kPass);

    // The share lets broad groups change, but the folder could not be read.
    SharesFacts folderUnknown = RunningServer();
    folderUnknown.shares.push_back(Share(L"Team", L"D:\\Team", Perms({ Ace(AccountKind::Users, true, kShareChange, L"S-1-5-32-545") }),
                                         false, false));
    j = JudgeShares(folderUnknown);
    CHECK_EQ(SharesStatus(folderUnknown, j, &text), kNa);

    // A share whose folder is gone is not a finding.
    SharesFacts gone = RunningServer();
    gone.shares.push_back(Share(L"Old", L"Z:\\Old", Perms({ Ace(AccountKind::Everyone, true, kShareFull, L"S-1-1-0") }), true, true));
    gone.shares[0].folderExists = false;
    j = JudgeShares(gone);
    CHECK_EQ(SharesStatus(gone, j, &text), kPass);

    // Only the administrative shares.
    SharesFacts adminOnly = RunningServer();
    adminOnly.shares.push_back(Share(L"ADMIN$", L"C:\\Windows", Perms({}), true, false));
    j = JudgeShares(adminOnly);
    CHECK_EQ(SharesStatus(adminOnly, j, &text), kPass);
    CHECK(Has(text, L"shares no folders"));

    // The Server service decides whether anything is shared at all.
    SharesFacts stopped;
    stopped.serverInstalled = true;
    j = JudgeShares(stopped);
    CHECK_EQ(SharesStatus(stopped, j, &text), kNa);
    CHECK(Has(text, L"not running"));
    SharesFacts missing;
    CHECK_EQ(SharesStatus(missing, JudgeShares(missing), &text), kNa);
    SharesFacts unlisted = RunningServer();
    unlisted.listed = false;
    unlisted.listError = L"access denied";
    CHECK_EQ(SharesStatus(unlisted, JudgeShares(unlisted), &text), kNa);
}

TEST(Host_ShareRegistryValue)
{
    std::wstring path;
    DWORD type = 99;
    CHECK(ParseShareRegistryValue({ L"CATimeout=0", L"CSCFlags=0", L"MaxUses=4294967295", L"Path=C:\\Users\\a b\\Desktop\\Share",
                                    L"Permissions=860", L"Remark=", L"ShareName=Share", L"Type=0" }, path, type));
    CHECK_EQ(path, std::wstring(L"C:\\Users\\a b\\Desktop\\Share"));
    CHECK_EQ(type, static_cast<DWORD>(0));
    CHECK(ParseShareRegistryValue({ L"Path=E:\\", L"Type=1" }, path, type));
    CHECK_EQ(type, static_cast<DWORD>(1));
    CHECK(!ParseShareRegistryValue({ L"Type=0", L"Remark=x" }, path, type));
}

// A normal user gets the share list from the registry, an administrator from the Server
// service. On this PC both must name the same shares, folders and broad grants.
TEST(Host_ShareReadersAgree)
{
    std::vector<ShareFacts> server;
    std::vector<ShareFacts> registry;
    std::wstring serverError;
    std::wstring registryError;
    bool fromServer = ReadShareListFromServer(server, serverError);
    bool fromRegistry = ReadShareListFromRegistry(registry, registryError);
    std::printf("    note: server list %s (%zu), registry list %s (%zu)\n", fromServer ? "read" : tf::Narrow(serverError).c_str(),
                server.size(), fromRegistry ? "read" : tf::Narrow(registryError).c_str(), registry.size());
    REQUIRE(fromRegistry);   // normal users may read the registry copy
    for (const ShareFacts& r : registry) {
        CHECK(!r.name.empty());
        CHECK(!r.path.empty());
    }
    if (!fromServer) return;   // a normal user: only the registry path can be compared with nothing
    int compared = 0;
    for (const ShareFacts& s : server) {
        if (!IsDiskShare(s.type) || IsDefaultAdminShare(s.name, s.type)) continue;
        const ShareFacts* match = nullptr;
        for (const ShareFacts& r : registry) {
            if (EqualsI(r.name, s.name)) match = &r;
        }
        if (!match) {
            tf::Fail(__FILE__, __LINE__, "share missing from the registry list: " + tf::Narrow(s.name));
            continue;
        }
        ++compared;
        CHECK(EqualsI(match->path, s.path));
        CHECK_EQ(match->permissions.known, s.permissions.known);
        std::vector<ShareGrant> a = BroadShareChangeGrants(s.permissions);
        std::vector<ShareGrant> b = BroadShareChangeGrants(match->permissions);
        REQUIRE(a.size() == b.size());
        for (size_t i = 0; i < a.size(); ++i) {
            CHECK_EQ(a[i].sid, b[i].sid);
            CHECK_EQ(a[i].full, b[i].full);
        }
    }
    std::printf("    note: %d share(s) compared\n", compared);
}

// ---------------------------------------------------------------------------
// net.smbguest
// ---------------------------------------------------------------------------
TEST(Host_SmbGuestDefaults)
{
    std::wstring why;
    CHECK(InsecureGuestAllowedByDefault(L"Core", 26100, false, &why));             // Home, as on this PC
    CHECK(Has(why, L"Home"));
    CHECK(InsecureGuestAllowedByDefault(L"CoreSingleLanguage", 26200, false, nullptr));
    CHECK(InsecureGuestAllowedByDefault(L"Professional", 22631, false, nullptr));  // Pro 23H2
    CHECK(!InsecureGuestAllowedByDefault(L"Professional", 26100, false, nullptr)); // Pro 24H2
    CHECK(!InsecureGuestAllowedByDefault(L"Enterprise", 19045, false, nullptr));
    CHECK(!InsecureGuestAllowedByDefault(L"Education", 16299, false, nullptr));
    CHECK(InsecureGuestAllowedByDefault(L"Enterprise", 15063, false, nullptr));    // before 1709
    CHECK(!InsecureGuestAllowedByDefault(L"ServerStandard", 17763, true, nullptr));
    CHECK(InsecureGuestAllowedByDefault(L"SomethingNew", 26100, false, &why));     // unknown: assumed allowed, and says so
    CHECK(Has(why, L"not one this check knows"));
}

TEST(Host_SmbGuestVerdicts)
{
    std::vector<std::wstring> lines;
    SmbGuestFacts pro;
    pro.editionId = L"Professional";
    pro.build = 26100;
    CHECK_EQ(SmbGuestStatus(pro, &lines), kPass);   // nothing set, the default is off
    REQUIRE(lines.size() == 2);
    CHECK(Has(lines[0], L"Windows default"));

    SmbGuestFacts home = pro;
    home.editionId = L"Core";
    CHECK_EQ(SmbGuestStatus(home, &lines), kWarn);
    CHECK(Has(lines[0], L"ALLOWED"));
    home.clientLocal = Dw(0);   // Set-SmbClientConfiguration -EnableInsecureGuestLogons $false writes this
    CHECK_EQ(SmbGuestStatus(home, &lines), kPass);

    SmbGuestFacts local = pro;
    local.clientLocal = Dw(1);
    CHECK_EQ(SmbGuestStatus(local, &lines), kWarn);
    local.clientPolicy = Dw(0);   // Group Policy wins over the local value
    CHECK_EQ(SmbGuestStatus(local, &lines), kPass);
    CHECK(Has(lines[0], L"Group Policy"));
    SmbGuestFacts policyOn = pro;
    policyOn.clientPolicy = Dw(1);
    CHECK_EQ(SmbGuestStatus(policyOn, &lines), kWarn);

    // The server side.
    SmbGuestFacts nullSessions = pro;
    nullSessions.restrictNullSession = Dw(0);
    CHECK_EQ(SmbGuestStatus(nullSessions, &lines), kWarn);
    CHECK(Has(lines[1], L"NOT restricted"));
    nullSessions.restrictNullSession = Dw(1);
    CHECK_EQ(SmbGuestStatus(nullSessions, &lines), kPass);
    nullSessions.nullSessionShares = { L"", L"  " };   // an empty REG_MULTI_SZ entry is not a share
    CHECK_EQ(SmbGuestStatus(nullSessions, &lines), kPass);
    nullSessions.nullSessionShares = { L"COMCFG" };
    CHECK_EQ(SmbGuestStatus(nullSessions, &lines), kWarn);
    CHECK(Has(lines.back(), L"COMCFG"));
}

// ---------------------------------------------------------------------------
// fw.rules
// ---------------------------------------------------------------------------
static FirewallRuleFacts AppRule(const wchar_t* name, const wchar_t* app, long protocol)
{
    FirewallRuleFacts r;
    r.name = name;
    r.application = app;
    r.protocol = protocol;
    r.localPorts = L"*";
    r.remoteAddresses = L"*";
    r.profiles = kFirewallProfilePublic;
    r.enabled = true;
    r.inbound = true;
    r.allow = true;
    return r;
}

TEST(Host_FirewallRuleSelection)
{
    FirewallRuleFacts app = AppRule(L"demo_server", L"D:\\apps\\demo_server.exe", 6);
    CHECK(IsPublicAnyAddressAllow(app));
    CHECK(IsReportedFirewallRule(app));
    CHECK(!AllowsEverything(app));

    FirewallRuleFacts all = app;
    all.profiles = 0x7FFFFFFF;   // NET_FW_PROFILE2_ALL
    CHECK(IsReportedFirewallRule(all));
    FirewallRuleFacts privateOnly = app;
    privateOnly.profiles = 0x2;
    CHECK(!IsReportedFirewallRule(privateOnly));
    FirewallRuleFacts lan = app;
    lan.remoteAddresses = L"LocalSubnet";
    CHECK(!IsReportedFirewallRule(lan));
    FirewallRuleFacts off = app;
    off.enabled = false;
    CHECK(!IsReportedFirewallRule(off));
    FirewallRuleFacts outbound = app;
    outbound.inbound = false;
    CHECK(!IsReportedFirewallRule(outbound));
    FirewallRuleFacts block = app;
    block.allow = false;
    CHECK(!IsReportedFirewallRule(block));

    // Windows' own groups and Store app rules: skipped while they are narrow.
    FirewallRuleFacts builtIn = AppRule(L"Core Networking - IPv6 (IPv6-In)", L"System", 41);
    builtIn.grouping = L"@FirewallAPI.dll,-25000";
    CHECK(IsWindowsManagedRule(builtIn));
    CHECK(!IsReportedFirewallRule(builtIn));
    FirewallRuleFacts store = app;
    store.packageId = L"S-1-15-2-1-2-3";
    CHECK(IsWindowsManagedRule(store));
    CHECK(!IsReportedFirewallRule(store));
    FirewallRuleFacts packageGroup = app;
    packageGroup.grouping = L"@{Microsoft.Windows.Photos_2022.31070.26005.0_x64__8wekyb3d8bbwe?ms-resource://x}";
    CHECK(!IsWindowsManagedRule(packageGroup));   // "@{" is a package's name text, not a Windows rule group
    FirewallRuleFacts vendorGroup = app;
    vendorGroup.grouping = L"Microsoft Edge WebView2 Runtime";
    CHECK(!IsWindowsManagedRule(vendorGroup));

    // ...but one that allows everything is reported even from a Windows group.
    FirewallRuleFacts wide = AppRule(L"Allow all", L"", kFirewallProtocolAny);
    wide.grouping = L"@FirewallAPI.dll,-28502";
    CHECK(AllowsEverything(wide));
    CHECK(IsReportedFirewallRule(wide));
    FirewallRuleFacts port = wide;
    port.protocol = 6;
    port.localPorts = L"445";
    CHECK(!AllowsEverything(port));
    CHECK(!IsReportedFirewallRule(port));

    CHECK_EQ(FirewallProtocolName(6), std::wstring(L"TCP"));
    CHECK_EQ(FirewallProtocolName(kFirewallProtocolAny), std::wstring(L"any protocol"));
    CHECK_EQ(FirewallProtocolName(132), std::wstring(L"protocol 132"));

    std::wstring line = FirewallRuleLine(port);
    CHECK(Has(line, L"\"Allow all\": any program, TCP, local port 445"));
    FirewallRuleFacts risky = AppRule(L"caddy.exe", L"C:\\Users\\a\\AppData\\Local\\Temp\\caddy.exe", 17);
    risky.programWritable = true;
    risky.writableWho = L"PC\\a";
    CHECK(Has(FirewallRuleLine(risky), L"can be changed by PC\\a"));

    std::vector<FirewallRuleFacts> sorted = { app, risky, AppRule(L"Alpha", L"C:\\Program Files\\a.exe", 6) };
    SortFirewallFindings(sorted);
    CHECK_EQ(sorted[0].name, std::wstring(L"caddy.exe"));   // risky first
    CHECK_EQ(sorted[1].name, std::wstring(L"Alpha"));
    CHECK_EQ(sorted[2].name, std::wstring(L"demo_server"));
}

TEST(Host_FirewallRulesVerdicts)
{
    std::wstring text;
    FirewallRulesFacts f;
    f.apiOk = true;
    f.publicKnown = true;
    f.publicOn = true;
    f.rulesRead = 990;
    CHECK_EQ(FirewallRulesStatus(f, &text), kPass);
    // Rules for programs in protected folders only: the normal "clicked Allow" case, listed as INFO.
    f.reported = 3;
    CHECK_EQ(FirewallRulesStatus(f, &text), std::wstring(CHECK_INFO));
    CHECK(Has(text, L"3 inbound rule(s)"));
    CHECK(Has(text, L"clicks Allow"));
    // A risky program location, or a rule that allows everything, makes it a WARNING.
    f.reportedRisky = 1;
    CHECK_EQ(FirewallRulesStatus(f, &text), kWarn);
    CHECK(Has(text, L"3 inbound rule(s)"));
    CHECK(Has(text, L"1 for a program in a folder normal users can change"));
    CHECK(Has(text, L"the fix plan turns off only these"));
    FirewallRulesFacts wide = f;
    wide.reportedRisky = 0;
    wide.reportedWideOpen = 2;
    CHECK_EQ(FirewallRulesStatus(wide, &text), kWarn);
    CHECK(Has(text, L"2 that allow everything"));
    FirewallRuleFacts plain = AppRule(L"Game", L"C:\\Program Files\\game.exe", 6);
    CHECK(!IsRiskyFirewallRule(plain));
    plain.programInDropFolder = true;
    CHECK(IsRiskyFirewallRule(plain));
    f.windowsManagedSkipped = 12;
    FirewallRulesStatus(f, &text);
    CHECK(Has(text, L"12 rule(s) of Windows' own groups"));

    FirewallRulesFacts shields = f;   // block all incoming connections on Public
    shields.blockAllInbound = true;
    CHECK_EQ(FirewallRulesStatus(shields, &text), kPass);
    FirewallRulesFacts publicOff = f;
    publicOff.publicOn = false;
    CHECK_EQ(FirewallRulesStatus(publicOff, &text), kNa);
    CHECK(Has(text, L"Windows Firewall check"));
    FirewallRulesFacts noApi;
    noApi.apiError = L"COM could not be started";
    CHECK_EQ(FirewallRulesStatus(noApi, &text), kNa);
}

TEST(Host_FirewallStoreNames)
{
    // Real entries as Windows writes them (the format Windows writes; names made up).
    FirewallStoreRule tcp = ParseFirewallRuleData(L"TCP Query User{11111111-2222-4333-8444-555555555555}D:\\apps\\demo_server.exe",
        L"v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=D:\\apps\\demo_server.exe|Name=demo_server|Desc=demo_server|Defer=User|");
    CHECK(tcp.parsed);
    CHECK(tcp.allow && tcp.active && tcp.inbound && tcp.allPublic && tcp.remoteAny);
    CHECK_EQ(tcp.protocol, 6L);
    CHECK_EQ(tcp.name, std::wstring(L"demo_server"));
    FirewallStoreRule udp = ParseFirewallRuleData(L"UDP Query User{66666666-7777-4888-9999-AAAAAAAAAAAA}D:\\apps\\demo_server.exe",
        L"v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=D:\\apps\\demo_server.exe|Name=demo_server|Desc=demo_server|Defer=User|");
    FirewallStoreRule priv = ParseFirewallRuleData(L"TCP Query User{1}D:\\apps\\demo_server.exe",
        L"v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=D:\\apps\\demo_server.exe|Name=demo_server|");
    CHECK(!priv.allPublic);
    FirewallStoreRule lan = ParseFirewallRuleData(L"lan",
        L"v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=D:\\apps\\demo_server.exe|RA4=LocalSubnet|Name=demo_server|");
    CHECK(lan.allPublic);   // no Profile entry: every profile
    CHECK(!lan.remoteAny);
    FirewallStoreRule ports = ParseFirewallRuleData(L"web",
        L"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=443|LPort=80|Name=Web|");
    CHECK_EQ(ports.localPorts, std::wstring(L"443,80"));
    CHECK(!ParseFirewallRuleData(L"", L"v2.10|").parsed);

    std::vector<FirewallStoreRule> store = { tcp, udp, priv, lan, ports };
    // Each COM rule finds exactly its own entry: the TCP and UDP twins stay apart, the
    // Private-only and LAN-only rules with the same name are never offered.
    std::vector<std::wstring> ids = MatchFirewallStoreIds(AppRule(L"demo_server", L"D:\\APPS\\demo_server.exe", 6), store);
    REQUIRE(ids.size() == 1);
    CHECK_EQ(ids[0], tcp.id);
    ids = MatchFirewallStoreIds(AppRule(L"demo_server", L"D:\\apps\\demo_server.exe", 17), store);
    REQUIRE(ids.size() == 1);
    CHECK_EQ(ids[0], udp.id);
    FirewallRuleFacts web = AppRule(L"Web", L"", 6);
    web.localPorts = L"80, 443";   // the API joins ports with commas, in its own order
    ids = MatchFirewallStoreIds(web, store);
    REQUIRE(ids.size() == 1);
    CHECK_EQ(ids[0], std::wstring(L"web"));
    CHECK(MatchFirewallStoreIds(AppRule(L"other", L"D:\\apps\\demo_server.exe", 6), store).empty());

    CHECK(!HasWildcardCharacters(tcp.id));
    CHECK(HasWildcardCharacters(L"TCP Query User{1}D:\\games[1]\\x.exe"));
    CHECK(HasWildcardCharacters(L"a*"));
}

// ---------------------------------------------------------------------------
// acct.autologon
// ---------------------------------------------------------------------------
TEST(Host_AutoLogonVerdicts)
{
    std::wstring text;
    AutoLogonFacts off;
    CHECK_EQ(AutoLogonStatus(off, &text), kPass);
    CHECK(Has(text, L"not set"));
    off.autoAdminLogon = L"0";
    CHECK_EQ(AutoLogonStatus(off, &text), kPass);

    AutoLogonFacts plain;
    plain.autoAdminLogon = L"1";
    plain.defaultUserName = L"alice";
    plain.defaultDomainName = L"ALICE-PC";
    plain.defaultPasswordPresent = true;
    plain.defaultPasswordBytes = 18;
    CHECK_EQ(AutoLogonStatus(plain, &text), kFail);
    CHECK(Has(text, L"plain text"));
    CHECK(Has(text, L"ALICE-PC\\alice"));
    CHECK(Has(text, L"did not read it"));

    // The account name goes through the report's name hiding like any other name.
    RedactionTerms terms;
    terms.userName = L"alice";
    terms.computerName = L"ALICE-PC";
    std::wstring hidden = RedactText(text, terms);
    CHECK(!ContainsI(hidden, L"alice"));
    CHECK(Has(hidden, L"<user>"));

    // Encrypted (LSA secret) or no password: a warning.
    AutoLogonFacts lsa = plain;
    lsa.defaultPasswordPresent = false;
    lsa.defaultPasswordBytes = 0;
    CHECK_EQ(AutoLogonStatus(lsa, &text), kWarn);
    CHECK(Has(text, L"LSA secret"));
    AutoLogonFacts empty = plain;
    empty.defaultPasswordBytes = 2;   // an empty string
    CHECK_EQ(AutoLogonStatus(empty, &text), kWarn);
    CHECK(Has(text, L"empty"));
    AutoLogonFacts unnamed = lsa;
    unnamed.defaultUserName.clear();
    unnamed.defaultDomainName.clear();
    unnamed.autoLogonCount = Dw(2);
    CHECK_EQ(AutoLogonStatus(unnamed, &text), kWarn);
    CHECK(Has(text, L"AutoLogonCount is 2"));

    // Off, but a plain-text password left behind: still a pass, with a note to delete it.
    AutoLogonFacts leftover = plain;
    leftover.autoAdminLogon = L"0";
    CHECK_EQ(AutoLogonStatus(leftover, &text), kPass);
    CHECK(Has(text, L"delete it"));

    AutoLogonFacts closed;
    closed.keyReadable = false;
    closed.autoAdminLogon = L"1";
    CHECK_EQ(AutoLogonStatus(closed, &text), kNa);
    CHECK(Has(text, L"administrator"));
}

// ---------------------------------------------------------------------------
// cred.ntlm
// ---------------------------------------------------------------------------
TEST(Host_NtlmVerdicts)
{
    std::vector<std::wstring> lines;
    NtlmFacts defaults;   // nothing set: level 3, NoLMHash 1, 128-bit only (the Windows defaults)
    CHECK_EQ(NtlmStatus(defaults, &lines), kWarn);
    REQUIRE(lines.size() == 4);
    CHECK(Has(lines[0], L"3, the Windows default"));
    CHECK(Has(lines[1], L"Windows default 1"));
    CHECK(Has(lines[2], L"NTLMv2 session security"));

    NtlmFacts strict;
    strict.lmCompatibilityLevel = Dw(5);
    strict.noLmHash = Dw(1);
    strict.minClientSec = Dw(kNtlmWantedMinSec);
    strict.minServerSec = Dw(0x20080030);   // more bits than needed is fine
    CHECK_EQ(NtlmStatus(strict, &lines), kPass);
    CHECK_EQ(kNtlmWantedMinSec, static_cast<DWORD>(537395200));

    for (DWORD level : { 0u, 1u, 2u }) {
        NtlmFacts old = strict;
        old.lmCompatibilityLevel = Dw(level);
        if (NtlmStatus(old, nullptr) != kFail) tf::Fail(__FILE__, __LINE__, "level " + std::to_string(level) + " is not a FAIL");
    }
    for (DWORD level : { 3u, 4u, 9u }) {
        NtlmFacts mid = strict;
        mid.lmCompatibilityLevel = Dw(level);
        if (NtlmStatus(mid, nullptr) != kWarn) tf::Fail(__FILE__, __LINE__, "level " + std::to_string(level) + " is not a WARNING");
    }

    NtlmFacts lmHash = strict;
    lmHash.noLmHash = Dw(0);
    CHECK_EQ(NtlmStatus(lmHash, &lines), kFail);
    CHECK(Has(lines[1], L"0:"));

    NtlmFacts clientOnly128 = strict;
    clientOnly128.minClientSec.set = false;   // default: 128-bit only
    CHECK_EQ(NtlmStatus(clientOnly128, &lines), kWarn);
    NtlmFacts serverNone = strict;
    serverNone.minServerSec = Dw(0);
    CHECK_EQ(NtlmStatus(serverNone, &lines), kWarn);
    CHECK(Has(lines[3], L"128-bit encryption"));

    // FAIL beats WARNING.
    NtlmFacts both = serverNone;
    both.lmCompatibilityLevel = Dw(1);
    CHECK_EQ(NtlmStatus(both, &lines), kFail);

    NtlmFacts closed;
    closed.lsaReadable = false;
    CHECK_EQ(NtlmStatus(closed, &lines), kNa);
    CHECK(Has(lines[0], L"administrator"));
}

// ---------------------------------------------------------------------------
// svc.drivers
// ---------------------------------------------------------------------------
TEST(Host_DriverImagePaths)
{
    const std::wstring root = L"C:\\Windows";
    CHECK_EQ(DriverImagePathToFile(L"\\SystemRoot\\System32\\drivers\\tcpip.sys", L"Tcpip", root),
             std::wstring(L"C:\\Windows\\System32\\drivers\\tcpip.sys"));
    CHECK_EQ(DriverImagePathToFile(L"\\systemroot\\system32\\DriverStore\\FileRepository\\x.inf_amd64_1\\x.sys", L"x", root),
             std::wstring(L"C:\\Windows\\system32\\DriverStore\\FileRepository\\x.inf_amd64_1\\x.sys"));
    CHECK_EQ(DriverImagePathToFile(L"System32\\drivers\\ACPI.sys", L"ACPI", root), std::wstring(L"C:\\Windows\\System32\\drivers\\ACPI.sys"));
    CHECK_EQ(DriverImagePathToFile(L"system32\\DRIVERS\\nvlddmkm.sys", L"nvlddmkm", root + L"\\"),
             std::wstring(L"C:\\Windows\\system32\\DRIVERS\\nvlddmkm.sys"));
    CHECK_EQ(DriverImagePathToFile(L"\\??\\C:\\Program Files (x86)\\EVGA\\Kernel\\driver-x64.sys", L"Driver", root),
             std::wstring(L"C:\\Program Files (x86)\\EVGA\\Kernel\\driver-x64.sys"));
    CHECK_EQ(DriverImagePathToFile(L"\\\\?\\D:\\Tools\\x.sys", L"x", root), std::wstring(L"D:\\Tools\\x.sys"));
    CHECK_EQ(DriverImagePathToFile(L"%SystemRoot%\\System32\\drivers\\y.sys", L"y", root), std::wstring(L"C:\\Windows\\System32\\drivers\\y.sys"));
    CHECK_EQ(DriverImagePathToFile(L"\\Windows\\System32\\drivers\\z.sys", L"z", root), std::wstring(L"C:\\Windows\\System32\\drivers\\z.sys"));
    CHECK_EQ(DriverImagePathToFile(L"\"C:\\Program Files\\Vendor\\v.sys\"", L"v", root), std::wstring(L"C:\\Program Files\\Vendor\\v.sys"));
    CHECK_EQ(DriverImagePathToFile(L"D:\\Drivers\\w.sys", L"w", root), std::wstring(L"D:\\Drivers\\w.sys"));
    // No ImagePath: what the kernel loads for the service name.
    CHECK_EQ(DriverImagePathToFile(L"", L"Beep", root), std::wstring(L"C:\\Windows\\System32\\drivers\\Beep.sys"));
    CHECK_EQ(DriverImagePathToFile(L"  ", L"Null", L"D:\\WINNT"), std::wstring(L"D:\\WINNT\\System32\\drivers\\Null.sys"));
}

TEST(Host_DriverVerdicts)
{
    DriverFacts good;
    good.name = L"tcpip";
    good.file = L"C:\\Windows\\System32\\drivers\\tcpip.sys";
    good.startType = SERVICE_BOOT_START;
    good.fileExists = true;
    good.signatureValid = true;
    CHECK_EQ(DriverProblems(good), 0u);

    DriverFacts unsigned_ = good;
    unsigned_.name = L"odd";
    unsigned_.startType = SERVICE_DEMAND_START;
    unsigned_.signatureValid = false;
    unsigned_.signatureStatus = L"Unsigned";
    CHECK_EQ(DriverProblems(unsigned_), kDriverUnsigned);
    CHECK(Has(DriverFindingLine(unsigned_), L"not validly signed (Unsigned)"));

    DriverFacts missing = good;
    missing.name = L"gone";
    missing.startType = SERVICE_AUTO_START;
    missing.fileExists = false;
    missing.signatureValid = false;   // never checked for a missing file
    CHECK_EQ(DriverProblems(missing), kDriverMissing);
    CHECK(Has(DriverFindingLine(missing), L"the file is missing"));

    DriverFacts writable = good;
    writable.name = L"vendor";
    writable.startType = SERVICE_SYSTEM_START;
    writable.folderWritable = true;
    writable.writableWho = L"BUILTIN\\Users";
    CHECK_EQ(DriverProblems(writable), kDriverWritableFolder);
    CHECK(Has(DriverFindingLine(writable), L"its folder can be changed by BUILTIN\\Users"));
    CHECK(Has(DriverFindingLine(writable), L"System start"));
    writable.fileWritable = true;
    CHECK_EQ(DriverProblems(writable), kDriverWritableFolder | kDriverWritableFile);

    // Disabled drivers cannot load: no finding however bad the file is.
    DriverFacts disabled = missing;
    disabled.startType = SERVICE_DISABLED;
    CHECK_EQ(DriverProblems(disabled), 0u);

    std::vector<DriverFacts> list = { unsigned_, missing, writable, good };
    SortDriverFindings(list);
    CHECK_EQ(list[0].name, std::wstring(L"tcpip"));    // boot
    CHECK_EQ(list[1].name, std::wstring(L"vendor"));   // system
    CHECK_EQ(list[2].name, std::wstring(L"gone"));     // automatic
    CHECK_EQ(list[3].name, std::wstring(L"odd"));      // manual
    CHECK(DriverStartRank(SERVICE_BOOT_START) < DriverStartRank(SERVICE_DISABLED));

    std::wstring text;
    DriversFacts f;
    f.listed = true;
    f.total = 460;
    f.checked = 400;
    f.disabled = 60;
    CHECK_EQ(DriversStatus(f, &text), kPass);
    CHECK(Has(text, L"All 400"));
    CHECK(Has(text, L"60 disabled"));
    f.flagged = 2;
    CHECK_EQ(DriversStatus(f, &text), kWarn);
    f.flagged = 0;
    f.unreadable = 5;
    CHECK_EQ(DriversStatus(f, &text), kPass);
    CHECK(Has(text, L"run as administrator"));
    DriversFacts closed;
    closed.listed = true;
    closed.total = 10;
    closed.unreadable = 10;
    CHECK_EQ(DriversStatus(closed, &text), kNa);
    DriversFacts noScm;
    noScm.listError = L"error 5";
    CHECK_EQ(DriversStatus(noScm, &text), kNa);
}

// ---------------------------------------------------------------------------
// Catalog rows and the fix plan
// ---------------------------------------------------------------------------
TEST(Host_CatalogAndScripts)
{
    for (const wchar_t* id : { L"net.shares", L"net.smbguest", L"fw.rules", L"acct.autologon", L"cred.ntlm", L"svc.drivers" }) {
        const CheckInfo* info = FindCheckInfo(id);
        if (!info) {
            tf::Fail(__FILE__, __LINE__, "no catalog row for " + tf::Narrow(id));
            continue;
        }
        if (!info->scored) tf::Fail(__FILE__, __LINE__, tf::Narrow(id) + " is not scored");
    }
    const CheckInfo* shares = FindCheckInfo(L"net.shares");
    const CheckInfo* guest = FindCheckInfo(L"net.smbguest");
    const CheckInfo* rules = FindCheckInfo(L"fw.rules");
    const CheckInfo* autologon = FindCheckInfo(L"acct.autologon");
    const CheckInfo* ntlm = FindCheckInfo(L"cred.ntlm");
    const CheckInfo* drivers = FindCheckInfo(L"svc.drivers");
    REQUIRE(shares && guest && rules && autologon && ntlm && drivers);

    CHECK(shares->scriptPerTarget);
    CHECK(Has(shares->fixScript, L"Grant-SmbShareAccess"));
    CHECK(Has(shares->fixScript, L"-AccessRight Read"));
    CHECK(Has(shares->undoScript, L"-AccessRight $parts[2]"));
    CHECK(Has(shares->fix, L"Revoke-SmbShareAccess"));
    CHECK(rules->scriptPerTarget);
    CHECK_EQ(rules->fixScript, std::wstring(L"Disable-NetFirewallRule -Name $target"));
    CHECK_EQ(rules->undoScript, std::wstring(L"Enable-NetFirewallRule -Name $target"));
    CHECK(Has(guest->fixScript, L"Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force"));
    CHECK(guest->undoScript.empty());   // depends on what the evidence showed: by hand
    CHECK(Has(autologon->fixScript, L"-Name AutoAdminLogon -Value '0'"));
    CHECK(autologon->undoScript.empty());
    CHECK(Has(autologon->explanation, L"never reads"));
    CHECK(Has(ntlm->fixScript, L"537395200"));
    CHECK(ntlm->scriptNeedsRestart);
    CHECK(Has(ntlm->fixScriptNote, L"old devices"));
    CHECK(Has(ntlm->explanation, L"Very old devices"));
    CHECK(drivers->fixScript.empty());   // which driver to touch is a judgement: by hand
    CHECK(Has(drivers->explanation, L"never starts, stops or changes a driver"));
}

TEST(Host_FixPlanSteps)
{
    SecurityCheckResult share = MakeCheckResult(L"net.shares");
    share.status = CHECK_WARNING;
    share.detail = L"1 shared folder(s) let broad groups change files over the network:";
    share.targets = { L"TeamShare|S-1-1-0|Full", L"Bob's Files|S-1-5-11|Change" };
    SecurityCheckResult rule = MakeCheckResult(L"fw.rules");
    rule.status = CHECK_WARNING;
    rule.detail = L"2 inbound rule(s)";
    rule.targets = { L"TCP Query User{11111111-2222-4333-8444-555555555555}D:\\apps\\demo_server.exe" };
    SecurityCheckResult noNames = MakeCheckResult(L"fw.rules");
    noNames.status = CHECK_WARNING;
    noNames.detail = L"rules from Group Policy";

    std::vector<FixStep> steps = BuildFixSteps({ share, rule }, false, false);
    REQUIRE(steps.size() == 2);
    const FixStep* shareStep = steps[0].checkId == L"net.shares" ? &steps[0] : &steps[1];
    const FixStep* ruleStep = steps[0].checkId == L"fw.rules" ? &steps[0] : &steps[1];
    CHECK(shareStep->kind == FixStepKind::Command);
    REQUIRE(!shareStep->commands.empty());
    CHECK_EQ(shareStep->commands[0], std::wstring(L"$target = 'TeamShare|S-1-1-0|Full'"));
    bool quoted = false;
    for (const std::wstring& c : shareStep->commands) quoted = quoted || c == L"$target = 'Bob''s Files|S-1-5-11|Change'";
    CHECK(quoted);
    CHECK(ruleStep->kind == FixStepKind::Command);
    CHECK(ruleStep->commands.back() == L"Disable-NetFirewallRule -Name $target");

    // No exact names recorded: the step is done by hand, with the evidence.
    std::vector<FixStep> manual = BuildFixSteps({ noNames }, false, false);
    REQUIRE(manual.size() == 1);
    CHECK(manual[0].kind == FixStepKind::Manual);

    // Hidden names make every per-name step manual.
    std::vector<FixStep> redacted = BuildFixSteps({ share }, false, true);
    REQUIRE(redacted.size() == 1);
    CHECK(redacted[0].kind == FixStepKind::Manual);

    // The undo puts the old right back from the target.
    std::vector<FixStep> undo = BuildFixSteps({ share }, true, false);
    REQUIRE(undo.size() == 1);
    CHECK(undo[0].kind == FixStepKind::Command);
    CHECK(undo[0].commands.back().find(L"-AccessRight $parts[2]") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// The real checks on this PC: a verdict or N/A with a reason, never ERROR
// ---------------------------------------------------------------------------
TEST(Host_ChecksRunHere)
{
    std::vector<SecurityCheckResult> results = {
        CheckSharedFolders(), CheckSmbGuestAccess(), CheckFirewallRules(), CheckAutoLogon(), CheckNtlmSettings(), CheckDriverServices(),
    };
    for (const SecurityCheckResult& r : results) {
        std::printf("    note: %s -> %s (%zu target(s))\n", tf::Narrow(r.id).c_str(), tf::Narrow(r.status).c_str(), r.targets.size());
        if (r.status == CHECK_ERROR) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " returned ERROR: " + tf::Narrow(r.detail));
        if (r.detail.empty()) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " has no detail");
        if (r.detail.size() > 20000) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " does not cap its evidence");
        if (!FindCheckInfo(r.id)) tf::Fail(__FILE__, __LINE__, "unknown id " + tf::Narrow(r.id));
        // Targets are only filled for a problem, and each one can go into a command exactly.
        if (!r.targets.empty() && r.status != CHECK_WARNING && r.status != CHECK_FAIL) {
            tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " has targets without a finding");
        }
        for (const std::wstring& t : r.targets) {
            if (!IsScriptSafeValue(t)) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " target cannot go into a command: " + tf::Narrow(t));
        }
    }
    // Only the shares and firewall rule checks name things one by one for the fix plan.
    CHECK(results[1].targets.empty());
    CHECK(results[3].targets.empty());
    CHECK(results[4].targets.empty());
    CHECK(results[5].targets.empty());
}
