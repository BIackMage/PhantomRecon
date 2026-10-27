// Review fixes for the second and third checks packs (HostRules.cpp, HygieneRules.cpp).
// Each test names the defect it pins down; values are made up in the format Windows uses.

#include "TestFramework.h"

#include "../HostRules.h"

#include <windows.h>

// A Store app's rule as INetFwRule reports it: no program, service or port, every
// protocol, but bound to the app's package SID (LocalAppPackageId). Windows applies it
// only to that app's own processes, so it does not open the whole PC.
static FirewallRuleFacts PackageRule()
{
    FirewallRuleFacts r;
    r.name = L"@{Contoso.DemoApp_1.0.0.0_x64__abcdefghjkmnp?ms-resource://Contoso.DemoApp/resources/DisplayName}";
    r.grouping = r.name;
    r.packageId = L"S-1-15-2-1111111111-2222222222-3333333333-4444444444-1111111111-2222222222-3333333333";
    r.localPorts = L"*";
    r.remoteAddresses = L"*";
    r.protocol = kFirewallProtocolAny;
    r.profiles = 0x7FFFFFFF;   // NET_FW_PROFILE2_ALL
    r.enabled = true;
    r.inbound = true;
    r.allow = true;
    return r;
}

TEST(FixPack_PackageFirewallRuleIsNotWideOpen)
{
    FirewallRuleFacts app = PackageRule();
    CHECK(IsPublicAnyAddressAllow(app));
    CHECK(IsWindowsManagedRule(app));
    CHECK(!AllowsEverything(app));          // limited to one app's processes
    CHECK(!IsReportedFirewallRule(app));    // a Windows-managed rule that is limited: skipped
    CHECK(!IsRiskyFirewallRule(app));       // never turned off by the fix plan

    // The same rule without the package binding does open the whole PC.
    FirewallRuleFacts unbound = app;
    unbound.packageId.clear();
    unbound.grouping.clear();
    CHECK(AllowsEverything(unbound));
    CHECK(IsReportedFirewallRule(unbound));
    CHECK(IsRiskyFirewallRule(unbound));
}

// Many Store app rules bind the app by its package family name (PFN=) in the firewall
// store. INetFwRule shows no program, no package and every port for them, so the check
// must take the binding from the store, or it reports "allows everything" and the fix
// plan turns off the app's own rule.
TEST(FixPack_PackageFamilyRuleFromTheStore)
{
    const std::wstring id = L"Contoso.DemoApp_abcdefghjkmnpS-1-5-21-1-2-3-1001-In-Allow-ServerCapability";
    FirewallStoreRule pfn = ParseFirewallRuleData(id,
        L"v2.33|Action=Allow|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|Profile=Public|Name=Demo App|Desc=Demo App|"
        L"PFN=Contoso.DemoApp_abcdefghjkmnp|LUOwn=S-1-5-21-1-2-3-1001|EmbedCtxt=Demo App|Platform=2:6:2|Platform2=GTEQ|Edge=TRUE|");
    REQUIRE(pfn.parsed);
    CHECK_EQ(pfn.package, std::wstring(L"Contoso.DemoApp_abcdefghjkmnp"));
    FirewallStoreRule appPkg = ParseFirewallRuleData(L"{11111111-2222-4333-8444-555555555555}",
        L"v2.32|Action=Allow|Active=TRUE|Dir=In|Name=Other App|AppPkgId=S-1-15-2-1-2-3-4-5-6-7|EmbedCtxt=Other App|");
    CHECK_EQ(appPkg.package, std::wstring(L"S-1-15-2-1-2-3-4-5-6-7"));
    FirewallStoreRule plain = ParseFirewallRuleData(L"wide", L"v2.10|Action=Allow|Active=TRUE|Dir=In|Name=Allow all|");
    CHECK(plain.package.empty());

    // The API's view of the PFN rule: name and group from the store, nothing else set.
    FirewallRuleFacts api = PackageRule();
    api.name = L"Demo App";
    api.grouping = L"Demo App";
    api.packageId.clear();
    CHECK(AllowsEverything(api));   // what the API alone suggests

    std::vector<FirewallStoreRule> store = { pfn, appPkg, plain };
    CHECK_EQ(StorePackageForRule(api, store), std::wstring(L"Contoso.DemoApp_abcdefghjkmnp"));
    api.packageId = StorePackageForRule(api, store);
    CHECK(!AllowsEverything(api));
    CHECK(!IsReportedFirewallRule(api));

    // A rule that really allows everything stays reported: its store entry names no package.
    FirewallRuleFacts wide = PackageRule();
    wide.name = L"Allow all";
    wide.grouping.clear();
    wide.packageId.clear();
    CHECK(StorePackageForRule(wide, store).empty());
    CHECK(IsReportedFirewallRule(wide));

    // Not in the store (a Group Policy rule), or one matching entry without a package:
    // nothing is assumed.
    FirewallRuleFacts unknown = api;
    unknown.packageId.clear();
    unknown.name = L"Not stored";
    CHECK(StorePackageForRule(unknown, store).empty());
    FirewallStoreRule twin = ParseFirewallRuleData(L"twin", L"v2.10|Action=Allow|Active=TRUE|Dir=In|Name=Demo App|EmbedCtxt=Demo App|");
    std::vector<FirewallStoreRule> mixed = { pfn, twin };
    FirewallRuleFacts demo = api;
    demo.packageId.clear();
    CHECK(StorePackageForRule(demo, mixed).empty());
}
