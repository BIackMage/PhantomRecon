#include "pch.h"
#include "SecurityChecksSharing.h"

#include "AppPaths.h"
#include "CheckHelpers.h"
#include "HostRules.h"
#include "RegUtil.h"
#include "ServiceUtil.h"
#include "SystemInfo.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <windows.h>
#include <aclapi.h>
#include <lm.h>
#include <netfw.h>
#include <sddl.h>
#include <VersionHelpers.h>
#include <map>
#include <set>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SecurityChecksSharing] " + msg + L"\n").c_str());
}

static OptionalDword ReadOptionalDword(HKEY root, const std::wstring& key, const std::wstring& value)
{
    OptionalDword o;
    o.set = RegReadDword(root, key, value, o.value);
    return o;
}

// ===========================================================================
// Shared folders
// ===========================================================================
static const wchar_t* const kSharesKey = L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares";
static const wchar_t* const kSharesSecurityKey = L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares\\Security";

static std::wstring SidString(PSID sid)
{
    LPWSTR text = NULL;
    if (!sid || !ConvertSidToStringSidW(sid, &text)) return L"";
    std::wstring out = text;
    LocalFree(text);
    return out;
}

static AccountKind ClassifySid(PSID sid)
{
    if (!sid || !IsValidSid(sid)) return AccountKind::Other;
    if (IsWellKnownSid(sid, WinWorldSid)) return AccountKind::Everyone;
    if (IsWellKnownSid(sid, WinAuthenticatedUserSid)) return AccountKind::AuthenticatedUsers;
    if (IsWellKnownSid(sid, WinBuiltinUsersSid)) return AccountKind::Users;
    if (IsWellKnownSid(sid, WinBuiltinGuestsSid)) return AccountKind::Guests;
    // The Guest account of this PC or a domain: S-1-5-21-<machine or domain>-501.
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID_IDENTIFIER_AUTHORITY auth = GetSidIdentifierAuthority(sid);
    UCHAR count = *GetSidSubAuthorityCount(sid);
    if (auth && memcmp(auth, &nt, sizeof(nt)) == 0 && count >= 2 && *GetSidSubAuthority(sid, 0) == SECURITY_NT_NON_UNIQUE &&
        *GetSidSubAuthority(sid, count - 1) == DOMAIN_USER_RID_GUEST) {
        return AccountKind::GuestAccount;
    }
    return AccountKind::Other;
}

// The share-level permission list. A missing descriptor or DACL means no share-level
// limit at all (Everyone Full Control), the conservative reading.
static SharePermissions PermissionsFromDescriptor(PSECURITY_DESCRIPTOR sd)
{
    SharePermissions p;
    if (!sd) {
        p.known = true;
        p.noDacl = true;
        return p;
    }
    if (!IsValidSecurityDescriptor(sd)) {
        DebugLog(L"Share security descriptor is not valid");
        return p;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = NULL;
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) {
        DebugLog(L"GetSecurityDescriptorDacl failed, error " + std::to_wstring(GetLastError()));
        return p;
    }
    p.known = true;
    if (!present || !dacl) {
        p.noDacl = true;
        return p;
    }
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        LPVOID ace = NULL;
        if (!GetAce(dacl, i, &ace) || !ace) continue;
        const ACE_HEADER* header = static_cast<const ACE_HEADER*>(ace);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE) continue;
        ACCESS_ALLOWED_ACE* entry = static_cast<ACCESS_ALLOWED_ACE*>(ace);   // same layout as ACCESS_DENIED_ACE
        PSID sid = reinterpret_cast<PSID>(&entry->SidStart);
        ShareAce a;
        a.who = ClassifySid(sid);
        a.allow = header->AceType == ACCESS_ALLOWED_ACE_TYPE;
        a.mask = entry->Mask;
        a.sid = SidString(sid);
        p.aces.push_back(a);
    }
    return p;
}

// NetShareEnum at level 502 gives path and permissions, but only to administrators.
bool ReadShareListFromServer(std::vector<ShareFacts>& out, std::wstring& error)
{
    out.clear();
    DWORD resume = 0;
    NET_API_STATUS rc = NERR_Success;
    do {
        LPBYTE buffer = NULL;
        DWORD read = 0;
        DWORD total = 0;
        rc = NetShareEnum(NULL, 502, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if ((rc == NERR_Success || rc == ERROR_MORE_DATA) && buffer) {
            const SHARE_INFO_502* info = reinterpret_cast<const SHARE_INFO_502*>(buffer);
            for (DWORD i = 0; i < read; ++i) {
                ShareFacts s;
                s.name = info[i].shi502_netname ? info[i].shi502_netname : L"";
                s.path = info[i].shi502_path ? info[i].shi502_path : L"";
                s.type = info[i].shi502_type;
                s.permissions = PermissionsFromDescriptor(info[i].shi502_security_descriptor);
                out.push_back(s);
            }
        }
        if (buffer) NetApiBufferFree(buffer);
    } while (rc == ERROR_MORE_DATA);
    if (rc != NERR_Success) {
        out.clear();
        error = L"NetShareEnum answered " + std::to_wstring(rc);
        DebugLog(L"ReadShareListFromServer: " + error);
        return false;
    }
    DebugLog(L"ReadShareListFromServer: " + std::to_wstring(out.size()) + L" share(s)");
    return true;
}

// The same facts from the registry the Server service keeps them in, which normal
// users may read on current Windows.
bool ReadShareListFromRegistry(std::vector<ShareFacts>& out, std::wstring& error)
{
    out.clear();
    LONG open = RegOpenStatus(HKEY_LOCAL_MACHINE, kSharesKey);
    if (open == ERROR_FILE_NOT_FOUND) return true;   // nothing has ever been shared
    if (open != ERROR_SUCCESS) {
        error = L"the Shares registry key answered " + std::to_wstring(open);
        return false;
    }
    LONG securityOpen = RegOpenStatus(HKEY_LOCAL_MACHINE, kSharesSecurityKey);
    for (const RegValue& v : RegEnumValues(HKEY_LOCAL_MACHINE, kSharesKey)) {
        if (v.type != REG_MULTI_SZ) continue;
        ShareFacts s;
        s.name = v.name;
        if (!ParseShareRegistryValue(RegReadMultiString(HKEY_LOCAL_MACHINE, kSharesKey, v.name), s.path, s.type)) continue;
        std::vector<BYTE> sd;
        if (securityOpen == ERROR_SUCCESS && RegReadBinary(HKEY_LOCAL_MACHINE, kSharesSecurityKey, v.name, sd) &&
            sd.size() >= sizeof(SECURITY_DESCRIPTOR_RELATIVE)) {
            s.permissions = PermissionsFromDescriptor(sd.data());
        }
        else if (securityOpen == ERROR_SUCCESS || securityOpen == ERROR_FILE_NOT_FOUND) {
            s.permissions.known = true;    // no stored descriptor: no share-level limit
            s.permissions.noDacl = true;
        }
        out.push_back(s);
    }
    DebugLog(L"ReadShareListFromRegistry: " + std::to_wstring(out.size()) + L" share(s), Security key status " +
             std::to_wstring(securityOpen));
    return true;
}

// The folder's own DACL, judged for Everyone, Authenticated Users, Users and
// INTERACTIVE (the AppPaths helper). The signed-in user's own rights do not count
// here: a share of a person's own folder is not open because that person may write.
static void ReadFolderPermissions(ShareFacts& s)
{
    s.folderExists = DirectoryExists(s.path);
    if (!s.folderExists) return;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD rc = GetNamedSecurityInfoW(ToExtendedPath(s.path).c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL,
                                     &dacl, NULL, &sd);
    if (rc != ERROR_SUCCESS) {
        DebugLog(L"Folder permissions of share " + s.name + L" unreadable, error " + std::to_wstring(rc));
        return;
    }
    s.folderKnown = true;
    s.folderWritable = DaclLetsLowPrivilegeGroupsWrite(dacl, true, &s.folderWho);
    LocalFree(sd);
}

SecurityCheckResult CheckSharedFolders()
{
    SecurityCheckResult result = MakeCheckResult(L"net.shares");
    SharesFacts facts;
    ServiceInfo server;
    facts.serverInstalled = QueryServiceByName(L"LanmanServer", server);
    facts.serverRunning = facts.serverInstalled && server.state == SERVICE_RUNNING;

    if (facts.serverRunning) {
        std::wstring serverError;
        if (ReadShareListFromServer(facts.shares, serverError)) {
            facts.listed = true;
            facts.source = L"the Server service (NetShareEnum)";
        }
        else {
            std::wstring registryError;
            DebugLog(serverError + L", reading the registry instead");
            if (ReadShareListFromRegistry(facts.shares, registryError)) {
                facts.listed = true;
                facts.source = L"the registry (HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares); the Server "
                               L"service lists shares with their permissions only to administrators";
            }
            else {
                facts.listError = serverError + L", " + registryError;
            }
        }
        for (ShareFacts& s : facts.shares) {
            if (IsDiskShare(s.type) && !IsDefaultAdminShare(s.name, s.type)) ReadFolderPermissions(s);
        }
    }

    ShareJudgement judgement = JudgeShares(facts);
    std::wstring text;
    result.status = SharesStatus(facts, judgement, &text);
    result.detail = text;
    if (result.status == CHECK_WARNING) result.targets = ShareFixTargets(judgement.findings);
    DebugLog(L"Shared folders -> " + result.status + L", " + std::to_wstring(result.targets.size()) + L" fix target(s)");
    return result;
}

// ===========================================================================
// SMB guest and anonymous access
// ===========================================================================
SecurityCheckResult CheckSmbGuestAccess()
{
    SecurityCheckResult result = MakeCheckResult(L"net.smbguest");
    const wchar_t* serverKey = L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters";
    SmbGuestFacts facts;
    facts.clientLocal = ReadOptionalDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                                          L"AllowInsecureGuestAuth");
    facts.clientPolicy = ReadOptionalDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation",
                                           L"AllowInsecureGuestAuth");
    facts.restrictNullSession = ReadOptionalDword(HKEY_LOCAL_MACHINE, serverKey, L"RestrictNullSessAccess");
    facts.nullSessionShares = RegReadMultiString(HKEY_LOCAL_MACHINE, serverKey, L"NullSessionShares");
    facts.editionId = RegReadString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"EditionID");
    facts.build = GetWindowsBuildNumber();
    facts.isServer = IsWindowsServer();

    std::vector<std::wstring> lines;
    result.status = SmbGuestStatus(facts, &lines);
    result.detail = (result.status == CHECK_PASS
                         ? std::wstring(L"Guest sign-in to other computers' shares is off, and anonymous access to this PC's "
                                        L"shares is restricted.")
                         : std::wstring(L"This PC may sign in to other computers' shares as a guest, or lets anonymous users "
                                        L"reach its own shares.")) +
                    L"\n" + JoinW(lines, L"\n") + L"\nWindows edition: " +
                    (facts.editionId.empty() ? std::wstring(L"unknown") : facts.editionId) + L", build " +
                    std::to_wstring(facts.build) + L".";
    DebugLog(L"SMB guest -> " + result.status);
    return result;
}

// ===========================================================================
// Inbound firewall rules
// ===========================================================================
static const wchar_t* const kFirewallStoreKey =
    L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";

static std::wstring TakeBstr(BSTR value)
{
    std::wstring out = value ? std::wstring(value, SysStringLen(value)) : std::wstring();
    if (value) SysFreeString(value);
    return out;
}

static FirewallRuleFacts ReadRuleFacts(INetFwRule* rule)
{
    FirewallRuleFacts f;
    BSTR text = NULL;
    if (SUCCEEDED(rule->get_Name(&text))) f.name = TakeBstr(text);
    text = NULL;
    if (SUCCEEDED(rule->get_Grouping(&text))) f.grouping = TakeBstr(text);
    text = NULL;
    if (SUCCEEDED(rule->get_ApplicationName(&text))) f.application = ExpandEnvironment(TakeBstr(text));
    text = NULL;
    if (SUCCEEDED(rule->get_ServiceName(&text))) f.service = TakeBstr(text);
    text = NULL;
    if (SUCCEEDED(rule->get_LocalPorts(&text))) f.localPorts = TakeBstr(text);
    text = NULL;
    if (SUCCEEDED(rule->get_RemoteAddresses(&text))) f.remoteAddresses = TakeBstr(text);
    long protocol = kFirewallProtocolAny;
    if (SUCCEEDED(rule->get_Protocol(&protocol))) f.protocol = protocol;
    long profiles = 0;
    if (SUCCEEDED(rule->get_Profiles(&profiles))) f.profiles = profiles;
    VARIANT_BOOL enabled = VARIANT_FALSE;
    if (SUCCEEDED(rule->get_Enabled(&enabled))) f.enabled = enabled == VARIANT_TRUE;
    NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
    if (SUCCEEDED(rule->get_Direction(&direction))) f.inbound = direction == NET_FW_RULE_DIR_IN;
    NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
    if (SUCCEEDED(rule->get_Action(&action))) f.allow = action == NET_FW_ACTION_ALLOW;
    INetFwRule3* rule3 = NULL;
    if (SUCCEEDED(rule->QueryInterface(__uuidof(INetFwRule3), reinterpret_cast<void**>(&rule3))) && rule3) {
        text = NULL;
        if (SUCCEEDED(rule3->get_LocalAppPackageId(&text))) f.packageId = TakeBstr(text);
        rule3->Release();
    }
    return f;
}

// Every rule through INetFwPolicy2, read only. False when the API does not answer.
static bool ReadFirewallRules(FirewallRulesFacts& facts, std::vector<FirewallRuleFacts>& rules)
{
    INetFwPolicy2* policy = NULL;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                                  reinterpret_cast<void**>(&policy));
    if (FAILED(hr) || !policy) {
        facts.apiError = L"HNetCfg.FwPolicy2 could not be created, error " + std::to_wstring(static_cast<long>(hr));
        return false;
    }
    VARIANT_BOOL on = VARIANT_FALSE;
    if (SUCCEEDED(policy->get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, &on))) {
        facts.publicKnown = true;
        facts.publicOn = on == VARIANT_TRUE;
    }
    VARIANT_BOOL blockAll = VARIANT_FALSE;
    if (SUCCEEDED(policy->get_BlockAllInboundTraffic(NET_FW_PROFILE2_PUBLIC, &blockAll))) facts.blockAllInbound = blockAll == VARIANT_TRUE;

    bool ok = false;
    INetFwRules* list = NULL;
    if (SUCCEEDED(policy->get_Rules(&list)) && list) {
        IUnknown* enumUnknown = NULL;
        if (SUCCEEDED(list->get__NewEnum(&enumUnknown)) && enumUnknown) {
            IEnumVARIANT* e = NULL;
            if (SUCCEEDED(enumUnknown->QueryInterface(__uuidof(IEnumVARIANT), reinterpret_cast<void**>(&e))) && e) {
                ok = true;
                VARIANT v;
                VariantInit(&v);
                ULONG fetched = 0;
                while (e->Next(1, &v, &fetched) == S_OK && fetched == 1) {
                    if (v.vt == VT_DISPATCH && v.pdispVal) {
                        INetFwRule* rule = NULL;
                        if (SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&rule))) && rule) {
                            rules.push_back(ReadRuleFacts(rule));
                            rule->Release();
                        }
                    }
                    VariantClear(&v);
                }
                e->Release();
            }
            enumUnknown->Release();
        }
        list->Release();
    }
    policy->Release();
    if (!ok) facts.apiError = L"the rule list could not be read";
    return ok;
}

// The local store, for each rule's unique name (what Disable-NetFirewallRule -Name takes).
static std::vector<FirewallStoreRule> ReadFirewallStore()
{
    std::vector<FirewallStoreRule> store;
    for (const RegValue& v : RegEnumValues(HKEY_LOCAL_MACHINE, kFirewallStoreKey)) {
        if (v.type != REG_SZ && v.type != REG_EXPAND_SZ) continue;
        FirewallStoreRule r = ParseFirewallRuleData(v.name, v.text);
        if (!r.parsed) continue;
        r.application = ExpandEnvironment(r.application);
        store.push_back(r);
    }
    DebugLog(std::to_wstring(store.size()) + L" rules in the local firewall store");
    return store;
}

struct ProgramPlace {
    bool         writable = false;
    bool         drop = false;
    std::wstring who;
};

static ProgramPlace JudgeProgramPlace(const std::wstring& program, std::map<std::wstring, ProgramPlace>& cache)
{
    std::wstring key = ToLowerW(program);
    auto it = cache.find(key);
    if (it != cache.end()) return it->second;
    ProgramPlace place;
    std::wstring folder = DirectoryOf(program);
    // Store app folders are locked down by Windows as a whole, whatever the individual
    // file permissions say (the same rule as the service program check).
    if (program.find(L'\\') != std::wstring::npos && !IsPackagedAppPath(program)) {
        place.drop = IsUserDropLocation(program);
        if (FileExists(program)) place.writable = LowPrivilegeWritable(program, false, &place.who);
        if (!place.writable && !folder.empty() && DirectoryExists(folder)) place.writable = LowPrivilegeWritable(folder, true, &place.who);
    }
    cache[key] = place;
    return place;
}

SecurityCheckResult CheckFirewallRules()
{
    SecurityCheckResult result = MakeCheckResult(L"fw.rules");
    FirewallRulesFacts facts;
    std::vector<FirewallRuleFacts> rules;
    {
        ComScope com;
        if (!com.Ok()) facts.apiError = L"COM could not be started";
        else facts.apiOk = ReadFirewallRules(facts, rules);
    }
    facts.rulesRead = static_cast<int>(rules.size());

    // The local store, for each rule's unique name (the fix plan) and for the Store app
    // binding by package family name, which INetFwRule does not show.
    std::vector<FirewallStoreRule> store = facts.apiOk ? ReadFirewallStore() : std::vector<FirewallStoreRule>();
    std::vector<FirewallRuleFacts> reported;
    std::map<std::wstring, ProgramPlace> places;
    int storePackages = 0;
    for (FirewallRuleFacts& r : rules) {
        if (!IsPublicAnyAddressAllow(r)) continue;
        if (TrimW(r.packageId).empty() && AllowsEverything(r)) {
            r.packageId = StorePackageForRule(r, store);
            if (!r.packageId.empty()) storePackages++;
        }
        if (!IsReportedFirewallRule(r)) {
            facts.windowsManagedSkipped++;
            continue;
        }
        if (!TrimW(r.application).empty()) {
            ProgramPlace place = JudgeProgramPlace(r.application, places);
            r.programWritable = place.writable;
            r.programInDropFolder = place.drop;
            r.writableWho = place.who;
        }
        if (r.programWritable || r.programInDropFolder) facts.reportedRisky++;
        else if (AllowsEverything(r)) facts.reportedWideOpen++;
        reported.push_back(r);
    }
    facts.reported = static_cast<int>(reported.size());
    DebugLog(std::to_wstring(storePackages) + L" rule(s) bound to a Store app only in the local store (PFN or AppPkgId)");

    std::wstring text;
    result.status = FirewallRulesStatus(facts, &text);
    result.detail = text;
    if (result.status == CHECK_WARNING || result.status == CHECK_INFO) {
        SortFirewallFindings(reported);
        CappedList listed(60);
        for (const FirewallRuleFacts& r : reported) listed.Add(FirewallRuleLine(r));
        result.detail += L"\n" + listed.Text();
    }
    if (result.status == CHECK_WARNING) {
        // The fix plan turns off only the risky rules, and needs each one's unique name
        // exactly; otherwise the step is left to do by hand rather than fixing only some.
        std::vector<std::wstring> ids;
        std::set<std::wstring> seen;
        int unmatched = 0;
        int wildcard = 0;
        for (const FirewallRuleFacts& r : reported) {
            if (!IsRiskyFirewallRule(r)) continue;
            std::vector<std::wstring> found = MatchFirewallStoreIds(r, store);
            if (found.empty()) unmatched++;
            for (const std::wstring& id : found) {
                if (HasWildcardCharacters(id)) wildcard++;
                if (seen.insert(ToLowerW(id)).second) ids.push_back(id);
            }
        }
        if (unmatched == 0 && wildcard == 0) {
            result.targets = ids;
        }
        else {
            result.detail += L"The fix plan leaves this step to do by hand: " +
                (unmatched > 0 ? std::to_wstring(unmatched) + L" rule(s) were not found by their exact name in the local firewall "
                                 L"store (rules set by Group Policy, for example)"
                               : std::to_wstring(wildcard) + L" rule name(s) hold a character PowerShell reads as a wildcard") +
                L".\n";
        }
        DebugLog(L"Firewall rules: " + std::to_wstring(ids.size()) + L" store name(s), " + std::to_wstring(unmatched) +
                 L" unmatched, " + std::to_wstring(wildcard) + L" with wildcard characters");
    }
    DebugLog(L"Inbound firewall rules -> " + result.status);
    return result;
}
