#include "pch.h"
#include "HostRules.h"

#include "SecurityChecks.h"
#include "TextUtils.h"

#include <algorithm>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[HostRules] " + msg + L"\n").c_str());
}

static std::wstring DwordText(const OptionalDword& v)
{
    return v.set ? std::to_wstring(v.value) : std::wstring(L"not set");
}

static std::wstring HexText(DWORD v)
{
    wchar_t buf[16];
    swprintf_s(buf, L"0x%08X", v);
    return buf;
}

// ===========================================================================
// Shared folders
// ===========================================================================
std::wstring AccountKindName(AccountKind kind)
{
    switch (kind) {
    case AccountKind::Everyone:           return L"Everyone";
    case AccountKind::AuthenticatedUsers: return L"Authenticated Users";
    case AccountKind::Users:              return L"Users";
    case AccountKind::Guests:             return L"Guests";
    case AccountKind::GuestAccount:       return L"Guest";
    default:                              return L"another account";
    }
}

bool IsDiskShare(DWORD type)
{
    return (type & kShareTypeMask) == kShareTypeDisk;
}

bool IsDefaultAdminShare(const std::wstring& name, DWORD type)
{
    if (type & kShareTypeSpecial) return true;
    std::wstring lower = ToLowerW(TrimW(name));
    if (lower == L"admin$" || lower == L"ipc$" || lower == L"print$") return true;
    return lower.size() == 2 && lower[1] == L'$' && lower[0] >= L'a' && lower[0] <= L'z';
}

// Generic rights as the file system maps them (the share permission dialog stores
// specific rights, but a descriptor written by a program may use generic ones).
static DWORD MapFileGenericRights(DWORD mask)
{
    DWORD out = mask & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
    if (mask & GENERIC_READ) out |= FILE_GENERIC_READ;
    if (mask & GENERIC_WRITE) out |= FILE_GENERIC_WRITE;
    if (mask & GENERIC_EXECUTE) out |= FILE_GENERIC_EXECUTE;
    if (mask & GENERIC_ALL) out |= FILE_ALL_ACCESS;
    return out;
}

static const DWORD kShareChangeRights = FILE_WRITE_DATA | FILE_APPEND_DATA;

static void AddShareGrant(std::vector<ShareGrant>& grants, const ShareAce& ace, bool full)
{
    for (ShareGrant& g : grants) {
        if (g.who == ace.who && EqualsI(g.sid, ace.sid)) {
            g.full = g.full || full;
            return;
        }
    }
    ShareGrant g;
    g.who = ace.who;
    g.sid = ace.sid;
    g.full = full;
    grants.push_back(g);
}

// Every allow entry this principal holds that still grants change rights after the
// deny entries before it. All of them, not only the first: reducing one broad account
// to Read leaves the others' Change in place.
static void WalkShareAces(const SharePermissions& permissions, const std::vector<AccountKind>& held, std::vector<ShareGrant>& grants)
{
    DWORD denied = 0;
    for (const ShareAce& ace : permissions.aces) {
        if (std::find(held.begin(), held.end(), ace.who) == held.end()) continue;
        DWORD mask = MapFileGenericRights(ace.mask);
        if (!ace.allow) {
            denied |= mask;
            continue;
        }
        if ((mask & ~denied & kShareChangeRights) != 0) {
            AddShareGrant(grants, ace, (mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);
        }
    }
}

std::vector<ShareGrant> BroadShareChangeGrants(const SharePermissions& permissions)
{
    std::vector<ShareGrant> grants;
    if (!permissions.known) return grants;
    if (permissions.noDacl) {
        ShareGrant g;
        g.who = AccountKind::Everyone;
        g.sid = L"S-1-1-0";
        g.full = true;
        grants.push_back(g);
        return grants;
    }
    WalkShareAces(permissions, { AccountKind::Everyone, AccountKind::AuthenticatedUsers, AccountKind::Users }, grants);
    WalkShareAces(permissions, { AccountKind::Everyone, AccountKind::Guests, AccountKind::GuestAccount }, grants);
    return grants;
}

ShareJudgement JudgeShares(const SharesFacts& facts)
{
    ShareJudgement j;
    for (const ShareFacts& s : facts.shares) {
        if (!IsDiskShare(s.type)) continue;
        if (IsDefaultAdminShare(s.name, s.type)) {
            j.skippedAdmin++;
            continue;
        }
        j.checked++;
        if (!s.folderExists) continue;   // nothing to change through a share whose folder is gone
        std::vector<ShareGrant> grants = BroadShareChangeGrants(s.permissions);
        if (s.permissions.known) {
            if (grants.empty()) continue;
            if (!s.folderKnown) {
                j.unknown.push_back(L"  \"" + s.name + L"\" (" + s.path + L"): the share lets broad groups change files, but "
                                    L"the folder's own permissions could not be read.");
                continue;
            }
            if (!s.folderWritable) continue;
            ShareFinding f;
            f.name = s.name;
            f.path = s.path;
            f.folderWho = s.folderWho;
            f.grants = grants;
            j.findings.push_back(f);
            continue;
        }
        if (s.folderKnown && !s.folderWritable) continue;   // the folder alone keeps normal users out
        j.unknown.push_back(L"  \"" + s.name + L"\" (" + s.path + L"): the share's permissions could not be read" +
                            (s.folderKnown ? L"; the folder lets " + s.folderWho + L" change files." : std::wstring(L".")));
    }
    return j;
}

static std::wstring GrantText(const ShareGrant& g)
{
    return AccountKindName(g.who) + (g.full ? L" (Full Control)" : L" (Change)");
}

std::wstring SharesStatus(const SharesFacts& facts, const ShareJudgement& judgement, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    if (!facts.serverInstalled) {
        status = CHECK_NA;
        t = L"This PC has no Server service (LanmanServer), so it shares no folders.";
    }
    else if (!facts.serverRunning) {
        status = CHECK_NA;
        t = L"The Server service (LanmanServer) is not running, so this PC shares no folders over the network right now.";
    }
    else if (!facts.listed) {
        status = CHECK_NA;
        t = L"The list of shared folders could not be read (" + facts.listError + L"). Run as administrator to read it.";
    }
    else if (!judgement.findings.empty()) {
        status = CHECK_WARNING;
        t = std::to_wstring(judgement.findings.size()) + L" shared folder(s) let broad groups change files over the network:";
        for (const ShareFinding& f : judgement.findings) {
            std::vector<std::wstring> who;
            for (const ShareGrant& g : f.grants) who.push_back(GrantText(g));
            t += L"\n  \"" + f.name + L"\" (" + f.path + L"): the share allows " + JoinW(who, L", ") +
                 L", and the folder lets " + f.folderWho + L" change files.";
        }
        if (!judgement.unknown.empty()) t += L"\nNot judged:\n" + JoinW(judgement.unknown, L"\n");
    }
    else if (!judgement.unknown.empty()) {
        status = CHECK_NA;
        t = std::to_wstring(judgement.unknown.size()) + L" shared folder(s) could not be judged. Run as administrator to read "
            L"their permissions.\n" + JoinW(judgement.unknown, L"\n");
    }
    else if (judgement.checked == 0) {
        status = CHECK_PASS;
        t = L"This PC shares no folders besides Windows' own administrative shares (" + std::to_wstring(judgement.skippedAdmin) +
            L" skipped).";
    }
    else {
        status = CHECK_PASS;
        t = L"None of the " + std::to_wstring(judgement.checked) + L" shared folder(s) lets Everyone, Authenticated Users, Users or "
            L"Guest change files over the network.";
    }
    if (facts.listed && !facts.source.empty()) t += L"\nShares read from " + facts.source + L".";
    if (text) *text = t;
    DebugLog(L"Shares: server " + std::to_wstring(facts.serverRunning) + L", listed " + std::to_wstring(facts.listed) + L", " +
             std::to_wstring(judgement.checked) + L" checked, " + std::to_wstring(judgement.findings.size()) + L" found, " +
             std::to_wstring(judgement.unknown.size()) + L" unknown -> " + status);
    return status;
}

std::vector<std::wstring> ShareFixTargets(const std::vector<ShareFinding>& findings)
{
    std::vector<std::wstring> targets;
    for (const ShareFinding& f : findings) {
        for (const ShareGrant& g : f.grants) {
            if (f.name.empty() || g.sid.empty() || f.name.find(L'|') != std::wstring::npos) continue;
            targets.push_back(f.name + L"|" + g.sid + L"|" + (g.full ? L"Full" : L"Change"));
        }
    }
    return targets;
}

bool ParseShareRegistryValue(const std::vector<std::wstring>& lines, std::wstring& path, DWORD& type)
{
    bool havePath = false;
    type = kShareTypeDisk;
    for (const std::wstring& line : lines) {
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = TrimW(line.substr(0, eq));
        std::wstring value = line.substr(eq + 1);
        if (EqualsI(key, L"Path")) {
            path = value;
            havePath = true;
        }
        else if (EqualsI(key, L"Type")) {
            type = static_cast<DWORD>(wcstoul(value.c_str(), nullptr, 10));
        }
    }
    return havePath;
}

// ===========================================================================
// SMB guest and anonymous access
// ===========================================================================
static const DWORD kWindows10_1709Build = 16299;
static const DWORD kWindows11_24H2Build = 26100;

bool InsecureGuestAllowedByDefault(const std::wstring& editionId, DWORD build, bool isServer, std::wstring* why)
{
    std::wstring e = ToLowerW(TrimW(editionId));
    bool allowed = true;
    std::wstring w;
    if (isServer || e.rfind(L"server", 0) == 0) {
        allowed = build < kWindows10_1709Build;
        w = allowed ? L"Windows Server before version 1709 allows insecure guest logons by default."
                    : L"Windows Server 2019 and later do not allow insecure guest logons by default.";
    }
    else if (e.rfind(L"enterprise", 0) == 0 || e.rfind(L"education", 0) == 0 || e.rfind(L"iotenterprise", 0) == 0) {
        allowed = build < kWindows10_1709Build;
        w = allowed ? L"Enterprise and Education editions before Windows 10 1709 allow insecure guest logons by default."
                    : L"Enterprise and Education editions do not allow insecure guest logons by default (since Windows 10 1709).";
    }
    else if (e.rfind(L"professional", 0) == 0) {
        allowed = build < kWindows11_24H2Build;
        w = allowed ? L"Pro editions before Windows 11 24H2 allow insecure guest logons by default."
                    : L"Pro editions do not allow insecure guest logons by default since Windows 11 24H2.";
    }
    else if (e.rfind(L"core", 0) == 0) {
        allowed = true;
        w = L"Windows Home allows insecure guest logons by default.";
    }
    else {
        allowed = true;
        w = L"This Windows edition (" + (editionId.empty() ? std::wstring(L"unknown") : editionId) +
            L") is not one this check knows, so it assumes insecure guest logons are allowed by default.";
    }
    if (why) *why = w;
    return allowed;
}

std::wstring SmbGuestStatus(const SmbGuestFacts& facts, std::vector<std::wstring>* lines)
{
    std::vector<std::wstring> l;
    bool warn = false;

    bool clientAllowed = false;
    if (facts.clientPolicy.set) {
        clientAllowed = facts.clientPolicy.value != 0;
        l.push_back(std::wstring(L"Insecure guest logons to other computers' shares: ") + (clientAllowed ? L"ALLOWED" : L"off") +
                    L" by Group Policy (AllowInsecureGuestAuth=" + std::to_wstring(facts.clientPolicy.value) + L").");
    }
    else if (facts.clientLocal.set) {
        clientAllowed = facts.clientLocal.value != 0;
        l.push_back(std::wstring(L"Insecure guest logons to other computers' shares: ") + (clientAllowed ? L"ALLOWED" : L"off") +
                    L" (AllowInsecureGuestAuth=" + std::to_wstring(facts.clientLocal.value) + L").");
    }
    else {
        std::wstring why;
        clientAllowed = InsecureGuestAllowedByDefault(facts.editionId, facts.build, facts.isServer, &why);
        l.push_back(std::wstring(L"Insecure guest logons to other computers' shares: ") + (clientAllowed ? L"ALLOWED" : L"off") +
                    L", the Windows default (AllowInsecureGuestAuth is not set). " + why);
    }
    if (clientAllowed) warn = true;

    if (facts.restrictNullSession.set && facts.restrictNullSession.value == 0) {
        warn = true;
        l.push_back(L"Anonymous access to this PC's shares and named pipes: NOT restricted (RestrictNullSessAccess=0).");
    }
    else {
        l.push_back(L"Anonymous access to this PC's shares and named pipes: restricted (RestrictNullSessAccess=" +
                    (facts.restrictNullSession.set ? std::to_wstring(facts.restrictNullSession.value) + L")."
                                                   : std::wstring(L"not set, the Windows default 1).")));
    }

    std::vector<std::wstring> open;
    for (const std::wstring& s : facts.nullSessionShares) {
        if (!TrimW(s).empty()) open.push_back(TrimW(s));
    }
    if (!open.empty()) {
        warn = true;
        l.push_back(L"Shares anyone may open without signing in (NullSessionShares): " + JoinW(open, L", ") + L".");
    }

    std::wstring status = warn ? CHECK_WARNING : CHECK_PASS;
    if (lines) *lines = l;
    DebugLog(L"SMB guest: policy " + DwordText(facts.clientPolicy) + L", local " + DwordText(facts.clientLocal) + L", edition " +
             facts.editionId + L", build " + std::to_wstring(facts.build) + L", client allowed " + std::to_wstring(clientAllowed) +
             L", RestrictNullSessAccess " + DwordText(facts.restrictNullSession) + L", null shares " +
             std::to_wstring(open.size()) + L" -> " + status);
    return status;
}

// ===========================================================================
// Inbound firewall rules
// ===========================================================================
static bool AnyText(const std::wstring& s)
{
    std::wstring t = TrimW(s);
    return t.empty() || t == L"*";
}

bool IsPublicAnyAddressAllow(const FirewallRuleFacts& rule)
{
    return rule.enabled && rule.inbound && rule.allow && (rule.profiles & kFirewallProfilePublic) != 0 &&
           AnyText(rule.remoteAddresses);
}

bool IsWindowsManagedRule(const FirewallRuleFacts& rule)
{
    if (!TrimW(rule.packageId).empty()) return true;
    std::wstring g = TrimW(rule.grouping);
    return g.size() > 1 && g[0] == L'@' && g[1] != L'{';
}

bool AllowsEverything(const FirewallRuleFacts& rule)
{
    // A rule bound to a Store app package applies only to that app's processes, even
    // with no program, service or port set.
    return TrimW(rule.packageId).empty() && TrimW(rule.application).empty() && TrimW(rule.service).empty() &&
           rule.protocol == kFirewallProtocolAny && AnyText(rule.localPorts);
}

bool IsReportedFirewallRule(const FirewallRuleFacts& rule)
{
    if (!IsPublicAnyAddressAllow(rule)) return false;
    return !IsWindowsManagedRule(rule) || AllowsEverything(rule);
}

bool IsRiskyFirewallRule(const FirewallRuleFacts& rule)
{
    return rule.programWritable || rule.programInDropFolder || AllowsEverything(rule);
}

std::wstring FirewallProtocolName(long protocol)
{
    switch (protocol) {
    case 1:   return L"ICMPv4";
    case 2:   return L"IGMP";
    case 6:   return L"TCP";
    case 17:  return L"UDP";
    case 41:  return L"IPv6";
    case 47:  return L"GRE";
    case 58:  return L"ICMPv6";
    case kFirewallProtocolAny: return L"any protocol";
    default:  return L"protocol " + std::to_wstring(protocol);
    }
}

std::wstring FirewallRuleLine(const FirewallRuleFacts& rule)
{
    std::wstring line = L"  \"" + rule.name + L"\": ";
    if (!TrimW(rule.application).empty()) line += L"program " + rule.application;
    else if (!TrimW(rule.service).empty()) line += L"service " + rule.service;
    else line += L"any program";
    line += L", " + FirewallProtocolName(rule.protocol);
    if (rule.protocol == 6 || rule.protocol == 17 || rule.protocol == kFirewallProtocolAny) {
        line += AnyText(rule.localPorts) ? std::wstring(L", any local port") : L", local port " + rule.localPorts;
    }
    if (AllowsEverything(rule)) line += L" (allows everything)";
    if (rule.programWritable) line += L" [the program or its folder can be changed by " + rule.writableWho + L"]";
    else if (rule.programInDropFolder) line += L" [the program is in a download, temporary or shared folder]";
    return line + L"\n";
}

void SortFirewallFindings(std::vector<FirewallRuleFacts>& rules)
{
    std::stable_sort(rules.begin(), rules.end(), [](const FirewallRuleFacts& a, const FirewallRuleFacts& b) {
        bool ra = IsRiskyFirewallRule(a);
        bool rb = IsRiskyFirewallRule(b);
        if (ra != rb) return ra;
        int byName = _wcsicmp(a.name.c_str(), b.name.c_str());
        if (byName != 0) return byName < 0;
        return _wcsicmp(a.application.c_str(), b.application.c_str()) < 0;
    });
}

std::wstring FirewallRulesStatus(const FirewallRulesFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    if (!facts.apiOk) {
        status = CHECK_NA;
        t = L"The Windows Firewall programming interface did not answer (" + facts.apiError + L"), so its rules could not be read.";
    }
    else if (facts.publicKnown && !facts.publicOn) {
        status = CHECK_NA;
        t = L"The Public firewall profile is off, so its rules do not apply right now. The Windows Firewall check reports the "
            L"profile itself.";
    }
    else if (facts.blockAllInbound) {
        status = CHECK_PASS;
        t = L"The Public profile blocks all incoming connections, including allowed apps, so no allow rule applies there (" +
            std::to_wstring(facts.rulesRead) + L" rules read).";
    }
    else if (facts.reportedRisky > 0 || facts.reportedWideOpen > 0) {
        status = CHECK_WARNING;
        t = std::to_wstring(facts.reported) + L" inbound rule(s) let any computer on a public network connect to this PC";
        std::vector<std::wstring> why;
        if (facts.reportedRisky > 0) {
            why.push_back(std::to_wstring(facts.reportedRisky) + L" for a program in a folder normal users can change or where "
                          L"downloads and temporary files land");
        }
        if (facts.reportedWideOpen > 0) {
            why.push_back(std::to_wstring(facts.reportedWideOpen) + L" that allow everything (any program, protocol and port)");
        }
        t += L"; " + JoinW(why, L", and ") + L" (listed first; the fix plan turns off only these).";
    }
    else if (facts.reported > 0) {
        status = CHECK_INFO;
        t = std::to_wstring(facts.reported) + L" inbound rule(s) let any computer on a public network reach one program or "
            L"port on this PC. Windows adds such a rule when someone clicks Allow for a program, so this is common. None is "
            L"for a program normal users can change, and none opens everything. Turn off any you do not recognise.";
    }
    else {
        status = CHECK_PASS;
        t = L"No enabled inbound rule opens this PC to any address on public networks (" + std::to_wstring(facts.rulesRead) +
            L" rules read).";
    }
    if (facts.apiOk && facts.windowsManagedSkipped > 0 && status != CHECK_NA) {
        t += L" " + std::to_wstring(facts.windowsManagedSkipped) + L" rule(s) of Windows' own groups and Store apps that are "
             L"limited to one app, program, service or port were not judged.";
    }
    if (text) *text = t;
    DebugLog(L"Firewall rules: api " + std::to_wstring(facts.apiOk) + L", public on " + std::to_wstring(facts.publicOn) +
             L", block all " + std::to_wstring(facts.blockAllInbound) + L", read " + std::to_wstring(facts.rulesRead) +
             L", reported " + std::to_wstring(facts.reported) + L" (" + std::to_wstring(facts.reportedRisky) + L" risky), skipped " +
             std::to_wstring(facts.windowsManagedSkipped) + L" -> " + status);
    return status;
}

FirewallStoreRule ParseFirewallRuleData(const std::wstring& id, const std::wstring& data)
{
    FirewallStoreRule r;
    r.id = id;
    std::vector<std::wstring> ports;
    bool anyProfile = false;
    bool profileSeen = false;
    bool sawField = false;
    size_t start = 0;
    while (start <= data.size()) {
        size_t bar = data.find(L'|', start);
        std::wstring field = data.substr(start, bar == std::wstring::npos ? std::wstring::npos : bar - start);
        start = bar == std::wstring::npos ? data.size() + 1 : bar + 1;
        size_t eq = field.find(L'=');
        if (eq == std::wstring::npos) continue;   // the version token ("v2.10") and empty tails
        std::wstring key = field.substr(0, eq);
        std::wstring value = field.substr(eq + 1);
        sawField = true;
        if (EqualsI(key, L"Action")) r.allow = EqualsI(value, L"Allow");
        else if (EqualsI(key, L"Active")) r.active = EqualsI(value, L"TRUE");
        else if (EqualsI(key, L"Dir")) r.inbound = EqualsI(value, L"In");
        else if (EqualsI(key, L"Protocol")) r.protocol = static_cast<long>(wcstol(value.c_str(), nullptr, 10));
        else if (EqualsI(key, L"Profile")) {
            profileSeen = true;
            if (EqualsI(value, L"Public")) anyProfile = true;
        }
        else if (EqualsI(key, L"LPort")) ports.push_back(value);
        else if (EqualsI(key, L"App")) r.application = value;
        else if (EqualsI(key, L"Svc")) r.service = value;
        else if (EqualsI(key, L"Name")) r.name = value;
        else if (EqualsI(key, L"EmbedCtxt")) r.grouping = value;
        else if (EqualsI(key, L"AppPkgId") || EqualsI(key, L"PFN")) {
            if (r.package.empty()) r.package = value;
        }
        else if (EqualsI(key, L"RA4") || EqualsI(key, L"RA6") || EqualsI(key, L"RA42") || EqualsI(key, L"RA62")) {
            if (!AnyText(value) && !EqualsI(value, L"Any")) r.remoteAny = false;
        }
    }
    r.allPublic = !profileSeen || anyProfile;
    r.localPorts = JoinW(ports, L",");
    r.parsed = sawField && !r.id.empty();
    return r;
}

static std::wstring NormalisedPorts(const std::wstring& ports)
{
    if (AnyText(ports)) return L"";
    std::vector<std::wstring> parts = SplitW(ToLowerW(ports), L',');
    std::sort(parts.begin(), parts.end());
    return JoinW(parts, L",");
}

static std::wstring RuleKey(const std::wstring& name, const std::wstring& app, const std::wstring& service, long protocol,
                            const std::wstring& ports, const std::wstring& grouping)
{
    return ToLowerW(TrimW(name)) + L"|" + ToLowerW(TrimW(app)) + L"|" + ToLowerW(TrimW(service)) + L"|" +
           std::to_wstring(protocol) + L"|" + NormalisedPorts(ports) + L"|" + ToLowerW(TrimW(grouping));
}

std::wstring FirewallRuleKey(const FirewallRuleFacts& rule)
{
    return RuleKey(rule.name, rule.application, rule.service, rule.protocol, rule.localPorts, rule.grouping);
}

std::wstring FirewallRuleKey(const FirewallStoreRule& rule)
{
    return RuleKey(rule.name, rule.application, rule.service, rule.protocol, rule.localPorts, rule.grouping);
}

std::vector<std::wstring> MatchFirewallStoreIds(const FirewallRuleFacts& rule, const std::vector<FirewallStoreRule>& store)
{
    std::vector<std::wstring> ids;
    std::wstring key = FirewallRuleKey(rule);
    for (const FirewallStoreRule& s : store) {
        if (!s.parsed || !s.active || !s.inbound || !s.allow || !s.allPublic || !s.remoteAny) continue;
        if (FirewallRuleKey(s) == key) ids.push_back(s.id);
    }
    return ids;
}

std::wstring StorePackageForRule(const FirewallRuleFacts& rule, const std::vector<FirewallStoreRule>& store)
{
    std::wstring key = FirewallRuleKey(rule);
    std::wstring package;
    for (const FirewallStoreRule& s : store) {
        if (!s.parsed || !s.active || !s.inbound || !s.allow || !s.allPublic || !s.remoteAny) continue;
        if (FirewallRuleKey(s) != key) continue;
        if (TrimW(s.package).empty()) return L"";   // one entry for any app: nothing is assumed
        if (package.empty()) package = TrimW(s.package);
    }
    return package;
}

bool HasWildcardCharacters(const std::wstring& name)
{
    return name.find_first_of(L"*?[]`") != std::wstring::npos;
}

// ===========================================================================
// Automatic sign-in
// ===========================================================================
std::wstring AutoLogonStatus(const AutoLogonFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    bool on = TrimW(facts.autoAdminLogon) == L"1";
    bool plain = facts.defaultPasswordPresent && facts.defaultPasswordBytes > sizeof(wchar_t);
    std::wstring user = TrimW(facts.defaultUserName);
    std::wstring domain = TrimW(facts.defaultDomainName);
    std::wstring account = user.empty() ? std::wstring(L"an account the registry does not name")
                                        : (domain.empty() ? user : domain + L"\\" + user);
    if (!facts.keyReadable) {
        status = CHECK_NA;
        t = L"The sign-in settings (HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon) could not be read. Run as "
            L"administrator to read them.";
    }
    else if (!on) {
        status = CHECK_PASS;
        t = L"Windows does not sign in by itself (AutoAdminLogon is " +
            (TrimW(facts.autoAdminLogon).empty() ? std::wstring(L"not set") : L"\"" + TrimW(facts.autoAdminLogon) + L"\"") + L").";
        if (plain) {
            t += L" A DefaultPassword value is still stored in the registry, where every user can read it; delete it.";
        }
    }
    else if (plain) {
        status = CHECK_FAIL;
        t = L"Windows signs in by itself as " + account + L", with the password stored in plain text in the registry "
            L"(DefaultPassword), where every user and program on this PC can read it. This check only saw that the value "
            L"exists; it did not read it.";
    }
    else {
        status = CHECK_WARNING;
        t = L"Windows signs in by itself as " + account + L". No password is stored in plain text in the registry, so it is "
            L"kept encrypted as an LSA secret, or the account has none. Anyone who switches the PC on gets this account's "
            L"desktop.";
        if (facts.defaultPasswordPresent) t += L" (DefaultPassword exists but is empty.)";
    }
    if (on && facts.autoLogonCount.set) {
        t += L" AutoLogonCount is " + std::to_wstring(facts.autoLogonCount.value) +
             L": Windows turns automatic sign-in off after that many sign-ins.";
    }
    if (text) *text = t;
    DebugLog(L"Auto sign-in: readable " + std::to_wstring(facts.keyReadable) + L", on " + std::to_wstring(on) +
             L", DefaultPassword present " + std::to_wstring(facts.defaultPasswordPresent) + L" (" +
             std::to_wstring(facts.defaultPasswordBytes) + L" bytes), user named " + std::to_wstring(!user.empty()) + L" -> " + status);
    return status;
}

// ===========================================================================
// NTLM and LAN Manager
// ===========================================================================
static int Worse(int a, int b)
{
    return a > b ? a : b;
}

// 0 pass, 1 warning, 2 fail
static std::wstring MinSecLine(const wchar_t* label, const wchar_t* valueName, const OptionalDword& v, int& level)
{
    DWORD value = v.set ? v.value : kNtlmDefaultMinSec;
    bool has128 = (value & kNtlmRequire128Bit) != 0;
    bool hasV2 = (value & kNtlmRequireV2Session) != 0;
    std::wstring line = std::wstring(label) + L" (" + valueName + L"): " +
                        (v.set ? HexText(value) : HexText(value) + L", the Windows default (not set)") + L": ";
    if (has128 && hasV2) {
        line += L"requires NTLMv2 session security and 128-bit encryption.";
    }
    else {
        level = Worse(level, 1);
        std::vector<std::wstring> missing;
        if (!hasV2) missing.push_back(L"NTLMv2 session security");
        if (!has128) missing.push_back(L"128-bit encryption");
        line += L"does not require " + JoinW(missing, L" or ") + L".";
    }
    return line;
}

std::wstring NtlmStatus(const NtlmFacts& facts, std::vector<std::wstring>* lines)
{
    std::vector<std::wstring> l;
    if (!facts.lsaReadable) {
        l.push_back(L"The sign-in protocol settings (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa) could not be read. Run as "
                    L"administrator to read them.");
        if (lines) *lines = l;
        DebugLog(L"NTLM: Lsa key unreadable -> N/A");
        return CHECK_NA;
    }
    int level = 0;

    DWORD lm = facts.lmCompatibilityLevel.set ? facts.lmCompatibilityLevel.value : kLmCompatibilityDefault;
    std::wstring head = L"LAN Manager authentication level (LmCompatibilityLevel): " +
                        (facts.lmCompatibilityLevel.set ? std::to_wstring(lm) : std::to_wstring(lm) + L", the Windows default (not set)") +
                        L": ";
    switch (lm) {
    case 0:
        level = Worse(level, 2);
        l.push_back(head + L"this PC answers sign-in requests with LM and NTLMv1, old answers that can be cracked quickly.");
        break;
    case 1:
        level = Worse(level, 2);
        l.push_back(head + L"this PC answers with LM and NTLMv1 (NTLMv2 session security only when the other side asks).");
        break;
    case 2:
        level = Worse(level, 2);
        l.push_back(head + L"this PC answers with NTLMv1, which can be cracked or turned back into the password hash.");
        break;
    case 3:
        level = Worse(level, 1);
        l.push_back(head + L"this PC answers with NTLMv2 only, but accepts LM and NTLMv1 answers from computers that sign in "
                           L"to it. Level 5 refuses them.");
        break;
    case 4:
        level = Worse(level, 1);
        l.push_back(head + L"this PC answers with NTLMv2 only and refuses LM, but still accepts NTLMv1 answers from computers "
                           L"that sign in to it. Level 5 refuses them.");
        break;
    case 5:
        l.push_back(head + L"this PC answers with NTLMv2 only and refuses LM and NTLMv1 answers.");
        break;
    default:
        level = Worse(level, 1);
        l.push_back(head + L"not a value Windows defines (0 to 5), so what it does is not known.");
        break;
    }

    if (facts.noLmHash.set && facts.noLmHash.value == 0) {
        level = Worse(level, 2);
        l.push_back(L"LM password hashes (NoLMHash): 0: Windows stores a LAN Manager hash of each password set from now on. "
                    L"LM hashes are cracked in minutes.");
    }
    else {
        l.push_back(L"LM password hashes (NoLMHash): " +
                    (facts.noLmHash.set ? std::to_wstring(facts.noLmHash.value) : std::wstring(L"not set, the Windows default 1")) +
                    L": no LAN Manager hash is stored for new passwords.");
    }

    l.push_back(MinSecLine(L"Minimum session security when this PC signs in elsewhere", L"NtlmMinClientSec", facts.minClientSec, level));
    l.push_back(MinSecLine(L"Minimum session security when others sign in to this PC", L"NtlmMinServerSec", facts.minServerSec, level));

    std::wstring status = level == 2 ? CHECK_FAIL : level == 1 ? CHECK_WARNING : CHECK_PASS;
    if (lines) *lines = l;
    DebugLog(L"NTLM: level " + DwordText(facts.lmCompatibilityLevel) + L", NoLMHash " + DwordText(facts.noLmHash) +
             L", client " + DwordText(facts.minClientSec) + L", server " + DwordText(facts.minServerSec) + L" -> " + status);
    return status;
}

// ===========================================================================
// Driver services
// ===========================================================================
std::wstring DriverImagePathToFile(const std::wstring& imagePathIn, const std::wstring& serviceName, const std::wstring& systemRootIn)
{
    std::wstring root = TrimW(systemRootIn);
    while (!root.empty() && root.back() == L'\\') root.pop_back();
    std::wstring p = TrimW(imagePathIn);
    if (!p.empty() && p[0] == L'"') {
        size_t end = p.find(L'"', 1);
        p = end == std::wstring::npos ? p.substr(1) : p.substr(1, end - 1);
    }
    if (p.empty()) return root + L"\\System32\\drivers\\" + serviceName + L".sys";
    p = ReplaceAllI(p, L"%SystemRoot%", root);
    p = ReplaceAllI(p, L"%windir%", root);
    if (StartsWithI(p, L"\\SystemRoot\\")) return root + p.substr(11);
    if (StartsWithI(p, L"\\??\\") || StartsWithI(p, L"\\\\?\\")) return p.substr(4);
    if (p.size() >= 2 && p[1] == L':') return p;
    if (StartsWithI(p, L"\\\\")) return p;
    if (p[0] == L'\\') return (root.size() >= 2 ? root.substr(0, 2) : std::wstring(L"C:")) + p;
    return root + L"\\" + p;
}

unsigned DriverProblems(const DriverFacts& driver)
{
    if (driver.startType == SERVICE_DISABLED) return 0;
    if (!driver.fileExists) return kDriverMissing;
    unsigned bits = 0;
    if (!driver.signatureValid) bits |= kDriverUnsigned;
    if (driver.folderWritable) bits |= kDriverWritableFolder;
    if (driver.fileWritable) bits |= kDriverWritableFile;
    return bits;
}

int DriverStartRank(DWORD startType)
{
    switch (startType) {
    case SERVICE_BOOT_START:   return 0;
    case SERVICE_SYSTEM_START: return 1;
    case SERVICE_AUTO_START:   return 2;
    case SERVICE_DEMAND_START: return 3;
    case SERVICE_DISABLED:     return 4;
    default:                   return 5;
    }
}

void SortDriverFindings(std::vector<DriverFacts>& drivers)
{
    std::stable_sort(drivers.begin(), drivers.end(), [](const DriverFacts& a, const DriverFacts& b) {
        int ra = DriverStartRank(a.startType);
        int rb = DriverStartRank(b.startType);
        if (ra != rb) return ra < rb;
        return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
    });
}

static const wchar_t* DriverStartText(DWORD startType)
{
    switch (startType) {
    case SERVICE_BOOT_START:   return L"Boot start";
    case SERVICE_SYSTEM_START: return L"System start";
    case SERVICE_AUTO_START:   return L"Automatic";
    case SERVICE_DEMAND_START: return L"Manual";
    case SERVICE_DISABLED:     return L"Disabled";
    default:                   return L"unknown start type";
    }
}

std::wstring DriverFindingLine(const DriverFacts& driver)
{
    unsigned bits = DriverProblems(driver);
    std::vector<std::wstring> problems;
    if (bits & kDriverMissing) problems.push_back(L"the file is missing");
    if (bits & kDriverUnsigned) {
        problems.push_back(L"not validly signed" + (driver.signatureStatus.empty() ? std::wstring() : L" (" + driver.signatureStatus + L")"));
    }
    if (bits & kDriverWritableFile) problems.push_back(L"the file can be changed by " + driver.writableWho);
    if (bits & kDriverWritableFolder) problems.push_back(L"its folder can be changed by " + driver.writableWho);
    return L"  [" + driver.name + L"] " + driver.file + L" (" + DriverStartText(driver.startType) + L"): " + JoinW(problems, L"; ") + L"\n";
}

std::wstring DriversStatus(const DriversFacts& facts, std::wstring* text)
{
    std::wstring status;
    std::wstring t;
    if (!facts.listed) {
        status = CHECK_NA;
        t = L"The Service Control Manager could not list the driver services (" + facts.listError + L").";
    }
    else if (facts.checked == 0 && facts.unreadable > 0) {
        status = CHECK_NA;
        t = L"None of the " + std::to_wstring(facts.total) + L" driver services' settings could be read. Run as administrator "
            L"to read them.";
    }
    else if (facts.flagged > 0) {
        status = CHECK_WARNING;
        t = std::to_wstring(facts.flagged) + L" driver service(s) point to a file that is missing, not validly signed, or that "
            L"normal users can change (boot and system start drivers first):";
    }
    else {
        status = CHECK_PASS;
        t = L"All " + std::to_wstring(facts.checked) + L" driver service(s) checked point to a validly signed file that normal "
            L"users cannot change.";
    }
    if (facts.listed && facts.disabled > 0) {
        t += L" " + std::to_wstring(facts.disabled) + L" disabled driver service(s) were not judged: they cannot load until an "
             L"administrator changes their start type.";
    }
    if (facts.listed && facts.unreadable > 0 && facts.checked > 0) {
        t += L" " + std::to_wstring(facts.unreadable) + L" driver service(s) could not be read; run as administrator to check "
             L"them too.";
    }
    if (text) *text = t;
    DebugLog(L"Drivers: listed " + std::to_wstring(facts.listed) + L", total " + std::to_wstring(facts.total) + L", checked " +
             std::to_wstring(facts.checked) + L", unreadable " + std::to_wstring(facts.unreadable) + L", disabled " +
             std::to_wstring(facts.disabled) + L", flagged " + std::to_wstring(facts.flagged) + L" -> " + status);
    return status;
}
