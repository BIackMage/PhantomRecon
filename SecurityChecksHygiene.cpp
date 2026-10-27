#include "pch.h"
#include "SecurityChecksHygiene.h"

#include "AppPaths.h"
#include "HygieneRules.h"
#include "RegUtil.h"
#include "SystemInfo.h"
#include "TextUtils.h"

#include <winsock2.h>
#include <iphlpapi.h>
#include <lm.h>
#include <map>
#include <set>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SecurityChecksHygiene] " + msg + L"\n").c_str());
}

static OptionalDword ReadOptionalDword(HKEY root, const std::wstring& key, const std::wstring& value)
{
    OptionalDword o;
    o.set = RegReadDword(root, key, value, o.value);
    return o;
}

// Readable, or simply not there (a missing key holds no setting, which is not an error).
static bool KeyReadable(const std::wstring& key)
{
    LONG rc = RegOpenStatus(HKEY_LOCAL_MACHINE, key);
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
}

static std::wstring System32Path(const wchar_t* file)
{
    std::wstring root = ExpandEnvironment(L"%SystemRoot%");
    if (root.empty() || root[0] == L'%') root = L"C:\\Windows";
    return root + L"\\System32\\" + file;
}

// ===========================================================================
// WDigest password caching
// ===========================================================================
SecurityCheckResult CheckWDigest()
{
    SecurityCheckResult result = MakeCheckResult(L"cred.wdigest");
    const wchar_t* key = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";
    WDigestFacts facts;
    facts.keyReadable = KeyReadable(key);
    facts.useLogonCredential = ReadOptionalDword(HKEY_LOCAL_MACHINE, key, L"UseLogonCredential");
    facts.build = GetWindowsBuildNumber();
    std::wstring text;
    result.status = WDigestStatus(facts, &text);
    result.detail = text;
    DebugLog(L"WDigest -> " + result.status);
    return result;
}

// ===========================================================================
// Windows Update paused or deferred
// ===========================================================================
SecurityCheckResult CheckUpdatePause()
{
    SecurityCheckResult result = MakeCheckResult(L"wu.paused");
    const wchar_t* ux = L"SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings";
    const wchar_t* policy = L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";
    UpdatePauseFacts facts;
    facts.settingsReadable = KeyReadable(ux);
    facts.policyReadable = KeyReadable(policy);
    facts.pauseUpdatesExpiry = RegReadString(HKEY_LOCAL_MACHINE, ux, L"PauseUpdatesExpiryTime", false);
    facts.pauseQualityEnd = RegReadString(HKEY_LOCAL_MACHINE, ux, L"PauseQualityUpdatesEndTime", false);
    facts.pauseFeatureEnd = RegReadString(HKEY_LOCAL_MACHINE, ux, L"PauseFeatureUpdatesEndTime", false);
    facts.deferQuality = ReadOptionalDword(HKEY_LOCAL_MACHINE, policy, L"DeferQualityUpdates");
    facts.deferQualityDays = ReadOptionalDword(HKEY_LOCAL_MACHINE, policy, L"DeferQualityUpdatesPeriodInDays");
    facts.deferFeature = ReadOptionalDword(HKEY_LOCAL_MACHINE, policy, L"DeferFeatureUpdates");
    facts.deferFeatureDays = ReadOptionalDword(HKEY_LOCAL_MACHINE, policy, L"DeferFeatureUpdatesPeriodInDays");
    facts.policyPauseQualityStart = RegReadString(HKEY_LOCAL_MACHINE, policy, L"PauseQualityUpdatesStartTime", false);
    facts.policyPauseFeatureStart = RegReadString(HKEY_LOCAL_MACHINE, policy, L"PauseFeatureUpdatesStartTime", false);
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    facts.nowUnix = FileTimeToUnix(now);

    std::vector<std::wstring> lines;
    result.status = UpdatePauseStatus(facts, &lines);
    std::wstring head = result.status == CHECK_WARNING ? L"Security updates are held back on this PC." :
                        result.status == CHECK_PASS ? L"Security updates are not paused or held back." :
                        L"Whether updates are paused could not be read.";
    result.detail = head + L"\n" + JoinW(lines, L"\n") + L"\nThe Windows Update check reports the service, the last install "
                    L"and a pending restart.";
    DebugLog(L"Update pause -> " + result.status);
    return result;
}

// ===========================================================================
// Remote Assistance
// ===========================================================================
SecurityCheckResult CheckRemoteAssistance()
{
    SecurityCheckResult result = MakeCheckResult(L"net.remoteassist");
    const wchar_t* local = L"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance";
    const wchar_t* policy = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services";
    RemoteAssistFacts facts;
    facts.programPresent = FileExists(System32Path(L"msra.exe"));
    facts.localReadable = KeyReadable(local);
    facts.localAllowGetHelp = ReadOptionalDword(HKEY_LOCAL_MACHINE, local, L"fAllowToGetHelp");
    facts.localAllowFullControl = ReadOptionalDword(HKEY_LOCAL_MACHINE, local, L"fAllowFullControl");
    facts.policyAllowGetHelp = ReadOptionalDword(HKEY_LOCAL_MACHINE, policy, L"fAllowToGetHelp");
    facts.policyAllowFullControl = ReadOptionalDword(HKEY_LOCAL_MACHINE, policy, L"fAllowFullControl");
    facts.policyAllowUnsolicited = ReadOptionalDword(HKEY_LOCAL_MACHINE, policy, L"fAllowUnsolicited");
    facts.policyUnsolicitedFullControl = ReadOptionalDword(HKEY_LOCAL_MACHINE, policy, L"fAllowUnsolicitedFullControl");

    std::vector<std::wstring> lines;
    result.status = RemoteAssistStatus(facts, &lines);
    std::wstring head = result.status == CHECK_WARNING ? L"Remote Assistance lets a helper take control of this PC." :
                        result.status == CHECK_PASS ? L"Remote Assistance cannot be used to take control of this PC." :
                        L"Remote Assistance was not judged.";
    result.detail = head + L"\n" + JoinW(lines, L"\n");
    DebugLog(L"Remote Assistance -> " + result.status);
    return result;
}

// ===========================================================================
// Cached domain sign-ins
// ===========================================================================
SecurityCheckResult CheckCachedLogons()
{
    SecurityCheckResult result = MakeCheckResult(L"cred.cachedlogons");
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    CachedLogonsFacts facts;
    LPWSTR name = NULL;
    NETSETUP_JOIN_STATUS join = NetSetupUnknownStatus;
    NET_API_STATUS rc = NetGetJoinInformation(NULL, &name, &join);
    if (name) NetApiBufferFree(name);   // the domain or workgroup name is not needed
    facts.joinKnown = rc == NERR_Success && join != NetSetupUnknownStatus;
    facts.domainJoined = facts.joinKnown && join == NetSetupDomainName;
    facts.keyReadable = RegOpenStatus(HKEY_LOCAL_MACHINE, key) == ERROR_SUCCESS;
    facts.valuePresent = RegValueExists(HKEY_LOCAL_MACHINE, key, L"CachedLogonsCount");
    if (facts.valuePresent) {
        facts.cachedLogonsCount = RegReadString(HKEY_LOCAL_MACHINE, key, L"CachedLogonsCount", false);
        if (facts.cachedLogonsCount.empty()) {
            DWORD asNumber = 0;   // a tool may have written it as a DWORD
            if (RegReadDword(HKEY_LOCAL_MACHINE, key, L"CachedLogonsCount", asNumber)) facts.cachedLogonsCount = std::to_wstring(asNumber);
        }
    }
    std::wstring text;
    result.status = CachedLogonsStatus(facts, &text);
    result.detail = text;
    DebugLog(L"Cached logons -> " + result.status + L" (NetGetJoinInformation " + std::to_wstring(rc) + L", join state " +
             std::to_wstring(static_cast<int>(join)) + L")");
    return result;
}

// ===========================================================================
// Windows' built-in sudo
// ===========================================================================
SecurityCheckResult CheckSudo()
{
    SecurityCheckResult result = MakeCheckResult(L"hard.sudo");
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Sudo";
    SudoFacts facts;
    bool program = FileExists(System32Path(L"sudo.exe"));
    bool settings = RegKeyExists(HKEY_LOCAL_MACHINE, key);
    facts.available = program || settings;
    facts.enabled = ReadOptionalDword(HKEY_LOCAL_MACHINE, key, L"Enabled");
    facts.policyMaximum = ReadOptionalDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Sudo", L"Enabled");
    std::wstring text;
    result.status = SudoStatus(facts, &text);
    result.detail = text;
    DebugLog(L"sudo -> " + result.status + L" (sudo.exe " + std::to_wstring(program) + L", settings key " + std::to_wstring(settings) + L")");
    return result;
}

// ===========================================================================
// DNS over HTTPS
// ===========================================================================
static const wchar_t* const kDnscacheInterfaces = L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\InterfaceSpecificParameters";

// Adapter GUID ("{...}", lowercase) to its name, for every adapter Windows lists.
static std::map<std::wstring, std::wstring> AdapterNames()
{
    std::map<std::wstring, std::wstring> names;
    ULONG size = 16 * 1024;
    std::vector<BYTE> buffer(size);
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (rc != NO_ERROR) {
        DebugLog(L"GetAdaptersAddresses failed, error " + std::to_wstring(rc));
        return names;
    }
    for (IP_ADAPTER_ADDRESSES* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
        if (!a->AdapterName || !a->FriendlyName) continue;
        std::string guid = a->AdapterName;
        names[ToLowerW(std::wstring(guid.begin(), guid.end()))] = a->FriendlyName;
    }
    return names;
}

static void ReadDohServers(DohFacts& facts)
{
    LONG open = RegOpenStatus(HKEY_LOCAL_MACHINE, kDnscacheInterfaces);
    facts.interfacesRead = open == ERROR_SUCCESS || open == ERROR_FILE_NOT_FOUND;
    if (open != ERROR_SUCCESS) {
        DebugLog(L"InterfaceSpecificParameters open status " + std::to_wstring(open));
        return;
    }
    std::map<std::wstring, std::wstring> names = AdapterNames();
    std::set<std::wstring> seen;
    // Windows 11 keeps the settings under DohInterfaceSettings; newer builds also use
    // DohProfileSettings. Both are read; an entry found under both is listed once.
    const wchar_t* const groups[] = { L"DohInterfaceSettings", L"DohProfileSettings" };
    for (const std::wstring& guid : RegEnumSubKeys(HKEY_LOCAL_MACHINE, kDnscacheInterfaces)) {
        auto named = names.find(ToLowerW(guid));
        std::wstring adapter = named != names.end() ? named->second : L"adapter " + guid;
        for (const wchar_t* group : groups) {
            for (int family = 0; family < 2; ++family) {
                std::wstring familyKey = std::wstring(kDnscacheInterfaces) + L"\\" + guid + L"\\" + group + (family == 0 ? L"\\Doh" : L"\\Doh6");
                for (const std::wstring& server : RegEnumSubKeys(HKEY_LOCAL_MACHINE, familyKey)) {
                    if (!seen.insert(ToLowerW(guid + L"|" + server)).second) continue;
                    std::wstring serverKey = familyKey + L"\\" + server;
                    DohServerSetting s;
                    s.adapter = adapter;
                    s.server = server;
                    s.ipv6 = family == 1;
                    RegReadDword(HKEY_LOCAL_MACHINE, serverKey, L"DohFlags", s.flags);   // the low 32 bits of the QWORD
                    s.dohTemplate = RegReadString(HKEY_LOCAL_MACHINE, serverKey, L"DohTemplate", false);
                    facts.servers.push_back(s);
                }
            }
        }
    }
    DebugLog(std::to_wstring(facts.servers.size()) + L" per-adapter DNS over HTTPS entries");
}

SecurityCheckResult CheckDnsOverHttps()
{
    SecurityCheckResult result = MakeCheckResult(L"net.doh");
    DohFacts facts;
    facts.policy = ReadOptionalDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"DoHPolicy");
    facts.autoDoh = ReadOptionalDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", L"EnableAutoDoh");
    facts.knownServers = static_cast<int>(
        RegEnumSubKeys(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DohWellKnownServers").size());
    ReadDohServers(facts);
    std::wstring text;
    result.status = DohStatus(facts, &text);
    result.detail = text;
    DebugLog(L"DNS over HTTPS -> " + result.status);
    return result;
}
