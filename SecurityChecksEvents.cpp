#include "pch.h"
#include "SecurityChecksEvents.h"

#include "AppPaths.h"
#include "CheckHelpers.h"
#include "EventLogQuery.h"
#include "EventRules.h"
#include "FileAnalysis.h"
#include "ServiceUtil.h"
#include "TextUtils.h"

#include <windows.h>
#include <lm.h>
#include <sddl.h>

#include <map>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SecurityChecksEvents] " + msg + L"\n").c_str());
}

static const wchar_t* const kSecurityChannel  = L"Security";
static const wchar_t* const kSystemChannel    = L"System";
static const wchar_t* const kDefenderChannel  = L"Microsoft-Windows-Windows Defender/Operational";
static const wchar_t* const kAuditProvider    = L"Microsoft-Windows-Security-Auditing";
static const wchar_t* const kEventlogProvider = L"Microsoft-Windows-Eventlog";
static const wchar_t* const kScmProvider      = L"Service Control Manager";
static const wchar_t* const kDefenderProvider = L"Microsoft-Windows-Windows Defender";

static EventQueryResult Run(const wchar_t* channel, const wchar_t* provider, std::vector<unsigned int> ids, unsigned int days)
{
    EventQuery q;
    q.channel = channel;
    q.provider = provider;
    q.ids = std::move(ids);
    q.days = days;
    q.maxEvents = kDefaultMaxEvents;
    EventQueryResult r = RunEventQuery(q);
    DebugLog(std::wstring(channel) + L": " + EventQueryStatusName(r.status) + L", " + std::to_wstring(r.events.size()) + L" event(s)");
    return r;
}

static SecurityCheckResult FromVerdict(const wchar_t* id, const EventVerdict& verdict)
{
    SecurityCheckResult result = MakeCheckResult(id);
    result.status = verdict.status;
    result.detail = TrimW(verdict.detail);
    DebugLog(std::wstring(id) + L" -> " + result.status);
    return result;
}

// ---------------------------------------------------------------------------
// 1. Logs cleared
// ---------------------------------------------------------------------------
SecurityCheckResult CheckEventsLogCleared()
{
    EventQueryResult security = Run(kSecurityChannel, kEventlogProvider, { 1102 }, kLogClearedDays);
    EventQueryResult system = Run(kSystemChannel, kEventlogProvider, { 104 }, kLogClearedDays);
    return FromVerdict(L"events.logcleared", LogClearedVerdict(security, system));
}

// ---------------------------------------------------------------------------
// 2. Services installed
// ---------------------------------------------------------------------------

// Event 7045 logs the display name. The service key name, from this PC's own Service
// Control Manager, or "" when no service has that display name (any more).
static std::wstring ServiceKeyName(const std::wstring& displayName)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        DebugLog(L"ServiceKeyName: OpenSCManager failed: " + std::to_wstring(GetLastError()));
        return L"";
    }
    wchar_t key[512] = {};
    DWORD size = static_cast<DWORD>(sizeof(key) / sizeof(key[0]));
    std::wstring out;
    if (GetServiceKeyNameW(scm, displayName.c_str(), key, &size)) out = key;
    CloseServiceHandle(scm);
    DebugLog(L"ServiceKeyName: \"" + displayName + L"\" -> \"" + out + L"\"");
    return out;
}

// True when a service of this name (key or display name) still runs this program.
// An app update registers its service again with a new program path; the old entry
// then no longer belongs to any service.
static bool ServiceStillRunsProgram(const std::wstring& name, const std::wstring& program)
{
    ServiceInfo info;
    bool found = QueryServiceByName(name, info);
    if (!found) {
        std::wstring key = ServiceKeyName(name);
        if (!key.empty()) found = QueryServiceByName(key, info);
    }
    bool same = found && !program.empty() && EqualsI(info.exePath, program);
    DebugLog(L"ServiceStillRunsProgram: " + name + L" found " + std::to_wstring(found) + L", same program " + std::to_wstring(same));
    return same;
}

// Fill in where the program is, whether it is there and signed, and whether normal
// users can change it. Reuses the helpers the persistence and service checks use.
static void InspectInstall(ServiceInstall& s)
{
    s.program = s.imagePath.empty() ? std::wstring() : ExtractServiceExePath(s.imagePath);
    if (!s.program.empty() && s.program.find(L'\\') == std::wstring::npos) {
        wchar_t full[MAX_PATH] = {};
        if (SearchPathW(NULL, s.program.c_str(), L".exe", MAX_PATH, full, NULL)) s.program = full;
    }
    s.stillInstalled = ServiceStillRunsProgram(s.name, s.program);
    if (s.program.empty()) {
        DebugLog(L"InspectInstall: " + s.name + L" names no program");
        return;
    }
    s.dropFolder = IsUserDropLocation(s.program);
    s.managedFolder = IsUnderProgramFiles(s.program) || IsPackagedAppPath(s.program);
    if (!FileExists(s.program)) {
        s.missing = true;
        DebugLog(L"InspectInstall: " + s.name + L" program missing: " + s.program);
        return;
    }
    if (!s.dropFolder && !IsProtectedWindowsPath(s.program) && !IsPackagedAppPath(s.program)) {
        std::wstring who;
        if (LowPrivilegeWritable(DirectoryOf(s.program), true, &who) || LowPrivilegeWritable(s.program, false, &who)) {
            s.userWritable = true;
            s.writableBy = who;
        }
    }
    if (SignatureExpected(s.program)) {
        SignatureSummary sig = GetSignatureSummary(s.program);
        s.signatureChecked = true;
        s.validlySigned = sig.valid;
        s.signatureStatus = sig.status;
    }
    DebugLog(L"InspectInstall: " + s.name + L" " + s.program + L", drop " + std::to_wstring(s.dropFolder) + L", writable " +
             std::to_wstring(s.userWritable) + L", signed " + std::to_wstring(s.validlySigned));
}

SecurityCheckResult CheckEventsNewServices()
{
    EventQueryResult system = Run(kSystemChannel, kScmProvider, { 7045 }, kNewServiceDays);
    std::vector<ServiceInstall> installs = ServiceInstallsFromEvents(system.events);
    for (ServiceInstall& s : installs) InspectInstall(s);
    return FromVerdict(L"events.newservices", NewServicesVerdict(system, installs));
}

// ---------------------------------------------------------------------------
// 3. Accounts created, members added to Administrators
// ---------------------------------------------------------------------------

// SID text to name for every local account, from this PC's own account database
// (NetUserEnum on the local computer). No name lookup goes to a domain controller.
static std::map<std::wstring, std::wstring> LocalAccountSids()
{
    std::map<std::wstring, std::wstring> out;
    DWORD resume = 0;
    NET_API_STATUS status;
    do {
        LPBYTE buffer = NULL;
        DWORD read = 0;
        DWORD total = 0;
        status = NetUserEnum(NULL, 23, FILTER_NORMAL_ACCOUNT, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if ((status == NERR_Success || status == ERROR_MORE_DATA) && buffer) {
            const USER_INFO_23* users = reinterpret_cast<const USER_INFO_23*>(buffer);
            for (DWORD i = 0; i < read; ++i) {
                if (!users[i].usri23_name || !users[i].usri23_user_sid) continue;
                LPWSTR text = NULL;
                if (ConvertSidToStringSidW(users[i].usri23_user_sid, &text) && text) {
                    out[text] = users[i].usri23_name;
                    LocalFree(text);
                }
            }
        }
        if (buffer) NetApiBufferFree(buffer);
    } while (status == ERROR_MORE_DATA);
    DebugLog(L"LocalAccountSids: " + std::to_wstring(out.size()) + L" account(s), status " + std::to_wstring(status));
    return out;
}

SecurityCheckResult CheckEventsNewAccounts()
{
    EventQueryResult security = Run(kSecurityChannel, kAuditProvider, { 4720, 4732 }, kNewAccountDays);
    std::map<std::wstring, std::wstring> sidNames;
    if (!security.events.empty()) sidNames = LocalAccountSids();
    return FromVerdict(L"events.newaccounts", NewAccountsVerdict(security, sidNames));
}

// ---------------------------------------------------------------------------
// 4. Failed sign-ins and lockouts
// ---------------------------------------------------------------------------
SecurityCheckResult CheckEventsFailedLogons()
{
    EventQueryResult failures = Run(kSecurityChannel, kAuditProvider, { 4625 }, kFailedLogonDays);
    EventQueryResult lockouts = Run(kSecurityChannel, kAuditProvider, { 4740 }, kFailedLogonDays);
    return FromVerdict(L"events.failedlogons", FailedLogonsVerdict(failures, lockouts));
}

// ---------------------------------------------------------------------------
// 5. Microsoft Defender
// ---------------------------------------------------------------------------
SecurityCheckResult CheckEventsDefender()
{
    EventQueryResult defender = Run(kDefenderChannel, kDefenderProvider, { 1116, 1117, 5001 }, kDefenderEventDays);
    return FromVerdict(L"events.defender", DefenderEventsVerdict(defender));
}
