#pragma once

#include <map>
#include <string>
#include <vector>

#include "EventLogQuery.h"

// ---------------------------------------------------------------------------
// EventRules: the pure verdict logic behind the "Recent activity" checks.
//
// Events in, status and evidence out. No system calls: the checks run the
// queries (EventLogQuery) and look up the files and signatures, then hand the
// facts here, so tests can feed made-up events and check the verdict.
// Statuses are the CHECK_* strings from SecurityChecks.h.
//
// Evidence never shows arguments of a command line (a command line can hold a
// password); it names the program instead.
// ---------------------------------------------------------------------------

// How far back each check looks, and the failed sign-in count that is worth a look.
constexpr unsigned int kLogClearedDays    = 30;
constexpr unsigned int kNewServiceDays    = 14;
constexpr unsigned int kNewAccountDays    = 30;
constexpr unsigned int kFailedLogonDays   = 7;
constexpr unsigned int kDefenderEventDays = 30;
constexpr size_t       kFailedLogonWarnAt = 20;

// The Administrators group, the only group check 3 reports additions to.
constexpr const wchar_t* kAdministratorsSid = L"S-1-5-32-544";

struct EventVerdict {
    std::wstring status;
    std::wstring detail;
};

// Why a log gave nothing to judge, in plain words. For the Security log and access
// denied: "... run as administrator to read the Security log." Empty when status is Ok.
std::wstring EventQueryProblemText(const EventQueryResult& result, const std::wstring& logName);

// "DOMAIN\user" from the <prefix>DomainName and <prefix>UserName fields (prefix
// "Subject" or "Target"). "-" and empty parts are left out; with no name at all the
// <prefix>UserSid or <prefix>Sid field, else "unknown account".
std::wstring EventAccountText(const EventRecord& event, const std::wstring& prefix);

// --- 1. Logs cleared (Security 1102, System 104) ---
EventVerdict LogClearedVerdict(const EventQueryResult& security, const EventQueryResult& system);

// --- 2. Services installed (System 7045) ---
struct ServiceInstall {
    // From the event (the newest one when the same service was installed more than once).
    std::wstring timeText;
    unsigned int count = 1;           // events for this name and image path
    std::wstring name;
    std::wstring imagePath;           // as logged, may hold arguments; never shown
    std::wstring serviceType;         // "user mode service", "kernel mode driver"
    std::wstring startType;           // "auto start", "demand start", ...
    std::wstring account;

    // Facts the check adds from the file system.
    std::wstring program;             // program file of imagePath, expanded
    bool         missing = false;     // the file is not there
    bool         managedFolder = false; // under Program Files or WindowsApps, where only installers write
    bool         dropFolder = false;  // IsUserDropLocation
    bool         userWritable = false;// normal users can write to its folder
    std::wstring writableBy;          // who can, for the evidence
    bool         signatureChecked = false;
    bool         validlySigned = true;
    std::wstring signatureStatus;
    bool         stillInstalled = true; // a service of this name still runs this program
};

// One entry per service name and image path, newest first.
std::vector<ServiceInstall> ServiceInstallsFromEvents(const std::vector<EventRecord>& events);

// True when the program is gone, no service runs it any more, and it was under
// Program Files or WindowsApps: an uninstall or an app update removed it (Store apps
// register their service again for each new version). Not a concern on its own.
bool ServiceInstallRemovedByInstaller(const ServiceInstall& install);

// The reasons an install is worth a look, empty when there is none: no program in the
// event; the program is missing (unless ServiceInstallRemovedByInstaller); it is in a
// user drop folder or a folder normal users can write to; it is not validly signed;
// the service runs a command shell or script host; its command line shows a classic
// abuse pattern (CommandLineSuspicion strength 2, named by the rule, never quoted).
std::vector<std::wstring> ServiceInstallConcerns(const ServiceInstall& install);

EventVerdict NewServicesVerdict(const EventQueryResult& query, const std::vector<ServiceInstall>& installs);

// --- 3. Local accounts created (4720), members added to Administrators (4732) ---
// sidNames: local account SIDs to names, for members the event names only by SID.
EventVerdict NewAccountsVerdict(const EventQueryResult& security, const std::map<std::wstring, std::wstring>& sidNames);

// --- 4. Failed sign-ins (4625) and lockouts (4740) ---
// "2" -> "2 (at the keyboard)"; unknown types are returned as given.
std::wstring LogonTypeName(const std::wstring& logonType);

// "0xC000006A" -> "wrong password"; "" when the code is not one we name.
std::wstring LogonFailureReason(const std::wstring& statusCode);

EventVerdict FailedLogonsVerdict(const EventQueryResult& failures, const EventQueryResult& lockouts);

// --- 5. Microsoft Defender detections (1116, 1117) and real-time protection off (5001) ---

// The Path field of a detection ("file:_C:\x.exe; CmdLine:_C:\a.exe -p secret") as
// text that names files and programs only: command lines lose their arguments, web
// downloads their address. At most maxItems resources, then "and N more".
std::wstring DefenderResourceText(const std::wstring& path, size_t maxItems = 3);

EventVerdict DefenderEventsVerdict(const EventQueryResult& defender);
