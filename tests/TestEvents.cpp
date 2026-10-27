// The "Recent activity" checks: event XML parsing, the XPath filter, the verdicts on
// made-up events, the score staying put, the reports, redaction, and live queries of
// this PC's own logs.

#include "TestFramework.h"
#include "JsonCheck.h"

#include "../CheckCatalog.h"
#include "../DetailText.h"
#include "../EventLogQuery.h"
#include "../EventRules.h"
#include "../HardeningScore.h"
#include "../Redactor.h"
#include "../Reports.h"
#include "../SecurityChecksEvents.h"
#include "../SystemInfo.h"
#include "../TextUtils.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <set>

static bool Has(const std::wstring& text, const std::wstring& part)
{
    return text.find(part) != std::wstring::npos;
}

#define CHECK_HAS(text, part)                                                                         \
    do {                                                                                              \
        if (!Has((text), (part)))                                                                     \
            tf::Fail(__FILE__, __LINE__, "missing \"" + tf::Narrow(part) + "\" in: " + tf::Narrow(text)); \
    } while (0)

#define CHECK_LACKS(text, part)                                                                       \
    do {                                                                                              \
        if (Has((text), (part)))                                                                      \
            tf::Fail(__FILE__, __LINE__, "unexpected \"" + tf::Narrow(part) + "\" in: " + tf::Narrow(text)); \
    } while (0)

static unsigned long long Ticks(WORD year, WORD month, WORD day, WORD hour, WORD minute, WORD second)
{
    SYSTEMTIME st = {};
    st.wYear = year;
    st.wMonth = month;
    st.wDay = day;
    st.wHour = hour;
    st.wMinute = minute;
    st.wSecond = second;
    FILETIME ft = {};
    SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    return li.QuadPart;
}

static EventRecord Ev(unsigned int id, int day, const std::map<std::wstring, std::wstring>& data)
{
    EventRecord e;
    e.id = id;
    e.fileTime = Ticks(2026, 10, static_cast<WORD>(day), 12, 0, 0);
    wchar_t buf[32];
    swprintf_s(buf, L"2026-10-%02d 12:00", day);
    e.timeText = buf;
    e.data = data;
    return e;
}

static EventQueryResult Res(const wchar_t* channel, EventQueryStatus status, std::vector<EventRecord> events = {})
{
    EventQueryResult r;
    r.channel = channel;
    r.status = status;
    r.events = std::move(events);
    return r;
}

// ---------------------------------------------------------------------------
// Event XML as EvtRender writes it
// ---------------------------------------------------------------------------
static const wchar_t* kServiceXml =
    L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    L"<Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/>"
    L"<EventID Qualifiers='16384'>7045</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode>"
    L"<Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='2026-10-23T02:09:22.2503854Z'/>"
    L"<EventRecordID>127452</EventRecordID><Correlation/><Execution ProcessID='1804' ThreadID='42740'/>"
    L"<Channel>System</Channel><Computer>DESKTOP-42</Computer><Security UserID='S-1-5-18'/></System>"
    L"<EventData><Data Name='ServiceName'>Acme Updater</Data>"
    L"<Data Name='ImagePath'>\"C:\\Program Files\\Acme\\upd.exe\" --run &amp; --quiet</Data>"
    L"<Data Name='ServiceType'>user mode service</Data><Data Name='StartType'>auto start</Data>"
    L"<Data Name='AccountName'>LocalSystem</Data><Data Name='Unused'/></EventData></Event>";

static const wchar_t* kClearXml =
    L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    L"<Provider Name='Microsoft-Windows-Eventlog' Guid='{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}'/>"
    L"<EventID>104</EventID><Version>0</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode>"
    L"<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-20T08:00:00Z'/>"
    L"<EventRecordID>5</EventRecordID><Correlation/><Execution ProcessID='1' ThreadID='2'/>"
    L"<Channel>System</Channel><Computer>DESKTOP-42</Computer><Security UserID='S-1-5-21-1-2-3-1001'/></System>"
    L"<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>"
    L"<SubjectUserName>zelda</SubjectUserName><SubjectDomainName>DESKTOP-42</SubjectDomainName>"
    L"<Channel>Application</Channel><BackupPath></BackupPath></LogFileCleared></UserData></Event>";

TEST(Events_XmlFieldExtraction)
{
    EventRecord e;
    REQUIRE(ParseEventXml(kServiceXml, e));
    CHECK_EQ(e.id, 7045u);   // the Qualifiers attribute does not change the id
    CHECK_EQ(e.provider, std::wstring(L"Service Control Manager"));
    CHECK_EQ(e.channel, std::wstring(L"System"));
    CHECK_EQ(e.computer, std::wstring(L"DESKTOP-42"));
    CHECK_EQ(e.systemTime, std::wstring(L"2026-10-23T02:09:22.2503854Z"));
    CHECK_EQ(e.fileTime, Ticks(2026, 10, 23, 2, 9, 22) + 2503854ull);
    CHECK_EQ(e.Field(L"ServiceName"), std::wstring(L"Acme Updater"));
    CHECK_EQ(e.Field(L"ImagePath"), std::wstring(L"\"C:\\Program Files\\Acme\\upd.exe\" --run & --quiet"));
    CHECK_EQ(e.Field(L"StartType"), std::wstring(L"auto start"));
    CHECK(e.data.count(L"Unused") == 1 && e.Field(L"Unused").empty());   // self-closing <Data/>
    CHECK(e.Field(L"Nope").empty());
    CHECK(e.data.count(L"EventRecordID") == 0);   // System fields are not data fields

    EventRecord c;
    REQUIRE(ParseEventXml(kClearXml, c));
    CHECK_EQ(c.id, 104u);
    CHECK_EQ(c.provider, std::wstring(L"Microsoft-Windows-Eventlog"));
    CHECK_EQ(c.fileTime, Ticks(2026, 10, 20, 8, 0, 0));
    CHECK_EQ(c.Field(L"SubjectUserName"), std::wstring(L"zelda"));   // UserData fields
    CHECK_EQ(c.Field(L"SubjectDomainName"), std::wstring(L"DESKTOP-42"));
    CHECK_EQ(c.Field(L"Channel"), std::wstring(L"Application"));
    CHECK_EQ(EventAccountText(c, L"Subject"), std::wstring(L"DESKTOP-42\\zelda"));

    // Data without a Name, entities, double quotes, an XML declaration and a comment.
    EventRecord u;
    REQUIRE(ParseEventXml(L"<?xml version=\"1.0\"?><!-- x --><Event><System><EventID>9</EventID>"
                          L"<Provider Name=\"P &amp; Q\"/></System><EventData><Data>first</Data><Data>&lt;b&gt; &#65;&#x42;</Data>"
                          L"</EventData></Event>", u));
    CHECK_EQ(u.id, 9u);
    CHECK_EQ(u.provider, std::wstring(L"P & Q"));
    CHECK_EQ(u.Field(L"#1"), std::wstring(L"first"));
    CHECK_EQ(u.Field(L"#2"), std::wstring(L"<b> AB"));
    CHECK_EQ(u.fileTime, 0ull);   // no TimeCreated

    // Not well formed: rejected, never guessed at.
    EventRecord bad;
    CHECK(!ParseEventXml(L"", bad));
    CHECK(!ParseEventXml(L"<Event><System></Event>", bad));                     // unclosed System
    CHECK(!ParseEventXml(L"<Other><System/></Other>", bad));                    // not an Event
    CHECK(!ParseEventXml(L"<Event><System></system></Event>", bad));           // case matters
    CHECK(!ParseEventXml(L"<Event/><Event/>", bad));                            // two roots
    CHECK(!ParseEventXml(L"junk<Event/>", bad));                                // text outside
    CHECK(!ParseEventXml(L"<Event><Data Name=x>1</Data></Event>", bad));       // unquoted attribute
    CHECK(!ParseEventXml(L"<Event><Data Name='x>1</Data></Event>", bad));      // unclosed attribute
    CHECK(!ParseEventXml(L"<Event><System>", bad));
    CHECK(ParseEventXml(L"<Event/>", bad));
    CHECK_EQ(bad.id, 0u);
}

TEST(Events_EntitiesAndTimes)
{
    CHECK_EQ(DecodeXmlEntities(L"a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;"), std::wstring(L"a & b <c> \"d\" 'e'"));
    CHECK_EQ(DecodeXmlEntities(L"&#233;&#x1F600;"), std::wstring(L"\x00e9\xD83D\xDE00"));
    CHECK_EQ(DecodeXmlEntities(L"&nbsp; &#0; &#xD800; & alone &amp"), std::wstring(L"&nbsp; &#0; &#xD800; & alone &amp"));
    CHECK_EQ(DecodeXmlEntities(L"plain"), std::wstring(L"plain"));

    unsigned long long t = 0;
    CHECK(ParseEventSystemTime(L"2026-10-25T11:31:18.9171017Z", t));
    CHECK_EQ(t, Ticks(2026, 10, 25, 11, 31, 18) + 9171017ull);
    CHECK(ParseEventSystemTime(L"2026-10-25T11:31:18Z", t));
    CHECK_EQ(t, Ticks(2026, 10, 25, 11, 31, 18));
    CHECK(ParseEventSystemTime(L"2026-10-25T11:31:18.5Z", t));
    CHECK_EQ(t, Ticks(2026, 10, 25, 11, 31, 18) + 5000000ull);
    CHECK(ParseEventSystemTime(L"2026-10-25T11:31:18.123456789Z", t));   // digits past 100 ns are dropped
    CHECK_EQ(t, Ticks(2026, 10, 25, 11, 31, 18) + 1234567ull);
    CHECK(!ParseEventSystemTime(L"2026-10-25T11:31:18", t));     // no UTC marker
    CHECK(!ParseEventSystemTime(L"2026-13-25T11:31:18Z", t));    // month 13
    CHECK(!ParseEventSystemTime(L"yesterday", t));
    CHECK(!ParseEventSystemTime(L"", t));
}

TEST(Events_XPathAndErrors)
{
    EventQuery q;
    q.channel = L"System";
    q.provider = L"Service Control Manager";
    q.ids = { 7045 };
    q.days = 14;
    CHECK_EQ(BuildEventXPath(q), std::wstring(L"*[System[Provider[@Name='Service Control Manager'] and (EventID=7045) and "
                                              L"TimeCreated[timediff(@SystemTime) <= 1209600000]]]"));
    q.provider.clear();
    q.ids = { 4720, 4732 };
    q.days = 30;   // 2,592,000,000 ms: past the 32-bit range, must not wrap
    CHECK_EQ(BuildEventXPath(q), std::wstring(L"*[System[(EventID=4720 or EventID=4732) and "
                                              L"TimeCreated[timediff(@SystemTime) <= 2592000000]]]"));
    q.days = 0;
    q.provider = L"It's";
    CHECK_EQ(BuildEventXPath(q), std::wstring(L"*[System[Provider[@Name=\"It's\"] and (EventID=4720 or EventID=4732)]]"));

    CHECK(ClassifyEventLogError(ERROR_SUCCESS) == EventQueryStatus::Ok);
    CHECK(ClassifyEventLogError(ERROR_ACCESS_DENIED) == EventQueryStatus::AccessDenied);
    CHECK(ClassifyEventLogError(ERROR_EVT_CHANNEL_NOT_FOUND) == EventQueryStatus::ChannelMissing);
    CHECK(ClassifyEventLogError(ERROR_EVT_INVALID_CHANNEL_PATH) == EventQueryStatus::ChannelMissing);
    CHECK(ClassifyEventLogError(ERROR_EVT_INVALID_QUERY) == EventQueryStatus::Error);

    EventQueryResult denied = Res(L"Security", EventQueryStatus::AccessDenied);
    CHECK_HAS(EventQueryProblemText(denied, L"Security"), L"run as administrator to read the Security log");
    CHECK(EventQueryProblemText(Res(L"System", EventQueryStatus::Ok), L"System").empty());
    CHECK_HAS(EventQueryProblemText(Res(L"X", EventQueryStatus::ChannelMissing), L"X"), L"does not exist");
}

// ---------------------------------------------------------------------------
// 1. Logs cleared
// ---------------------------------------------------------------------------
TEST(Events_LogClearedVerdict)
{
    EventRecord appCleared = Ev(104, 20, { { L"SubjectUserName", L"zelda" }, { L"SubjectDomainName", L"DESKTOP-42" },
                                           { L"Channel", L"Application" } });
    EventRecord secCleared = Ev(1102, 22, { { L"SubjectUserName", L"bob" }, { L"SubjectDomainName", L"DESKTOP-42" } });
    EventRecord noName = Ev(104, 18, {});

    // A normal user: the Security part is N/A, the System part is still reported.
    EventVerdict v = LogClearedVerdict(Res(L"Security", EventQueryStatus::AccessDenied),
                                       Res(L"System", EventQueryStatus::Ok, { appCleared, noName }));
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));
    CHECK_HAS(v.detail, L"2 event log clear(s) in the last 30 days");
    CHECK_HAS(v.detail, L"2026-10-20 12:00  the Application log was cleared by DESKTOP-42\\zelda");
    CHECK_HAS(v.detail, L"an event log was cleared by an account the event does not name");
    CHECK_HAS(v.detail, L"Security part: N/A");
    CHECK_HAS(v.detail, L"run as administrator to read the Security log");
    CHECK(v.detail.find(L"2026-10-20") < v.detail.find(L"2026-10-18"));   // newest first

    v = LogClearedVerdict(Res(L"Security", EventQueryStatus::AccessDenied), Res(L"System", EventQueryStatus::Ok));
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));
    CHECK_HAS(v.detail, L"No event log was cleared in the last 30 days (System log checked)");
    CHECK_HAS(v.detail, L"run as administrator to read the Security log");

    // Administrator: both parts, sorted together.
    v = LogClearedVerdict(Res(L"Security", EventQueryStatus::Ok, { secCleared }), Res(L"System", EventQueryStatus::Ok, { appCleared }));
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));
    CHECK_HAS(v.detail, L"the Security log was cleared by DESKTOP-42\\bob");
    CHECK(v.detail.find(L"Security log was cleared") < v.detail.find(L"Application log was cleared"));
    CHECK_LACKS(v.detail, L"N/A");

    v = LogClearedVerdict(Res(L"Security", EventQueryStatus::Ok), Res(L"System", EventQueryStatus::Ok));
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));
    CHECK_HAS(v.detail, L"Security and System log checked");

    // Other event ids in the result are not clears.
    v = LogClearedVerdict(Res(L"Security", EventQueryStatus::Ok, { Ev(4624, 20, {}) }), Res(L"System", EventQueryStatus::Ok, { Ev(7045, 20, {}) }));
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));

    // Nothing readable: N/A for expected reasons, ERROR only for an unexpected failure.
    v = LogClearedVerdict(Res(L"Security", EventQueryStatus::AccessDenied), Res(L"System", EventQueryStatus::AccessDenied));
    CHECK_EQ(v.status, std::wstring(CHECK_NA));
    EventQueryResult broken = Res(L"System", EventQueryStatus::Error);
    broken.error = 1234;
    v = LogClearedVerdict(Res(L"Security", EventQueryStatus::AccessDenied), broken);
    CHECK_EQ(v.status, std::wstring(CHECK_ERROR));
    CHECK_HAS(v.detail, L"Windows error 1234");

    // The cap is reported.
    EventQueryResult capped = Res(L"System", EventQueryStatus::Ok, { appCleared });
    capped.capped = true;
    v = LogClearedVerdict(Res(L"Security", EventQueryStatus::Ok), capped);
    CHECK_HAS(v.detail, L"Only the newest 1 matching events of the System log were read");
}

// ---------------------------------------------------------------------------
// 2. Services installed
// ---------------------------------------------------------------------------
static EventRecord ServiceEvent(int day, const wchar_t* name, const wchar_t* image, const wchar_t* start = L"auto start")
{
    return Ev(7045, day, { { L"ServiceName", name }, { L"ImagePath", image }, { L"ServiceType", L"user mode service" },
                           { L"StartType", start }, { L"AccountName", L"LocalSystem" } });
}

TEST(Events_NewServicesVerdict)
{
    std::vector<EventRecord> events = {
        ServiceEvent(24, L"Acme", L"\"C:\\Program Files\\Acme\\svc.exe\" --token SECRET123"),
        ServiceEvent(22, L"Dropper", L"C:\\Users\\zelda\\AppData\\Local\\Temp\\x.exe", L"demand start"),
        ServiceEvent(21, L"Acme", L"\"C:\\Program Files\\Acme\\svc.exe\" --token SECRET123"),   // same service again
        ServiceEvent(20, L"Gone", L"C:\\Tools\\gone.exe"),
        Ev(7036, 20, { { L"param1", L"Not an install" } }),
    };
    std::vector<ServiceInstall> installs = ServiceInstallsFromEvents(events);
    REQUIRE(installs.size() == 3);
    CHECK_EQ(installs[0].name, std::wstring(L"Acme"));
    CHECK_EQ(installs[0].count, 2u);
    CHECK_EQ(installs[0].timeText, std::wstring(L"2026-10-24 12:00"));   // the newest event
    CHECK_EQ(installs[1].startType, std::wstring(L"demand start"));

    // Facts the check would add.
    installs[0].program = L"C:\\Program Files\\Acme\\svc.exe";
    installs[0].signatureChecked = true;
    installs[1].program = L"C:\\Users\\zelda\\AppData\\Local\\Temp\\x.exe";
    installs[1].dropFolder = true;
    installs[1].signatureChecked = true;
    installs[1].validlySigned = false;
    installs[1].signatureStatus = L"Unsigned";
    installs[2].program = L"C:\\Tools\\gone.exe";
    installs[2].missing = true;
    installs[2].stillInstalled = false;

    CHECK(ServiceInstallConcerns(installs[0]).empty());
    CHECK_EQ(ServiceInstallConcerns(installs[1]).size(), static_cast<size_t>(2));
    CHECK_EQ(ServiceInstallConcerns(installs[2]).size(), static_cast<size_t>(1));

    EventQueryResult system = Res(L"System", EventQueryStatus::Ok, events);
    EventVerdict v = NewServicesVerdict(system, installs);
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));
    CHECK_HAS(v.detail, L"2 of 3 service(s) installed in the last 14 days are worth a look");
    CHECK_HAS(v.detail, L"Dropper: C:\\Users\\zelda\\AppData\\Local\\Temp\\x.exe, demand start, user mode service");
    CHECK_HAS(v.detail, L"worth a look: the program is in a folder where users drop files");
    CHECK_HAS(v.detail, L"worth a look: the program is not validly signed (Unsigned)");
    CHECK_HAS(v.detail, L"worth a look: the program file is missing (and no service runs it any more)");
    CHECK_HAS(v.detail, L"The other services installed in that time:");
    CHECK_HAS(v.detail, L"Acme: C:\\Program Files\\Acme\\svc.exe, auto start, user mode service, installed 2 times");
    CHECK_LACKS(v.detail, L"SECRET123");   // arguments are never shown

    // A writable folder alone is enough.
    std::vector<ServiceInstall> writable = { installs[0] };
    writable[0].userWritable = true;
    writable[0].writableBy = L"BUILTIN\\Users";
    v = NewServicesVerdict(system, writable);
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));
    CHECK_HAS(v.detail, L"normal users can write to the program's folder (BUILTIN\\Users)");

    // All clean: PASS, and the list is still shown.
    v = NewServicesVerdict(system, { installs[0] });
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));
    CHECK_HAS(v.detail, L"1 service(s) installed in the last 14 days");
    CHECK_HAS(v.detail, L"Acme: C:\\Program Files\\Acme\\svc.exe");

    v = NewServicesVerdict(Res(L"System", EventQueryStatus::Ok), {});
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));
    CHECK_HAS(v.detail, L"No service was installed in the last 14 days");

    v = NewServicesVerdict(Res(L"System", EventQueryStatus::AccessDenied), {});
    CHECK_EQ(v.status, std::wstring(CHECK_NA));

    // Removed again with its program from Program Files: an uninstall or an app update.
    ServiceInstall updated;
    updated.name = L"StoreApp";
    updated.timeText = L"2026-10-20 12:00";
    updated.imagePath = L"\"C:\\Program Files\\WindowsApps\\App_1.0.0.0_x64__abc\\svc.exe\"";
    updated.program = L"C:\\Program Files\\WindowsApps\\App_1.0.0.0_x64__abc\\svc.exe";
    updated.missing = true;
    updated.stillInstalled = false;
    updated.managedFolder = true;
    CHECK(ServiceInstallRemovedByInstaller(updated));
    CHECK(ServiceInstallConcerns(updated).empty());
    v = NewServicesVerdict(system, { updated });
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));
    CHECK_HAS(v.detail, L"StoreApp: C:\\Program Files\\WindowsApps\\App_1.0.0.0_x64__abc\\svc.exe, since removed with its program");
    // Still installed, or outside Program Files: the missing file is a concern.
    ServiceInstall broken = updated;
    broken.stillInstalled = true;
    CHECK(!ServiceInstallRemovedByInstaller(broken));
    CHECK_EQ(ServiceInstallConcerns(broken).size(), static_cast<size_t>(1));
    ServiceInstall vanished = updated;
    vanished.program = L"C:\\Windows\\a1b2c3.exe";
    vanished.managedFolder = false;
    CHECK_EQ(ServiceInstallConcerns(vanished).size(), static_cast<size_t>(1));

    // A shell with an encoded command, the way remote execution tools create services.
    std::vector<ServiceInstall> shell = ServiceInstallsFromEvents({ ServiceEvent(23, L"x7Kq2",
        L"%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand SQBFAFgAIAAoAE4AZQB3AA==", L"demand start") });
    REQUIRE(shell.size() == 1);
    shell[0].program = L"C:\\WINDOWS\\system32\\cmd.exe";
    shell[0].signatureChecked = true;
    std::vector<std::wstring> shellConcerns = ServiceInstallConcerns(shell[0]);
    CHECK_EQ(shellConcerns.size(), static_cast<size_t>(2));
    v = NewServicesVerdict(system, shell);
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));
    CHECK_HAS(v.detail, L"the service runs cmd.exe, a command shell or script host");
    CHECK_HAS(v.detail, L"its command line shows a pattern malware uses: encoded PowerShell command");
    CHECK_LACKS(v.detail, L"SQBFAFgA");

    // No program in the event at all.
    std::vector<ServiceInstall> empty = ServiceInstallsFromEvents({ ServiceEvent(20, L"Odd", L"") });
    REQUIRE(empty.size() == 1);
    std::vector<std::wstring> concerns = ServiceInstallConcerns(empty[0]);
    REQUIRE(concerns.size() == 1);
    CHECK_EQ(concerns.front(), std::wstring(L"the event names no program file"));
}

// ---------------------------------------------------------------------------
// 3. Accounts
// ---------------------------------------------------------------------------
TEST(Events_NewAccountsVerdict)
{
    const std::wstring sid = L"S-1-5-21-111-222-333-1005";
    std::vector<EventRecord> events = {
        Ev(4732, 23, { { L"MemberName", L"-" }, { L"MemberSid", sid }, { L"TargetUserName", L"Administrators" },
                       { L"TargetDomainName", L"Builtin" }, { L"TargetSid", L"S-1-5-32-544" },
                       { L"SubjectUserName", L"zelda" }, { L"SubjectDomainName", L"DESKTOP-42" } }),
        Ev(4732, 23, { { L"MemberName", L"-" }, { L"MemberSid", sid }, { L"TargetUserName", L"Users" },
                       { L"TargetSid", L"S-1-5-32-545" }, { L"SubjectUserName", L"zelda" } }),   // not Administrators
        Ev(4720, 22, { { L"TargetUserName", L"helper" }, { L"TargetDomainName", L"DESKTOP-42" }, { L"TargetSid", sid },
                       { L"SubjectUserName", L"zelda" }, { L"SubjectDomainName", L"DESKTOP-42" } }),
    };
    std::map<std::wstring, std::wstring> names = { { L"s-1-5-21-111-222-333-1005", L"helper" } };   // case does not matter
    EventVerdict v = NewAccountsVerdict(Res(L"Security", EventQueryStatus::Ok, events), names);
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));
    CHECK_HAS(v.detail, L"1 local account(s) created and 1 addition(s) to the Administrators group in the last 30 days");
    CHECK_HAS(v.detail, L"2026-10-23 12:00  added to the Administrators group: helper, by DESKTOP-42\\zelda");
    CHECK_HAS(v.detail, L"2026-10-22 12:00  account created: DESKTOP-42\\helper, by DESKTOP-42\\zelda");
    CHECK_LACKS(v.detail, L"Users");

    // Without a name for the SID the SID is shown.
    v = NewAccountsVerdict(Res(L"Security", EventQueryStatus::Ok, { events[0] }), {});
    CHECK_HAS(v.detail, L"added to the Administrators group: " + sid);

    v = NewAccountsVerdict(Res(L"Security", EventQueryStatus::Ok, { events[1] }), names);
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));
    CHECK_HAS(v.detail, L"No local account was created");

    v = NewAccountsVerdict(Res(L"Security", EventQueryStatus::AccessDenied), names);
    CHECK_EQ(v.status, std::wstring(CHECK_NA));
    CHECK_HAS(v.detail, L"run as administrator to read the Security log");
}

// ---------------------------------------------------------------------------
// 4. Failed sign-ins
// ---------------------------------------------------------------------------
static EventRecord Failure(const wchar_t* user, const wchar_t* type, const wchar_t* sub = L"0xc000006a")
{
    return Ev(4625, 24, { { L"TargetUserName", user }, { L"TargetDomainName", L"DESKTOP-42" }, { L"LogonType", type },
                          { L"Status", L"0xc000006d" }, { L"SubStatus", sub } });
}

TEST(Events_FailedLogonsVerdict)
{
    CHECK_EQ(LogonTypeName(L"10"), std::wstring(L"10 (Remote Desktop)"));
    CHECK_EQ(LogonTypeName(L"3"), std::wstring(L"3 (over the network)"));
    CHECK_EQ(LogonTypeName(L"99"), std::wstring(L"99"));
    CHECK_EQ(LogonFailureReason(L"0xC0000064"), std::wstring(L"the user name does not exist"));
    CHECK(LogonFailureReason(L"0x12345678").empty());

    EventQueryResult noLockouts = Res(L"Security", EventQueryStatus::Ok);
    std::vector<EventRecord> nineteen;
    for (int i = 0; i < 19; ++i) nineteen.push_back(Failure(L"zelda", L"2"));
    EventVerdict v = FailedLogonsVerdict(Res(L"Security", EventQueryStatus::Ok, nineteen), noLockouts);
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));
    CHECK_HAS(v.detail, L"19 failed sign-in(s) and 0 account lockout(s) in the last 7 days");

    std::vector<EventRecord> twenty = nineteen;
    twenty.push_back(Failure(L"admin", L"10", L"0xc0000064"));
    for (int i = 0; i < 3; ++i) twenty.push_back(Failure(L"administrator", L"3", L"0x0"));
    v = FailedLogonsVerdict(Res(L"Security", EventQueryStatus::Ok, twenty), noLockouts);
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));
    CHECK_HAS(v.detail, L"23 failed sign-in(s)");
    CHECK_HAS(v.detail, L"  DESKTOP-42\\zelda: 19\n");
    CHECK_HAS(v.detail, L"  DESKTOP-42\\administrator: 3\n");
    CHECK(v.detail.find(L"zelda: 19") < v.detail.find(L"administrator: 3"));   // most tried first
    CHECK(v.detail.find(L"administrator: 3") < v.detail.find(L"admin: 1"));
    CHECK_HAS(v.detail, L"  2 (at the keyboard): 19\n");
    CHECK_HAS(v.detail, L"  10 (Remote Desktop): 1\n");
    CHECK_HAS(v.detail, L"  wrong password: 19\n");
    CHECK_HAS(v.detail, L"  the user name does not exist: 1\n");
    CHECK_HAS(v.detail, L"  wrong user name or password: 3\n");   // SubStatus 0x0: the Status code

    // One lockout is enough, whatever the count.
    EventRecord lock = Ev(4740, 23, { { L"TargetUserName", L"zelda" }, { L"TargetDomainName", L"DESKTOP-42" } });
    v = FailedLogonsVerdict(Res(L"Security", EventQueryStatus::Ok, { Failure(L"zelda", L"2") }),
                            Res(L"Security", EventQueryStatus::Ok, { lock }));
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));
    CHECK_HAS(v.detail, L"1 failed sign-in(s) and 1 account lockout(s)");
    CHECK_HAS(v.detail, L"zelda was locked out (the attempts came from computer DESKTOP-42)");

    // The cap means "at least".
    EventQueryResult capped = Res(L"Security", EventQueryStatus::Ok, twenty);
    capped.capped = true;
    v = FailedLogonsVerdict(capped, noLockouts);
    CHECK_HAS(v.detail, L"at least 23 failed sign-in(s)");

    v = FailedLogonsVerdict(Res(L"Security", EventQueryStatus::AccessDenied), Res(L"Security", EventQueryStatus::AccessDenied));
    CHECK_EQ(v.status, std::wstring(CHECK_NA));
    CHECK_HAS(v.detail, L"run as administrator to read the Security log");

    v = FailedLogonsVerdict(Res(L"Security", EventQueryStatus::Ok), noLockouts);
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));
    CHECK_HAS(v.detail, L"0 failed sign-in(s)");
}

// ---------------------------------------------------------------------------
// 5. Microsoft Defender
// ---------------------------------------------------------------------------
TEST(Events_DefenderResourceText)
{
    CHECK_EQ(DefenderResourceText(L"file:_C:\\Users\\zelda\\Downloads\\x.exe"), std::wstring(L"C:\\Users\\zelda\\Downloads\\x.exe"));
    CHECK_EQ(DefenderResourceText(L"file:_C:\\a.exe; file:_C:\\b.exe"), std::wstring(L"C:\\a.exe; C:\\b.exe"));
    CHECK_EQ(DefenderResourceText(L"file:_C:\\a.exe;file:_C:\\b.exe;file:_C:\\c.exe;file:_C:\\d.exe;file:_C:\\e.exe"),
             std::wstring(L"C:\\a.exe; C:\\b.exe; C:\\c.exe; and 2 more"));

    // A command line keeps only its program, semicolons inside it included.
    std::wstring cmd = DefenderResourceText(
        L"CmdLine:_C:\\Program Files\\Tool\\tool.exe run --username Administrator --password Password!123 -- -Command "
        L"Set-MpPreference -DisableRealtimeMonitoring $true; Add-MpPreference -ExclusionPath 'C:\\GW'; 'Done'");
    CHECK_EQ(cmd, std::wstring(L"a command line run by C:\\Program Files\\Tool\\tool.exe (its arguments are not shown: they can hold passwords)"));
    CHECK_LACKS(cmd, L"Password!123");
    CHECK_LACKS(cmd, L"ExclusionPath");

    std::wstring web = DefenderResourceText(L"webfile:_C:\\Users\\z\\Downloads\\y.zip|https://example.invalid/y.zip?token=abc|pid:1");
    CHECK_EQ(web, std::wstring(L"C:\\Users\\z\\Downloads\\y.zip (downloaded; the address is not shown)"));
    CHECK_EQ(DefenderResourceText(L"regkey:_HKLM\\SOFTWARE\\X"), std::wstring(L"registry HKLM\\SOFTWARE\\X"));
    CHECK_EQ(DefenderResourceText(L"process:_pid:4321,ProcessStart:1337"), std::wstring(L"a running process"));
    CHECK_EQ(DefenderResourceText(L"behavior:_process: C:\\x.exe, pid:1"), std::wstring(L"behavior resource"));
    CHECK_EQ(DefenderResourceText(L""), std::wstring(L"(no file named)"));
    CHECK_EQ(DefenderResourceText(L"C:\\plain\\file.exe"), std::wstring(L"C:\\plain\\file.exe"));
    CHECK_LACKS(DefenderResourceText(L"C:\\x\\tool.exe --password hunter2"), L"hunter2");
}

TEST(Events_DefenderVerdict)
{
    CHECK_EQ(DefenderEventsVerdict(Res(L"Microsoft-Windows-Windows Defender/Operational", EventQueryStatus::ChannelMissing)).status,
             std::wstring(CHECK_NA));
    EventVerdict v = DefenderEventsVerdict(Res(L"Microsoft-Windows-Windows Defender/Operational", EventQueryStatus::Ok));
    CHECK_EQ(v.status, std::wstring(CHECK_PASS));
    CHECK_HAS(v.detail, L"no detection in the last 30 days");

    std::vector<EventRecord> events = {
        Ev(5001, 25, { { L"Product Name", L"Microsoft Defender Antivirus" } }),
        Ev(1117, 24, { { L"Threat Name", L"Trojan:Win32/Example.A" }, { L"Action Name", L"Quarantine" },
                       { L"Path", L"CmdLine:_C:\\Tools\\run.exe --password Secret!9" }, { L"Error Code", L"0x00000000" } }),
        Ev(1116, 24, { { L"Threat Name", L"Trojan:Win32/Example.A" }, { L"Severity Name", L"Severe" },
                       { L"Category Name", L"Trojan" }, { L"Path", L"CmdLine:_C:\\Tools\\run.exe --password Secret!9" } }),
        Ev(1117, 21, { { L"Threat Name", L"PUA:Win32/Bundle" }, { L"Action Name", L"Remove" },
                       { L"Path", L"file:_C:\\Users\\zelda\\Downloads\\setup.exe" }, { L"Error Code", L"0x80508023" },
                       { L"Error Description", L"The file could not be found" } }),
    };
    v = DefenderEventsVerdict(Res(L"Microsoft-Windows-Windows Defender/Operational", EventQueryStatus::Ok, events));
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));
    CHECK_HAS(v.detail, L"1 detection(s), 2 action(s) taken, real-time protection turned off 1 time(s)");
    CHECK_HAS(v.detail, L"2026-10-25 12:00  real-time protection was turned off");
    CHECK_HAS(v.detail, L"detected: Trojan:Win32/Example.A (Severe, Trojan) in a command line run by C:\\Tools\\run.exe");
    CHECK_HAS(v.detail, L"action taken: Quarantine on Trojan:Win32/Example.A");
    CHECK_HAS(v.detail, L"action taken: Remove on PUA:Win32/Bundle in C:\\Users\\zelda\\Downloads\\setup.exe (the action failed: The file could not be found)");
    CHECK_LACKS(v.detail, L"Secret!9");

    // 5001 alone is a warning.
    v = DefenderEventsVerdict(Res(L"Microsoft-Windows-Windows Defender/Operational", EventQueryStatus::Ok, { events[0] }));
    CHECK_EQ(v.status, std::wstring(CHECK_WARNING));

    v = DefenderEventsVerdict(Res(L"Microsoft-Windows-Windows Defender/Operational", EventQueryStatus::ChannelDisabled));
    CHECK_EQ(v.status, std::wstring(CHECK_NA));
    CHECK_HAS(v.detail, L"turned off");
}

// ---------------------------------------------------------------------------
// The score, the catalog and the reports
// ---------------------------------------------------------------------------
static const wchar_t* const kEventIds[] = {
    L"events.logcleared", L"events.newservices", L"events.newaccounts", L"events.failedlogons", L"events.defender",
};

TEST(Events_CatalogRowsAreNotScored)
{
    const std::vector<std::wstring>& categories = GetCheckCategories();
    REQUIRE(!categories.empty());
    CHECK_EQ(categories.back(), std::wstring(L"Recent activity"));   // shown last
    std::set<std::wstring> eventIds(std::begin(kEventIds), std::end(kEventIds));
    for (const wchar_t* id : kEventIds) {
        const CheckInfo* info = FindCheckInfo(id);
        if (!info) {
            tf::Fail(__FILE__, __LINE__, "no catalog row for " + tf::Narrow(id));
            continue;
        }
        CHECK(!info->scored);
        CHECK_EQ(info->category, std::wstring(L"Recent activity"));
    }
    for (const CheckInfo& info : GetCheckCatalog()) {
        bool isEvent = eventIds.count(info.id) > 0;
        if (info.scored == isEvent) tf::Fail(__FILE__, __LINE__, "wrong scored flag on " + tf::Narrow(info.id));
    }
    // The Recent activity rows are the last rows, so they come last in every report.
    const std::vector<CheckInfo>& catalog = GetCheckCatalog();
    REQUIRE(catalog.size() > 5);
    for (size_t i = catalog.size() - 5; i < catalog.size(); ++i) CHECK(eventIds.count(catalog[i].id) == 1);
}

static SecurityCheckResult With(const std::wstring& id, const wchar_t* status)
{
    SecurityCheckResult r = MakeCheckResult(id);
    r.status = status;
    r.detail = L"evidence";
    return r;
}

TEST(Events_WarningDoesNotChangeScore)
{
    std::vector<SecurityCheckResult> base = { With(L"hard.uac", CHECK_PASS), With(L"lsa.ppl", CHECK_FAIL),
                                              With(L"net.llmnr", CHECK_WARNING) };
    HardeningScore before = ComputeHardeningScore(base);

    for (const wchar_t* id : kEventIds) {
        for (const wchar_t* status : { CHECK_WARNING, CHECK_PASS, CHECK_FAIL }) {
            std::vector<SecurityCheckResult> more = base;
            more.push_back(With(id, status));
            HardeningScore after = ComputeHardeningScore(more);
            std::string what = tf::Narrow(id) + " " + tf::Narrow(status);
            if (after.score != before.score) tf::Fail(__FILE__, __LINE__, "score moved for " + what);
            if (after.counted != before.counted) tf::Fail(__FILE__, __LINE__, "counted moved for " + what);
            if (after.earned != before.earned || after.possible != before.possible) tf::Fail(__FILE__, __LINE__, "weights moved for " + what);
        }
    }
    // Still counted as a warning in the totals, so the reports list it.
    std::vector<SecurityCheckResult> withWarning = base;
    withWarning.push_back(With(L"events.logcleared", CHECK_WARNING));
    HardeningScore s = ComputeHardeningScore(withWarning);
    CHECK_EQ(s.warn, before.warn + 1);
    CHECK_EQ(s.score, before.score);

    // Only event checks: nothing to score.
    CHECK_EQ(ComputeHardeningScore({ With(L"events.defender", CHECK_WARNING) }).label, std::wstring(L"Not scored"));
}

TEST(Events_ReportsShowTheChecks)
{
    std::wstring md = BuildFindingsMarkdown();
    CHECK_HAS(md, L"## Recent activity");
    for (const wchar_t* id : kEventIds) {
        size_t at = md.find(std::wstring(L"- Check id: `") + id + L"`");
        if (at == std::wstring::npos) {
            tf::Fail(__FILE__, __LINE__, "FINDINGS.md lacks " + tf::Narrow(id));
            continue;
        }
        size_t next = md.find(L"### ", at);
        std::wstring section = md.substr(at, next == std::wstring::npos ? std::wstring::npos : next - at);
        CHECK_HAS(section, L"- Hardening score: not scored");
    }
    // A scored check has no such line.
    size_t uac = md.find(L"- Check id: `hard.uac`");
    REQUIRE(uac != std::wstring::npos);
    CHECK(md.substr(uac, md.find(L"### ", uac) - uac).find(L"not scored") == std::wstring::npos);

    ReportData d;
    FillReportHost(d, false);
    d.hasAudit = true;
    d.audit = { With(L"hard.uac", CHECK_PASS), With(L"events.newservices", CHECK_WARNING) };
    d.audit[1].detail = L"1 of 1 service(s) installed in the last 14 days are worth a look";
    d.score = ComputeHardeningScore(d.audit);

    std::wstring html = BuildHtmlReport(d);
    CHECK_HAS(html, L"Recent activity");
    CHECK_HAS(html, L"Medium severity, not scored");
    CHECK_HAS(html, L"events.newservices");
    CHECK_HAS(html, L"1 of 1 service(s) installed");

    std::wstring json = BuildJsonReport(d);
    JsonCheck check(json);
    bool valid = check.Valid();
    if (!valid) tf::Fail(__FILE__, __LINE__, "JSON report invalid: " + tf::Narrow(check.error));
    CHECK_EQ(check.KeyCount(L"scored"), 2);
    CHECK_HAS(json, L"events.newservices");
    CHECK(Has(json, L"\"scored\":false") || Has(json, L"\"scored\": false"));

    const CheckInfo* info = FindCheckInfo(L"events.newservices");
    REQUIRE(info != nullptr);
    std::wstring text = BuildFindingDetailText(*info, &d.audit[1]);
    CHECK_HAS(text, L"Not scored");
    CHECK_HAS(text, L"1 of 1 service(s) installed");
    CHECK_HAS(BuildAuditFindingsText(d.audit), L"[WARNING] Services installed recently");
}

// ---------------------------------------------------------------------------
// Names in event evidence are hidden like every other check's
// ---------------------------------------------------------------------------
TEST(Events_RedactionCoversEventEvidence)
{
    RedactionTerms fixed;
    fixed.userName = L"zelda";
    fixed.profileDirectory = L"C:\\Users\\zelda";
    fixed.computerName = L"DESKTOP-42";

    EventVerdict cleared = LogClearedVerdict(Res(L"Security", EventQueryStatus::AccessDenied),
        Res(L"System", EventQueryStatus::Ok, { Ev(104, 20, { { L"SubjectUserName", L"zelda" },
                                                             { L"SubjectDomainName", L"DESKTOP-42" },
                                                             { L"Channel", L"Application" } }) }));
    std::wstring r = RedactText(cleared.detail, fixed);
    CHECK_HAS(r, L"cleared by <host>\\<user>");
    CHECK_LACKS(ToLowerW(r), L"zelda");
    CHECK_LACKS(r, L"DESKTOP-42");

    std::vector<EventRecord> failures(25, Failure(L"zelda", L"10"));
    r = RedactText(FailedLogonsVerdict(Res(L"Security", EventQueryStatus::Ok, failures), Res(L"Security", EventQueryStatus::Ok)).detail, fixed);
    CHECK_HAS(r, L"<host>\\<user>: 25");
    CHECK_LACKS(ToLowerW(r), L"zelda");

    std::vector<ServiceInstall> installs = ServiceInstallsFromEvents({ ServiceEvent(20, L"Dropper", L"C:\\Users\\zelda\\Downloads\\x.exe") });
    REQUIRE(installs.size() == 1);
    installs[0].program = L"C:\\Users\\zelda\\Downloads\\x.exe";
    installs[0].dropFolder = true;
    r = RedactText(NewServicesVerdict(Res(L"System", EventQueryStatus::Ok), installs).detail, fixed);
    CHECK_HAS(r, L"C:\\Users\\<user>\\Downloads\\x.exe");
    CHECK_LACKS(ToLowerW(r), L"zelda");

    // The same through the report path, with this PC's own names in a made-up event.
    RedactionTerms mine = CurrentRedactionTerms();
    if (mine.userName.empty()) return;
    EventVerdict own = NewAccountsVerdict(Res(L"Security", EventQueryStatus::Ok,
        { Ev(4720, 22, { { L"TargetUserName", L"helper" }, { L"TargetDomainName", mine.computerName },
                         { L"SubjectUserName", mine.userName }, { L"SubjectDomainName", mine.computerName } }) }), {});
    ReportData d;
    FillReportHost(d, true);
    d.hasAudit = true;
    SecurityCheckResult res = MakeCheckResult(L"events.newaccounts");
    res.status = own.status;
    res.detail = own.detail;
    d.audit.push_back(res);
    ReportData red = RedactReport(d);
    CHECK_HAS(red.audit[0].detail, L"by <");
    CHECK(!ContainsI(red.audit[0].detail, L"by " + mine.computerName + L"\\" + mine.userName));
    CHECK(!ContainsI(red.audit[0].detail, L"\\" + mine.userName + L"\n"));
    CHECK(BuildJsonReport(d).find(L"\\\\" + mine.userName + L"\\n") == std::wstring::npos);
}

// ---------------------------------------------------------------------------
// This PC's own logs
// ---------------------------------------------------------------------------
TEST(Events_LiveSystemQuery)
{
    // The System log is readable without administrator rights.
    EventQuery q;
    q.channel = L"System";
    q.ids = { 6005, 6006, 6013, 7036 };   // event log started and stopped, uptime, service state changes
    q.days = 30;
    q.maxEvents = 40;
    EventQueryResult r = RunEventQuery(q);
    std::printf("    note: System log %s, %zu event(s)%s\n", tf::Narrow(EventQueryStatusName(r.status)).c_str(), r.events.size(),
                r.capped ? ", cap reached" : "");
    REQUIRE(r.status == EventQueryStatus::Ok);
    CHECK_EQ(r.error, 0ul);
    CHECK(r.events.size() <= 40);
    CHECK_EQ(r.unreadable, static_cast<size_t>(0));
    std::set<unsigned int> wanted(q.ids.begin(), q.ids.end());
    unsigned long long previous = ~0ull;
    unsigned long long now = 0;
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER li;
        li.LowPart = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        now = li.QuadPart;
    }
    const unsigned long long thirtyOneDays = 31ull * 24 * 3600 * 10000000ull;
    for (const EventRecord& e : r.events) {
        if (wanted.count(e.id) == 0) tf::Fail(__FILE__, __LINE__, "unexpected event id " + std::to_string(e.id));
        CHECK(e.fileTime != 0);
        CHECK(e.fileTime <= previous);            // newest first
        CHECK(e.fileTime + thirtyOneDays >= now); // the time filter held
        CHECK(!e.timeText.empty() && e.timeText[0] != L'(');
        CHECK(EqualsI(e.channel, L"System"));
        previous = e.fileTime;
    }

    // The cap: one event at most, and it says when there were more.
    q.maxEvents = 1;
    EventQueryResult one = RunEventQuery(q);
    REQUIRE(one.status == EventQueryStatus::Ok);
    CHECK(one.events.size() <= 1);
    if (r.events.size() > 1) CHECK(one.capped);
    if (!one.events.empty()) CHECK(wanted.count(one.events[0].id) == 1);

    // A log that does not exist.
    EventQuery missing;
    missing.channel = L"PhantomRecon-No-Such-Log/Operational";
    missing.ids = { 1 };
    CHECK(RunEventQuery(missing).status == EventQueryStatus::ChannelMissing);

    // The Security log: readable when elevated, access denied for a normal user
    // (unless the account is in Event Log Readers).
    EventQuery sec;
    sec.channel = L"Security";
    sec.ids = { 4625 };
    sec.days = 1;
    sec.maxEvents = 5;
    EventQueryResult s = RunEventQuery(sec);
    std::printf("    note: Security log %s (elevated: %s)\n", tf::Narrow(EventQueryStatusName(s.status)).c_str(),
                IsProcessElevated() ? "yes" : "no");
    if (IsProcessElevated()) CHECK(s.status == EventQueryStatus::Ok);
    else CHECK(s.status == EventQueryStatus::AccessDenied || s.status == EventQueryStatus::Ok);
}

TEST(Events_ChecksRunHere)
{
    EventQuery probe;
    probe.channel = L"Security";
    probe.ids = { 4625 };
    probe.days = 1;
    probe.maxEvents = 1;
    bool securityDenied = RunEventQuery(probe).status == EventQueryStatus::AccessDenied;

    std::vector<SecurityCheckResult> results = {
        CheckEventsLogCleared(), CheckEventsNewServices(), CheckEventsNewAccounts(), CheckEventsFailedLogons(), CheckEventsDefender(),
    };
    for (size_t i = 0; i < results.size(); ++i) {
        const SecurityCheckResult& r = results[i];
        std::printf("    note: %s -> %s\n", tf::Narrow(r.id).c_str(), tf::Narrow(r.status).c_str());
        CHECK_EQ(r.id, std::wstring(kEventIds[i]));
        if (r.status == CHECK_ERROR) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " returned ERROR: " + tf::Narrow(r.detail));
        if (r.detail.empty()) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " has no detail");
        if (r.name.empty()) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " has no name");
        if (r.detail.size() > 20000) tf::Fail(__FILE__, __LINE__, tf::Narrow(r.id) + " evidence is not capped");
    }
    if (securityDenied) {
        // A normal user: the Security parts are N/A with the reason, the System part still counts.
        CHECK_EQ(results[2].status, std::wstring(CHECK_NA));
        CHECK_HAS(results[2].detail, L"run as administrator to read the Security log");
        CHECK_EQ(results[3].status, std::wstring(CHECK_NA));
        CHECK_HAS(results[3].detail, L"run as administrator to read the Security log");
        CHECK(results[0].status == CHECK_PASS || results[0].status == CHECK_WARNING);
        CHECK_HAS(results[0].detail, L"Security part: N/A");
    }
    else {
        CHECK(results[2].status == CHECK_PASS || results[2].status == CHECK_WARNING);
        CHECK(results[3].status == CHECK_PASS || results[3].status == CHECK_WARNING);
    }
    // The System log is readable by everyone.
    CHECK(results[1].status == CHECK_PASS || results[1].status == CHECK_WARNING);
}
