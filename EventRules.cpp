#include "pch.h"
#include "EventRules.h"

#include "CheckHelpers.h"
#include "SecurityChecks.h"
#include "TextUtils.h"

#include <algorithm>
#include <sstream>
#include <utility>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[EventRules] " + msg + L"\n").c_str());
}

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

// Events can be judged: the log was read. A log that is turned off can still hold
// older events, which are judged; with none there is nothing to say.
static bool Judgeable(const EventQueryResult& r)
{
    return r.status == EventQueryStatus::Ok || (r.status == EventQueryStatus::ChannelDisabled && !r.events.empty());
}

// Status when nothing could be judged: N/A for the expected cases (no rights, no
// such log, log turned off), ERROR for anything else.
static std::wstring UnjudgeableStatus(const std::vector<const EventQueryResult*>& results)
{
    for (const EventQueryResult* r : results) {
        if (r->status == EventQueryStatus::Error) return CHECK_ERROR;
    }
    return CHECK_NA;
}

static std::wstring CapNotes(const EventQueryResult& r, const std::wstring& logName)
{
    std::wstring out;
    if (r.capped) {
        out += L"Only the newest " + std::to_wstring(r.events.size()) + L" matching events of the " + logName +
               L" log were read; there are more.\n";
    }
    if (r.unreadable > 0) {
        out += std::to_wstring(r.unreadable) + L" event(s) of the " + logName + L" log could not be read and are left out.\n";
    }
    return out;
}

static std::wstring ShortTime(const EventRecord& e)
{
    return e.timeText.empty() ? std::wstring(L"(time unknown)") : e.timeText;
}

static bool IsBlankField(const std::wstring& value)
{
    std::wstring v = TrimW(value);
    return v.empty() || v == L"-";
}

std::wstring EventQueryProblemText(const EventQueryResult& result, const std::wstring& logName)
{
    std::wstring text;
    switch (result.status) {
    case EventQueryStatus::Ok:
        break;
    case EventQueryStatus::AccessDenied:
        text = EqualsI(result.channel, L"Security")
            ? std::wstring(L"The Security log could not be read: run as administrator to read the Security log.")
            : L"The " + logName + L" log could not be read with this account's rights: run as administrator to read it.";
        break;
    case EventQueryStatus::ChannelMissing:
        text = L"The " + logName + L" log does not exist on this PC.";
        break;
    case EventQueryStatus::ChannelDisabled:
        text = L"The " + logName + L" log is turned off, so Windows does not record new events in it.";
        break;
    default:
        text = L"The " + logName + L" log could not be read (Windows error " + std::to_wstring(result.error) + L").";
        break;
    }
    if (!text.empty()) DebugLog(L"Problem with " + result.channel + L": " + text);
    return text;
}

std::wstring EventAccountText(const EventRecord& event, const std::wstring& prefix)
{
    std::wstring user = event.Field(prefix + L"UserName");
    std::wstring domain = event.Field(prefix + L"DomainName");
    if (!IsBlankField(user)) return IsBlankField(domain) ? TrimW(user) : TrimW(domain) + L"\\" + TrimW(user);
    std::wstring sid = event.Field(prefix + L"UserSid");
    if (IsBlankField(sid)) sid = event.Field(prefix + L"Sid");
    if (!IsBlankField(sid)) return TrimW(sid);
    return L"unknown account";
}

// ---------------------------------------------------------------------------
// 1. Logs cleared
// ---------------------------------------------------------------------------
EventVerdict LogClearedVerdict(const EventQueryResult& security, const EventQueryResult& system)
{
    struct Clear {
        unsigned long long when;
        std::wstring       line;
    };
    std::vector<Clear> clears;
    auto who = [](const EventRecord& e) {
        std::wstring account = EventAccountText(e, L"Subject");
        return account == L"unknown account" ? std::wstring(L"an account the event does not name") : account;
    };
    if (Judgeable(security)) {
        for (const EventRecord& e : security.events) {
            if (e.id != 1102) continue;
            clears.push_back({ e.fileTime, L"  " + ShortTime(e) + L"  the Security log was cleared by " + who(e) + L"\n" });
        }
    }
    if (Judgeable(system)) {
        for (const EventRecord& e : system.events) {
            if (e.id != 104) continue;
            std::wstring channel = TrimW(e.Field(L"Channel"));
            std::wstring what = channel.empty() ? std::wstring(L"an event log") : L"the " + channel + L" log";
            clears.push_back({ e.fileTime, L"  " + ShortTime(e) + L"  " + what + L" was cleared by " + who(e) + L"\n" });
        }
    }
    std::stable_sort(clears.begin(), clears.end(), [](const Clear& a, const Clear& b) { return a.when > b.when; });

    std::wstring problems;
    for (const auto& pair : { std::make_pair(&security, std::wstring(L"Security")), std::make_pair(&system, std::wstring(L"System")) }) {
        std::wstring p = EventQueryProblemText(*pair.first, pair.second);
        if (!p.empty()) problems += pair.second + L" part: N/A. " + p + L"\n";
    }
    std::wstring notes = CapNotes(security, L"Security") + CapNotes(system, L"System");

    EventVerdict v;
    if (!clears.empty()) {
        CappedList list(30);
        for (const Clear& c : clears) list.Add(c.line);
        v.status = CHECK_WARNING;
        v.detail = std::to_wstring(clears.size()) + L" event log clear(s) in the last " + std::to_wstring(kLogClearedDays) +
                   L" days:\n" + list.Text() + notes + problems;
    }
    else if (!Judgeable(security) && Judgeable(system)) {
        // The Security log is the one an intruder clears (1102). Without it a clean System
        // log is not enough for a PASS: say what was seen and what could not be.
        v.status = CHECK_NA;
        v.detail = L"No event log clear in the System log in the last " + std::to_wstring(kLogClearedDays) +
                   L" days. The Security log, the one an intruder would clear, was not read, so this is not a PASS.\n" +
                   notes + problems;
    }
    else if (Judgeable(security) || Judgeable(system)) {
        std::vector<std::wstring> checked;
        if (Judgeable(security)) checked.push_back(L"Security");
        if (Judgeable(system)) checked.push_back(L"System");
        v.status = CHECK_PASS;
        v.detail = L"No event log was cleared in the last " + std::to_wstring(kLogClearedDays) + L" days (" +
                   JoinW(checked, L" and ") + L" log checked).\n" + notes + problems;
    }
    else {
        v.status = UnjudgeableStatus({ &security, &system });
        v.detail = L"Neither log could be read.\n" + problems;
    }
    DebugLog(L"LogClearedVerdict: " + std::to_wstring(clears.size()) + L" clear(s) -> " + v.status);
    return v;
}

// ---------------------------------------------------------------------------
// 2. Services installed
// ---------------------------------------------------------------------------
std::vector<ServiceInstall> ServiceInstallsFromEvents(const std::vector<EventRecord>& events)
{
    std::vector<ServiceInstall> out;
    std::map<std::wstring, size_t> index;
    for (const EventRecord& e : events) {
        if (e.id != 7045) continue;
        std::wstring name = TrimW(e.Field(L"ServiceName"));
        std::wstring image = TrimW(e.Field(L"ImagePath"));
        std::wstring key = ToLowerW(name) + L"|" + ToLowerW(image);
        auto it = index.find(key);
        if (it != index.end()) {
            out[it->second].count++;
            continue;
        }
        ServiceInstall s;
        s.timeText = ShortTime(e);
        s.name = name.empty() ? std::wstring(L"(no name)") : name;
        s.imagePath = image;
        s.serviceType = TrimW(e.Field(L"ServiceType"));
        s.startType = TrimW(e.Field(L"StartType"));
        s.account = TrimW(e.Field(L"AccountName"));
        index[key] = out.size();
        out.push_back(s);
    }
    DebugLog(L"ServiceInstallsFromEvents: " + std::to_wstring(out.size()) + L" service(s) from " +
             std::to_wstring(events.size()) + L" event(s)");
    return out;
}

bool ServiceInstallRemovedByInstaller(const ServiceInstall& s)
{
    bool removed = !s.program.empty() && s.missing && !s.stillInstalled && s.managedFolder;
    if (removed) DebugLog(L"ServiceInstallRemovedByInstaller: " + s.name + L" was removed with its program");
    return removed;
}

std::vector<std::wstring> ServiceInstallConcerns(const ServiceInstall& s)
{
    std::vector<std::wstring> concerns;
    if (s.program.empty()) {
        concerns.push_back(L"the event names no program file");
    }
    else if (s.missing && !ServiceInstallRemovedByInstaller(s)) {
        concerns.push_back(std::wstring(L"the program file is missing") +
                           (s.stillInstalled ? L"" : L" (and no service runs it any more)"));
    }
    if (!s.program.empty()) {
        size_t slash = s.program.find_last_of(L"\\/");
        std::wstring exe = ToLowerW(slash == std::wstring::npos ? s.program : s.program.substr(slash + 1));
        if (IsShellOrScriptHost(exe)) {
            concerns.push_back(L"the service runs " + exe + L", a command shell or script host, instead of a service program");
        }
    }
    std::wstring why;
    if (!s.imagePath.empty() && CommandLineSuspicion(s.imagePath, &why) >= 2) {
        concerns.push_back(L"its command line shows a pattern malware uses: " + why);
    }
    if (s.dropFolder) concerns.push_back(L"the program is in a folder where users drop files (Temp, Downloads, Desktop, Public)");
    if (s.userWritable) {
        concerns.push_back(L"normal users can write to the program's folder" +
                           (s.writableBy.empty() ? std::wstring() : L" (" + s.writableBy + L")"));
    }
    if (s.signatureChecked && !s.validlySigned) {
        concerns.push_back(L"the program is not validly signed" +
                           (s.signatureStatus.empty() ? std::wstring() : L" (" + s.signatureStatus + L")"));
    }
    DebugLog(L"ServiceInstallConcerns: " + s.name + L" has " + std::to_wstring(concerns.size()));
    return concerns;
}

static std::wstring ServiceLine(const ServiceInstall& s)
{
    std::wstring line = L"  " + s.timeText + L"  " + s.name + L": " +
                        (s.program.empty() ? std::wstring(L"(no program named)") : s.program);
    if (!s.startType.empty()) line += L", " + s.startType;
    if (!s.serviceType.empty()) line += L", " + s.serviceType;
    if (s.count > 1) line += L", installed " + std::to_wstring(s.count) + L" times";
    if (ServiceInstallRemovedByInstaller(s)) line += L", since removed with its program (uninstalled or updated)";
    return line + L"\n";
}

EventVerdict NewServicesVerdict(const EventQueryResult& query, const std::vector<ServiceInstall>& installs)
{
    EventVerdict v;
    if (!Judgeable(query)) {
        v.status = UnjudgeableStatus({ &query });
        v.detail = EventQueryProblemText(query, L"System");
        DebugLog(L"NewServicesVerdict: log not readable -> " + v.status);
        return v;
    }
    CappedList flagged(20);
    CappedList others(30);
    for (const ServiceInstall& s : installs) {
        std::vector<std::wstring> concerns = ServiceInstallConcerns(s);
        if (concerns.empty()) {
            others.Add(ServiceLine(s));
            continue;
        }
        std::wstring entry = ServiceLine(s);
        for (const std::wstring& c : concerns) entry += L"      worth a look: " + c + L"\n";
        flagged.Add(entry);
    }
    std::wstring days = std::to_wstring(kNewServiceDays);
    std::wstring notes = CapNotes(query, L"System") + EventQueryProblemText(query, L"System");
    if (!notes.empty() && notes.back() != L'\n') notes += L"\n";

    if (!flagged.Empty()) {
        v.status = CHECK_WARNING;
        v.detail = std::to_wstring(flagged.Total()) + L" of " + std::to_wstring(installs.size()) +
                   L" service(s) installed in the last " + days + L" days are worth a look:\n" + flagged.Text();
        if (!others.Empty()) v.detail += L"The other services installed in that time:\n" + others.Text();
    }
    else if (!installs.empty()) {
        v.status = CHECK_PASS;
        v.detail = std::to_wstring(installs.size()) + L" service(s) installed in the last " + days +
                   L" days. None runs from a user folder, a folder normal users can change, an unsigned or missing file, "
                   L"a command shell or a suspicious command line:\n" + others.Text();
    }
    else {
        v.status = CHECK_PASS;
        v.detail = L"No service was installed in the last " + days + L" days.\n";
    }
    v.detail += notes;
    DebugLog(L"NewServicesVerdict: " + std::to_wstring(installs.size()) + L" install(s), " +
             std::to_wstring(flagged.Total()) + L" flagged -> " + v.status);
    return v;
}

// ---------------------------------------------------------------------------
// 3. Accounts created, members added to Administrators
// ---------------------------------------------------------------------------
static std::wstring MemberText(const EventRecord& e, const std::map<std::wstring, std::wstring>& sidNames)
{
    std::wstring sid = TrimW(e.Field(L"MemberSid"));
    if (!sid.empty()) {
        for (const auto& entry : sidNames) {
            if (EqualsI(entry.first, sid)) return entry.second;
        }
    }
    std::wstring name = e.Field(L"MemberName");
    if (!IsBlankField(name)) return TrimW(name);
    return sid.empty() ? std::wstring(L"an account the event does not name") : sid;
}

EventVerdict NewAccountsVerdict(const EventQueryResult& security, const std::map<std::wstring, std::wstring>& sidNames)
{
    EventVerdict v;
    if (!Judgeable(security)) {
        v.status = UnjudgeableStatus({ &security });
        v.detail = EventQueryProblemText(security, L"Security");
        DebugLog(L"NewAccountsVerdict: log not readable -> " + v.status);
        return v;
    }
    CappedList list(30);
    size_t created = 0, added = 0;
    for (const EventRecord& e : security.events) {
        if (e.id == 4720) {
            ++created;
            list.Add(L"  " + ShortTime(e) + L"  account created: " + EventAccountText(e, L"Target") + L", by " +
                     EventAccountText(e, L"Subject") + L"\n");
        }
        else if (e.id == 4732 && EqualsI(TrimW(e.Field(L"TargetSid")), kAdministratorsSid)) {
            ++added;
            list.Add(L"  " + ShortTime(e) + L"  added to the Administrators group: " + MemberText(e, sidNames) + L", by " +
                     EventAccountText(e, L"Subject") + L"\n");
        }
    }
    std::wstring days = std::to_wstring(kNewAccountDays);
    if (!list.Empty()) {
        v.status = CHECK_WARNING;
        v.detail = std::to_wstring(created) + L" local account(s) created and " + std::to_wstring(added) +
                   L" addition(s) to the Administrators group in the last " + days + L" days:\n" + list.Text();
    }
    else {
        v.status = CHECK_PASS;
        v.detail = L"No local account was created and nobody was added to the Administrators group in the last " + days +
                   L" days.\n";
    }
    v.detail += CapNotes(security, L"Security");
    DebugLog(L"NewAccountsVerdict: " + std::to_wstring(created) + L" created, " + std::to_wstring(added) + L" added -> " + v.status);
    return v;
}

// ---------------------------------------------------------------------------
// 4. Failed sign-ins and lockouts
// ---------------------------------------------------------------------------
std::wstring LogonTypeName(const std::wstring& logonTypeIn)
{
    static const struct { const wchar_t* type; const wchar_t* name; } kTypes[] = {
        { L"2",  L"at the keyboard" },
        { L"3",  L"over the network" },
        { L"4",  L"batch job or scheduled task" },
        { L"5",  L"service" },
        { L"7",  L"unlocking the screen" },
        { L"8",  L"over the network with a clear-text password" },
        { L"9",  L"other credentials (runas /netonly)" },
        { L"10", L"Remote Desktop" },
        { L"11", L"cached domain sign-in" },
        { L"12", L"cached Remote Desktop sign-in" },
        { L"13", L"cached unlock" },
    };
    std::wstring type = TrimW(logonTypeIn);
    for (const auto& t : kTypes) {
        if (type == t.type) return type + L" (" + t.name + L")";
    }
    return type.empty() ? std::wstring(L"unknown") : type;
}

std::wstring LogonFailureReason(const std::wstring& statusCode)
{
    static const struct { const wchar_t* code; const wchar_t* reason; } kReasons[] = {
        { L"0xc0000064", L"the user name does not exist" },
        { L"0xc000006a", L"wrong password" },
        { L"0xc000006d", L"wrong user name or password" },
        { L"0xc000006f", L"outside the allowed sign-in hours" },
        { L"0xc0000070", L"not allowed from this computer" },
        { L"0xc0000071", L"the password has expired" },
        { L"0xc0000072", L"the account is disabled" },
        { L"0xc0000133", L"the clocks of the two computers differ too much" },
        { L"0xc000015b", L"this sign-in type is not allowed for the account" },
        { L"0xc0000193", L"the account has expired" },
        { L"0xc0000224", L"the password must be changed first" },
        { L"0xc0000234", L"the account is locked out" },
        { L"0xc000005e", L"no sign-in server was available" },
    };
    std::wstring code = ToLowerW(TrimW(statusCode));
    for (const auto& r : kReasons) {
        if (code == r.code) return r.reason;
    }
    return L"";
}

// Sorted by count, most first, then by text.
static std::vector<std::pair<std::wstring, size_t>> Ranked(const std::map<std::wstring, std::pair<std::wstring, size_t>>& counts)
{
    std::vector<std::pair<std::wstring, size_t>> out;
    for (const auto& entry : counts) out.push_back(entry.second);
    std::stable_sort(out.begin(), out.end(), [](const std::pair<std::wstring, size_t>& a, const std::pair<std::wstring, size_t>& b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    return out;
}

static void Count(std::map<std::wstring, std::pair<std::wstring, size_t>>& counts, const std::wstring& text)
{
    auto& entry = counts[ToLowerW(text)];
    if (entry.second == 0) entry.first = text;
    entry.second++;
}

static std::wstring RankedLines(const std::vector<std::pair<std::wstring, size_t>>& ranked, size_t maxLines)
{
    std::wstring out;
    for (size_t i = 0; i < ranked.size() && i < maxLines; ++i) {
        out += L"  " + ranked[i].first + L": " + std::to_wstring(ranked[i].second) + L"\n";
    }
    if (ranked.size() > maxLines) out += L"  ... and " + std::to_wstring(ranked.size() - maxLines) + L" more.\n";
    return out;
}

EventVerdict FailedLogonsVerdict(const EventQueryResult& failures, const EventQueryResult& lockouts)
{
    EventVerdict v;
    if (!Judgeable(failures) && !Judgeable(lockouts)) {
        v.status = UnjudgeableStatus({ &failures, &lockouts });
        std::wstring p = EventQueryProblemText(failures, L"Security");
        v.detail = p.empty() ? EventQueryProblemText(lockouts, L"Security") : p;
        DebugLog(L"FailedLogonsVerdict: log not readable -> " + v.status);
        return v;
    }
    std::map<std::wstring, std::pair<std::wstring, size_t>> accounts, types, reasons;
    size_t failed = 0;
    if (Judgeable(failures)) {
        for (const EventRecord& e : failures.events) {
            if (e.id != 4625) continue;
            ++failed;
            Count(accounts, EventAccountText(e, L"Target"));
            Count(types, LogonTypeName(e.Field(L"LogonType")));
            std::wstring code = TrimW(e.Field(L"SubStatus"));
            if (code.empty() || code == L"0x0") code = TrimW(e.Field(L"Status"));
            std::wstring reason = LogonFailureReason(code);
            Count(reasons, reason.empty() ? (code.empty() ? std::wstring(L"not given") : L"code " + code) : reason);
        }
    }
    CappedList lockList(20);
    if (Judgeable(lockouts)) {
        for (const EventRecord& e : lockouts.events) {
            if (e.id != 4740) continue;
            std::wstring user = e.Field(L"TargetUserName");
            std::wstring caller = e.Field(L"TargetDomainName");
            lockList.Add(L"  " + ShortTime(e) + L"  " + (IsBlankField(user) ? std::wstring(L"an account") : TrimW(user)) +
                         L" was locked out" + (IsBlankField(caller) ? std::wstring() : L" (the attempts came from computer " + TrimW(caller) + L")") +
                         L"\n");
        }
    }
    bool atLeast = failures.capped;
    std::wstring countText = (atLeast ? L"at least " : L"") + std::to_wstring(failed);
    bool warn = failed >= kFailedLogonWarnAt || !lockList.Empty();

    std::wstringstream d;
    d << countText << L" failed sign-in(s) and " << lockList.Total() << L" account lockout(s) in the last " << kFailedLogonDays
      << L" days.\n";
    if (failed > 0) {
        d << L"Accounts tried most:\n" << RankedLines(Ranked(accounts), 5);
        d << L"Sign-in types:\n" << RankedLines(Ranked(types), 6);
        d << L"Reasons:\n" << RankedLines(Ranked(reasons), 6);
    }
    if (!lockList.Empty()) d << L"Lockouts:\n" << lockList.Text();
    d << CapNotes(failures, L"Security") << CapNotes(lockouts, L"Security");
    if (!Judgeable(failures)) d << L"Failed sign-ins: N/A. " << EventQueryProblemText(failures, L"Security") << L"\n";
    if (!Judgeable(lockouts)) d << L"Lockouts: N/A. " << EventQueryProblemText(lockouts, L"Security") << L"\n";

    v.status = warn ? CHECK_WARNING : CHECK_PASS;
    v.detail = d.str();
    DebugLog(L"FailedLogonsVerdict: " + countText + L" failure(s), " + std::to_wstring(lockList.Total()) + L" lockout(s) -> " + v.status);
    return v;
}

// ---------------------------------------------------------------------------
// 5. Microsoft Defender
// ---------------------------------------------------------------------------

// Start of a resource in a Defender Path field: "kind:_" with a kind of letters only.
static bool ResourceKindAt(const std::wstring& text, size_t pos, std::wstring& kind)
{
    size_t p = pos;
    while (p < text.size() && iswalpha(text[p])) ++p;
    if (p == pos || p + 1 >= text.size() || text[p] != L':' || text[p + 1] != L'_') return false;
    kind = text.substr(pos, p - pos);
    return true;
}

static std::wstring OneResource(const std::wstring& kindIn, const std::wstring& rest)
{
    std::wstring kind = ToLowerW(kindIn);
    std::wstring value = TrimW(rest);
    if (kind == L"file" || kind == L"containerfile" || kind == L"amsi") return value.empty() ? L"a file" : value;
    if (kind == L"cmdline") {
        std::wstring program = ProgramFromCommandLine(value);
        return program.empty() ? std::wstring(L"a command line (not shown: command lines can hold passwords)")
                               : L"a command line run by " + program + L" (its arguments are not shown: they can hold passwords)";
    }
    if (kind == L"webfile") {
        std::wstring file = TrimW(value.substr(0, value.find(L'|')));
        return (file.empty() ? std::wstring(L"a downloaded file") : file) + L" (downloaded; the address is not shown)";
    }
    if (kind == L"regkey") return L"registry " + value;
    if (kind == L"process") return L"a running process";
    return kindIn + L" resource";
}

std::wstring DefenderResourceText(const std::wstring& path, size_t maxItems)
{
    // Split only where a new "kind:_" begins after a semicolon: a command line can
    // hold semicolons of its own, and its pieces must stay with it (and hidden).
    std::vector<std::pair<std::wstring, std::wstring>> resources;   // kind, value
    size_t pos = 0;
    std::wstring kind;
    while (pos < path.size() && iswspace(path[pos])) ++pos;
    if (pos < path.size() && ResourceKindAt(path, pos, kind)) {
        size_t start = pos + kind.size() + 2;
        size_t search = start;
        while (true) {
            size_t semi = path.find(L';', search);
            if (semi == std::wstring::npos) {
                resources.push_back({ kind, path.substr(start) });
                break;
            }
            size_t next = semi + 1;
            while (next < path.size() && iswspace(path[next])) ++next;
            std::wstring nextKind;
            if (next < path.size() && ResourceKindAt(path, next, nextKind)) {
                resources.push_back({ kind, path.substr(start, semi - start) });
                kind = nextKind;
                start = next + nextKind.size() + 2;
                search = start;
            }
            else {
                search = semi + 1;
            }
        }
    }
    else if (!TrimW(path).empty()) {
        // No kind prefix: a plain file path, unless there is more after the program,
        // in which case it is treated as a command line and its arguments are hidden.
        std::wstring t = TrimW(path);
        std::wstring program = ProgramFromCommandLine(t);
        bool commandLine = program.empty() || !EqualsI(program, t);
        resources.push_back({ commandLine ? std::wstring(L"CmdLine") : std::wstring(L"file"), t });
    }
    if (resources.empty()) return L"(no file named)";
    std::vector<std::wstring> parts;
    for (size_t i = 0; i < resources.size() && i < maxItems; ++i) parts.push_back(OneResource(resources[i].first, resources[i].second));
    std::wstring out = JoinW(parts, L"; ");
    if (resources.size() > maxItems) out += L"; and " + std::to_wstring(resources.size() - maxItems) + L" more";
    DebugLog(L"DefenderResourceText: " + std::to_wstring(resources.size()) + L" resource(s)");
    return out;
}

EventVerdict DefenderEventsVerdict(const EventQueryResult& defender)
{
    EventVerdict v;
    if (defender.status == EventQueryStatus::ChannelMissing) {
        v.status = CHECK_NA;
        v.detail = L"The Microsoft Defender log does not exist on this PC: another antivirus product is in charge, or "
                   L"Defender was removed.";
        DebugLog(L"DefenderEventsVerdict: no Defender log -> N/A");
        return v;
    }
    if (!Judgeable(defender)) {
        v.status = UnjudgeableStatus({ &defender });
        v.detail = EventQueryProblemText(defender, L"Microsoft Defender");
        DebugLog(L"DefenderEventsVerdict: log not readable -> " + v.status);
        return v;
    }
    CappedList list(25);
    size_t detections = 0, actions = 0, off = 0;
    for (const EventRecord& e : defender.events) {
        std::wstring threat = TrimW(e.Field(L"Threat Name"));
        if (threat.empty()) threat = L"an unnamed threat";
        if (e.id == 1116) {
            ++detections;
            std::wstring severity = TrimW(e.Field(L"Severity Name"));
            std::wstring category = TrimW(e.Field(L"Category Name"));
            std::wstring about;
            if (!severity.empty()) about = severity;
            if (!category.empty()) about += (about.empty() ? L"" : L", ") + category;
            list.Add(L"  " + ShortTime(e) + L"  detected: " + threat + (about.empty() ? L"" : L" (" + about + L")") + L" in " +
                     DefenderResourceText(e.Field(L"Path")) + L"\n");
        }
        else if (e.id == 1117) {
            ++actions;
            std::wstring action = TrimW(e.Field(L"Action Name"));
            std::wstring error = ToLowerW(TrimW(e.Field(L"Error Code")));
            bool failed = !error.empty() && error != L"0x00000000" && error != L"0x0" && error != L"0";
            list.Add(L"  " + ShortTime(e) + L"  action taken: " + (action.empty() ? std::wstring(L"(not named)") : action) +
                     L" on " + threat + L" in " + DefenderResourceText(e.Field(L"Path")) +
                     (failed ? L" (the action failed: " + TrimW(e.Field(L"Error Description")) + L")" : L"") + L"\n");
        }
        else if (e.id == 5001) {
            ++off;
            list.Add(L"  " + ShortTime(e) + L"  real-time protection was turned off\n");
        }
    }
    std::wstring days = std::to_wstring(kDefenderEventDays);
    if (!list.Empty()) {
        v.status = CHECK_WARNING;
        v.detail = L"Microsoft Defender in the last " + days + L" days: " + std::to_wstring(detections) + L" detection(s), " +
                   std::to_wstring(actions) + L" action(s) taken, real-time protection turned off " + std::to_wstring(off) +
                   L" time(s):\n" + list.Text();
    }
    else {
        v.status = CHECK_PASS;
        v.detail = L"Microsoft Defender recorded no detection in the last " + days +
                   L" days, and real-time protection was not turned off.\n";
    }
    v.detail += CapNotes(defender, L"Microsoft Defender");
    std::wstring p = EventQueryProblemText(defender, L"Microsoft Defender");
    if (!p.empty()) v.detail += p + L"\n";
    DebugLog(L"DefenderEventsVerdict: " + std::to_wstring(detections) + L" detection(s), " + std::to_wstring(actions) +
             L" action(s), " + std::to_wstring(off) + L" off -> " + v.status);
    return v;
}
