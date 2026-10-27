#pragma once

#include <map>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// EventLogQuery: reads events from this PC's own Windows event logs.
//
// A small wrapper over the Windows Event Log API (EvtQuery, EvtNext, EvtRender,
// EvtClose). Every query goes to the local computer: no session handle is ever
// opened, so a query can never reach another machine. Each query filters on
// provider, event id and age, reads the newest events first, and stops after
// maxEvents so one busy log cannot slow the audit down.
//
// The XML parsing and the XPath text are pure functions, so tests can feed them
// made-up event XML.
// ---------------------------------------------------------------------------

// Events read per query unless the query says otherwise.
constexpr size_t kDefaultMaxEvents = 500;

enum class EventQueryStatus {
    Ok,               // the log was read
    AccessDenied,     // this account may not read the log (the Security log needs administrator rights)
    ChannelMissing,   // the log does not exist on this PC
    ChannelDisabled,  // the log exists but is turned off, so nothing new is recorded
    Error,            // anything else; error holds the Windows error code
};

// One event, with the fields the checks use.
struct EventRecord {
    unsigned int       id = 0;
    std::wstring       provider;      // Provider Name
    std::wstring       channel;       // Channel, "System", "Security", ...
    std::wstring       computer;      // Computer
    std::wstring       systemTime;    // TimeCreated SystemTime exactly as written ("2026-10-25T11:31:18.9171017Z")
    unsigned long long fileTime = 0;  // the same time as a UTC FILETIME value; 0 when unreadable
    std::wstring       timeText;      // local time "2026-10-25 13:31", filled by RunEventQuery

    // Named fields: <EventData><Data Name='X'>value</Data>, and the fields of the one
    // element inside <UserData> (<UserData><LogFileCleared><SubjectUserName>...). A
    // <Data> without a Name is stored as "#1", "#2", ... in order.
    std::map<std::wstring, std::wstring> data;

    // The value of a named field, "" when the event does not have it.
    std::wstring Field(const std::wstring& name) const;
};

struct EventQuery {
    std::wstring              channel;              // "System", "Security", "Microsoft-Windows-Windows Defender/Operational"
    std::wstring              provider;             // Provider Name to match, "" for any
    std::vector<unsigned int> ids;                  // event ids to match, at least one
    unsigned int              days = 30;            // only events at most this many days old
    size_t                    maxEvents = kDefaultMaxEvents;
};

struct EventQueryResult {
    std::wstring             channel;
    EventQueryStatus         status = EventQueryStatus::Ok;
    unsigned long            error = 0;             // Windows error code when status is not Ok
    std::vector<EventRecord> events;                // newest first
    bool                     capped = false;        // more events matched than maxEvents; only the newest were read
    size_t                   unreadable = 0;        // events that could not be rendered or parsed
};

// Run one query against the local computer's log.
EventQueryResult RunEventQuery(const EventQuery& query);

// The XPath filter RunEventQuery passes to EvtQuery, for example
// *[System[Provider[@Name='Service Control Manager'] and (EventID=7045) and TimeCreated[timediff(@SystemTime) <= 1209600000]]]
std::wstring BuildEventXPath(const EventQuery& query);

// Windows error code from the Event Log API to a status: ERROR_ACCESS_DENIED is
// AccessDenied, ERROR_EVT_CHANNEL_NOT_FOUND and ERROR_EVT_INVALID_CHANNEL_PATH are
// ChannelMissing, 0 is Ok, everything else is Error.
EventQueryStatus ClassifyEventLogError(unsigned long error);

// "ok", "access denied", "missing", "turned off", "error".
std::wstring EventQueryStatusName(EventQueryStatus status);

// Parse the XML EvtRender gives for one event. False when the text is not a
// well-formed <Event> element.
bool ParseEventXml(const std::wstring& xml, EventRecord& out);

// "2026-10-25T11:31:18.9171017Z" (fraction optional) to a UTC FILETIME value.
bool ParseEventSystemTime(const std::wstring& text, unsigned long long& fileTime);

// Replace the five XML entities and numeric character references (&#65; &#x41;).
// Unknown entities are left as written.
std::wstring DecodeXmlEntities(const std::wstring& text);
