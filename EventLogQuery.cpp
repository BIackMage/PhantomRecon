#include "pch.h"
#include "EventLogQuery.h"

#include "SystemInfo.h"
#include "TextUtils.h"

#include <windows.h>
#include <winevt.h>

#include <algorithm>
#include <cwchar>
#include <utility>

#pragma comment(lib, "wevtapi.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[EventLogQuery] " + msg + L"\n").c_str());
}

// ---------------------------------------------------------------------------
// RAII for every EVT_HANDLE: the handle is closed when the owner goes away,
// on every path out of a function.
// ---------------------------------------------------------------------------
namespace {

class EvtHandle {
public:
    explicit EvtHandle(EVT_HANDLE handle = NULL) : m_handle(handle) {}
    ~EvtHandle() { Reset(); }
    EvtHandle(const EvtHandle&) = delete;
    EvtHandle& operator=(const EvtHandle&) = delete;
    EvtHandle(EvtHandle&& other) noexcept : m_handle(other.m_handle) { other.m_handle = NULL; }
    EvtHandle& operator=(EvtHandle&& other) noexcept
    {
        if (this != &other) {
            Reset();
            m_handle = other.m_handle;
            other.m_handle = NULL;
        }
        return *this;
    }
    EVT_HANDLE Get() const { return m_handle; }
    explicit operator bool() const { return m_handle != NULL; }
    void Reset()
    {
        if (m_handle) {
            EvtClose(m_handle);
            m_handle = NULL;
        }
    }

private:
    EVT_HANDLE m_handle;
};

// One open element while the event XML is read.
struct XmlFrame {
    std::wstring name;        // local name, without a namespace prefix
    std::wstring nameAttr;    // value of its Name attribute
    bool         hasNameAttr = false;
    std::wstring text;
};

} // namespace

std::wstring EventRecord::Field(const std::wstring& name) const
{
    auto it = data.find(name);
    return it == data.end() ? std::wstring() : it->second;
}

// ---------------------------------------------------------------------------
// Pure helpers: entities, times, XPath, error codes
// ---------------------------------------------------------------------------
static void AppendCodePoint(std::wstring& out, unsigned long cp)
{
    if (cp < 0x10000) {
        out += static_cast<wchar_t>(cp);
        return;
    }
    cp -= 0x10000;
    out += static_cast<wchar_t>(0xD800 + (cp >> 10));
    out += static_cast<wchar_t>(0xDC00 + (cp & 0x3FF));
}

std::wstring DecodeXmlEntities(const std::wstring& text)
{
    if (text.find(L'&') == std::wstring::npos) return text;
    std::wstring out;
    out.reserve(text.size());
    size_t i = 0;
    size_t decoded = 0;
    while (i < text.size()) {
        if (text[i] != L'&') {
            out += text[i++];
            continue;
        }
        size_t semi = text.find(L';', i + 1);
        if (semi == std::wstring::npos || semi - i > 12) {
            out += text[i++];
            continue;
        }
        std::wstring name = text.substr(i + 1, semi - i - 1);
        bool ok = true;
        if (name == L"lt") out += L'<';
        else if (name == L"gt") out += L'>';
        else if (name == L"amp") out += L'&';
        else if (name == L"quot") out += L'"';
        else if (name == L"apos") out += L'\'';
        else if (name.size() > 1 && name[0] == L'#') {
            bool hex = name[1] == L'x' || name[1] == L'X';
            std::wstring digits = name.substr(hex ? 2 : 1);
            wchar_t* end = nullptr;
            unsigned long cp = digits.empty() ? 0 : wcstoul(digits.c_str(), &end, hex ? 16 : 10);
            ok = !digits.empty() && end && *end == L'\0' && cp > 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);
            if (ok) AppendCodePoint(out, cp);
        }
        else {
            ok = false;
        }
        if (ok) {
            i = semi + 1;
            ++decoded;
        }
        else {
            out += text[i++];
        }
    }
    if (decoded > 0 && out.size() > 4096) DebugLog(L"DecodeXmlEntities: " + std::to_wstring(decoded) + L" entities in a long value");
    return out;
}

static bool ReadDigits(const std::wstring& s, size_t pos, size_t count, int& value)
{
    if (pos + count > s.size()) return false;
    value = 0;
    for (size_t i = pos; i < pos + count; ++i) {
        if (s[i] < L'0' || s[i] > L'9') return false;
        value = value * 10 + (s[i] - L'0');
    }
    return true;
}

bool ParseEventSystemTime(const std::wstring& textIn, unsigned long long& fileTime)
{
    std::wstring text = TrimW(textIn);
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    bool shape = text.size() >= 20 && text[4] == L'-' && text[7] == L'-' && (text[10] == L'T' || text[10] == L' ') &&
                 text[13] == L':' && text[16] == L':';
    if (!shape || !ReadDigits(text, 0, 4, year) || !ReadDigits(text, 5, 2, month) || !ReadDigits(text, 8, 2, day) ||
        !ReadDigits(text, 11, 2, hour) || !ReadDigits(text, 14, 2, minute) || !ReadDigits(text, 17, 2, second)) {
        DebugLog(L"ParseEventSystemTime: not a time: \"" + text + L"\"");
        return false;
    }
    size_t pos = 19;
    unsigned long long fraction = 0;
    int fractionDigits = 0;
    if (pos < text.size() && text[pos] == L'.') {
        ++pos;
        while (pos < text.size() && text[pos] >= L'0' && text[pos] <= L'9') {
            if (fractionDigits < 7) {
                fraction = fraction * 10 + static_cast<unsigned long long>(text[pos] - L'0');
                ++fractionDigits;
            }
            ++pos;
        }
        while (fractionDigits > 0 && fractionDigits < 7) {
            fraction *= 10;
            ++fractionDigits;
        }
    }
    if (pos != text.size() - 1 || text[pos] != L'Z') {
        DebugLog(L"ParseEventSystemTime: no UTC marker in \"" + text + L"\"");
        return false;
    }
    SYSTEMTIME st = {};
    st.wYear = static_cast<WORD>(year);
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour);
    st.wMinute = static_cast<WORD>(minute);
    st.wSecond = static_cast<WORD>(second);
    FILETIME ft = {};
    if (!SystemTimeToFileTime(&st, &ft)) {
        DebugLog(L"ParseEventSystemTime: out of range: \"" + text + L"\"");
        return false;
    }
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    fileTime = li.QuadPart + fraction;
    return true;
}

std::wstring BuildEventXPath(const EventQuery& query)
{
    std::vector<std::wstring> clauses;
    if (!query.provider.empty()) {
        bool single = query.provider.find(L'\'') != std::wstring::npos;
        bool both = single && query.provider.find(L'"') != std::wstring::npos;
        if (both) {
            DebugLog(L"BuildEventXPath: provider name has both quote kinds, not filtered: " + query.provider);
        }
        else {
            const wchar_t* q = single ? L"\"" : L"'";
            clauses.push_back(std::wstring(L"Provider[@Name=") + q + query.provider + q + L"]");
        }
    }
    if (!query.ids.empty()) {
        std::wstring ids = L"(";
        for (size_t i = 0; i < query.ids.size(); ++i) {
            if (i > 0) ids += L" or ";
            ids += L"EventID=" + std::to_wstring(query.ids[i]);
        }
        clauses.push_back(ids + L")");
    }
    if (query.days > 0) {
        unsigned long long ms = static_cast<unsigned long long>(query.days) * 86400000ull;
        clauses.push_back(L"TimeCreated[timediff(@SystemTime) <= " + std::to_wstring(ms) + L"]");
    }
    std::wstring xpath = clauses.empty() ? std::wstring(L"*") : L"*[System[" + JoinW(clauses, L" and ") + L"]]";
    DebugLog(L"BuildEventXPath: " + query.channel + L" " + xpath);
    return xpath;
}

EventQueryStatus ClassifyEventLogError(unsigned long error)
{
    EventQueryStatus status;
    switch (error) {
    case ERROR_SUCCESS:
        status = EventQueryStatus::Ok;
        break;
    case ERROR_ACCESS_DENIED:
        status = EventQueryStatus::AccessDenied;
        break;
    case ERROR_EVT_CHANNEL_NOT_FOUND:
    case ERROR_EVT_INVALID_CHANNEL_PATH:
        status = EventQueryStatus::ChannelMissing;
        break;
    default:
        status = EventQueryStatus::Error;
        break;
    }
    DebugLog(L"ClassifyEventLogError: " + std::to_wstring(error) + L" -> " + EventQueryStatusName(status));
    return status;
}

std::wstring EventQueryStatusName(EventQueryStatus status)
{
    switch (status) {
    case EventQueryStatus::Ok:              return L"ok";
    case EventQueryStatus::AccessDenied:    return L"access denied";
    case EventQueryStatus::ChannelMissing:  return L"missing";
    case EventQueryStatus::ChannelDisabled: return L"turned off";
    default:                                return L"error";
    }
}

// ---------------------------------------------------------------------------
// Event XML
//
// EvtRender gives one <Event> element with <System> and either <EventData> or
// <UserData>. Only the parts the checks use are kept; the rest is skipped. The
// text is treated as data from outside: anything that is not well formed is
// rejected rather than guessed at.
// ---------------------------------------------------------------------------
static std::wstring LocalName(const std::wstring& qualified)
{
    size_t colon = qualified.find(L':');
    return colon == std::wstring::npos ? qualified : qualified.substr(colon + 1);
}

static bool IsXmlSpace(wchar_t c)
{
    return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n';
}

// parents: the open elements above this one, the root first.
static void StartElement(EventRecord& rec, const std::vector<XmlFrame>& parents, const std::wstring& name,
                         const std::map<std::wstring, std::wstring>& attrs)
{
    if (parents.size() != 2 || parents[1].name != L"System") return;
    if (name == L"Provider") {
        auto it = attrs.find(L"Name");
        if (it != attrs.end()) rec.provider = it->second;
    }
    else if (name == L"TimeCreated") {
        auto it = attrs.find(L"SystemTime");
        if (it != attrs.end()) {
            rec.systemTime = it->second;
            unsigned long long ft = 0;
            if (ParseEventSystemTime(it->second, ft)) rec.fileTime = ft;
        }
    }
}

static void EndElement(EventRecord& rec, const std::vector<XmlFrame>& parents, const XmlFrame& frame, int& unnamedData)
{
    if (parents.size() == 2 && parents[1].name == L"System") {
        if (frame.name == L"EventID") {
            std::wstring t = TrimW(frame.text);
            wchar_t* end = nullptr;
            unsigned long v = t.empty() ? 0 : wcstoul(t.c_str(), &end, 10);
            if (end && *end == L'\0' && v <= 0xFFFF) rec.id = static_cast<unsigned int>(v);
        }
        else if (frame.name == L"Channel") {
            rec.channel = TrimW(frame.text);
        }
        else if (frame.name == L"Computer") {
            rec.computer = TrimW(frame.text);
        }
        return;
    }
    if (parents.size() == 2 && parents[1].name == L"EventData" && frame.name == L"Data") {
        std::wstring key = frame.hasNameAttr ? frame.nameAttr : L"#" + std::to_wstring(++unnamedData);
        rec.data[key] = TrimW(frame.text);
        return;
    }
    if (parents.size() == 3 && parents[1].name == L"UserData") {
        rec.data[frame.name] = TrimW(frame.text);
    }
}

bool ParseEventXml(const std::wstring& xml, EventRecord& out)
{
    EventRecord rec;
    std::vector<XmlFrame> stack;
    bool sawRoot = false;
    bool rootClosed = false;
    int unnamedData = 0;
    const size_t n = xml.size();
    size_t i = 0;

    auto fail = [&](const wchar_t* why) {
        DebugLog(std::wstring(L"ParseEventXml: ") + why + L" at character " + std::to_wstring(i));
        return false;
    };

    while (i < n) {
        if (xml[i] != L'<') {
            size_t next = xml.find(L'<', i);
            if (next == std::wstring::npos) next = n;
            std::wstring text = xml.substr(i, next - i);
            if (!stack.empty()) stack.back().text += DecodeXmlEntities(text);
            else if (!TrimW(text).empty()) return fail(L"text outside the Event element");
            i = next;
            continue;
        }
        if (xml.compare(i, 4, L"<!--") == 0) {
            size_t end = xml.find(L"-->", i + 4);
            if (end == std::wstring::npos) return fail(L"unclosed comment");
            i = end + 3;
            continue;
        }
        if (xml.compare(i, 9, L"<![CDATA[") == 0) {
            size_t end = xml.find(L"]]>", i + 9);
            if (end == std::wstring::npos) return fail(L"unclosed CDATA");
            if (!stack.empty()) stack.back().text += xml.substr(i + 9, end - i - 9);
            i = end + 3;
            continue;
        }
        if (i + 1 < n && (xml[i + 1] == L'?' || xml[i + 1] == L'!')) {
            size_t end = xml.find(L'>', i);
            if (end == std::wstring::npos) return fail(L"unclosed declaration");
            i = end + 1;
            continue;
        }

        size_t p = i + 1;
        bool closing = false;
        if (p < n && xml[p] == L'/') {
            closing = true;
            ++p;
        }
        size_t nameStart = p;
        while (p < n && !IsXmlSpace(xml[p]) && xml[p] != L'/' && xml[p] != L'>') ++p;
        std::wstring name = LocalName(xml.substr(nameStart, p - nameStart));
        if (name.empty()) return fail(L"tag without a name");

        std::map<std::wstring, std::wstring> attrs;
        bool selfClosing = false;
        while (true) {
            while (p < n && IsXmlSpace(xml[p])) ++p;
            if (p >= n) return fail(L"unclosed tag");
            if (xml[p] == L'>') {
                ++p;
                break;
            }
            if (xml[p] == L'/') {
                if (closing || p + 1 >= n || xml[p + 1] != L'>') return fail(L"stray slash in a tag");
                selfClosing = true;
                p += 2;
                break;
            }
            if (closing) return fail(L"attribute in an end tag");
            size_t attrStart = p;
            while (p < n && !IsXmlSpace(xml[p]) && xml[p] != L'=' && xml[p] != L'>' && xml[p] != L'/') ++p;
            std::wstring attrName = LocalName(xml.substr(attrStart, p - attrStart));
            while (p < n && IsXmlSpace(xml[p])) ++p;
            if (attrName.empty() || p >= n || xml[p] != L'=') return fail(L"attribute without a value");
            ++p;
            while (p < n && IsXmlSpace(xml[p])) ++p;
            if (p >= n || (xml[p] != L'\'' && xml[p] != L'"')) return fail(L"unquoted attribute value");
            wchar_t quote = xml[p++];
            size_t valueEnd = xml.find(quote, p);
            if (valueEnd == std::wstring::npos) return fail(L"unclosed attribute value");
            attrs[attrName] = DecodeXmlEntities(xml.substr(p, valueEnd - p));
            p = valueEnd + 1;
        }
        i = p;

        if (closing) {
            if (stack.empty() || stack.back().name != name) return fail(L"end tag does not match");
            XmlFrame frame = std::move(stack.back());
            stack.pop_back();
            EndElement(rec, stack, frame, unnamedData);
            if (stack.empty()) rootClosed = true;
            continue;
        }
        if (rootClosed) return fail(L"a second root element");
        if (stack.empty()) {
            if (name != L"Event") return fail(L"the root element is not Event");
            sawRoot = true;
        }
        XmlFrame frame;
        frame.name = name;
        auto nameAttr = attrs.find(L"Name");
        if (nameAttr != attrs.end()) {
            frame.hasNameAttr = true;
            frame.nameAttr = nameAttr->second;
        }
        StartElement(rec, stack, name, attrs);
        if (selfClosing) {
            EndElement(rec, stack, frame, unnamedData);
            if (stack.empty()) rootClosed = true;
        }
        else {
            stack.push_back(std::move(frame));
        }
    }
    if (!sawRoot || !rootClosed || !stack.empty()) return fail(L"the Event element is not complete");
    out = std::move(rec);
    return true;
}

// ---------------------------------------------------------------------------
// The query itself
// ---------------------------------------------------------------------------
static bool RenderEventXml(EVT_HANDLE event, std::wstring& xml)
{
    DWORD used = 0;
    DWORD properties = 0;
    if (!EvtRender(NULL, event, EvtRenderEventXml, 0, NULL, &used, &properties)) {
        DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) {
            DebugLog(L"EvtRender (size) failed: " + std::to_wstring(error));
            return false;
        }
    }
    std::vector<wchar_t> buffer(used / sizeof(wchar_t) + 1, L'\0');
    DWORD bytes = static_cast<DWORD>(buffer.size() * sizeof(wchar_t));
    if (!EvtRender(NULL, event, EvtRenderEventXml, bytes, buffer.data(), &used, &properties)) {
        DebugLog(L"EvtRender failed: " + std::to_wstring(GetLastError()));
        return false;
    }
    buffer.back() = L'\0';
    xml.assign(buffer.data());
    return true;
}

// enabled is set when the log's configuration could be read.
static bool ReadChannelEnabled(const std::wstring& channel, bool& enabled)
{
    EvtHandle config(EvtOpenChannelConfig(NULL, channel.c_str(), 0));
    if (!config) {
        DebugLog(L"EvtOpenChannelConfig(" + channel + L") failed: " + std::to_wstring(GetLastError()));
        return false;
    }
    EVT_VARIANT value = {};
    DWORD used = 0;
    if (!EvtGetChannelConfigProperty(config.Get(), EvtChannelConfigEnabled, 0, sizeof(value), &value, &used) ||
        value.Type != EvtVarTypeBoolean) {
        DebugLog(L"EvtGetChannelConfigProperty(" + channel + L", Enabled) failed: " + std::to_wstring(GetLastError()));
        return false;
    }
    enabled = value.BooleanVal != FALSE;
    return true;
}

static std::wstring LocalTimeText(unsigned long long fileTime)
{
    if (fileTime == 0) return L"(time unknown)";
    ULARGE_INTEGER li;
    li.QuadPart = fileTime;
    FILETIME ft;
    ft.dwLowDateTime = li.LowPart;
    ft.dwHighDateTime = li.HighPart;
    std::wstring text = FormatFileTime(ft);
    return text.empty() ? std::wstring(L"(time unknown)") : text;
}

EventQueryResult RunEventQuery(const EventQuery& query)
{
    EventQueryResult result;
    result.channel = query.channel;
    ULONGLONG started = GetTickCount64();
    std::wstring xpath = BuildEventXPath(query);

    // Session NULL: the local computer. This module never opens a remote session.
    EvtHandle results(EvtQuery(NULL, query.channel.c_str(), xpath.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection));
    if (!results) {
        result.error = GetLastError();
        result.status = ClassifyEventLogError(result.error);
        if (result.status == EventQueryStatus::Ok) result.status = EventQueryStatus::Error;
        DebugLog(L"EvtQuery(" + query.channel + L") failed: " + std::to_wstring(result.error) + L" (" +
                 EventQueryStatusName(result.status) + L")");
        return result;
    }

    const size_t kBatch = 64;
    while (true) {
        size_t want = query.maxEvents > result.events.size() ? query.maxEvents - result.events.size() : 0;
        DWORD ask = static_cast<DWORD>(want == 0 ? 1 : (std::min)(want, kBatch));
        EVT_HANDLE raw[64] = {};
        DWORD returned = 0;
        if (!EvtNext(results.Get(), ask, raw, 10000, 0, &returned)) {
            DWORD error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS) {
                result.error = error;
                result.status = ClassifyEventLogError(error);
                if (result.status == EventQueryStatus::Ok) result.status = EventQueryStatus::Error;
                DebugLog(L"EvtNext(" + query.channel + L") stopped: " + std::to_wstring(error));
            }
            break;
        }
        std::vector<EvtHandle> batch;
        batch.reserve(returned);
        for (DWORD k = 0; k < returned && k < 64; ++k) batch.emplace_back(raw[k]);
        if (want == 0) {
            result.capped = !batch.empty();
            break;
        }
        for (const EvtHandle& event : batch) {
            std::wstring xml;
            EventRecord record;
            if (RenderEventXml(event.Get(), xml) && ParseEventXml(xml, record)) {
                record.timeText = LocalTimeText(record.fileTime);
                result.events.push_back(std::move(record));
            }
            else {
                ++result.unreadable;
            }
        }
    }

    // The log hands events back by record number, and a provider can write an event
    // with a slightly older time stamp after a newer one. Order by time, newest first.
    std::stable_sort(result.events.begin(), result.events.end(),
                     [](const EventRecord& a, const EventRecord& b) { return a.fileTime > b.fileTime; });

    if (result.status == EventQueryStatus::Ok) {
        bool enabled = true;
        if (ReadChannelEnabled(query.channel, enabled) && !enabled) result.status = EventQueryStatus::ChannelDisabled;
    }
    DebugLog(L"RunEventQuery(" + query.channel + L"): " + EventQueryStatusName(result.status) + L", " +
             std::to_wstring(result.events.size()) + L" event(s)" + (result.capped ? L" (cap reached)" : L"") +
             (result.unreadable ? L", " + std::to_wstring(result.unreadable) + L" unreadable" : L"") + L" in " +
             std::to_wstring(GetTickCount64() - started) + L" ms");
    return result;
}
