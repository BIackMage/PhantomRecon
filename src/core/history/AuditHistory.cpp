#include "pch.h"
#include "AuditHistory.h"

#include "AppPaths.h"
#include "CheckCatalog.h"
#include "FileIO.h"
#include "JsonReader.h"
#include "JsonWriter.h"
#include "StringConv.h"
#include "Version.h"

#include <cmath>
#include <set>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[AuditHistory] " + msg + L"\n").c_str());
}

// The file is small (500 records of a few kilobytes); anything far larger is not ours.
static const size_t kMaxHistoryFileBytes = 64 * 1024 * 1024;

// Longest check id kept from the file. Real ids are under 30 characters.
static const size_t kMaxCheckIdChars = 100;

std::wstring AuditHistoryFileName()
{
    return L"phantom_recon_history.jsonl";
}

std::wstring DefaultAuditHistoryPath()
{
    return AppFilePath(AuditHistoryFileName());
}

// ---------------------------------------------------------------------------
// Times
// ---------------------------------------------------------------------------
std::wstring NowUtcIso()
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    wchar_t buf[32];
    swprintf_s(buf, L"%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static bool ReadDigits(const std::wstring& s, size_t pos, size_t count, int& value)
{
    value = 0;
    for (size_t i = 0; i < count; ++i) {
        wchar_t c = s[pos + i];
        if (c < L'0' || c > L'9') return false;
        value = value * 10 + (c - L'0');
    }
    return true;
}

bool ParseUtcIso(const std::wstring& s, SYSTEMTIME* utcOut)
{
    // Exactly "YYYY-MM-DDTHH:MM:SSZ".
    if (s.size() != 20) return false;
    if (s[4] != L'-' || s[7] != L'-' || s[10] != L'T' || s[13] != L':' || s[16] != L':' || s[19] != L'Z') return false;
    int year, month, day, hour, minute, second;
    if (!ReadDigits(s, 0, 4, year) || !ReadDigits(s, 5, 2, month) || !ReadDigits(s, 8, 2, day) ||
        !ReadDigits(s, 11, 2, hour) || !ReadDigits(s, 14, 2, minute) || !ReadDigits(s, 17, 2, second)) {
        return false;
    }
    if (year < 2000 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 ||
        second > 59) {
        return false;
    }
    SYSTEMTIME st = {};
    st.wYear = static_cast<WORD>(year);
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour);
    st.wMinute = static_cast<WORD>(minute);
    st.wSecond = static_cast<WORD>(second);
    FILETIME ft;
    if (!SystemTimeToFileTime(&st, &ft)) return false;   // 30 February and the like
    if (utcOut) *utcOut = st;
    return true;
}

static bool ToLocal(const std::wstring& isoUtc, SYSTEMTIME& local)
{
    SYSTEMTIME utc;
    if (!ParseUtcIso(isoUtc, &utc)) return false;
    if (!SystemTimeToTzSpecificLocalTime(NULL, &utc, &local)) local = utc;
    return true;
}

static const wchar_t* MonthName(WORD month)
{
    static const wchar_t* const names[12] = { L"Jan", L"Feb", L"Mar", L"Apr", L"May", L"Jun",
                                              L"Jul", L"Aug", L"Sep", L"Oct", L"Nov", L"Dec" };
    return month >= 1 && month <= 12 ? names[month - 1] : L"?";
}

std::wstring HistoryDateText(const std::wstring& isoUtc, bool withYear)
{
    SYSTEMTIME local;
    if (!ToLocal(isoUtc, local)) return L"";
    SYSTEMTIME now;
    GetLocalTime(&now);
    wchar_t buf[32];
    if (withYear || local.wYear != now.wYear) {
        swprintf_s(buf, L"%u %s %u", local.wDay, MonthName(local.wMonth), local.wYear);
    }
    else {
        swprintf_s(buf, L"%u %s", local.wDay, MonthName(local.wMonth));
    }
    return buf;
}

std::wstring HistoryDateTimeText(const std::wstring& isoUtc)
{
    SYSTEMTIME local;
    if (!ToLocal(isoUtc, local)) return L"";
    wchar_t buf[32];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u", local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute);
    return buf;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------
static bool IsKnownStatus(const std::wstring& s)
{
    return s == CHECK_PASS || s == CHECK_FAIL || s == CHECK_WARNING || s == CHECK_INFO || s == CHECK_ERROR || s == CHECK_NA;
}

AuditRecord MakeAuditRecord(const std::vector<SecurityCheckResult>& results, const HardeningScore& score,
                            const std::wstring& nowUtc)
{
    AuditRecord r;
    r.firstSeen = nowUtc;
    r.lastSeen = nowUtc;
    r.version = PHANTOMRECON_VERSION_W;
    r.score = score.score;
    r.label = score.label;
    r.pass = score.pass;
    r.warn = score.warn;
    r.fail = score.fail;
    r.info = score.info + score.notApplicable;
    r.error = score.error;
    for (const SecurityCheckResult& result : results) {
        if (!result.id.empty()) r.statuses[result.id] = result.status;
    }
    return r;
}

std::wstring AuditRecordToJsonLine(const AuditRecord& record)
{
    JsonWriter w;
    w.SetCompact(true);
    w.BeginObject();
    w.Key(L"firstSeen"); w.String(record.firstSeen);
    w.Key(L"lastSeen"); w.String(record.lastSeen);
    w.Key(L"version"); w.String(record.version);
    w.Key(L"score"); w.Number(record.score);
    w.Key(L"label"); w.String(record.label);
    w.Key(L"pass"); w.Number(record.pass);
    w.Key(L"warn"); w.Number(record.warn);
    w.Key(L"fail"); w.Number(record.fail);
    w.Key(L"info"); w.Number(record.info);
    w.Key(L"error"); w.Number(record.error);
    w.Key(L"statuses");
    w.BeginObject();
    for (const auto& entry : record.statuses) {
        w.Key(entry.first);
        w.String(entry.second);
    }
    w.EndObject();
    w.EndObject();
    return w.Text();
}

static bool WholeNumber(const JsonValue* v, int low, int high, int& out)
{
    if (!v || v->type != JsonValue::Type::Number) return false;
    double d = v->number;
    if (!std::isfinite(d) || d != std::floor(d) || d < low || d > high) return false;
    out = static_cast<int>(d);
    return true;
}

bool AuditRecordFromJsonLine(const std::string& utf8Line, AuditRecord& out, std::string& why)
{
    out = AuditRecord();
    JsonValue root;
    if (!ParseJson(utf8Line, root, why)) return false;
    if (!root.IsObject()) {
        why = "not a JSON object";
        return false;
    }

    const JsonValue* first = root.Find("firstSeen");
    const JsonValue* last = root.Find("lastSeen");
    if (!first || !first->IsString() || !last || !last->IsString()) {
        why = "firstSeen or lastSeen missing";
        return false;
    }
    out.firstSeen = Utf8ToWide(first->text);
    out.lastSeen = Utf8ToWide(last->text);
    if (!ParseUtcIso(out.firstSeen, nullptr) || !ParseUtcIso(out.lastSeen, nullptr)) {
        why = "firstSeen or lastSeen is not a UTC time";
        return false;
    }
    if (!WholeNumber(root.Find("score"), 0, 100, out.score)) {
        why = "score missing or not a whole number from 0 to 100";
        return false;
    }
    const JsonValue* statuses = root.Find("statuses");
    if (!statuses || !statuses->IsObject()) {
        why = "statuses missing";
        return false;
    }

    // Optional fields: a record from another version may lack them.
    const JsonValue* version = root.Find("version");
    if (version && version->IsString()) out.version = Utf8ToWide(version->text);
    const JsonValue* label = root.Find("label");
    if (label && label->IsString()) out.label = Utf8ToWide(label->text);
    const int kMaxCount = 100000;
    WholeNumber(root.Find("pass"), 0, kMaxCount, out.pass);
    WholeNumber(root.Find("warn"), 0, kMaxCount, out.warn);
    WholeNumber(root.Find("fail"), 0, kMaxCount, out.fail);
    WholeNumber(root.Find("info"), 0, kMaxCount, out.info);
    WholeNumber(root.Find("error"), 0, kMaxCount, out.error);

    int dropped = 0;
    for (const auto& member : statuses->members) {
        std::wstring id = Utf8ToWide(member.first);
        if (id.empty() || id.size() > kMaxCheckIdChars || !member.second.IsString()) {
            ++dropped;
            continue;
        }
        std::wstring status = Utf8ToWide(member.second.text);
        if (!IsKnownStatus(status)) {
            ++dropped;
            continue;
        }
        out.statuses[id] = status;
    }
    if (dropped > 0) DebugLog(L"Record from " + out.firstSeen + L": " + std::to_wstring(dropped) + L" unknown status entries dropped");
    why.clear();
    return true;
}

std::vector<AuditRecord> ParseAuditHistoryText(const std::string& text, int* skipped)
{
    std::vector<AuditRecord> records;
    int bad = 0;
    size_t start = 0;
    int lineNumber = 0;
    // A UTF-8 byte order mark (a text editor may add one) is not part of the first line.
    if (text.size() >= 3 && text.compare(0, 3, "\xEF\xBB\xBF") == 0) start = 3;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        std::string line = text.substr(start, end - start);
        start = end + 1;
        ++lineNumber;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
        size_t lead = line.find_first_not_of(" \t");
        if (lead == std::string::npos) continue;   // blank line
        if (lead > 0) line.erase(0, lead);

        AuditRecord record;
        std::string why;
        if (AuditRecordFromJsonLine(line, record, why)) {
            records.push_back(std::move(record));
        }
        else {
            ++bad;
            DebugLog(L"Line " + std::to_wstring(lineNumber) + L" skipped: " + Utf8ToWide(why));
        }
    }
    if (skipped) *skipped = bad;
    return records;
}

bool LoadAuditHistory(const std::wstring& path, std::vector<AuditRecord>& records, int* skipped)
{
    records.clear();
    if (skipped) *skipped = 0;
    if (!FileExists(path)) {
        DebugLog(L"No history file yet: " + path);
        return true;
    }
    std::vector<uint8_t> bytes;
    bool truncated = false;
    if (!ReadBinaryFile(path, bytes, kMaxHistoryFileBytes, &truncated)) {
        DebugLog(L"Could not read " + path + L" (error " + std::to_wstring(GetLastError()) + L")");
        return false;
    }
    if (truncated) DebugLog(L"History file larger than expected; only the start is read: " + path);
    std::string text(bytes.begin(), bytes.end());
    int bad = 0;
    records = ParseAuditHistoryText(text, &bad);
    if (skipped) *skipped = bad;
    DebugLog(L"Loaded " + std::to_wstring(records.size()) + L" records, skipped " + std::to_wstring(bad) + L" lines: " + path);
    return true;
}

bool SaveAuditHistory(const std::wstring& path, const std::vector<AuditRecord>& records)
{
    std::wstring text;
    for (const AuditRecord& r : records) text += AuditRecordToJsonLine(r) + L"\n";
    // Write next to the file, then swap it in, so a crash never leaves half a file.
    std::wstring temp = path + L".tmp";
    if (!WriteUtf8File(temp, text, false)) {
        DebugLog(L"Could not write " + temp);
        DeleteFileW(temp.c_str());
        return false;
    }
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DebugLog(L"Could not replace " + path + L" (error " + std::to_wstring(GetLastError()) + L")");
        DeleteFileW(temp.c_str());
        return false;
    }
    DebugLog(L"Saved " + std::to_wstring(records.size()) + L" records to " + path);
    return true;
}

bool SameAuditState(const AuditRecord& a, const AuditRecord& b)
{
    return a.score == b.score && a.statuses == b.statuses;
}

bool AddAuditRecord(std::vector<AuditRecord>& records, const AuditRecord& current, size_t maxRecords)
{
    if (maxRecords == 0) maxRecords = 1;
    bool appended = false;
    if (!records.empty() && SameAuditState(records.back(), current)) {
        records.back().lastSeen = current.lastSeen;
        DebugLog(L"Same state as the newest record (first seen " + records.back().firstSeen + L"); lastSeen updated");
    }
    else {
        records.push_back(current);
        appended = true;
        DebugLog(L"New record appended, score " + std::to_wstring(current.score));
    }
    if (records.size() > maxRecords) {
        size_t drop = records.size() - maxRecords;
        records.erase(records.begin(), records.begin() + static_cast<std::ptrdiff_t>(drop));
        DebugLog(L"Dropped the " + std::to_wstring(drop) + L" oldest record(s) to keep " + std::to_wstring(maxRecords));
    }
    return appended;
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------
static bool IsProblem(const std::wstring& s)
{
    return s == CHECK_FAIL || s == CHECK_WARNING;
}

static bool IsClean(const std::wstring& s)
{
    return s == CHECK_PASS || s == CHECK_NA;
}

// The ids of the current audit in catalog order, then any the catalog does not list.
static std::vector<std::wstring> OrderedIds(const AuditRecord& current)
{
    std::vector<std::wstring> ids;
    std::set<std::wstring> seen;
    for (const CheckInfo& info : GetCheckCatalog()) {
        if (current.statuses.count(info.id)) {
            ids.push_back(info.id);
            seen.insert(info.id);
        }
    }
    for (const auto& entry : current.statuses) {
        if (!seen.count(entry.first)) ids.push_back(entry.first);
    }
    return ids;
}

AuditComparison CompareWithPrevious(const AuditRecord& current, const AuditRecord& previous)
{
    AuditComparison c;
    c.hasPrevious = true;
    c.sameState = SameAuditState(current, previous);
    c.previousFirstSeen = previous.firstSeen;
    c.previousDate = previous.lastSeen;
    c.previousScore = previous.score;
    c.currentScore = current.score;
    c.scoreChange = current.score - previous.score;

    for (const std::wstring& id : OrderedIds(current)) {
        const std::wstring& now = current.statuses.at(id);
        auto before = previous.statuses.find(id);
        if (before == previous.statuses.end()) {
            c.newChecks.push_back({ id, L"", now });
            continue;
        }
        const std::wstring& was = before->second;
        if (was == now) continue;
        AuditChange change{ id, was, now };

        const CheckInfo* info = FindCheckInfo(id);
        if (info && !info->scored) {
            c.activity.push_back(change);
            continue;
        }
        if (IsProblem(was) && IsClean(now)) c.fixed.push_back(change);
        else if (!IsProblem(was) && IsProblem(now)) c.newProblems.push_back(change);
        else if (was == CHECK_WARNING && now == CHECK_FAIL) c.worse.push_back(change);
        else if (was == CHECK_FAIL && now == CHECK_WARNING) c.better.push_back(change);
        // Anything else (PASS to N/A, FAIL to ERROR, INFO to PASS) moved no problem in or
        // out, so it is in no list; sameState is still false.
    }
    DebugLog(L"Compared with the record of " + previous.lastSeen + L": score " + std::to_wstring(c.scoreChange) +
             L", fixed " + std::to_wstring(c.fixed.size()) + L", new " + std::to_wstring(c.newProblems.size()) +
             L", worse " + std::to_wstring(c.worse.size()) + L", better " + std::to_wstring(c.better.size()) +
             L", new checks " + std::to_wstring(c.newChecks.size()) + L", activity " + std::to_wstring(c.activity.size()));
    return c;
}

std::vector<std::wstring> AuditChangeIds(const std::vector<AuditChange>& changes)
{
    std::vector<std::wstring> ids;
    ids.reserve(changes.size());
    for (const AuditChange& c : changes) ids.push_back(c.id);
    return ids;
}

AuditHistoryUpdate RecordAuditInHistory(const std::wstring& path, const AuditRecord& current)
{
    AuditHistoryUpdate update;
    std::vector<AuditRecord> records;
    if (!LoadAuditHistory(path, records, &update.skippedLines)) {
        // Never overwrite a history that exists but could not be read (locked, no access).
        update.error = L"the audit history could not be read: " + path;
        update.comparison.currentScore = current.score;
        update.recent.push_back(current);
        DebugLog(update.error + L"; nothing written");
        return update;
    }
    update.loaded = true;
    if (!records.empty()) update.comparison = CompareWithPrevious(current, records.back());
    else update.comparison.currentScore = current.score;   // first audit: nothing to compare with
    AddAuditRecord(records, current);
    update.saved = SaveAuditHistory(path, records);
    if (!update.saved) update.error = L"the audit history could not be written: " + path;

    size_t from = records.size() > kAuditHistoryChartRecords ? records.size() - kAuditHistoryChartRecords : 0;
    update.recent.assign(records.begin() + static_cast<std::ptrdiff_t>(from), records.end());
    return update;
}
