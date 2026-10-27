#include "pch.h"
#include "Reports.h"

#include "AppPaths.h"
#include "CheckCatalog.h"
#include "FileIO.h"
#include "JsonWriter.h"
#include "Redactor.h"
#include "SystemInfo.h"
#include "TextUtils.h"
#include "Version.h"

#include <algorithm>
#include <map>

void FillReportHost(ReportData& data, bool redact)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[40];
    swprintf_s(buf, L"%04u-%02u-%02uT%02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    data.generatedAt = buf;
    data.hostName = GetComputerNameString();
    data.osText = GetWindowsVersionText();
    data.userName = GetCurrentUserNameString();
    data.redacted = redact;
}

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[Reports] " + msg + L"\n").c_str());
}

std::vector<ScanRow> RedactRows(const std::vector<ScanRow>& rows)
{
    std::vector<ScanRow> out;
    out.reserve(rows.size());
    for (const ScanRow& r : rows) out.push_back(RedactScanRow(r));
    return out;
}

std::vector<SecurityCheckResult> RedactAuditResults(const std::vector<SecurityCheckResult>& results)
{
    std::vector<SecurityCheckResult> out = results;
    for (SecurityCheckResult& r : out) {
        r.name = RedactText(r.name);
        r.detail = RedactText(r.detail);
    }
    return out;
}

ReportData RedactReport(const ReportData& in)
{
    ReportData d = in;
    d.redacted = true;
    // The host and user fields hold exactly one name each; the placeholder is certain
    // even when the name is too unusual for the word matcher.
    d.hostName = d.hostName.empty() ? L"" : L"<host>";
    d.userName = d.userName.empty() ? L"" : L"<user>";
    d.osText = RedactText(d.osText);
    d.audit = RedactAuditResults(d.audit);
    d.scan.root = RedactText(d.scan.root);
    d.scan.csvPath = RedactText(d.scan.csvPath);
    d.scan.baselinePath = RedactText(d.scan.baselinePath);
    d.scan.finalState = RedactText(d.scan.finalState);
    d.scanTitle = RedactText(d.scanTitle);
    d.scanModeName = RedactText(d.scanModeName);
    d.rows = RedactRows(d.rows);
    DebugLog(L"RedactReport: " + std::to_wstring(d.audit.size()) + L" findings, " + std::to_wstring(d.rows.size()) + L" rows");
    return d;
}

std::vector<TechniqueCount> CollectTechniques(const ReportData& data)
{
    std::map<std::wstring, TechniqueCount> counts;
    auto add = [&counts](const std::wstring& id, const std::wstring& why) {
        if (id.empty()) return;
        TechniqueCount& t = counts[id];
        t.id = id;
        t.count++;
        if (t.comment.size() < 400 && t.comment.find(why) == std::wstring::npos) {
            if (!t.comment.empty()) t.comment += L"; ";
            t.comment += why;
        }
    };
    for (const SecurityCheckResult& r : data.audit) {
        if (r.status != CHECK_FAIL && r.status != CHECK_WARNING) continue;
        const CheckInfo* info = FindCheckInfo(r.id);
        if (!info) continue;
        for (const std::wstring& id : info->attack) add(id, L"audit: " + info->title);
    }
    for (const ScanRow& row : data.rows) {
        if (row.status == L"MISSING") continue;
        for (const std::wstring& id : SplitAnyW(row.entry.attackIds, L", ")) add(id, L"file: " + FileNameOf(row.entry.path));
    }
    std::vector<TechniqueCount> out;
    for (auto& pair : counts) out.push_back(pair.second);
    std::sort(out.begin(), out.end(), [](const TechniqueCount& a, const TechniqueCount& b) { return a.count > b.count; });
    return out;
}

std::wstring BuildNavigatorReport(const ReportData& input)
{
    // The technique comments name files ("file: tool.exe"), so they come from the
    // redacted rows when names are hidden.
    ReportData data = input.redacted ? RedactReport(input) : input;
    return BuildNavigatorLayer(L"Phantom Recon findings", L"Techniques suggested by findings on " +
        data.hostName + L", " + data.generatedAt, CollectTechniques(data));
}

static void WriteEntry(JsonWriter& w, const ScanRow& row)
{
    const BaselineEntry& e = row.entry;
    w.BeginObject();
    w.Key(L"path"); w.String(e.path);
    w.Key(L"status"); w.String(row.status);
    w.Key(L"changeDetails"); w.String(row.changeDetails);
    w.Key(L"riskDelta"); w.Number(row.riskDelta);
    w.Key(L"score"); w.Number(e.malwareScore);
    w.Key(L"size"); w.Number(static_cast<long long>(e.fileSize));
    w.Key(L"md5"); w.String(e.md5);
    w.Key(L"sha256"); w.String(e.sha256);
    w.Key(L"imphash"); w.String(e.imphash);
    w.Key(L"ssdeep"); w.String(e.ssdeep);
    w.Key(L"signature"); w.String(e.signature);
    w.Key(L"signatureType"); w.String(e.signatureType);
    w.Key(L"catalogSigner"); w.String(e.catalogSigner);
    w.Key(L"revocation"); w.String(e.revocation);
    w.Key(L"thumbprint"); w.String(e.thumbprint);
    w.Key(L"issuer"); w.String(e.issuer);
    w.Key(L"rootCA"); w.String(e.rootCA);
    w.Key(L"version"); w.String(e.version);
    w.Key(L"developer"); w.String(e.developer);
    w.Key(L"hidden"); w.Bool(e.hidden == L"Yes");
    w.Key(L"entropy"); w.Number(e.entropy);
    w.Key(L"imports"); w.Number(e.totalImports);
    w.Key(L"suspiciousImports"); w.Number(e.suspiciousImports);
    w.Key(L"packing"); w.String(e.packingStatus);
    w.Key(L"zoneId"); w.Number(e.zoneId);
    w.Key(L"hostUrl"); w.String(e.zoneHostUrl);
    w.Key(L"knownGood"); w.Bool(e.knownGood);
    w.Key(L"attack"); w.StringArray(SplitAnyW(e.attackIds, L", "));
    w.Key(L"indicators");
    w.BeginArray();
    for (const std::wstring* list : { &e.sigWarnings, &e.packIndicators, &e.peAnomalies, &e.originWarnings, &e.scriptIndicators }) {
        for (const std::wstring& item : SplitW(*list, L';')) w.String(item);
    }
    w.EndArray();
    w.EndObject();
}

std::wstring BuildJsonReport(const ReportData& input)
{
    ReportData data = input.redacted ? RedactReport(input) : input;
    JsonWriter w;
    w.BeginObject();
    w.Key(L"schema"); w.String(L"phantomrecon.report/1");
    w.Key(L"tool");
    w.BeginObject();
    w.Key(L"name"); w.String(PHANTOMRECON_NAME_W);
    w.Key(L"version"); w.String(PHANTOMRECON_VERSION_W);
    w.EndObject();
    w.Key(L"generatedAt"); w.String(data.generatedAt);
    w.Key(L"host");
    w.BeginObject();
    w.Key(L"name"); w.String(data.hostName);
    w.Key(L"os"); w.String(data.osText);
    w.Key(L"user"); w.String(data.userName);
    w.Key(L"redacted"); w.Bool(data.redacted);
    w.EndObject();

    if (data.hasAudit) {
        w.Key(L"hardeningScore");
        w.BeginObject();
        w.Key(L"score"); w.Number(data.score.score);
        w.Key(L"label"); w.String(data.score.label);
        w.Key(L"pass"); w.Number(data.score.pass);
        w.Key(L"warn"); w.Number(data.score.warn);
        w.Key(L"fail"); w.Number(data.score.fail);
        w.Key(L"info"); w.Number(data.score.info + data.score.notApplicable);
        w.Key(L"error"); w.Number(data.score.error);
        w.EndObject();

        w.Key(L"findings");
        w.BeginArray();
        for (const SecurityCheckResult& r : data.audit) {
            const CheckInfo* info = FindCheckInfo(r.id);
            w.BeginObject();
            w.Key(L"id"); w.String(r.id);
            w.Key(L"title"); w.String(r.name);
            w.Key(L"status"); w.String(r.status);
            w.Key(L"severity"); w.String(info ? SeverityName(info->severity) : L"Info");
            w.Key(L"scored"); w.Bool(info ? info->scored : false);
            w.Key(L"category"); w.String(info ? info->category : L"");
            w.Key(L"attack"); w.StringArray(info ? info->attack : std::vector<std::wstring>());
            w.Key(L"cisControls"); w.StringArray(info ? info->cisControls : std::vector<std::wstring>());
            w.Key(L"cisBenchmark"); w.String(info ? info->cisBenchmark : L"");
            w.Key(L"detail"); w.String(r.detail);
            w.Key(L"explanation"); w.String(info ? info->explanation : L"");
            w.Key(L"fix"); w.String(info ? info->fix : L"");
            w.Key(L"undo"); w.String(info ? info->undo : L"");
            w.EndObject();
        }
        w.EndArray();
    }

    if (data.hasScan) {
        const ScanSummary& s = data.scan;
        w.Key(L"scan");
        w.BeginObject();
        w.Key(L"title"); w.String(data.scanTitle);
        w.Key(L"mode"); w.String(data.scanModeName.empty() ? ScanModeName(s.mode) : data.scanModeName);
        w.Key(L"root"); w.String(s.root);
        w.Key(L"startedAt"); w.String(s.startedAt);
        w.Key(L"seconds"); w.Number(s.seconds);
        w.Key(L"cancelled"); w.Bool(s.cancelled);
        w.Key(L"filesProcessed"); w.Number(s.filesProcessed);
        w.Key(L"executables"); w.Number(s.executables);
        w.Key(L"counts");
        w.BeginObject();
        w.Key(L"match"); w.Number(s.match);
        w.Key(L"new"); w.Number(s.added);
        w.Key(L"changed"); w.Number(s.changed);
        w.Key(L"missing"); w.Number(s.missing);
        w.Key(L"updated"); w.Number(s.updated);
        w.Key(L"known"); w.Number(s.known);
        w.Key(L"highRisk"); w.Number(s.highRisk);
        w.EndObject();
        w.Key(L"rows");
        w.BeginArray();
        for (const ScanRow& row : data.rows) WriteEntry(w, row);
        w.EndArray();
        w.EndObject();
    }

    w.Key(L"attack");
    w.BeginArray();
    for (const TechniqueCount& t : CollectTechniques(data)) {
        w.BeginObject();
        w.Key(L"id"); w.String(t.id);
        w.Key(L"name"); w.String(AttackTechniqueName(t.id));
        w.Key(L"count"); w.Number(t.count);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return w.Text() + L"\n";
}

bool SaveReportFile(const std::wstring& path, const std::wstring& text)
{
    return WriteUtf8File(path, text, false);
}
