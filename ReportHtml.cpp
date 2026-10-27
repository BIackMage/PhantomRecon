#include "pch.h"
#include "Reports.h"

#include "AppPaths.h"
#include "CheckCatalog.h"
#include "ReportHistory.h"
#include "TextUtils.h"
#include "Version.h"

#include <algorithm>
#include <cmath>
#include <map>
#include <sstream>

static std::wstring H(const std::wstring& s)
{
    return HtmlEscape(AsciiPunctuation(s));
}

static const wchar_t* kCss = LR"CSS(
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5b6475;--line:#dde1e8;--fail:#c62828;--warn:#b26a00;--pass:#2e7d32;--info:#4a5a75;--accent:#2f6fde;--code:#f0f2f6}
@media (prefers-color-scheme:dark){:root{--bg:#16181d;--card:#1f2229;--text:#e6e8ee;--muted:#a3abbb;--line:#323743;--fail:#ef6b6b;--warn:#f0b04a;--pass:#62c26b;--info:#93a3c2;--accent:#6f9cff;--code:#262a33}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:32px 0 12px}h3{font-size:16px;margin:0}
.meta{color:var(--muted);font-size:13px}
.top{display:flex;gap:20px;align-items:center;flex-wrap:wrap;margin:20px 0}
.ring{width:132px;height:132px}.ring text{font:700 30px "Segoe UI",sans-serif;fill:var(--text)}
.tiles{display:flex;gap:12px;flex-wrap:wrap}.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:96px}
.tile b{display:block;font-size:24px}.tile span{color:var(--muted);font-size:13px}
.fail{color:var(--fail)}.warn{color:var(--warn)}.pass{color:var(--pass)}.info{color:var(--info)}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 16px}
button,select,input{font:inherit;color:var(--text);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 12px}
button{cursor:pointer}button.on{border-color:var(--accent);color:var(--accent)}
.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:10px;padding:14px 16px;margin:10px 0}
.finding[data-status=FAIL]{border-left-color:var(--fail)}.finding[data-status=WARNING]{border-left-color:var(--warn)}.finding[data-status=PASS]{border-left-color:var(--pass)}
.head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.pill{font-size:12px;font-weight:700;padding:1px 8px;border-radius:999px;border:1px solid currentColor}
.sev{color:var(--muted);font-size:13px}.chips{margin-top:6px}.chip{display:inline-block;font-size:12px;background:var(--code);border-radius:6px;padding:1px 7px;margin:2px 4px 0 0;color:var(--muted)}
pre{background:var(--code);border-radius:8px;padding:10px 12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;font:13px/1.45 Consolas,monospace;margin:6px 0}
.fix{position:relative}.copy{position:absolute;top:6px;right:6px;font-size:12px;padding:2px 8px}
details summary{cursor:pointer;color:var(--muted);font-size:14px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{cursor:pointer;user-select:none;background:var(--code)}
td.path{word-break:break-all;max-width:420px}tr.hi td:first-child{border-left:4px solid var(--fail)}tr.mid td:first-child{border-left:4px solid var(--warn)}
footer{margin-top:40px;color:var(--muted);font-size:13px}
.hist ul{margin:4px 0 12px;padding-left:22px}.trend{display:block;width:100%;max-width:680px;height:auto;margin:14px 0 6px}.trend .grid{stroke:var(--line);stroke-width:1}.trend .line{fill:none;stroke:var(--accent);stroke-width:2.5;stroke-linejoin:round}.trend .dot{fill:var(--accent)}.trend text{font:12px "Segoe UI",sans-serif;fill:var(--muted)}
@media print{.bar,.copy{display:none}.finding{break-inside:avoid}body{background:#fff}}
)CSS";

static const wchar_t* kScript = LR"JS(
function filterFindings(kind,btn){document.querySelectorAll('.bar.f button').forEach(b=>b.classList.remove('on'));btn.classList.add('on');
document.querySelectorAll('.finding').forEach(f=>{const s=f.dataset.status;let show=kind==='all'||(kind==='attention'&&(s==='FAIL'||s==='WARNING'))||(kind==='pass'&&s==='PASS');f.style.display=show?'':'none';});}
function copyFix(btn){const t=btn.parentElement.querySelector('pre').innerText;navigator.clipboard.writeText(t).then(()=>{btn.textContent='Copied';setTimeout(()=>btn.textContent='Copy',1500);});}
function filterRows(){const st=document.getElementById('st').value,q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('#rows tbody tr').forEach(r=>{const ok=(st==='all'||r.dataset.status===st||(st==='review'&&r.dataset.review==='1'))&&(!q||r.innerText.toLowerCase().includes(q));r.style.display=ok?'':'none';});}
function sortRows(col,numeric){const tb=document.querySelector('#rows tbody');const rows=[...tb.rows];const th=document.querySelectorAll('#rows th')[col];const asc=th.dataset.asc!=='1';
document.querySelectorAll('#rows th').forEach(h=>h.dataset.asc='');th.dataset.asc=asc?'1':'0';
rows.sort((a,b)=>{let x=a.cells[col].dataset.v||a.cells[col].innerText,y=b.cells[col].dataset.v||b.cells[col].innerText;if(numeric){x=parseFloat(x)||0;y=parseFloat(y)||0;return asc?x-y:y-x;}return asc?x.localeCompare(y):y.localeCompare(x);});rows.forEach(r=>tb.appendChild(r));}
)JS";

static std::wstring StatusClass(const std::wstring& status)
{
    if (status == CHECK_FAIL) return L"fail";
    if (status == CHECK_WARNING) return L"warn";
    if (status == CHECK_PASS) return L"pass";
    return L"info";
}

static std::wstring ScoreRing(int score, const std::wstring& label)
{
    double r = 54.0;
    double circumference = 2 * 3.14159265358979 * r;
    double filled = circumference * score / 100.0;
    std::wstring color = score >= 75 ? L"var(--pass)" : (score >= 50 ? L"var(--warn)" : L"var(--fail)");
    std::wstringstream s;
    s << L"<svg class=\"ring\" viewBox=\"0 0 132 132\" role=\"img\" aria-label=\"Hardening score " << score << L" out of 100\">"
      << L"<circle cx=\"66\" cy=\"66\" r=\"54\" fill=\"none\" stroke=\"var(--line)\" stroke-width=\"12\"/>"
      << L"<circle cx=\"66\" cy=\"66\" r=\"54\" fill=\"none\" stroke=\"" << color << L"\" stroke-width=\"12\" stroke-linecap=\"round\""
      << L" stroke-dasharray=\"" << FormatFixed(filled, 1) << L" " << FormatFixed(circumference, 1) << L"\" transform=\"rotate(-90 66 66)\"/>"
      << L"<text x=\"66\" y=\"72\" text-anchor=\"middle\">" << score << L"</text></svg>"
      << L"<div><b style=\"font-size:20px\">Hardening score " << score << L"/100</b><div class=\"meta\">" << H(label)
      << L". Every scored check is weighted by severity; a warning earns half. Recent activity checks report events and are not scored.</div></div>";
    return s.str();
}

static void WriteFindings(std::wstringstream& html, const ReportData& d)
{
    html << L"<h2>Security posture</h2>\n<div class=\"top\">" << ScoreRing(d.score.score, d.score.label) << L"</div>\n";
    html << L"<div class=\"tiles\">"
         << L"<div class=\"tile\"><b class=\"fail\">" << d.score.fail << L"</b><span>Fail</span></div>"
         << L"<div class=\"tile\"><b class=\"warn\">" << d.score.warn << L"</b><span>Warning</span></div>"
         << L"<div class=\"tile\"><b class=\"pass\">" << d.score.pass << L"</b><span>Pass</span></div>"
         << L"<div class=\"tile\"><b class=\"info\">" << d.score.info + d.score.notApplicable + d.score.error << L"</b><span>Info</span></div></div>\n";
    if (d.hasHistory) html << BuildHistoryHtmlSection(d.history, d.historyRecords);
    html << L"<div class=\"bar f\"><button class=\"on\" onclick=\"filterFindings('attention',this)\">Needs attention</button>"
         << L"<button onclick=\"filterFindings('all',this)\">All checks</button><button onclick=\"filterFindings('pass',this)\">Passed</button></div>\n";

    for (const std::wstring& category : GetCheckCategories()) {
        bool header = false;
        for (const SecurityCheckResult& r : d.audit) {
            const CheckInfo* info = FindCheckInfo(r.id);
            if (!info || info->category != category) continue;
            if (!header) {
                html << L"<h3 style=\"margin-top:22px\">" << H(category) << L"</h3>\n";
                header = true;
            }
            bool attention = r.status == CHECK_FAIL || r.status == CHECK_WARNING;
            html << L"<article class=\"finding\" data-status=\"" << H(r.status) << L"\"" << (attention ? L"" : L" style=\"display:none\"") << L">"
                 << L"<div class=\"head\"><span class=\"pill " << StatusClass(r.status) << L"\">" << H(r.status) << L"</span>"
                 << L"<h3>" << H(r.name) << L"</h3><span class=\"sev\">" << SeverityName(info->severity) << L" severity"
                 << (info->scored ? L"" : L", not scored") << L"</span></div>";
            html << L"<p>" << H(info->explanation) << L"</p>";
            html << L"<pre>" << H(r.detail) << L"</pre>";
            if (attention) {
                html << L"<div class=\"fix\"><b>How to fix</b><button class=\"copy\" onclick=\"copyFix(this)\">Copy</button><pre>" << H(info->fix) << L"</pre></div>";
                html << L"<details><summary>How to undo the fix</summary><pre>" << H(info->undo) << L"</pre></details>";
            }
            html << L"<div class=\"chips\">";
            for (const std::wstring& t : info->attack) {
                html << L"<span class=\"chip\" title=\"" << H(AttackTechniqueName(t)) << L"\">ATT&amp;CK " << H(t) << L"</span>";
            }
            for (const std::wstring& c : info->cisControls) html << L"<span class=\"chip\">CIS " << H(c) << L"</span>";
            html << L"<span class=\"chip\">" << H(r.id) << L"</span></div></article>\n";
        }
    }
}

static int RowPriority(const ScanRow& r)
{
    if (r.status == L"NEW" || r.status == L"CHANGED") return 0;
    if (r.status == L"MISSING") return 1;
    if (r.entry.malwareScore >= 7.0) return 2;
    if (r.entry.malwareScore >= 4.0) return 3;
    return 4;
}

static void WriteScan(std::wstringstream& html, const ReportData& d)
{
    const ScanSummary& s = d.scan;
    std::wstring modeName = d.scanModeName.empty() ? ScanModeName(s.mode) : d.scanModeName;
    html << L"<h2>" << H(d.scanTitle.empty() ? modeName : d.scanTitle) << L"</h2>\n";
    html << L"<p class=\"meta\">" << s.executables << L" executable files analysed out of " << s.filesProcessed
         << L" files" << (s.root.empty() ? L"" : L" under " + H(s.root)) << L", in " << FormatFixed(s.seconds, 0) << L" seconds"
         << (s.cancelled ? L". The scan was cancelled; results are partial." : L".") << L"</p>\n";
    html << L"<div class=\"tiles\">"
         << L"<div class=\"tile\"><b class=\"fail\">" << s.added << L"</b><span>New</span></div>"
         << L"<div class=\"tile\"><b class=\"warn\">" << s.changed << L"</b><span>Changed</span></div>"
         << L"<div class=\"tile\"><b class=\"warn\">" << s.missing << L"</b><span>Missing</span></div>"
         << L"<div class=\"tile\"><b class=\"pass\">" << s.match << L"</b><span>Unchanged</span></div>"
         << L"<div class=\"tile\"><b class=\"info\">" << s.updated + s.known << L"</b><span>Updated or known</span></div>"
         << L"<div class=\"tile\"><b class=\"fail\">" << s.highRisk << L"</b><span>Score 7 or more</span></div></div>\n";

    std::vector<ScanRow> rows = d.rows;
    std::stable_sort(rows.begin(), rows.end(), [](const ScanRow& a, const ScanRow& b) {
        int pa = RowPriority(a), pb = RowPriority(b);
        if (pa != pb) return pa < pb;
        return a.entry.malwareScore > b.entry.malwareScore;
    });
    const size_t limit = 3000;
    bool truncated = rows.size() > limit;
    if (truncated) rows.resize(limit);

    html << L"<div class=\"bar\"><select id=\"st\" onchange=\"filterRows()\"><option value=\"all\">All rows</option>"
         << L"<option value=\"review\" selected>Needs review</option><option value=\"NEW\">New</option><option value=\"CHANGED\">Changed</option>"
         << L"<option value=\"MISSING\">Missing</option><option value=\"MATCH\">Unchanged</option></select>"
         << L"<input id=\"q\" placeholder=\"Search path, signer, hash\" oninput=\"filterRows()\" size=\"32\"></div>\n";
    if (truncated) html << L"<p class=\"meta\">Showing the " << limit << L" most important of " << d.rows.size() << L" rows. The CSV and JSON have all of them.</p>\n";

    html << L"<table id=\"rows\"><thead><tr><th onclick=\"sortRows(0,0)\">Status</th><th onclick=\"sortRows(1,1)\">Score</th>"
         << L"<th onclick=\"sortRows(2,0)\">File</th><th onclick=\"sortRows(3,0)\">Signature</th><th onclick=\"sortRows(4,0)\">What changed / indicators</th>"
         << L"<th onclick=\"sortRows(5,0)\">ATT&amp;CK</th></tr></thead><tbody>\n";
    for (const ScanRow& r : rows) {
        const BaselineEntry& e = r.entry;
        bool review = r.status == L"NEW" || r.status == L"CHANGED" || r.status == L"MISSING" || e.malwareScore >= 7.0;
        std::wstring cls = e.malwareScore >= 7.0 ? L"hi" : (e.malwareScore >= 4.0 ? L"mid" : L"");
        std::vector<std::wstring> notes;
        if (!r.changeDetails.empty() && r.changeDetails != L"No changes") notes.push_back(r.changeDetails);
        for (const std::wstring* list : { &e.sigWarnings, &e.peAnomalies, &e.originWarnings, &e.scriptIndicators }) {
            for (const std::wstring& item : SplitW(*list, L';')) {
                std::wstring code = IndicatorCode(item);
                if (code != L"CATALOG_SIGNED" && code != L"DOTNET" && code != L"REPRODUCIBLE_BUILD") notes.push_back(item);
            }
        }
        if (e.packingStatus.rfind(L"PACKED", 0) == 0) notes.push_back(e.packingStatus);
        html << L"<tr class=\"" << cls << L"\" data-status=\"" << H(r.status) << L"\" data-review=\"" << (review ? L"1" : L"0") << L"\""
             << (review ? L"" : L" style=\"display:none\"") << L">"
             << L"<td>" << H(r.status) << L"</td><td data-v=\"" << FormatFixed(e.malwareScore, 2) << L"\">" << FormatFixed(e.malwareScore, 1) << L"</td>"
             << L"<td class=\"path\">" << H(e.path) << L"</td><td>" << H(e.signature) << L"</td>"
             << L"<td>" << H(JoinW(notes, L"; ")) << L"</td><td>" << H(e.attackIds) << L"</td></tr>\n";
    }
    html << L"</tbody></table>\n";
}

static void WriteTechniques(std::wstringstream& html, const ReportData& d)
{
    std::vector<TechniqueCount> techniques = CollectTechniques(d);
    if (techniques.empty()) return;
    html << L"<h2>MITRE ATT&amp;CK techniques these findings relate to</h2>\n"
         << L"<p class=\"meta\">A technique here means a finding makes it easier, or a file shows a trait often seen with it. "
         << L"It is not proof that anything used it.</p>\n"
         << L"<table><thead><tr><th>Technique</th><th>Name</th><th>Count</th><th>From</th></tr></thead><tbody>\n";
    for (const TechniqueCount& t : techniques) {
        html << L"<tr><td>" << H(t.id) << L"</td><td>" << H(AttackTechniqueName(t.id)) << L"</td><td>" << t.count
             << L"</td><td>" << H(t.comment) << L"</td></tr>\n";
    }
    html << L"</tbody></table>\n";
}

std::wstring BuildHtmlReport(const ReportData& input)
{
    ReportData d = input.redacted ? RedactReport(input) : input;
    std::wstringstream html;
    html << L"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
         << L"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
         << L"<title>Phantom Recon report</title><style>" << kCss << L"</style></head><body><main>\n";
    html << L"<h1>Phantom Recon report</h1>\n<div class=\"meta\">" << H(d.hostName) << L" &middot; " << H(d.osText)
         << L" &middot; " << H(d.generatedAt) << L" &middot; " << PHANTOMRECON_NAME_W << L" " << PHANTOMRECON_VERSION_W;
    if (d.redacted) html << L" &middot; user, computer and domain names are hidden";
    html << L"</div>\n";

    if (d.hasAudit) WriteFindings(html, d);
    if (d.hasScan) WriteScan(html, d);
    WriteTechniques(html, d);

    html << L"<footer>Made by Phantom Recon, a free defensive auditing tool. Commands in this report change system settings: "
         << L"read them before you run them, and keep the undo step. Nothing in this report was sent anywhere.</footer>\n";
    html << L"</main><script>" << kScript << L"</script></body></html>\n";
    return html.str();
}
