#include "pch.h"
#include "CliRunner.h"

#include "AppPaths.h"
#include "Baseline.h"
#include "CheckCatalog.h"
#include "FileIO.h"
#include "HardeningScore.h"
#include "KnownGood.h"
#include "Reports.h"
#include "SampleData.h"
#include "ScanCsv.h"
#include "ScheduledScan.h"
#include "SecurityChecks.h"
#include "TextUtils.h"
#include "Version.h"

#include <sstream>

std::wstring CliUsageText()
{
    return
        L"Phantom Recon " PHANTOMRECON_VERSION_W L" - defensive Windows auditing from the command line\n"
        L"\n"
        L"Usage: PhantomReconCli.exe [what to do] [where to write] [options]\n"
        L"\n"
        L"What to do (one or more):\n"
        L"  --audit                     Check this PC's security settings\n"
        L"  --baseline-scan <folder>    Record every program under <folder> as the known-good baseline\n"
        L"  --full <folder>             Compare everything under <folder> with the baseline\n"
        L"  --fast                      Compare installed programs with the baseline\n"
        L"  --diff <older> <newer>      Compare two baseline files\n"
        L"  --make-samples <folder>     Write the harmless demo files and a demo baseline\n"
        L"  --findings-md <file>        Write the list of every check (docs/FINDINGS.md)\n"
        L"  --schedule-weekly           Run --fast every Sunday as you (creates one scheduled task)\n"
        L"  --unschedule-weekly         Remove that scheduled task\n"
        L"\n"
        L"Where to write:\n"
        L"  --baseline <file>           Baseline to write or compare against (default: next to the program)\n"
        L"  --report <file.html>        HTML report\n"
        L"  --json <file.json>          JSON report (schema phantomrecon.report/1)\n"
        L"  --navigator <file.json>     MITRE ATT&CK Navigator layer\n"
        L"  --csv <file.csv>            Scan rows as CSV\n"
        L"  --text <file.txt>           Plain-text audit report\n"
        L"\n"
        L"Options:\n"
        L"  --exclude \"a;b;*.log\"       Skip folders, paths or extensions\n"
        L"  --known-good <file>         SHA-256 list of files you trust\n"
        L"  --revocation off|cache|online   Certificate revocation checks (default cache: no network)\n"
        L"  --no-fuzzy                  Skip fuzzy hashing (faster)\n"
        L"  --redact                    Hide user, computer and domain names in reports\n"
        L"  --notify                    Show a desktop notification when done\n"
        L"  --quiet                     Print only errors\n"
        L"  --portable                  Keep everything next to the program; never schedule tasks\n"
        L"  --version, --help\n"
        L"\n"
        L"Exit code: 0 nothing needs attention, 1 something needs attention, 2 error.\n";
}

CliOptions ParseCliArguments(const std::vector<std::wstring>& args)
{
    CliOptions o;
    auto need = [&](size_t& i, std::wstring& target, const wchar_t* flag) {
        if (i + 1 >= args.size()) {
            o.error = std::wstring(flag) + L" needs a value";
            return;
        }
        target = args[++i];
    };
    for (size_t i = 0; i < args.size() && o.error.empty(); ++i) {
        std::wstring a = ToLowerW(args[i]);
        if (a == L"--help" || a == L"-h" || a == L"/?") o.help = true;
        else if (a == L"--version") o.version = true;
        else if (a == L"--audit") o.audit = true;
        else if (a == L"--baseline-scan") need(i, o.baselineScanRoot, L"--baseline-scan");
        else if (a == L"--full") need(i, o.fullScanRoot, L"--full");
        else if (a == L"--fast") o.fastScan = true;
        else if (a == L"--diff") {
            need(i, o.diffOlder, L"--diff");
            if (o.error.empty()) need(i, o.diffNewer, L"--diff");
        }
        else if (a == L"--baseline") need(i, o.baselinePath, L"--baseline");
        else if (a == L"--csv") need(i, o.csvPath, L"--csv");
        else if (a == L"--report") need(i, o.htmlPath, L"--report");
        else if (a == L"--json") need(i, o.jsonPath, L"--json");
        else if (a == L"--navigator") need(i, o.navigatorPath, L"--navigator");
        else if (a == L"--text") need(i, o.textReportPath, L"--text");
        else if (a == L"--findings-md") need(i, o.findingsMdPath, L"--findings-md");
        else if (a == L"--make-samples") need(i, o.samplesDir, L"--make-samples");
        else if (a == L"--exclude") need(i, o.exclusions, L"--exclude");
        else if (a == L"--known-good") need(i, o.knownGoodPath, L"--known-good");
        else if (a == L"--revocation") {
            need(i, o.revocation, L"--revocation");
            std::wstring r = ToLowerW(o.revocation);
            if (o.error.empty() && r != L"off" && r != L"cache" && r != L"online") o.error = L"--revocation must be off, cache or online";
        }
        else if (a == L"--no-fuzzy") o.noFuzzy = true;
        else if (a == L"--redact") o.redact = true;
        else if (a == L"--notify") o.notify = true;
        else if (a == L"--quiet") o.quiet = true;
        else if (a == L"--portable") { /* read by IsPortableMode() */ }
        else if (a == L"--schedule-weekly") o.scheduleWeekly = true;
        else if (a == L"--unschedule-weekly") o.unscheduleWeekly = true;
        else o.error = L"Unknown option: " + args[i];
    }
    int scans = (!o.baselineScanRoot.empty() ? 1 : 0) + (!o.fullScanRoot.empty() ? 1 : 0) + (o.fastScan ? 1 : 0) + (!o.diffOlder.empty() ? 1 : 0);
    if (o.error.empty() && scans > 1) o.error = L"Pick one of --baseline-scan, --full, --fast or --diff per run";
    bool anything = o.help || o.version || o.audit || scans > 0 || !o.samplesDir.empty() || !o.findingsMdPath.empty() ||
                    o.scheduleWeekly || o.unscheduleWeekly;
    if (o.error.empty() && !anything) o.help = true;
    return o;
}

static void Say(const CliEnvironment& env, const CliOptions& o, const std::wstring& text)
{
    if (!o.quiet && env.out) env.out(text);
}

static void Error(const CliEnvironment& env, const std::wstring& text)
{
    if (env.out) env.out(L"Error: " + text + L"\n");
}

int RunCli(const CliOptions& o, const CliEnvironment& env)
{
    if (!o.error.empty()) {
        Error(env, o.error);
        if (env.out) env.out(L"Run with --help for the list of options.\n");
        return 2;
    }
    if (o.help) {
        if (env.out) env.out(CliUsageText());
        return 0;
    }
    if (o.version) {
        if (env.out) env.out(std::wstring(PHANTOMRECON_NAME_W) + L" " + PHANTOMRECON_VERSION_W + L"\n");
        return 0;
    }

    int exitCode = 0;
    std::wstring baselinePath = o.baselinePath.empty() ? env.defaultBaselinePath : AbsolutePath(o.baselinePath);
    if (!o.knownGoodPath.empty()) LoadKnownGoodList(o.knownGoodPath);

    if (!o.findingsMdPath.empty()) {
        if (WriteUtf8File(o.findingsMdPath, ReplaceAllW(BuildFindingsMarkdown(), L"\n", L"\r\n"))) {
            Say(env, o, L"Wrote " + o.findingsMdPath + L"\n");
        }
        else {
            Error(env, L"could not write " + o.findingsMdPath);
            return 2;
        }
    }

    if (!o.samplesDir.empty()) {
        SamplePackResult pack = CreateSamplePack(o.samplesDir);
        if (!pack.ok) {
            Error(env, pack.error);
            return 2;
        }
        Say(env, o, L"Sample pack written to " + pack.folder + L" (" + std::to_wstring(pack.files.size()) + L" files).\n"
                    L"Demo baseline: " + pack.baselinePath + L"\nRead README_SAMPLES.txt in that folder for what to try.\n");
    }

    if (o.unscheduleWeekly) {
        std::wstring error;
        if (!RemoveWeeklyScan(error)) {
            Error(env, error);
            return 2;
        }
        Say(env, o, L"Weekly scan removed.\n");
    }
    if (o.scheduleWeekly) {
        std::wstring error;
        std::wstring reports = env.defaultReportsDir;
        EnsureDirectory(reports);
        if (!RegisterWeeklyScan(env.exePathForSchedule, baselinePath, reports, error)) {
            Error(env, error);
            return 2;
        }
        Say(env, o, L"Weekly Fast Scan scheduled for Sundays at 10:00. Reports go to " + reports + L"\n");
    }

    ReportData report;
    FillReportHost(report, o.redact);

    if (o.audit) {
        Say(env, o, L"Running the security audit...\n");
        AuditContext context;
        context.baselinePath = FileExists(baselinePath) ? baselinePath : L"";
        context.onProgress = [&](int done, int total, const std::wstring& title) {
            if (title != L"Done") Say(env, o, L"  [" + std::to_wstring(done + 1) + L"/" + std::to_wstring(total) + L"] " + title + L"\n");
        };
        report.audit = RunAllSecurityChecks(context);
        report.score = ComputeHardeningScore(report.audit);
        report.hasAudit = true;
        Say(env, o, L"\n" + GetSecuritySummary(report.audit) + L"\n\n");
        if (report.score.fail > 0) exitCode = 1;
        if (!o.textReportPath.empty() && !WriteSecurityReport(o.textReportPath, report.audit)) {
            Error(env, L"could not write " + o.textReportPath);
            exitCode = 2;
        }
    }

    ScanOptions scanOptions;
    ParseExclusions(o.exclusions, scanOptions);
    std::wstring rev = ToLowerW(o.revocation);
    scanOptions.revocation = rev == L"off" ? RevocationMode::Off : (rev == L"online" ? RevocationMode::Online : RevocationMode::CacheOnly);
    scanOptions.computeFuzzyHash = !o.noFuzzy;

    ScanCallbacks callbacks;
    int lastPercent = -1;
    int total = 0;
    int counter = 0;
    callbacks.onTotal = [&](int t) { total = t; counter = 0; lastPercent = -1; };
    callbacks.onPhase = [&](const std::wstring& phase) { Say(env, o, phase + L"\n"); };
    callbacks.onFile = [&](const std::wstring&, const std::wstring&, bool) {
        if (total <= 0) return;
        int percent = static_cast<int>(100.0 * (++counter) / total);
        if (percent / 10 != lastPercent / 10) {
            lastPercent = percent;
            Say(env, o, L"  " + std::to_wstring((std::min)(percent, 100)) + L"%\n");
        }
    };
    callbacks.onRow = [&](const ScanRow& row) { report.rows.push_back(row); };

    auto finishScan = [&](const ScanSummary& summary, const std::wstring& title) {
        report.hasScan = true;
        report.scan = summary;
        report.scanTitle = title;
        Say(env, o, summary.finalState + L" " + std::to_wstring(summary.executables) + L" programs analysed in " +
                    FormatFixed(summary.seconds, 0) + L" s.\n");
        if (summary.mode != ScanMode::Baseline) {
            Say(env, o, L"  New " + std::to_wstring(summary.added) + L", changed " + std::to_wstring(summary.changed) +
                        L", missing " + std::to_wstring(summary.missing) + L", unchanged " + std::to_wstring(summary.match) +
                        L", updated or known " + std::to_wstring(summary.updated + summary.known) + L"\n");
            if (summary.added + summary.changed + summary.missing > 0) exitCode = (std::max)(exitCode, 1);
        }
        if (summary.highRisk > 0) {
            Say(env, o, L"  " + std::to_wstring(summary.highRisk) + L" file(s) scored 7 or more.\n");
            exitCode = (std::max)(exitCode, 1);
        }
        if (summary.csvFailed) {
            Error(env, L"could not write " + o.csvPath);
            exitCode = 2;
        }
    };

    if (!o.baselineScanRoot.empty()) {
        std::wstring root = AbsolutePath(o.baselineScanRoot);
        if (!DirectoryExists(root)) {
            Error(env, L"folder not found: " + root);
            return 2;
        }
        ScanSummary s = RunScan(ScanMode::Baseline, root, o.csvPath, nullptr, baselinePath, scanOptions, callbacks);
        finishScan(s, L"Baseline of " + root);
        if (s.baselineSaved) Say(env, o, L"Baseline saved: " + baselinePath + L" (" + std::to_wstring(s.baselineEntries) + L" files)\n");
        else {
            Error(env, L"the baseline was not saved");
            exitCode = 2;
        }
    }
    else if (!o.fullScanRoot.empty() || o.fastScan) {
        Baseline baseline;
        if (!baseline.LoadFromFile(baselinePath)) {
            Error(env, L"no usable baseline at " + baselinePath + L". Take one with --baseline-scan first.");
            return 2;
        }
        Say(env, o, L"Baseline: " + baselinePath + L", " + std::to_wstring(baseline.Count()) + L" files, " +
                    std::to_wstring((std::max)(0, baseline.GetAgeDays())) + L" days old\n");
        if (o.fastScan) {
            ScanSummary s = RunScan(ScanMode::FastScan, L"", o.csvPath, &baseline, L"", scanOptions, callbacks);
            finishScan(s, L"Fast Scan of installed programs");
        }
        else {
            std::wstring root = AbsolutePath(o.fullScanRoot);
            if (!DirectoryExists(root)) {
                Error(env, L"folder not found: " + root);
                return 2;
            }
            ScanSummary s = RunScan(ScanMode::FullScan, root, o.csvPath, &baseline, L"", scanOptions, callbacks);
            finishScan(s, L"Full Scan of " + root);
        }
    }
    else if (!o.diffOlder.empty()) {
        Baseline older, newer;
        if (!older.LoadFromFile(o.diffOlder) || !newer.LoadFromFile(o.diffNewer)) {
            Error(env, L"could not read both baseline files");
            return 2;
        }
        report.rows = DiffBaselines(older, newer, false);
        ScanSummary s;
        s.mode = ScanMode::FullScan;
        for (const ScanRow& r : report.rows) {
            if (r.status == L"NEW") s.added++;
            else if (r.status == L"CHANGED") s.changed++;
            else if (r.status == L"MISSING") s.missing++;
            else if (r.status == L"UPDATED") s.updated++;
            else if (r.status == L"KNOWN") s.known++;
        }
        s.match = static_cast<int>(newer.Count()) - s.added - s.changed - s.updated - s.known;
        s.finalState = L"Baseline comparison";
        if (!o.csvPath.empty() && !ExportRowsToCsv(o.csvPath, report.rows)) s.csvFailed = true;
        finishScan(s, L"Baseline comparison: " + FileNameOf(o.diffOlder) + L" vs " + FileNameOf(o.diffNewer));
    }

    if (report.hasAudit || report.hasScan) {
        auto save = [&](const std::wstring& path, const std::wstring& text, const wchar_t* what) {
            if (path.empty()) return;
            if (SaveReportFile(path, text)) Say(env, o, std::wstring(what) + L": " + AbsolutePath(path) + L"\n");
            else {
                Error(env, L"could not write " + path);
                exitCode = 2;
            }
        };
        save(o.htmlPath, BuildHtmlReport(report), L"HTML report");
        save(o.jsonPath, BuildJsonReport(report), L"JSON report");
        save(o.navigatorPath, BuildNavigatorReport(report), L"ATT&CK Navigator layer");
    }

    if (o.notify && env.notify) {
        std::wstring text;
        if (report.hasScan) {
            text = std::to_wstring(report.scan.added) + L" new, " + std::to_wstring(report.scan.changed) + L" changed, " +
                   std::to_wstring(report.scan.missing) + L" missing.";
        }
        if (report.hasAudit) text += (text.empty() ? L"" : L" ") + std::wstring(L"Hardening score ") + std::to_wstring(report.score.score) + L"/100.";
        env.notify(exitCode == 0 ? L"Phantom Recon: all clear" : L"Phantom Recon: please review", text);
    }
    return exitCode;
}
