#include "pch.h"
#include "CliRunner.h"

#include "AppPaths.h"
#include "AuditHistory.h"
#include "Baseline.h"
#include "CheckCatalog.h"
#include "FileIO.h"
#include "FixScript.h"
#include "FixScriptBackup.h"
#include "HardeningScore.h"
#include "KnownGood.h"
#include "Redactor.h"
#include "Reports.h"
#include "SampleData.h"
#include "ScanCsv.h"
#include "ScheduledScan.h"
#include "SecurityChecks.h"
#include "TextUtils.h"
#include "Version.h"

#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[CliRunner] " + msg + L"\n").c_str());
}

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
        L"                              (several folders: \"C:\\Program Files;D:\\Tools\")\n"
        L"  --fast                      Compare installed programs with the baseline\n"
        L"  --diff <older> <newer>      Compare two baseline files\n"
        L"  --make-samples <folder>     Write the harmless demo files and a demo baseline\n"
        L"  --findings-md <file>        Write the list of every check (docs/FINDINGS.md)\n"
        L"  --schedule-weekly           Run --fast every Sunday as you (creates one scheduled task;\n"
        L"                              needs a baseline, so take one first)\n"
        L"  --unschedule-weekly         Remove that scheduled task\n"
        L"  --history                   Show the last 20 audits on this PC: date, score, pass, warn, fail\n"
        L"\n"
        L"Where to write:\n"
        L"  --baseline <file>           Baseline to write or compare against (default: next to the program)\n"
        L"  --report <file.html>        HTML report (needs --audit or a scan)\n"
        L"  --json <file.json>          JSON report, schema phantomrecon.report/1 (needs --audit or a scan)\n"
        L"  --navigator <file.json>     MITRE ATT&CK Navigator layer (needs --audit or a scan)\n"
        L"  --csv <file.csv>            Scan rows as CSV (needs a scan)\n"
        L"  --text <file.txt>           Plain-text audit report (needs --audit)\n"
        L"  --fix-script <file.ps1>     Fix plan: a PowerShell script you read and run yourself, one\n"
        L"                              confirmed step at a time, plus <file>-undo.ps1 to reverse it\n"
        L"                              (needs --audit; nothing is run, both files are replaced)\n"
        L"\n"
        L"Options:\n"
        L"  --exclude \"a;b;*.log\"       Skip folders, paths or extensions\n"
        L"  --known-good <file>         SHA-256 list of files you trust\n"
        L"  --revocation off|cache|online   Certificate revocation checks (default cache: no network)\n"
        L"  --no-fuzzy                  Skip fuzzy hashing (faster)\n"
        L"  --redact                    Hide user, computer and domain names in every file written\n"
        L"                              (HTML, JSON, Navigator, CSV and text)\n"
        L"  --notify                    Show a desktop notification when done, also when the run fails\n"
        L"  --quiet                     Print only errors\n"
        L"  --no-history                Do not read or write the audit history (phantom_recon_history.jsonl);\n"
        L"                              without it, --audit records its result and says what changed\n"
        L"                              since the last audit\n"
        L"  --portable                  Keep everything next to the program; never schedule tasks\n"
        L"  --version, --help\n"
        L"\n"
        L"Exit code: 0 nothing needs attention, 1 something needs attention, 2 error.\n";
}

// True when an argument is an option rather than a value: "--anything", "-h" or "/?".
static bool LooksLikeOption(const std::wstring& arg)
{
    return (arg.size() >= 2 && arg[0] == L'-' && arg[1] == L'-') || arg == L"-h" || arg == L"/?";
}

CliOptions ParseCliArguments(const std::vector<std::wstring>& args)
{
    CliOptions o;
    // An option's value is the next argument, unless that is empty or is itself an
    // option: "--findings-md --audit" must not write a file called "--audit".
    auto need = [&](size_t& i, std::wstring& target, const wchar_t* flag) {
        if (i + 1 >= args.size()) {
            o.error = std::wstring(flag) + L" needs a value";
            return;
        }
        const std::wstring& value = args[i + 1];
        if (TrimW(value).empty()) {
            o.error = std::wstring(flag) + L" needs a value (it was empty)";
            return;
        }
        if (LooksLikeOption(value)) {
            o.error = std::wstring(flag) + L" needs a value, but the next argument is the option " + value;
            return;
        }
        target = value;
        ++i;
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
        else if (a == L"--fix-script") need(i, o.fixScriptPath, L"--fix-script");
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
        else if (a == L"--history") o.showHistory = true;
        else if (a == L"--no-history") o.noHistory = true;
        else o.error = L"Unknown option: " + args[i];
    }
    if (o.error.empty() && o.showHistory && o.noHistory) o.error = L"--history shows the audit history; it cannot be used with --no-history";
    int scans = (!o.baselineScanRoot.empty() ? 1 : 0) + (!o.fullScanRoot.empty() ? 1 : 0) + (o.fastScan ? 1 : 0) + (!o.diffOlder.empty() ? 1 : 0);
    if (o.error.empty() && scans > 1) o.error = L"Pick one of --baseline-scan, --full, --fast or --diff per run";
    if (!o.error.empty() || o.help || o.version) return o;

    bool action = o.audit || scans > 0 || !o.samplesDir.empty() || !o.findingsMdPath.empty() ||
                  o.scheduleWeekly || o.unscheduleWeekly || o.showHistory;
    if (!action) {
        // Only a bare run shows the help. Options with nothing to do are a mistake the
        // caller (often a script or a scheduled task) must hear about.
        if (args.empty()) o.help = true;
        else o.error = L"Nothing to do. Add --audit, --baseline-scan, --full, --fast, --diff, --make-samples, "
                       L"--findings-md, --history or --schedule-weekly.";
        return o;
    }
    bool reports = !o.htmlPath.empty() || !o.jsonPath.empty() || !o.navigatorPath.empty();
    if (!o.textReportPath.empty() && !o.audit) o.error = L"--text writes the audit report; add --audit";
    else if (!o.fixScriptPath.empty() && !o.audit) o.error = L"--fix-script writes a fix plan from the audit; add --audit";
    else if (!o.fixScriptPath.empty() && !HasPs1Extension(o.fixScriptPath))
        o.error = L"--fix-script needs a file name ending in .ps1 (PowerShell runs no other)";
    else if (!o.csvPath.empty() && scans == 0) o.error = L"--csv writes scan rows; add --baseline-scan, --full, --fast or --diff";
    else if (reports && !o.audit && scans == 0) o.error = L"--report, --json and --navigator need --audit or a scan";
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

// After --audit: record the result in the history and fill the report's history
// part. Returns the paragraph for the console and the text report, "" when history
// is off (--no-history or no file location) or the file could not be read.
static std::wstring RecordCliAuditHistory(const CliOptions& o, const CliEnvironment& env, ReportData& report)
{
    if (o.noHistory || env.historyPath.empty()) {
        DebugLog(L"Audit history off: nothing read or written");
        return L"";
    }
    AuditHistoryUpdate update = RecordAuditInHistory(env.historyPath, MakeAuditRecord(report.audit, report.score, NowUtcIso()));
    if (!update.error.empty()) Say(env, o, L"Note: " + update.error + L"\n");
    if (update.skippedLines > 0) {
        Say(env, o, L"Note: " + std::to_wstring(update.skippedLines) + L" damaged line(s) in the audit history were skipped.\n");
    }
    if (!update.loaded) return L"";
    report.hasHistory = true;
    report.history = update.comparison;
    report.historyRecords = update.recent;
    DebugLog(L"Audit history: " + HistoryScoreLine(update.comparison));
    return BuildHistoryParagraph(update.comparison);
}

// --history: the last records as a table. Printed even with --quiet (it is what was
// asked for). False when the file exists but cannot be read.
static bool PrintCliHistory(const CliEnvironment& env)
{
    if (env.historyPath.empty()) {
        if (env.out) env.out(L"No audit history is kept for this run.\n");
        return true;
    }
    std::vector<AuditRecord> records;
    int skipped = 0;
    if (!LoadAuditHistory(env.historyPath, records, &skipped)) return false;
    if (env.out) {
        env.out(BuildHistoryTable(records));
        if (skipped > 0) env.out(std::to_wstring(skipped) + L" damaged line(s) in the file were skipped.\n");
        env.out(L"File: " + env.historyPath + L"\n");
    }
    DebugLog(L"--history printed " + std::to_wstring(records.size()) + L" records");
    return true;
}

int RunCli(const CliOptions& o, const CliEnvironment& env)
{
    if (!o.error.empty()) {
        Error(env, o.error);
        if (env.out) env.out(L"Run with --help for the list of options.\n");
        if (o.notify && env.notify) env.notify(L"Phantom Recon: the run failed", o.error);
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
    std::wstring firstError;
    ReportData report;
    FillReportHost(report, o.redact);

    // Every error from here on goes through fail(), and every way out through finish(),
    // so --notify is shown for a failed run too (a weekly task has no other voice).
    auto fail = [&](const std::wstring& text) {
        Error(env, text);
        if (firstError.empty()) firstError = text;
        exitCode = 2;
    };
    auto finish = [&]() -> int {
        if (o.notify && env.notify) {
            std::wstring text;
            if (report.hasScan) {
                text = std::to_wstring(report.scan.added) + L" new, " + std::to_wstring(report.scan.changed) + L" changed, " +
                       std::to_wstring(report.scan.missing) + L" missing.";
            }
            if (report.hasAudit) text += (text.empty() ? L"" : L" ") + std::wstring(L"Hardening score ") + std::to_wstring(report.score.score) + L"/100.";
            if (!firstError.empty()) text = L"Error: " + firstError + (text.empty() ? L"" : L" " + text);
            std::wstring title = exitCode == 2 ? L"Phantom Recon: the run failed"
                               : exitCode == 1 ? L"Phantom Recon: please review" : L"Phantom Recon: all clear";
            env.notify(title, o.redact ? RedactText(text) : text);
        }
        DebugLog(L"RunCli finished with exit code " + std::to_wstring(exitCode));
        return exitCode;
    };

    std::wstring baselinePath = o.baselinePath.empty() ? env.defaultBaselinePath : AbsolutePath(o.baselinePath);
    if (!o.knownGoodPath.empty()) LoadKnownGoodList(o.knownGoodPath);

    if (!o.findingsMdPath.empty()) {
        if (WriteUtf8File(o.findingsMdPath, ReplaceAllW(BuildFindingsMarkdown(), L"\n", L"\r\n"))) {
            Say(env, o, L"Wrote " + o.findingsMdPath + L"\n");
        }
        else {
            fail(L"could not write " + o.findingsMdPath);
            return finish();
        }
    }

    if (!o.samplesDir.empty()) {
        SamplePackResult pack = CreateSamplePack(o.samplesDir);
        if (!pack.ok) {
            fail(pack.error);
            return finish();
        }
        Say(env, o, L"Sample pack written to " + pack.folder + L" (" + std::to_wstring(pack.files.size()) + L" files).\n"
                    L"Demo baseline: " + pack.baselinePath + L"\nRead README_SAMPLES.txt in that folder for what to try.\n");
    }

    if (o.unscheduleWeekly) {
        std::wstring error;
        if (!RemoveWeeklyScan(error)) {
            fail(error);
            return finish();
        }
        Say(env, o, L"Weekly scan removed.\n");
    }

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
        std::wstring historyParagraph = RecordCliAuditHistory(o, env, report);
        if (!historyParagraph.empty()) Say(env, o, historyParagraph + L"\n\n");
        if (!o.textReportPath.empty() &&
            !WriteSecurityReport(o.textReportPath, o.redact ? RedactAuditResults(report.audit) : report.audit, historyParagraph)) {
            fail(L"could not write " + o.textReportPath);
        }
        if (!o.fixScriptPath.empty()) {
            // Written, never run. With --redact the evidence-dependent steps are manual.
            FixScriptOptions fixOptions;
            fixOptions.generatedAt = report.generatedAt;
            fixOptions.redacted = o.redact;
            std::wstring fixPath = AbsolutePath(o.fixScriptPath);
            std::wstring undoPath, error;
            if (SaveFixScripts(fixPath, o.redact ? RedactAuditResults(report.audit) : report.audit, fixOptions, undoPath, error)) {
                Say(env, o, L"Fix script: " + fixPath + L"\nUndo script: " + undoPath +
                            L"\nBackup file (the fix script writes it before a registry step it applies): " +
                            BackupPathFor(fixPath) +
                            L"\nRead every step before you run it. Phantom Recon does not run either script.\n");
            }
            else {
                fail(error);
            }
        }
    }

    if (o.showHistory && !PrintCliHistory(env)) {
        fail(L"could not read the audit history at " + env.historyPath);
    }

    ScanOptions scanOptions;
    ParseExclusions(o.exclusions, scanOptions);
    std::wstring rev = ToLowerW(o.revocation);
    scanOptions.revocation = rev == L"off" ? RevocationMode::Off : (rev == L"online" ? RevocationMode::Online : RevocationMode::CacheOnly);
    scanOptions.computeFuzzyHash = !o.noFuzzy;
    scanOptions.redactCsv = o.redact;

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
        if (summary.csvFailed) fail(L"could not write " + o.csvPath);
    };

    // "--full C:\A;D:\B" scans both folders in one run.
    auto resolveRoots = [&](const std::wstring& text, std::vector<std::wstring>& roots) -> bool {
        roots.clear();
        for (const std::wstring& r : SplitScanRoots(text)) {
            std::wstring full = AbsolutePath(r);
            if (!DirectoryExists(full)) {
                fail(L"folder not found: " + full);
                return false;
            }
            roots.push_back(full);
        }
        if (roots.empty()) {
            fail(L"no folder given");
            return false;
        }
        return true;
    };

    // A failed scan step records the error and returns; the audit above still gets
    // its reports written below.
    auto runScanStep = [&]() {
        if (!o.baselineScanRoot.empty()) {
            std::vector<std::wstring> roots;
            if (!resolveRoots(o.baselineScanRoot, roots)) return;
            ScanSummary s = RunScan(ScanMode::Baseline, roots, o.csvPath, nullptr, baselinePath, scanOptions, callbacks);
            finishScan(s, L"Baseline of " + JoinW(roots, L"; "));
            if (s.baselineSaved) Say(env, o, L"Baseline saved: " + baselinePath + L" (" + std::to_wstring(s.baselineEntries) + L" files)\n");
            else fail(L"the baseline was not saved");
        }
        else if (!o.fullScanRoot.empty() || o.fastScan) {
            Baseline baseline;
            if (!baseline.LoadFromFile(baselinePath)) {
                fail(L"no usable baseline at " + baselinePath + L". Take one with --baseline-scan first.");
                return;
            }
            Say(env, o, L"Baseline: " + baselinePath + L", " + std::to_wstring(baseline.Count()) + L" files, " +
                        std::to_wstring((std::max)(0, baseline.GetAgeDays())) + L" days old\n");
            if (o.fastScan) {
                ScanSummary s = RunScan(ScanMode::FastScan, L"", o.csvPath, &baseline, L"", scanOptions, callbacks);
                finishScan(s, L"Fast Scan of installed programs");
            }
            else {
                std::vector<std::wstring> roots;
                if (!resolveRoots(o.fullScanRoot, roots)) return;
                ScanSummary s = RunScan(ScanMode::FullScan, roots, o.csvPath, &baseline, L"", scanOptions, callbacks);
                finishScan(s, L"Full Scan of " + JoinW(roots, L"; "));
            }
        }
        else if (!o.diffOlder.empty()) {
            ULONGLONG started = GetTickCount64();
            Baseline older, newer;
            if (!older.LoadFromFile(o.diffOlder) || !newer.LoadFromFile(o.diffNewer)) {
                fail(L"could not read both baseline files");
                return;
            }
            report.rows = DiffBaselines(older, newer, false);
            ScanSummary s;
            s.mode = ScanMode::FullScan;
            s.startedAt = report.generatedAt;
            s.baselinePath = AbsolutePath(o.diffNewer);
            for (const ScanRow& r : report.rows) {
                if (r.status == L"NEW") s.added++;
                else if (r.status == L"CHANGED") s.changed++;
                else if (r.status == L"MISSING") s.missing++;
                else if (r.status == L"UPDATED") s.updated++;
                else if (r.status == L"KNOWN") s.known++;
            }
            // The newer baseline is the "scan": every file in it was analysed, and a file
            // scoring 7 or more needs attention whether it changed or not, as in a scan.
            s.executables = static_cast<int>(newer.Count());
            s.filesProcessed = s.executables;
            s.totalFiles = s.executables;
            for (const BaselineEntry* e : newer.AllEntries()) {
                if (e->malwareScore >= 7.0) s.highRisk++;
            }
            s.match = static_cast<int>(newer.Count()) - s.added - s.changed - s.updated - s.known;
            s.finalState = L"Baseline comparison";
            if (!o.csvPath.empty() && !ExportRowsToCsv(o.csvPath, o.redact ? RedactRows(report.rows) : report.rows)) s.csvFailed = true;
            s.seconds = static_cast<double>(GetTickCount64() - started) / 1000.0;
            report.scanModeName = L"Baseline comparison";
            finishScan(s, L"Baseline comparison: " + FileNameOf(o.diffOlder) + L" vs " + FileNameOf(o.diffNewer));
        }
    };
    runScanStep();

    // After the scan, so "--baseline-scan <folder> --schedule-weekly" works in one run.
    // RegisterWeeklyScan refuses when the baseline is missing or unreadable.
    if (o.scheduleWeekly) {
        std::wstring error;
        std::wstring reports = env.defaultReportsDir;
        if (!RegisterWeeklyScan(env.exePathForSchedule, baselinePath, reports, error)) {
            fail(error + (FileExists(baselinePath) ? L"" : L" Use --baseline-scan <folder> to take one."));
        }
        else {
            EnsureDirectory(reports);
            Say(env, o, L"Weekly Fast Scan scheduled for Sundays at 10:00. Reports go to " + reports + L"\n");
        }
    }

    if (report.hasAudit || report.hasScan) {
        auto save = [&](const std::wstring& path, const std::wstring& text, const wchar_t* what) {
            if (path.empty()) return;
            if (SaveReportFile(path, text)) Say(env, o, std::wstring(what) + L": " + AbsolutePath(path) + L"\n");
            else fail(L"could not write " + path);
        };
        save(o.htmlPath, BuildHtmlReport(report), L"HTML report");
        save(o.jsonPath, BuildJsonReport(report), L"JSON report");
        save(o.navigatorPath, BuildNavigatorReport(report), L"ATT&CK Navigator layer");
    }

    return finish();
}
