#include "pch.h"
#include "FixScript.h"

#include "AppPaths.h"
#include "FileIO.h"
#include "StringConv.h"
#include "TextUtils.h"
#include "Version.h"

#include <windows.h>
#include <algorithm>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[FixScript] " + msg + L"\n").c_str());
}

// Evidence is for reading, not for the whole report: a manual step shows this much.
static const size_t kMaxEvidenceLines = 60;
static const size_t kMaxShownLineChars = 600;
static const size_t kMaxSafeValueChars = 2048;

// ---------------------------------------------------------------------------
// Quoting and value checks
// ---------------------------------------------------------------------------

// PowerShell's tokenizer ends a single-quoted string at any of these five characters,
// and reads two of them in a row as one.
static bool IsPowerShellQuoteChar(wchar_t c)
{
    return c == L'\'' || c == 0x2018 || c == 0x2019 || c == 0x201A || c == 0x201B;
}

std::wstring PowerShellQuote(const std::wstring& value)
{
    std::wstring out;
    out.reserve(value.size() + 8);
    out += L'\'';
    for (wchar_t c : value) {
        out += c;
        if (IsPowerShellQuoteChar(c)) out += c;
    }
    out += L'\'';
    return out;
}

// C0 and C1 controls, DEL, and the Unicode line and paragraph separators.
static bool IsControlOrBreak(wchar_t c)
{
    return c < 0x20 || c == 0x7F || (c >= 0x80 && c <= 0x9F) || c == 0x2028 || c == 0x2029;
}

bool IsScriptSafeValue(const std::wstring& value)
{
    if (value.empty() || value.size() > kMaxSafeValueChars) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        wchar_t c = value[i];
        if (IsControlOrBreak(c) || c == L'"') return false;
        if (IsHighSurrogate(c)) {
            if (i + 1 >= value.size() || !IsLowSurrogate(value[i + 1])) return false;
            ++i;
        }
        else if (IsLowSurrogate(c)) {
            return false;
        }
    }
    return true;
}

// Text that is only shown: control characters become '?', long lines are cut. The
// result still goes through PowerShellQuote, so nothing in it can run.
static std::wstring ShownText(const std::wstring& text)
{
    std::wstring out;
    out.reserve(text.size());
    for (wchar_t c : text) {
        if (c == L'\t') out += L"    ";
        else if (IsControlOrBreak(c)) out += L'?';
        else out += c;
    }
    if (out.size() > kMaxShownLineChars) out = out.substr(0, kMaxShownLineChars) + L" ...";
    return out;
}

// For the header comments: a line comment ends at a line break, so none may remain.
static std::wstring CommentText(const std::wstring& text)
{
    std::wstring out;
    for (wchar_t c : text) out += IsControlOrBreak(c) ? L'?' : c;
    return out;
}

// Split on line ends. keepEmpty keeps blank lines (prose); scripts drop them.
static std::vector<std::wstring> SplitLines(const std::wstring& text, bool keepEmpty)
{
    std::vector<std::wstring> lines;
    std::wstring current;
    auto flush = [&]() {
        while (!current.empty() && (current.back() == L'\r' || current.back() == L' ')) current.pop_back();
        if (keepEmpty || !TrimW(current).empty()) lines.push_back(current);
        current.clear();
    };
    for (wchar_t c : text) {
        if (c == L'\n') flush();
        else current += c;
    }
    if (!current.empty()) flush();
    return lines;
}

// The one-line why: the explanation's first sentence, and the second as well when the
// first is too short to say why ("SMB is Windows file sharing."). Cut at a word.
static std::wstring FirstSentence(const std::wstring& text)
{
    size_t end = text.find(L". ");
    if (end != std::wstring::npos && end < 60) {
        size_t second = text.find(L". ", end + 2);
        end = second;
    }
    std::wstring s = end == std::wstring::npos ? text : text.substr(0, end + 1);
    if (s.size() > 240) {
        size_t space = s.rfind(L' ', 236);
        s = s.substr(0, space == std::wstring::npos || space < 120 ? 236 : space) + L" ...";
    }
    return s;
}

static bool IsProblem(const SecurityCheckResult& r)
{
    return r.status == CHECK_FAIL || r.status == CHECK_WARNING;
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------
static std::vector<std::wstring> EvidenceLines(const std::wstring& detail)
{
    std::vector<std::wstring> all = SplitLines(detail, false);
    std::vector<std::wstring> out;
    for (size_t i = 0; i < all.size() && i < kMaxEvidenceLines; ++i) out.push_back(all[i]);
    if (all.size() > kMaxEvidenceLines) {
        out.push_back(L"... and " + std::to_wstring(all.size() - kMaxEvidenceLines) +
                      L" more line(s) in the audit report.");
    }
    return out;
}

static FixStep MakeStep(const CheckInfo& info, const SecurityCheckResult& result, bool undo, bool redacted)
{
    FixStep step;
    step.checkId = info.id;
    step.title = info.title;
    step.severity = SeverityName(info.severity);
    step.status = result.status;
    step.why = FirstSentence(info.explanation);
    step.note = undo ? info.undoScriptNote : info.fixScriptNote;
    step.needsRestart = info.scriptNeedsRestart;

    const std::wstring& script = undo ? info.undoScript : info.fixScript;
    std::wstring reason;
    if (!script.empty()) {
        std::vector<std::wstring> lines = SplitLines(script, false);
        if (!info.scriptPerTarget) {
            step.kind = FixStepKind::Command;
            step.commands = lines;
            step.needsAdmin = info.scriptNeedsAdmin;
            return step;
        }
        bool allSafe = !result.targets.empty();
        for (const std::wstring& t : result.targets) {
            if (!IsScriptSafeValue(t)) allSafe = false;
        }
        if (redacted) {
            reason = L"Names are hidden in this plan, and a hidden name would make a broken command, so this step is done by hand.";
        }
        else if (result.targets.empty()) {
            reason = L"The audit did not record the exact names a command needs, so this step is done by hand.";
        }
        else if (!allSafe) {
            reason = L"A name on this PC holds a character a command cannot carry exactly (a line break, a control "
                     L"character or a double quote), so this step is done by hand.";
        }
        else {
            step.kind = FixStepKind::Command;
            step.needsAdmin = info.scriptNeedsAdmin;
            for (const std::wstring& t : result.targets) {
                step.commands.push_back(L"$target = " + PowerShellQuote(t));
                for (const std::wstring& line : lines) step.commands.push_back(line);
            }
            return step;
        }
    }
    step.kind = FixStepKind::Manual;
    step.manualReason = reason;
    step.instructions = SplitLines(undo ? info.undo : info.fix, true);
    step.evidence = EvidenceLines(result.detail);
    return step;
}

std::vector<FixStep> BuildFixSteps(const std::vector<SecurityCheckResult>& results, bool undo, bool redacted,
                                   const std::vector<CheckInfo>& catalog)
{
    struct Ordered {
        int     severity;
        FixStep step;
    };
    std::vector<Ordered> ordered;
    for (const CheckInfo& info : catalog) {
        const SecurityCheckResult* found = nullptr;
        for (const SecurityCheckResult& r : results) {
            if (r.id == info.id) {
                found = &r;
                break;
            }
        }
        if (!found || !IsProblem(*found)) continue;
        // Unscored checks (Recent activity) report events, not a setting: there is
        // nothing for a fix step to change, and the audit report already explains them.
        if (!info.scored) continue;
        ordered.push_back({ static_cast<int>(info.severity), MakeStep(info, *found, undo, redacted) });
    }
    // Critical first; within a severity the catalog order stays.
    std::stable_sort(ordered.begin(), ordered.end(), [](const Ordered& a, const Ordered& b) { return a.severity > b.severity; });
    std::vector<FixStep> steps;
    for (Ordered& o : ordered) steps.push_back(std::move(o.step));
    if (undo) std::reverse(steps.begin(), steps.end());
    return steps;
}

// ---------------------------------------------------------------------------
// Script text
// ---------------------------------------------------------------------------
namespace {

class ScriptText {
public:
    void Line(const std::wstring& text = L"")
    {
        m_text += text;
        m_text += L"\r\n";
    }
    void Comment(const std::wstring& text) { Line(text.empty() ? L"#" : L"# " + CommentText(text)); }
    // Write-Host of a constant: the only way any text reaches the console.
    void Say(const std::wstring& indent, const std::wstring& text) { Line(indent + L"Write-Host " + PowerShellQuote(ShownText(text))); }
    const std::wstring& Text() const { return m_text; }

private:
    std::wstring m_text;
};

struct PlanCounts {
    int fail = 0;
    int warn = 0;
    int commands = 0;
    int manual = 0;
    bool needsAdmin = false;
};

PlanCounts CountPlan(const std::vector<FixStep>& steps)
{
    PlanCounts c;
    for (const FixStep& s : steps) {
        if (s.status == CHECK_FAIL) c.fail++;
        else c.warn++;
        if (s.kind == FixStepKind::Command) {
            c.commands++;
            if (s.needsAdmin) c.needsAdmin = true;
        }
        else {
            c.manual++;
        }
    }
    return c;
}

std::wstring NowText()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[40];
    swprintf_s(buf, L"%04u-%02u-%02uT%02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

void WriteHeader(ScriptText& s, const FixScriptOptions& o, const PlanCounts& c, size_t stepCount, bool undo)
{
    std::wstring self = undo ? o.undoScriptName : o.scriptName;
    if (self.empty()) self = undo ? L"phantom-recon-fix-undo.ps1" : L"phantom-recon-fix.ps1";
    std::wstring other = undo ? o.scriptName : o.undoScriptName;
    if (other.empty()) other = undo ? L"the fix script saved with it" : L"the undo script saved with it (same name, ending in -undo.ps1)";

    s.Comment(undo ? L"Phantom Recon undo plan" : L"Phantom Recon fix plan");
    s.Comment(L"");
    if (undo) {
        s.Comment(L"Reverses the steps of the fix plan " + other + L", which was saved with this file from");
        s.Comment(std::wstring(L"the same ") + PHANTOMRECON_NAME_W + L" " + PHANTOMRECON_VERSION_W +
                  L" audit. Phantom Recon never runs this script.");
    }
    else {
        s.Comment(std::wstring(L"The problems the ") + PHANTOMRECON_NAME_W + L" " + PHANTOMRECON_VERSION_W +
                  L" security audit found on this PC, as steps you");
        s.Comment(L"review and run yourself. Phantom Recon changed nothing and never runs this script.");
    }
    s.Comment(L"");
    s.Comment(L"Created:  " + (o.generatedAt.empty() ? NowText() : o.generatedAt));
    s.Comment(L"Findings: " + std::to_wstring(c.fail) + L" FAIL, " + std::to_wstring(c.warn) + L" WARNING");
    s.Comment(L"Steps:    " + std::to_wstring(stepCount) + L" (" + std::to_wstring(c.commands) + L" with commands, " +
              std::to_wstring(c.manual) + L" done by hand)");
    if (o.redacted) {
        s.Comment(L"Names:    hidden. Steps that would name files, services or networks on this PC are");
        s.Comment(L"          done by hand, because a hidden name would make a broken command.");
    }
    s.Comment(L"");
    s.Comment(L"Read every step before you run it.");
    if (stepCount == 0) return;
    s.Comment(L"");
    s.Comment(L"See the steps without changing anything (any PowerShell, in this folder):");
    s.Comment(L"  powershell -NoProfile -ExecutionPolicy Bypass -File \".\\" + self + L"\" -ListOnly");
    s.Comment(c.needsAdmin ? L"Run it (PowerShell opened with Run as administrator, in this folder):"
                           : L"Run it (PowerShell, in this folder):");
    s.Comment(L"  powershell -NoProfile -ExecutionPolicy Bypass -File \".\\" + self + L"\"");
    s.Comment(L"Every step with commands asks \"Apply this step? [y/N]\" first; anything but y skips it.");
    s.Comment(L"Steps done by hand print what to do and wait for Enter.");
    s.Comment(L"Nothing here restarts the PC. The end of the run says which steps need a restart.");
    s.Comment(L"");
    if (undo) {
        s.Comment(L"Answer y only for the steps you applied from the fix plan.");
    }
    else {
        s.Comment(L"Undo: run " + other + L" the same way, and answer y only for");
        s.Comment(L"the steps you applied. Keep the two files together.");
    }
}

void WriteAdminGuard(ScriptText& s)
{
    s.Line(L"if (-not $ListOnly) {");
    s.Line(L"    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())");
    s.Line(L"    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {");
    s.Say(L"        ", L"Some steps need administrator rights. Open PowerShell with Run as administrator and run this script again.");
    s.Say(L"        ", L"To read the steps without changing anything, add -ListOnly.");
    s.Line(L"        exit 1");
    s.Line(L"    }");
    s.Line(L"}");
}

void WriteStepDescription(ScriptText& s, const FixStep& step, size_t number, size_t total, bool undo)
{
    std::wstring counter = L"Step " + std::to_wstring(number) + L" of " + std::to_wstring(total);
    s.Line(L"# " + counter + L": " + CommentText(step.checkId) + L" (" + step.severity + L", " + step.status + L")");
    s.Say(L"", L"");
    s.Say(L"", counter + L": " + (undo ? L"undo " : L"") + step.title);
    s.Say(L"", L"Severity: " + step.severity + L". Audit result: " + step.status + L".");
    s.Say(L"", L"Why: " + step.why);
    if (!step.note.empty()) s.Say(L"", L"Note: " + step.note);
    if (step.needsRestart) s.Say(L"", L"This change takes effect after a restart.");
}

void WriteCommandStep(ScriptText& s, const FixStep& step, size_t number, size_t total, bool undo)
{
    WriteStepDescription(s, step, number, total, undo);
    s.Say(L"", L"Commands:");
    for (const std::wstring& c : step.commands) s.Say(L"", L"    " + c);
    s.Line(L"if (-not $ListOnly) {");
    s.Line(L"    $answer = Read-Host 'Apply this step? [y/N]'");
    s.Line(L"    if ($answer -eq 'y') {");
    s.Line(L"        try {");
    for (const std::wstring& c : step.commands) {
        s.Line(L"            $global:LASTEXITCODE = 0");
        s.Line(L"            " + c);
        s.Line(L"            if ($LASTEXITCODE) { throw ('A command ended with exit code ' + $LASTEXITCODE + '.') }");
    }
    s.Line(L"            $applied++");
    if (step.needsRestart) s.Line(L"            $restartSteps.Add(" + PowerShellQuote(ShownText(step.title)) + L")");
    s.Say(L"            ", L"Applied.");
    s.Line(L"        }");
    s.Line(L"        catch {");
    s.Line(L"            $failed++");
    s.Line(L"            Write-Warning ('Step " + std::to_wstring(number) + L" failed: ' + $_.Exception.Message)");
    s.Line(L"        }");
    s.Line(L"    }");
    s.Line(L"    else {");
    s.Line(L"        $skipped++");
    s.Say(L"        ", L"Skipped.");
    s.Line(L"    }");
    s.Line(L"}");
    s.Line();
}

void WriteManualStep(ScriptText& s, const FixStep& step, size_t number, size_t total, bool undo)
{
    WriteStepDescription(s, step, number, total, undo);
    if (!step.manualReason.empty()) s.Say(L"", step.manualReason);
    s.Say(L"", undo ? L"This undo is done by hand. What to do:" : L"This step is done by hand. What to do:");
    for (const std::wstring& line : step.instructions) s.Say(L"", L"    " + line);
    if (!step.evidence.empty()) {
        s.Say(L"", L"What the audit found:");
        for (const std::wstring& line : step.evidence) s.Say(L"", L"    " + line);
    }
    s.Line(L"if (-not $ListOnly) {");
    s.Line(L"    $null = Read-Host 'Press Enter when you have done this step, or to leave it for later'");
    s.Line(L"    $byHand++");
    s.Line(L"}");
    s.Line();
}

void WriteSummary(ScriptText& s, size_t total)
{
    s.Say(L"", L"");
    s.Line(L"if ($ListOnly) {");
    s.Say(L"    ", L"List only: nothing was changed. " + std::to_wstring(total) + L" step(s) listed.");
    s.Line(L"    exit 0");
    s.Line(L"}");
    s.Line(L"Write-Host ('Applied: ' + $applied + '. Skipped: ' + $skipped + '. Failed: ' + $failed + '. Done by hand: ' + $byHand + '.')");
    s.Line(L"if ($restartSteps.Count -gt 0) {");
    s.Say(L"    ", L"Restart the PC to finish these steps. This script does not restart it:");
    s.Line(L"    foreach ($name in $restartSteps) { Write-Host ('    ' + $name) }");
    s.Line(L"}");
    s.Line(L"if ($failed -gt 0) { exit 1 }");
    s.Line(L"exit 0");
}

std::wstring BuildScript(const std::vector<SecurityCheckResult>& results, const FixScriptOptions& options,
                         const std::vector<CheckInfo>& catalog, bool undo)
{
    std::vector<FixStep> steps = BuildFixSteps(results, undo, options.redacted, catalog);
    PlanCounts counts = CountPlan(steps);
    ScriptText s;
    WriteHeader(s, options, counts, steps.size(), undo);
    s.Line();
    s.Line(L"param([switch]$ListOnly)");
    s.Line();

    if (steps.empty()) {
        s.Say(L"", undo ? L"The audit found no failed or warning checks, so there is nothing to undo. This script changes nothing."
                        : L"The audit found no failed or warning checks, so there is nothing to fix. This script changes nothing.");
        s.Line(L"exit 0");
        DebugLog(std::wstring(undo ? L"Undo" : L"Fix") + L" plan: no problems, empty plan");
        return s.Text();
    }

    s.Line(L"$ErrorActionPreference = 'Stop'");
    s.Line(L"$applied = 0");
    s.Line(L"$skipped = 0");
    s.Line(L"$failed = 0");
    s.Line(L"$byHand = 0");
    s.Line(L"$restartSteps = New-Object System.Collections.Generic.List[string]");
    s.Line();
    if (counts.needsAdmin) {
        WriteAdminGuard(s);
        s.Line();
    }
    s.Say(L"", std::wstring(undo ? L"Phantom Recon undo plan: " : L"Phantom Recon fix plan: ") + std::to_wstring(steps.size()) +
               L" step(s), " + std::to_wstring(counts.commands) + L" with commands and " + std::to_wstring(counts.manual) +
               L" done by hand.");
    s.Line(L"if ($ListOnly) { Write-Host 'List only: nothing is changed.' }");
    s.Line();

    for (size_t i = 0; i < steps.size(); ++i) {
        if (steps[i].kind == FixStepKind::Command) WriteCommandStep(s, steps[i], i + 1, steps.size(), undo);
        else WriteManualStep(s, steps[i], i + 1, steps.size(), undo);
    }
    WriteSummary(s, steps.size());
    DebugLog(std::wstring(undo ? L"Undo" : L"Fix") + L" plan: " + std::to_wstring(steps.size()) + L" steps, " +
             std::to_wstring(counts.commands) + L" with commands, " + std::to_wstring(counts.manual) + L" by hand" +
             (options.redacted ? L", names hidden" : L""));
    return s.Text();
}

} // namespace

std::wstring BuildFixScript(const std::vector<SecurityCheckResult>& results, const FixScriptOptions& options,
                            const std::vector<CheckInfo>& catalog)
{
    return BuildScript(results, options, catalog, false);
}

std::wstring BuildUndoScript(const std::vector<SecurityCheckResult>& results, const FixScriptOptions& options,
                             const std::vector<CheckInfo>& catalog)
{
    return BuildScript(results, options, catalog, true);
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------
bool HasPs1Extension(const std::wstring& path)
{
    return EndsWithI(path, L".ps1");
}

std::wstring UndoScriptPathFor(const std::wstring& fixScriptPath)
{
    if (HasPs1Extension(fixScriptPath)) return fixScriptPath.substr(0, fixScriptPath.size() - 4) + L"-undo.ps1";
    return fixScriptPath + L"-undo.ps1";
}

bool SaveFixScripts(const std::wstring& fixScriptPath, const std::vector<SecurityCheckResult>& results,
                    const FixScriptOptions& optionsIn, std::wstring& undoScriptPath, std::wstring& error)
{
    error.clear();
    undoScriptPath = UndoScriptPathFor(fixScriptPath);
    FixScriptOptions options = optionsIn;
    options.scriptName = FileNameOf(fixScriptPath);
    options.undoScriptName = FileNameOf(undoScriptPath);
    if (options.generatedAt.empty()) options.generatedAt = NowText();

    if (!WriteUtf8File(fixScriptPath, BuildFixScript(results, options), true)) {
        error = L"could not write " + fixScriptPath;
        DebugLog(L"SaveFixScripts: " + error);
        return false;
    }
    if (!WriteUtf8File(undoScriptPath, BuildUndoScript(results, options), true)) {
        error = L"could not write " + undoScriptPath;
        DebugLog(L"SaveFixScripts: " + error);
        return false;
    }
    DebugLog(L"Fix plan saved to " + fixScriptPath + L" and " + undoScriptPath);
    return true;
}
