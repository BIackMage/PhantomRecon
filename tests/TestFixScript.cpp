// The fix plan (FixScript.cpp, CheckScripts.cpp): step order, the y/N gate, -ListOnly,
// quoting of hostile names, manual steps, the empty plan, the undo order, BOM and CRLF.
// Every generated script is parsed by the real Windows PowerShell parser, and the plans
// built from a test-only catalog are run, so the tests judge what PowerShell does with
// the text and not only what the text looks like.

#include "TestFramework.h"

#include "../CheckCatalog.h"
#include "../CheckScripts.h"
#include "../CliRunner.h"
#include "../FileIO.h"
#include "../FixScript.h"
#include "../SecurityChecks.h"
#include "../StringConv.h"
#include "../TextUtils.h"

#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <regex>
#include <set>

// ---------------------------------------------------------------------------
// Helpers: run Windows PowerShell, parse a script with its parser
// ---------------------------------------------------------------------------
namespace {

struct ProcessResult {
    bool        ran = false;
    DWORD       exitCode = 0xFFFFFFFF;
    std::string output;   // stdout and stderr together, as the console encoding wrote them
};

std::wstring PowerShellExe()
{
    wchar_t root[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
    std::wstring base = (n > 0 && n < MAX_PATH) ? std::wstring(root) : std::wstring(L"C:\\Windows");
    return base + L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
}

int g_processCounter = 0;

// Runs powershell.exe with args, feeding stdinText as its standard input (redirected
// stdin is how a test answers Read-Host). Waits at most two minutes.
ProcessResult RunPowerShell(const std::wstring& args, const std::string& stdinText)
{
    ProcessResult result;
    std::wstring tag = std::to_wstring(++g_processCounter);
    std::wstring inPath = tf::TestDir() + L"ps-in-" + tag + L".txt";
    std::wstring outPath = tf::TestDir() + L"ps-out-" + tag + L".txt";
    if (!WriteBinaryFile(inPath, stdinText.data(), stdinText.size())) return result;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE in = CreateFileW(inPath.c_str(), GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE out = CreateFileW(outPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (in == INVALID_HANDLE_VALUE || out == INVALID_HANDLE_VALUE) {
        if (in != INVALID_HANDLE_VALUE) CloseHandle(in);
        if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
        return result;
    }
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in;
    si.hStdOutput = out;
    si.hStdError = out;
    PROCESS_INFORMATION pi = {};
    std::wstring cmd = L"\"" + PowerShellExe() + L"\" -NoProfile -ExecutionPolicy Bypass " + args;
    BOOL ok = CreateProcessW(NULL, &cmd[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(in);
    CloseHandle(out);
    if (!ok) {
        std::printf("    note: powershell.exe did not start (error %lu)\n", GetLastError());
        return result;
    }
    if (WaitForSingleObject(pi.hProcess, 120000) != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 99);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    GetExitCodeProcess(pi.hProcess, &result.exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    std::vector<uint8_t> bytes;
    ReadBinaryFile(outPath, bytes, 4 * 1024 * 1024, nullptr);
    result.output.assign(bytes.begin(), bytes.end());
    result.ran = true;
    return result;
}

ProcessResult RunScript(const std::wstring& scriptPath, const std::wstring& extraArgs, const std::string& answers)
{
    return RunPowerShell(L"-File \"" + scriptPath + L"\"" + (extraArgs.empty() ? L"" : L" " + extraArgs), answers);
}

// What the real parser makes of a script: errors, double-quoted (expandable) strings,
// the name of every command, and the exact value of every $target = '...' assignment
// (as UTF-16 hex, so no console encoding stands between PowerShell and the test).
struct ParseReport {
    bool ok = false;                    // the parser ran and wrote its report
    int  errors = -1;
    int  expandable = -1;
    std::vector<std::string> errorText;
    std::vector<std::string> commands;
    std::vector<std::string> targets;   // hex of each value; "NOT-CONSTANT" when it is not a single-quoted constant
};

const char kParserScript[] =
    "param([string]$Path, [string]$Out)\r\n"
    "$ErrorActionPreference = 'Stop'\r\n"
    "$tokens = $null\r\n"
    "$errors = $null\r\n"
    "$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)\r\n"
    "$lines = New-Object System.Collections.Generic.List[string]\r\n"
    "$lines.Add('errors=' + $errors.Count)\r\n"
    "foreach ($e in $errors) { $lines.Add('error=' + $e.Extent.StartLineNumber + ': ' + $e.Message) }\r\n"
    "$expandable = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true))\r\n"
    "$lines.Add('expandable=' + $expandable.Count)\r\n"
    "foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) { $lines.Add('command=' + $c.GetCommandName()) }\r\n"
    "$assigns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.Left.VariablePath.UserPath -eq 'target' }, $true)\r\n"
    "foreach ($a in $assigns) {\r\n"
    "    $expr = $null\r\n"
    "    if ($a.Right -is [System.Management.Automation.Language.CommandExpressionAst]) { $expr = $a.Right.Expression }\r\n"
    "    if ($expr -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $expr.StringConstantType -eq 'SingleQuoted') {\r\n"
    "        $lines.Add('target=' + (($expr.Value.ToCharArray() | ForEach-Object { '{0:x4}' -f [int]$_ }) -join ''))\r\n"
    "    }\r\n"
    "    else { $lines.Add('target=NOT-CONSTANT') }\r\n"
    "}\r\n"
    "[System.IO.File]::WriteAllLines($Out, $lines)\r\n";

ParseReport ParseWithPowerShell(const std::wstring& scriptPath)
{
    ParseReport report;
    std::wstring tag = std::to_wstring(++g_processCounter);
    std::wstring parser = tf::TestDir() + L"parse-" + tag + L".ps1";
    std::wstring out = tf::TestDir() + L"parse-" + tag + L".txt";
    if (!WriteBinaryFile(parser, kParserScript, sizeof(kParserScript) - 1)) return report;
    ProcessResult r = RunPowerShell(L"-File \"" + parser + L"\" -Path \"" + scriptPath + L"\" -Out \"" + out + L"\"", "");
    std::wstring text;
    if (!r.ran || r.exitCode != 0 || !ReadTextFile(out, text, 8 * 1024 * 1024)) {
        std::printf("    note: the parser run failed (exit %lu): %s\n", r.exitCode, r.output.c_str());
        return report;
    }
    for (const std::wstring& line : SplitW(text, L'\n')) {
        std::string l = tf::Narrow(line);
        if (l.rfind("errors=", 0) == 0) report.errors = std::stoi(l.substr(7));
        else if (l.rfind("expandable=", 0) == 0) report.expandable = std::stoi(l.substr(11));
        else if (l.rfind("error=", 0) == 0) report.errorText.push_back(l.substr(6));
        else if (l.rfind("command=", 0) == 0) report.commands.push_back(l.substr(8));
        else if (l.rfind("target=", 0) == 0) report.targets.push_back(l.substr(7));
    }
    report.ok = report.errors >= 0 && report.expandable >= 0;
    for (const std::string& e : report.errorText) std::printf("    parse error: %s\n", e.c_str());
    return report;
}

std::string Hex(const std::wstring& value)
{
    std::string out;
    char buf[8];
    for (wchar_t c : value) {
        sprintf_s(buf, "%04x", static_cast<unsigned int>(c));
        out += buf;
    }
    return out;
}

bool Contains(const std::wstring& text, const std::wstring& part)
{
    return text.find(part) != std::wstring::npos;
}

bool Contains(const std::string& text, const std::string& part)
{
    return text.find(part) != std::string::npos;
}

size_t CountOf(const std::wstring& text, const std::wstring& part)
{
    size_t n = 0;
    for (size_t pos = text.find(part); pos != std::wstring::npos; pos = text.find(part, pos + part.size())) ++n;
    return n;
}

SecurityCheckResult Result(const std::wstring& id, const wchar_t* status, const std::wstring& detail = L"evidence line")
{
    SecurityCheckResult r = MakeCheckResult(id);
    r.status = status;
    r.detail = detail;
    return r;
}

// The ids of the steps, in order.
std::vector<std::wstring> StepIds(const std::vector<FixStep>& steps)
{
    std::vector<std::wstring> ids;
    for (const FixStep& s : steps) ids.push_back(s.checkId);
    return ids;
}

// The hostile names from the task, plus Unicode quotes PowerShell also treats as quotes.
std::vector<std::wstring> HostileSafeNames()
{
    return {
        L"a'; Remove-Item C:\\x -Recurse; '",
        L"$(calc)",
        L"back`tick`n",
        L"#not a comment",
        L"caf\x00e9 \x65e5\x672c \x0436 \x2018left\x2019 \x201alow\x201b",
        L"\xd83d\xde00 emoji pair",
        std::wstring(300, L'n'),
    };
}

// Write a script the way SaveFixScripts does (BOM, the text is already CRLF).
std::wstring WriteScript(const std::wstring& name, const std::wstring& text)
{
    std::wstring path = tf::TestDir() + name;
    WriteUtf8File(path, text, true);
    return path;
}

// A small catalog whose commands only touch the test folder, so the plans can be run.
std::vector<CheckInfo> RunnableCatalog(const std::wstring& dir)
{
    auto make = [](const wchar_t* id, const wchar_t* title, Severity sev) {
        CheckInfo info;
        info.id = id;
        info.title = title;
        info.category = L"Test";
        info.severity = sev;
        info.explanation = std::wstring(L"Explanation of ") + title + L". Second sentence.";
        info.fix = std::wstring(L"Fix text for ") + title + L".";
        info.undo = std::wstring(L"Undo text for ") + title + L".";
        info.scriptNeedsAdmin = false;
        return info;
    };
    std::vector<CheckInfo> c;

    CheckInfo low = make(L"t.low", L"Low step", Severity::Low);
    low.fixScript = L"Set-Content -LiteralPath " + PowerShellQuote(dir + L"low.txt") + L" -Value 'low'";
    low.undoScript = L"Remove-Item -LiteralPath " + PowerShellQuote(dir + L"low.txt");
    c.push_back(low);

    CheckInfo crit = make(L"t.crit", L"Critical step", Severity::Critical);
    crit.fixScript = L"New-Item -ItemType File -Path " + PowerShellQuote(dir + L"crit.txt") + L" -Force | Out-Null";
    crit.undoScript = L"Remove-Item -LiteralPath " + PowerShellQuote(dir + L"crit.txt");
    crit.scriptNeedsRestart = true;
    crit.fixScriptNote = L"A note shown before the question.";
    c.push_back(crit);

    CheckInfo fail = make(L"t.fail", L"Failing step", Severity::High);
    fail.fixScript = L"cmd.exe /c exit 3";
    c.push_back(fail);

    CheckInfo target = make(L"t.target", L"Per-name step", Severity::Medium);
    target.fixScript = L"Add-Content -LiteralPath " + PowerShellQuote(dir + L"targets.txt") + L" -Value $target -Encoding UTF8";
    target.undoScript = L"Add-Content -LiteralPath " + PowerShellQuote(dir + L"undone.txt") + L" -Value $target -Encoding UTF8";
    target.scriptPerTarget = true;
    c.push_back(target);

    CheckInfo manual = make(L"t.manual", L"Manual step", Severity::Medium);
    c.push_back(manual);
    return c;
}

std::vector<SecurityCheckResult> RunnableResults()
{
    std::vector<SecurityCheckResult> r;
    for (const wchar_t* id : { L"t.low", L"t.crit", L"t.fail", L"t.target", L"t.manual" }) {
        SecurityCheckResult x;
        x.id = id;
        x.name = id;
        x.status = CHECK_FAIL;
        x.detail = L"Evidence for " + std::wstring(id);
        if (x.id == L"t.target") x.targets = HostileSafeNames();
        r.push_back(x);
    }
    return r;
}

bool FileThere(const std::wstring& path)
{
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::vector<std::wstring> ReadLines(const std::wstring& path)
{
    std::wstring text;
    std::vector<std::wstring> lines;
    if (!ReadTextFile(path, text, 4 * 1024 * 1024)) return lines;
    std::wstring current;
    for (wchar_t c : text) {
        if (c == L'\n') {
            if (!current.empty() && current.back() == L'\r') current.pop_back();
            lines.push_back(current);
            current.clear();
        }
        else {
            current += c;
        }
    }
    if (!current.empty()) lines.push_back(current);
    return lines;
}

} // namespace

// ---------------------------------------------------------------------------
// Quoting and file names
// ---------------------------------------------------------------------------
TEST(FixScript_QuoteAndSafeValues)
{
    CHECK_EQ(PowerShellQuote(L"plain"), std::wstring(L"'plain'"));
    CHECK_EQ(PowerShellQuote(L""), std::wstring(L"''"));
    CHECK_EQ(PowerShellQuote(L"it's"), std::wstring(L"'it''s'"));
    CHECK_EQ(PowerShellQuote(L"a'; Remove-Item C:\\x -Recurse; '"), std::wstring(L"'a''; Remove-Item C:\\x -Recurse; '''"));
    CHECK_EQ(PowerShellQuote(L"$(calc) `n \"x\""), std::wstring(L"'$(calc) `n \"x\"'"));
    // PowerShell also ends a single-quoted string at these four.
    CHECK_EQ(PowerShellQuote(L"\x2018\x2019\x201a\x201b"), std::wstring(L"'\x2018\x2018\x2019\x2019\x201a\x201a\x201b\x201b'"));

    for (const std::wstring& name : HostileSafeNames()) {
        if (!IsScriptSafeValue(name)) tf::Fail(__FILE__, __LINE__, "should be safe: " + tf::Narrow(name));
    }
    CHECK(!IsScriptSafeValue(L""));
    CHECK(!IsScriptSafeValue(L"line\nbreak"));
    CHECK(!IsScriptSafeValue(L"carriage\rreturn"));
    CHECK(!IsScriptSafeValue(L"tab\there"));
    CHECK(!IsScriptSafeValue(std::wstring(L"nul") + L'\0' + L"inside"));
    CHECK(!IsScriptSafeValue(L"next\x0085line"));
    CHECK(!IsScriptSafeValue(L"sep\x2028line"));
    CHECK(!IsScriptSafeValue(L"say \"hi\""));
    CHECK(!IsScriptSafeValue(L"lone \xd800 high"));
    CHECK(!IsScriptSafeValue(L"lone \xdc00 low"));
    CHECK(!IsScriptSafeValue(std::wstring(2049, L'x')));
    CHECK(IsScriptSafeValue(std::wstring(2048, L'x')));

    CHECK_EQ(UndoScriptPathFor(L"C:\\x\\plan.ps1"), std::wstring(L"C:\\x\\plan-undo.ps1"));
    CHECK_EQ(UndoScriptPathFor(L"C:\\x\\Plan.PS1"), std::wstring(L"C:\\x\\Plan-undo.ps1"));
    CHECK_EQ(UndoScriptPathFor(L"C:\\x\\plan"), std::wstring(L"C:\\x\\plan-undo.ps1"));
    CHECK(HasPs1Extension(L"a.PS1"));
    CHECK(!HasPs1Extension(L"a.ps1.txt"));
}

// ---------------------------------------------------------------------------
// Order, gates, manual steps, undo order (the real catalog)
// ---------------------------------------------------------------------------
TEST(FixScript_StepOrderGatesAndUndo)
{
    std::vector<SecurityCheckResult> results = {
        Result(L"def.cfa", CHECK_WARNING),          // Low, command
        Result(L"def.realtime", CHECK_FAIL),        // Critical, command
        Result(L"hard.secureboot", CHECK_FAIL),     // Medium, by hand (firmware)
        Result(L"hard.uac", CHECK_WARNING),         // High, command, restart
        Result(L"acct.guest", CHECK_PASS),          // not a problem
        Result(L"net.llmnr", CHECK_FAIL),           // High, command
        Result(L"svc.writable", CHECK_FAIL, L"1 service program(s) can be changed:\n  [Svc] C:\\Odd Path\\svc.exe"),   // Critical, by hand
        Result(L"net.rdp", CHECK_ERROR),            // errors are not steps
    };
    std::vector<FixStep> steps = BuildFixSteps(results, false, false);
    std::vector<std::wstring> expected = { L"def.realtime", L"svc.writable", L"hard.uac", L"net.llmnr", L"hard.secureboot", L"def.cfa" };
    CHECK(StepIds(steps) == expected);
    REQUIRE(steps.size() == expected.size());
    CHECK(steps[0].kind == FixStepKind::Command);
    CHECK(steps[1].kind == FixStepKind::Manual);
    CHECK(steps[4].kind == FixStepKind::Manual);
    CHECK(steps[2].needsRestart);
    CHECK(Contains(JoinW(steps[1].evidence, L"\n"), L"C:\\Odd Path\\svc.exe"));
    CHECK(Contains(JoinW(steps[1].instructions, L"\n"), L"icacls"));

    // The one-line why: a short first sentence takes the second along; a long one is cut at a word.
    std::vector<FixStep> whySteps = BuildFixSteps({ Result(L"net.smbsigning", CHECK_FAIL), Result(L"persist.sweep", CHECK_WARNING),
                                                    Result(L"net.llmnr", CHECK_FAIL) }, false, false);
    REQUIRE(whySteps.size() == 3);
    for (const FixStep& s : whySteps) {
        if (s.checkId == L"net.smbsigning") {
            CHECK_EQ(s.why, std::wstring(L"SMB is Windows file sharing. Signing proves each message came from the real server."));
        }
        else if (s.checkId == L"persist.sweep") {
            CHECK(s.why.size() <= 240);
            CHECK(s.why.size() > 150);
            CHECK(EndsWithI(s.why, L" ..."));
            CHECK(!EndsWithI(s.why, L"C ..."));   // not cut inside "COM"
        }
        else {
            CHECK_EQ(s.why, std::wstring(L"When DNS cannot find a name, Windows shouts the question to the whole local network with LLMNR."));
        }
    }

    std::vector<FixStep> undo = BuildFixSteps(results, true, false);
    std::vector<std::wstring> reversed(expected.rbegin(), expected.rend());
    CHECK(StepIds(undo) == reversed);
    // def.realtime has no undo command on purpose (turning real-time protection off is
    // troubleshooting only), so its undo is a step done by hand.
    REQUIRE(undo.size() == reversed.size());
    CHECK(undo.back().checkId == L"def.realtime" && undo.back().kind == FixStepKind::Manual);
    CHECK(undo.front().checkId == L"def.cfa" && undo.front().kind == FixStepKind::Command);
    CHECK(Contains(JoinW(undo.front().commands, L"\n"), L"-EnableControlledFolderAccess Disabled"));

    FixScriptOptions options;
    options.generatedAt = L"2026-10-26T12:00:00";
    options.scriptName = L"plan.ps1";
    options.undoScriptName = L"plan-undo.ps1";
    std::wstring fix = BuildFixScript(results, options);
    std::wstring undoText = BuildUndoScript(results, options);

    // Header: what it is, version, date, counts, the warning, how to run and undo.
    CHECK(Contains(fix, L"# Phantom Recon fix plan"));
    CHECK(Contains(fix, L"Phantom Recon 1.0.0"));
    CHECK(Contains(fix, L"# Created:  2026-10-26T12:00:00"));
    CHECK(Contains(fix, L"# Findings: 4 FAIL, 2 WARNING"));
    CHECK(Contains(fix, L"# Steps:    6 (4 with commands, 2 done by hand)"));
    CHECK(Contains(fix, L"# Read every step before you run it."));
    CHECK(Contains(fix, L"-ExecutionPolicy Bypass -File \".\\plan.ps1\" -ListOnly"));
    CHECK(Contains(fix, L"Run as administrator"));
    CHECK(Contains(fix, L"plan-undo.ps1"));
    CHECK(Contains(fix, L"\r\nparam([switch]$ListOnly)\r\n"));
    CHECK(Contains(fix, L"[Security.Principal.WindowsBuiltInRole]::Administrator"));   // steps need admin

    // Step comments in the order of the steps.
    size_t last = 0;
    for (size_t i = 0; i < expected.size(); ++i) {
        std::wstring marker = L"# Step " + std::to_wstring(i + 1) + L" of 6: " + expected[i] + L" (";
        size_t at = fix.find(marker);
        if (at == std::wstring::npos || at < last) tf::Fail(__FILE__, __LINE__, "step out of order: " + tf::Narrow(marker));
        else last = at;
    }

    // Every command step asks first; every block that runs commands has the gate before
    // its try, and manual blocks never run anything.
    CHECK_EQ(CountOf(fix, L"$answer = Read-Host 'Apply this step? [y/N]'\r\n    if ($answer -eq 'y') {"), static_cast<size_t>(4));
    CHECK_EQ(CountOf(fix, L"Read-Host 'Press Enter when you have done this step"), static_cast<size_t>(2));
    std::vector<std::wstring> blocks;
    for (size_t pos = fix.find(L"# Step "); pos != std::wstring::npos;) {
        size_t next = fix.find(L"# Step ", pos + 1);
        blocks.push_back(fix.substr(pos, next == std::wstring::npos ? std::wstring::npos : next - pos));
        pos = next;
    }
    REQUIRE(blocks.size() == 6);
    for (const std::wstring& b : blocks) {
        size_t gate = b.find(L"Apply this step? [y/N]");
        size_t tryAt = b.find(L"try {");
        size_t listOnly = b.find(L"if (-not $ListOnly) {");
        if (tryAt != std::wstring::npos) {
            CHECK(gate != std::wstring::npos && gate < tryAt);
            CHECK(listOnly != std::wstring::npos && listOnly < gate);
            CHECK(Contains(b, L"catch {"));
            CHECK(Contains(b, L"Write-Warning"));
        }
        else {
            CHECK(gate == std::wstring::npos);
            CHECK(Contains(b, L"This step is done by hand"));
        }
    }
    CHECK(Contains(blocks[0], L"Set-MpPreference -DisableRealtimeMonitoring $false"));
    CHECK(Contains(blocks[2], L"$restartSteps.Add('User Account Control')"));
    CHECK(Contains(fix, L"'Applied: ' + $applied + '. Skipped: ' + $skipped + '. Failed: ' + $failed"));
    for (const std::wstring* text : { &fix, &undoText }) {
        std::wstring lower = ToLowerW(*text);
        CHECK(!Contains(lower, L"restart-computer"));
        CHECK(!Contains(lower, L"shutdown"));
        CHECK(!Contains(lower, L"bcdedit"));
    }

    // The undo script: same shape, the undo commands, reverse order.
    CHECK(Contains(undoText, L"# Phantom Recon undo plan"));
    CHECK(Contains(undoText, L"plan.ps1"));
    CHECK(undoText.find(L"# Step 1 of 6: def.cfa") < undoText.find(L"# Step 6 of 6: def.realtime"));
    CHECK(Contains(undoText, L"Set-MpPreference -EnableControlledFolderAccess Disabled"));
    // Turning real-time protection off is shown as the catalog's undo text, never run.
    CHECK(Contains(undoText, L"Write-Host '    Set-MpPreference -DisableRealtimeMonitoring $true"));
    CHECK(!Contains(undoText, L"            Set-MpPreference -DisableRealtimeMonitoring $true"));
    // cfa and llmnr; uac, secureboot, svc.writable and realtime have no undo command.
    CHECK_EQ(CountOf(undoText, L"Read-Host 'Apply this step? [y/N]'"), static_cast<size_t>(2));
    CHECK(Contains(undoText, L"-ExecutionPolicy Bypass -File \".\\plan-undo.ps1\" -ListOnly"));

    std::wstring fixPath = WriteScript(L"order.ps1", fix);
    std::wstring undoPath = WriteScript(L"order-undo.ps1", undoText);
    for (const std::wstring& p : { fixPath, undoPath }) {
        ParseReport parsed = ParseWithPowerShell(p);
        REQUIRE(parsed.ok);
        CHECK_EQ(parsed.errors, 0);
        CHECK_EQ(parsed.expandable, 0);   // no double-quoted string anywhere
    }

    // -ListOnly as a normal user: the admin guard does not stop it, nothing runs.
    ProcessResult listed = RunScript(fixPath, L"-ListOnly", "");
    REQUIRE(listed.ran);
    CHECK_EQ(listed.exitCode, static_cast<DWORD>(0));
    CHECK(Contains(listed.output, "List only: nothing is changed."));
    CHECK(Contains(listed.output, "Step 1 of 6: Antivirus real-time protection"));
    CHECK(Contains(listed.output, "Set-MpPreference -DisableRealtimeMonitoring $false"));
    CHECK(Contains(listed.output, "List only: nothing was changed. 6 step(s) listed."));
    CHECK(!Contains(listed.output, "Apply this step"));
    CHECK(!Contains(listed.output, "Applied."));
}

// ---------------------------------------------------------------------------
// Hostile names reach PowerShell only as single-quoted constants
// ---------------------------------------------------------------------------
TEST(FixScript_HostileNamesStayLiteral)
{
    REQUIRE(FindCheckInfo(L"net.wifiopen") != nullptr);
    REQUIRE(FindCheckInfo(L"net.wifiopen")->scriptPerTarget);
    SecurityCheckResult wifi = Result(L"net.wifiopen", CHECK_WARNING, L"saved open networks");
    wifi.targets = HostileSafeNames();

    FixScriptOptions options;
    std::wstring fix = BuildFixScript({ wifi }, options);
    std::wstring undo = BuildUndoScript({ wifi }, options);
    for (const std::wstring& name : wifi.targets) {
        CHECK(Contains(fix, L"$target = " + PowerShellQuote(name) + L"\r\n"));
        CHECK(Contains(undo, L"$target = " + PowerShellQuote(name) + L"\r\n"));
    }
    CHECK_EQ(CountOf(fix, L"connectionmode=manual"), wifi.targets.size() * 2);   // shown once, run once
    CHECK_EQ(CountOf(undo, L"connectionmode=auto"), wifi.targets.size() * 2);

    const std::set<std::string> allowed = { "Write-Host", "Read-Host", "Write-Warning", "New-Object", "netsh" };
    for (const std::pair<const wchar_t*, std::wstring*> file : { std::make_pair(L"hostile.ps1", &fix), std::make_pair(L"hostile-undo.ps1", &undo) }) {
        ParseReport parsed = ParseWithPowerShell(WriteScript(file.first, *file.second));
        REQUIRE(parsed.ok);
        CHECK_EQ(parsed.errors, 0);
        CHECK_EQ(parsed.expandable, 0);
        for (const std::string& c : parsed.commands) {
            if (allowed.count(c) == 0) tf::Fail(__FILE__, __LINE__, "unexpected command in the parsed script: " + c);
        }
        // The parser reads back exactly the names that went in, in order.
        REQUIRE(parsed.targets.size() == wifi.targets.size());
        for (size_t i = 0; i < wifi.targets.size(); ++i) CHECK_EQ(parsed.targets[i], Hex(wifi.targets[i]));
    }

    // A name that cannot be carried exactly makes the step manual; the name is shown,
    // still only inside single-quoted Write-Host text.
    SecurityCheckResult odd = Result(L"net.wifiopen", CHECK_WARNING,
        L"2 saved Wi-Fi network(s):\n  \"two\nlines'; calc; '\"\n  \"say \"hi\"\"");
    odd.targets = { L"two\nlines'; calc; '", L"say \"hi\"" };
    std::vector<FixStep> steps = BuildFixSteps({ odd }, false, false);
    REQUIRE(steps.size() == 1);
    CHECK(steps[0].kind == FixStepKind::Manual);
    CHECK(Contains(steps[0].manualReason, L"cannot carry exactly"));
    std::wstring manualText = BuildFixScript({ odd }, options);
    CHECK(!Contains(manualText, L"$target ="));
    CHECK(!Contains(manualText, L"Read-Host 'Apply this step? [y/N]'"));
    CHECK(Contains(manualText, L"Read-Host 'Press Enter when you have done this step"));
    CHECK(Contains(manualText, L"Write-Host '      \"two'"));
    CHECK(Contains(manualText, L"Write-Host 'lines''; calc; ''\"'") || Contains(manualText, L"lines''; calc; ''\""));
    ParseReport parsedManual = ParseWithPowerShell(WriteScript(L"odd.ps1", manualText));
    REQUIRE(parsedManual.ok);
    CHECK_EQ(parsedManual.errors, 0);
    CHECK_EQ(parsedManual.expandable, 0);
    for (const std::string& c : parsedManual.commands) {
        if (allowed.count(c) == 0) tf::Fail(__FILE__, __LINE__, "unexpected command in the manual script: " + c);
    }
    CHECK(parsedManual.targets.empty());

    // No names recorded (an unreadable profile list): manual too.
    SecurityCheckResult none = Result(L"net.wifiopen", CHECK_WARNING, L"None of the 3 saved Wi-Fi network(s) could be read.");
    std::vector<FixStep> noneSteps = BuildFixSteps({ none }, false, false);
    REQUIRE(noneSteps.size() == 1);
    CHECK(noneSteps[0].kind == FixStepKind::Manual);
}

// ---------------------------------------------------------------------------
// Hidden names
// ---------------------------------------------------------------------------
TEST(FixScript_RedactedPlanIsManualForNames)
{
    SecurityCheckResult wifi = Result(L"net.wifiopen", CHECK_WARNING, L"1 saved network:\n  \"<user>'s phone\"");
    wifi.targets = { L"<user>'s phone" };
    SecurityCheckResult cloud = Result(L"def.cloud", CHECK_FAIL);
    FixScriptOptions options;
    options.redacted = true;
    std::vector<FixStep> steps = BuildFixSteps({ wifi, cloud }, false, true);
    REQUIRE(steps.size() == 2);
    for (const FixStep& s : steps) {
        if (s.checkId == L"net.wifiopen") {
            CHECK(s.kind == FixStepKind::Manual);
            CHECK(Contains(s.manualReason, L"Names are hidden"));
            CHECK(Contains(JoinW(s.evidence, L"\n"), L"<user>'s phone"));
        }
        else {
            CHECK(s.kind == FixStepKind::Command);   // a fixed command names nothing on this PC
        }
    }
    std::wstring text = BuildFixScript({ wifi, cloud }, options);
    CHECK(Contains(text, L"# Names:    hidden."));
    CHECK(!Contains(text, L"$target ="));
    CHECK(Contains(text, L"Write-Host '    1 saved network:'"));
    CHECK(Contains(text, L"''s phone"));
    CHECK(Contains(text, L"Set-MpPreference -MAPSReporting Advanced"));
    ParseReport parsed = ParseWithPowerShell(WriteScript(L"redacted.ps1", text));
    REQUIRE(parsed.ok);
    CHECK_EQ(parsed.errors, 0);

    // Without hiding names the same results give a command for the network.
    std::vector<FixStep> open = BuildFixSteps({ wifi, cloud }, false, false);
    for (const FixStep& s : open) {
        if (s.checkId == L"net.wifiopen") CHECK(s.kind == FixStepKind::Command);
    }
    FixScriptOptions plain;
    CHECK(!Contains(BuildFixScript({ wifi, cloud }, plain), L"# Names:"));
}

// ---------------------------------------------------------------------------
// Nothing to fix
// ---------------------------------------------------------------------------
TEST(FixScript_EmptyPlan)
{
    std::vector<SecurityCheckResult> results = {
        Result(L"def.realtime", CHECK_PASS), Result(L"net.llmnr", CHECK_NA), Result(L"hard.uac", CHECK_INFO),
        Result(L"svc.writable", CHECK_ERROR),
    };
    CHECK(BuildFixSteps(results, false, false).empty());
    FixScriptOptions options;
    std::wstring fix = BuildFixScript(results, options);
    std::wstring undo = BuildUndoScript(results, options);
    CHECK(Contains(fix, L"# Steps:    0 (0 with commands, 0 done by hand)"));
    CHECK(Contains(fix, L"nothing to fix. This script changes nothing."));
    CHECK(Contains(undo, L"nothing to undo. This script changes nothing."));
    for (const std::wstring* text : { &fix, &undo }) {
        CHECK(Contains(*text, L"param([switch]$ListOnly)"));
        CHECK(!Contains(*text, L"Read-Host"));
        CHECK(!Contains(*text, L"Set-"));
        CHECK(!Contains(*text, L"Administrator"));
    }
    std::wstring path = WriteScript(L"empty.ps1", fix);
    ParseReport parsed = ParseWithPowerShell(path);
    REQUIRE(parsed.ok);
    CHECK_EQ(parsed.errors, 0);
    std::set<std::string> commands(parsed.commands.begin(), parsed.commands.end());
    CHECK(commands == std::set<std::string>({ "Write-Host" }));
    ProcessResult run = RunScript(path, L"", "y\r\ny\r\n");
    REQUIRE(run.ran);
    CHECK_EQ(run.exitCode, static_cast<DWORD>(0));
    CHECK(Contains(run.output, "nothing to fix"));
    CHECK(Contains(BuildFixScript({}, options), L"nothing to fix"));   // no results at all
}

// Recent activity checks report events, not settings: a WARNING there is no fix step,
// while a scored check next to it still is.
TEST(FixScript_UnscoredChecksAreNotSteps)
{
    const CheckInfo* events = FindCheckInfo(L"events.defender");
    REQUIRE(events != nullptr);
    CHECK(!events->scored);
    std::vector<SecurityCheckResult> results = {
        Result(L"events.defender", CHECK_WARNING), Result(L"events.logcleared", CHECK_WARNING),
        Result(L"net.llmnr", CHECK_FAIL),
    };
    std::vector<FixStep> steps = BuildFixSteps(results, false, false);
    REQUIRE(steps.size() == 1);
    CHECK_EQ(steps[0].checkId, std::wstring(L"net.llmnr"));
    CHECK(BuildFixSteps(results, true, false).size() == 1);
    CHECK(BuildFixSteps({ Result(L"events.defender", CHECK_WARNING) }, false, false).empty());
}

// ---------------------------------------------------------------------------
// The files: UTF-8 with BOM, CRLF only, the undo script next to the fix script
// ---------------------------------------------------------------------------
TEST(FixScript_FilesAreBomAndCrlf)
{
    SecurityCheckResult wifi = Result(L"net.wifiopen", CHECK_WARNING, L"open:\n  caf\x00e9 \x65e5\x672c\n");
    wifi.targets = { L"caf\x00e9 \x65e5\x672c" };
    std::vector<SecurityCheckResult> results = { wifi, Result(L"hard.bitlocker", CHECK_FAIL, L"BitLocker is off for C:.\r\nsecond line") };
    std::wstring fixPath = tf::TestDir() + L"saved plan.ps1";
    std::wstring undoPath, error;
    FixScriptOptions options;
    REQUIRE(SaveFixScripts(fixPath, results, options, undoPath, error));
    CHECK(error.empty());
    CHECK_EQ(undoPath, tf::TestDir() + L"saved plan-undo.ps1");
    for (const std::wstring& p : { fixPath, undoPath }) {
        std::vector<uint8_t> bytes;
        REQUIRE(ReadBinaryFile(p, bytes, 4 * 1024 * 1024, nullptr));
        REQUIRE(bytes.size() > 3);
        CHECK(bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF);
        size_t lf = 0, crlf = 0, loneCr = 0;
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (bytes[i] == '\n') {
                ++lf;
                if (i > 0 && bytes[i - 1] == '\r') ++crlf;
            }
            if (bytes[i] == '\r' && (i + 1 >= bytes.size() || bytes[i + 1] != '\n')) ++loneCr;
        }
        CHECK(lf > 20);
        CHECK_EQ(lf, crlf);
        CHECK_EQ(loneCr, static_cast<size_t>(0));
        std::wstring text;
        REQUIRE(ReadTextFile(p, text, 4 * 1024 * 1024));
        CHECK(Contains(text, L"caf\x00e9 \x65e5\x672c"));                 // UTF-8 kept the name
        CHECK(Contains(text, L"# Phantom Recon "));
        CHECK(Contains(text, L"saved plan.ps1"));
        CHECK(Contains(text, L"saved plan-undo.ps1"));
        ParseReport parsed = ParseWithPowerShell(p);
        REQUIRE(parsed.ok);
        CHECK_EQ(parsed.errors, 0);
        REQUIRE(parsed.targets.size() == 1);
        CHECK_EQ(parsed.targets[0], Hex(wifi.targets[0]));   // PowerShell 5.1 read the UTF-8 name exactly
    }

    // A folder that does not exist: an error, no crash.
    std::wstring badUndo;
    CHECK(!SaveFixScripts(tf::TestDir() + L"no\\such\\folder\\plan.ps1", results, options, badUndo, error));
    CHECK(!error.empty());
}

// ---------------------------------------------------------------------------
// The plans run: -ListOnly, y, n, "yes", a failing step, the undo in reverse
// ---------------------------------------------------------------------------
TEST(FixScript_RunsOnlyConfirmedSteps)
{
    const std::wstring dir = tf::TestDir();
    std::vector<CheckInfo> catalog = RunnableCatalog(dir);
    std::vector<SecurityCheckResult> results = RunnableResults();
    std::vector<FixStep> steps = BuildFixSteps(results, false, false, catalog);
    std::vector<std::wstring> order = { L"t.crit", L"t.fail", L"t.target", L"t.manual", L"t.low" };
    CHECK(StepIds(steps) == order);

    FixScriptOptions options;
    options.scriptName = L"run.ps1";
    options.undoScriptName = L"run-undo.ps1";
    std::wstring fixText = BuildFixScript(results, options, catalog);
    CHECK(!Contains(fixText, L"WindowsBuiltInRole"));   // no step needs admin, so no guard
    std::wstring fixPath = WriteScript(L"run.ps1", fixText);
    std::wstring undoPath = WriteScript(L"run-undo.ps1", BuildUndoScript(results, options, catalog));

    // Parse before running: the hostile names must be constants before anything executes them.
    ParseReport parsed = ParseWithPowerShell(fixPath);
    REQUIRE(parsed.ok);
    REQUIRE(parsed.errors == 0);
    REQUIRE(parsed.expandable == 0);
    REQUIRE(parsed.targets.size() == HostileSafeNames().size());
    for (size_t i = 0; i < parsed.targets.size(); ++i) REQUIRE(parsed.targets[i] == Hex(HostileSafeNames()[i]));
    for (const std::string& c : parsed.commands) {
        if (c == "Remove-Item" || ToLowerA(c) == "calc") tf::Fail(__FILE__, __LINE__, "a name became a command: " + c);
    }
    REQUIRE(ParseWithPowerShell(undoPath).errors == 0);

    const std::wstring crit = dir + L"crit.txt", low = dir + L"low.txt", targets = dir + L"targets.txt", undone = dir + L"undone.txt";

    // -ListOnly: everything listed, nothing run.
    ProcessResult listed = RunScript(fixPath, L"-ListOnly", "y\r\ny\r\ny\r\n\r\ny\r\n");
    REQUIRE(listed.ran);
    CHECK_EQ(listed.exitCode, static_cast<DWORD>(0));
    CHECK(Contains(listed.output, "List only: nothing was changed. 5 step(s) listed."));
    CHECK(Contains(listed.output, "Note: A note shown before the question."));
    CHECK(!FileThere(crit) && !FileThere(low) && !FileThere(targets));

    // Every answer no: nothing runs, the summary says so.
    ProcessResult no = RunScript(fixPath, L"", "n\r\nn\r\nn\r\n\r\nn\r\n");
    REQUIRE(no.ran);
    CHECK_EQ(no.exitCode, static_cast<DWORD>(0));
    CHECK(Contains(no.output, "Applied: 0. Skipped: 4. Failed: 0. Done by hand: 1."));
    CHECK(!FileThere(crit) && !FileThere(low) && !FileThere(targets));

    // Anything but y skips: "yes" and an empty answer (end of input) too.
    ProcessResult partial = RunScript(fixPath, L"", "yes\r\n");
    REQUIRE(partial.ran);
    CHECK(Contains(partial.output, "Applied: 0. Skipped: 4. Failed: 0. Done by hand: 1."));
    CHECK(!FileThere(crit) && !FileThere(targets));

    // Every answer y: the failing step is caught and counted, the others still run.
    ProcessResult yes = RunScript(fixPath, L"", "y\r\ny\r\ny\r\n\r\nY\r\n");
    REQUIRE(yes.ran);
    CHECK_EQ(yes.exitCode, static_cast<DWORD>(1));   // a step failed
    CHECK(Contains(yes.output, "Applied: 3. Skipped: 0. Failed: 1. Done by hand: 1."));
    CHECK(Contains(yes.output, "Step 2 failed: A command ended with exit code 3."));
    CHECK(Contains(yes.output, "Restart the PC to finish these steps. This script does not restart it:"));
    CHECK(Contains(yes.output, "    Critical step"));
    CHECK(FileThere(crit));
    CHECK(FileThere(low));
    std::vector<std::wstring> written = ReadLines(targets);
    CHECK(written == HostileSafeNames());   // each name reached the command exactly

    // The undo plan, in reverse: low, manual, target, fail (by hand), crit.
    std::vector<FixStep> undoSteps = BuildFixSteps(results, true, false, catalog);
    std::vector<std::wstring> reversed(order.rbegin(), order.rend());
    CHECK(StepIds(undoSteps) == reversed);
    ProcessResult undo = RunScript(undoPath, L"", "y\r\n\r\ny\r\n\r\ny\r\n");
    REQUIRE(undo.ran);
    CHECK_EQ(undo.exitCode, static_cast<DWORD>(0));
    CHECK(Contains(undo.output, "Applied: 3. Skipped: 0. Failed: 0. Done by hand: 2."));
    CHECK(!FileThere(crit));
    CHECK(!FileThere(low));
    CHECK(ReadLines(undone) == HostileSafeNames());
}

// ---------------------------------------------------------------------------
// The catalog's scripts
// ---------------------------------------------------------------------------
namespace {

// Lines that turn protection off. None may appear in a fixScript.
const std::vector<std::wregex>& ProtectionOffPatterns()
{
    static const std::vector<std::wregex> patterns = [] {
        const wchar_t* raw[] = {
            // "Set-MpPreference -Disable<anything> $true" (or 1). The real-time fix itself is
            // "-DisableRealtimeMonitoring $false", which turns protection on.
            L"-disable[a-z]*\\s+(\\$true|1)\\b",
            L"set-mppreference\\s.*-disable[a-z]*\\s+(\\$true|1|yes)\\b",
            L"remove-mppreference",
            L"add-mppreference\\s+-exclusion",
            L"-mapsreporting\\s+(disabled|0)\\b",
            L"-enablecontrolledfolderaccess\\s+disabled",
            L"_actions\\s+disabled",
            L"bcdedit",
            L"(stop|set)-service\\s+(-name\\s+)?(windefend|wdnissvc|securityhealthservice|mpssvc|wscsvc)",
            L"sc(\\.exe)?\\s+(stop|config|delete)\\s+(windefend|wdnissvc|mpssvc)",
            L"disable-bitlocker",
            L"suspend-bitlocker",
            L"disable-computerrestore",
            L"set-netfirewallprofile.*-enabled\\s+(false|\\$false|0)",
            L"netsh\\s+advfirewall.*state\\s+off",
            L"enablelua\\s+-value\\s+0",
            L"hypervisorenforcedcodeintegrity.*-name\\s+enabled\\s+-value\\s+0",
            L"vulnerabledriverblocklistenable\\s+-value\\s+0",
            L"enablescriptblocklogging\\s+-value\\s+0",
            L"-name\\s+runasppl\\s*$",
            L"restart-computer",
            L"shutdown",
            L"set-executionpolicy",
        };
        std::vector<std::wregex> out;
        for (const wchar_t* r : raw) out.emplace_back(r, std::regex_constants::ECMAScript | std::regex_constants::icase);
        return out;
    }();
    return patterns;
}

bool TurnsProtectionOff(const std::wstring& script)
{
    for (const std::wstring& line : SplitW(script, L'\n')) {
        for (const std::wregex& re : ProtectionOffPatterns()) {
            if (std::regex_search(line, re)) return true;
        }
    }
    return false;
}

} // namespace

TEST(FixScript_CatalogScriptsAreSafe)
{
    // The patterns can fail: each of these is caught.
    for (const wchar_t* bad : { L"Set-MpPreference -DisableRealtimeMonitoring $true", L"Set-MpPreference -DisableIOAVProtection 1",
                                L"Remove-MpPreference -ExclusionPath 'C:\\x'", L"Add-MpPreference -ExclusionPath 'C:\\x'",
                                L"bcdedit /set {current} nx AlwaysOff", L"Stop-Service WinDefend", L"Set-Service -Name WinDefend -StartupType Disabled",
                                L"Set-MpPreference -MAPSReporting Disabled", L"Disable-BitLocker -MountPoint C:",
                                L"Set-NetFirewallProfile -Profile Public -Enabled False", L"Restart-Computer -Force",
                                L"Remove-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL" }) {
        if (!TurnsProtectionOff(bad)) tf::Fail(__FILE__, __LINE__, "pattern missed: " + tf::Narrow(bad));
    }
    CHECK(!TurnsProtectionOff(L"Set-MpPreference -DisableRealtimeMonitoring $false"));

    std::set<std::wstring> scripted;
    for (const CheckScript& s : GetCheckScripts()) {
        std::string id = tf::Narrow(s.id);
        if (!scripted.insert(s.id).second) tf::Fail(__FILE__, __LINE__, "two script entries for " + id);
        const CheckInfo* info = FindCheckInfo(s.id);
        if (!info) {
            tf::Fail(__FILE__, __LINE__, "script entry without a catalog row: " + id);
            continue;
        }
        CHECK_EQ(info->fixScript, std::wstring(s.fixScript));
        CHECK_EQ(info->undoScript, std::wstring(s.undoScript));
        if (info->fixScript.empty()) tf::Fail(__FILE__, __LINE__, "empty fixScript for " + id);
        if (TurnsProtectionOff(info->fixScript)) tf::Fail(__FILE__, __LINE__, "fixScript turns protection off: " + id);
        for (const std::wstring* text : { &info->fixScript, &info->undoScript, &info->fixScriptNote, &info->undoScriptNote }) {
            for (wchar_t c : *text) {
                if (c >= 0x80 || c == L'"' || c == L'\r' || c == L'\t') {
                    tf::Fail(__FILE__, __LINE__, "non-ASCII, double quote, CR or tab in the script of " + id);
                    break;
                }
            }
        }
        CHECK_EQ(Contains(info->fixScript, L"$target"), info->scriptPerTarget);
        if (!info->undoScript.empty()) CHECK_EQ(Contains(info->undoScript, L"$target"), info->scriptPerTarget);
        // Every command is in the prose fix: the plan runs what the catalog already tells the user.
        if (!info->scriptPerTarget) {
            for (const std::wstring& line : SplitW(info->fixScript, L'\n')) {
                std::wstring cmd = line.substr(0, line.find(L' '));
                if (!Contains(info->fix, cmd)) tf::Fail(__FILE__, __LINE__, "fixScript command not in the fix text of " + id + ": " + tf::Narrow(cmd));
            }
        }
    }
    // Settings pages, firmware switches and choices stay manual.
    for (const wchar_t* id : { L"def.tamper", L"def.smartscreen", L"hard.smartapp", L"hard.bitlocker", L"hard.secureboot",
                               L"hard.tpm", L"hard.macros", L"lsa.credguard", L"svc.writable", L"svc.unquoted", L"dll.hijack",
                               L"def.exclusions", L"hard.exploitprot", L"net.rdp", L"svc.spooler" }) {
        const CheckInfo* info = FindCheckInfo(id);
        if (info && !info->fixScript.empty()) tf::Fail(__FILE__, __LINE__, "should be a manual step: " + tf::Narrow(id));
    }
    CHECK(scripted.size() >= 25);
}

TEST(FixScript_EveryCatalogScriptParses)
{
    // Every check FAILs at once, so every fix and undo command of the catalog is in one
    // plan, and the real parser must accept all of it.
    std::vector<SecurityCheckResult> results;
    size_t perTargetChecks = 0;
    for (const CheckInfo& info : GetCheckCatalog()) {
        SecurityCheckResult r = Result(info.id, CHECK_FAIL, L"evidence for " + info.id);
        if (info.scriptPerTarget) {
            r.targets = { L"Cafe Free WiFi", L"it's open" };
            ++perTargetChecks;
        }
        results.push_back(r);
    }
    REQUIRE(perTargetChecks > 0);
    FixScriptOptions options;
    std::wstring fix = BuildFixScript(results, options);
    std::wstring undo = BuildUndoScript(results, options);
    size_t commandSteps = 0;
    for (const FixStep& s : BuildFixSteps(results, false, false)) {
        if (s.kind == FixStepKind::Command) ++commandSteps;
    }
    CHECK_EQ(commandSteps, GetCheckScripts().size());
    CHECK_EQ(CountOf(fix, L"Read-Host 'Apply this step? [y/N]'"), commandSteps);
    for (const std::pair<const wchar_t*, std::wstring*> file : { std::make_pair(L"all.ps1", &fix), std::make_pair(L"all-undo.ps1", &undo) }) {
        ParseReport parsed = ParseWithPowerShell(WriteScript(file.first, *file.second));
        REQUIRE(parsed.ok);
        CHECK_EQ(parsed.errors, 0);
        CHECK_EQ(parsed.expandable, 0);
        CHECK_EQ(parsed.targets.size(), 2 * perTargetChecks);   // two names per check that names things one by one
    }
}

// ---------------------------------------------------------------------------
// Console option
// ---------------------------------------------------------------------------
TEST(FixScript_CliOption)
{
    CliOptions ok = ParseCliArguments({ L"--audit", L"--fix-script", L"plan.ps1" });
    CHECK(ok.error.empty());
    CHECK_EQ(ok.fixScriptPath, std::wstring(L"plan.ps1"));
    CHECK(!ParseCliArguments({ L"--audit", L"--fix-script" }).error.empty());                // missing value
    CHECK(!ParseCliArguments({ L"--audit", L"--fix-script", L"" }).error.empty());           // empty value
    CHECK(!ParseCliArguments({ L"--fix-script", L"--audit" }).error.empty());                // next is an option
    CHECK(!ParseCliArguments({ L"--fix-script", L"plan.ps1" }).error.empty());               // needs --audit
    CHECK(!ParseCliArguments({ L"--fast", L"--fix-script", L"plan.ps1" }).error.empty());    // a scan is not an audit
    CHECK(!ParseCliArguments({ L"--audit", L"--fix-script", L"plan.txt" }).error.empty());   // PowerShell runs only .ps1
    CHECK(Contains(CliUsageText(), L"--fix-script <file.ps1>"));

    CliEnvironment env;
    std::wstring out;
    env.out = [&](const std::wstring& t) { out += t; };
    CHECK_EQ(RunCli(ParseCliArguments({ L"--fix-script", L"plan.ps1" }), env), 2);   // nothing to do
    CHECK(Contains(out, L"--audit"));
    out.clear();
    CHECK_EQ(RunCli(ParseCliArguments({ L"--make-samples", tf::TestDir() + L"s", L"--fix-script", L"plan.ps1" }), env), 2);
    CHECK(Contains(out, L"--fix-script writes a fix plan from the audit; add --audit"));
    CHECK(GetFileAttributesW((tf::TestDir() + L"s").c_str()) == INVALID_FILE_ATTRIBUTES);   // a bad command line does nothing
}
