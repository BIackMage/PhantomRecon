// Review fixes for the night features (fix plan, Recent activity checks): registry
// keys the fix commands must not wipe, the undo of the log sizes, names that end in
// a backslash, local account names for the Administrators check, and the local time
// of an event across a daylight saving change.

#include "TestFramework.h"

#include "CheckCatalog.h"
#include "CheckScripts.h"
#include "EventLogQuery.h"
#include "EventRules.h"
#include "FileIO.h"
#include "FixScript.h"
#include "SecurityChecks.h"
#include "SecurityChecksEvents.h"
#include "TextUtils.h"

#include <windows.h>
#include <cstdio>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <vector>

namespace {

std::vector<std::wstring> Lines(const std::wstring& text)
{
    std::vector<std::wstring> out;
    for (const std::wstring& line : SplitW(text, L'\n')) {
        std::wstring t = TrimW(line);
        if (!t.empty()) out.push_back(t);
    }
    return out;
}

bool IsRegistryNewItem(const std::wstring& line)
{
    return line.find(L"New-Item") != std::wstring::npos &&
           (line.find(L"'HKLM:") != std::wstring::npos || line.find(L"'HKCU:") != std::wstring::npos);
}

// Runs a script with Windows PowerShell and returns what it printed, "" when it did not run.
std::string RunPowerShellScript(const std::wstring& name, const std::string& script)
{
    std::wstring scriptPath = tf::TestDir() + name + L".ps1";
    std::wstring outPath = tf::TestDir() + name + L".out.txt";
    if (!WriteBinaryFile(scriptPath, script.data(), script.size())) return "";
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE out = CreateFileW(outPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) return "";
    wchar_t root[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
    std::wstring exe = ((n > 0 && n < MAX_PATH) ? std::wstring(root) : std::wstring(L"C:\\Windows")) +
                       L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    std::wstring cmd = L"\"" + exe + L"\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + scriptPath + L"\"";
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = NULL;
    si.hStdOutput = out;
    si.hStdError = out;
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(NULL, &cmd[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(out);
    if (!ok) {
        std::printf("    note: powershell.exe did not start (error %lu)\n", GetLastError());
        return "";
    }
    if (WaitForSingleObject(pi.hProcess, 120000) != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 99);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    std::vector<uint8_t> bytes;
    ReadBinaryFile(outPath, bytes, 1024 * 1024, nullptr);
    return std::string(bytes.begin(), bytes.end());
}

size_t Count(const std::string& text, const std::string& part)
{
    size_t c = 0;
    for (size_t p = text.find(part); p != std::string::npos; p = text.find(part, p + part.size())) ++c;
    return c;
}

} // namespace

// ---------------------------------------------------------------------------
// New-Item -Force on a registry key that already exists deletes every value and
// subkey under it (Windows PowerShell 5.1). The fix commands only create a key that
// is missing, so policies already there survive.
// ---------------------------------------------------------------------------
TEST(FixNight_RegistryKeyCreationKeepsExistingValues)
{
    static const std::wregex guarded(
        L"^if \\(-not \\(Test-Path '([^']+)'\\)\\) \\{ New-Item '([^']+)' -Force \\| Out-Null \\}$");
    std::vector<std::wstring> scriptLines;
    size_t checked = 0;
    for (const CheckInfo& info : GetCheckCatalog()) {
        for (const std::wstring* text : { &info.fix, &info.undo, &info.fixScript, &info.undoScript }) {
            for (const std::wstring& line : Lines(*text)) {
                if (!IsRegistryNewItem(line)) continue;
                ++checked;
                std::wsmatch m;
                if (!std::regex_match(line, m, guarded) || m[1].str() != m[2].str()) {
                    tf::Fail(__FILE__, __LINE__, "New-Item on an existing key wipes it: " + tf::Narrow(info.id) + ": " + tf::Narrow(line));
                }
                if (text == &info.fixScript || text == &info.undoScript) scriptLines.push_back(line);
            }
        }
    }
    CHECK(checked >= 14);   // 8 lines in the fix texts, 7 in the scripts
    REQUIRE(!scriptLines.empty());

    // Run each script line for real, on a key under HKCU that already holds a value.
    wchar_t base[96];
    swprintf_s(base, L"HKCU:\\Software\\PhantomReconTests-%lu", GetCurrentProcessId());
    std::string ps = "$ErrorActionPreference = 'Stop'\r\n";
    static const std::wregex hklmPath(L"'(HKLM:[^']+)'");
    for (size_t i = 0; i < scriptLines.size(); ++i) {
        std::wsmatch m;
        REQUIRE(std::regex_search(scriptLines[i], m, hklmPath));
        std::wstring key = std::wstring(base) + L"\\Key" + std::to_wstring(i);
        std::wstring line = ReplaceAllW(scriptLines[i], m[1].str(), key);
        // Safety: the line runs for real, so nothing in it may still name the machine hive.
        REQUIRE(line.find(L"HKLM:") == std::wstring::npos);
        REQUIRE(line.find(std::wstring(base)) != std::wstring::npos);
        std::string k = tf::Narrow(key);
        ps += "New-Item '" + k + "\\Sub' -Force | Out-Null\r\n";
        ps += "Set-ItemProperty '" + k + "' -Name Keep -Value 7 -Type DWord\r\n";
        ps += tf::Narrow(line) + "\r\n";
        ps += "if ((Get-ItemProperty '" + k + "').Keep -eq 7 -and (Test-Path '" + k + "\\Sub')) { Write-Output 'kept " +
              std::to_string(i) + "' } else { Write-Output 'lost " + std::to_string(i) + "' }\r\n";
    }
    ps += "Remove-Item '" + tf::Narrow(base) + "' -Recurse -Force\r\n";
    ps += "if (Test-Path '" + tf::Narrow(base) + "') { Write-Output 'not cleaned' } else { Write-Output 'cleaned' }\r\n";
    std::string output = RunPowerShellScript(L"newitem-keeps", ps);
    std::printf("    note: %zu script line(s) run on HKCU test keys\n", scriptLines.size());
    CHECK_EQ(Count(output, "kept "), scriptLines.size());
    CHECK_EQ(Count(output, "lost "), static_cast<size_t>(0));
    CHECK(output.find("cleaned") != std::string::npos && output.find("not cleaned") == std::string::npos);
    if (Count(output, "kept ") != scriptLines.size()) std::printf("    output: %s\n", output.c_str());
}

// ---------------------------------------------------------------------------
// Undo puts back every log size the fix changes (audit.policy also grows the
// PowerShell operational log).
// ---------------------------------------------------------------------------
TEST(FixNight_UndoResetsEveryLogTheFixResizes)
{
    static const std::wregex resize(L"^wevtutil sl (\\S+) .*/ms:\\d+.*$");
    size_t logs = 0;
    for (const CheckInfo& info : GetCheckCatalog()) {
        for (const std::pair<const std::wstring*, const std::wstring*> pair :
             { std::make_pair(&info.fix, &info.undo), std::make_pair(&info.fixScript, &info.undoScript) }) {
            for (const std::wstring& line : Lines(*pair.first)) {
                std::wsmatch m;
                if (!std::regex_match(line, m, resize)) continue;
                ++logs;
                std::wstring want = L"wevtutil sl " + m[1].str() + L" /ms:";
                bool undone = false;
                for (const std::wstring& u : Lines(*pair.second)) {
                    if (u.rfind(want, 0) == 0) undone = true;
                }
                if (!undone) tf::Fail(__FILE__, __LINE__, tf::Narrow(info.id) + ": the undo does not reset " + tf::Narrow(m[1].str()));
            }
        }
    }
    CHECK_EQ(logs, static_cast<size_t>(4));   // Security and PowerShell/Operational, in the text and the script
    const CheckInfo* audit = FindCheckInfo(L"audit.policy");
    REQUIRE(audit != nullptr);
    CHECK(audit->undoScript.find(L"wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:15728640") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// A name ending in a backslash reaches a native program mangled when PowerShell 5.1
// quotes it, so its step is done by hand.
// ---------------------------------------------------------------------------
TEST(FixNight_TrailingBackslashNameIsManual)
{
    CHECK(!IsScriptSafeValue(L"Cafe Net\\"));
    CHECK(!IsScriptSafeValue(L"Net\\"));
    CHECK(!IsScriptSafeValue(L"\\"));
    CHECK(IsScriptSafeValue(L"Cafe\\Net"));
    CHECK(IsScriptSafeValue(L"Cafe Net"));

    SecurityCheckResult wifi = MakeCheckResult(L"net.wifiopen");
    wifi.status = CHECK_WARNING;
    wifi.detail = L"1 saved Wi-Fi network(s) without a password connect automatically.";
    wifi.targets = { L"Cafe Net\\" };
    std::vector<FixStep> steps = BuildFixSteps({ wifi }, false, false);
    REQUIRE(steps.size() == 1);
    CHECK(steps[0].kind == FixStepKind::Manual);
    CHECK(steps[0].manualReason.find(L"backslash at the end") != std::wstring::npos);
    CHECK(steps[0].commands.empty());
}

// ---------------------------------------------------------------------------
// events.newaccounts names a member it only has as a SID through the local account
// database; that lookup must find the accounts.
// ---------------------------------------------------------------------------
TEST(FixNight_LocalAccountSidsFindTheAccounts)
{
    std::map<std::wstring, std::wstring> sids = LocalAccountSids();
    std::printf("    note: %zu local account(s)\n", sids.size());
    REQUIRE(!sids.empty());
    std::wstring adminSid, adminName;
    for (const auto& entry : sids) {
        CHECK(entry.first.rfind(L"S-1-5-21-", 0) == 0);
        CHECK(!entry.second.empty());
        if (entry.first.size() > 4 && entry.first.compare(entry.first.size() - 4, 4, L"-500") == 0) {
            adminSid = entry.first;
            adminName = entry.second;
        }
    }
    REQUIRE(!adminSid.empty());   // the built-in Administrator account (RID 500) is always in the database

    EventRecord added;
    added.id = 4732;
    added.timeText = L"2026-10-23 12:00";
    added.data = { { L"MemberName", L"-" }, { L"MemberSid", adminSid }, { L"TargetSid", L"S-1-5-32-544" },
                   { L"SubjectUserName", L"someone" } };
    EventQueryResult security;
    security.channel = L"Security";
    security.events = { added };
    EventVerdict v = NewAccountsVerdict(security, sids);
    CHECK(v.detail.find(L"added to the Administrators group: " + adminName + L",") != std::wstring::npos);
}

// ---------------------------------------------------------------------------
// The local time of an event uses the daylight saving rule of its own date.
// ---------------------------------------------------------------------------
TEST(FixNight_EventTimeUsesDaylightRuleOfThatDate)
{
    CHECK_EQ(EventTimeText(0), std::wstring(L"(time unknown)"));
    for (WORD month : { static_cast<WORD>(1), static_cast<WORD>(7) }) {
        SYSTEMTIME utc = {};
        utc.wYear = 2026;
        utc.wMonth = month;
        utc.wDay = 15;
        utc.wHour = 12;
        FILETIME ft = {};
        REQUIRE(SystemTimeToFileTime(&utc, &ft));
        SYSTEMTIME local = {};
        REQUIRE(SystemTimeToTzSpecificLocalTime(NULL, &utc, &local));
        wchar_t expected[40];
        swprintf_s(expected, L"%04u-%02u-%02u %02u:%02u", local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute);
        ULARGE_INTEGER li;
        li.LowPart = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        CHECK_EQ(EventTimeText(li.QuadPart), std::wstring(expected));
    }
}
