#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "Baseline.h"
#include "CheckHelpers.h"
#include "FileAnalysis.h"
#include "HashUtils.h"
#include "SystemInfo.h"
#include "TextUtils.h"

#include <windows.h>
#include <tlhelp32.h>
#include <map>
#include <set>
#include <sstream>


static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[Processes] " + msg + L"\n").c_str());
}

struct ProcessInfo {
    DWORD        pid = 0;
    DWORD        parentPid = 0;
    std::wstring name;        // lowercase exe name
    std::wstring image;       // full path, "" when not accessible
};

static std::vector<ProcessInfo> SnapshotProcesses()
{
    std::vector<ProcessInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo p;
            p.pid = pe.th32ProcessID;
            p.parentPid = pe.th32ParentProcessID;
            p.name = ToLowerW(pe.szExeFile);
            if (p.pid > 4) {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
                if (h) {
                    wchar_t path[MAX_PATH * 2] = {};
                    DWORD size = MAX_PATH * 2;
                    if (QueryFullProcessImageNameW(h, 0, path, &size)) p.image = path;
                    CloseHandle(h);
                }
            }
            out.push_back(p);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

// ---------------------------------------------------------------------------
// Running programs
// ---------------------------------------------------------------------------
SecurityCheckResult CheckRunningPrograms(const AuditContext& context)
{
    SecurityCheckResult result = MakeCheckResult(L"proc.image");
    std::vector<ProcessInfo> processes = SnapshotProcesses();
    std::map<DWORD, const ProcessInfo*> byPid;
    for (const ProcessInfo& p : processes) byPid[p.pid] = &p;

    CappedList highList(60), reviewList(60), baselineNotes(30);
    int inaccessible = 0;
    std::set<std::wstring> checkedImages;
    int inBaseline = 0, notInBaseline = 0, outsideBaseline = 0, changed = 0;

    for (const ProcessInfo& p : processes) {
        if (p.pid <= 4 || p.pid == GetCurrentProcessId()) continue;
        std::vector<std::wstring> reasons;
        bool severe = false;

        // Masquerading: a Windows process name running from the wrong folder
        std::wstring expected = ExpectedSystemProcessFolder(p.name);
        if (!expected.empty() && !p.image.empty()) {
            std::wstring folder = ToLowerW(DirectoryOf(p.image));
            if (folder != expected) {
                reasons.push_back(L"has a Windows process name but runs from " + DirectoryOf(p.image));
                severe = true;
            }
        }
        // Parent of core Windows processes
        std::wstring expectedParent = ExpectedParentProcess(p.name);
        if (!expectedParent.empty()) {
            auto parent = byPid.find(p.parentPid);
            if (parent != byPid.end() && parent->second->name != expectedParent) {
                reasons.push_back(L"started by " + parent->second->name + L" instead of " + expectedParent);
                severe = true;
            }
        }
        // Office starting a shell or script host
        if (IsShellOrScriptHost(p.name)) {
            auto parent = byPid.find(p.parentPid);
            if (parent != byPid.end() && IsOfficeProcess(parent->second->name)) {
                reasons.push_back(L"started by " + parent->second->name + L" (Office starting a shell)");
                severe = true;
            }
        }

        if (p.image.empty()) {
            inaccessible++;
        }
        else {
            if (IsUserDropLocation(p.image)) {
                reasons.push_back(L"runs from a user drop folder");
            }
            std::wstring key = ToLowerW(p.image);
            if (checkedImages.insert(key).second) {
                if (!IsUnderWindowsDirectory(p.image) || IsUserDropLocation(p.image)) {
                    SignatureSummary sig = GetSignatureSummary(p.image);
                    if (!sig.valid && IsUserDropLocation(p.image)) {
                        reasons.push_back(L"unsigned program in a user drop folder");
                        severe = true;
                    }
                    else if (!sig.valid) {
                        reasons.push_back(L"not validly signed (" + sig.status + L")");
                    }
                }
                if (context.baseline) {
                    const BaselineEntry* b = context.baseline->FindEntry(p.image);
                    if (!b && !context.baseline->CoversFolderOf(p.image)) {
                        outsideBaseline++;   // the baseline never recorded this folder
                    }
                    else if (!b) {
                        notInBaseline++;
                        baselineNotes.Add(L"  not in baseline: " + p.image + L"\n");
                    }
                    else {
                        inBaseline++;
                        std::wstring sha = ComputeFileSHA256(ToExtendedPath(p.image));
                        if (!sha.empty() && !b->sha256.empty() && !EqualsI(sha, b->sha256)) {
                            changed++;
                            reasons.push_back(L"file changed since the baseline");
                        }
                    }
                }
            }
        }

        if (!reasons.empty()) {
            std::wstring line = std::wstring(L"  ") + (severe ? L"[HIGH] " : L"[REVIEW] ") + p.name + L" (pid " +
                std::to_wstring(p.pid) + L")" + (p.image.empty() ? L"" : L"\n      " + p.image) +
                L"\n      why: " + JoinW(reasons, L"; ") + L"\n";
            if (severe) highList.Add(line);
            else reviewList.Add(line);
        }
    }
    size_t high = highList.Total();
    size_t review = reviewList.Total();

    std::wstringstream detail;
    detail << processes.size() << L" process(es) running";
    if (inaccessible > 0) detail << L"; " << inaccessible << L" could not be opened" << (IsProcessElevated() ? L"" : L" (run as administrator to see them)");
    detail << L".\n";
    if (context.baseline) {
        detail << L"Against the baseline: " << inBaseline << L" program(s) known, " << changed << L" changed, "
               << notInBaseline << L" not in it although their folder is, " << outsideBaseline
               << L" in folders the baseline does not cover.\n";
    }
    if (high + review > 0) detail << L"Flagged:\n" << highList.Text() << reviewList.Text();
    if (notInBaseline > 0) detail << L"Programs not in the baseline:\n" << baselineNotes.Text();

    result.status = high > 0 ? CHECK_FAIL : (review > 0 || changed > 0 ? CHECK_WARNING : CHECK_PASS);
    result.detail = detail.str();
    return result;
}
