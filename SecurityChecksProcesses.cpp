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
    unsigned long long created = 0;   // FILETIME of the start, 0 when not readable
    bool         pseudo = false;      // kernel pseudo-process (Registry, MemCompression, ...): no file
};

// Only the image name and start time are read (PROCESS_QUERY_LIMITED_INFORMATION); never memory.
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
                    FILETIME created = {}, exited = {}, kernel = {}, user = {};
                    if (GetProcessTimes(h, &created, &exited, &kernel, &user)) {
                        p.created = (static_cast<unsigned long long>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
                    }
                    CloseHandle(h);
                }
                // Elevated, Windows names some kernel pseudo-processes ("Registry",
                // "MemCompression") instead of giving a path. There is no file to check.
                if (IsPseudoProcessImage(p.image)) {
                    DebugLog(L"Pseudo-process " + p.image + L" (pid " + std::to_wstring(p.pid) + L") skipped");
                    p.pseudo = true;
                    p.image.clear();
                }
            }
            out.push_back(p);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

// The parent a snapshot names, if it is still the process that started this one.
// Windows reuses PIDs: when the parent exits, a later process can get its PID.
// confirmed is false when either start time could not be read.
static const ProcessInfo* RealParent(const ProcessInfo& child, const std::map<DWORD, const ProcessInfo*>& byPid, bool& confirmed)
{
    confirmed = false;
    auto parent = byPid.find(child.parentPid);
    if (parent == byPid.end() || child.parentPid == 0) return nullptr;
    int order = ParentStartOrder(parent->second->created, child.created);
    if (order < 0) {
        DebugLog(L"pid " + std::to_wstring(child.pid) + L": parent pid " + std::to_wstring(child.parentPid) +
                 L" now belongs to " + parent->second->name + L", which started later; not its parent");
        return nullptr;
    }
    confirmed = order > 0;
    return parent->second;
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
        if (p.pid <= 4 || p.pid == GetCurrentProcessId() || p.pseudo) continue;
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
        // Parent of core Windows processes, and Office starting a shell or script host.
        // A parent whose start time could not be read may be a later process that got
        // the old PID, so that case is a REVIEW, not a HIGH.
        bool parentConfirmed = false;
        const ProcessInfo* parent = RealParent(p, byPid, parentConfirmed);
        const wchar_t* unconfirmed = L" (start times not readable, so the parent could not be confirmed)";
        std::wstring expectedParent = ExpectedParentProcess(p.name);
        if (!expectedParent.empty() && parent && parent->name != expectedParent) {
            reasons.push_back(L"started by " + parent->name + L" instead of " + expectedParent + (parentConfirmed ? L"" : unconfirmed));
            if (parentConfirmed) severe = true;
        }
        if (IsShellOrScriptHost(p.name) && parent && IsOfficeProcess(parent->name)) {
            reasons.push_back(L"started by " + parent->name + L" (Office starting a shell)" + (parentConfirmed ? L"" : unconfirmed));
            if (parentConfirmed) severe = true;
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
                // Windows' own folders are trusted, except the ones normal users can
                // write to (C:\Windows\Tasks, Temp, Tracing and similar).
                if (!IsProtectedWindowsPath(p.image)) {
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
