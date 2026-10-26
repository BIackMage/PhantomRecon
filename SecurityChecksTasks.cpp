#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "CheckHelpers.h"
#include "FileAnalysis.h"
#include "SystemInfo.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <windows.h>
#include <comdef.h>
#include <sddl.h>
#include <taskschd.h>
#include <map>
#include <set>
#include <sstream>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[Tasks] " + msg + L"\n").c_str());
}

struct TaskAction {
    std::wstring path;
    std::wstring arguments;
};

struct TaskInfo {
    std::wstring path;          // \Folder\Name
    std::wstring author;
    std::wstring userId;
    bool         enabled = true;
    bool         highest = false;
    std::vector<std::wstring> triggers;
    std::vector<TaskAction>   actions;
    bool         comHandler = false;
    bool         definitionRead = false;   // false: Windows listed the task but would not show what it runs
};

static std::wstring Bstr(BSTR b)
{
    std::wstring s = b ? std::wstring(b, SysStringLen(b)) : L"";
    if (b) SysFreeString(b);
    return s;
}

static std::wstring TriggerName(TASK_TRIGGER_TYPE2 t)
{
    switch (t) {
    case TASK_TRIGGER_EVENT:                return L"on event";
    case TASK_TRIGGER_TIME:                 return L"once";
    case TASK_TRIGGER_DAILY:                return L"daily";
    case TASK_TRIGGER_WEEKLY:               return L"weekly";
    case TASK_TRIGGER_MONTHLY:              return L"monthly";
    case TASK_TRIGGER_MONTHLYDOW:           return L"monthly";
    case TASK_TRIGGER_IDLE:                 return L"on idle";
    case TASK_TRIGGER_REGISTRATION:         return L"on registration";
    case TASK_TRIGGER_BOOT:                 return L"at boot";
    case TASK_TRIGGER_LOGON:                return L"at logon";
    case TASK_TRIGGER_SESSION_STATE_CHANGE: return L"on session change";
    default:                                return L"custom";
    }
}

static void ReadTask(IRegisteredTask* task, TaskInfo& info)
{
    BSTR path = NULL;
    if (SUCCEEDED(task->get_Path(&path))) info.path = Bstr(path);
    VARIANT_BOOL enabled = VARIANT_TRUE;
    if (SUCCEEDED(task->get_Enabled(&enabled))) info.enabled = enabled == VARIANT_TRUE;

    ITaskDefinition* def = NULL;
    if (FAILED(task->get_Definition(&def)) || !def) {
        DebugLog(L"Definition not readable: " + info.path);
        return;
    }
    info.definitionRead = true;

    IRegistrationInfo* reg = NULL;
    if (SUCCEEDED(def->get_RegistrationInfo(&reg)) && reg) {
        BSTR author = NULL;
        if (SUCCEEDED(reg->get_Author(&author))) info.author = Bstr(author);
        reg->Release();
    }
    IPrincipal* principal = NULL;
    if (SUCCEEDED(def->get_Principal(&principal)) && principal) {
        BSTR user = NULL;
        if (SUCCEEDED(principal->get_UserId(&user))) info.userId = Bstr(user);
        TASK_RUNLEVEL_TYPE level = TASK_RUNLEVEL_LUA;
        if (SUCCEEDED(principal->get_RunLevel(&level))) info.highest = level == TASK_RUNLEVEL_HIGHEST;
        principal->Release();
    }
    ITriggerCollection* triggers = NULL;
    if (SUCCEEDED(def->get_Triggers(&triggers)) && triggers) {
        long count = 0;
        triggers->get_Count(&count);
        for (long i = 1; i <= count; ++i) {
            ITrigger* trigger = NULL;
            if (SUCCEEDED(triggers->get_Item(i, &trigger)) && trigger) {
                TASK_TRIGGER_TYPE2 type;
                if (SUCCEEDED(trigger->get_Type(&type))) info.triggers.push_back(TriggerName(type));
                trigger->Release();
            }
        }
        triggers->Release();
    }
    IActionCollection* actions = NULL;
    if (SUCCEEDED(def->get_Actions(&actions)) && actions) {
        long count = 0;
        actions->get_Count(&count);
        for (long i = 1; i <= count; ++i) {
            IAction* action = NULL;
            if (FAILED(actions->get_Item(i, &action)) || !action) continue;
            TASK_ACTION_TYPE type;
            if (SUCCEEDED(action->get_Type(&type))) {
                if (type == TASK_ACTION_EXEC) {
                    IExecAction* exec = NULL;
                    if (SUCCEEDED(action->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(&exec))) && exec) {
                        TaskAction a;
                        BSTR p = NULL, args = NULL;
                        if (SUCCEEDED(exec->get_Path(&p))) a.path = Bstr(p);
                        if (SUCCEEDED(exec->get_Arguments(&args))) a.arguments = Bstr(args);
                        info.actions.push_back(a);
                        exec->Release();
                    }
                }
                else if (type == TASK_ACTION_COM_HANDLER) {
                    info.comHandler = true;
                }
            }
            action->Release();
        }
        actions->Release();
    }
    def->Release();
}

static void WalkFolder(ITaskFolder* folder, std::vector<TaskInfo>& out, int& denied, int depth)
{
    if (depth > 12) return;
    IRegisteredTaskCollection* tasks = NULL;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
        long count = 0;
        tasks->get_Count(&count);
        for (long i = 1; i <= count; ++i) {
            IRegisteredTask* task = NULL;
            if (SUCCEEDED(tasks->get_Item(_variant_t(i), &task)) && task) {
                TaskInfo info;
                ReadTask(task, info);
                out.push_back(info);
                task->Release();
            }
        }
        tasks->Release();
    }
    else {
        denied++;
    }

    ITaskFolderCollection* subfolders = NULL;
    if (SUCCEEDED(folder->GetFolders(0, &subfolders)) && subfolders) {
        long count = 0;
        subfolders->get_Count(&count);
        for (long i = 1; i <= count; ++i) {
            ITaskFolder* sub = NULL;
            if (SUCCEEDED(subfolders->get_Item(_variant_t(i), &sub)) && sub) {
                WalkFolder(sub, out, denied, depth + 1);
                sub->Release();
            }
        }
        subfolders->Release();
    }
}

// True for the LocalSystem account in any spelling the Task Scheduler stores:
// "SYSTEM", "NT AUTHORITY\SYSTEM", "S-1-5-18", or a localized name such as
// "NT-AUTORITAET\SYSTEM" or "AUTORITE NT\Systeme". Other names are resolved to a SID
// once per audit (cache) and compared with LocalSystem's.
static bool IsSystemAccount(const std::wstring& userIn, std::map<std::wstring, bool>& cache)
{
    std::wstring user = TrimW(userIn);
    std::wstring u = ToLowerW(user);
    if (u.empty()) return false;
    if (u == L"system" || u == L"s-1-5-18" || u == L"nt authority\\system" || u == L"localsystem") return true;
    auto known = cache.find(u);
    if (known != cache.end()) return known->second;

    bool system = false;
    PSID stringSid = NULL;
    if (u.rfind(L"s-1-", 0) == 0) {
        if (ConvertStringSidToSidW(user.c_str(), &stringSid)) {
            system = IsWellKnownSid(stringSid, WinLocalSystemSid) != FALSE;
            LocalFree(stringSid);
        }
    }
    else {
        BYTE sid[SECURITY_MAX_SID_SIZE] = {};
        DWORD sidSize = sizeof(sid);
        wchar_t domain[256] = {};
        DWORD domainSize = 256;
        SID_NAME_USE use;
        if (LookupAccountNameW(NULL, user.c_str(), sid, &sidSize, domain, &domainSize, &use)) {
            system = IsWellKnownSid(sid, WinLocalSystemSid) != FALSE;
        }
    }
    if (system) DebugLog(L"Task account " + user + L" is LocalSystem");
    cache[u] = system;
    return system;
}

// Every registered task is also a file under %SystemRoot%\System32\Tasks, named like
// the task path. A normal user may list the names, while the Task Scheduler API leaves
// out tasks that user may not read. unlisted counts folders that could not be listed.
static void ListTaskFiles(const std::wstring& dir, const std::wstring& relative, std::vector<std::wstring>& out,
                          int depth, int& unlisted)
{
    if (depth > 12) return;
    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW(JoinPath(dir, L"*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        DebugLog(L"Cannot list task folder " + dir + L" (error " + std::to_wstring(GetLastError()) + L")");
        unlisted++;
        return;
    }
    do {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        std::wstring rel = relative + L"\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ListTaskFiles(JoinPath(dir, name), rel, out, depth + 1, unlisted);
        else out.push_back(rel);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

SecurityCheckResult CheckScheduledTasks()
{
    SecurityCheckResult result = MakeCheckResult(L"persist.tasks");
    ComScope com;
    ITaskService* service = NULL;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, reinterpret_cast<void**>(&service));
    if (FAILED(hr) || !service) {
        result.status = CHECK_ERROR;
        result.detail = L"The Task Scheduler API is not available.";
        return result;
    }
    hr = service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    ITaskFolder* root = NULL;
    if (FAILED(hr) || FAILED(service->GetFolder(_bstr_t(L"\\"), &root)) || !root) {
        service->Release();
        result.status = CHECK_ERROR;
        result.detail = L"Could not connect to the Task Scheduler.";
        return result;
    }

    std::vector<TaskInfo> tasks;
    int denied = 0;
    WalkFolder(root, tasks, denied, 0);
    root->Release();
    service->Release();
    DebugLog(L"Read " + std::to_wstring(tasks.size()) + L" tasks");

    std::map<std::wstring, bool> accountCache;
    std::wstringstream flagged;
    std::wstringstream inventory;
    int high = 0, medium = 0;
    for (const TaskInfo& t : tasks) {
        bool microsoftFolder = StartsWithI(t.path, L"\\Microsoft\\");
        for (const TaskAction& a : t.actions) {
            std::wstring program = ProgramFromCommandLine(a.path.find(L' ') != std::wstring::npos && a.path[0] != L'"'
                ? L"\"" + a.path + L"\"" : a.path);
            if (program.find(L'\\') == std::wstring::npos) {
                // Bare name: resolve through the search path the task would use.
                wchar_t full[MAX_PATH] = {};
                if (SearchPathW(NULL, program.c_str(), L".exe", MAX_PATH, full, NULL)) program = full;
            }
            std::wstring command = a.path + (a.arguments.empty() ? L"" : L" " + a.arguments);
            std::vector<std::wstring> reasons;
            std::wstring why;
            bool severe = false;

            // Windows' own tasks run Windows programs with hidden windows all the time;
            // only strong signs count for them. A Windows folder that normal users can
            // write to (Tasks, Temp, Tracing) does not count as Windows' own.
            bool windowsProgram = IsProtectedWindowsPath(program);
            bool windowsOwnTask = microsoftFolder && windowsProgram;
            int strength = CommandLineSuspicion(command, &why);
            if (strength == 2 || (strength == 1 && !windowsOwnTask)) {
                reasons.push_back(why);
                if (strength == 2) severe = true;
            }
            if (IsUserDropLocation(program)) {
                reasons.push_back(L"program is in a user drop folder");
                severe = true;
            }
            bool exists = program.find(L'\\') != std::wstring::npos && FileExists(program);
            if (program.find(L'\\') != std::wstring::npos && !exists) {
                reasons.push_back(L"program file is missing");
            }
            SignatureSummary sig;
            bool sigRead = false;
            if (exists && SignatureExpected(program)) {
                sig = GetSignatureSummary(program);
                sigRead = true;
                if (!sig.valid && !windowsProgram) reasons.push_back(L"program is not validly signed (" + sig.status + L")");
            }

            // The file a host program runs: "rundll32 C:\x\e.dll", "wscript C:\x\s.vbs",
            // "powershell -File C:\x\s.ps1", "cmd /c C:\x\e.exe".
            std::wstring payload = ScriptHostPayload(command);
            if (!payload.empty() && payload.find(L'\\') == std::wstring::npos) {
                wchar_t full[MAX_PATH] = {};
                payload = SearchPathW(NULL, payload.c_str(), NULL, MAX_PATH, full, NULL) ? std::wstring(full) : L"";
            }
            if (EqualsI(payload, program)) payload.clear();
            bool payloadMicrosoft = true;
            if (!payload.empty()) {
                DebugLog(L"Task " + t.path + L" runs " + payload);
                if (!FileExists(payload)) {
                    reasons.push_back(L"the file it runs is missing: " + payload);
                    payloadMicrosoft = false;
                }
                else if (IsUserDropLocation(payload)) {
                    reasons.push_back(L"it runs " + payload + L", which is in a user drop folder");
                    severe = true;
                    payloadMicrosoft = false;
                }
                else if (SignatureExpected(payload)) {
                    SignatureSummary payloadSig = GetSignatureSummary(payload);
                    payloadMicrosoft = payloadSig.microsoft;
                    if (!payloadSig.valid && !IsProtectedWindowsPath(payload)) {
                        reasons.push_back(L"the file it runs is not validly signed (" + payloadSig.status + L"): " + payload);
                    }
                }
                else {
                    payloadMicrosoft = IsProtectedWindowsPath(payload);
                }
            }

            // A SYSTEM task outside \Microsoft\ is Windows' own only when the author says
            // Microsoft and what it runs is signed by Microsoft. The author is free text
            // and is often left empty, so it alone proves nothing.
            if (!microsoftFolder && IsSystemAccount(t.userId, accountCache)) {
                if (exists && !sigRead) {
                    sig = GetSignatureSummary(program);
                    sigRead = true;
                }
                bool microsoftCode = sigRead && sig.microsoft && payloadMicrosoft;
                if (!IsMicrosoftTaskAuthor(t.author) || !microsoftCode) {
                    reasons.push_back(L"runs as SYSTEM, created by " + (t.author.empty() ? std::wstring(L"(no author recorded)") : t.author));
                }
            }

            if (!reasons.empty() && t.enabled) {
                if (severe) high++; else medium++;
                flagged << L"  " << (severe ? L"[HIGH] " : L"[REVIEW] ") << t.path << L"\n"
                        << L"      runs: " << command << L"\n"
                        << L"      as " << (t.userId.empty() ? L"(interactive user)" : t.userId)
                        << L", " << (t.triggers.empty() ? L"no trigger" : JoinW(t.triggers, L", "))
                        << L"\n      why: " << JoinW(reasons, L"; ") << L"\n";
            }
            if (!microsoftFolder) {
                inventory << L"  " << t.path << (t.enabled ? L"" : L" (disabled)") << L": " << command << L"\n";
            }
        }
    }

    // Tasks that exist but were not read: Windows hides tasks a normal user may not
    // read, and a task whose security entry was removed from the registry is hidden
    // from everyone while it keeps running.
    std::set<std::wstring> readPaths;
    for (const TaskInfo& t : tasks) {
        if (t.definitionRead) readPaths.insert(ToLowerW(t.path));
    }
    std::wstring tasksDir = ExpandEnvironment(L"%SystemRoot%\\System32\\Tasks");
    std::vector<std::wstring> taskFiles;
    int unlistedFolders = 0;
    bool haveDir = DirectoryExists(tasksDir);
    if (haveDir) ListTaskFiles(tasksDir, L"", taskFiles, 0, unlistedFolders);
    CappedList unreadOther(30), unreadMicrosoft(30);
    for (const std::wstring& f : taskFiles) {
        if (readPaths.count(ToLowerW(f))) continue;
        if (StartsWithI(f, L"\\Microsoft\\")) unreadMicrosoft.Add(L"  " + f + L"\n");
        else unreadOther.Add(L"  " + f + L"\n");
    }
    size_t unread = unreadOther.Total() + unreadMicrosoft.Total();
    bool elevated = IsProcessElevated();
    DebugLog(std::to_wstring(taskFiles.size()) + L" task files on disk, " + std::to_wstring(unread) + L" not readable through the API");

    std::wstringstream detail;
    detail << tasks.size() << L" task(s) read";
    if (haveDir) detail << L", " << taskFiles.size() << L" task file(s) on disk";
    if (denied > 0) detail << L", " << denied << L" folder(s) not readable without administrator rights";
    detail << L".\n";
    if (!haveDir) {
        detail << L"The task folder " << tasksDir << L" could not be read, so tasks hidden from this account may be missed.\n";
    }
    else if (unlistedFolders > 0) {
        detail << unlistedFolders << L" folder(s) under " << tasksDir << L" could not be listed by this account, so tasks in them may be missed.\n";
    }
    if (unread > 0) {
        if (elevated) {
            detail << unread << L" task file(s) exist that the Task Scheduler does not show even to an administrator. "
                   << L"A task hidden this way still runs. Look at these files:\n";
            detail << unreadOther.Text() << unreadMicrosoft.Text();
        }
        else {
            detail << unread << L" task(s) exist that Windows does not let this account read (" << unreadMicrosoft.Total()
                   << L" of them under \\Microsoft\\). Run as administrator to check what they run.\n";
            if (!unreadOther.Empty()) detail << L"Not readable, outside \\Microsoft\\:\n" << unreadOther.Text();
        }
    }
    if (high + medium > 0) detail << L"Flagged:\n" << flagged.str();
    std::wstring inv = inventory.str();
    if (!inv.empty()) detail << L"Tasks outside \\Microsoft\\:\n" << inv;

    // Tasks that could not be checked are not a pass: as a normal user the ones outside
    // \Microsoft\ are unknown; as administrator any task hidden from the API is suspect.
    bool uncheckedTasks = elevated ? unread > 0 : !unreadOther.Empty();
    if (high > 0) result.status = CHECK_FAIL;
    else if (medium > 0 || uncheckedTasks) result.status = CHECK_WARNING;
    else result.status = CHECK_PASS;
    result.detail = detail.str();
    return result;
}
