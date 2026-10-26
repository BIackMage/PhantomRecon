#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "CheckHelpers.h"
#include "FileAnalysis.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <windows.h>
#include <comdef.h>
#include <taskschd.h>
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
    if (FAILED(task->get_Definition(&def)) || !def) return;

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

static bool IsSystemAccount(const std::wstring& user)
{
    std::wstring u = ToLowerW(user);
    return u == L"system" || u == L"s-1-5-18" || u == L"nt authority\\system" || u == L"localsystem";
}

static bool IsMicrosoftAuthor(const std::wstring& author)
{
    return author.empty() || ContainsI(author, L"Microsoft") || author[0] == L'$' || author[0] == L'@';
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
            // only strong signs count for them.
            bool windowsOwnTask = microsoftFolder && IsUnderWindowsDirectory(program);
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
            if (exists && !IsUnderWindowsDirectory(program)) {
                SignatureSummary sig = GetSignatureSummary(program);
                if (!sig.valid) reasons.push_back(L"program is not validly signed (" + sig.status + L")");
            }
            if (IsSystemAccount(t.userId) && !IsMicrosoftAuthor(t.author) && !microsoftFolder) {
                reasons.push_back(L"runs as SYSTEM, created by " + t.author);
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

    std::wstringstream detail;
    detail << tasks.size() << L" task(s) read";
    if (denied > 0) detail << L", " << denied << L" folder(s) not readable without administrator rights";
    detail << L".\n";
    if (high + medium > 0) detail << L"Flagged:\n" << flagged.str();
    std::wstring inv = inventory.str();
    if (!inv.empty()) detail << L"Tasks outside \\Microsoft\\:\n" << inv;

    if (high > 0) result.status = CHECK_FAIL;
    else if (medium > 0) result.status = CHECK_WARNING;
    else result.status = CHECK_PASS;
    result.detail = detail.str();
    return result;
}
