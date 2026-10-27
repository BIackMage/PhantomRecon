#include "pch.h"
#include "ScheduledScan.h"

#include "AppPaths.h"
#include "Baseline.h"
#include "WmiQuery.h"

#include <windows.h>
#include <comdef.h>
#include <taskschd.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[ScheduledScan] " + msg + L"\n").c_str());
}

std::wstring WeeklyScanTaskName()
{
    return L"Phantom Recon Weekly Fast Scan";
}

std::wstring WeeklyScanArguments(const std::wstring& baselinePath, const std::wstring& reportsDir, bool auditHistory)
{
    // Every path is a file inside a folder, never one ending in a backslash, so the
    // closing quote is never escaped when the program splits its command line.
    std::wstring args = L"--fast --audit --baseline \"" + baselinePath + L"\" --report \"" +
                        JoinPath(reportsDir, L"weekly_report.html") + L"\" --csv \"" + JoinPath(reportsDir, L"weekly_scan.csv") +
                        L"\" --notify-on-change --quiet";
    if (!auditHistory) args += L" --no-history";
    return args;
}

std::wstring WeeklyTaskCommandLine(const std::wstring& exePath, const std::wstring& arguments)
{
    return L"\"" + exePath + L"\" " + arguments;
}

WeeklyTaskPlan PlanWeeklyTask(const std::wstring& exePath, const std::wstring& baselinePath, const std::wstring& reportsDir,
                              bool auditHistory, bool portable)
{
    WeeklyTaskPlan plan;
    if (portable) {
        plan.error = L"Portable mode never creates scheduled tasks.";
    }
    else if (exePath.empty() || baselinePath.empty() || reportsDir.empty()) {
        plan.error = L"The weekly task needs the program, a baseline and a reports folder.";
    }
    else {
        plan.ok = true;
        plan.exePath = exePath;
        plan.arguments = WeeklyScanArguments(baselinePath, reportsDir, auditHistory);
        plan.commandLine = WeeklyTaskCommandLine(exePath, plan.arguments);
    }
    DebugLog(plan.ok ? L"Plan: " + plan.commandLine : L"Plan refused: " + plan.error);
    return plan;
}

static std::wstring HrText(HRESULT hr)
{
    wchar_t buf[32];
    swprintf_s(buf, L"0x%08X", static_cast<unsigned int>(hr));
    return buf;
}

// Next Sunday at 10:00 local time, as the ISO string Task Scheduler wants.
static std::wstring NextSundayMorning()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER t;
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    int days = (7 - st.wDayOfWeek) % 7;
    if (days == 0) days = 7;
    t.QuadPart += static_cast<ULONGLONG>(days) * 864000000000ULL;
    ft.dwLowDateTime = t.LowPart;
    ft.dwHighDateTime = t.HighPart;
    SYSTEMTIME next;
    FileTimeToSystemTime(&ft, &next);
    wchar_t buf[40];
    swprintf_s(buf, L"%04u-%02u-%02uT10:00:00", next.wYear, next.wMonth, next.wDay);
    return buf;
}

static ITaskService* ConnectService(std::wstring& error)
{
    ITaskService* service = NULL;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, reinterpret_cast<void**>(&service));
    if (FAILED(hr) || !service) {
        error = L"Task Scheduler is not available (" + HrText(hr) + L")";
        return NULL;
    }
    hr = service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        service->Release();
        error = L"Could not connect to Task Scheduler (" + HrText(hr) + L")";
        return NULL;
    }
    return service;
}

bool RegisterWeeklyScan(const std::wstring& exePath, const std::wstring& baselinePath, const std::wstring& reportsDir,
                        bool auditHistory, std::wstring& commandLine, std::wstring& error)
{
    commandLine.clear();
    // A task without a usable baseline would fail every Sunday, quietly. Refuse instead.
    Baseline check;
    if (baselinePath.empty() || !FileExists(baselinePath) || !check.LoadFromFile(baselinePath)) {
        error = L"There is no usable baseline at " + baselinePath + L", so the weekly scan would fail every week. "
                L"Take a baseline first. No task was created.";
        DebugLog(L"Register refused: " + error);
        return false;
    }
    WeeklyTaskPlan plan = PlanWeeklyTask(exePath, baselinePath, reportsDir, auditHistory, IsPortableMode());
    if (!plan.ok) {
        error = plan.error;
        DebugLog(L"Register refused: " + error);
        return false;
    }
    ComScope com;
    ITaskService* service = ConnectService(error);
    if (!service) return false;

    bool ok = false;
    ITaskFolder* root = NULL;
    ITaskDefinition* task = NULL;
    HRESULT hr = service->GetFolder(_bstr_t(L"\\"), &root);
    if (SUCCEEDED(hr)) hr = service->NewTask(0, &task);
    if (SUCCEEDED(hr)) {
        IRegistrationInfo* info = NULL;
        if (SUCCEEDED(task->get_RegistrationInfo(&info)) && info) {
            info->put_Author(_bstr_t(L"Phantom Recon"));
            info->put_Description(_bstr_t(L"Weekly check-up: a Fast Scan against your Phantom Recon baseline and the security "
                                          L"audit, with a notification when something got worse. Remove it from Phantom "
                                          L"Recon's Scans menu or with PhantomReconCli.exe --unschedule-weekly."));
            info->Release();
        }
        IPrincipal* principal = NULL;
        if (SUCCEEDED(task->get_Principal(&principal)) && principal) {
            principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
            principal->put_RunLevel(TASK_RUNLEVEL_LUA);
            principal->Release();
        }
        ITaskSettings* settings = NULL;
        if (SUCCEEDED(task->get_Settings(&settings)) && settings) {
            settings->put_StartWhenAvailable(VARIANT_TRUE);
            settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
            settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
            settings->put_ExecutionTimeLimit(_bstr_t(L"PT2H"));
            settings->Release();
        }
        ITriggerCollection* triggers = NULL;
        ITrigger* trigger = NULL;
        IWeeklyTrigger* weekly = NULL;
        if (SUCCEEDED(task->get_Triggers(&triggers)) && triggers &&
            SUCCEEDED(triggers->Create(TASK_TRIGGER_WEEKLY, &trigger)) && trigger &&
            SUCCEEDED(trigger->QueryInterface(IID_IWeeklyTrigger, reinterpret_cast<void**>(&weekly))) && weekly) {
            weekly->put_StartBoundary(_bstr_t(NextSundayMorning().c_str()));
            weekly->put_DaysOfWeek(1);     // Sunday
            weekly->put_WeeksInterval(1);
        }
        else {
            hr = E_FAIL;
        }
        if (weekly) weekly->Release();
        if (trigger) trigger->Release();
        if (triggers) triggers->Release();

        IActionCollection* actions = NULL;
        IAction* action = NULL;
        IExecAction* exec = NULL;
        if (SUCCEEDED(hr) && SUCCEEDED(task->get_Actions(&actions)) && actions &&
            SUCCEEDED(actions->Create(TASK_ACTION_EXEC, &action)) && action &&
            SUCCEEDED(action->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(&exec))) && exec) {
            exec->put_Path(_bstr_t(plan.exePath.c_str()));
            exec->put_Arguments(_bstr_t(plan.arguments.c_str()));
            exec->put_WorkingDirectory(_bstr_t(DirectoryOf(plan.exePath).c_str()));
        }
        else if (SUCCEEDED(hr)) {
            hr = E_FAIL;
        }
        if (exec) exec->Release();
        if (action) action->Release();
        if (actions) actions->Release();

        if (SUCCEEDED(hr)) {
            IRegisteredTask* registered = NULL;
            hr = root->RegisterTaskDefinition(_bstr_t(WeeklyScanTaskName().c_str()), task, TASK_CREATE_OR_UPDATE,
                _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""), &registered);
            if (registered) registered->Release();
        }
        ok = SUCCEEDED(hr);
        if (!ok) error = L"Could not create the task (" + HrText(hr) + L")";
    }
    else {
        error = L"Could not prepare the task (" + HrText(hr) + L")";
    }
    if (task) task->Release();
    if (root) root->Release();
    service->Release();
    if (ok) commandLine = plan.commandLine;
    DebugLog(ok ? L"Registered weekly scan: " + plan.commandLine : L"Register failed: " + error);
    return ok;
}

bool RemoveWeeklyScan(std::wstring& error)
{
    ComScope com;
    ITaskService* service = ConnectService(error);
    if (!service) return false;
    ITaskFolder* root = NULL;
    HRESULT hr = service->GetFolder(_bstr_t(L"\\"), &root);
    if (SUCCEEDED(hr)) {
        hr = root->DeleteTask(_bstr_t(WeeklyScanTaskName().c_str()), 0);
        root->Release();
    }
    service->Release();
    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) return true;
    if (FAILED(hr)) {
        error = L"Could not remove the task (" + HrText(hr) + L")";
        return false;
    }
    DebugLog(L"Removed weekly scan");
    return true;
}

bool IsWeeklyScanRegistered()
{
    ComScope com;
    std::wstring error;
    ITaskService* service = ConnectService(error);
    if (!service) return false;
    bool found = false;
    ITaskFolder* root = NULL;
    if (SUCCEEDED(service->GetFolder(_bstr_t(L"\\"), &root)) && root) {
        IRegisteredTask* task = NULL;
        if (SUCCEEDED(root->GetTask(_bstr_t(WeeklyScanTaskName().c_str()), &task)) && task) {
            found = true;
            task->Release();
        }
        root->Release();
    }
    service->Release();
    return found;
}

// The first exec action of a task definition.
static bool ReadExecAction(ITaskDefinition* definition, std::wstring& exePath, std::wstring& arguments)
{
    bool ok = false;
    IActionCollection* actions = NULL;
    IAction* action = NULL;
    IExecAction* exec = NULL;
    if (SUCCEEDED(definition->get_Actions(&actions)) && actions &&
        SUCCEEDED(actions->get_Item(1, &action)) && action &&
        SUCCEEDED(action->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(&exec))) && exec) {
        BSTR path = NULL;
        BSTR args = NULL;
        if (SUCCEEDED(exec->get_Path(&path))) {
            exePath = path ? path : L"";
            ok = true;
        }
        if (SUCCEEDED(exec->get_Arguments(&args))) arguments = args ? args : L"";
        if (path) SysFreeString(path);
        if (args) SysFreeString(args);
    }
    if (exec) exec->Release();
    if (action) action->Release();
    if (actions) actions->Release();
    return ok;
}

bool ReadWeeklyScanCommand(std::wstring& exePath, std::wstring& arguments)
{
    exePath.clear();
    arguments.clear();
    ComScope com;
    std::wstring error;
    ITaskService* service = ConnectService(error);
    if (!service) return false;
    bool ok = false;
    ITaskFolder* root = NULL;
    IRegisteredTask* task = NULL;
    ITaskDefinition* definition = NULL;
    if (SUCCEEDED(service->GetFolder(_bstr_t(L"\\"), &root)) && root &&
        SUCCEEDED(root->GetTask(_bstr_t(WeeklyScanTaskName().c_str()), &task)) && task &&
        SUCCEEDED(task->get_Definition(&definition)) && definition) {
        ok = ReadExecAction(definition, exePath, arguments);
    }
    if (definition) definition->Release();
    if (task) task->Release();
    if (root) root->Release();
    service->Release();
    DebugLog(ok ? L"Registered task runs: " + WeeklyTaskCommandLine(exePath, arguments) : L"No readable weekly task");
    return ok;
}
