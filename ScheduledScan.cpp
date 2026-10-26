#include "pch.h"
#include "ScheduledScan.h"

#include "AppPaths.h"
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

std::wstring WeeklyScanArguments(const std::wstring& baselinePath, const std::wstring& reportsDir)
{
    return L"--fast --baseline \"" + baselinePath + L"\" --report \"" + JoinPath(reportsDir, L"weekly_report.html") +
           L"\" --csv \"" + JoinPath(reportsDir, L"weekly_scan.csv") + L"\" --notify --quiet";
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

bool RegisterWeeklyScan(const std::wstring& exePath, const std::wstring& baselinePath,
                        const std::wstring& reportsDir, std::wstring& error)
{
    if (IsPortableMode()) {
        error = L"Portable mode never creates scheduled tasks.";
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
            info->put_Description(_bstr_t(L"Weekly Fast Scan against your Phantom Recon baseline. Remove it from Phantom Recon's Schedule menu."));
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
            exec->put_Path(_bstr_t(exePath.c_str()));
            exec->put_Arguments(_bstr_t(WeeklyScanArguments(baselinePath, reportsDir).c_str()));
            exec->put_WorkingDirectory(_bstr_t(DirectoryOf(exePath).c_str()));
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
    DebugLog(ok ? L"Registered weekly scan" : L"Register failed: " + error);
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
