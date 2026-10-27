// PhantomReconTests.exe: runs every test in this folder.
//   PhantomReconTests.exe                 run all
//   PhantomReconTests.exe Baseline        run tests whose name contains "Baseline"
//   PhantomReconTests.exe --timeout 120   stop the run when one test takes over 120 s
//
// Every run gets its own folder under %TEMP%\PhantomReconTests\. Each test works in
// a subfolder of it (TestDir()), and the program's data folder (scoring INI,
// known-good list, revocation cache) is pointed at <run>\data through the
// PHANTOMRECON_DATA_DIR variable, so files next to the exe never change a result.
// The run folder is removed at the end, and %TEMP%\PhantomReconTests too when empty.
//
// Exit codes: 0 every selected test passed; 1 a test failed; 2 bad arguments, no test
// matched the filter, or the temp folder could not be made; 3 a test crashed; 4 a
// test hung past the timeout. A crash or hang prints the test's name and the totals
// so far before the program stops.

#include "TestFramework.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <csignal>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <malloc.h>
#include <mutex>
#include <thread>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>

#include "AppPaths.h"
#include "StringConv.h"
#include "SystemInfo.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace tf {

// Runner state. This is the test program, not the app: AppState rules do not apply.
static std::atomic<int> g_failures{ 0 };
static std::wstring     g_testDir;
static std::wstring     g_runDir;
static std::wstring     g_dataDir;
static std::atomic<const char*> g_currentTest{ nullptr };   // read by the watchdog thread
static int              g_passed = 0;
static int              g_failed = 0;
static int              g_notSelected = 0;
static int              g_cleanupProblems = 0;

static const int kExitFailed = 1;
static const int kExitSetup = 2;
static const int kExitCrash = 3;
static const int kExitHang = 4;
static const unsigned kDefaultTimeoutSeconds = 600;

std::vector<TestCase>& Registry()
{
    static std::vector<TestCase> tests;
    return tests;
}

std::string Narrow(const std::wstring& s)
{
    return WideToUtf8(s);
}

void Fail(const char* file, int line, const std::string& message)
{
    ++g_failures;
    const char* base = strrchr(file, '\\');
    std::printf("    FAIL %s:%d  %s\n", base ? base + 1 : file, line, message.c_str());
    std::fflush(stdout);
}

std::wstring TestDir()
{
    return g_testDir;
}

std::wstring DataDir()
{
    return g_dataDir;
}

static void DebugLine(const std::wstring& text)
{
    OutputDebugStringW((L"[Tests] " + text + L"\n").c_str());
}

static void PrintTotals()
{
    std::printf("\n%d passed, %d failed, %d not selected, %d checks failed\n", g_passed, g_failed, g_notSelected,
        g_failures.load());
    if (g_cleanupProblems > 0) {
        std::printf("%d temp folder(s) could not be removed (see the notes above)\n", g_cleanupProblems);
    }
    std::fflush(stdout);
}

// Create a folder (and its parents). Reports why when it cannot.
static bool MakeFolder(const std::wstring& dir, std::string& why)
{
    int rc = SHCreateDirectoryExW(NULL, dir.c_str(), NULL);
    if (rc == ERROR_SUCCESS || rc == ERROR_ALREADY_EXISTS || rc == ERROR_FILE_EXISTS) {
        DWORD attrs = GetFileAttributesW(dir.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return true;
    }
    why = "cannot create " + Narrow(dir) + " (error " + std::to_string(rc) + ")";
    return false;
}

// Delete a folder tree. A file still open (a handle a test forgot, or a virus
// scanner reading it) can make the first try fail, so it tries a few times.
static bool DeleteFolder(const std::wstring& dir)
{
    if (dir.empty()) return true;
    std::wstring from = dir;
    if (!from.empty() && from.back() == L'\\') from.pop_back();
    if (GetFileAttributesW(from.c_str()) == INVALID_FILE_ATTRIBUTES) return true;
    from.push_back(L'\0');   // SHFileOperation wants a double-NUL list
    for (int attempt = 0; attempt < 5; ++attempt) {
        SHFILEOPSTRUCTW op = {};
        op.wFunc = FO_DELETE;
        op.pFrom = from.c_str();
        op.fFlags = FOF_NO_UI;
        int rc = SHFileOperationW(&op);
        if (rc == 0 && !op.fAnyOperationsAborted && GetFileAttributesW(from.c_str()) == INVALID_FILE_ATTRIBUTES) return true;
        Sleep(200);
    }
    return GetFileAttributesW(from.c_str()) == INVALID_FILE_ATTRIBUTES;
}

static void CleanUpRun()
{
    if (!g_runDir.empty() && !DeleteFolder(g_runDir)) {
        std::printf("note: could not remove the run folder %s\n", Narrow(g_runDir).c_str());
        ++g_cleanupProblems;
    }
    // The parent goes too, but only when no other run is using it.
    std::wstring parent = g_runDir;
    if (!parent.empty() && parent.back() == L'\\') parent.pop_back();
    size_t slash = parent.find_last_of(L'\\');
    if (slash != std::wstring::npos) RemoveDirectoryW(parent.substr(0, slash).c_str());
}

// ---------------------------------------------------------------------------
// Crash and hang reporting
// ---------------------------------------------------------------------------
static void ReportFatal(const char* what, unsigned long code, int exitCode)
{
    const char* current = g_currentTest.load();
    std::printf("\n%s  %s", what, current ? current : "(between tests)");
    if (code != 0) std::printf("  (exception 0x%08lX)", code);
    std::printf("\nThe run stopped here; tests after this one did not run.\n");
    ++g_failed;
    PrintTotals();
    DebugLine(L"fatal: " + Utf8ToWide(what) + L" in " + Utf8ToWide(current ? current : "(none)"));
    // Exit without running destructors or DLL detach code: the process is in an
    // unknown state, and a hung thread may hold a lock they would wait for.
    TerminateProcess(GetCurrentProcess(), static_cast<UINT>(exitCode));
}

// A crash on another thread (a worker started by the code under test).
static LONG WINAPI UnhandledFilter(EXCEPTION_POINTERS* info)
{
    ReportFatal("CRASH (background thread)", info && info->ExceptionRecord ? info->ExceptionRecord->ExceptionCode : 0, kExitCrash);
    return EXCEPTION_EXECUTE_HANDLER;
}

// std::set_terminate only covers the thread that calls it. An exception escaping
// another thread ends in abort(), and SIGABRT handlers are process-wide.
static void TerminateHandler()
{
    ReportFatal("CRASH (std::terminate, an exception escaped)", 0, kExitCrash);
}

static void AbortHandler(int)
{
    ReportFatal("CRASH (abort, for example an exception escaped a thread)", 0, kExitCrash);
}

// Runs the body with the C++ handlers; std exceptions are ordinary test failures.
static void RunBodyCpp(const TestCase& t)
{
    try {
        t.body();
    }
    catch (const RequireFailed&) {
        // already reported
    }
    catch (const std::exception& e) {
        Fail(__FILE__, __LINE__, std::string("exception: ") + e.what());
    }
    catch (...) {
        Fail(__FILE__, __LINE__, "unknown exception");
    }
}

// Structured exceptions (access violation, stack overflow) are not C++ exceptions;
// they land here. No C++ objects with destructors may live in this function.
static unsigned long RunBodySeh(const TestCase* t)
{
    __try {
        RunBodyCpp(*t);
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        unsigned long code = GetExceptionCode();
        if (code == EXCEPTION_STACK_OVERFLOW) _resetstkoflw();
        return code;
    }
}

// Watches the running test. When one runs past the limit, the run stops with the
// test's name in the log instead of the CI job timing out with no clue.
class Watchdog {
public:
    explicit Watchdog(unsigned seconds) : limit(seconds), thread([this] { Loop(); }) {}
    ~Watchdog()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stopping = true;
        }
        wake.notify_all();
        thread.join();
    }
    void Start()
    {
        std::lock_guard<std::mutex> lock(mutex);
        deadline = std::chrono::steady_clock::now() + std::chrono::seconds(limit);
        armed = true;
    }
    void Stop()
    {
        std::lock_guard<std::mutex> lock(mutex);
        armed = false;
    }

private:
    void Loop()
    {
        std::unique_lock<std::mutex> lock(mutex);
        while (!stopping) {
            wake.wait_for(lock, std::chrono::seconds(1));
            if (stopping || !armed) continue;
            if (std::chrono::steady_clock::now() < deadline) continue;
            std::string what = "HUNG (over " + std::to_string(limit) + " s)";
            ReportFatal(what.c_str(), 0, kExitHang);
        }
    }

    unsigned limit;
    std::mutex mutex;
    std::condition_variable wake;
    std::chrono::steady_clock::time_point deadline;
    bool armed = false;
    bool stopping = false;
    std::thread thread;   // last member: starts after the others are ready
};

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

// A run that crashed or hung was stopped before it could clean up. Its folder is
// run_<pid>_<ticks>; remove it once no process with that id is running.
static void RemoveStaleRuns(const std::wstring& parent)
{
    WIN32_FIND_DATAW fd = {};
    HANDLE find = FindFirstFileW((parent + L"run_*").c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        DWORD pid = static_cast<DWORD>(wcstoul(fd.cFileName + 4, nullptr, 10));
        if (pid == 0 || pid == GetCurrentProcessId()) continue;
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (process) {
            CloseHandle(process);
            continue;   // that run may still be going
        }
        if (GetLastError() == ERROR_ACCESS_DENIED) continue;   // exists, just not ours to open
        std::wstring stale = parent + fd.cFileName;
        if (DeleteFolder(stale)) DebugLine(L"removed the folder of an earlier stopped run: " + stale);
        else std::printf("note: could not remove the folder of an earlier stopped run: %s\n", Narrow(stale).c_str());
    } while (FindNextFileW(find, &fd));
    FindClose(find);
}

static bool PrepareRunFolder()
{
    wchar_t tempPath[MAX_PATH + 1] = {};
    DWORD n = GetTempPathW(MAX_PATH + 1, tempPath);
    if (n == 0 || n > MAX_PATH) {
        std::printf("setup: cannot read the temp folder path (error %lu)\n", GetLastError());
        return false;
    }
    std::wstring parent = std::wstring(tempPath) + L"PhantomReconTests\\";
    RemoveStaleRuns(parent);
    g_runDir = parent + L"run_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64()) + L"\\";
    g_dataDir = g_runDir + L"data\\";
    std::string why;
    if (!MakeFolder(g_dataDir, why)) {
        std::printf("setup: %s\n", why.c_str());
        return false;
    }
    std::wstring var = DataFolderEnvironmentName();
    if (!SetEnvironmentVariableW(var.c_str(), g_dataDir.c_str())) {
        std::printf("setup: cannot set %s (error %lu)\n", Narrow(var).c_str(), GetLastError());
        return false;
    }
    // Make sure the override really took: a stray scoring INI next to the exe must not count.
    if (AppFilePath(L"x") != g_dataDir + L"x") {
        std::printf("setup: the data-folder override did not take effect (%s)\n", Narrow(AppFilePath(L"x")).c_str());
        return false;
    }
    // Several checks behave differently with and without administrator rights; the CI
    // log must show which kind of run this was.
    // Same rule the checks use (Administrators group active in the token), so the line
    // matches what the checks saw.
    std::string elevated = IsProcessElevated() ? "yes" : "no";
    std::printf("Run folder: %s\nElevated: %s\n\n", Narrow(g_runDir).c_str(), elevated.c_str());
    std::fflush(stdout);
    DebugLine(L"run folder " + g_runDir);
    return true;
}

int RunAll(const std::vector<std::string>& filters, unsigned timeoutSeconds)
{
    std::vector<const TestCase*> selected;
    for (const TestCase& t : Registry()) {
        bool match = filters.empty();
        for (const std::string& f : filters) {
            if (std::string(t.name).find(f) != std::string::npos) match = true;
        }
        if (match) selected.push_back(&t);
        else ++g_notSelected;
    }
    if (selected.empty()) {
        std::printf("No test name contains");
        for (const std::string& f : filters) std::printf(" \"%s\"", f.c_str());
        std::printf(". Nothing was run.\n");
        return kExitSetup;
    }
    if (!PrepareRunFolder()) return kExitSetup;

    Watchdog watchdog(timeoutSeconds);
    for (const TestCase* t : selected) {
        int before = g_failures.load();
        g_currentTest = t->name;
        std::printf("RUN   %s\n", t->name);
        std::fflush(stdout);

        std::string why;
        g_testDir = g_runDir + Utf8ToWide(t->name) + L"\\";
        ULONGLONG start = GetTickCount64();
        if (!MakeFolder(g_testDir, why)) {
            Fail(__FILE__, __LINE__, "scratch folder: " + why);
        }
        else {
            watchdog.Start();
            unsigned long seh = RunBodySeh(t);
            watchdog.Stop();
            if (seh != 0) {
                ReportFatal("CRASH", seh, kExitCrash);
            }
        }
        if (!DeleteFolder(g_testDir)) {
            std::printf("    note: could not remove %s (a file in it is still open)\n", Narrow(g_testDir).c_str());
            ++g_cleanupProblems;
        }
        bool ok = g_failures.load() == before;
        std::printf("%s  %-50s %6llu ms\n", ok ? "PASS" : "FAIL", t->name,
            static_cast<unsigned long long>(GetTickCount64() - start));
        std::fflush(stdout);
        if (ok) ++g_passed;
        else ++g_failed;
    }
    g_currentTest = nullptr;
    PrintTotals();
    CleanUpRun();
    return g_failed == 0 ? 0 : kExitFailed;
}

} // namespace tf

static void Usage()
{
    std::printf("PhantomReconTests.exe [--timeout SECONDS] [name-filter ...]\n");
}

int wmain(int argc, wchar_t** argv)
{
    // No error dialogs: in CI a dialog waits for a click that never comes.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetUnhandledExceptionFilter(tf::UnhandledFilter);
    std::set_terminate(tf::TerminateHandler);
    signal(SIGABRT, tf::AbortHandler);

    unsigned timeoutSeconds = tf::kDefaultTimeoutSeconds;
    std::vector<std::string> filters;
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--timeout") {
            if (i + 1 >= argc) {
                Usage();
                return tf::kExitSetup;
            }
            wchar_t* end = nullptr;
            unsigned long value = wcstoul(argv[++i], &end, 10);
            if (!end || *end != L'\0' || value == 0 || value > 86400) {
                std::printf("--timeout needs a number of seconds from 1 to 86400\n");
                return tf::kExitSetup;
            }
            timeoutSeconds = static_cast<unsigned>(value);
        }
        else if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            Usage();
            return 0;
        }
        else if (arg.rfind(L"--", 0) == 0) {
            std::printf("Unknown option %s\n", WideToUtf8(arg).c_str());
            Usage();
            return tf::kExitSetup;
        }
        else {
            filters.push_back(WideToUtf8(arg));
        }
    }

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    int code = tf::RunAll(filters, timeoutSeconds);
    CoUninitialize();
    return code;
}
