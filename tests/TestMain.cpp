// PhantomReconTests.exe: runs every test in this folder.
//   PhantomReconTests.exe            run all
//   PhantomReconTests.exe Baseline   run tests whose name contains "Baseline"

#include "TestFramework.h"

#include <windows.h>
#include <cstdio>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>

#include "../StringConv.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace tf {

static int          g_failures = 0;
static std::wstring g_testDir;

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
}

std::wstring TestDir()
{
    return g_testDir;
}

static std::wstring MakeTempFolder(const char* testName)
{
    wchar_t tempPath[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring dir = std::wstring(tempPath) + L"PhantomReconTests\\" + Utf8ToWide(testName) + L"_" +
                       std::to_wstring(GetCurrentProcessId()) + L"\\";
    SHCreateDirectoryExW(NULL, dir.c_str(), NULL);
    return dir;
}

static void DeleteFolder(const std::wstring& dir)
{
    if (dir.empty()) return;
    std::wstring from = dir;
    if (!from.empty() && from.back() == L'\\') from.pop_back();
    from.push_back(L'\0');   // SHFileOperation wants a double-NUL list
    SHFILEOPSTRUCTW op = {};
    op.wFunc = FO_DELETE;
    op.pFrom = from.c_str();
    op.fFlags = FOF_NO_UI;
    SHFileOperationW(&op);
}

int RunAll(const std::vector<std::string>& filters)
{
    int passed = 0, failed = 0, skipped = 0;
    for (const TestCase& t : Registry()) {
        bool selected = filters.empty();
        for (const std::string& f : filters) {
            if (std::string(t.name).find(f) != std::string::npos) selected = true;
        }
        if (!selected) {
            ++skipped;
            continue;
        }
        int before = g_failures;
        g_testDir = MakeTempFolder(t.name);
        ULONGLONG start = GetTickCount64();
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
        DeleteFolder(g_testDir);
        bool ok = g_failures == before;
        std::printf("%s  %-50s %6llu ms\n", ok ? "PASS" : "FAIL", t.name,
            static_cast<unsigned long long>(GetTickCount64() - start));
        std::fflush(stdout);
        if (ok) ++passed;
        else ++failed;
    }
    std::printf("\n%d passed, %d failed, %d not selected, %d checks failed\n", passed, failed, skipped, g_failures);
    return failed == 0 ? 0 : 1;
}

} // namespace tf

int wmain(int argc, wchar_t** argv)
{
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    std::vector<std::string> filters;
    for (int i = 1; i < argc; ++i) filters.push_back(WideToUtf8(argv[i]));
    int code = tf::RunAll(filters);
    CoUninitialize();
    return code;
}
