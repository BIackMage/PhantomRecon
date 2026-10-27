#include "PowerShellRun.h"

#include "TestFramework.h"

#include "FileIO.h"

#include <cstdio>
#include <vector>

namespace {

std::wstring PowerShellPath()
{
    wchar_t root[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
    std::wstring base = (n > 0 && n < MAX_PATH) ? std::wstring(root) : std::wstring(L"C:\\Windows");
    return base + L"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
}

int g_runCounter = 0;

} // namespace

PsRunResult RunPowerShellScriptFile(const std::wstring& scriptPath, const std::wstring& extraArgs, const std::string& stdinText)
{
    PsRunResult result;
    std::wstring tag = std::to_wstring(++g_runCounter);
    std::wstring inPath = tf::TestDir() + L"psrun-in-" + tag + L".txt";
    std::wstring outPath = tf::TestDir() + L"psrun-out-" + tag + L".txt";
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
    std::wstring cmd = L"\"" + PowerShellPath() + L"\" -NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath + L"\"" +
                       (extraArgs.empty() ? L"" : L" " + extraArgs);
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
