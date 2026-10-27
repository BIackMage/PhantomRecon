#include "pch.h"
#include "DebugTrace.h"

#include "StringConv.h"

#include <windows.h>

static bool TraceToConsole()
{
    static const bool enabled = [] {
        wchar_t value[8] = {};
        DWORD n = GetEnvironmentVariableW(L"PHANTOMRECON_TRACE", value, 8);
        return n > 0 && value[0] == L'1';
    }();
    return enabled;
}

void Trace(const wchar_t* module, const std::wstring& message)
{
    std::wstring line = std::wstring(L"[") + module + L"] " + message + L"\n";
    OutputDebugStringW(line.c_str());
    if (TraceToConsole()) {
        HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
        if (err && err != INVALID_HANDLE_VALUE) {
            std::string utf8 = WideToUtf8(line);
            DWORD written = 0;
            WriteFile(err, utf8.data(), static_cast<DWORD>(utf8.size()), &written, NULL);
            FlushFileBuffers(err);
        }
    }
}
