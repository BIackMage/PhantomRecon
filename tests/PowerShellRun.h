#pragma once

// ---------------------------------------------------------------------------
// PowerShellRun: run a script file with Windows PowerShell 5.1 for a test, feeding
// text as its standard input (how a test answers Read-Host), and collect what it
// printed. Files go to the running test's TestDir(). Waits at most two minutes.
// ---------------------------------------------------------------------------

#include <windows.h>
#include <string>

struct PsRunResult {
    bool        ran = false;
    DWORD       exitCode = 0xFFFFFFFF;
    std::string output;   // stdout and stderr together, in the console encoding
};

PsRunResult RunPowerShellScriptFile(const std::wstring& scriptPath, const std::wstring& extraArgs, const std::string& stdinText);
