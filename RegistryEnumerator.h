#pragma once

#include <string>
#include <vector>
#include <windows.h>

// ---------------------------------------------------------------------------
// InstalledProgram - one entry from the Windows registry Uninstall keys
// ---------------------------------------------------------------------------
struct InstalledProgram {
    std::wstring displayName;
    std::wstring installLocation;   // may be empty
    std::wstring displayVersion;
    std::wstring publisher;
    std::wstring uninstallString;
};

// ---------------------------------------------------------------------------
// RegistryEnumerator - enumerates installed programs and their executables
// ---------------------------------------------------------------------------
class RegistryEnumerator {
public:
    // Enumerate all installed programs from standard registry locations:
    //   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    //   HKLM\SOFTWARE\WoW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
    //   HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
    static std::vector<InstalledProgram> EnumerateInstalledPrograms();

    // Given a list of installed programs, find all executable files (.exe, .dll, etc.)
    // in their install locations. Returns a deduplicated list of full file paths.
    static std::vector<std::wstring> GetExecutablePathsFromPrograms(
        const std::vector<InstalledProgram>& programs, int maxDepth = 3);

private:
    // Enumerate subkeys under a single registry path
    static void EnumerateUninstallKey(HKEY hRoot, const wchar_t* subKeyPath,
        std::vector<InstalledProgram>& out);

    // Read a string value from a registry key, returns empty string on failure
    static std::wstring ReadRegString(HKEY hKey, const wchar_t* valueName);

    // Recursively find executables in a directory
    static void FindExecutablesInDirectory(const std::wstring& directory,
        std::vector<std::wstring>& out, int maxDepth = 3);
};
