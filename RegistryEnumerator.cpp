#include "pch.h"
#include "RegistryEnumerator.h"
#include <algorithm>
#include <set>
#include <Shlwapi.h>

// ---------------------------------------------------------------------------
// Debug logging helper
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[RegistryEnumerator] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

static void DebugLog(const std::wstring& msg)
{
    DebugLog(msg.c_str());
}

// ---------------------------------------------------------------------------
// ReadRegString
// ---------------------------------------------------------------------------
std::wstring RegistryEnumerator::ReadRegString(HKEY hKey, const wchar_t* valueName)
{
    DWORD dataType = 0;
    DWORD dataSize = 0;

    // Query size first
    LONG result = RegQueryValueExW(hKey, valueName, NULL, &dataType, NULL, &dataSize);
    if (result != ERROR_SUCCESS || (dataType != REG_SZ && dataType != REG_EXPAND_SZ)) {
        return L"";
    }

    if (dataSize == 0) {
        return L"";
    }

    // Allocate buffer and read
    std::vector<wchar_t> buffer(dataSize / sizeof(wchar_t) + 1, L'\0');
    result = RegQueryValueExW(hKey, valueName, NULL, &dataType,
        reinterpret_cast<LPBYTE>(buffer.data()), &dataSize);
    if (result != ERROR_SUCCESS) {
        return L"";
    }

    // If REG_EXPAND_SZ, expand environment variables
    std::wstring value(buffer.data());
    if (dataType == REG_EXPAND_SZ && !value.empty()) {
        wchar_t expanded[MAX_PATH * 2];
        DWORD expandedLen = ExpandEnvironmentStringsW(value.c_str(), expanded,
            static_cast<DWORD>(sizeof(expanded) / sizeof(expanded[0])));
        if (expandedLen > 0 && expandedLen < sizeof(expanded) / sizeof(expanded[0])) {
            value = expanded;
        }
    }

    return value;
}

// ---------------------------------------------------------------------------
// EnumerateUninstallKey — read all subkeys under one Uninstall registry path
// ---------------------------------------------------------------------------
void RegistryEnumerator::EnumerateUninstallKey(HKEY hRoot, const wchar_t* subKeyPath,
    std::vector<InstalledProgram>& out)
{
    HKEY hUninstall = NULL;
    LONG result = RegOpenKeyExW(hRoot, subKeyPath, 0, KEY_READ, &hUninstall);
    if (result != ERROR_SUCCESS) {
        DebugLog(std::wstring(L"Failed to open key: ") + subKeyPath);
        return;
    }

    DWORD subKeyCount = 0;
    DWORD maxSubKeyLen = 0;
    RegQueryInfoKeyW(hUninstall, NULL, NULL, NULL, &subKeyCount, &maxSubKeyLen,
        NULL, NULL, NULL, NULL, NULL, NULL);

    DebugLog(std::wstring(L"Enumerating ") + std::to_wstring(subKeyCount) +
        L" subkeys under " + subKeyPath);

    std::vector<wchar_t> subKeyName(maxSubKeyLen + 1, L'\0');

    for (DWORD i = 0; i < subKeyCount; i++) {
        DWORD nameLen = maxSubKeyLen + 1;
        result = RegEnumKeyExW(hUninstall, i, subKeyName.data(), &nameLen,
            NULL, NULL, NULL, NULL);
        if (result != ERROR_SUCCESS) {
            continue;
        }

        HKEY hSubKey = NULL;
        result = RegOpenKeyExW(hUninstall, subKeyName.data(), 0, KEY_READ, &hSubKey);
        if (result != ERROR_SUCCESS) {
            continue;
        }

        InstalledProgram prog;
        prog.displayName = ReadRegString(hSubKey, L"DisplayName");
        prog.installLocation = ReadRegString(hSubKey, L"InstallLocation");
        prog.displayVersion = ReadRegString(hSubKey, L"DisplayVersion");
        prog.publisher = ReadRegString(hSubKey, L"Publisher");
        prog.uninstallString = ReadRegString(hSubKey, L"UninstallString");

        RegCloseKey(hSubKey);

        // Skip entries with no display name (system components, updates, etc.)
        if (prog.displayName.empty()) {
            continue;
        }

        // Skip entries that are clearly Windows updates
        std::wstring lowerName = prog.displayName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
        if (lowerName.find(L"update for") == 0 || lowerName.find(L"hotfix for") == 0 ||
            lowerName.find(L"security update") == 0) {
            continue;
        }

        out.push_back(std::move(prog));
    }

    RegCloseKey(hUninstall);
}

// ---------------------------------------------------------------------------
// EnumerateInstalledPrograms — check all three standard registry locations
// ---------------------------------------------------------------------------
std::vector<InstalledProgram> RegistryEnumerator::EnumerateInstalledPrograms()
{
    std::vector<InstalledProgram> programs;

    DebugLog(L"Starting installed program enumeration");

    // 64-bit programs (or native on 32-bit OS)
    EnumerateUninstallKey(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", programs);

    // 32-bit programs on 64-bit OS
    EnumerateUninstallKey(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\WoW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", programs);

    // Per-user programs
    EnumerateUninstallKey(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", programs);

    DebugLog(std::wstring(L"Total programs found: ") + std::to_wstring(programs.size()));

    return programs;
}

// ---------------------------------------------------------------------------
// FindExecutablesInDirectory — recursive search with depth limit
// ---------------------------------------------------------------------------
void RegistryEnumerator::FindExecutablesInDirectory(const std::wstring& directory,
    std::vector<std::wstring>& out, int maxDepth)
{
    if (maxDepth <= 0) return;

    std::wstring searchPath = directory;
    // Ensure trailing backslash
    if (!searchPath.empty() && searchPath.back() != L'\\') {
        searchPath += L'\\';
    }

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW((searchPath + L"*").c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        std::wstring name = findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (name != L"." && name != L"..") {
                FindExecutablesInDirectory(searchPath + name, out, maxDepth - 1);
            }
        }
        else {
            // Check for executable/scriptable extensions
            size_t dotPos = name.find_last_of(L'.');
            if (dotPos != std::wstring::npos && dotPos < name.length() - 1) {
                std::wstring ext = name.substr(dotPos);
                std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

                bool isExecutable =
                    // PE binaries
                    ext == L".exe"  || ext == L".dll"  || ext == L".com"  ||
                    ext == L".scr"  || ext == L".sys"  || ext == L".drv"  ||
                    ext == L".cpl"  || ext == L".ocx"  ||
                    // Installers
                    ext == L".msi"  || ext == L".msp"  || ext == L".mst"  ||
                    // Shell scripts
                    ext == L".bat"  || ext == L".cmd"  || ext == L".ps1"  ||
                    ext == L".psm1" || ext == L".psd1" ||
                    // VBScript / JScript (WSH)
                    ext == L".vbs"  || ext == L".vbe"  || ext == L".js"   ||
                    ext == L".jse"  || ext == L".wsf"  || ext == L".wsh"  ||
                    ext == L".wsc"  ||
                    // HTML Application
                    ext == L".hta"  ||
                    // Legacy / shortcut
                    ext == L".pif"  || ext == L".lnk"  || ext == L".inf"  ||
                    ext == L".reg";

                if (isExecutable) {
                    out.push_back(searchPath + name);
                }
            }
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

// ---------------------------------------------------------------------------
// GetExecutablePathsFromPrograms — extract executables from install locations
// ---------------------------------------------------------------------------
std::vector<std::wstring> RegistryEnumerator::GetExecutablePathsFromPrograms(
    const std::vector<InstalledProgram>& programs)
{
    DebugLog(L"Resolving executable paths from installed programs");

    // Use a set for deduplication (case-insensitive)
    struct CaseInsensitiveLess {
        bool operator()(const std::wstring& a, const std::wstring& b) const {
            std::wstring la = a, lb = b;
            std::transform(la.begin(), la.end(), la.begin(), ::towlower);
            std::transform(lb.begin(), lb.end(), lb.begin(), ::towlower);
            return la < lb;
        }
    };
    std::set<std::wstring, CaseInsensitiveLess> uniquePaths;

    for (const auto& prog : programs) {
        // Try install location first
        if (!prog.installLocation.empty()) {
            std::wstring location = prog.installLocation;
            // Remove trailing backslash for consistency
            if (location.size() > 3 && location.back() == L'\\') {
                location.pop_back();
            }

            // Verify directory exists
            DWORD attrs = GetFileAttributesW(location.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                std::vector<std::wstring> exes;
                FindExecutablesInDirectory(location, exes, 3);
                for (auto& e : exes) {
                    uniquePaths.insert(std::move(e));
                }
            }
        }

        // Also try extracting exe path from uninstall string
        if (!prog.uninstallString.empty()) {
            std::wstring uninstall = prog.uninstallString;

            // Remove surrounding quotes if present
            if (uninstall.size() > 2 && uninstall.front() == L'"') {
                size_t closeQuote = uninstall.find(L'"', 1);
                if (closeQuote != std::wstring::npos) {
                    uninstall = uninstall.substr(1, closeQuote - 1);
                }
            }
            else {
                // Take everything up to the first space (for paths without quotes)
                size_t spacePos = uninstall.find(L' ');
                if (spacePos != std::wstring::npos) {
                    uninstall = uninstall.substr(0, spacePos);
                }
            }

            // Check if this path is an exe that exists
            std::wstring lowerUninstall = uninstall;
            std::transform(lowerUninstall.begin(), lowerUninstall.end(),
                lowerUninstall.begin(), ::towlower);

            if (lowerUninstall.length() > 4) {
                std::wstring ext = lowerUninstall.substr(lowerUninstall.length() - 4);
                if (ext == L".exe" || ext == L".msi") {
                    DWORD attrs = GetFileAttributesW(uninstall.c_str());
                    if (attrs != INVALID_FILE_ATTRIBUTES &&
                        !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                        uniquePaths.insert(uninstall);
                    }
                }
            }
        }
    }

    std::vector<std::wstring> result(uniquePaths.begin(), uniquePaths.end());

    DebugLog(std::wstring(L"Resolved ") + std::to_wstring(result.size()) +
        L" unique executable paths");

    return result;
}
