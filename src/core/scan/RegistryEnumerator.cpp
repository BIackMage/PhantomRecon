#include "pch.h"
#include "RegistryEnumerator.h"
#include "AppPaths.h"
#include <algorithm>
#include <cwctype>
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
// EnumerateUninstallKey - read all subkeys under one Uninstall registry path
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
// EnumerateInstalledPrograms - check all three standard registry locations
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
// FindExecutablesInDirectory - recursive search with depth limit
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

    // Long-path prefix for deep install folders; the paths handed back stay plain.
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(ToExtendedPath(searchPath + L"*").c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        std::wstring name = findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (name != L"." && name != L"..") {
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                    // Junctions and directory links can point anywhere (or back up the
                    // tree). The folder walker never follows them; neither does this.
                    DebugLog(L"Not following link: " + searchPath + name);
                    continue;
                }
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
// Path helpers for registry values
// ---------------------------------------------------------------------------
static std::wstring TrimSpaces(const std::wstring& s)
{
    const wchar_t* ws = L" \t\r\n";
    size_t start = s.find_first_not_of(ws);
    if (start == std::wstring::npos) return L"";
    size_t end = s.find_last_not_of(ws);
    return s.substr(start, end - start + 1);
}

static bool IsAbsolutePath(const std::wstring& p)
{
    return (p.size() >= 3 && iswalpha(p[0]) && p[1] == L':' && p[2] == L'\\') || p.rfind(L"\\\\", 0) == 0;
}

static bool IsExistingFile(const std::wstring& p)
{
    DWORD attrs = GetFileAttributesW(ToExtendedPath(p).c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static bool HasProgramExtension(const std::wstring& p)
{
    if (p.size() <= 4) return false;
    std::wstring ext = p.substr(p.size() - 4);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    return ext == L".exe" || ext == L".msi";
}

// 8.3 short names expanded so the same file has one spelling in every scan.
static std::wstring LongForm(const std::wstring& p)
{
    if (p.find(L'~') == std::wstring::npos) return p;
    std::wstring io = ToExtendedPath(p);
    bool prefixed = io.size() != p.size();
    DWORD needed = GetLongPathNameW(io.c_str(), NULL, 0);
    if (needed == 0) return p;
    std::wstring out(needed, L'\0');
    DWORD written = GetLongPathNameW(io.c_str(), &out[0], needed);
    if (written == 0 || written >= needed) return p;
    out.resize(written);
    if (prefixed) {
        if (out.rfind(L"\\\\?\\UNC\\", 0) == 0) out = L"\\\\" + out.substr(8);
        else if (out.rfind(L"\\\\?\\", 0) == 0) out = out.substr(4);
    }
    return out;
}

std::wstring RegistryEnumerator::CleanInstallLocation(const std::wstring& raw)
{
    // Installers write InstallLocation as C:\App, C:\App\, "C:\App" or "C:\App\". The
    // quoted forms used to fail the folder check and the program was skipped.
    std::wstring location = TrimSpaces(raw);
    if (location.size() >= 2 && location.front() == L'"') {
        size_t close = location.find(L'"', 1);
        location = close == std::wstring::npos ? location.substr(1) : location.substr(1, close - 1);
        location = TrimSpaces(location);
        DebugLog(L"CleanInstallLocation: quotes removed: " + location);
    }
    for (wchar_t& c : location) {
        if (c == L'/') c = L'\\';
    }
    while (location.size() > 3 && location.back() == L'\\') location.pop_back();
    if (!IsAbsolutePath(location)) return L"";
    return LongForm(location);
}

std::wstring RegistryEnumerator::ExecutableFromCommandLine(const std::wstring& raw)
{
    std::wstring command = TrimSpaces(raw);
    if (command.empty()) return L"";

    if (command.front() == L'"') {
        size_t close = command.find(L'"', 1);
        std::wstring path = close == std::wstring::npos ? command.substr(1) : command.substr(1, close - 1);
        path = TrimSpaces(path);
        if (IsAbsolutePath(path) && HasProgramExtension(path) && IsExistingFile(path)) return LongForm(path);
        return L"";
    }

    // No quotes: "C:\Program Files\App\uninst.exe /S" was cut at the first space, which
    // gave "C:\Program" and lost the program. Try every prefix that ends at a space (or
    // at the end) the way CreateProcess resolves an unquoted path, shortest first, and
    // take the first one that names an existing .exe or .msi.
    size_t pos = 0;
    while (true) {
        size_t space = command.find(L' ', pos);
        std::wstring candidate = command.substr(0, space);
        if (IsAbsolutePath(candidate) && HasProgramExtension(candidate) && IsExistingFile(candidate)) {
            if (candidate.find(L' ') != std::wstring::npos) {
                DebugLog(L"ExecutableFromCommandLine: unquoted path with spaces resolved: " + candidate);
            }
            return LongForm(candidate);
        }
        if (space == std::wstring::npos) break;
        pos = space + 1;
    }
    return L"";
}

// ---------------------------------------------------------------------------
// GetExecutablePathsFromPrograms - extract executables from install locations
// ---------------------------------------------------------------------------
std::vector<std::wstring> RegistryEnumerator::GetExecutablePathsFromPrograms(
    const std::vector<InstalledProgram>& programs, int maxDepth)
{
    if (maxDepth < 1) maxDepth = 1;
    if (maxDepth > 10) maxDepth = 10;
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
        std::wstring location = CleanInstallLocation(prog.installLocation);
        if (!location.empty()) {
            // Verify directory exists
            DWORD attrs = GetFileAttributesW(ToExtendedPath(location).c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
                    DebugLog(L"Install folder is a link, scanning its own files only: " + location);
                }
                std::vector<std::wstring> exes;
                FindExecutablesInDirectory(location, exes, maxDepth);
                for (auto& e : exes) {
                    uniquePaths.insert(std::move(e));
                }
            }
            else {
                DebugLog(L"Install folder not found: " + location + L" (" + prog.displayName + L")");
            }
        }

        // Also try extracting exe path from uninstall string
        std::wstring uninstall = ExecutableFromCommandLine(prog.uninstallString);
        if (!uninstall.empty()) {
            uniquePaths.insert(uninstall);
        }
    }

    std::vector<std::wstring> result(uniquePaths.begin(), uniquePaths.end());

    DebugLog(std::wstring(L"Resolved ") + std::to_wstring(result.size()) +
        L" unique executable paths");

    return result;
}
