#include "pch.h"
#include "AppPaths.h"

#include "TextUtils.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

std::wstring GetExePath()
{
    std::vector<wchar_t> buffer(MAX_PATH);
    while (true) {
        DWORD len = GetModuleFileNameW(NULL, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) return L"";
        if (len < buffer.size() - 1) return std::wstring(buffer.data(), len);
        buffer.resize(buffer.size() * 2);
        if (buffer.size() > 32768) return std::wstring(buffer.data(), len);
    }
}

std::wstring GetExeDirectory()
{
    std::wstring exe = GetExePath();
    size_t slash = exe.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L".\\";
    return exe.substr(0, slash + 1);
}

std::wstring AppFilePath(const std::wstring& fileName)
{
    return GetExeDirectory() + fileName;
}

bool IsPortableMode()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            if (_wcsicmp(argv[i], L"--portable") == 0) {
                LocalFree(argv);
                return true;
            }
        }
        LocalFree(argv);
    }

    if (FileExists(AppFilePath(L"portable.flag"))) return true;

    std::wstring dir = GetExeDirectory();
    if (dir.size() >= 3 && dir[1] == L':') {
        std::wstring root = dir.substr(0, 3);
        if (GetDriveTypeW(root.c_str()) == DRIVE_REMOVABLE) return true;
    }
    return false;
}

std::wstring DefaultReportsDirectory()
{
    return GetExeDirectory() + L"reports";
}

bool FileExists(const std::wstring& path)
{
    DWORD attrs = GetFileAttributesW(ToExtendedPath(path).c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool DirectoryExists(const std::wstring& path)
{
    DWORD attrs = GetFileAttributesW(ToExtendedPath(path).c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool EnsureDirectory(const std::wstring& directory)
{
    if (directory.empty()) return false;
    if (DirectoryExists(directory)) return true;

    std::wstring parent = DirectoryOf(directory);
    if (!parent.empty() && parent != directory && !(parent.size() == 2 && parent[1] == L':')) {
        EnsureDirectory(parent);
    }
    if (CreateDirectoryW(ToExtendedPath(directory).c_str(), NULL)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS && DirectoryExists(directory);
}

std::wstring FileNameOf(const std::wstring& path)
{
    size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::wstring DirectoryOf(const std::wstring& path)
{
    std::wstring p = path;
    while (p.size() > 3 && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
    size_t slash = p.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L"";
    if (slash == 2 && p.size() > 1 && p[1] == L':') return p.substr(0, 3);
    return p.substr(0, slash);
}

std::wstring JoinPath(const std::wstring& directory, const std::wstring& name)
{
    if (directory.empty()) return name;
    if (name.empty()) return directory;
    bool dirSlash = directory.back() == L'\\' || directory.back() == L'/';
    bool nameSlash = name.front() == L'\\' || name.front() == L'/';
    if (dirSlash && nameSlash) return directory + name.substr(1);
    if (dirSlash || nameSlash) return directory + name;
    return directory + L"\\" + name;
}

std::wstring ExtensionOf(const std::wstring& path)
{
    std::wstring name = FileNameOf(path);
    size_t dot = name.find_last_of(L'.');
    if (dot == std::wstring::npos || dot == name.size() - 1) return L"";
    return ToLowerW(name.substr(dot));
}

std::wstring ExpandEnvironment(const std::wstring& text)
{
    if (text.find(L'%') == std::wstring::npos) return text;
    DWORD needed = ExpandEnvironmentStringsW(text.c_str(), NULL, 0);
    if (needed == 0) return text;
    std::wstring out(needed, L'\0');
    DWORD written = ExpandEnvironmentStringsW(text.c_str(), &out[0], needed);
    if (written == 0 || written > needed) return text;
    out.resize(written - 1);
    return out;
}

std::wstring ToExtendedPath(const std::wstring& path)
{
    if (path.size() < 240) return path;
    if (path.rfind(L"\\\\?\\", 0) == 0) return path;
    if (path.rfind(L"\\\\.\\", 0) == 0) return path;

    std::wstring normalized = ReplaceAllW(path, L"/", L"\\");
    if (normalized.rfind(L"\\\\", 0) == 0) {
        return L"\\\\?\\UNC\\" + normalized.substr(2);
    }
    if (normalized.size() >= 3 && normalized[1] == L':' && normalized[2] == L'\\') {
        return L"\\\\?\\" + normalized;
    }
    return path;   // relative paths cannot take the prefix
}

std::wstring AbsolutePath(const std::wstring& path)
{
    if (path.empty()) return path;
    DWORD needed = GetFullPathNameW(path.c_str(), 0, NULL, NULL);
    if (needed == 0) return path;
    std::wstring out(needed, L'\0');
    DWORD written = GetFullPathNameW(path.c_str(), needed, &out[0], NULL);
    if (written == 0 || written >= needed) return path;
    out.resize(written);
    return out;
}

// ---------------------------------------------------------------------------
// DACL walk for low-privilege write access
// ---------------------------------------------------------------------------
static std::vector<BYTE> CurrentUserSid()
{
    std::vector<BYTE> sid;
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return sid;

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
    std::vector<BYTE> buffer(needed);
    if (needed > 0 && GetTokenInformation(hToken, TokenUser, buffer.data(), needed, &needed)) {
        TOKEN_USER* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
        DWORD len = GetLengthSid(user->User.Sid);
        sid.resize(len);
        CopySid(len, sid.data(), user->User.Sid);
    }
    CloseHandle(hToken);
    return sid;
}

static std::wstring SidToName(PSID sid)
{
    wchar_t name[256] = {};
    wchar_t domain[256] = {};
    DWORD nameLen = 256;
    DWORD domainLen = 256;
    SID_NAME_USE use;
    if (LookupAccountSidW(NULL, sid, name, &nameLen, domain, &domainLen, &use)) {
        if (domain[0]) return std::wstring(domain) + L"\\" + name;
        return name;
    }
    LPWSTR text = NULL;
    if (ConvertSidToStringSidW(sid, &text)) {
        std::wstring out = text;
        LocalFree(text);
        return out;
    }
    return L"(unknown)";
}

bool LowPrivilegeWritable(const std::wstring& path, bool isDirectory, std::wstring* whoOut)
{
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD rc = GetNamedSecurityInfoW(ToExtendedPath(path).c_str(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    if (rc != ERROR_SUCCESS) {
        return false;
    }
    if (dacl == NULL) {
        // A NULL DACL grants everyone full access.
        if (whoOut) *whoOut = L"Everyone (no DACL)";
        LocalFree(sd);
        return true;
    }

    // Well-known low-privilege principals.
    const WELL_KNOWN_SID_TYPE lowTypes[] = {
        WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid,
    };
    std::vector<std::vector<BYTE>> lowSids;
    for (WELL_KNOWN_SID_TYPE t : lowTypes) {
        DWORD size = SECURITY_MAX_SID_SIZE;
        std::vector<BYTE> sid(size);
        if (CreateWellKnownSid(t, NULL, sid.data(), &size)) {
            sid.resize(size);
            lowSids.push_back(sid);
        }
    }
    std::vector<BYTE> self = CurrentUserSid();
    if (!self.empty()) lowSids.push_back(self);

    const DWORD fileWrite = FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL | WRITE_DAC | WRITE_OWNER;
    const DWORD dirWrite = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | GENERIC_WRITE | GENERIC_ALL | WRITE_DAC | WRITE_OWNER;
    const DWORD wanted = isDirectory ? dirWrite : fileWrite;

    bool writable = false;
    for (DWORD i = 0; i < dacl->AceCount && !writable; ++i) {
        LPVOID ace = NULL;
        if (!GetAce(dacl, i, &ace)) continue;
        ACE_HEADER* header = static_cast<ACE_HEADER*>(ace);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;

        ACCESS_ALLOWED_ACE* allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
        if ((allowed->Mask & wanted) == 0) continue;

        PSID aceSid = reinterpret_cast<PSID>(&allowed->SidStart);
        for (const std::vector<BYTE>& low : lowSids) {
            if (EqualSid(aceSid, const_cast<BYTE*>(low.data()))) {
                writable = true;
                if (whoOut) *whoOut = SidToName(aceSid);
                break;
            }
        }
    }

    LocalFree(sd);
    return writable;
}

static std::wstring KnownFolderEnv(const wchar_t* var)
{
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(var, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"";
    return buf;
}

bool IsUserDropLocation(const std::wstring& path)
{
    std::wstring lower = ToLowerW(path);
    if (lower.rfind(L"\\\\", 0) == 0 && lower.rfind(L"\\\\?\\", 0) != 0) return true;   // network share
    const wchar_t* markers[] = {
        L"\\temp\\", L"\\tmp\\", L"\\downloads\\", L"\\desktop\\", L"\\users\\public\\",
        L"\\$recycle.bin\\", L"\\appdata\\local\\temp\\", L"\\windows\\temp\\",
    };
    for (const wchar_t* m : markers) {
        if (lower.find(m) != std::wstring::npos) return true;
    }
    std::wstring temp = ToLowerW(KnownFolderEnv(L"TEMP"));
    if (!temp.empty() && lower.rfind(temp, 0) == 0) return true;
    return false;
}

bool IsUnderWindowsDirectory(const std::wstring& path)
{
    std::wstring windir = KnownFolderEnv(L"SystemRoot");
    if (windir.empty()) windir = L"C:\\Windows";
    return StartsWithI(path, windir + L"\\");
}

bool IsUnderProgramFiles(const std::wstring& path)
{
    std::wstring pf = KnownFolderEnv(L"ProgramFiles");
    std::wstring pf86 = KnownFolderEnv(L"ProgramFiles(x86)");
    std::wstring pfw = KnownFolderEnv(L"ProgramW6432");
    if (!pf.empty() && StartsWithI(path, pf + L"\\")) return true;
    if (!pf86.empty() && StartsWithI(path, pf86 + L"\\")) return true;
    if (!pfw.empty() && StartsWithI(path, pfw + L"\\")) return true;
    return false;
}
