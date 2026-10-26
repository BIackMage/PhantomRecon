#include "pch.h"
#include "AppPaths.h"

#include "DebugTrace.h"
#include "RegUtil.h"
#include "TextUtils.h"

#include <windows.h>
#include <aclapi.h>
#include <authz.h>
#include <knownfolders.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "authz.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

static void DebugLog(const std::wstring& msg)
{
    Trace(L"AppPaths", msg);
}

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
// Write access for normal users
// ---------------------------------------------------------------------------
static const GENERIC_MAPPING kFileMapping = { FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS };

// Rights that let a normal user plant or change code: create a file in a folder,
// change a file's contents, or take over its permissions or owner. Creating a
// subfolder alone (FILE_ADD_SUBDIRECTORY) does not let anyone plant a DLL next to a
// program, so it does not count for folders.
static ACCESS_MASK WriteRights(bool isDirectory)
{
    return isDirectory ? static_cast<ACCESS_MASK>(FILE_ADD_FILE | WRITE_DAC | WRITE_OWNER)
                       : static_cast<ACCESS_MASK>(FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER);
}

static std::vector<BYTE> CopySidBytes(PSID sid)
{
    std::vector<BYTE> out;
    if (!sid || !IsValidSid(sid)) return out;
    DWORD len = GetLengthSid(sid);
    out.resize(len);
    if (!CopySid(len, out.data(), sid)) out.clear();
    return out;
}

static std::vector<BYTE> TokenUserSid(HANDLE token)
{
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    if (needed == 0) return {};
    std::vector<BYTE> buffer(needed);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) return {};
    return CopySidBytes(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid);
}

static bool TokenIsElevated(HANDLE token)
{
    TOKEN_ELEVATION elevation = {};
    DWORD size = 0;
    return GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) && elevation.TokenIsElevated != 0;
}

// Everyone, Authenticated Users, BUILTIN\Users and INTERACTIVE: the groups every
// standard user who signs in at the keyboard holds.
static std::vector<std::vector<BYTE>> LowPrivilegeGroupSids()
{
    const WELL_KNOWN_SID_TYPE lowTypes[] = {
        WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid,
    };
    std::vector<std::vector<BYTE>> sids;
    for (WELL_KNOWN_SID_TYPE t : lowTypes) {
        DWORD size = SECURITY_MAX_SID_SIZE;
        std::vector<BYTE> sid(size);
        if (CreateWellKnownSid(t, NULL, sid.data(), &size)) {
            sid.resize(size);
            sids.push_back(sid);
        }
    }
    return sids;
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

// Walk the entries in order, as Windows does, for a principal holding every SID in
// sids. A deny entry takes away rights no earlier allow entry granted; an allow
// entry grants only rights no earlier deny entry took away. firstGranter receives
// the SID of the first allow entry that granted one of the wanted rights.
static ACCESS_MASK GrantedByAces(const ACL* dacl, const std::vector<std::vector<BYTE>>& sids, ACCESS_MASK wanted, PSID* firstGranter)
{
    GENERIC_MAPPING mapping = kFileMapping;
    ACCESS_MASK granted = 0;
    ACCESS_MASK denied = 0;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        LPVOID ace = NULL;
        if (!GetAce(const_cast<ACL*>(dacl), i, &ace) || !ace) continue;
        const ACE_HEADER* header = static_cast<const ACE_HEADER*>(ace);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE) continue;

        // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE have the same layout.
        ACCESS_ALLOWED_ACE* entry = static_cast<ACCESS_ALLOWED_ACE*>(ace);
        PSID aceSid = reinterpret_cast<PSID>(&entry->SidStart);
        bool matches = false;
        for (const std::vector<BYTE>& sid : sids) {
            if (!sid.empty() && EqualSid(aceSid, const_cast<BYTE*>(sid.data()))) {
                matches = true;
                break;
            }
        }
        if (!matches) continue;

        ACCESS_MASK mask = entry->Mask;
        MapGenericMask(&mask, &mapping);
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
            denied |= mask & ~granted;
        }
        else {
            ACCESS_MASK added = mask & ~denied & ~granted;
            if ((added & wanted) != 0 && firstGranter && !*firstGranter) *firstGranter = aceSid;
            granted |= added;
        }
    }
    return granted;
}

bool DaclLetsLowPrivilegeGroupsWrite(const void* daclIn, bool isDirectory, std::wstring* whoOut)
{
    const ACL* dacl = static_cast<const ACL*>(daclIn);
    if (dacl == NULL) {
        // A NULL DACL grants everyone full access.
        if (whoOut) *whoOut = L"Everyone (no DACL)";
        return true;
    }
    ACCESS_MASK wanted = WriteRights(isDirectory);
    PSID granter = NULL;
    ACCESS_MASK granted = GrantedByAces(dacl, LowPrivilegeGroupSids(), wanted, &granter);
    if ((granted & wanted) == 0) return false;
    if (whoOut) *whoOut = granter ? SidToName(granter) : L"normal users";
    return true;
}

// Tokens that stand for the person using this PC without elevation:
//   - this process's own token when it is not elevated;
//   - when it is elevated, the linked non-elevated token of the same user;
//   - the desktop shell's token, which is the signed-in user even when this program
//     was elevated with another account's credentials.
// Only PROCESS_QUERY_LIMITED_INFORMATION and TOKEN_QUERY are used. The caller closes
// every handle.
static std::vector<HANDLE> NormalUserTokens()
{
    std::vector<HANDLE> tokens;
    HANDLE own = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &own)) {
        if (!TokenIsElevated(own)) {
            tokens.push_back(own);
        }
        else {
            TOKEN_LINKED_TOKEN linked = {};
            DWORD size = 0;
            if (GetTokenInformation(own, TokenLinkedToken, &linked, sizeof(linked), &size) && linked.LinkedToken) {
                if (TokenIsElevated(linked.LinkedToken)) CloseHandle(linked.LinkedToken);
                else tokens.push_back(linked.LinkedToken);
            }
            CloseHandle(own);
        }
    }

    HWND shell = GetShellWindow();
    DWORD pid = 0;
    if (shell) GetWindowThreadProcessId(shell, &pid);
    if (pid != 0 && pid != GetCurrentProcessId()) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (process) {
            HANDLE shellToken = NULL;
            if (OpenProcessToken(process, TOKEN_QUERY, &shellToken)) {
                std::vector<BYTE> shellSid = TokenUserSid(shellToken);
                bool alreadyCovered = false;
                for (HANDLE t : tokens) {
                    std::vector<BYTE> sid = TokenUserSid(t);
                    if (!sid.empty() && !shellSid.empty() && EqualSid(sid.data(), shellSid.data())) alreadyCovered = true;
                }
                if (shellSid.empty() || alreadyCovered || TokenIsElevated(shellToken)) CloseHandle(shellToken);
                else tokens.push_back(shellToken);
            }
            CloseHandle(process);
        }
    }
    return tokens;
}

// Rights Windows' own access check grants this token on the security descriptor.
// Honours group membership, deny entries, the owner's implicit rights and the
// integrity label. ok is false when the check could not run.
static ACCESS_MASK AuthzGrantedAccess(PSECURITY_DESCRIPTOR sd, HANDLE token, bool& ok)
{
    ok = false;
    AUTHZ_RESOURCE_MANAGER_HANDLE rm = NULL;
    if (!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, NULL, NULL, NULL, NULL, &rm)) {
        DebugLog(L"AuthzInitializeResourceManager failed, error " + std::to_wstring(GetLastError()));
        return 0;
    }
    ACCESS_MASK granted = 0;
    AUTHZ_CLIENT_CONTEXT_HANDLE context = NULL;
    LUID unused = {};
    if (AuthzInitializeContextFromToken(0, token, rm, NULL, unused, NULL, &context)) {
        AUTHZ_ACCESS_REQUEST request = {};
        request.DesiredAccess = MAXIMUM_ALLOWED;
        DWORD error = 0;
        AUTHZ_ACCESS_REPLY reply = {};
        reply.ResultListLength = 1;
        reply.GrantedAccessMask = &granted;
        reply.Error = &error;
        if (AuthzAccessCheck(0, context, &request, NULL, sd, NULL, 0, &reply, NULL)) {
            ok = true;
        }
        else {
            DebugLog(L"AuthzAccessCheck failed, error " + std::to_wstring(GetLastError()));
        }
        AuthzFreeContext(context);
    }
    else {
        DebugLog(L"AuthzInitializeContextFromToken failed, error " + std::to_wstring(GetLastError()));
    }
    AuthzFreeResourceManager(rm);
    return granted;
}

// Can the person using this PC without elevation write? Asked of Windows with that
// person's token where one is available, so a folder in their own profile counts even
// when this program runs as administrator.
static bool NormalUserCanWrite(PSECURITY_DESCRIPTOR sd, const ACL* dacl, bool isDirectory, std::wstring* whoOut)
{
    ACCESS_MASK wanted = WriteRights(isDirectory);
    std::vector<HANDLE> tokens = NormalUserTokens();
    bool decided = false;
    bool writable = false;
    for (HANDLE token : tokens) {
        if (writable) break;
        bool ok = false;
        ACCESS_MASK granted = AuthzGrantedAccess(sd, token, ok);
        if (!ok) continue;
        decided = true;
        if ((granted & wanted) != 0) {
            writable = true;
            std::vector<BYTE> sid = TokenUserSid(token);
            if (whoOut) *whoOut = sid.empty() ? L"the signed-in user" : SidToName(sid.data());
        }
    }
    for (HANDLE token : tokens) CloseHandle(token);
    if (decided) return writable;

    // No non-elevated token to ask (an elevated run with UAC off, or no shell): judge
    // the entries for this user's own SID plus the standard groups.
    HANDLE own = NULL;
    if (!dacl || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &own)) return false;
    std::vector<BYTE> self = TokenUserSid(own);
    CloseHandle(own);
    if (self.empty()) return false;
    std::vector<std::vector<BYTE>> sids = LowPrivilegeGroupSids();
    sids.push_back(self);
    PSID granter = NULL;
    ACCESS_MASK granted = GrantedByAces(dacl, sids, wanted, &granter);
    if ((granted & wanted) == 0) return false;
    if (whoOut) *whoOut = granter ? SidToName(granter) : SidToName(self.data());
    return true;
}

bool LowPrivilegeWritable(const std::wstring& path, bool isDirectory, std::wstring* whoOut)
{
    std::wstring target = ToExtendedPath(path);
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                              DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    DWORD rc = GetNamedSecurityInfoW(target.c_str(), SE_FILE_OBJECT, si, NULL, NULL, &dacl, NULL, &sd);
    if (rc != ERROR_SUCCESS) {
        si &= ~static_cast<SECURITY_INFORMATION>(LABEL_SECURITY_INFORMATION);
        dacl = NULL;
        sd = NULL;
        rc = GetNamedSecurityInfoW(target.c_str(), SE_FILE_OBJECT, si, NULL, NULL, &dacl, NULL, &sd);
    }
    if (rc != ERROR_SUCCESS) {
        DebugLog(L"LowPrivilegeWritable: cannot read the permissions of " + path + L" (error " + std::to_wstring(rc) + L")");
        return false;
    }

    std::wstring who;
    bool writable = DaclLetsLowPrivilegeGroupsWrite(dacl, isDirectory, &who);
    if (!writable) writable = NormalUserCanWrite(sd, dacl, isDirectory, &who);
    LocalFree(sd);
    if (writable && whoOut) *whoOut = who;
    return writable;
}

// ---------------------------------------------------------------------------
// Where users drop files
// ---------------------------------------------------------------------------
static std::wstring KnownFolderEnv(const wchar_t* var)
{
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(var, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"";
    return buf;
}

static std::wstring StripExtendedPrefix(const std::wstring& path)
{
    if (path.rfind(L"\\\\?\\UNC\\", 0) == 0) return L"\\\\" + path.substr(8);
    if (path.rfind(L"\\\\?\\", 0) == 0) return path.substr(4);
    return path;
}

// True when the path is <drive>:\Users\<someone>\<folder>\... (the real profile
// folder, not any folder that happens to have the same name).
static bool UnderProfileFolder(const std::wstring& lower, const wchar_t* folder)
{
    size_t users = lower.find(L":\\users\\");
    if (users == std::wstring::npos) return false;
    size_t nameStart = users + 8;
    size_t nameEnd = lower.find(L'\\', nameStart);
    if (nameEnd == std::wstring::npos) return false;
    std::wstring rest = lower.substr(nameEnd + 1);
    std::wstring want = std::wstring(folder) + L"\\";
    return rest.rfind(want, 0) == 0;
}

// OneDrive moves Desktop and Downloads to <profile>\OneDrive\ or
// <profile>\OneDrive - <organization>\.
static bool UnderProfileOneDrive(const std::wstring& lower, const wchar_t* folder)
{
    size_t users = lower.find(L":\\users\\");
    if (users == std::wstring::npos) return false;
    size_t nameEnd = lower.find(L'\\', users + 8);
    if (nameEnd == std::wstring::npos) return false;
    std::wstring rest = lower.substr(nameEnd + 1);
    if (rest.rfind(L"onedrive", 0) != 0) return false;
    size_t slash = rest.find(L'\\');
    if (slash == std::wstring::npos) return false;
    return rest.substr(slash + 1).rfind(std::wstring(folder) + L"\\", 0) == 0;
}

static void AddKnownFolder(std::vector<std::wstring>& out, REFKNOWNFOLDERID id)
{
    PWSTR path = NULL;
    if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, NULL, &path)) && path) {
        out.push_back(ToLowerW(path));
    }
    CoTaskMemFree(path);
}

// Desktop and Downloads wherever they really are: OneDrive, a group policy or the user
// can move them to another folder or drive. Covers this user and every other user
// whose registry hive is loaded.
static std::vector<std::wstring> RedirectedDropFolders()
{
    std::vector<std::wstring> out;
    AddKnownFolder(out, FOLDERID_Desktop);
    AddKnownFolder(out, FOLDERID_Downloads);

    const std::wstring shellFolders = L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders";
    const wchar_t* values[] = { L"Desktop", L"{374DE290-123F-4565-9164-39C4925E467B}" };   // Downloads
    for (const std::wstring& sid : RegEnumSubKeys(HKEY_USERS, L"")) {
        if (sid.rfind(L"S-1-5-21-", 0) != 0 || EndsWithI(sid, L"_Classes")) continue;
        std::wstring profile = RegReadString(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid, L"ProfileImagePath");
        for (const wchar_t* value : values) {
            std::wstring raw = RegReadString(HKEY_USERS, sid + shellFolders, value, false);
            if (raw.empty()) continue;
            if (!profile.empty()) raw = ReplaceAllI(raw, L"%USERPROFILE%", profile);
            if (raw.find(L'%') != std::wstring::npos) continue;   // depends on that user's own environment
            out.push_back(ToLowerW(raw));
        }
    }

    for (std::wstring& folder : out) {
        while (folder.size() > 3 && (folder.back() == L'\\' || folder.back() == L'/')) folder.pop_back();
    }
    return out;
}

bool IsUserWritableWindowsFolder(const std::wstring& pathIn)
{
    std::wstring windir = KnownFolderEnv(L"SystemRoot");
    if (windir.empty()) windir = L"C:\\Windows";
    std::wstring lower = ToLowerW(StripExtendedPrefix(pathIn));
    std::wstring base = ToLowerW(windir) + L"\\";
    if (lower.rfind(base, 0) != 0) return false;
    std::wstring rest = lower.substr(base.size()) + L"\\";

    // Folders under %SystemRoot% where a standard user may create files on a default
    // Windows 10 or 11 install. A file there proves nothing about where it came from.
    static const wchar_t* const writable[] = {
        L"tasks\\",
        L"temp\\",
        L"tracing\\",
        L"registration\\crmlog\\",
        L"debug\\wia\\",
        L"system32\\tasks\\",
        L"system32\\tasks_migrated\\",
        L"system32\\fxstmp\\",
        L"system32\\com\\dmp\\",
        L"system32\\microsoft\\crypto\\rsa\\machinekeys\\",
        L"system32\\spool\\printers\\",
        L"system32\\spool\\servers\\",
        L"system32\\spool\\drivers\\color\\",
        L"syswow64\\tasks\\",
        L"syswow64\\fxstmp\\",
        L"syswow64\\com\\dmp\\",
    };
    for (const wchar_t* w : writable) {
        if (rest.rfind(w, 0) == 0) return true;
    }
    return false;
}

bool IsUserDropLocation(const std::wstring& pathIn)
{
    std::wstring path = StripExtendedPrefix(pathIn);
    std::wstring lower = ToLowerW(path);
    if (lower.rfind(L"\\\\", 0) == 0) return true;   // network share
    if (UnderProfileFolder(lower, L"downloads") || UnderProfileFolder(lower, L"desktop") ||
        UnderProfileFolder(lower, L"appdata\\local\\temp")) {
        return true;
    }
    if (UnderProfileOneDrive(lower, L"downloads") || UnderProfileOneDrive(lower, L"desktop")) return true;
    const wchar_t* markers[] = {
        L":\\users\\public\\", L":\\$recycle.bin\\", L":\\windows\\temp\\", L":\\temp\\", L":\\tmp\\",
    };
    for (const wchar_t* m : markers) {
        if (lower.find(m) != std::wstring::npos) return true;
    }
    if (IsUserWritableWindowsFolder(path)) return true;
    std::wstring temp = ToLowerW(KnownFolderEnv(L"TEMP"));
    if (!temp.empty() && lower.rfind(temp + L"\\", 0) == 0) return true;

    for (const std::wstring& folder : RedirectedDropFolders()) {
        if (folder.size() <= 3) continue;   // a whole drive set as Downloads says nothing useful
        if (lower.rfind(folder + L"\\", 0) == 0) return true;
    }
    return false;
}

bool IsPackagedAppPath(const std::wstring& path)
{
    std::wstring pf = KnownFolderEnv(L"ProgramFiles");
    if (pf.empty()) pf = L"C:\\Program Files";
    return StartsWithI(path, pf + L"\\WindowsApps\\");
}

bool IsUnderWindowsDirectory(const std::wstring& path)
{
    std::wstring windir = KnownFolderEnv(L"SystemRoot");
    if (windir.empty()) windir = L"C:\\Windows";
    return StartsWithI(StripExtendedPrefix(path), windir + L"\\");
}

bool IsProtectedWindowsPath(const std::wstring& path)
{
    if (!IsUnderWindowsDirectory(path) || IsUserWritableWindowsFolder(path)) return false;
    std::wstring dir = DirectoryOf(StripExtendedPrefix(path));
    std::wstring who;
    if (!dir.empty() && DirectoryExists(dir) && LowPrivilegeWritable(dir, true, &who)) {
        DebugLog(L"IsProtectedWindowsPath: " + dir + L" is writable by " + who + L", not trusted");
        return false;
    }
    return true;
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
