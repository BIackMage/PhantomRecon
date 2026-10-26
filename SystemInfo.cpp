#include "pch.h"
#include "SystemInfo.h"

#include "RegUtil.h"

#include <lm.h>
#include <userenv.h>
#define SECURITY_WIN32
#include <security.h>
#include <secext.h>
#include <sstream>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "secur32.lib")

std::wstring GetComputerNameString()
{
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
    if (!GetComputerNameW(name, &size)) return L"Unknown";
    return std::wstring(name);
}

std::wstring GetProcessorInfo()
{
    SYSTEM_INFO sysInfo = {};
    GetNativeSystemInfo(&sysInfo);

    std::wstringstream ss;
    ss << L"Processor: ";
    switch (sysInfo.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: ss << L"AMD64 (x64)"; break;
    case PROCESSOR_ARCHITECTURE_ARM:   ss << L"ARM";         break;
    case PROCESSOR_ARCHITECTURE_ARM64: ss << L"ARM64";       break;
    case PROCESSOR_ARCHITECTURE_IA64:  ss << L"IA64";        break;
    case PROCESSOR_ARCHITECTURE_INTEL: ss << L"Intel";       break;
    default:                           ss << L"Unknown";     break;
    }
    ss << L", Cores: " << sysInfo.dwNumberOfProcessors;
    return ss.str();
}

std::wstring GetRamInfo()
{
    MEMORYSTATUSEX memInfo = {};
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    std::wstringstream ss;
    ss << L"RAM: " << (memInfo.ullTotalPhys / (1024ULL * 1024ULL)) << L" MB";
    return ss.str();
}

std::wstring GetDiskSpaceInfo()
{
    ULARGE_INTEGER freeBytesAvailable = {};
    ULARGE_INTEGER totalBytes = {};
    ULARGE_INTEGER totalFreeBytes = {};
    GetDiskFreeSpaceExW(NULL, &freeBytesAvailable, &totalBytes, &totalFreeBytes);
    const ULONGLONG gib = 1024ULL * 1024ULL * 1024ULL;
    std::wstringstream ss;
    ss << L"Disk Space: " << (totalBytes.QuadPart / gib) << L" GB"
       << L" (Used: " << ((totalBytes.QuadPart - totalFreeBytes.QuadPart) / gib) << L" GB"
       << L", Free: " << (totalFreeBytes.QuadPart / gib) << L" GB)";
    return ss.str();
}

std::wstring BuildSystemInfoText()
{
    std::wstringstream ss;
    ss << L"Computer: " << GetComputerNameString() << L"\n";
    ss << GetWindowsVersionText() << L"\n";
    ss << GetProcessorInfo() << L"\n";
    ss << GetRamInfo() << L"\n";
    ss << GetDiskSpaceInfo() << L"\n";
    return ss.str();
}

DWORD GetWindowsBuildNumber()
{
    std::wstring build = RegReadString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
    return static_cast<DWORD>(_wtoi(build.c_str()));
}

std::wstring GetWindowsVersionText()
{
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    std::wstring product = RegReadString(HKEY_LOCAL_MACHINE, key, L"ProductName");
    std::wstring display = RegReadString(HKEY_LOCAL_MACHINE, key, L"DisplayVersion");
    DWORD build = GetWindowsBuildNumber();
    // ProductName still says "Windows 10" on Windows 11; the build number tells them apart.
    if (build >= 22000 && product.find(L"Windows 10") != std::wstring::npos) {
        product.replace(product.find(L"Windows 10"), 10, L"Windows 11");
    }
    std::wstringstream ss;
    ss << L"OS: " << (product.empty() ? L"Windows" : product);
    if (!display.empty()) ss << L" " << display;
    ss << L" (build " << build << L")";
    return ss.str();
}

bool IsProcessElevated()
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation = {};
    DWORD size = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

bool SetProcessPrivilege(const wchar_t* privilegeName, bool enable)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(token);
    return ok && err == ERROR_SUCCESS;
}

std::wstring GetCurrentUserNameString()
{
    wchar_t name[256] = {};
    DWORD size = 256;
    if (!GetUserNameW(name, &size)) return L"";
    return name;
}

std::wstring GetUserProfileFolder()
{
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) return buf;
    return L"";
}

std::wstring GetJoinedDomainName()
{
    LPWSTR name = NULL;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
    if (NetGetJoinInformation(NULL, &name, &status) != NERR_Success) return L"";
    if (name) NetApiBufferFree(name);
    if (status != NetSetupDomainName) return L"";

    wchar_t dns[256] = {};
    DWORD size = 256;
    if (GetComputerNameExW(ComputerNameDnsDomain, dns, &size) && dns[0]) return dns;
    return L"";
}

static void SystemInfoLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SystemInfo] " + msg + L"\n").c_str());
}

std::wstring GetDnsHostNameString()
{
    DWORD size = 0;
    GetComputerNameExW(ComputerNamePhysicalDnsHostname, NULL, &size);
    if (size == 0) return L"";
    std::wstring name(size, L'\0');
    if (!GetComputerNameExW(ComputerNamePhysicalDnsHostname, &name[0], &size)) return L"";
    name.resize(size);
    return name;
}

std::wstring GetJoinedNetbiosName(bool* isDomain)
{
    if (isDomain) *isDomain = false;
    LPWSTR name = NULL;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
    if (NetGetJoinInformation(NULL, &name, &status) != NERR_Success) return L"";
    std::wstring result;
    if (name && (status == NetSetupDomainName || status == NetSetupWorkgroupName)) result = name;
    if (name) NetApiBufferFree(name);
    if (isDomain) *isDomain = status == NetSetupDomainName;
    return result;
}

bool GetLogonDomainAndUser(std::wstring& domain, std::wstring& user)
{
    domain.clear();
    user.clear();
    ULONG size = 0;
    GetUserNameExW(NameSamCompatible, NULL, &size);
    if (size == 0) return false;
    std::wstring text(size, L'\0');
    if (!GetUserNameExW(NameSamCompatible, &text[0], &size)) return false;
    text.resize(size);
    size_t slash = text.find(L'\\');
    if (slash == std::wstring::npos) {
        user = text;
        return true;
    }
    domain = text.substr(0, slash);
    user = text.substr(slash + 1);
    return true;
}

std::wstring GetUserDisplayName()
{
    ULONG size = 0;
    GetUserNameExW(NameDisplay, NULL, &size);
    if (size == 0) return L"";
    std::wstring text(size, L'\0');
    if (!GetUserNameExW(NameDisplay, &text[0], &size)) return L"";
    text.resize(size);
    return text;
}

std::vector<LocalAccountName> GetLocalAccountNames()
{
    std::vector<LocalAccountName> out;
    DWORD resume = 0;
    NET_API_STATUS status;
    do {
        LPBYTE buffer = NULL;
        DWORD read = 0;
        DWORD total = 0;
        status = NetUserEnum(NULL, 20, FILTER_NORMAL_ACCOUNT, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if ((status == NERR_Success || status == ERROR_MORE_DATA) && buffer) {
            const USER_INFO_20* users = reinterpret_cast<const USER_INFO_20*>(buffer);
            for (DWORD i = 0; i < read; ++i) {
                LocalAccountName a;
                if (users[i].usri20_name) a.name = users[i].usri20_name;
                if (users[i].usri20_full_name) a.fullName = users[i].usri20_full_name;
                a.rid = users[i].usri20_user_id;
                if (!a.name.empty()) out.push_back(a);
            }
        }
        if (buffer) NetApiBufferFree(buffer);
    } while (status == ERROR_MORE_DATA);
    if (status != NERR_Success) SystemInfoLog(L"NetUserEnum stopped with status " + std::to_wstring(status));
    return out;
}

std::vector<std::wstring> GetProfileFolderNames()
{
    std::vector<std::wstring> out;
    const std::wstring key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    for (const std::wstring& sid : RegEnumSubKeys(HKEY_LOCAL_MACHINE, key)) {
        // S-1-5-21: local and domain accounts. S-1-12-1: Microsoft Entra accounts.
        // S-1-5-18/19/20 (system, local service, network service) are not people.
        if (sid.rfind(L"S-1-5-21-", 0) != 0 && sid.rfind(L"S-1-12-1-", 0) != 0) continue;
        std::wstring path = RegReadString(HKEY_LOCAL_MACHINE, key + L"\\" + sid, L"ProfileImagePath");
        while (!path.empty() && path.back() == L'\\') path.pop_back();
        size_t slash = path.find_last_of(L'\\');
        std::wstring leaf = slash == std::wstring::npos ? path : path.substr(slash + 1);
        if (!leaf.empty()) out.push_back(leaf);
    }
    return out;
}

std::wstring GetShortPathString(const std::wstring& path)
{
    if (path.empty()) return L"";
    DWORD size = GetShortPathNameW(path.c_str(), NULL, 0);
    if (size == 0) return L"";
    std::wstring shortPath(size, L'\0');
    DWORD written = GetShortPathNameW(path.c_str(), &shortPath[0], size);
    if (written == 0 || written >= size) return L"";
    shortPath.resize(written);
    return shortPath;
}

long long FileTimeToUnix(const FILETIME& ft)
{
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    if (li.QuadPart < 116444736000000000ULL) return 0;
    return static_cast<long long>((li.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

std::wstring FormatFileTime(const FILETIME& ft)
{
    FILETIME local;
    SYSTEMTIME st = {};
    if (!FileTimeToLocalFileTime(&ft, &local) || !FileTimeToSystemTime(&local, &st)) return L"";
    wchar_t buf[40];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buf;
}

std::wstring FormatUnixTime(long long unixSeconds)
{
    ULARGE_INTEGER li;
    li.QuadPart = static_cast<ULONGLONG>(unixSeconds) * 10000000ULL + 116444736000000000ULL;
    FILETIME ft;
    ft.dwLowDateTime = li.LowPart;
    ft.dwHighDateTime = li.HighPart;
    return FormatFileTime(ft);
}
