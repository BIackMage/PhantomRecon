#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "FileIO.h"
#include "RegUtil.h"
#include "ServiceUtil.h"
#include "SystemInfo.h"
#include "TextUtils.h"

#include "CheckHelpers.h"
#include "PeFile.h"

#include <windows.h>
#include <tlhelp32.h>
#include <set>
#include <sstream>

// ---------------------------------------------------------------------------
// Running programs with more rights than a normal user
// ---------------------------------------------------------------------------
struct PrivilegedProgram {
    std::wstring image;
    std::wstring name;
    bool         system = false;   // runs as LocalSystem; otherwise elevated administrator
};

// Lowercase DLL names Windows always loads from System32 (KnownDLLs), which a
// planted copy in a program folder cannot replace.
static std::set<std::wstring> KnownDlls()
{
    std::set<std::wstring> out;
    for (const RegValue& v : RegEnumValues(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs")) {
        if (!v.text.empty()) out.insert(ToLowerW(v.text));
    }
    return out;
}

// Programs running as SYSTEM or elevated. Only the image name and the token are
// read (PROCESS_QUERY_LIMITED_INFORMATION and TOKEN_QUERY); never memory.
static std::vector<PrivilegedProgram> PrivilegedPrograms(int& notChecked)
{
    std::vector<PrivilegedProgram> out;
    std::set<std::wstring> seen;
    notChecked = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4 || pe.th32ProcessID == GetCurrentProcessId()) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!h) {
                notChecked++;
                continue;
            }
            wchar_t path[MAX_PATH * 2] = {};
            DWORD size = MAX_PATH * 2;
            bool havePath = QueryFullProcessImageNameW(h, 0, path, &size) != FALSE;
            HANDLE token = NULL;
            bool system = false, elevated = false, tokenRead = false;
            if (OpenProcessToken(h, TOKEN_QUERY, &token)) {
                BYTE buffer[256] = {};
                DWORD len = 0;
                if (GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &len)) {
                    system = IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(buffer)->User.Sid, WinLocalSystemSid) != FALSE;
                    tokenRead = true;
                }
                TOKEN_ELEVATION elevation = {};
                if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &len)) {
                    elevated = elevation.TokenIsElevated != 0;
                    tokenRead = true;
                }
                CloseHandle(token);
            }
            CloseHandle(h);
            if (!tokenRead) {
                notChecked++;
                continue;
            }
            if (!havePath || !(system || elevated)) continue;
            std::wstring image = path;
            if (!seen.insert(ToLowerW(image)).second) continue;
            out.push_back({ image, pe.szExeFile, system });
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

// ---------------------------------------------------------------------------
// DLL search order: the first folder Windows looks in for a program's DLLs is
// the program's own folder. Service folders, folders of programs running as
// SYSTEM or administrator, and system PATH folders that normal users can write
// to all let a planted DLL run with those rights.
// ---------------------------------------------------------------------------
SecurityCheckResult CheckDllSearchPaths()
{
    SecurityCheckResult result = MakeCheckResult(L"dll.hijack");
    std::wstringstream details;
    int serviceFolders = 0;
    int pathFolders = 0;

    std::set<std::wstring> seen;
    std::wstring error;
    for (const ServiceInfo& s : EnumerateServices(&error)) {
        if (s.startType == SERVICE_DISABLED || s.exePath.empty()) continue;
        std::wstring dir = DirectoryOf(s.exePath);
        if (dir.empty() || !DirectoryExists(dir)) continue;
        if (IsPackagedAppPath(s.exePath)) continue;   // protected by Windows as a whole
        std::wstring key = ToLowerW(dir);
        if (!seen.insert(key).second) continue;
        std::wstring who;
        if (LowPrivilegeWritable(dir, true, &who)) {
            serviceFolders++;
            details << L"  Service folder " << dir << L" (service " << s.name << L", runs as "
                    << (s.account.empty() ? L"LocalSystem" : s.account) << L") is writable by " << who << L"\n";
        }
    }

    // System PATH: services and SYSTEM processes that miss a DLL fall back to it.
    std::wstring systemPath = RegReadString(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", L"Path", true);
    for (const std::wstring& raw : SplitW(systemPath, L';')) {
        std::wstring dir = TrimW(raw);
        while (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'"')) dir.pop_back();
        if (!dir.empty() && dir.front() == L'"') dir.erase(dir.begin());
        if (dir.empty() || !DirectoryExists(dir)) continue;
        std::wstring who;
        if (LowPrivilegeWritable(dir, true, &who)) {
            pathFolders++;
            details << L"  System PATH folder " << dir << L" is writable by " << who << L"\n";
        }
    }

    // Running programs with administrator or SYSTEM rights: their own folder is the
    // first place Windows looks for each DLL they load that is not a KnownDLL.
    int notChecked = 0;
    int programFolders = 0;
    std::set<std::wstring> known = KnownDlls();
    CappedList programLines(40);
    for (const PrivilegedProgram& p : PrivilegedPrograms(notChecked)) {
        if (IsPackagedAppPath(p.image) || IsUnderWindowsDirectory(p.image)) continue;
        std::wstring dir = DirectoryOf(p.image);
        std::wstring key = ToLowerW(dir);
        if (dir.empty() || !seen.insert(key).second) continue;   // already reported as a service folder
        std::wstring who;
        if (!LowPrivilegeWritable(dir, true, &who)) continue;

        std::vector<std::wstring> plantable;
        PeInfo pe = ParsePeFile(ToExtendedPath(p.image));
        std::set<std::wstring> dllNames;
        for (const PeImport& imp : pe.imports) dllNames.insert(ToLowerW(std::wstring(imp.dll.begin(), imp.dll.end())));
        for (const std::wstring& dll : dllNames) {
            if (known.count(dll) || dll.rfind(L"api-ms-win-", 0) == 0 || dll.rfind(L"ext-ms-", 0) == 0) continue;
            plantable.push_back(dll);
        }
        programFolders++;
        std::wstring line = L"  Program folder " + dir + L" (" + p.name + L", running as " +
            (p.system ? L"SYSTEM" : L"an administrator") + L") is writable by " + who + L"\n";
        if (!plantable.empty()) {
            if (plantable.size() > 6) plantable.resize(6);
            line += L"      DLLs it loads that a copy in that folder would replace: " + JoinW(plantable, L", ") + L"\n";
        }
        programLines.Add(line);
    }
    details << programLines.Text();

    int total = serviceFolders + pathFolders + programFolders;
    std::wstring coverage = notChecked > 0
        ? L"\n" + std::to_wstring(notChecked) + L" running program(s) could not be checked" +
          (IsProcessElevated() ? L"." : L"; run as administrator to include them.")
        : L"";
    if (total > 0) {
        result.status = CHECK_FAIL;
        result.detail = std::to_wstring(total) + L" folder(s) let normal users plant DLLs that "
            L"privileged programs may load:\n" + details.str() + coverage;
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"No service folder, folder of a program running with administrator or SYSTEM rights, or system "
                        L"PATH folder is writable by normal users." + coverage;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Group Policy Preference passwords (cpassword) in SYSVOL
// ---------------------------------------------------------------------------
static bool IsGppFileName(const std::wstring& nameLower)
{
    return nameLower == L"groups.xml" || nameLower == L"services.xml" || nameLower == L"scheduledtasks.xml" ||
           nameLower == L"datasources.xml" || nameLower == L"printers.xml" || nameLower == L"drives.xml";
}

static void SearchGpp(const std::wstring& dir, int depth, std::vector<std::wstring>& hits, int& filesRead)
{
    if (depth > 8 || filesRead > 5000) return;
    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW(JoinPath(dir, L"*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        std::wstring full = JoinPath(dir, name);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            SearchGpp(full, depth + 1, hits, filesRead);
        }
        else if (IsGppFileName(ToLowerW(name))) {
            filesRead++;
            std::wstring text;
            if (ReadTextFile(full, text, 2 * 1024 * 1024)) {
                std::wstring lower = ToLowerW(text);
                size_t pos = lower.find(L"cpassword=\"");
                while (pos != std::wstring::npos) {
                    size_t start = pos + 11;
                    if (start < lower.size() && lower[start] != L'"') {
                        hits.push_back(full);
                        break;
                    }
                    pos = lower.find(L"cpassword=\"", start);
                }
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

SecurityCheckResult CheckGppPasswords()
{
    SecurityCheckResult result = MakeCheckResult(L"gpp.cpassword");
    std::wstring domain = GetJoinedDomainName();
    if (domain.empty()) {
        result.status = CHECK_NA;
        result.detail = L"This PC is not joined to a domain, so there is no SYSVOL to check.";
        return result;
    }
    std::wstring policies = L"\\\\" + domain + L"\\SYSVOL\\" + domain + L"\\Policies";
    if (!DirectoryExists(policies)) {
        result.status = CHECK_ERROR;
        result.detail = L"SYSVOL is not reachable at " + policies + L" (no domain controller in reach?).";
        return result;
    }
    std::vector<std::wstring> hits;
    int filesRead = 0;
    SearchGpp(policies, 0, hits, filesRead);
    if (!hits.empty()) {
        result.status = CHECK_FAIL;
        result.detail = std::to_wstring(hits.size()) + L" Group Policy Preference file(s) still hold a cpassword:\n";
        for (const std::wstring& h : hits) result.detail += L"  " + h + L"\n";
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"No cpassword values in " + std::to_wstring(filesRead) + L" preference file(s) under " + policies + L".";
    }
    return result;
}
