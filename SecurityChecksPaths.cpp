#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "FileIO.h"
#include "RegUtil.h"
#include "ServiceUtil.h"
#include "SystemInfo.h"
#include "TextUtils.h"

#include <windows.h>
#include <set>
#include <sstream>

// ---------------------------------------------------------------------------
// DLL search order: service folders and system PATH folders writable by users
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

    if (serviceFolders + pathFolders > 0) {
        result.status = CHECK_FAIL;
        result.detail = std::to_wstring(serviceFolders + pathFolders) + L" folder(s) let normal users plant DLLs that "
            L"privileged programs may load:\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"No service folder or system PATH folder is writable by normal users.";
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
