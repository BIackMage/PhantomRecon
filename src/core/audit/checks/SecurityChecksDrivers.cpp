#include "pch.h"
#include "SecurityChecksDrivers.h"

#include "AppPaths.h"
#include "CheckHelpers.h"
#include "FileAnalysis.h"
#include "HostRules.h"
#include "ServiceUtil.h"
#include "TextUtils.h"

#include <windows.h>
#include <map>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SecurityChecksDrivers] " + msg + L"\n").c_str());
}

struct FolderVerdict {
    bool         writable = false;
    std::wstring who;
};

SecurityCheckResult CheckDriverServices()
{
    SecurityCheckResult result = MakeCheckResult(L"svc.drivers");
    DriversFacts facts;
    std::wstring error;
    // Configuration only (QueryServiceConfig): nothing is started, stopped or changed.
    std::vector<ServiceInfo> services = EnumerateServicesOfType(SERVICE_DRIVER, &error);
    facts.listed = !(services.empty() && !error.empty());
    facts.listError = error;
    facts.total = static_cast<int>(services.size());

    std::wstring root = ExpandEnvironment(L"%SystemRoot%");
    if (root.empty() || root[0] == L'%') root = L"C:\\Windows";

    std::vector<DriverFacts> findings;
    std::map<std::wstring, FolderVerdict> folders;   // most drivers share System32\drivers
    ULONGLONG started = GetTickCount64();
    for (const ServiceInfo& s : services) {
        if (!s.configRead) {
            facts.unreadable++;
            continue;
        }
        if (s.startType == SERVICE_DISABLED) {
            facts.disabled++;
            continue;
        }
        // A file system recognizer without an ImagePath lives inside another driver.
        if (s.serviceType == SERVICE_RECOGNIZER_DRIVER && TrimW(s.binaryPathRaw).empty()) continue;
        facts.checked++;

        DriverFacts d;
        d.name = s.name;
        d.displayName = s.displayName;
        d.imagePath = s.binaryPathRaw;
        d.file = DriverImagePathToFile(s.binaryPathRaw, s.name, root);
        d.startType = s.startType;
        d.fileExists = FileExists(d.file);
        if (d.fileExists) {
            SignatureSummary signature = GetSignatureSummary(d.file);
            d.signatureValid = signature.valid;
            d.signatureStatus = signature.status;
            d.fileWritable = LowPrivilegeWritable(d.file, false, &d.writableWho);
            std::wstring folder = DirectoryOf(d.file);
            std::wstring key = ToLowerW(folder);
            auto it = folders.find(key);
            if (it == folders.end()) {
                FolderVerdict v;
                if (!folder.empty() && DirectoryExists(folder)) v.writable = LowPrivilegeWritable(folder, true, &v.who);
                it = folders.emplace(key, v).first;
            }
            d.folderWritable = it->second.writable;
            if (d.folderWritable && !d.fileWritable) d.writableWho = it->second.who;
        }
        if (DriverProblems(d) != 0) {
            facts.flagged++;
            findings.push_back(d);
        }
    }

    std::wstring text;
    result.status = DriversStatus(facts, &text);
    result.detail = text;
    if (!findings.empty()) {
        SortDriverFindings(findings);
        CappedList listed(60);
        for (const DriverFacts& d : findings) listed.Add(DriverFindingLine(d));
        result.detail += L"\n" + listed.Text();
    }
    DebugLog(L"Driver services -> " + result.status + L" (" + std::to_wstring(facts.checked) + L" checked, " +
             std::to_wstring(folders.size()) + L" folder(s), " + std::to_wstring(GetTickCount64() - started) + L" ms)");
    return result;
}
