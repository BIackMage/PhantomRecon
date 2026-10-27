#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "Baseline.h"
#include "CheckCatalog.h"
#include "FileIO.h"
#include "HardeningScore.h"
#include "SystemInfo.h"
#include "TextUtils.h"
#include "Version.h"

#include <map>
#include <memory>
#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[Audit] " + msg + L"\n").c_str());
}

using CheckFn = std::function<SecurityCheckResult(const AuditContext&)>;

// Safety net: no single check's evidence may exceed this many characters. Each
// check caps its own lists; this catches anything that slips past (a report that
// is mostly one check is no use to anyone, and Windows edit boxes choke on it).
static const size_t kMaxDetailChars = 20000;

std::wstring LimitDetail(const std::wstring& detail)
{
    if (detail.size() <= kMaxDetailChars) return detail;
    size_t cut = detail.rfind(L'\n', kMaxDetailChars);
    if (cut == std::wstring::npos || cut < kMaxDetailChars / 2) cut = kMaxDetailChars;
    return detail.substr(0, cut) + L"\n... (the rest of this evidence, " + std::to_wstring(detail.size() - cut) +
           L" characters, was cut to keep the report readable)";
}

template <typename F>
static CheckFn Plain(F f)
{
    return [f](const AuditContext&) { return f(); };
}

static const std::map<std::wstring, CheckFn>& CheckFunctions()
{
    static const std::map<std::wstring, CheckFn> functions = {
        { L"def.realtime",        Plain(CheckDefenderRealtime) },
        { L"def.tamper",          Plain(CheckDefenderTamper) },
        { L"def.cloud",           Plain(CheckDefenderCloud) },
        { L"def.signatures",      Plain(CheckDefenderSignatures) },
        { L"def.exclusions",      Plain(CheckDefenderExclusions) },
        { L"def.asr",             Plain(CheckDefenderAsr) },
        { L"def.smartscreen",     Plain(CheckSmartScreen) },
        { L"def.cfa",             Plain(CheckControlledFolderAccess) },
        { L"wu.status",           Plain(CheckWindowsUpdateStatus) },
        { L"sw.outdated",         Plain(CheckOutdatedSoftware) },
        { L"hard.bitlocker",      Plain(CheckBitLocker) },
        { L"hard.tpm",            Plain(CheckTpm) },
        { L"hard.secureboot",     Plain(CheckSecureBoot) },
        { L"hard.uac",            Plain(CheckUac) },
        { L"hard.autoplay",       Plain(CheckAutoPlay) },
        { L"hard.wsh",            Plain(CheckWindowsScriptHost) },
        { L"hard.psv2",           Plain(CheckPowerShellV2) },
        { L"hard.macros",         Plain(CheckOfficeMacros) },
        { L"hard.hvci",           Plain(CheckMemoryIntegrity) },
        { L"hard.driverblocklist", Plain(CheckDriverBlocklist) },
        { L"hard.smartapp",       Plain(CheckSmartAppControl) },
        { L"hard.exploitprot",    Plain(CheckExploitProtection) },
        { L"backup.restore",      Plain(CheckSystemRestore) },
        { L"acct.screenlock",     Plain(CheckScreenLock) },
        { L"net.wifiopen",        Plain(CheckOpenWifi) },
        { L"lsa.ppl",             Plain(CheckLsaProtection) },
        { L"lsa.credguard",       Plain(CheckCredentialGuard) },
        { L"acct.guest",          Plain(CheckGuestAccount) },
        { L"acct.admin",          Plain(CheckBuiltinAdministrator) },
        { L"acct.local",          Plain(CheckLocalAccounts) },
        { L"acct.passwordpolicy", Plain(CheckPasswordPolicy) },
        { L"svc.unquoted",        Plain(CheckUnquotedServicePaths) },
        { L"svc.writable",        Plain(CheckWritableServiceExes) },
        { L"msi.alwayselevated",  Plain(CheckAlwaysInstallElevated) },
        { L"dll.hijack",          Plain(CheckDllSearchPaths) },
        { L"files.unattend",      Plain(CheckUnattendedInstallFiles) },
        { L"gpp.cpassword",       Plain(CheckGppPasswords) },
        { L"svc.spooler",         Plain(CheckPrintSpooler) },
        { L"fw.profiles",         Plain(CheckWindowsFirewall) },
        { L"net.listening",       Plain(CheckListeningPorts) },
        { L"net.llmnr",           Plain(CheckLLMNR) },
        { L"net.nbtns",           Plain(CheckNBTNS) },
        { L"net.mdns",            Plain(CheckMDNS) },
        { L"net.smbsigning",      Plain(CheckSMBSigning) },
        { L"net.smbv1",           Plain(CheckSmbV1) },
        { L"net.rdp",             Plain(CheckRemoteDesktop) },
        { L"net.winrm",           Plain(CheckWinRm) },
        { L"net.remoteregistry",  Plain(CheckRemoteRegistry) },
        { L"net.wpad",            Plain(CheckProxyAutoDetect) },
        { L"net.hosts",           Plain(CheckHostsFile) },
        { L"net.dns",             Plain(CheckDnsSettings) },
        { L"cert.roots",          Plain(CheckRootCertificates) },
        { L"persist.sweep",       CheckPersistence },
        { L"persist.tasks",       Plain(CheckScheduledTasks) },
        { L"proc.image",          CheckRunningPrograms },
        { L"audit.subcategories", Plain(CheckAuditSubcategories) },
        { L"audit.policy",        Plain(CheckEventLogSettings) },
        { L"ps.logging",          Plain(CheckPowerShellLogging) },
    };
    return functions;
}

std::vector<std::wstring> GetCheckFunctionIds()
{
    std::vector<std::wstring> ids;
    for (const auto& entry : CheckFunctions()) ids.push_back(entry.first);
    DebugLog(std::to_wstring(ids.size()) + L" check functions registered");
    return ids;
}

const std::vector<RegisteredCheck>& GetRegisteredChecks()
{
    // Report order follows the catalog, so every check has catalog text and
    // every catalog row has a function (tests enforce both directions).
    static const std::vector<RegisteredCheck> checks = [] {
        std::vector<RegisteredCheck> list;
        const auto& functions = CheckFunctions();
        for (const CheckInfo& info : GetCheckCatalog()) {
            auto it = functions.find(info.id);
            if (it != functions.end()) list.push_back({ info.id, it->second });
        }
        return list;
    }();
    return checks;
}

std::vector<SecurityCheckResult> RunAllSecurityChecks(const AuditContext& contextIn)
{
    AuditContext context = contextIn;
    std::unique_ptr<Baseline> baseline;
    if (!context.baseline && !context.baselinePath.empty() && FileExists(context.baselinePath)) {
        baseline = std::make_unique<Baseline>();
        if (baseline->LoadFromFile(context.baselinePath)) {
            context.baseline = baseline.get();
        }
    }

    const std::vector<RegisteredCheck>& checks = GetRegisteredChecks();
    std::vector<SecurityCheckResult> results;
    results.reserve(checks.size());
    int done = 0;
    for (const RegisteredCheck& check : checks) {
        if (context.isCancelled && context.isCancelled()) break;
        const CheckInfo* info = FindCheckInfo(check.id);
        if (context.onProgress) context.onProgress(done, static_cast<int>(checks.size()), info ? info->title : check.id);

        SecurityCheckResult r;
        ULONGLONG started = GetTickCount64();
        try {
            r = check.run(context);
        }
        catch (const std::exception& e) {
            r = MakeCheckResult(check.id);
            r.status = CHECK_ERROR;
            std::string what = e.what();
            r.detail = L"The check stopped with an error: " + std::wstring(what.begin(), what.end());
        }
        catch (...) {
            r = MakeCheckResult(check.id);
            r.status = CHECK_ERROR;
            r.detail = L"The check stopped with an unexpected error.";
        }
        if (r.id.empty()) r.id = check.id;
        if (r.name.empty()) r.name = info ? info->title : check.id;
        r.detail = LimitDetail(AsciiPunctuation(r.detail));
        DebugLog(check.id + L" -> " + r.status + L" in " + std::to_wstring(GetTickCount64() - started) + L" ms");
        results.push_back(r);
        done++;
    }
    if (context.onProgress) context.onProgress(done, static_cast<int>(checks.size()), L"Done");
    return results;
}

std::vector<SecurityCheckResult> RunAllSecurityChecks()
{
    return RunAllSecurityChecks(AuditContext());
}

std::wstring GetSecuritySummary(const std::vector<SecurityCheckResult>& results)
{
    HardeningScore score = ComputeHardeningScore(results);
    std::wstringstream ss;
    ss << L"--- Security Audit ---\n";
    ss << L"Hardening score: " << score.score << L"/100 (" << score.label << L")\n";
    for (const SecurityCheckResult& r : results) {
        if (r.status != CHECK_FAIL && r.status != CHECK_WARNING) continue;
        ss << (r.status == CHECK_FAIL ? L"[FAIL] " : L"[WARN] ") << r.name << L"\n";
    }
    ss << L"\nTotal: " << score.pass << L" pass, " << score.fail << L" fail, " << score.warn << L" warn, "
       << score.info + score.notApplicable << L" info, " << score.error << L" err";
    return ss.str();
}

bool WriteSecurityReport(const std::wstring& outputPath, const std::vector<SecurityCheckResult>& results)
{
    HardeningScore score = ComputeHardeningScore(results);
    std::wstringstream out;
    out << L"=== " << PHANTOMRECON_NAME_W << L" Security Audit Report ===\r\n";
    out << L"Version " << PHANTOMRECON_VERSION_W << L"\r\n";
    out << GetWindowsVersionText() << L"\r\n";
    out << L"Hardening score: " << score.score << L"/100 (" << score.label << L"), "
        << score.pass << L" pass, " << score.warn << L" warn, " << score.fail << L" fail\r\n";
    out << L"=========================================\r\n\r\n";

    for (const SecurityCheckResult& r : results) {
        const CheckInfo* info = FindCheckInfo(r.id);
        out << L"CHECK: " << r.name << L" [" << r.id << L"]\r\n";
        out << L"STATUS: " << r.status;
        if (info) out << L"   SEVERITY: " << SeverityName(info->severity);
        out << L"\r\n";
        if (info && !info->attack.empty()) out << L"ATT&CK: " << JoinW(info->attack, L", ") << L"\r\n";
        if (info && !info->cisControls.empty()) out << L"CIS Controls v8: " << JoinW(info->cisControls, L", ") << L"\r\n";
        out << L"DETAIL: " << ReplaceAllW(r.detail, L"\n", L"\r\n") << L"\r\n";
        if (info && (r.status == CHECK_FAIL || r.status == CHECK_WARNING)) {
            out << L"WHAT IT MEANS: " << info->explanation << L"\r\n";
            out << L"HOW TO FIX:\r\n" << ReplaceAllW(info->fix, L"\n", L"\r\n") << L"\r\n";
            out << L"HOW TO UNDO:\r\n" << ReplaceAllW(info->undo, L"\n", L"\r\n") << L"\r\n";
        }
        out << L"-----------------------------------------\r\n";
    }
    return WriteUtf8File(outputPath, out.str(), true);
}
