#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "CheckHelpers.h"
#include "FileIO.h"
#include "RegUtil.h"
#include "RegistryEnumerator.h"
#include "SystemInfo.h"
#include "TextUtils.h"

#include <windows.h>
#include <wincrypt.h>
#include <iomanip>
#include <set>
#include <sstream>

#pragma comment(lib, "crypt32.lib")

// ---------------------------------------------------------------------------
// Outdated software
// ---------------------------------------------------------------------------
struct BrowserExe {
    const wchar_t* name;
    std::vector<std::wstring> candidates;
};

// Browsers update themselves every few weeks. An executable that has not
// changed in two months means auto-update is broken.
static void CheckBrowserFreshness(std::wstringstream& details, int& stale)
{
    std::wstring pf = ExpandEnvironment(L"%ProgramFiles%");
    std::wstring pf86 = ExpandEnvironment(L"%ProgramFiles(x86)%");
    std::wstring local = ExpandEnvironment(L"%LOCALAPPDATA%");
    std::vector<BrowserExe> browsers = {
        { L"Google Chrome", { pf + L"\\Google\\Chrome\\Application\\chrome.exe", pf86 + L"\\Google\\Chrome\\Application\\chrome.exe",
                              local + L"\\Google\\Chrome\\Application\\chrome.exe" } },
        { L"Microsoft Edge", { pf86 + L"\\Microsoft\\Edge\\Application\\msedge.exe", pf + L"\\Microsoft\\Edge\\Application\\msedge.exe" } },
        { L"Mozilla Firefox", { pf + L"\\Mozilla Firefox\\firefox.exe", pf86 + L"\\Mozilla Firefox\\firefox.exe" } },
        { L"Brave", { pf + L"\\BraveSoftware\\Brave-Browser\\Application\\brave.exe", local + L"\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" } },
    };

    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    long long now = FileTimeToUnix(nowFt);
    for (const BrowserExe& b : browsers) {
        for (const std::wstring& path : b.candidates) {
            WIN32_FILE_ATTRIBUTE_DATA info = {};
            if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &info)) continue;
            long long modified = FileTimeToUnix(info.ftLastWriteTime);
            long long days = (now - modified) / 86400;
            details << L"  " << b.name << L": last updated " << FormatFileTime(info.ftLastWriteTime) << L" (" << days << L" days ago)";
            if (days > 60) {
                stale++;
                details << L"  STALE: auto-update seems broken";
            }
            details << L"\n";
            break;
        }
    }
}

SecurityCheckResult CheckOutdatedSoftware()
{
    SecurityCheckResult result = MakeCheckResult(L"sw.outdated");
    std::vector<InstalledProgram> programs = RegistryEnumerator::EnumerateInstalledPrograms();

    std::vector<SoftwareRule> rules = GetBuiltInSoftwareRules();
    std::wstring extraText;
    std::wstring extraPath = AppFilePath(L"outdated_software.txt");
    if (ReadTextFile(extraPath, extraText)) {
        std::vector<SoftwareRule> extra = ParseSoftwareRules(extraText);
        rules.insert(rules.end(), extra.begin(), extra.end());
    }

    std::vector<SoftwareFinding> findings = FindOutdatedSoftware(programs, rules);
    std::wstringstream details;
    for (const SoftwareFinding& f : findings) {
        details << L"  " << f.name << L" " << f.version;
        if (!f.minimumVersion.empty()) details << L" (update to " << f.minimumVersion << L" or later)";
        details << L": " << f.reason << L"\n";
    }

    std::wstringstream browsers;
    int stale = 0;
    CheckBrowserFreshness(browsers, stale);

    std::wstringstream detail;
    detail << programs.size() << L" installed program(s) checked against " << rules.size() << L" rule(s).\n";
    if (!findings.empty()) detail << L"Outdated or end-of-life:\n" << details.str();
    if (!browsers.str().empty()) detail << L"Browsers:\n" << browsers.str();

    if (!findings.empty()) result.status = CHECK_FAIL;
    else if (stale > 0) result.status = CHECK_WARNING;
    else result.status = CHECK_PASS;
    result.detail = detail.str();
    return result;
}

// ---------------------------------------------------------------------------
// Trusted root certificates
// ---------------------------------------------------------------------------
static std::wstring CertName(PCCERT_CONTEXT cert, DWORD flags)
{
    DWORD len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, NULL, NULL, 0);
    if (len <= 1) return L"";
    std::vector<wchar_t> buf(len);
    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, NULL, buf.data(), len);
    return buf.data();
}

static std::wstring Sha1Hex(PCCERT_CONTEXT cert)
{
    BYTE hash[20] = {};
    DWORD len = sizeof(hash);
    if (!CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID, hash, &len)) return L"";
    std::wstringstream ss;
    for (DWORD i = 0; i < len; ++i) ss << std::uppercase << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(hash[i]);
    return ss.str();
}

// Thumbprints of the roots in Microsoft's Trusted Root Program that Windows
// keeps in the AuthRoot store, read live so the list is never stale.
static std::set<std::wstring> AuthRootThumbprints()
{
    std::set<std::wstring> out;
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG, L"AuthRoot");
    if (!store) return out;
    PCCERT_CONTEXT cert = NULL;
    while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL) out.insert(Sha1Hex(cert));
    CertCloseStore(store, 0);
    return out;
}

static bool IsBuiltInRootSubject(const std::wstring& subject)
{
    const wchar_t* builtIn[] = {
        L"Microsoft Root Authority", L"Microsoft Root Certificate Authority", L"Microsoft Authenticode(tm) Root Authority",
        L"Copyright (c) 1997 Microsoft Corp.", L"Microsoft ECC Product Root Certificate Authority",
        L"Microsoft ECC TS Root Certificate Authority", L"Microsoft Time Stamp Root Certificate Authority",
        L"Microsoft Identity Verification Root Certificate Authority", L"Symantec Enterprise Mobile Root for Microsoft",
        L"Thawte Timestamping CA", L"VeriSign Time Stamping Service Root",
    };
    for (const wchar_t* b : builtIn) {
        if (StartsWithI(subject, b)) return true;
    }
    return false;
}

struct RootFinding {
    std::wstring store;
    std::wstring subject;
    std::wstring issuer;
    std::wstring thumbprint;
    std::wstring expires;
    std::wstring added;
    bool policy = false;
};

static void ScanRootStore(DWORD location, const wchar_t* locationName, HKEY regRoot, const std::wstring& regBase,
                          const std::set<std::wstring>& authRoot, std::vector<RootFinding>& out, int& total)
{
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, NULL,
        location | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG, L"Root");
    if (!store) return;
    PCCERT_CONTEXT cert = NULL;
    while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL) {
        total++;
        std::wstring thumb = Sha1Hex(cert);
        std::wstring subject = CertName(cert, 0);
        if (authRoot.count(thumb)) continue;
        if (IsBuiltInRootSubject(subject)) continue;
        RootFinding f;
        f.store = locationName;
        f.subject = AsciiPunctuation(subject);
        f.issuer = AsciiPunctuation(CertName(cert, CERT_NAME_ISSUER_FLAG));
        f.thumbprint = thumb;
        SYSTEMTIME st = {};
        FileTimeToSystemTime(&cert->pCertInfo->NotAfter, &st);
        wchar_t buf[32];
        swprintf_s(buf, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
        f.expires = buf;
        FILETIME written = {};
        if (RegKeyLastWrite(regRoot, regBase + L"\\" + thumb, written)) f.added = FormatFileTime(written);
        out.push_back(f);
    }
    CertCloseStore(store, 0);
}

SecurityCheckResult CheckRootCertificates()
{
    SecurityCheckResult result = MakeCheckResult(L"cert.roots");
    std::set<std::wstring> authRoot = AuthRootThumbprints();
    std::vector<RootFinding> findings;
    int total = 0;
    ScanRootStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, L"Computer", HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\SystemCertificates\\ROOT\\Certificates", authRoot, findings, total);
    ScanRootStore(CERT_SYSTEM_STORE_CURRENT_USER, L"Current user", HKEY_CURRENT_USER,
        L"Software\\Microsoft\\SystemCertificates\\Root\\Certificates", authRoot, findings, total);

    // Roots pushed by Group Policy are deliberate company roots: list, do not flag.
    std::vector<RootFinding> policyRoots;
    {
        HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, NULL,
            CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG, L"Root");
        if (store) {
            PCCERT_CONTEXT cert = NULL;
            while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL) {
                RootFinding f;
                f.store = L"Group Policy";
                f.subject = CertName(cert, 0);
                f.thumbprint = Sha1Hex(cert);
                f.policy = true;
                policyRoots.push_back(f);
            }
            CertCloseStore(store, 0);
        }
    }

    std::wstringstream details;
    for (const RootFinding& f : findings) {
        details << L"  [" << f.store << L"] " << f.subject << L"\n      thumbprint " << f.thumbprint
                << L", expires " << f.expires;
        if (!f.added.empty()) details << L", added about " << f.added;
        details << L"\n";
    }
    for (const RootFinding& f : policyRoots) {
        details << L"  [Group Policy] " << f.subject << L" (" << f.thumbprint << L")\n";
    }

    if (!findings.empty()) {
        result.status = CHECK_WARNING;
        result.detail = std::to_wstring(findings.size()) + L" trusted root(s) are not part of Microsoft's root program. "
            L"Make sure you or your organization installed them:\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"All " + std::to_wstring(total) + L" trusted roots come from Microsoft's root program or Windows itself." +
            (policyRoots.empty() ? L"" : L"\n" + details.str());
    }
    return result;
}
