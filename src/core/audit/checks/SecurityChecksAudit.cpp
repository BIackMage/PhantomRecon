#include "pch.h"
#include "SecurityCheckModules.h"

#include "CheckHelpers.h"
#include "RegUtil.h"
#include "SystemInfo.h"
#include "TextUtils.h"

#include <windows.h>
#include <objbase.h>
#include <ntsecapi.h>

#pragma comment(lib, "ole32.lib")
#include <sstream>

#pragma comment(lib, "advapi32.lib")

static bool ParseGuid(const std::wstring& text, GUID& out)
{
    return CLSIDFromString(text.c_str(), &out) == NOERROR;
}

static std::wstring AuditFlagsText(ULONG flags)
{
    bool s = (flags & POLICY_AUDIT_EVENT_SUCCESS) != 0;
    bool f = (flags & POLICY_AUDIT_EVENT_FAILURE) != 0;
    if (s && f) return L"Success and Failure";
    if (s) return L"Success";
    if (f) return L"Failure";
    return L"No Auditing";
}

SecurityCheckResult CheckAuditSubcategories()
{
    SecurityCheckResult result = MakeCheckResult(L"audit.subcategories");
    const std::vector<AuditSubcategory>& wanted = GetRecommendedAuditSubcategories();

    std::vector<GUID> guids;
    for (const AuditSubcategory& a : wanted) {
        GUID g = {};
        if (ParseGuid(a.guid, g)) guids.push_back(g);
    }

    // Reading the audit policy needs SeSecurityPrivilege, which only an elevated
    // administrator has. Enable it for the duration of the call.
    bool privilege = SetProcessPrivilege(SE_SECURITY_NAME, true);
    PAUDIT_POLICY_INFORMATION policies = NULL;
    BOOLEAN ok = AuditQuerySystemPolicy(guids.data(), static_cast<ULONG>(guids.size()), &policies);
    DWORD err = ok ? 0 : GetLastError();
    if (privilege) SetProcessPrivilege(SE_SECURITY_NAME, false);

    if (!ok) {
        if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD) {
            result.status = CHECK_INFO;
            result.detail = L"Windows only lets administrators read the audit policy. Run Phantom Recon as administrator for this check.";
        }
        else {
            result.status = CHECK_ERROR;
            result.detail = L"AuditQuerySystemPolicy failed (error " + std::to_wstring(err) + L").";
        }
        return result;
    }

    std::wstringstream details;
    std::wstringstream missing;
    int gaps = 0;
    for (size_t i = 0; i < wanted.size() && i < guids.size(); ++i) {
        ULONG flags = policies[i].AuditingInformation;
        bool needSuccess = wanted[i].wantSuccess && !(flags & POLICY_AUDIT_EVENT_SUCCESS);
        bool needFailure = wanted[i].wantFailure && !(flags & POLICY_AUDIT_EVENT_FAILURE);

        std::wstring name = wanted[i].name;
        PWSTR localized = NULL;
        if (AuditLookupSubCategoryNameW(&guids[i], &localized) && localized) {
            name = localized;
            AuditFree(localized);
        }
        details << L"  " << name << L": " << AuditFlagsText(flags);
        if (needSuccess || needFailure) {
            gaps++;
            details << L"  (recommended: " << (wanted[i].wantSuccess ? L"Success" : L"")
                    << (wanted[i].wantSuccess && wanted[i].wantFailure ? L" and " : L"")
                    << (wanted[i].wantFailure ? L"Failure" : L"") << L")";
            missing << L"  auditpol /set /subcategory:" << wanted[i].guid
                    << (wanted[i].wantSuccess ? L" /success:enable" : L"")
                    << (wanted[i].wantFailure ? L" /failure:enable" : L"") << L"\n";
        }
        details << L"\n";
    }
    AuditFree(policies);

    DWORD cmdLine = 0;
    bool cmdLineOn = RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
        L"ProcessCreationIncludeCmdLine_Enabled", cmdLine) && cmdLine == 1;
    details << L"  Command line in process events: " << (cmdLineOn ? L"On" : L"Off") << L"\n";

    if (gaps > 0) {
        result.status = gaps >= 4 ? CHECK_FAIL : CHECK_WARNING;
        result.detail = std::to_wstring(gaps) + L" of " + std::to_wstring(wanted.size()) +
            L" important audit subcategories are not recorded.\n" + details.str() +
            L"Commands for the missing ones:\n" + missing.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"All recommended audit subcategories are recorded.\n" + details.str();
    }
    return result;
}
