#include "pch.h"
#include "SecurityCheckModules.h"

#include "SystemInfo.h"
#include "TextUtils.h"

#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <sstream>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

struct LocalAccount {
    std::wstring name;
    DWORD        rid = 0;
    bool         disabled = false;
    bool         passwordNotRequired = false;
    bool         passwordNeverExpires = false;
    DWORD        passwordAgeSeconds = 0;
    DWORD        lastLogon = 0;       // seconds since 1970, 0 = never
};

static std::vector<LocalAccount> EnumerateLocalAccounts(std::wstring* error)
{
    std::vector<LocalAccount> accounts;
    DWORD resume = 0;
    NET_API_STATUS status;
    do {
        LPBYTE buffer = NULL;
        DWORD read = 0, total = 0;
        status = NetUserEnum(NULL, 3, FILTER_NORMAL_ACCOUNT, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            if (error) *error = L"NetUserEnum failed (" + std::to_wstring(status) + L")";
            if (buffer) NetApiBufferFree(buffer);
            break;
        }
        USER_INFO_3* users = reinterpret_cast<USER_INFO_3*>(buffer);
        for (DWORD i = 0; i < read; ++i) {
            LocalAccount a;
            a.name = users[i].usri3_name ? users[i].usri3_name : L"";
            a.rid = users[i].usri3_user_id;
            a.disabled = (users[i].usri3_flags & UF_ACCOUNTDISABLE) != 0;
            a.passwordNotRequired = (users[i].usri3_flags & UF_PASSWD_NOTREQD) != 0;
            a.passwordNeverExpires = (users[i].usri3_flags & UF_DONT_EXPIRE_PASSWD) != 0;
            a.passwordAgeSeconds = users[i].usri3_password_age;
            a.lastLogon = users[i].usri3_last_logon;
            accounts.push_back(a);
        }
        if (buffer) NetApiBufferFree(buffer);
    } while (status == ERROR_MORE_DATA);
    return accounts;
}

static const LocalAccount* FindByRid(const std::vector<LocalAccount>& accounts, DWORD rid)
{
    for (const LocalAccount& a : accounts) {
        if (a.rid == rid) return &a;
    }
    return nullptr;
}

static std::vector<std::wstring> LocalAdministrators()
{
    std::vector<std::wstring> members;
    // Look up the localized name of BUILTIN\Administrators from its SID.
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sid);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid, &sidSize)) return members;
    wchar_t name[256] = {};
    wchar_t domain[256] = {};
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(NULL, sid, name, &nameLen, domain, &domainLen, &use)) return members;

    LPBYTE buffer = NULL;
    DWORD read = 0, total = 0;
    DWORD_PTR resume = 0;
    if (NetLocalGroupGetMembers(NULL, name, 2, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume) == NERR_Success) {
        LOCALGROUP_MEMBERS_INFO_2* info = reinterpret_cast<LOCALGROUP_MEMBERS_INFO_2*>(buffer);
        for (DWORD i = 0; i < read; ++i) {
            if (info[i].lgrmi2_domainandname) members.push_back(info[i].lgrmi2_domainandname);
        }
    }
    if (buffer) NetApiBufferFree(buffer);
    return members;
}

SecurityCheckResult CheckGuestAccount()
{
    SecurityCheckResult result = MakeCheckResult(L"acct.guest");
    std::wstring error;
    std::vector<LocalAccount> accounts = EnumerateLocalAccounts(&error);
    if (accounts.empty()) {
        result.status = CHECK_ERROR;
        result.detail = error.empty() ? L"No local accounts could be read." : error;
        return result;
    }
    const LocalAccount* guest = FindByRid(accounts, DOMAIN_USER_RID_GUEST);
    if (!guest) {
        result.status = CHECK_PASS;
        result.detail = L"There is no Guest account.";
    }
    else if (guest->disabled) {
        result.status = CHECK_PASS;
        result.detail = L"The Guest account (" + guest->name + L") is disabled.";
    }
    else {
        result.status = CHECK_FAIL;
        result.detail = L"The Guest account (" + guest->name + L") is ENABLED.";
    }
    const LocalAccount* defaultAccount = FindByRid(accounts, 503);
    if (defaultAccount && !defaultAccount->disabled) {
        result.detail += L"\nDefaultAccount (" + defaultAccount->name + L") is also enabled.";
        if (result.status == CHECK_PASS) result.status = CHECK_WARNING;
    }
    return result;
}

SecurityCheckResult CheckBuiltinAdministrator()
{
    SecurityCheckResult result = MakeCheckResult(L"acct.admin");
    std::wstring error;
    std::vector<LocalAccount> accounts = EnumerateLocalAccounts(&error);
    const LocalAccount* admin = FindByRid(accounts, DOMAIN_USER_RID_ADMIN);
    if (!admin) {
        result.status = accounts.empty() ? CHECK_ERROR : CHECK_PASS;
        result.detail = accounts.empty() ? error : L"No built-in Administrator account found.";
        return result;
    }
    bool renamed = !EqualsI(admin->name, L"Administrator");
    if (admin->disabled) {
        result.status = CHECK_PASS;
        result.detail = L"The built-in Administrator (" + admin->name + L") is disabled.";
    }
    else if (renamed) {
        result.status = CHECK_WARNING;
        result.detail = L"The built-in Administrator is enabled but renamed to \"" + admin->name + L"\".";
    }
    else {
        result.status = CHECK_FAIL;
        result.detail = L"The built-in Administrator account is enabled and still called Administrator.";
    }
    return result;
}

SecurityCheckResult CheckLocalAccounts()
{
    SecurityCheckResult result = MakeCheckResult(L"acct.local");
    std::wstring error;
    std::vector<LocalAccount> accounts = EnumerateLocalAccounts(&error);
    if (accounts.empty()) {
        result.status = CHECK_ERROR;
        result.detail = error.empty() ? L"No local accounts could be read." : error;
        return result;
    }

    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    long long now = FileTimeToUnix(nowFt);

    std::wstringstream details;
    int problems = 0;
    int enabled = 0;
    for (const LocalAccount& a : accounts) {
        if (!a.disabled) enabled++;
        long long pwDays = a.passwordAgeSeconds / 86400;
        std::wstring lastLogon = a.lastLogon == 0 ? L"never" : FormatUnixTime(a.lastLogon);
        details << L"  " << a.name << L": " << (a.disabled ? L"disabled" : L"enabled")
                << L", password " << pwDays << L" days old, last logon " << lastLogon;
        std::vector<std::wstring> notes;
        if (!a.disabled && a.passwordNotRequired && a.rid != DOMAIN_USER_RID_GUEST) {
            notes.push_back(L"PASSWORD NOT REQUIRED");
            problems++;
        }
        if (!a.disabled && a.passwordNeverExpires && pwDays > 365) notes.push_back(L"password over a year old and never expires");
        if (!a.disabled && a.lastLogon != 0 && now - static_cast<long long>(a.lastLogon) > 180LL * 86400) {
            notes.push_back(L"no logon for 6 months");
        }
        if (!notes.empty()) details << L" [" << JoinW(notes, L"; ") << L"]";
        details << L"\n";
    }

    std::vector<std::wstring> admins = LocalAdministrators();
    details << L"Administrators group: " << (admins.empty() ? L"(could not read)" : JoinW(admins, L", ")) << L"\n";

    if (problems > 0) {
        result.status = CHECK_FAIL;
        result.detail = std::to_wstring(problems) + L" enabled account(s) do not need a password.\n" + details.str();
    }
    else if (admins.size() > 3) {
        result.status = CHECK_WARNING;
        result.detail = std::to_wstring(admins.size()) + L" members in Administrators. Fewer is safer.\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = std::to_wstring(enabled) + L" enabled local account(s).\n" + details.str();
    }
    return result;
}

SecurityCheckResult CheckPasswordPolicy()
{
    SecurityCheckResult result = MakeCheckResult(L"acct.passwordpolicy");
    LPBYTE b0 = NULL;
    LPBYTE b3 = NULL;
    if (NetUserModalsGet(NULL, 0, &b0) != NERR_Success || NetUserModalsGet(NULL, 3, &b3) != NERR_Success) {
        if (b0) NetApiBufferFree(b0);
        if (b3) NetApiBufferFree(b3);
        result.status = CHECK_ERROR;
        result.detail = L"The local password policy could not be read.";
        return result;
    }
    USER_MODALS_INFO_0* m0 = reinterpret_cast<USER_MODALS_INFO_0*>(b0);
    USER_MODALS_INFO_3* m3 = reinterpret_cast<USER_MODALS_INFO_3*>(b3);
    DWORD minLen = m0->usrmod0_min_passwd_len;
    DWORD history = m0->usrmod0_password_hist_len;
    DWORD maxAgeDays = m0->usrmod0_max_passwd_age == TIMEQ_FOREVER ? 0 : m0->usrmod0_max_passwd_age / 86400;
    DWORD threshold = m3->usrmod3_lockout_threshold;
    DWORD duration = m3->usrmod3_lockout_duration / 60;
    NetApiBufferFree(b0);
    NetApiBufferFree(b3);

    std::wstringstream details;
    details << L"Minimum password length: " << minLen << L"\n";
    details << L"Password history: " << history << L"\n";
    details << L"Maximum password age: " << (maxAgeDays == 0 ? L"never expires" : std::to_wstring(maxAgeDays) + L" days") << L"\n";
    details << L"Lockout threshold: " << (threshold == 0 ? L"never locks out" : std::to_wstring(threshold) + L" attempts") << L"\n";
    details << L"Lockout duration: " << duration << L" minutes\n";
    std::wstring domain = GetJoinedDomainName();
    if (!domain.empty()) details << L"This PC is joined to " << domain << L"; domain accounts follow the domain policy.\n";

    bool fail = threshold == 0 || threshold > 10 || minLen < 8;
    bool warn = minLen < 14 || threshold > 5;
    if (fail) {
        result.status = CHECK_FAIL;
        result.detail = std::wstring(threshold == 0 ? L"Accounts never lock out after wrong passwords." : L"Password rules are weak.") +
            L"\n" + details.str();
    }
    else if (warn) {
        result.status = CHECK_WARNING;
        result.detail = L"Password rules are below the CIS recommendation (14 characters, lockout at 5 or fewer).\n" + details.str();
    }
    else {
        result.status = CHECK_PASS;
        result.detail = L"Password length and lockout meet the recommendation.\n" + details.str();
    }
    return result;
}
