#include "pch.h"
#include "SecurityChecksSignin.h"

#include "HostRules.h"
#include "RegUtil.h"
#include "TextUtils.h"

#include <windows.h>

#pragma comment(lib, "advapi32.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SecurityChecksSignin] " + msg + L"\n").c_str());
}

static OptionalDword ReadOptionalDword(HKEY root, const std::wstring& key, const std::wstring& value)
{
    OptionalDword o;
    o.set = RegReadDword(root, key, value, o.value);
    return o;
}

// ===========================================================================
// Automatic sign-in
// ===========================================================================
static const wchar_t* const kWinlogonKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

// SECURITY: DefaultPassword holds a sign-in password in plain text. This asks Windows
// only whether the value exists and how many bytes it has: the data pointer passed to
// RegQueryValueExW is NULL, so the password itself is never read, kept, logged, shown
// or sent anywhere. Do not change this to read the data.
static bool DefaultPasswordExists(DWORD& bytes)
{
    bytes = 0;
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kWinlogonKey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    DWORD type = 0;
    LONG rc = RegQueryValueExW(key, L"DefaultPassword", NULL, &type, NULL, &bytes);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS) bytes = 0;
    return rc == ERROR_SUCCESS;
}

SecurityCheckResult CheckAutoLogon()
{
    SecurityCheckResult result = MakeCheckResult(L"acct.autologon");
    AutoLogonFacts facts;
    facts.keyReadable = RegOpenStatus(HKEY_LOCAL_MACHINE, kWinlogonKey) != ERROR_ACCESS_DENIED;
    facts.autoAdminLogon = RegReadString(HKEY_LOCAL_MACHINE, kWinlogonKey, L"AutoAdminLogon", false);
    if (facts.autoAdminLogon.empty()) {
        DWORD asNumber = 0;   // some tools write it as a DWORD; Winlogon reads both
        if (RegReadDword(HKEY_LOCAL_MACHINE, kWinlogonKey, L"AutoAdminLogon", asNumber)) facts.autoAdminLogon = std::to_wstring(asNumber);
    }
    facts.defaultPasswordPresent = DefaultPasswordExists(facts.defaultPasswordBytes);
    // The account name goes into the evidence like every other name on this PC, so the
    // report's name hiding (Redactor) replaces it when the user asks for that.
    facts.defaultUserName = RegReadString(HKEY_LOCAL_MACHINE, kWinlogonKey, L"DefaultUserName", false);
    facts.defaultDomainName = RegReadString(HKEY_LOCAL_MACHINE, kWinlogonKey, L"DefaultDomainName", false);
    facts.autoLogonCount = ReadOptionalDword(HKEY_LOCAL_MACHINE, kWinlogonKey, L"AutoLogonCount");

    std::wstring text;
    result.status = AutoLogonStatus(facts, &text);
    result.detail = text;
    DebugLog(L"Automatic sign-in -> " + result.status);
    return result;
}

// ===========================================================================
// NTLM and LAN Manager
// ===========================================================================
SecurityCheckResult CheckNtlmSettings()
{
    SecurityCheckResult result = MakeCheckResult(L"cred.ntlm");
    const wchar_t* lsa = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
    const wchar_t* msv = L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0";
    NtlmFacts facts;
    facts.lsaReadable = RegOpenStatus(HKEY_LOCAL_MACHINE, lsa) != ERROR_ACCESS_DENIED;
    facts.lmCompatibilityLevel = ReadOptionalDword(HKEY_LOCAL_MACHINE, lsa, L"LmCompatibilityLevel");
    facts.noLmHash = ReadOptionalDword(HKEY_LOCAL_MACHINE, lsa, L"NoLMHash");
    facts.minClientSec = ReadOptionalDword(HKEY_LOCAL_MACHINE, msv, L"NtlmMinClientSec");
    facts.minServerSec = ReadOptionalDword(HKEY_LOCAL_MACHINE, msv, L"NtlmMinServerSec");

    std::vector<std::wstring> lines;
    result.status = NtlmStatus(facts, &lines);
    std::wstring head = result.status == CHECK_FAIL ? L"This PC uses or keeps old sign-in answers that can be cracked." :
                        result.status == CHECK_WARNING ? L"This PC still accepts weaker NTLM sign-ins than it needs to." :
                        result.status == CHECK_PASS ? L"This PC uses and accepts only NTLMv2 with 128-bit session security, and keeps no LM hashes." :
                        L"The sign-in protocol settings could not be judged.";
    result.detail = head + L"\n" + JoinW(lines, L"\n");
    DebugLog(L"NTLM -> " + result.status);
    return result;
}
