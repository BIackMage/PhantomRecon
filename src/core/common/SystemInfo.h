#pragma once

#include <windows.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// SystemInfo: read-only facts about the host. Safe from any thread; none of
// these touch a window.
// ---------------------------------------------------------------------------

std::wstring GetComputerNameString();
std::wstring GetProcessorInfo();
std::wstring GetRamInfo();
std::wstring GetDiskSpaceInfo();

// The four lines above joined with newlines, ending in a newline.
std::wstring BuildSystemInfoText();

// "Windows 11 Pro 24H2 (build 26100)" style text from the registry.
std::wstring GetWindowsVersionText();
DWORD GetWindowsBuildNumber();

// True when this process runs with an elevated (administrator) token.
bool IsProcessElevated();

// Enable or disable a privilege (SE_SECURITY_NAME, SE_DEBUG_NAME, ...) in the
// process token. Returns true when the privilege is now in the requested state.
bool SetProcessPrivilege(const wchar_t* privilegeName, bool enable);

// Current user name (no domain) and the profile folder path.
std::wstring GetCurrentUserNameString();
std::wstring GetUserProfileFolder();

// DNS domain the computer is joined to, or "" when it is not domain-joined.
std::wstring GetJoinedDomainName();

// ---------------------------------------------------------------------------
// Names the Redactor hides. Each returns "" (or an empty list) when Windows
// does not report the value; none of them changes anything.
// ---------------------------------------------------------------------------

// DNS host name ("my-very-long-laptop-name"). Can be longer than the 15-character
// NetBIOS name GetComputerNameString returns, and spelled differently.
std::wstring GetDnsHostNameString();

// NetBIOS name of the joined domain ("CORP"), or of the workgroup when the PC is not
// domain-joined. isDomain is set to true only for a domain.
std::wstring GetJoinedNetbiosName(bool* isDomain);

// "DOMAIN\user" of the account running this process (NameSamCompatible), split.
// For a local account the domain part is the computer name.
bool GetLogonDomainAndUser(std::wstring& domain, std::wstring& user);

// Display name of the signed-in user ("Alice Example"), or "".
std::wstring GetUserDisplayName();

struct LocalAccountName {
    std::wstring name;        // sign-in name
    std::wstring fullName;    // "Full name" field, often empty
    DWORD        rid = 0;     // last part of the SID: 500 Administrator, 501 Guest, ...
};

// Every local user account (NetUserEnum, readable by any signed-in user).
std::vector<LocalAccountName> GetLocalAccountNames();

// Leaf folder names of every user profile on this PC (ProfileList in the registry),
// for local, domain and Microsoft Entra accounts. System profiles are left out.
std::vector<std::wstring> GetProfileFolderNames();

// 8.3 short form of a path ("C:\Users\MICHAE~1"), or "" when it has none.
std::wstring GetShortPathString(const std::wstring& path);

// FILETIME / Unix time helpers for reports.
std::wstring FormatFileTime(const FILETIME& ft);           // "2026-10-26 14:05"
std::wstring FormatUnixTime(long long unixSeconds);         // "2026-10-26 14:05"
long long FileTimeToUnix(const FILETIME& ft);
