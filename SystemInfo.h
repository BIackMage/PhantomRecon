#pragma once

#include <windows.h>
#include <string>

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
std::wstring GetUserProfileDirectory();

// DNS domain the computer is joined to, or "" when it is not domain-joined.
std::wstring GetJoinedDomainName();

// FILETIME / Unix time helpers for reports.
std::wstring FormatFileTime(const FILETIME& ft);           // "2026-10-26 14:05"
std::wstring FormatUnixTime(long long unixSeconds);         // "2026-10-26 14:05"
long long FileTimeToUnix(const FILETIME& ft);
