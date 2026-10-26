#pragma once

#include <string>
#include <vector>

// Individual security check result
struct SecurityCheckResult {
    std::wstring name;       // short name (e.g. "Unquoted Service Paths")
    std::wstring status;     // "PASS", "FAIL", "WARNING", "INFO", "ERROR"
    std::wstring detail;     // human-readable detail / list of findings
};

// Run all security checks and return a vector of results.
std::vector<SecurityCheckResult> RunAllSecurityChecks();

// Produce a compact multi-line summary suitable for a UI label.
std::wstring GetSecuritySummary(const std::vector<SecurityCheckResult>& results);

// Write a full security audit report to a text file.
void WriteSecurityReport(const std::wstring& outputPath,
                         const std::vector<SecurityCheckResult>& results);

// --- Individual checks (also usable standalone) ---

// Services whose ImagePath contains spaces and is not quoted
SecurityCheckResult CheckUnquotedServicePaths();

// Service executables that the current user can write to
SecurityCheckResult CheckWritableServiceExes();

// HKLM + HKCU AlwaysInstallElevated registry keys
SecurityCheckResult CheckAlwaysInstallElevated();

// Common unattended-install / sysprep files that may contain credentials
SecurityCheckResult CheckUnattendedInstallFiles();

// Whether Credential Guard (LsaIso.exe) is running
SecurityCheckResult CheckCredentialGuard();

// LLMNR enabled/disabled via group policy
SecurityCheckResult CheckLLMNR();

// NetBIOS over TCP/IP (NBT-NS) status per adapter
SecurityCheckResult CheckNBTNS();

// mDNS enabled/disabled
SecurityCheckResult CheckMDNS();

// SMB signing required on the client side
SecurityCheckResult CheckSMBSigning();

// WPAD / proxy auto-detect
SecurityCheckResult CheckProxyAutoDetect();
