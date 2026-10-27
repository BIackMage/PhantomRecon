#pragma once

#include "AuditRules.h"   // OptionalDword

#include <windows.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// PlatformRules: the pure verdict logic behind the platform checks (memory
// integrity, vulnerable driver block list, Smart App Control, exploit
// protection, screen lock, System Restore, open Wi-Fi). No system calls: the
// checks in SecurityChecksPlatform.cpp and SecurityChecksWireless.cpp read the
// facts and hand them here, so tests can feed crafted facts and check the
// verdict. Each *Status function returns a CHECK_* string and, when text is not
// null, the sentence that explains it.
// ---------------------------------------------------------------------------

// First Windows 11 build, and the first with Smart App Control and the block list
// on by default (Windows 11 22H2).
const DWORD kWindows11Build = 22000;
const DWORD kWindows11_22H2Build = 22621;

// --- Memory integrity (hard.hvci) ---

struct HvciFacts {
    OptionalDword registryEnabled;    // DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity Enabled
    bool          wmiOk = false;      // Win32_DeviceGuard answered
    bool          wmiConfigured = false;   // SecurityServicesConfigured contains 2
    bool          wmiRunning = false;      // SecurityServicesRunning contains 2
};

// PASS running; WARNING configured but not running; WARNING off.
std::wstring HvciStatus(const HvciFacts& facts, std::wstring* text);

// --- Vulnerable driver block list (hard.driverblocklist) ---

struct DriverBlocklistFacts {
    bool          keyReadable = true;   // CI\Config could be opened (or does not exist)
    OptionalDword enabled;              // CI\Config VulnerableDriverBlocklistEnable
    DWORD         build = 0;
    bool          isServer = false;
    bool          hvciRunning = false;
    bool          smartAppControlOn = false;
};

// 1 on, 0 off. When the value is missing the list is on by default on Windows 11
// 22H2 and later (client), and whenever memory integrity or Smart App Control is on.
std::wstring DriverBlocklistStatus(const DriverBlocklistFacts& facts, std::wstring* text);

// --- Smart App Control (hard.smartapp) ---

struct SmartAppControlFacts {
    DWORD         build = 0;
    bool          isServer = false;
    bool          keyReadable = true;
    OptionalDword state;                // CI\Policy VerifiedAndReputablePolicyState: 0 off, 1 on, 2 evaluation
};

// N/A on Windows 10, Windows 11 before 22H2 and Windows Server. On PASS, off WARNING,
// evaluation PASS with a note (Windows decides on its own; nothing is misconfigured).
std::wstring SmartAppControlStatus(const SmartAppControlFacts& facts, std::wstring* text);

// --- System exploit protection (hard.exploitprot) ---

// A 2-bit field of a process mitigation policy word: 0 not set (Windows default),
// 1 always on, 2 always off, 3 reserved.
int MitigationField(unsigned long long options, int shift);

struct ExploitProtectionFacts {
    int                depPolicy = -1;          // GetSystemDEPPolicy: 0 AlwaysOff, 1 AlwaysOn, 2 OptIn, 3 OptOut; -1 unknown
    OptionalDword      sehopDisabled;           // Session Manager\kernel DisableExceptionChainValidation
    bool               mitigationsSet = false;  // Session Manager\kernel MitigationOptions present (8 bytes or more)
    unsigned long long mitigationOptions = 0;   // its first 64 bits
};

// FAIL when DEP is AlwaysOff; WARNING when SEHOP, bottom-up ASLR, high-entropy ASLR
// or CFG is switched off system-wide, or when the DEP policy could not be read;
// PASS otherwise. lines receives one line per setting for the evidence.
std::wstring ExploitProtectionStatus(const ExploitProtectionFacts& facts, std::vector<std::wstring>* lines);

// --- Screen lock (acct.screenlock) ---

// The four screen saver values as text, "" when not set.
struct ScreenSaverValues {
    std::wstring active;    // ScreenSaveActive: "1" on
    std::wstring secure;    // ScreenSaverIsSecure: "1" asks for the password on resume
    std::wstring timeout;   // ScreenSaveTimeOut: seconds
    std::wstring exe;       // SCRNSAVE.EXE: the screen saver; none chosen when empty
};

struct ScreenLockFacts {
    OptionalDword     inactivitySecs;   // HKLM ...\Policies\System InactivityTimeoutSecs
    ScreenSaverValues user;             // HKCU\Control Panel\Desktop
    ScreenSaverValues policy;           // HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop
};

// Each value: the Group Policy copy when it is set, the user's otherwise.
ScreenSaverValues EffectiveScreenSaver(const ScreenLockFacts& facts);

// Seconds from a ScreenSaveTimeOut text; -1 when it is not a plain number.
long ParseScreenSaverSeconds(const std::wstring& text);

// PASS when the inactivity limit is 1 to 900 seconds, or a secure screen saver starts
// within 900 seconds. WARNING otherwise. lines receives what was found.
std::wstring ScreenLockStatus(const ScreenLockFacts& facts, std::vector<std::wstring>* lines);

// --- System Restore (backup.restore) ---

struct SystemRestoreFacts {
    bool                      isServer = false;
    OptionalDword             policyDisable;     // Policies\...\SystemRestore DisableSR
    OptionalDword             legacyDisable;     // CurrentVersion\SystemRestore DisableSR
    OptionalDword             sessionInterval;   // CurrentVersion\SystemRestore RPSessionInterval (a hint only)
    bool                      clientsReadable = false;   // SPP\Clients could be read (administrators only)
    bool                      clientsValueSet = false;   // its protected-volume list exists
    std::vector<std::wstring> protectedVolumes;           // the list's entries
    std::wstring              systemVolume;               // "\\?\Volume{guid}\" of the system drive
    std::wstring              systemDrive;                // "C:"
};

// True when one of the System Protection entries names the volume (by its GUID) or
// the drive letter ("(C%3A)").
bool RestoreListCoversVolume(const std::vector<std::wstring>& entries, const std::wstring& volumeGuidPath,
                             const std::wstring& driveLetter);

// N/A on Windows Server and, for normal users, when the per-drive list cannot be
// read. WARNING when turned off by policy or not on for the system drive. PASS on.
std::wstring SystemRestoreStatus(const SystemRestoreFacts& facts, std::wstring* text);

// --- Open Wi-Fi networks (net.wifiopen) ---

// The only parts of a WLAN profile this tool keeps. Key material is never copied.
struct WlanProfileSummary {
    bool         parsed = false;     // an <authEncryption> block with <authentication> was found
    std::wstring authentication;     // lowercase: open, shared, wpa2psk, wpa3sae, owe, ...
    std::wstring encryption;         // lowercase: none, wep, aes, tkip, gcmp256, ...
    std::wstring connectionMode;     // lowercase: auto or manual; "auto" when the element is missing
    bool         connectionModeMissing = false;
};

// Reads authentication, encryption and connectionMode out of a profile XML (the
// schema at http://www.microsoft.com/networking/WLAN/profile/v1).
WlanProfileSummary ParseWlanProfileXml(const std::wstring& xml);

// Open authentication without encryption, and not set to manual connection.
bool IsOpenAutoConnectProfile(const WlanProfileSummary& profile);

struct WifiFacts {
    bool                      serviceInstalled = false;   // WlanSvc exists
    bool                      serviceRunning = false;     // WlanSvc runs and WlanOpenHandle worked
    bool                      apiAvailable = false;       // wlanapi.dll could be loaded
    int                       interfaces = 0;             // Wi-Fi interfaces
    int                       profilesRead = 0;           // profiles parsed
    int                       profilesUnreadable = 0;     // profiles that could not be read or parsed
    std::vector<std::wstring> openAutoProfiles;           // names of open profiles that connect on their own
};

// N/A without the WLAN service, its API or a Wi-Fi interface. WARNING with any open
// auto-connect profile, or when no profile could be read. PASS otherwise.
std::wstring OpenWifiStatus(const WifiFacts& facts, std::wstring* text);
