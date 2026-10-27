#pragma once

#include <windows.h>
#include <string>

// ---------------------------------------------------------------------------
// AuditRules: the pure verdict logic behind the Defender, hardening, account,
// logging and firewall checks. No system calls: each check reads the facts and
// hands them here, so tests can feed crafted facts and check the verdict.
// Statuses are the CHECK_* strings from SecurityChecks.h.
// ---------------------------------------------------------------------------

// A registry DWORD that may be missing.
struct OptionalDword {
    bool  set = false;
    DWORD value = 0;
};

// --- Security Center (ROOT\SecurityCenter2) ---

// productState bits 12-15 equal to 1 mean the product is switched on.
bool SecurityCenterProductOn(unsigned long productState);

// --- Microsoft Defender ---

// True when AMRunningMode says Defender is the main antivirus ("Normal", or empty on
// builds that do not report it). False for "Passive Mode", "SxS Passive Mode",
// "EDR Block Mode" and "Not running".
bool IsDefenderPrimaryMode(const std::wstring& amRunningMode);

struct DefenderFacts {
    bool         statusOk = false;          // MSFT_MpComputerStatus answered
    std::wstring runningMode;               // AMRunningMode
    bool         securityCenterOk = false;  // ROOT\SecurityCenter2 answered (client Windows only)
    bool         otherProductOn = false;    // Security Center lists another antivirus that is on
};

enum class DefenderSituation {
    Primary,           // Defender is the main antivirus: judge its settings
    OtherProduct,      // another antivirus is on and Defender stepped back
    PassiveNoProduct,  // Defender stepped back, but no other product is known to be on
    Unreadable,        // Defender's status could not be read
};

DefenderSituation ClassifyDefender(const DefenderFacts& facts);

// Verdict of the real-time protection check when the situation is not Primary:
// OtherProduct PASS; PassiveNoProduct and Unreadable FAIL when Security Center
// answered and lists nothing that is on, WARNING when there is no Security Center
// to ask (servers). Empty for Primary (judge Defender's own fields).
std::wstring DefenderRealtimeStatus(const DefenderFacts& facts);

// Verdict of every other Defender setting check when the situation is not Primary:
// N/A (the setting belongs to whatever product is in charge, or cannot be read).
// Empty for Primary.
std::wstring DefenderSettingStatus(const DefenderFacts& facts);

// Controlled folder access mode (EnableControlledFolderAccess): 0 off, 1 block,
// 2 audit, 3 block disk modification only, 4 audit disk modification only.
std::wstring ControlledFolderAccessStatus(int mode, std::wstring* text);

// --- UAC ---

// ConsentPromptBehaviorAdmin 1 and 2 always prompt on the secure desktop, whatever
// PromptOnSecureDesktop says.
bool UacUsesSecureDesktop(DWORD consentPromptBehaviorAdmin, DWORD promptOnSecureDesktop);

// --- TPM ---

enum class TbsOutcome { Present, NoTpm, ServiceUnavailable, Error };
TbsOutcome ClassifyTbsResult(unsigned long tbsResult);

// Status when TPM Base Services cannot answer. tpmDriverDevices is the TPM driver's
// device count (Services\TPM\Enum\Count), -1 when unknown.
std::wstring TpmStatusWithoutTbs(int tpmDriverDevices);

// --- Credential Guard ---

enum class EditionSupport { Supported, NotSupported, Unknown };

// From EditionID (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion). Home ("Core...")
// and Pro ("Professional", "ProfessionalN", country and single-language Pro) cannot run
// Credential Guard; Enterprise, Education, Pro Education and Server can. Anything else,
// including Pro for Workstations, is Unknown.
EditionSupport CredentialGuardEditionSupport(const std::wstring& editionId);

// --- WPAD ---

// settingsSaved: DefaultConnectionSettings exists for this user. Without it Windows
// uses its default, which is automatic detection on.
std::wstring WpadStatus(bool settingsSaved, bool autoDetect, bool autoProxyServiceDisabled);

// --- Security event log size ---

struct LogSizeFacts {
    OptionalDword      policyKb;              // HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security MaxSize (KB)
    bool               channelKnown = false;  // EvtGetChannelConfigProperty answered
    unsigned long long channelBytes = 0;
    OptionalDword      legacyBytes;           // HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security MaxSize (bytes)
};

struct LogSize {
    bool               known = false;
    unsigned long long bytes = 0;
    std::wstring       source;   // "Group Policy", "log settings", "registry"
};

// Group Policy wins, then the channel's own setting, then the legacy registry value.
// Unknown when none could be read (the registry key needs administrator rights).
LogSize EffectiveSecurityLogSize(const LogSizeFacts& facts);

// --- Remote Desktop ---

struct RdpFacts {
    OptionalDword policyDeny;   // Policies\...\Terminal Services fDenyTSConnections
    OptionalDword localDeny;    // Control\Terminal Server fDenyTSConnections
    OptionalDword policyNla;    // Policies\...\Terminal Services UserAuthentication
    OptionalDword localNla;     // WinStations\RDP-Tcp UserAuthentication
};

struct RdpState {
    bool enabled = false;
    bool enabledByPolicy = false;   // the on/off state comes from Group Policy
    bool nlaRequired = false;
    bool nlaByPolicy = false;       // the NLA setting comes from Group Policy
};

// Group Policy overrides the local settings. Missing fDenyTSConnections means off.
RdpState EffectiveRdp(const RdpFacts& facts);

// --- WinRM ---

// listeners: number of configured listeners, -1 when the key could not be read
// (it needs administrator rights). policyListeners: Group Policy AllowAutoConfig=1.
std::wstring WinRmStatus(bool running, bool autoStart, int listeners, bool policyListeners);

// --- Built-in Administrator ---

// True when name is the built-in Administrator's default name in a known Windows
// language, or the singular of the localized Administrators group name
// ("Administrateurs" -> "Administrateur").
bool IsDefaultAdministratorName(const std::wstring& name, const std::wstring& administratorsGroupName);

// --- Windows Firewall ---

// thirdPartyOn: Security Center lists another firewall product that is on. Windows
// turns its own profiles off when one registers, so the profiles are not judged.
std::wstring FirewallStatus(bool anyProfileOff, bool anyInboundAllowed, bool thirdPartyOn);
