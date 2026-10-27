#pragma once

#include "AuditRules.h"   // OptionalDword

#include <windows.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// HygieneRules: the pure verdict logic behind the third platform pack: WDigest
// password caching, paused or deferred Windows updates, Remote Assistance offers,
// cached domain sign-ins, Windows' built-in sudo and DNS over HTTPS. No system
// calls: the checks in SecurityChecksHygiene.cpp read the facts and hand them here,
// so tests can feed crafted facts and check the verdict. Each *Status function
// returns a CHECK_* string and, when the out parameter is not null, the text that
// explains it.
// ---------------------------------------------------------------------------

// ===========================================================================
// WDigest password caching (cred.wdigest)
// ===========================================================================

// Windows 8.1 and Windows Server 2012 R2: from this build on, a missing
// UseLogonCredential value means WDigest keeps no password in memory.
const DWORD kWindows81Build = 9600;

struct WDigestFacts {
    bool          keyReadable = true;    // ...\SecurityProviders\WDigest could be opened (or does not exist)
    OptionalDword useLogonCredential;    // UseLogonCredential
    DWORD         build = 0;             // CurrentBuildNumber, 0 when unknown
};

// FAIL when UseLogonCredential is set and not 0. PASS when it is 0, or missing on
// Windows 8.1 / Server 2012 R2 and later (and when the build is unknown: this program
// runs on Windows 10 and later). FAIL when it is missing on an older build, where the
// default keeps passwords. N/A when the key cannot be read.
std::wstring WDigestStatus(const WDigestFacts& facts, std::wstring* text);

// ===========================================================================
// Windows Update paused or deferred (wu.paused)
// ===========================================================================

// Windows Update deferral of quality (security) updates longer than this is a WARNING.
const DWORD kMaxQualityDeferralDays = 7;
// A Group Policy pause (PauseQualityUpdatesStartTime / PauseFeatureUpdatesStartTime)
// lasts this many days from its start date.
const int kPolicyPauseDays = 35;

// "2031-03-12T09:30:00Z", "2031-03-12T09:30:00.5Z", "2031-03-12 09:30:00" or
// "2031-03-12", read as UTC, to seconds since 1970. False when it is not such a date.
bool ParseIso8601Utc(const std::wstring& text, long long& unixSeconds);

// "2031-03-12 09:30 UTC"
std::wstring FormatUtcDate(long long unixSeconds);

struct UpdatePauseFacts {
    bool          settingsReadable = true;   // WindowsUpdate\UX\Settings could be opened (or does not exist)
    bool          policyReadable = true;     // Policies\Microsoft\Windows\WindowsUpdate could be opened (or does not exist)

    // HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings (Settings > Windows Update > Pause updates)
    std::wstring  pauseUpdatesExpiry;        // PauseUpdatesExpiryTime
    std::wstring  pauseQualityEnd;           // PauseQualityUpdatesEndTime
    std::wstring  pauseFeatureEnd;           // PauseFeatureUpdatesEndTime

    // HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate (Group Policy)
    OptionalDword deferQuality;              // DeferQualityUpdates
    OptionalDword deferQualityDays;          // DeferQualityUpdatesPeriodInDays
    OptionalDword deferFeature;              // DeferFeatureUpdates
    OptionalDword deferFeatureDays;          // DeferFeatureUpdatesPeriodInDays
    std::wstring  policyPauseQualityStart;   // PauseQualityUpdatesStartTime
    std::wstring  policyPauseFeatureStart;   // PauseFeatureUpdatesStartTime

    long long     nowUnix = 0;               // the current time, UTC
};

// WARNING when quality (security) updates are paused until a time after nowUnix (the
// Settings pause, or a Group Policy pause started less than 35 days ago), or Group
// Policy defers them more than 7 days. A feature update pause or deferral alone is
// fine and only described. N/A when neither key can be read. PASS otherwise.
std::wstring UpdatePauseStatus(const UpdatePauseFacts& facts, std::vector<std::wstring>* lines);

// ===========================================================================
// Remote Assistance (net.remoteassist)
// ===========================================================================

struct RemoteAssistFacts {
    bool          programPresent = true;           // %SystemRoot%\System32\msra.exe exists
    bool          localReadable = true;            // Control\Remote Assistance could be opened (or does not exist)
    OptionalDword localAllowGetHelp;               // Control\Remote Assistance fAllowToGetHelp
    OptionalDword localAllowFullControl;           // Control\Remote Assistance fAllowFullControl
    OptionalDword policyAllowGetHelp;              // Policies\Microsoft\Windows NT\Terminal Services fAllowToGetHelp
    OptionalDword policyAllowFullControl;          // ... fAllowFullControl (Configure Solicited Remote Assistance)
    OptionalDword policyAllowUnsolicited;          // ... fAllowUnsolicited (Configure Offer Remote Assistance)
    OptionalDword policyUnsolicitedFullControl;    // ... fAllowUnsolicitedFullControl
};

// Group Policy wins over the local values. A missing local value is read as on, the
// Windows default. WARNING when unsolicited offers are allowed, or when solicited help
// with full control of the PC is allowed. PASS when Remote Assistance is off or view
// only. N/A when msra.exe is not installed or the local key cannot be read and no
// policy says anything.
std::wstring RemoteAssistStatus(const RemoteAssistFacts& facts, std::vector<std::wstring>* lines);

// ===========================================================================
// Cached domain sign-ins (cred.cachedlogons)
// ===========================================================================

const int kMaxCachedLogons = 4;          // the CIS benchmark's limit
const int kDefaultCachedLogons = 10;     // Windows' default when the value is missing

struct CachedLogonsFacts {
    bool         joinKnown = false;       // NetGetJoinInformation answered
    bool         domainJoined = false;    // joined to an Active Directory domain
    bool         keyReadable = true;      // ...\Winlogon could be opened
    bool         valuePresent = false;    // CachedLogonsCount exists
    std::wstring cachedLogonsCount;       // its text (REG_SZ)
};

// The number CachedLogonsCount holds: the default 10 when missing, -1 when it is not a
// whole number from 0 to 50 (what Windows accepts).
int EffectiveCachedLogons(const CachedLogonsFacts& facts);

// N/A when the PC is not joined to a domain (or the join state is unknown), or the key
// cannot be read. WARNING above 4 (the default 10 included), or when the value is not
// a number. PASS at 4 or below.
std::wstring CachedLogonsStatus(const CachedLogonsFacts& facts, std::wstring* text);

// ===========================================================================
// Windows' built-in sudo (hard.sudo)
// ===========================================================================

// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo Enabled.
const DWORD kSudoOff = 0;
const DWORD kSudoNewWindow = 1;     // forceNewWindow
const DWORD kSudoInputClosed = 2;   // disableInput
const DWORD kSudoInline = 3;        // normal

struct SudoFacts {
    bool          available = false;   // sudo.exe is in System32, or its settings key exists
    OptionalDword enabled;             // ...\CurrentVersion\Sudo Enabled
    OptionalDword policyMaximum;       // Policies\Microsoft\Windows\Sudo Enabled: the most Group Policy allows
};

// The mode in effect: the local value (0 when missing), lowered to the Group Policy
// maximum when one is set.
DWORD EffectiveSudoMode(const SudoFacts& facts);

// "off", "in a new window", "with input closed", "inline", or "an unknown mode (n)".
std::wstring SudoModeName(DWORD mode);

// N/A when this Windows has no sudo. WARNING for inline mode or a mode Windows does not
// define. PASS for off, a new window, or input closed.
std::wstring SudoStatus(const SudoFacts& facts, std::wstring* text);

// ===========================================================================
// DNS over HTTPS (net.doh)
// ===========================================================================

// HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient DoHPolicy.
const DWORD kDohPolicyProhibit = 1;
const DWORD kDohPolicyAllow = 2;
const DWORD kDohPolicyRequire = 3;

// One server entry under Dnscache\InterfaceSpecificParameters\{adapter}\
// Doh(Interface|Profile)Settings\Doh or \Doh6.
struct DohServerSetting {
    std::wstring adapter;          // the adapter's name, or its GUID when no name is known
    std::wstring server;           // the server address (the key name)
    bool         ipv6 = false;
    DWORD        flags = 0;        // DohFlags; 0 means DNS over HTTPS is off for this server
    std::wstring dohTemplate;      // DohTemplate: a template typed in by hand, may be empty
};

struct DohFacts {
    OptionalDword                 policy;            // DoHPolicy
    OptionalDword                 autoDoh;           // Dnscache\Parameters EnableAutoDoh (2 = use DoH for known servers)
    bool                          interfacesRead = false;   // InterfaceSpecificParameters could be read
    std::vector<DohServerSetting> servers;           // every entry found, on or off
    int                           knownServers = 0;  // servers in Dnscache\Parameters\DohWellKnownServers
};

// One evidence line per server with DNS over HTTPS on, in adapter order.
std::vector<std::wstring> DohServerLines(const std::vector<DohServerSetting>& servers);

// Always INFO: plain DNS on a trusted network is a normal setup, so this check only
// describes what is configured. text receives the description.
std::wstring DohStatus(const DohFacts& facts, std::wstring* text);
