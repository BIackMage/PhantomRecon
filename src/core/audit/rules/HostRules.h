#pragma once

#include "AuditRules.h"   // OptionalDword

#include <windows.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// HostRules: the pure verdict logic behind the second platform pack: shared
// folders, SMB guest and anonymous access, inbound firewall rules, automatic
// sign-in, NTLM settings and driver services. No system calls: the checks in
// SecurityChecksSharing.cpp, SecurityChecksSignin.cpp and SecurityChecksDrivers.cpp
// read the facts and hand them here, so tests can feed crafted facts and check the
// verdict. Each *Status function returns a CHECK_* string and, when the out
// parameter is not null, the text that explains it.
// ---------------------------------------------------------------------------

// ===========================================================================
// Shared folders (net.shares)
// ===========================================================================

// The accounts a share permission can name that every normal account (or a guest
// logon) holds. Other covers everything else, administrators included.
enum class AccountKind { Everyone, AuthenticatedUsers, Users, Guests, GuestAccount, Other };

// "Everyone", "Authenticated Users", "Users", "Guests", "Guest", "another account".
std::wstring AccountKindName(AccountKind kind);

// One entry of a share's permission list, in order.
struct ShareAce {
    AccountKind  who = AccountKind::Other;
    bool         allow = true;
    DWORD        mask = 0;     // access mask as stored (generic rights are mapped when judged)
    std::wstring sid;          // "S-1-1-0", for the fix plan
};

struct SharePermissions {
    bool                  known = false;   // the share's security descriptor could be read
    bool                  noDacl = false;  // no descriptor or no DACL: no share-level limit at all
    std::vector<ShareAce> aces;
};

// A broad account the share lets change files.
struct ShareGrant {
    AccountKind  who = AccountKind::Other;
    std::wstring sid;
    bool         full = false;   // Full Control, not only Change
};

// Share types (lmshare.h): the low byte is the kind, STYPE_SPECIAL marks the
// administrative shares Windows creates itself.
const DWORD kShareTypeDisk = 0x00000000;
const DWORD kShareTypeMask = 0x000000FF;
const DWORD kShareTypeSpecial = 0x80000000;

bool IsDiskShare(DWORD type);

// ADMIN$, IPC$, print$, a drive letter followed by $ (C$), or any share Windows
// marks special. Hidden shares a person made (name ending in $) are not skipped.
bool IsDefaultAdminShare(const std::wstring& name, DWORD type);

// Which broad accounts the share permissions let change files: the entries are
// walked in order for a normal account (Everyone, Authenticated Users, Users) and for
// a guest logon (Everyone, Guests, Guest), deny entries honoured. A share without a
// DACL grants Everyone Full Control.
std::vector<ShareGrant> BroadShareChangeGrants(const SharePermissions& permissions);

struct ShareFacts {
    std::wstring     name;
    std::wstring     path;
    DWORD            type = kShareTypeDisk;
    SharePermissions permissions;
    bool             folderExists = true;
    bool             folderKnown = false;     // the folder's own permissions could be read
    bool             folderWritable = false;  // a normal-user group may create or change files in it
    std::wstring     folderWho;               // the group that may
};

struct SharesFacts {
    bool                    serverInstalled = false;   // LanmanServer exists
    bool                    serverRunning = false;
    bool                    listed = false;            // the share list could be read
    std::wstring            listError;
    std::wstring            source;                    // where the list came from, for the evidence
    std::vector<ShareFacts> shares;
};

struct ShareFinding {
    std::wstring            name;
    std::wstring            path;
    std::wstring            folderWho;
    std::vector<ShareGrant> grants;
};

struct ShareJudgement {
    std::vector<ShareFinding> findings;      // shares a broad account can change through the network
    std::vector<std::wstring> unknown;       // shares that could not be judged, with the reason
    int                       checked = 0;   // disk shares judged (admin shares not counted)
    int                       skippedAdmin = 0;
};

ShareJudgement JudgeShares(const SharesFacts& facts);

// N/A when the Server service is not installed or not running, or the list cannot be
// read. WARNING with any finding. N/A when nothing was found but a share could not be
// judged. PASS otherwise.
std::wstring SharesStatus(const SharesFacts& facts, const ShareJudgement& judgement, std::wstring* text);

// One fix plan target per finding and account: "share|S-1-1-0|Full" or
// "share|S-1-5-11|Change". Share names cannot contain '|'.
std::vector<std::wstring> ShareFixTargets(const std::vector<ShareFinding>& findings);

// The share's lines in HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares
// ("Path=C:\Data", "Type=0", ...). False when no Path line is present.
bool ParseShareRegistryValue(const std::vector<std::wstring>& lines, std::wstring& path, DWORD& type);

// ===========================================================================
// SMB guest and anonymous access (net.smbguest)
// ===========================================================================

struct SmbGuestFacts {
    OptionalDword             clientLocal;         // LanmanWorkstation\Parameters AllowInsecureGuestAuth
    OptionalDword             clientPolicy;        // Policies\Microsoft\Windows\LanmanWorkstation AllowInsecureGuestAuth
    OptionalDword             restrictNullSession; // LanmanServer\Parameters RestrictNullSessAccess
    std::vector<std::wstring> nullSessionShares;   // LanmanServer\Parameters NullSessionShares
    std::wstring              editionId;           // CurrentVersion EditionID
    DWORD                     build = 0;
    bool                      isServer = false;
};

// Windows' own default when AllowInsecureGuestAuth is not set: off on Windows Server
// 2019 and later and on Enterprise and Education since Windows 10 1709 (build 16299),
// off on Pro since Windows 11 24H2 (build 26100), on for Home and for any edition this
// rule does not know. why receives the sentence that says which rule applied.
bool InsecureGuestAllowedByDefault(const std::wstring& editionId, DWORD build, bool isServer, std::wstring* why);

// WARNING when the SMB client may sign in to other computers' shares as a guest (Group
// Policy, then the local value, then the default above), when the Server service lets
// anonymous users list shares and accounts (RestrictNullSessAccess=0), or when shares
// are open to anonymous users (NullSessionShares). PASS otherwise.
std::wstring SmbGuestStatus(const SmbGuestFacts& facts, std::vector<std::wstring>* lines);

// ===========================================================================
// Inbound firewall rules (fw.rules)
// ===========================================================================

const long kFirewallProfilePublic = 0x4;      // NET_FW_PROFILE2_PUBLIC
const long kFirewallProtocolAny = 256;        // NET_FW_IP_PROTOCOL_ANY

// One rule as INetFwRule reports it, plus where its program is.
struct FirewallRuleFacts {
    std::wstring name;              // INetFwRule::Name (the display name)
    std::wstring grouping;          // INetFwRule::Grouping, "@FirewallAPI.dll,-25000" for Windows' own groups
    std::wstring application;       // program path, expanded; "" for any program
    std::wstring service;           // service short name; "" for any
    std::wstring packageId;         // INetFwRule3::LocalAppPackageId, or the store's PFN (StorePackageForRule): a Store app's rule
    std::wstring localPorts;        // "*", "80,443", "RPC", ...
    std::wstring remoteAddresses;   // "*" for any address
    long         protocol = kFirewallProtocolAny;
    long         profiles = 0;      // NET_FW_PROFILE_TYPE2 bits
    bool         enabled = false;
    bool         inbound = false;
    bool         allow = false;

    // Filled by the check for rules it reports.
    bool         programWritable = false;   // the program or its folder can be changed by normal users
    bool         programInDropFolder = false;   // Downloads, Temp, Desktop, Public and similar
    std::wstring writableWho;
    std::wstring id;                // the rule's unique name in the local store (Disable-NetFirewallRule -Name), "" when not found
};

// Enabled, inbound, Allow, applies to the Public profile, accepts any remote address.
bool IsPublicAnyAddressAllow(const FirewallRuleFacts& rule);

// Rules Windows manages itself: a built-in group (its group name is a Windows
// resource string such as "@FirewallAPI.dll,-25000", not a Store app's "@{...}"), or
// a rule bound to a Store app package (Windows writes those from the app's manifest).
bool IsWindowsManagedRule(const FirewallRuleFacts& rule);

// No program, no service, no Store app package, every protocol and every local port:
// the rule opens the whole PC.
bool AllowsEverything(const FirewallRuleFacts& rule);

// The rule this check lists: IsPublicAnyAddressAllow and, for a rule Windows
// manages, only when it also allows everything.
bool IsReportedFirewallRule(const FirewallRuleFacts& rule);

// "TCP", "UDP", "ICMPv4", "any protocol", or "protocol 47".
std::wstring FirewallProtocolName(long protocol);

// One line of evidence: name, program or service, protocol, ports and the location
// warning.
std::wstring FirewallRuleLine(const FirewallRuleFacts& rule);

// Rules in a user-writable or drop folder first, then by name.
void SortFirewallFindings(std::vector<FirewallRuleFacts>& rules);

struct FirewallRulesFacts {
    bool         apiOk = false;           // INetFwPolicy2 answered
    std::wstring apiError;
    bool         publicKnown = false;     // the Public profile's state could be read
    bool         publicOn = false;
    bool         blockAllInbound = false; // Public: block all incoming connections, allowed apps included
    int          rulesRead = 0;
    int          reported = 0;
    int          reportedRisky = 0;       // reported rules whose program is in a user-writable or drop folder
    int          reportedWideOpen = 0;    // reported rules that allow everything (any program, protocol and port)
    int          windowsManagedSkipped = 0;
};

// True for the rules that make fw.rules a WARNING and that the fix plan turns off:
// a program in a user-writable or drop folder, or a rule that allows everything.
bool IsRiskyFirewallRule(const FirewallRuleFacts& rule);

// N/A when the firewall API does not answer or the Public profile is off (the
// Windows Firewall check covers that). PASS when the Public profile blocks every
// incoming connection, or nothing is reported. WARNING when a reported rule is risky
// (IsRiskyFirewallRule). INFO when rules are reported but none is risky: a rule for a
// program in a protected folder is what Windows creates when someone clicks Allow, so
// it is listed for review rather than counted against the score.
std::wstring FirewallRulesStatus(const FirewallRulesFacts& facts, std::wstring* text);

// A rule in the local firewall store, HKLM\SYSTEM\CurrentControlSet\Services\
// SharedAccess\Parameters\FirewallPolicy\FirewallRules: the value name is the rule's
// unique name, the data "v2.10|Action=Allow|Active=TRUE|Dir=In|...|".
struct FirewallStoreRule {
    bool         parsed = false;
    std::wstring id;
    std::wstring name;
    std::wstring grouping;       // EmbedCtxt
    std::wstring application;    // App, as stored (the check expands it)
    std::wstring service;        // Svc
    std::wstring localPorts;     // LPort values joined with ","
    std::wstring package;        // AppPkgId or PFN: the Store app the rule is limited to, "" for none
    long         protocol = kFirewallProtocolAny;
    bool         allPublic = false;   // applies to the Public profile (no Profile entry means every profile)
    bool         remoteAny = true;    // no RA4 / RA6 entry
    bool         active = false;
    bool         inbound = false;
    bool         allow = false;
};

FirewallStoreRule ParseFirewallRuleData(const std::wstring& id, const std::wstring& data);

// The fields both sides share, normalised (lowercase, ports sorted), so a rule read
// through the API finds its entry in the store. The application must already be
// expanded on both sides.
std::wstring FirewallRuleKey(const FirewallRuleFacts& rule);
std::wstring FirewallRuleKey(const FirewallStoreRule& rule);

// The unique names of the store entries that match the rule and that this check
// would report as well. Empty when none does.
std::vector<std::wstring> MatchFirewallStoreIds(const FirewallRuleFacts& rule, const std::vector<FirewallStoreRule>& store);

// The Store app package the rule is limited to, taken from its store entries: a
// package family name (PFN) binding is not visible through INetFwRule. "" when no
// entry matches the rule or any matching entry names no package.
std::wstring StorePackageForRule(const FirewallRuleFacts& rule, const std::vector<FirewallStoreRule>& store);

// True when PowerShell's -Name parameter would read the name as a wildcard pattern.
bool HasWildcardCharacters(const std::wstring& name);

// ===========================================================================
// Automatic sign-in (acct.autologon)
// ===========================================================================

struct AutoLogonFacts {
    bool          keyReadable = true;       // ...\Winlogon could be opened
    std::wstring  autoAdminLogon;           // REG_SZ, "1" turns it on
    bool          defaultPasswordPresent = false;   // only whether the value exists, never its data
    DWORD         defaultPasswordBytes = 0;         // its size; 2 or less is an empty string
    std::wstring  defaultUserName;
    std::wstring  defaultDomainName;
    OptionalDword autoLogonCount;
};

// FAIL when AutoAdminLogon is 1 and a non-empty DefaultPassword is stored (readable by
// every user of this PC). WARNING when AutoAdminLogon is 1 without it (the password is
// kept as an LSA secret, or the account has none). N/A when the key cannot be read.
// PASS otherwise.
std::wstring AutoLogonStatus(const AutoLogonFacts& facts, std::wstring* text);

// ===========================================================================
// NTLM and LAN Manager (cred.ntlm)
// ===========================================================================

const DWORD kNtlmRequireV2Session = 0x00080000;   // NTLMSSP_NEGOTIATE_NTLM2: NTLMv2 session security
const DWORD kNtlmRequire128Bit = 0x20000000;      // NTLMSSP_NEGOTIATE_128
const DWORD kNtlmWantedMinSec = kNtlmRequireV2Session | kNtlmRequire128Bit;   // 537395200
const DWORD kNtlmDefaultMinSec = kNtlmRequire128Bit;   // Windows 7 and later when the value is not set
const DWORD kLmCompatibilityDefault = 3;               // Windows Vista and later when the value is not set

struct NtlmFacts {
    bool          lsaReadable = true;
    OptionalDword lmCompatibilityLevel;   // Control\Lsa LmCompatibilityLevel
    OptionalDword noLmHash;               // Control\Lsa NoLMHash
    OptionalDword minClientSec;           // Control\Lsa\MSV1_0 NtlmMinClientSec
    OptionalDword minServerSec;           // Control\Lsa\MSV1_0 NtlmMinServerSec
};

// LmCompatibilityLevel below 3 FAIL (this PC sends LM or NTLMv1 answers); 3 and 4
// WARNING (it answers with NTLMv2 only, but still accepts LM or NTLMv1 answers from
// other computers); 5 PASS; missing means 3. NoLMHash 0 FAIL (missing means 1). Either
// minimum session security without both 128-bit and NTLMv2 session security WARNING
// (missing means 128-bit only). The worst of these wins. N/A when the key cannot be
// read. lines receives one line per setting.
std::wstring NtlmStatus(const NtlmFacts& facts, std::vector<std::wstring>* lines);

// ===========================================================================
// Driver services (svc.drivers)
// ===========================================================================

// The file a driver service's ImagePath names: "\SystemRoot\..." and "%SystemRoot%"
// under systemRoot, "System32\drivers\x.sys" relative to it, "\??\C:\..." and
// "\\?\C:\..." without the prefix, "\Windows\..." on the system drive, and an empty
// ImagePath as systemRoot\System32\drivers\<service>.sys (what the kernel loads).
std::wstring DriverImagePathToFile(const std::wstring& imagePath, const std::wstring& serviceName, const std::wstring& systemRoot);

const unsigned kDriverMissing = 0x1;
const unsigned kDriverUnsigned = 0x2;
const unsigned kDriverWritableFolder = 0x4;
const unsigned kDriverWritableFile = 0x8;

struct DriverFacts {
    std::wstring name;
    std::wstring displayName;
    std::wstring imagePath;          // as configured
    std::wstring file;               // DriverImagePathToFile
    DWORD        startType = SERVICE_DEMAND_START;
    bool         fileExists = false;
    bool         signatureValid = false;
    std::wstring signatureStatus;
    bool         folderWritable = false;
    bool         fileWritable = false;
    std::wstring writableWho;
};

// The kDriver* bits that apply. A disabled driver has none: it cannot load until an
// administrator changes its start type. A missing file is not checked further.
unsigned DriverProblems(const DriverFacts& driver);

// Boot 0, System 1, Automatic 2, Manual 3, Disabled 4, anything else 5.
int DriverStartRank(DWORD startType);

// Boot and system start drivers first, then by start type and name.
void SortDriverFindings(std::vector<DriverFacts>& drivers);

// "  [name] C:\...\x.sys (Boot start): unsigned (Unsigned); folder writable by Users"
std::wstring DriverFindingLine(const DriverFacts& driver);

struct DriversFacts {
    bool         listed = false;     // the Service Control Manager answered
    std::wstring listError;
    int          total = 0;          // driver services listed
    int          unreadable = 0;     // configuration could not be read
    int          disabled = 0;
    int          checked = 0;        // judged
    int          flagged = 0;
};

// N/A when the Service Control Manager does not answer or no driver configuration
// could be read. WARNING with any finding. PASS with the count otherwise.
std::wstring DriversStatus(const DriversFacts& facts, std::wstring* text);
