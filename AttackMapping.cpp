#include "pch.h"
#include "AttackMapping.h"

#include "JsonWriter.h"
#include "TextUtils.h"

#include <algorithm>
#include <utility>

struct TechniqueName {
    const wchar_t* id;
    const wchar_t* name;
};

static const TechniqueName kTechniques[] = {
    { L"T1003",     L"OS Credential Dumping" },
    { L"T1003.001", L"LSASS Memory" },
    { L"T1005",     L"Data from Local System" },
    { L"T1012",     L"Query Registry" },
    { L"T1021.001", L"Remote Desktop Protocol" },
    { L"T1021.006", L"Windows Remote Management" },
    { L"T1027",     L"Obfuscated Files or Information" },
    { L"T1027.002", L"Software Packing" },
    { L"T1027.009", L"Embedded Payloads" },
    { L"T1027.010", L"Command Obfuscation" },
    { L"T1036",     L"Masquerading" },
    { L"T1036.002", L"Right-to-Left Override" },
    { L"T1036.005", L"Match Legitimate Name or Location" },
    { L"T1047",     L"Windows Management Instrumentation" },
    { L"T1053.005", L"Scheduled Task" },
    { L"T1055",     L"Process Injection" },
    { L"T1055.003", L"Thread Execution Hijacking" },
    { L"T1055.004", L"Asynchronous Procedure Call" },
    { L"T1055.012", L"Process Hollowing" },
    { L"T1059.001", L"PowerShell" },
    { L"T1059.003", L"Windows Command Shell" },
    { L"T1059.005", L"Visual Basic" },
    { L"T1059.007", L"JavaScript" },
    { L"T1068",     L"Exploitation for Privilege Escalation" },
    { L"T1070.001", L"Clear Windows Event Logs" },
    { L"T1070.004", L"File Deletion" },
    { L"T1070.006", L"Timestomp" },
    { L"T1071.001", L"Web Protocols" },
    { L"T1078.001", L"Default Accounts" },
    { L"T1078.003", L"Local Accounts" },
    { L"T1082",     L"System Information Discovery" },
    { L"T1090.001", L"Internal Proxy" },
    { L"T1091",     L"Replication Through Removable Media" },
    { L"T1095",     L"Non-Application Layer Protocol" },
    { L"T1105",     L"Ingress Tool Transfer" },
    { L"T1106",     L"Native API" },
    { L"T1110",     L"Brute Force" },
    { L"T1098",     L"Account Manipulation" },
    { L"T1112",     L"Modify Registry" },
    { L"T1129",     L"Shared Modules" },
    { L"T1136.001", L"Local Account" },
    { L"T1134",     L"Access Token Manipulation" },
    { L"T1134.001", L"Token Impersonation/Theft" },
    { L"T1137",     L"Office Application Startup" },
    { L"T1137.001", L"Office Template Macros" },
    { L"T1140",     L"Deobfuscate/Decode Files or Information" },
    { L"T1176",     L"Browser Extensions" },
    { L"T1197",     L"BITS Jobs" },
    { L"T1203",     L"Exploitation for Client Execution" },
    { L"T1204.002", L"Malicious File" },
    { L"T1210",     L"Exploitation of Remote Services" },
    { L"T1218.005", L"Mshta" },
    { L"T1218.007", L"Msiexec" },
    { L"T1218.010", L"Regsvr32" },
    { L"T1218.011", L"Rundll32" },
    { L"T1486",     L"Data Encrypted for Impact" },
    { L"T1490",     L"Inhibit System Recovery" },
    { L"T1542.003", L"Bootkit" },
    { L"T1543.003", L"Windows Service" },
    { L"T1546",     L"Event Triggered Execution" },
    { L"T1546.003", L"Windows Management Instrumentation Event Subscription" },
    { L"T1546.010", L"AppInit DLLs" },
    { L"T1546.012", L"Image File Execution Options Injection" },
    { L"T1546.015", L"Component Object Model Hijacking" },
    { L"T1547",     L"Boot or Logon Autostart Execution" },
    { L"T1547.001", L"Registry Run Keys / Startup Folder" },
    { L"T1547.002", L"Authentication Package" },
    { L"T1547.004", L"Winlogon Helper DLL" },
    { L"T1547.005", L"Security Support Provider" },
    { L"T1547.010", L"Port Monitors" },
    { L"T1548",     L"Abuse Elevation Control Mechanism" },
    { L"T1548.002", L"Bypass User Account Control" },
    { L"T1552.001", L"Credentials In Files" },
    { L"T1552.006", L"Group Policy Preferences" },
    { L"T1553.002", L"Code Signing" },
    { L"T1553.004", L"Install Root Certificate" },
    { L"T1553.005", L"Mark-of-the-Web Bypass" },
    { L"T1557",     L"Adversary-in-the-Middle" },
    { L"T1557.001", L"LLMNR/NBT-NS Poisoning and SMB Relay" },
    { L"T1562.001", L"Disable or Modify Tools" },
    { L"T1562.002", L"Disable Windows Event Logging" },
    { L"T1562.004", L"Disable or Modify System Firewall" },
    { L"T1564.001", L"Hidden Files and Directories" },
    { L"T1564.003", L"Hidden Window" },
    { L"T1564.004", L"NTFS File Attributes" },
    { L"T1574.001", L"DLL Search Order Hijacking" },
    { L"T1574.009", L"Path Interception by Unquoted Path" },
    { L"T1574.010", L"Services File Permissions Weakness" },
    { L"T1587.002", L"Code Signing Certificates" },
    { L"T1620",     L"Reflective Code Loading" },
    { L"T1622",     L"Debugger Evasion" },
};

std::wstring AttackTechniqueName(const std::wstring& id)
{
    for (const TechniqueName& t : kTechniques) {
        if (id == t.id) return t.name;
    }
    return L"";
}

std::vector<std::wstring> KnownAttackTechniques()
{
    std::vector<std::wstring> ids;
    for (const TechniqueName& t : kTechniques) ids.push_back(t.id);
    return ids;
}

struct CodeInfo {
    const wchar_t* code;
    const wchar_t* technique;
    const wchar_t* explanation;
};

// Every finding code produced by file analysis, with the technique it points to
// and one plain sentence for the detail window.
static const CodeInfo kCodes[] = {
    // Signature (FileAnalysis.cpp)
    { L"HASH_MISMATCH",           L"T1553.002", L"The file was changed after it was signed. A signature copied from another program (signature theft) or a tampered file looks like this." },
    { L"EXPLICIT_DISTRUST",       L"T1553.002", L"The signing certificate is on Windows' explicit distrust list." },
    { L"UNTRUSTED_SUBJECT",       L"T1553.002", L"The file is signed, but Windows does not trust the certificate that signed it." },
    { L"VERIFY_ERROR",            L"",          L"Windows could not finish checking the signature." },
    { L"CHAIN_BUILD_FAILED",      L"T1553.002", L"Windows could not build a certificate chain for the signer." },
    { L"CHAIN_SIGNATURE_INVALID", L"T1553.002", L"A certificate in the signer's chain has a broken signature." },
    { L"UNTRUSTED_ROOT",          L"T1553.002", L"The chain ends at a root certificate this PC does not trust. Cloned or home-made certificates look like this." },
    { L"PARTIAL_CHAIN",           L"T1553.002", L"The certificate chain is incomplete." },
    { L"EXPIRED_CERT",            L"",          L"A certificate in the chain has expired. Old signed programs are often fine if they were timestamped." },
    { L"REVOKED",                 L"T1553.002", L"The certificate authority has revoked the signing certificate. That usually means the key was stolen or misused." },
    { L"SELF_SIGNED",             L"T1587.002", L"The program is signed with a certificate its author made themselves. That proves nothing about who wrote it." },
    { L"POSSIBLE_CLONE",          L"T1553.002", L"The signer name looks real but the chain leads to an untrusted root: a likely cloned certificate." },
    { L"SIGNER_LOCATION_MISMATCH",L"T1036.005", L"A file in a Windows system folder is signed by someone other than Microsoft." },
    { L"SIGNED_IN_TEMP",          L"",          L"A signed program sits in a temporary or download folder. Fine for installers, odd for anything else." },
    { L"CATALOG_SIGNED",          L"",          L"The file is signed through a Windows security catalog instead of an embedded signature. Normal for Windows' own files." },
    { L"RLO_FILENAME",            L"T1036.002", L"The file name contains a right-to-left override character, a trick that makes evil.exe look like a .txt or .pdf." },
    // Packing (MalwareScoring.cpp)
    { L"PACKED",                  L"T1027.002", L"The program is packed or encrypted: its real code is unpacked only when it runs, which hides it from inspection." },
    { L"RWX_SECTION",             L"T1055",     L"A section is writable and executable at once. Normal compilers never do this; self-modifying and unpacking code does." },
    { L"HIGH_ENTROPY_CODE",       L"T1027.002", L"A code section looks like random data, which means it is compressed or encrypted." },
    { L"HIGH_ENTROPY_DATA",       L"T1027",     L"A data section looks like random data: compressed resources or an encrypted payload." },
    { L"SIZE_MISMATCH",           L"T1027.002", L"A section is far bigger in memory than on disk, a sign it is filled in at run time." },
    { L"EMPTY_CODE_SECTION",      L"T1027.002", L"An executable section has no data on disk. A packer fills it in when the program starts." },
    { L"KNOWN_PACKER_SECTION",    L"T1027.002", L"A section name matches a known packer such as UPX, Themida or VMProtect." },
    { L"UNUSUAL_ENTRY_SECTION",   L"T1027.002", L"The program starts outside its normal code section, which packers and injected stubs do." },
    { L"PACKER_ENTRY_PATTERN",    L"T1027.002", L"The first instructions match a known packer's unpacking stub." },
    { L"LOW_IMPORTS",             L"T1106",     L"The program imports almost no Windows functions, so it probably looks them up at run time to hide what it uses." },
    { L"DOTNET_PROTECTOR",        L"T1027.002", L"The .NET metadata names a protector such as ConfuserEx or SmartAssembly, which hides the program's real code." },
    // PE header anomalies (PeFile.cpp)
    { L"TIMESTAMP_FUTURE",        L"T1070.006", L"The build timestamp is in the future. Tools that fake timestamps leave this mark." },
    { L"TIMESTAMP_ZERO",          L"T1070.006", L"The build timestamp was wiped to zero." },
    { L"TIMESTAMP_ANCIENT",       L"T1070.006", L"The build timestamp is before 1993, older than 32-bit Windows itself." },
    { L"CHECKSUM_MISMATCH",       L"T1027",     L"The header checksum does not match the file. The file was changed after it was built." },
    { L"CHECKSUM_ZERO_DRIVER",    L"",          L"A driver has no header checksum. Windows requires one for drivers." },
    { L"TLS_CALLBACKS",           L"T1622",     L"The program has TLS callbacks: code that runs before the normal start point. Used legitimately by some runtimes, and by malware to run anti-debug checks early." },
    { L"OVERLAY_DATA",            L"",          L"Extra data is appended after the end of the program. Installers do this; so do droppers." },
    { L"OVERLAY_HIGH_ENTROPY",    L"T1027.009", L"The appended data looks encrypted or compressed." },
    { L"OVERLAY_EMBEDDED_PE",     L"T1027.009", L"The appended data contains another program. A program carrying a hidden program is a dropper pattern." },
    { L"PDB_USER_PATH",           L"",          L"The debug path still contains the author's user folder. Harmless, but it tells you who built it." },
    { L"PDB_SUSPICIOUS_WORDS",    L"T1027",     L"The debug path contains words like payload, loader or inject." },
    { L"SECTION_COUNT_HIGH",      L"T1027.002", L"The program has an unusual number of sections." },
    { L"SECTION_NAME_ODD",        L"T1027.002", L"A section name is empty or contains unprintable characters." },
    { L"IMPORT_TABLE_HUGE",       L"T1027",     L"The import table lists far more entries than any normal program; only the first part was read. Files built to slow scanners down look like this." },
    { L"DOTNET",                  L"",          L"This is a .NET program." },
    { L"REPRODUCIBLE_BUILD",      L"",          L"The program was built reproducibly, so the build-time field holds a content hash, not a date." },
    // Origin (FileOrigin.cpp)
    { L"MOTW_INTERNET",           L"T1204.002", L"Windows recorded that this file was downloaded from the internet." },
    { L"MOTW_RESTRICTED",         L"T1204.002", L"Windows recorded that this file came from a site in the Restricted zone." },
    { L"MOTW_MISSING",            L"T1553.005", L"An executable in Downloads or the Desktop has no download mark. Archive tools and attackers strip it to avoid warnings." },
    { L"ADS_EXECUTABLE",          L"T1564.004", L"A hidden NTFS stream attached to this file contains a program or script." },
    { L"ADS_PRESENT",             L"T1564.004", L"The file has an extra NTFS data stream. Usually harmless (some apps tag files this way), sometimes used to hide data." },
    { L"ADS_MANY",                L"T1564.004", L"The file carries an unusual number of extra NTFS data streams; only the first ones were inspected." },
    // Scripts (ScriptAnalysis.cpp)
    { L"ENCODED_COMMAND",         L"T1027.010", L"PowerShell is started with a base64-encoded command, which hides what it runs." },
    { L"INVOKE_EXPRESSION",       L"T1059.001", L"The script runs text as code (Invoke-Expression / IEX), often after downloading it." },
    { L"DOWNLOAD_CRADLE",         L"T1105",     L"The script downloads something from the internet." },
    { L"HIDDEN_WINDOW",           L"T1564.003", L"The script starts PowerShell with a hidden window." },
    { L"EXECUTION_POLICY_BYPASS", L"T1059.001", L"The script turns off PowerShell's execution policy for itself." },
    { L"REFLECTIVE_LOAD",         L"T1620",     L"The script loads a .NET program straight from memory." },
    { L"ADD_TYPE",                L"T1059.001", L"The script compiles C# code on the fly." },
    { L"CERTUTIL_ABUSE",          L"T1140",     L"certutil is used to download or decode a file, a classic living-off-the-land trick." },
    { L"BITSADMIN_TRANSFER",      L"T1197",     L"bitsadmin is used to download a file." },
    { L"MSHTA",                   L"T1218.005", L"mshta runs an HTML application, often straight from a web address." },
    { L"REGSVR32_SCRIPTLET",      L"T1218.010", L"regsvr32 loads a remote scriptlet (the Squiblydoo trick)." },
    { L"RUNDLL32_SCRIPT",         L"T1218.011", L"rundll32 runs JavaScript or an odd entry point." },
    { L"WMIC_PROCESS_CREATE",     L"T1047",     L"WMIC starts a process, which hides the parent." },
    { L"WSCRIPT_SHELL",           L"T1059.005", L"The script creates WScript.Shell to run commands." },
    { L"SHELL_APPLICATION",       L"T1059.005", L"The script uses Shell.Application to run programs." },
    { L"XMLHTTP",                 L"T1105",     L"The script makes web requests (XMLHTTP)." },
    { L"ADODB_STREAM",            L"T1105",     L"The script writes binary data to disk with ADODB.Stream, usually a downloaded file." },
    { L"FILESYSTEMOBJECT",        L"",          L"The script reads or writes files with FileSystemObject." },
    { L"ACTIVEXOBJECT",           L"T1059.007", L"The script creates ActiveX objects." },
    { L"EVAL",                    L"T1027",     L"The script runs a string as code (eval / new Function)." },
    { L"CHAR_CODE_OBFUSCATION",   L"T1027",     L"The script builds text from character codes to hide words from scanners." },
    { L"BASE64_BLOB",             L"T1027",     L"The script contains a long base64 block." },
    { L"BASE64_PE",               L"T1027.009", L"A base64 block in the script decodes to a Windows program." },
    { L"GZIP_PAYLOAD",            L"T1027",     L"A base64 block in the script decodes to compressed data." },
    { L"HEX_BLOB",                L"T1027",     L"The script contains a long run of hex digits, often an encoded payload." },
    { L"DECIMAL_BYTE_ARRAY",      L"T1027",     L"The script contains a long list of byte values, often an encoded payload." },
    { L"BACKTICK_OBFUSCATION",    L"T1027.010", L"Many PowerShell backticks break up words so scanners miss them." },
    { L"CARET_OBFUSCATION",       L"T1027.010", L"Many caret characters break up batch commands so scanners miss them." },
    { L"STRING_CONCAT_OBFUSCATION", L"T1027.010", L"Many short strings glued together hide the real words." },
    { L"HIGH_SYMBOL_RATIO",       L"T1027",     L"The script is mostly symbols rather than letters, a sign of obfuscation." },
    { L"RANDOM_IDENTIFIERS",      L"T1027",     L"Variable names look randomly generated." },
    { L"DEFENDER_TAMPERING",      L"T1562.001", L"The script changes Microsoft Defender settings." },
    { L"SHADOW_COPY_DELETE",      L"T1490",     L"The script deletes shadow copies, which ransomware does before encrypting." },
    { L"NO_PROFILE",              L"",          L"PowerShell is started without the user profile." },
};

std::wstring AttackTechniqueForCode(const std::wstring& code)
{
    for (const CodeInfo& c : kCodes) {
        if (code == c.code) return c.technique;
    }
    return L"";
}

std::wstring ExplainIndicator(const std::wstring& code)
{
    for (const CodeInfo& c : kCodes) {
        if (code == c.code) return c.explanation;
    }
    return L"";
}

void AddUniqueTechniques(std::vector<std::wstring>& target, const std::vector<std::wstring>& ids)
{
    for (const std::wstring& id : ids) {
        if (id.empty()) continue;
        if (std::find(target.begin(), target.end(), id) == target.end()) {
            target.push_back(id);
        }
    }
}

std::wstring IndicatorCode(const std::wstring& indicator)
{
    std::wstring t = TrimW(indicator);
    size_t end = 0;
    while (end < t.size() && (iswupper(t[end]) || iswdigit(t[end]) || t[end] == L'_')) ++end;
    return t.substr(0, end);
}

std::wstring BuildNavigatorLayer(const std::wstring& layerName, const std::wstring& description,
                                 const std::vector<TechniqueCount>& techniques)
{
    int maxCount = 1;
    for (const TechniqueCount& t : techniques) maxCount = (std::max)(maxCount, t.count);

    JsonWriter w;
    w.BeginObject();
    w.Key(L"name"); w.String(layerName);
    w.Key(L"versions");
    w.BeginObject();
    w.Key(L"attack");    w.String(L"16");
    w.Key(L"navigator"); w.String(L"5.1.0");
    w.Key(L"layer");     w.String(L"4.5");
    w.EndObject();
    w.Key(L"domain"); w.String(L"enterprise-attack");
    w.Key(L"description"); w.String(description);
    w.Key(L"sorting"); w.Number(3);
    w.Key(L"hideDisabled"); w.Bool(false);
    w.Key(L"techniques");
    w.BeginArray();
    for (const TechniqueCount& t : techniques) {
        w.BeginObject();
        w.Key(L"techniqueID"); w.String(t.id);
        w.Key(L"score"); w.Number(t.count);
        w.Key(L"enabled"); w.Bool(true);
        std::wstring comment = t.comment;
        std::wstring name = AttackTechniqueName(t.id);
        if (!name.empty()) comment = name + (comment.empty() ? L"" : L": " + comment);
        w.Key(L"comment"); w.String(comment);
        w.EndObject();
    }
    w.EndArray();
    w.Key(L"gradient");
    w.BeginObject();
    w.Key(L"colors");
    w.BeginArray();
    w.String(L"#ffe766ff");
    w.String(L"#ff6666ff");
    w.EndArray();
    w.Key(L"minValue"); w.Number(0);
    w.Key(L"maxValue"); w.Number(maxCount);
    w.EndObject();
    w.Key(L"legendItems"); w.BeginArray(); w.EndArray();
    w.Key(L"showTacticRowBackground"); w.Bool(false);
    w.Key(L"selectTechniquesAcrossTactics"); w.Bool(true);
    w.Key(L"selectSubtechniquesWithParent"); w.Bool(false);
    w.EndObject();
    return w.Text();
}
