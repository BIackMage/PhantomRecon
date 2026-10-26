// Group 4 fixes (audit checks B): browser extension names, scheduled tasks hidden
// from the account, DNS servers and zone ids, svchost service DLLs, user-writable
// Windows folders, host-program payloads, write access (elevated runs, create-folder
// rights, deny entries, PATH roots), root certificates by thumbprint, task authors,
// moved Desktop and Downloads, long paths, and the minor items: .url and .vsto files,
// snapshot whitespace, parent PID reuse, pseudo-processes, the hosts DataBasePath.

// Winsock headers first: windows.h would otherwise pull in the old winsock.h.
#include <winsock2.h>
#include <ws2tcpip.h>

#include "TestFramework.h"

#include "../AppPaths.h"
#include "../CheckHelpers.h"
#include "../FileIO.h"
#include "../SecurityCheckModules.h"
#include "../SecurityChecks.h"
#include "../SystemInfo.h"
#include "../TextUtils.h"

#include <windows.h>
#include <aclapi.h>
#include <iphlpapi.h>
#include <knownfolders.h>
#include <sddl.h>
#include <shlobj.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {

std::wstring WindowsDir()
{
    wchar_t buf[MAX_PATH] = {};
    UINT n = GetWindowsDirectoryW(buf, MAX_PATH);
    return n > 0 && n < MAX_PATH ? std::wstring(buf) : std::wstring(L"C:\\Windows");
}

// A DACL built from SDDL, for the pure DACL test. The returned descriptor owns the ACL.
struct SddlDacl {
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    explicit SddlDacl(const wchar_t* sddl)
    {
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL)) {
            BOOL present = FALSE, defaulted = FALSE;
            GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
            if (!present) dacl = NULL;
        }
    }
    ~SddlDacl()
    {
        if (sd) LocalFree(sd);
    }
};

// Make a folder in the test directory and give it exactly the DACL in sddl
// (protected, nothing inherited).
bool MakeFolderWithDacl(const std::wstring& path, const wchar_t* sddl)
{
    if (!CreateDirectoryW(path.c_str(), NULL)) return false;
    SddlDacl d(sddl);
    if (!d.sd) return false;
    DWORD rc = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, d.dacl, NULL);
    return rc == ERROR_SUCCESS;
}

std::wstring KnownFolder(REFKNOWNFOLDERID id)
{
    PWSTR path = NULL;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DONT_VERIFY, NULL, &path)) && path) out = path;
    CoTaskMemFree(path);
    return out;
}

bool Contains(const std::wstring& text, const std::wstring& part)
{
    return text.find(part) != std::wstring::npos;
}

} // namespace

// A2: an extension named "__MSG__" made the audit pop_back() an empty string.
TEST(FixB_A2_ExtensionMessageKey)
{
    CHECK_EQ(ExtensionMessageKey(L"__MSG__"), std::wstring(L""));
    CHECK_EQ(ExtensionMessageKey(L"__MSG___"), std::wstring(L""));
    CHECK_EQ(ExtensionMessageKey(L"__MSG_"), std::wstring(L""));
    CHECK_EQ(ExtensionMessageKey(L"__MSG_x"), std::wstring(L""));
    CHECK_EQ(ExtensionMessageKey(L"Plain Name"), std::wstring(L""));
    CHECK_EQ(ExtensionMessageKey(L"__MSG_appName__"), std::wstring(L"appName"));
    CHECK_EQ(ExtensionMessageKey(L"__MSG_a__"), std::wstring(L"a"));
}

// A2 end to end, plus the snapshot round trip (whitespace) and svchost service DLLs (C4):
// a fake Chrome profile with a "__MSG__" extension must be counted, not crash the sweep.
TEST(FixB_A2_C4_PersistenceSweepEndToEnd)
{
    std::wstring local = tf::TestDir() + L"local";
    std::wstring ext = local + L"\\Google\\Chrome\\User Data\\Default\\Extensions";
    REQUIRE(EnsureDirectory(ext + L"\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\1.0_0"));
    REQUIRE(EnsureDirectory(ext + L"\\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\\2.0_0\\_locales\\en"));
    std::string bad = "{ \"name\": \"__MSG__\", \"version\": \"1.0\" }";
    REQUIRE(WriteBinaryFile(ext + L"\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\1.0_0\\manifest.json", bad.data(), bad.size()));
    std::string good = "{ \"name\": \"__MSG_appName__\", \"default_locale\": \"en\" }";
    REQUIRE(WriteBinaryFile(ext + L"\\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\\2.0_0\\manifest.json", good.data(), good.size()));
    std::string messages = "{ \"appName\": { \"message\": \"Resolved Name\" } }";
    REQUIRE(WriteBinaryFile(ext + L"\\bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\\2.0_0\\_locales\\en\\messages.json", messages.data(), messages.size()));

    wchar_t saved[MAX_PATH * 2] = {};
    DWORD savedLen = GetEnvironmentVariableW(L"LOCALAPPDATA", saved, MAX_PATH * 2);
    REQUIRE(savedLen > 0 && savedLen < MAX_PATH * 2);
    REQUIRE(SetEnvironmentVariableW(L"LOCALAPPDATA", local.c_str()));

    AuditContext context;
    context.snapshotPath = tf::TestDir() + L"persistence.snapshot";
    SecurityCheckResult first;
    SecurityCheckResult second;
    try {
        first = CheckPersistence(context);
        second = CheckPersistence(context);
    }
    catch (...) {
        SetEnvironmentVariableW(L"LOCALAPPDATA", saved);
        throw;
    }
    SetEnvironmentVariableW(L"LOCALAPPDATA", saved);

    CHECK(Contains(first.detail, L"Chrome extension: 2\n"));
    CHECK(Contains(first.detail, L"first audit, so nothing is marked new yet"));
    // Every key written must read back: nothing is new on an immediate second run.
    CHECK(Contains(second.detail, L"; 0 new since the last audit"));
    // C4: services hosted by svchost.exe are inspected through their ServiceDll.
    CHECK(Contains(first.detail, L"Service DLL (svchost): "));
}

// C1: tasks the account cannot read were skipped silently and the check passed.
TEST(FixB_C1_UnreadableTasksAreReported)
{
    SecurityCheckResult r = CheckScheduledTasks();
    REQUIRE(r.status != CHECK_ERROR);
    if (DirectoryExists(WindowsDir() + L"\\System32\\Tasks")) {
        CHECK(Contains(r.detail, L"task file(s) on disk"));
    }
    // Tasks outside \Microsoft\ that could not be read are never a PASS.
    if (Contains(r.detail, L"Not readable, outside \\Microsoft\\:")) {
        CHECK(r.status == CHECK_WARNING || r.status == CHECK_FAIL);
    }
    if (IsProcessElevated() && Contains(r.detail, L"does not show even to an administrator")) {
        CHECK(r.status == CHECK_WARNING || r.status == CHECK_FAIL);
    }
}

// C2 and C3: DNS servers were dropped without WSAStartup; zone ids made link-local
// and site-local servers look public; hand-set IPv6 servers were never checked.
TEST(FixB_C2_C3_DnsServers)
{
    CHECK_EQ(StripAddressZone(L"fe80::1%12"), std::wstring(L"fe80::1"));
    CHECK_EQ(StripAddressZone(L"192.168.1.1"), std::wstring(L"192.168.1.1"));
    CHECK(IsPrivateOrLocalAddress(StripAddressZone(L"fe80::1%12")));
    CHECK(IsPrivateOrLocalAddress(StripAddressZone(L"fec0:0:0:ffff::1%7")));
    CHECK(!IsPrivateOrLocalAddress(L"8.8.4.5"));

    std::vector<std::wstring> list = ParseNameServerList(L"192.0.2.1,192.0.2.2 2001:DB8::1%4");
    REQUIRE(list.size() == 3);
    CHECK_EQ(list[0], std::wstring(L"192.0.2.1"));
    CHECK_EQ(list[2], std::wstring(L"2001:DB8::1"));
    CHECK(ParseNameServerList(L"").empty());
    CHECK_EQ(CanonicalAddress(L"2001:DB8:0:0::1"), CanonicalAddress(L"2001:db8::1"));
    CHECK_EQ(CanonicalAddress(L"fe80::1%3"), std::wstring(L"fe80::1"));
    CHECK_EQ(CanonicalAddress(L"not-an-address"), std::wstring(L"not-an-address"));

    // End to end: every DNS server Windows reports for a connected adapter is listed.
    ULONG size = 32 * 1024;
    std::vector<BYTE> buffer(size);
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    REQUIRE(rc == NO_ERROR);
    std::vector<std::wstring> expected;
    for (IP_ADAPTER_ADDRESSES* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (IP_ADAPTER_DNS_SERVER_ADDRESS* d = a->FirstDnsServerAddress; d; d = d->Next) {
            wchar_t text[64] = {};
            const SOCKADDR* sa = d->Address.lpSockaddr;
            if (sa && sa->sa_family == AF_INET) InetNtopW(AF_INET, &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr, text, 64);
            if (sa && sa->sa_family == AF_INET6) InetNtopW(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr, text, 64);
            if (text[0]) expected.push_back(text);
        }
    }
    SecurityCheckResult r = CheckDnsSettings();
    CHECK(r.status != CHECK_ERROR);
    for (const std::wstring& server : expected) {
        if (!Contains(r.detail, server)) tf::Fail(__FILE__, __LINE__, "DNS server missing from the report: " + tf::Narrow(server));
    }
    if (expected.empty()) CHECK(Contains(r.detail, L"No DNS servers are set"));
}

// C5: everything under C:\Windows was trusted, including folders users can write to.
TEST(FixB_C5_UserWritableWindowsFolders)
{
    std::wstring win = WindowsDir();
    CHECK(IsUserWritableWindowsFolder(win + L"\\Tasks\\x.exe"));
    CHECK(IsUserWritableWindowsFolder(win + L"\\Temp\\a\\b.dll"));
    CHECK(IsUserWritableWindowsFolder(win + L"\\Tracing\\x.exe"));
    CHECK(IsUserWritableWindowsFolder(win + L"\\System32\\spool\\drivers\\color\\x.exe"));
    CHECK(IsUserWritableWindowsFolder(win + L"\\Tasks"));
    CHECK(!IsUserWritableWindowsFolder(win + L"\\System32\\notepad.exe"));
    CHECK(!IsUserWritableWindowsFolder(win + L"\\TasksX\\x.exe"));
    CHECK(!IsUserWritableWindowsFolder(L"C:\\Program Files\\Tasks\\x.exe"));

    CHECK(IsProtectedWindowsPath(win + L"\\System32\\notepad.exe"));
    CHECK(!IsProtectedWindowsPath(win + L"\\Tasks\\x.exe"));
    CHECK(!IsProtectedWindowsPath(win + L"\\Temp\\x.exe"));
    CHECK(!IsProtectedWindowsPath(win + L"\\System32\\Tasks\\x.exe"));
    CHECK(!IsProtectedWindowsPath(L"C:\\Program Files\\App\\app.exe"));
    CHECK(IsUnderWindowsDirectory(win + L"\\Tracing\\x.exe"));   // still under Windows, just not trusted

    CHECK(IsUserDropLocation(win + L"\\Tracing\\x.exe"));
    CHECK(IsUserDropLocation(win + L"\\System32\\spool\\drivers\\color\\x.exe"));
    CHECK(!IsUserDropLocation(win + L"\\System32\\notepad.exe"));
}

// C6: only the host program (rundll32, wscript, powershell, cmd) was checked.
TEST(FixB_C6_ScriptHostPayload)
{
    CHECK_EQ(ScriptHostPayload(L"rundll32.exe C:\\Users\\x\\e.dll,Start"), std::wstring(L"C:\\Users\\x\\e.dll"));
    CHECK_EQ(ScriptHostPayload(L"C:\\Windows\\System32\\rundll32.exe \"C:\\a b\\e.dll\",#1"), std::wstring(L"C:\\a b\\e.dll"));
    CHECK_EQ(ScriptHostPayload(L"rundll32 C:\\x\\e.dll, Entry arg"), std::wstring(L"C:\\x\\e.dll"));
    CHECK_EQ(ScriptHostPayload(L"rundll32.exe shell32.dll,Control_RunDLL C:\\x\\panel.cpl"), std::wstring(L"C:\\x\\panel.cpl"));
    CHECK_EQ(ScriptHostPayload(L"wscript.exe //B //Nologo C:\\Users\\x\\run.vbs arg"), std::wstring(L"C:\\Users\\x\\run.vbs"));
    CHECK_EQ(ScriptHostPayload(L"cscript /nologo \"C:\\a b\\s.js\""), std::wstring(L"C:\\a b\\s.js"));
    CHECK_EQ(ScriptHostPayload(L"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"C:\\x\\y.ps1\" -a 1"), std::wstring(L"C:\\x\\y.ps1"));
    CHECK_EQ(ScriptHostPayload(L"powershell -f C:\\x\\y.ps1"), std::wstring(L"C:\\x\\y.ps1"));
    CHECK_EQ(ScriptHostPayload(L"powershell -WindowStyle Hidden C:\\x\\y.ps1"), std::wstring(L"C:\\x\\y.ps1"));
    CHECK_EQ(ScriptHostPayload(L"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -w hidden -File C:\\Users\\Public\\a.ps1"),
             std::wstring(L"C:\\Users\\Public\\a.ps1"));
    CHECK_EQ(ScriptHostPayload(L"C:\\Program Files\\PowerShell\\7\\pwsh.exe C:\\x\\y.ps1"), std::wstring(L"C:\\x\\y.ps1"));
    CHECK_EQ(ScriptHostPayload(L"powershell -Command Get-Date"), std::wstring(L""));
    CHECK_EQ(ScriptHostPayload(L"powershell -EncodedCommand AAAA"), std::wstring(L""));
    CHECK_EQ(ScriptHostPayload(L"cmd /c C:\\Users\\x\\e.exe"), std::wstring(L"C:\\Users\\x\\e.exe"));
    CHECK_EQ(ScriptHostPayload(L"cmd.exe /q /c start \"\" /min \"C:\\Users\\x\\e.bat\""), std::wstring(L"C:\\Users\\x\\e.bat"));
    CHECK_EQ(ScriptHostPayload(L"cmd /c wscript.exe C:\\x\\s.vbs"), std::wstring(L"C:\\x\\s.vbs"));
    CHECK_EQ(ScriptHostPayload(L"cmd /c \"\"C:\\a b\\x.exe\" arg\""), std::wstring(L"C:\\a b\\x.exe"));
    CHECK_EQ(ScriptHostPayload(L"cmd /c echo hi"), std::wstring(L""));
    CHECK_EQ(ScriptHostPayload(L"regsvr32 /s /u C:\\x\\a.dll"), std::wstring(L"C:\\x\\a.dll"));
    CHECK_EQ(ScriptHostPayload(L"mshta http://example.invalid/a.hta"), std::wstring(L""));
    CHECK_EQ(ScriptHostPayload(L"mshta C:\\x\\a.hta"), std::wstring(L"C:\\x\\a.hta"));
    CHECK_EQ(ScriptHostPayload(L"conhost.exe --headless C:\\x\\run.cmd"), std::wstring(L"C:\\x\\run.cmd"));
    CHECK_EQ(ScriptHostPayload(L"\"C:\\Program Files\\App\\app.exe\" --x"), std::wstring(L""));
    CHECK_EQ(ScriptHostPayload(L""), std::wstring(L""));
    CHECK(Contains(ScriptHostPayload(L"wscript %SystemRoot%\\x.vbs"), WindowsDir()));   // expanded
}

// C7 and C8: write access. Create-folder-only rights and deny entries were
// mishandled; C:\ was reported writable; the user's own access was ignored when elevated.
TEST(FixB_C7_C8_WriteAccess)
{
    {
        SddlDacl createFoldersOnly(L"D:(A;;0x100004;;;AU)(A;;FA;;;SY)");
        REQUIRE(createFoldersOnly.sd != NULL);
        CHECK(!DaclLetsLowPrivilegeGroupsWrite(createFoldersOnly.dacl, true));
        CHECK(DaclLetsLowPrivilegeGroupsWrite(createFoldersOnly.dacl, false));   // for a file 0x4 is append
    }
    {
        SddlDacl addFile(L"D:(A;;0x100002;;;AU)");
        std::wstring who;
        CHECK(DaclLetsLowPrivilegeGroupsWrite(addFile.dacl, true, &who));
        CHECK(!who.empty());
    }
    {
        SddlDacl denied(L"D:(D;;0x000C0002;;;WD)(A;;FA;;;BU)");   // deny add-file, change-permissions, take-owner
        CHECK(!DaclLetsLowPrivilegeGroupsWrite(denied.dacl, true));
    }
    {
        SddlDacl allowThenDeny(L"D:(A;;0x100002;;;BU)(D;;0x2;;;WD)");   // the allow comes first and wins
        CHECK(DaclLetsLowPrivilegeGroupsWrite(allowThenDeny.dacl, true));
    }
    {
        SddlDacl inheritOnly(L"D:(A;OICIIO;FA;;;BU)");
        CHECK(!DaclLetsLowPrivilegeGroupsWrite(inheritOnly.dacl, true));
    }
    {
        SddlDacl generic(L"D:(A;;GA;;;BU)");
        CHECK(DaclLetsLowPrivilegeGroupsWrite(generic.dacl, true));
        SddlDacl genericWrite(L"D:(A;;GW;;;IU)");
        CHECK(DaclLetsLowPrivilegeGroupsWrite(genericWrite.dacl, false));
    }
    {
        SddlDacl adminsOnly(L"D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)");
        CHECK(!DaclLetsLowPrivilegeGroupsWrite(adminsOnly.dacl, true));
        SddlDacl changePermissions(L"D:(A;;0x40000;;;BU)");   // WRITE_DAC alone is enough
        CHECK(DaclLetsLowPrivilegeGroupsWrite(changePermissions.dacl, true));
    }
    CHECK(DaclLetsLowPrivilegeGroupsWrite(nullptr, true));   // no DACL at all

    // The drive root: Authenticated Users may only create folders there by default.
    CHECK(!LowPrivilegeWritable(L"C:\\", true, nullptr));

    // Real folders. OWNER RIGHTS takes away the owner's implicit right to change the
    // permissions, so only the entries for the groups decide.
    std::wstring base = tf::TestDir();
    std::wstring noFiles = base + L"aclNoFiles";
    std::wstring files = base + L"aclFiles";
    std::wstring deny = base + L"aclDeny";
    REQUIRE(MakeFolderWithDacl(noFiles, L"D:P(A;;0x1300a9;;;OW)(A;;0x100004;;;AU)(A;;FA;;;SY)(A;;FA;;;BA)"));
    REQUIRE(MakeFolderWithDacl(files, L"D:P(A;;0x1300a9;;;OW)(A;;0x100002;;;AU)(A;;FA;;;SY)"));
    REQUIRE(MakeFolderWithDacl(deny, L"D:P(D;;0x2;;;WD)(A;;0x1300a9;;;OW)(A;;0x1301bf;;;AU)(A;;FA;;;SY)"));
    std::wstring who;
    CHECK(!LowPrivilegeWritable(noFiles, true, &who));
    who.clear();
    CHECK(LowPrivilegeWritable(files, true, &who));
    CHECK(!who.empty());
    CHECK(!LowPrivilegeWritable(deny, true, nullptr));
    CHECK(RemoveDirectoryW(noFiles.c_str()) != FALSE);
    CHECK(RemoveDirectoryW(files.c_str()) != FALSE);
    CHECK(RemoveDirectoryW(deny.c_str()) != FALSE);

    // A folder in this user's own profile: writable by this user. When elevated the
    // check asks the user's linked non-elevated token (C7), so the answer is the same.
    who.clear();
    CHECK(LowPrivilegeWritable(tf::TestDir(), true, &who));
    CHECK(!who.empty());

    // PATH entries: a drive root keeps its backslash.
    CHECK_EQ(CleanPathListEntry(L"C:\\"), std::wstring(L"C:\\"));
    CHECK_EQ(CleanPathListEntry(L" \"C:\\Tools\\\" "), std::wstring(L"C:\\Tools"));
    CHECK_EQ(CleanPathListEntry(L"C:\\Tools\\\\"), std::wstring(L"C:\\Tools"));
    CHECK_EQ(CleanPathListEntry(L"\"D:\\\""), std::wstring(L"D:\\"));
    CHECK_EQ(CleanPathListEntry(L"%SystemRoot%\\system32"), std::wstring(L"%SystemRoot%\\system32"));
    CHECK_EQ(CleanPathListEntry(L"  "), std::wstring(L""));
}

// C9: built-in roots were trusted by name prefix.
TEST(FixB_C9_RootsByThumbprint)
{
    CHECK(IsBuiltInWindowsRootThumbprint(L"A43489159A520F0D93D032CCAF37E7FE20A8B419"));
    CHECK(IsBuiltInWindowsRootThumbprint(L"cdd4eeae6000ac7f40c3802c171e30148030c072"));
    CHECK(IsBuiltInWindowsRootThumbprint(L"18F7C1FCC3090203FD5BAA2F861A754976C8DD25"));
    CHECK(!IsBuiltInWindowsRootThumbprint(L"0000000000000000000000000000000000000000"));
    CHECK(!IsBuiltInWindowsRootThumbprint(L"Microsoft Root Certificate Authority"));
    CHECK(!IsBuiltInWindowsRootThumbprint(L""));

    // On this PC: no built-in root is reported as foreign.
    SecurityCheckResult r = CheckRootCertificates();
    CHECK(r.status != CHECK_ERROR);
    const wchar_t* builtIn[] = {
        L"A43489159A520F0D93D032CCAF37E7FE20A8B419", L"CDD4EEAE6000AC7F40C3802C171E30148030C072",
        L"245C97DF7514E7CF2DF8BE72AE957B9E04741E85", L"7F88CD7223F3C813818C994614A89C99FA3B5247",
    };
    for (const wchar_t* t : builtIn) {
        if (Contains(r.detail, std::wstring(L"thumbprint ") + t)) tf::Fail(__FILE__, __LINE__, "built-in root reported: " + tf::Narrow(t));
    }
}

// C10: an empty task author counted as Microsoft.
TEST(FixB_C10_TaskAuthors)
{
    CHECK(!IsMicrosoftTaskAuthor(L""));
    CHECK(!IsMicrosoftTaskAuthor(L"   "));
    CHECK(IsMicrosoftTaskAuthor(L"Microsoft Corporation"));
    CHECK(IsMicrosoftTaskAuthor(L"$(@%SystemRoot%\\system32\\wininet.dll,-16000)"));
    CHECK(IsMicrosoftTaskAuthor(L"@%windir%\\system32\\x.dll,-1"));
    CHECK(!IsMicrosoftTaskAuthor(L"$(@C:\\Users\\x\\evil.dll,-1)"));
    CHECK(!IsMicrosoftTaskAuthor(L"$Contoso"));
    CHECK(!IsMicrosoftTaskAuthor(L"Contoso Ltd"));
}

// C12: Desktop and Downloads moved by OneDrive or to another folder.
TEST(FixB_C12_MovedDropFolders)
{
    CHECK(IsUserDropLocation(L"C:\\Users\\bob\\OneDrive\\Desktop\\x.exe"));
    CHECK(IsUserDropLocation(L"C:\\Users\\bob\\OneDrive - Contoso\\Downloads\\a.exe"));
    CHECK(IsUserDropLocation(L"D:\\Users\\bob\\Downloads\\a.exe"));
    CHECK(!IsUserDropLocation(L"C:\\Users\\bob\\OneDrive\\Documents\\a.exe"));
    CHECK(!IsUserDropLocation(L"C:\\Users\\bob\\OneDriveTools\\a.exe"));
    CHECK(!IsUserDropLocation(L"C:\\Program Files\\App\\a.exe"));
    // Wherever Windows says this user's Downloads and Desktop really are.
    std::wstring downloads = KnownFolder(FOLDERID_Downloads);
    std::wstring desktop = KnownFolder(FOLDERID_Desktop);
    if (!downloads.empty() && downloads.size() > 3) CHECK(IsUserDropLocation(downloads + L"\\x.exe"));
    if (!desktop.empty() && desktop.size() > 3) CHECK(IsUserDropLocation(desktop + L"\\x.exe"));
    CHECK(IsUserDropLocation(L"\\\\?\\UNC\\server\\share\\x.exe"));
    CHECK(IsUserDropLocation(L"\\\\server\\share\\x.exe"));
}

// I5: permissions of a path longer than MAX_PATH are read through the \\?\ prefix.
TEST(FixB_I5_LongPathWriteAccess)
{
    std::wstring deep = tf::TestDir();
    for (int i = 0; i < 30; ++i) deep += L"segment_" + std::to_wstring(i % 10) + L"\\";
    deep.pop_back();
    REQUIRE(deep.size() > MAX_PATH);
    REQUIRE(EnsureDirectory(deep));
    std::wstring who;
    CHECK(LowPrivilegeWritable(deep, true, &who));
    CHECK(!who.empty());
    std::wstring file = deep + L"\\f.txt";
    REQUIRE(WriteBinaryFile(file, "x", 1));
    CHECK(LowPrivilegeWritable(file, false, nullptr));
}

// Minor items: .url and .vsto files, snapshot whitespace, parent PID reuse,
// pseudo-processes, the hosts DataBasePath.
TEST(FixB_MinorItems)
{
    CHECK(!SignatureExpected(L"C:\\x\\Startup\\site.url"));
    CHECK(!SignatureExpected(L"C:\\x\\addin.vsto"));
    CHECK(!SignatureExpected(L"C:\\x\\run.CMD"));
    CHECK(!SignatureExpected(L"C:\\x\\run.ps1"));
    CHECK(SignatureExpected(L"C:\\x\\a.exe"));
    CHECK(SignatureExpected(L"C:\\x\\a.dll"));
    CHECK(SignatureExpected(L"C:\\x\\noextension"));

    CHECK_EQ(FileUrlToPath(L"file:///C:/Program%20Files/x/a.vsto|vstolocal"), std::wstring(L"C:\\Program Files\\x\\a.vsto"));
    CHECK_EQ(FileUrlToPath(L"C:\\x\\a.vsto|vstolocal"), std::wstring(L"C:\\x\\a.vsto"));
    CHECK_EQ(FileUrlToPath(L"file:///C:/caf%C3%A9/a.vsto"), std::wstring(L"C:\\caf\x00E9\\a.vsto"));
    CHECK_EQ(FileUrlToPath(L"file://server/share/a.vsto"), std::wstring(L"\\\\server\\share\\a.vsto"));
    CHECK_EQ(FileUrlToPath(L"file:///C:/100%/a"), std::wstring(L"C:\\100%\\a"));

    std::wstring key = NormalizeSnapshotKey(L"WMI|Name|line one\r\n\tline  two  ");
    CHECK_EQ(key, std::wstring(L"wmi|name|line one line two"));
    CHECK_EQ(NormalizeSnapshotKey(key), key);   // reads back exactly as written
    CHECK(NormalizeSnapshotKey(key).find(L'\n') == std::wstring::npos);
    CHECK_EQ(NormalizeSnapshotKey(L"run (hkcu)|x|c:\\a.exe\r"), std::wstring(L"run (hkcu)|x|c:\\a.exe"));

    CHECK_EQ(ParentStartOrder(100, 200), 1);
    CHECK_EQ(ParentStartOrder(200, 200), 1);
    CHECK_EQ(ParentStartOrder(300, 200), -1);   // the PID was reused by a later process
    CHECK_EQ(ParentStartOrder(0, 200), 0);
    CHECK_EQ(ParentStartOrder(100, 0), 0);

    CHECK(IsPseudoProcessImage(L"Registry"));
    CHECK(IsPseudoProcessImage(L"MemCompression"));
    CHECK(IsPseudoProcessImage(L"Secure System"));
    CHECK(!IsPseudoProcessImage(L"C:\\Windows\\System32\\svchost.exe"));
    CHECK(!IsPseudoProcessImage(L"\\Device\\HarddiskVolume3\\x.exe"));
    CHECK(!IsPseudoProcessImage(L""));

    CHECK_EQ(HostsFilePath(L"", L"C:\\Windows\\System32\\drivers\\etc"), std::wstring(L"C:\\Windows\\System32\\drivers\\etc\\hosts"));
    CHECK_EQ(HostsFilePath(L"D:\\alt\\", L"C:\\Windows\\System32\\drivers\\etc"), std::wstring(L"D:\\alt\\hosts"));
    CHECK_EQ(HostsFilePath(L"  D:\\alt  ", L"C:\\x"), std::wstring(L"D:\\alt\\hosts"));

    // On this PC the hosts check names the file it read.
    SecurityCheckResult hosts = CheckHostsFile();
    CHECK(Contains(hosts.detail, L"hosts"));
    CHECK(hosts.status != CHECK_ERROR);
}
