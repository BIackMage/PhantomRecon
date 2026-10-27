// Exact undo for the fix plan's registry steps (FixScriptBackup.cpp): the declared
// values match the command lines, and the generated fix and undo scripts, run for real
// on keys under HKCU\Software\PhantomReconTests-<pid>, put back exactly the earlier
// value and type (or remove a value that did not exist, and a key the fix created).
// The catalog lines are rewritten from HKLM: and HKCU: onto the test key, the way
// TestFixNightReview.cpp does it; no test touches HKLM. Every test key is deleted.

#include "TestFramework.h"
#include "PowerShellRun.h"

#include "../AppPaths.h"
#include "../CheckCatalog.h"
#include "../CheckScripts.h"
#include "../FileIO.h"
#include "../FixScript.h"
#include "../FixScriptBackup.h"
#include "../SecurityChecks.h"
#include "../TextUtils.h"

#include <windows.h>
#include <cstdio>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Registry access for the checks: direct Win32 calls, independent of PowerShell
// ---------------------------------------------------------------------------
struct RegValue {
    DWORD type = REG_NONE;
    std::vector<BYTE> data;
    bool operator==(const RegValue& o) const { return type == o.type && data == o.data; }
};

// "Software\PhantomReconTests-<pid>"
std::wstring TestRootKey()
{
    return L"Software\\PhantomReconTests-" + std::to_wstring(GetCurrentProcessId());
}

std::wstring PsPathOf(const std::wstring& hkcuSubkey)
{
    return L"HKCU:\\" + hkcuSubkey;
}

bool SetRegValue(const std::wstring& subkey, const std::wstring& name, DWORD type, const std::vector<BYTE>& data)
{
    HKEY key = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL) != ERROR_SUCCESS) return false;
    LONG rc = RegSetValueExW(key, name.c_str(), 0, type, data.empty() ? NULL : data.data(), static_cast<DWORD>(data.size()));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

bool CreateRegKey(const std::wstring& subkey)
{
    HKEY key = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, NULL, 0, KEY_READ, NULL, &key, NULL) != ERROR_SUCCESS) return false;
    RegCloseKey(key);
    return true;
}

bool KeyExists(const std::wstring& subkey)
{
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) return false;
    RegCloseKey(key);
    return true;
}

bool GetRegValue(const std::wstring& subkey, const std::wstring& name, RegValue& out)
{
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = 0;
    LONG rc = RegQueryValueExW(key, name.c_str(), NULL, &type, NULL, &size);
    if (rc == ERROR_SUCCESS) {
        out.type = type;
        out.data.assign(size, 0);
        rc = RegQueryValueExW(key, name.c_str(), NULL, &type, size ? out.data.data() : NULL, &size);
        out.data.resize(size);
    }
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

void DeleteRegTree(const std::wstring& subkey)
{
    RegDeleteTreeW(HKEY_CURRENT_USER, subkey.c_str());
    RegDeleteKeyW(HKEY_CURRENT_USER, subkey.c_str());
}

// Every key and value under subkey: "path\" for a key, "path|name" for a value.
void SnapshotInto(const std::wstring& subkey, const std::wstring& rel, std::map<std::wstring, RegValue>& out)
{
    HKEY key = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) return;
    out[rel + L"\\"] = RegValue();
    for (DWORD i = 0;; ++i) {
        wchar_t name[16384];
        DWORD nameLen = 16384, type = 0, size = 0;
        if (RegEnumValueW(key, i, name, &nameLen, NULL, &type, NULL, &size) != ERROR_SUCCESS) break;
        RegValue v;
        v.type = type;
        v.data.assign(size, 0);
        nameLen = 16384;
        RegEnumValueW(key, i, name, &nameLen, NULL, &type, size ? v.data.data() : NULL, &size);
        v.data.resize(size);
        out[rel + L"|" + std::wstring(name, nameLen)] = v;
    }
    std::vector<std::wstring> subs;
    for (DWORD i = 0;; ++i) {
        wchar_t name[256];
        DWORD nameLen = 256;
        if (RegEnumKeyExW(key, i, name, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        subs.push_back(std::wstring(name, nameLen));
    }
    RegCloseKey(key);
    for (const std::wstring& s : subs) SnapshotInto(subkey + L"\\" + s, rel + L"\\" + s, out);
}

std::map<std::wstring, RegValue> Snapshot(const std::wstring& subkey)
{
    std::map<std::wstring, RegValue> out;
    SnapshotInto(subkey, L"", out);
    return out;
}

std::string Describe(const RegValue& v)
{
    std::string s = "type " + std::to_string(v.type) + " [";
    char buf[4];
    for (BYTE b : v.data) {
        sprintf_s(buf, "%02x", b);
        s += buf;
    }
    return s + "]";
}

// Fails once per difference, with what differs.
bool SameSnapshot(const std::map<std::wstring, RegValue>& want, const std::map<std::wstring, RegValue>& got, const char* what)
{
    bool same = true;
    for (const auto& w : want) {
        auto it = got.find(w.first);
        if (it == got.end()) {
            tf::Fail(__FILE__, __LINE__, std::string(what) + ": missing " + tf::Narrow(w.first));
            same = false;
        }
        else if (!(it->second == w.second)) {
            tf::Fail(__FILE__, __LINE__, std::string(what) + ": " + tf::Narrow(w.first) + " is " + Describe(it->second) +
                     ", expected " + Describe(w.second));
            same = false;
        }
    }
    for (const auto& g : got) {
        if (want.count(g.first) == 0) {
            tf::Fail(__FILE__, __LINE__, std::string(what) + ": unexpected " + tf::Narrow(g.first));
            same = false;
        }
    }
    return same;
}

std::vector<BYTE> Dword(DWORD v)
{
    return std::vector<BYTE>(reinterpret_cast<BYTE*>(&v), reinterpret_cast<BYTE*>(&v) + sizeof(v));
}

std::vector<BYTE> Qword(unsigned long long v)
{
    return std::vector<BYTE>(reinterpret_cast<BYTE*>(&v), reinterpret_cast<BYTE*>(&v) + sizeof(v));
}

std::vector<BYTE> Sz(const std::wstring& s)
{
    std::wstring z = s;
    z.push_back(L'\0');
    const BYTE* p = reinterpret_cast<const BYTE*>(z.data());
    return std::vector<BYTE>(p, p + z.size() * sizeof(wchar_t));
}

// REG_MULTI_SZ: each string ends in a NUL, and the list ends in one more.
std::vector<BYTE> MultiSz(const std::vector<std::wstring>& parts)
{
    std::wstring z;
    for (const std::wstring& p : parts) {
        z += p;
        z.push_back(L'\0');
    }
    z.push_back(L'\0');
    const BYTE* p = reinterpret_cast<const BYTE*>(z.data());
    return std::vector<BYTE>(p, p + z.size() * sizeof(wchar_t));
}

bool Contains(const std::string& text, const std::string& part)
{
    return text.find(part) != std::string::npos;
}

bool Contains(const std::wstring& text, const std::wstring& part)
{
    return text.find(part) != std::wstring::npos;
}

size_t CountOf(const std::string& text, const std::string& part)
{
    size_t n = 0;
    for (size_t p = text.find(part); p != std::string::npos; p = text.find(part, p + part.size())) ++n;
    return n;
}

std::string Answers(size_t count, const char* answer = "y")
{
    std::string s;
    for (size_t i = 0; i < count; ++i) s += std::string(answer) + "\r\n";
    return s;
}

// ---------------------------------------------------------------------------
// Catalog rows moved onto the test key
// ---------------------------------------------------------------------------

// HKLM:\X -> HKCU:\<scenario>\HKLM\X and HKCU:\X -> HKCU:\<scenario>\HKCU\X, so the
// real catalog lines run on the test key.
std::wstring MovePath(const std::wstring& text, const std::wstring& scenarioKey)
{
    std::wstring out = ReplaceAllW(text, L"HKLM:\\", L"\x0001LM\\");
    out = ReplaceAllW(out, L"HKCU:\\", L"\x0001CU\\");
    out = ReplaceAllW(out, L"\x0001LM\\", PsPathOf(scenarioKey) + L"\\HKLM\\");
    out = ReplaceAllW(out, L"\x0001CU\\", PsPathOf(scenarioKey) + L"\\HKCU\\");
    return out;
}

// Only the lines that name a registry path, moved onto the test key. Every other line
// (Set-SmbClientConfiguration, Set-MpPreference, ...) would change this PC for real,
// so it never reaches a test script.
std::wstring MovedRegistryLines(const std::wstring& script, const std::wstring& scenarioKey)
{
    std::vector<std::wstring> kept;
    for (const std::wstring& line : SplitW(script, L'\n')) {
        std::wstring moved = MovePath(line, scenarioKey);
        if (moved.find(PsPathOf(scenarioKey) + L"\\") != std::wstring::npos) kept.push_back(moved);
    }
    return JoinW(kept, L"\n");
}

CheckInfo MovedRow(const CheckInfo& real, const std::wstring& scenarioKey, const std::wstring& newId = L"")
{
    CheckInfo info = real;
    if (!newId.empty()) info.id = newId;
    info.fixScript = MovedRegistryLines(real.fixScript, scenarioKey);
    info.undoScript = MovedRegistryLines(real.undoScript, scenarioKey);
    for (RegistryValueRef& v : info.scriptRegistry) v.key = MovePath(v.key, scenarioKey);
    info.scriptNeedsAdmin = false;
    return info;
}

// HKCU:\Software\... -> Software\... for the Win32 calls.
std::wstring SubkeyOf(const std::wstring& psPath)
{
    return psPath.rfind(L"HKCU:\\", 0) == 0 ? psPath.substr(6) : psPath;
}

SecurityCheckResult FailResult(const std::wstring& id)
{
    SecurityCheckResult r = MakeCheckResult(id);
    r.id = id;
    r.name = id;
    r.status = CHECK_FAIL;
    r.detail = L"evidence for " + id;
    return r;
}

struct Plan {
    std::wstring fixPath;
    std::wstring undoPath;
    std::wstring backupPath;
    std::wstring fixText;
    std::wstring undoText;
};

Plan WritePlan(const std::wstring& name, const std::vector<CheckInfo>& catalog)
{
    // Safety: every command a test plan can run works on the test key and nothing else.
    const std::wstring testPath = PsPathOf(TestRootKey()) + L"\\";
    for (const CheckInfo& info : catalog) {
        for (const std::wstring* script : { &info.fixScript, &info.undoScript }) {
            for (const std::wstring& line : SplitW(*script, L'\n')) {
                if (TrimW(line).empty()) continue;
                REQUIRE(line.find(testPath) != std::wstring::npos);
                REQUIRE(line.find(L"HKLM:") == std::wstring::npos);
            }
        }
        for (const RegistryValueRef& v : info.scriptRegistry) REQUIRE(v.key.rfind(testPath, 0) == 0);
    }
    std::vector<SecurityCheckResult> results;
    for (const CheckInfo& info : catalog) results.push_back(FailResult(info.id));
    Plan p;
    p.fixPath = tf::TestDir() + name + L".ps1";
    p.undoPath = UndoScriptPathFor(p.fixPath);
    p.backupPath = BackupPathFor(p.fixPath);
    FixScriptOptions options;
    options.generatedAt = L"2026-10-27T01:00:00";
    options.scriptName = FileNameOf(p.fixPath);
    options.undoScriptName = FileNameOf(p.undoPath);
    p.fixText = BuildFixScript(results, options, catalog);
    p.undoText = BuildUndoScript(results, options, catalog);
    WriteUtf8File(p.fixPath, p.fixText, true);
    WriteUtf8File(p.undoPath, p.undoText, true);
    return p;
}

PsRunResult Run(const std::wstring& path, const std::string& answers, const std::wstring& args = L"")
{
    PsRunResult r = RunPowerShellScriptFile(path, args, answers);
    if (!r.ran) tf::Fail(__FILE__, __LINE__, "powershell.exe did not run " + tf::Narrow(path));
    return r;
}

void PrintOnFailure(const PsRunResult& r, bool ok)
{
    if (!ok) std::printf("    output:\n%s\n", r.output.c_str());
}

// Deletes the scenario key when the test ends, also after a failed REQUIRE.
struct KeyCleanup {
    std::wstring subkey;
    explicit KeyCleanup(std::wstring k) : subkey(std::move(k)) { DeleteRegTree(subkey); }
    ~KeyCleanup()
    {
        DeleteRegTree(subkey);
        if (KeyExists(subkey)) std::printf("    note: test key %s was not removed\n", tf::Narrow(subkey).c_str());
    }
};

// ---------------------------------------------------------------------------
// Reading the catalog's command lines for the declared-values test
// ---------------------------------------------------------------------------
struct Touch {
    std::wstring key;
    std::wstring name;
    bool each = false;
    bool operator<(const Touch& o) const
    {
        if (ToLowerW(key) != ToLowerW(o.key)) return ToLowerW(key) < ToLowerW(o.key);
        if (ToLowerW(name) != ToLowerW(o.name)) return ToLowerW(name) < ToLowerW(o.name);
        return each < o.each;
    }
};

std::wstring Unquote(const std::wstring& name)
{
    if (name.size() >= 2 && name.front() == L'\'' && name.back() == L'\'') return name.substr(1, name.size() - 2);
    return name;
}

// The registry values a fixScript sets or removes, and the keys it creates. False
// with why set when a line touches the registry in a way this reader does not know.
bool ReadRegistryTouches(const std::wstring& script, std::set<Touch>& touches, std::vector<std::wstring>& createdKeys, std::string& why)
{
    static const std::wregex setRe(L"^Set-ItemProperty '([^']+)' -Name ('[^']*'|[A-Za-z0-9_]+) -Value \\S+( -Type [A-Za-z]+)?$");
    static const std::wregex removeRe(L"^Remove-ItemProperty '([^']+)' -Name ([A-Za-z0-9_,]+)( -ErrorAction SilentlyContinue)?$");
    static const std::wregex eachRe(L"^Get-ChildItem '([^']+)' \\| ForEach-Object \\{ Set-ItemProperty \\$_\\.PSPath -Name ([A-Za-z0-9_]+) -Value \\S+( -Type [A-Za-z]+)? \\}$");
    static const std::wregex newKeyRe(L"^if \\(-not \\(Test-Path '([^']+)'\\)\\) \\{ New-Item '([^']+)' -Force \\| Out-Null \\}$");
    static const std::wregex registryHint(L"(HKLM:|HKCU:|HKEY_|Registry::|ItemProperty|\\breg(\\.exe)?\\s|New-Item|Remove-Item|Set-Item\\b)",
                                          std::regex_constants::ECMAScript | std::regex_constants::icase);
    for (const std::wstring& raw : SplitW(script, L'\n')) {
        std::wstring line = TrimW(raw);
        if (line.empty()) continue;
        std::wsmatch m;
        if (std::regex_match(line, m, setRe)) {
            touches.insert({ m[1].str(), Unquote(m[2].str()), false });
        }
        else if (std::regex_match(line, m, removeRe)) {
            for (const std::wstring& n : SplitW(m[2].str(), L',')) touches.insert({ m[1].str(), n, false });
        }
        else if (std::regex_match(line, m, eachRe)) {
            touches.insert({ m[1].str(), m[2].str(), true });
        }
        else if (std::regex_match(line, m, newKeyRe)) {
            createdKeys.push_back(m[1].str());
        }
        else if (std::regex_search(line, registryHint)) {
            // A provider path in a cmdlet that is not the registry (WSMan:) is fine.
            if (line.find(L"WSMan:") != std::wstring::npos && line.find(L"HK") == std::wstring::npos) continue;
            why = "a registry line the declared-values test cannot read: " + tf::Narrow(line);
            return false;
        }
    }
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// The declared values match the command lines, both ways
// ---------------------------------------------------------------------------
TEST(FixUndo_DeclaredValuesMatchTheCommands)
{
    size_t registrySteps = 0;
    for (const CheckInfo& info : GetCheckCatalog()) {
        std::string id = tf::Narrow(info.id);
        std::set<Touch> touched;
        std::vector<std::wstring> created;
        std::string why;
        if (!ReadRegistryTouches(info.fixScript, touched, created, why)) {
            tf::Fail(__FILE__, __LINE__, id + ": " + why);
            continue;
        }
        std::set<Touch> declared;
        for (const RegistryValueRef& v : info.scriptRegistry) {
            if (!declared.insert({ v.key, v.name, v.eachSubkey }).second) tf::Fail(__FILE__, __LINE__, id + ": declared twice: " + tf::Narrow(v.name));
            if (v.key.rfind(L"HKLM:\\", 0) != 0 && v.key.rfind(L"HKCU:\\", 0) != 0) tf::Fail(__FILE__, __LINE__, id + ": key is not HKLM:\\ or HKCU:\\");
            if (v.key.find(L'\'') != std::wstring::npos || v.key.back() == L'\\') tf::Fail(__FILE__, __LINE__, id + ": odd key " + tf::Narrow(v.key));
        }
        for (const Touch& t : touched) {
            if (declared.count(t) == 0) {
                tf::Fail(__FILE__, __LINE__, id + ": the fixScript changes " + tf::Narrow(t.key) + " " + tf::Narrow(t.name) +
                         " but CheckScripts.cpp does not declare it");
            }
        }
        for (const Touch& d : declared) {
            if (touched.count(d) == 0) {
                tf::Fail(__FILE__, __LINE__, id + ": declared " + tf::Narrow(d.key) + " " + tf::Narrow(d.name) + " but no fixScript line changes it");
            }
        }
        // A key the commands create is a declared key or a parent of one, so the undo
        // may remove it when it is empty.
        for (const std::wstring& k : created) {
            bool ok = false;
            for (const RegistryValueRef& v : info.scriptRegistry) {
                if (!v.eachSubkey && (EqualsI(v.key, k) || StartsWithI(v.key, k + L"\\"))) ok = true;
            }
            if (!ok) tf::Fail(__FILE__, __LINE__, id + ": creates the key " + tf::Narrow(k) + " that no declared value is in");
        }
        if (!info.scriptRegistry.empty()) {
            ++registrySteps;
            CHECK(!info.scriptPerTarget);
            CHECK(HasSavedRegistryValues(info.scriptRegistry));
        }
    }
    std::printf("    note: %zu registry step(s) declared\n", registrySteps);
    CHECK(registrySteps >= 12);

    // The reader is strict: an undeclared form of registry write is caught.
    std::set<Touch> t;
    std::vector<std::wstring> c;
    std::string why;
    CHECK(!ReadRegistryTouches(L"reg add HKLM\\SOFTWARE\\Demo /v X /d 1", t, c, why));
    CHECK(!ReadRegistryTouches(L"New-ItemProperty 'HKLM:\\SOFTWARE\\Demo' -Name X -Value 1", t, c, why));
    CHECK(!ReadRegistryTouches(L"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Demo' -Name X -Value 1", t, c, why));
    CHECK(ReadRegistryTouches(L"Set-MpPreference -MAPSReporting Advanced", t, c, why));
    CHECK(t.empty());

    // A stored password is declared (so the line is accounted for) but never backed up.
    const CheckInfo* autologon = FindCheckInfo(L"acct.autologon");
    if (autologon) {
        bool secretMarked = false;
        for (const RegistryValueRef& v : autologon->scriptRegistry) {
            if (v.name == L"DefaultPassword") secretMarked = v.neverSaved;
        }
        CHECK(secretMarked);
        std::wstring lines = JoinW(RegistryValuesLines(autologon->scriptRegistry), L"\n");
        CHECK(!Contains(lines, L"DefaultPassword"));
        CHECK(Contains(lines, L"AutoAdminLogon"));
    }
}

TEST(FixUndo_BackupFileNames)
{
    CHECK_EQ(BackupFileNameFor(L"plan.ps1"), std::wstring(L"plan-backup.json"));
    CHECK_EQ(BackupFileNameFor(L"Plan.PS1"), std::wstring(L"Plan-backup.json"));
    CHECK_EQ(BackupFileNameFor(L""), std::wstring(L"phantom-recon-fix-backup.json"));
    CHECK_EQ(BackupPathFor(L"C:\\x\\saved plan.ps1"), std::wstring(L"C:\\x\\saved plan-backup.json"));
    CHECK_EQ(BackupPathFor(L"plan.ps1"), std::wstring(L"plan-backup.json"));
    // The backup name is a single-quoted literal, whatever the user called the file.
    std::vector<std::wstring> lines = BackupHelperLines(L"it's plan-backup.json", false);
    CHECK(Contains(JoinW(lines, L"\n"), L"$backupPath = Join-Path $backupFolder 'it''s plan-backup.json'"));
    for (bool undo : { false, true }) {
        for (const std::wstring& line : BackupHelperLines(L"plan-backup.json", undo)) {
            // tools/ci_smoke_test.py counts a step's "        try {" line against its question.
            CHECK(line != L"        try {");
            for (wchar_t ch : line) {
                if (ch == L'"' || ch >= 0x80 || ch == L'\t') {
                    tf::Fail(__FILE__, __LINE__, "double quote, tab or non-ASCII in the helper text: " + tf::Narrow(line));
                    break;
                }
            }
        }
    }
    CHECK(Contains(JoinW(BackupHelperLines(L"b.json", false), L"\n"), L"function Save-PRBackup"));
    CHECK(!Contains(JoinW(BackupHelperLines(L"b.json", false), L"\n"), L"function Restore-PRBackup"));
    CHECK(Contains(JoinW(BackupHelperLines(L"b.json", true), L"\n"), L"function Restore-PRBackup"));
}

// ---------------------------------------------------------------------------
// Every registry step of the real catalog: fix, then undo, gives back the exact
// registry it found (values, types, keys), including earlier values that are not the
// Windows default, values and keys that did not exist, and a stored password that
// never reaches the backup file.
// ---------------------------------------------------------------------------
TEST(FixUndo_EveryCatalogRegistryStepRoundTrips)
{
    const std::wstring scenario = TestRootKey() + L"\\All";
    KeyCleanup cleanup(TestRootKey());
    std::vector<CheckInfo> catalog;
    for (const CheckInfo& info : GetCheckCatalog()) {
        if (HasSavedRegistryValues(info.scriptRegistry) && !info.scriptPerTarget) catalog.push_back(MovedRow(info, scenario));
    }
    REQUIRE(catalog.size() >= 12);

    // Keys the commands create when missing; a key under one of them counts too.
    std::vector<std::wstring> guarded;
    for (const CheckInfo& info : catalog) {
        std::set<Touch> t;
        std::vector<std::wstring> created;
        std::string why;
        REQUIRE(ReadRegistryTouches(info.fixScript, t, created, why));
        for (const std::wstring& k : created) guarded.push_back(k);
    }
    auto isGuarded = [&](const std::wstring& key) {
        for (const std::wstring& g : guarded) {
            if (EqualsI(g, key) || StartsWithI(g, key + L"\\")) return true;
        }
        return false;
    };

    // Seed: earlier values of every type, non-default numbers such as 1800, values that
    // did not exist, keys that did not exist, a sibling value the fix must not touch.
    const std::wstring secret = L"demo-secret-1234";
    std::vector<std::pair<DWORD, std::vector<BYTE>>> kinds = {
        { REG_DWORD, Dword(1800) }, { REG_SZ, Sz(L"15") }, { REG_QWORD, Qword(1800) }, { REG_DWORD, Dword(0xFFFFFFFF) },
        { REG_EXPAND_SZ, Sz(L"%SystemRoot%\\demo") }, { REG_MULTI_SZ, MultiSz({ L"a", L"", L"b" }) }, { REG_BINARY, { 0, 1, 0xFF } },
    };
    size_t valueIndex = 0, keyIndex = 0;
    std::set<std::wstring> seenKeys;
    size_t seededExisting = 0, seededMissing = 0, keysMissing = 0;
    for (const CheckInfo& info : catalog) {
        for (const RegistryValueRef& v : info.scriptRegistry) {
            std::wstring sub = SubkeyOf(v.key);
            if (v.eachSubkey) {
                REQUIRE(SetRegValue(sub + L"\\Tcpip_{11111111-2222-4333-8444-555555555555}", v.name, REG_DWORD, Dword(1)));
                REQUIRE(CreateRegKey(sub + L"\\Tcpip_{22222222-3333-4444-8555-666666666666}"));
                REQUIRE(SetRegValue(sub + L"\\Tcpip_{33333333-4444-4555-8666-777777777777}", v.name, REG_SZ, Sz(L"x")));
                ++seededExisting;
                continue;
            }
            if (v.neverSaved) {
                REQUIRE(SetRegValue(sub, v.name, REG_SZ, Sz(secret)));
                continue;
            }
            bool newKey = seenKeys.insert(ToLowerW(v.key)).second;
            if (newKey) ++keyIndex;
            if (isGuarded(v.key) && keyIndex % 2 == 0 && !KeyExists(sub)) {
                ++keysMissing;   // the key did not exist before the fix
                continue;
            }
            if (newKey) REQUIRE(SetRegValue(sub, L"KeepThis", REG_DWORD, Dword(7)));
            if (valueIndex++ % 3 == 2) {
                ++seededMissing;   // the value did not exist before the fix
                continue;
            }
            const auto& kind = kinds[valueIndex % kinds.size()];
            REQUIRE(SetRegValue(sub, v.name, kind.first, kind.second));
            ++seededExisting;
        }
    }
    std::printf("    note: %zu step(s); %zu value(s) existed, %zu did not, %zu key(s) did not exist\n", catalog.size(),
                seededExisting, seededMissing, keysMissing);
    CHECK(seededExisting > 5 && seededMissing > 2 && keysMissing > 0);
    std::map<std::wstring, RegValue> before = Snapshot(scenario);

    Plan plan = WritePlan(L"all", catalog);
    CHECK_EQ(CountOf(tf::Narrow(plan.fixText), "Save-PRBackup '"), catalog.size());
    CHECK_EQ(CountOf(tf::Narrow(plan.undoText), "Restore-PRBackup '"), catalog.size());

    // -ListOnly: nothing changes and no backup file appears.
    PsRunResult listed = Run(plan.fixPath, Answers(catalog.size()), L"-ListOnly");
    CHECK_EQ(listed.exitCode, static_cast<DWORD>(0));
    CHECK(!FileExists(plan.backupPath));
    CHECK(SameSnapshot(before, Snapshot(scenario), "after -ListOnly"));

    PsRunResult fixed = Run(plan.fixPath, Answers(catalog.size()));
    bool fixOk = fixed.exitCode == 0 && Contains(fixed.output, "Applied: " + std::to_string(catalog.size()) + ". Skipped: 0. Failed: 0.");
    CHECK(fixOk);
    PrintOnFailure(fixed, fixOk);
    REQUIRE(FileExists(plan.backupPath));
    std::map<std::wstring, RegValue> afterFix = Snapshot(scenario);
    CHECK(afterFix != before);

    // The fix did what the catalog says (spot facts that hold for the real lines).
    RegValue v;
    const std::wstring system = scenario + L"\\HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    if (GetRegValue(system, L"InactivityTimeoutSecs", v)) CHECK(v == (RegValue{ REG_DWORD, Dword(900) }));
    else tf::Fail(__FILE__, __LINE__, "InactivityTimeoutSecs was not set by the fix");
    CHECK(!GetRegValue(scenario + L"\\HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", L"AlwaysInstallElevated", v) ||
          FindCheckInfo(L"msi.alwayselevated") == nullptr);

    // The stored password never reaches the backup, not even encoded.
    std::wstring backupText;
    REQUIRE(ReadTextFile(plan.backupPath, backupText, 4 * 1024 * 1024));
    CHECK(!Contains(backupText, secret));
    CHECK(!Contains(backupText, L"DefaultPassword"));
    CHECK(!Contains(backupText, L"ZABlAG0AbwAtAHMAZQBjAHIAZQB0AC0AMQAyADMANAA"));   // base64 of the UTF-16 text
    CHECK(Contains(backupText, L"\"Step\""));

    PsRunResult undone = Run(plan.undoPath, Answers(catalog.size()));
    bool undoOk = undone.exitCode == 0 && Contains(undone.output, "Applied: " + std::to_string(catalog.size()) + ". Skipped: 0. Failed: 0.") &&
                  CountOf(undone.output, "Applied from the backup: the exact values from before the fix are back.") == catalog.size();
    CHECK(undoOk);
    PrintOnFailure(undone, undoOk);

    // Exactly what was there, except the stored password, which the fix removed and the
    // undo leaves removed.
    std::map<std::wstring, RegValue> want = before;
    for (auto it = want.begin(); it != want.end();) {
        if (it->first.size() > 16 && it->first.compare(it->first.size() - 16, 16, L"|DefaultPassword") == 0) it = want.erase(it);
        else ++it;
    }
    CHECK(SameSnapshot(want, Snapshot(scenario), "after the undo"));
}

// ---------------------------------------------------------------------------
// Each value type, a non-default earlier value (1800), a value that did not exist
// and a key that did not exist, each in its own step built from a real catalog row.
// ---------------------------------------------------------------------------
TEST(FixUndo_EveryValueTypeRoundTrips)
{
    const CheckInfo* screenlock = FindCheckInfo(L"acct.screenlock");
    const CheckInfo* wsh = FindCheckInfo(L"hard.wsh");
    REQUIRE(screenlock != nullptr && wsh != nullptr);
    REQUIRE(screenlock->scriptRegistry.size() == 1 && wsh->scriptRegistry.size() == 1);
    KeyCleanup cleanup(TestRootKey());

    struct Case {
        const wchar_t* name;
        bool           exists;
        DWORD          type;
        std::vector<BYTE> data;
    };
    std::vector<Case> cases = {
        { L"dword1800", true, REG_DWORD, Dword(1800) },
        { L"dwordmax", true, REG_DWORD, Dword(0xFFFFFFFF) },
        { L"qword", true, REG_QWORD, Qword(0x100000001ULL) },
        { L"string", true, REG_SZ, Sz(L"15 minutes, it's set") },
        { L"expand", true, REG_EXPAND_SZ, Sz(L"%SystemRoot%\\demo") },
        { L"multi", true, REG_MULTI_SZ, MultiSz({ L"a", L"", L"b c" }) },
        { L"multiempty", true, REG_MULTI_SZ, MultiSz({}) },
        { L"binary", true, REG_BINARY, { 0, 1, 0xFF, 0 } },
        { L"binaryempty", true, REG_BINARY, {} },
        { L"none", true, REG_NONE, { 9, 8 } },
        { L"absent", false, REG_NONE, {} },
    };
    std::vector<CheckInfo> catalog;
    for (const Case& c : cases) {
        std::wstring scenario = TestRootKey() + L"\\Types\\" + c.name;
        CheckInfo row = MovedRow(*screenlock, scenario, std::wstring(L"t.type.") + c.name);
        std::wstring sub = SubkeyOf(row.scriptRegistry[0].key);
        REQUIRE(SetRegValue(sub, L"KeepThis", REG_SZ, Sz(L"keep")));
        if (c.exists) REQUIRE(SetRegValue(sub, row.scriptRegistry[0].name, c.type, c.data));
        catalog.push_back(row);
    }
    // A key that did not exist: the fix creates it, the undo removes it again.
    const std::wstring noKeyScenario = TestRootKey() + L"\\Types\\nokey";
    catalog.push_back(MovedRow(*wsh, noKeyScenario, L"t.type.nokey"));
    REQUIRE(CreateRegKey(noKeyScenario + L"\\HKLM\\SOFTWARE\\Microsoft"));
    const std::wstring createdKey = SubkeyOf(catalog.back().scriptRegistry[0].key);
    REQUIRE(!KeyExists(createdKey));

    std::map<std::wstring, RegValue> before = Snapshot(TestRootKey());
    Plan plan = WritePlan(L"types", catalog);
    PsRunResult fixed = Run(plan.fixPath, Answers(catalog.size()));
    bool fixOk = fixed.exitCode == 0 && Contains(fixed.output, "Failed: 0.");
    CHECK(fixOk);
    PrintOnFailure(fixed, fixOk);

    // The fix turned every one into the DWORD 900 it sets, whatever type it had.
    for (size_t i = 0; i < cases.size(); ++i) {
        RegValue v;
        bool got = GetRegValue(SubkeyOf(catalog[i].scriptRegistry[0].key), catalog[i].scriptRegistry[0].name, v);
        if (!got || !(v == RegValue{ REG_DWORD, Dword(900) })) tf::Fail(__FILE__, __LINE__, "the fix did not set " + tf::Narrow(cases[i].name));
    }
    CHECK(KeyExists(createdKey));

    PsRunResult undone = Run(plan.undoPath, Answers(catalog.size()));
    bool undoOk = undone.exitCode == 0 &&
                  CountOf(undone.output, "Applied from the backup: the exact values from before the fix are back.") == catalog.size();
    CHECK(undoOk);
    PrintOnFailure(undone, undoOk);

    // Value by value: the same type and the same bytes (no %SystemRoot% expansion).
    for (size_t i = 0; i < cases.size(); ++i) {
        RegValue v;
        bool got = GetRegValue(SubkeyOf(catalog[i].scriptRegistry[0].key), catalog[i].scriptRegistry[0].name, v);
        std::string name = tf::Narrow(cases[i].name);
        if (!cases[i].exists) {
            if (got) tf::Fail(__FILE__, __LINE__, name + ": the value did not exist before and is still there");
            continue;
        }
        if (!got) tf::Fail(__FILE__, __LINE__, name + ": the value is gone");
        else if (!(v == RegValue{ cases[i].type, cases[i].data })) {
            tf::Fail(__FILE__, __LINE__, name + ": " + Describe(v) + ", expected " + Describe(RegValue{ cases[i].type, cases[i].data }));
        }
    }
    CHECK(!KeyExists(createdKey));
    CHECK(SameSnapshot(before, Snapshot(TestRootKey()), "after the undo"));
}

// ---------------------------------------------------------------------------
// No backup: -ListOnly, a skipped step and a missing file fall back to the catalog's
// undo commands, and each step says which one it used.
// ---------------------------------------------------------------------------
TEST(FixUndo_WithoutBackupFallsBackAndSaysSo)
{
    const CheckInfo* screenlock = FindCheckInfo(L"acct.screenlock");
    REQUIRE(screenlock != nullptr);
    KeyCleanup cleanup(TestRootKey());
    std::vector<CheckInfo> catalog = { MovedRow(*screenlock, TestRootKey() + L"\\Fallback\\A", L"t.a"),
                                       MovedRow(*screenlock, TestRootKey() + L"\\Fallback\\B", L"t.b") };
    const std::wstring keyA = SubkeyOf(catalog[0].scriptRegistry[0].key), keyB = SubkeyOf(catalog[1].scriptRegistry[0].key);
    const std::wstring name = catalog[0].scriptRegistry[0].name;
    REQUIRE(SetRegValue(keyA, name, REG_DWORD, Dword(1800)));
    REQUIRE(SetRegValue(keyB, name, REG_DWORD, Dword(1800)));
    Plan plan = WritePlan(L"fallback", catalog);

    // The fix, step A skipped, step B applied: only B is in the backup.
    PsRunResult fixed = Run(plan.fixPath, "n\r\ny\r\n");
    CHECK(Contains(fixed.output, "Applied: 1. Skipped: 1. Failed: 0."));
    REQUIRE(FileExists(plan.backupPath));
    std::wstring backupText;
    REQUIRE(ReadTextFile(plan.backupPath, backupText, 1024 * 1024));
    CHECK(Contains(backupText, L"\"t.b\""));
    CHECK(!Contains(backupText, L"\"t.a\""));

    // -ListOnly of the undo: says what each step would use, changes nothing.
    std::vector<uint8_t> backupBytes;
    REQUIRE(ReadBinaryFile(plan.backupPath, backupBytes, 1024 * 1024, nullptr));
    PsRunResult listed = Run(plan.undoPath, "y\r\ny\r\n", L"-ListOnly");
    CHECK_EQ(listed.exitCode, static_cast<DWORD>(0));
    CHECK(Contains(listed.output, "Backup: found. This step puts back the exact values from before the fix."));
    CHECK(Contains(listed.output, "Backup: none for this step"));
    CHECK(Contains(listed.output, "Without a backup it sets the Windows default with these commands:"));
    std::vector<uint8_t> backupAfterList;
    REQUIRE(ReadBinaryFile(plan.backupPath, backupAfterList, 1024 * 1024, nullptr));
    CHECK(backupAfterList == backupBytes);
    RegValue v;
    CHECK(GetRegValue(keyA, name, v) && v == (RegValue{ REG_DWORD, Dword(1800) }));
    CHECK(GetRegValue(keyB, name, v) && v == (RegValue{ REG_DWORD, Dword(900) }));

    // The undo, both y. Reverse order: B from the backup, then A with the default.
    PsRunResult undone = Run(plan.undoPath, "y\r\ny\r\n");
    bool ok = undone.exitCode == 0 && Contains(undone.output, "Applied: 2. Skipped: 0. Failed: 0.") &&
              CountOf(undone.output, "Applied from the backup: the exact values from before the fix are back.") == 1 &&
              CountOf(undone.output, "Applied with the Windows default: there is no backup for this step.") == 1;
    CHECK(ok);
    PrintOnFailure(undone, ok);
    CHECK(undone.output.find("Applied from the backup") < undone.output.find("Applied with the Windows default"));
    CHECK(GetRegValue(keyB, name, v) && v == (RegValue{ REG_DWORD, Dword(1800) }));   // exact
    CHECK(!GetRegValue(keyA, name, v));                                                 // the default: removed

    // Again: B was already put back and changes nothing (A answered n).
    PsRunResult again = Run(plan.undoPath, "y\r\nn\r\n");
    CHECK(Contains(again.output, "Nothing to do: these values were already put back from the backup."));
    CHECK(Contains(again.output, "Applied: 0. Skipped: 2. Failed: 0."));
    CHECK(GetRegValue(keyB, name, v) && v == (RegValue{ REG_DWORD, Dword(1800) }));

    // No backup file at all: the undo falls back for every step.
    REQUIRE(DeleteFileW(plan.backupPath.c_str()));
    REQUIRE(SetRegValue(keyB, name, REG_DWORD, Dword(900)));
    PsRunResult noFile = Run(plan.undoPath, "y\r\nn\r\n");
    CHECK(Contains(noFile.output, "Applied with the Windows default: there is no backup for this step."));
    CHECK(!Contains(noFile.output, "Applied from the backup"));
    CHECK(!GetRegValue(keyB, name, v));
}

// ---------------------------------------------------------------------------
// Running the fix twice keeps the values from before the first run; a key the fix
// created stays when something else is in it now; a changed backup cannot point the
// undo at anything its step does not declare.
// ---------------------------------------------------------------------------
TEST(FixUndo_RerunsKeptKeysAndTamperedBackup)
{
    const CheckInfo* screenlock = FindCheckInfo(L"acct.screenlock");
    const CheckInfo* wsh = FindCheckInfo(L"hard.wsh");
    REQUIRE(screenlock != nullptr && wsh != nullptr);
    KeyCleanup cleanup(TestRootKey());

    // Twice, and a created key that is not empty at undo time.
    std::vector<CheckInfo> catalog = { MovedRow(*screenlock, TestRootKey() + L"\\Twice", L"t.twice"),
                                       MovedRow(*wsh, TestRootKey() + L"\\Kept", L"t.kept") };
    const std::wstring twiceKey = SubkeyOf(catalog[0].scriptRegistry[0].key);
    const std::wstring twiceName = catalog[0].scriptRegistry[0].name;
    const std::wstring keptKey = SubkeyOf(catalog[1].scriptRegistry[0].key);
    REQUIRE(SetRegValue(twiceKey, twiceName, REG_DWORD, Dword(1800)));
    REQUIRE(CreateRegKey(TestRootKey() + L"\\Kept\\HKLM\\SOFTWARE"));
    REQUIRE(!KeyExists(keptKey));
    Plan plan = WritePlan(L"twice", catalog);

    PsRunResult first = Run(plan.fixPath, "y\r\ny\r\n");
    CHECK(Contains(first.output, "Applied: 2. Skipped: 0. Failed: 0."));
    REQUIRE(SetRegValue(twiceKey, twiceName, REG_DWORD, Dword(42)));
    PsRunResult second = Run(plan.fixPath, "y\r\nn\r\n");
    CHECK(Contains(second.output, "Backup: kept from an earlier run"));
    RegValue v;
    CHECK(GetRegValue(twiceKey, twiceName, v) && v == (RegValue{ REG_DWORD, Dword(900) }));
    REQUIRE(SetRegValue(keptKey, L"AddedLater", REG_SZ, Sz(L"someone else's value")));

    PsRunResult undone = Run(plan.undoPath, "y\r\ny\r\n");
    bool ok = Contains(undone.output, "Applied: 2. Skipped: 0. Failed: 0.");
    CHECK(ok);
    PrintOnFailure(undone, ok);
    CHECK(GetRegValue(twiceKey, twiceName, v) && v == (RegValue{ REG_DWORD, Dword(1800) }));   // before the first run
    CHECK(KeyExists(keptKey));                                                                  // not empty: kept
    CHECK(!GetRegValue(keptKey, catalog[1].scriptRegistry[0].name, v));                         // its own value removed
    CHECK(GetRegValue(keptKey, L"AddedLater", v));

    // After an undo the next fix takes a fresh backup.
    REQUIRE(SetRegValue(twiceKey, twiceName, REG_DWORD, Dword(77)));
    PsRunResult third = Run(plan.fixPath, "y\r\nn\r\n");
    CHECK(Contains(third.output, "Backup: 1 registry value(s) saved to "));
    PsRunResult undoThird = Run(plan.undoPath, "n\r\ny\r\n");
    CHECK(Contains(undoThird.output, "Applied from the backup"));
    CHECK(GetRegValue(twiceKey, twiceName, v) && v == (RegValue{ REG_DWORD, Dword(77) }));

    // A backup changed to name another key: the step stops before it writes anything.
    std::vector<CheckInfo> tamperCatalog = { MovedRow(*screenlock, TestRootKey() + L"\\Tamper", L"t.tamper") };
    const std::wstring tamperKey = SubkeyOf(tamperCatalog[0].scriptRegistry[0].key);
    const std::wstring victimKey = TestRootKey() + L"\\Victim";
    REQUIRE(SetRegValue(tamperKey, twiceName, REG_DWORD, Dword(1800)));
    REQUIRE(SetRegValue(victimKey, twiceName, REG_DWORD, Dword(5)));
    Plan tamper = WritePlan(L"tamper", tamperCatalog);
    PsRunResult tamperFix = Run(tamper.fixPath, "y\r\n");
    CHECK(Contains(tamperFix.output, "Applied: 1."));
    std::wstring json;
    REQUIRE(ReadTextFile(tamper.backupPath, json, 1024 * 1024));
    std::wstring jsonKey = ReplaceAllW(PsPathOf(tamperKey), L"\\", L"\\\\");
    REQUIRE(Contains(json, jsonKey));
    std::wstring changed = ReplaceAllW(json, jsonKey, ReplaceAllW(PsPathOf(victimKey), L"\\", L"\\\\"));
    REQUIRE(WriteUtf8File(tamper.backupPath, changed, false));
    PsRunResult tamperUndo = Run(tamper.undoPath, "y\r\n");
    CHECK_EQ(tamperUndo.exitCode, static_cast<DWORD>(1));
    CHECK(Contains(tamperUndo.output, "does not change, so nothing was put back"));
    CHECK(GetRegValue(victimKey, twiceName, v) && v == (RegValue{ REG_DWORD, Dword(5) }));
    CHECK(GetRegValue(tamperKey, twiceName, v) && v == (RegValue{ REG_DWORD, Dword(900) }));

    // A damaged backup file: the fix step stops before its commands run.
    REQUIRE(WriteUtf8File(tamper.backupPath, L"{ not json", false));
    REQUIRE(SetRegValue(tamperKey, twiceName, REG_DWORD, Dword(1800)));
    PsRunResult damaged = Run(tamper.fixPath, "y\r\n");
    CHECK(Contains(damaged.output, "cannot be read"));
    CHECK(Contains(damaged.output, "Failed: 1."));
    CHECK(GetRegValue(tamperKey, twiceName, v) && v == (RegValue{ REG_DWORD, Dword(1800) }));
}
