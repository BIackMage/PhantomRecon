#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "Baseline.h"
#include "CheckHelpers.h"
#include "DebugTrace.h"
#include "FileAnalysis.h"
#include "FileIO.h"
#include "HashUtils.h"
#include "RegUtil.h"
#include "ServiceUtil.h"
#include "SystemInfo.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <algorithm>
#include <map>
#include <set>
#include <sstream>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

static void DebugLog(const std::wstring& msg)
{
    Trace(L"Persistence", msg);
}

enum class Level { None = 0, Review = 1, High = 2 };

struct PersistenceEntry {
    std::wstring source;
    std::wstring location;
    std::wstring name;
    std::wstring command;
    std::wstring program;
    std::vector<std::wstring> reasons;
    Level        level = Level::None;
    bool         isNew = false;
    bool         microsoft = false;
};

static void Flag(PersistenceEntry& e, Level level, const std::wstring& why)
{
    e.reasons.push_back(why);
    if (static_cast<int>(level) > static_cast<int>(e.level)) e.level = level;
}

// Resolve the program, check its signature and location.
static void Inspect(PersistenceEntry& e)
{
    DebugLog(L"Inspect: " + e.source + L" | " + e.name + L" | " + e.command);
    if (e.program.empty() && !e.command.empty()) e.program = ProgramFromCommandLine(e.command);
    if (!e.program.empty() && e.program.find(L'\\') == std::wstring::npos) {
        wchar_t full[MAX_PATH] = {};
        if (SearchPathW(NULL, e.program.c_str(), L".exe", MAX_PATH, full, NULL)) e.program = full;
    }

    std::wstring why;
    int strength = e.command.empty() ? 0 : CommandLineSuspicion(e.command, &why);
    if (strength > 0) Flag(e, strength == 2 ? Level::High : Level::Review, why);

    if (e.program.empty() || e.program.find(L'\\') == std::wstring::npos) return;
    if (!FileExists(e.program)) {
        Flag(e, Level::Review, L"program file is missing");
        return;
    }
    if (IsUserDropLocation(e.program)) Flag(e, Level::High, L"program is in a user drop folder");

    SignatureSummary sig = GetSignatureSummary(e.program);
    e.microsoft = sig.microsoft;
    if (!sig.valid) {
        Flag(e, IsUnderWindowsDirectory(e.program) ? Level::High : Level::Review,
             L"not validly signed (" + sig.status + L")");
    }
}

// ---------------------------------------------------------------------------
// Collectors
// ---------------------------------------------------------------------------
static void CollectRunKeys(std::vector<PersistenceEntry>& out)
{
    struct Key { HKEY root; const wchar_t* path; REGSAM view; const wchar_t* label; };
    const Key keys[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_64KEY, L"Run (HKLM)" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_64KEY, L"RunOnce (HKLM)" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", KEY_WOW64_32KEY, L"Run (HKLM 32-bit)" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", KEY_WOW64_32KEY, L"RunOnce (HKLM 32-bit)" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, L"Run (HKCU)" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, L"RunOnce (HKCU)" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 0, L"Policy Run (HKLM)" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 0, L"Policy Run (HKCU)" },
    };
    for (const Key& k : keys) {
        for (const RegValue& v : RegEnumValues(k.root, k.path, k.view)) {
            if (v.type != REG_SZ && v.type != REG_EXPAND_SZ) continue;
            if (v.text.empty()) continue;
            PersistenceEntry e;
            e.source = k.label;
            e.location = RegRootName(k.root) + L"\\" + k.path;
            e.name = v.name;
            e.command = ExpandEnvironment(v.text);
            Inspect(e);
            if (StartsWithI(k.label, L"Policy")) Flag(e, Level::Review, L"set through a policy Run key, rarely used by normal software");
            out.push_back(e);
        }
    }
    // Legacy Load / Run values under Windows NT\CurrentVersion\Windows
    for (const wchar_t* value : { L"Load", L"Run" }) {
        std::wstring cmd = RegReadString(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", value);
        if (TrimW(cmd).empty()) continue;
        PersistenceEntry e;
        e.source = L"Legacy Windows Load/Run";
        e.location = L"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
        e.name = value;
        e.command = cmd;
        Inspect(e);
        Flag(e, Level::High, L"legacy autostart value, almost never used by current software");
        out.push_back(e);
    }
}

static std::wstring ResolveShortcut(const std::wstring& lnk, std::wstring& arguments)
{
    std::wstring target;
    IShellLinkW* link = NULL;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, reinterpret_cast<void**>(&link))) || !link) {
        return target;
    }
    IPersistFile* file = NULL;
    if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&file))) && file) {
        if (SUCCEEDED(file->Load(lnk.c_str(), STGM_READ))) {
            wchar_t path[MAX_PATH * 2] = {};
            if (SUCCEEDED(link->GetPath(path, MAX_PATH * 2, NULL, SLGP_RAWPATH))) target = ExpandEnvironment(path);
            wchar_t args[1024] = {};
            if (SUCCEEDED(link->GetArguments(args, 1024))) arguments = args;
        }
        file->Release();
    }
    link->Release();
    return target;
}

static void CollectStartupFolders(std::vector<PersistenceEntry>& out)
{
    struct Folder { int csidl; const wchar_t* label; };
    const Folder folders[] = { { CSIDL_STARTUP, L"Startup folder (user)" }, { CSIDL_COMMON_STARTUP, L"Startup folder (all users)" } };
    for (const Folder& f : folders) {
        wchar_t dir[MAX_PATH] = {};
        if (FAILED(SHGetFolderPathW(NULL, f.csidl, NULL, 0, dir))) continue;
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(JoinPath(dir, L"*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (EqualsI(fd.cFileName, L"desktop.ini")) continue;
            PersistenceEntry e;
            e.source = f.label;
            e.location = dir;
            e.name = fd.cFileName;
            std::wstring full = JoinPath(dir, fd.cFileName);
            if (ExtensionOf(full) == L".lnk") {
                std::wstring args;
                e.program = ResolveShortcut(full, args);
                e.command = e.program + (args.empty() ? L"" : L" " + args);
            }
            else {
                e.program = full;
                e.command = full;
                if (ExtensionOf(full) != L".url") Flag(e, Level::Review, L"a program or script placed directly in the Startup folder");
            }
            Inspect(e);
            out.push_back(e);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}

static void CollectWinlogon(std::vector<PersistenceEntry>& out)
{
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    std::wstring shell = TrimW(RegReadString(HKEY_LOCAL_MACHINE, key, L"Shell", false));
    if (!shell.empty() && !EqualsI(shell, L"explorer.exe")) {
        PersistenceEntry e;
        e.source = L"Winlogon";
        e.location = std::wstring(L"HKLM\\") + key;
        e.name = L"Shell";
        e.command = shell;
        Inspect(e);
        Flag(e, Level::High, L"Winlogon Shell is not explorer.exe");
        out.push_back(e);
    }
    std::wstring userShell = TrimW(RegReadString(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", false));
    if (!userShell.empty()) {
        PersistenceEntry e;
        e.source = L"Winlogon";
        e.location = L"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
        e.name = L"Shell";
        e.command = userShell;
        Inspect(e);
        Flag(e, Level::High, L"a per-user Winlogon Shell override");
        out.push_back(e);
    }
    std::wstring userinit = TrimW(RegReadString(HKEY_LOCAL_MACHINE, key, L"Userinit", false));
    std::wstring expected = ToLowerW(ExpandEnvironment(L"%SystemRoot%") + L"\\system32\\userinit.exe");
    std::vector<std::wstring> parts = SplitW(userinit, L',');
    bool unexpected = false;
    for (const std::wstring& p : parts) {
        std::wstring lower = ToLowerW(ExpandEnvironment(p));
        if (lower != expected && lower != L"userinit.exe" && lower != L"userinit") unexpected = true;
    }
    if (unexpected) {
        PersistenceEntry e;
        e.source = L"Winlogon";
        e.location = std::wstring(L"HKLM\\") + key;
        e.name = L"Userinit";
        e.command = userinit;
        Inspect(e);
        Flag(e, Level::High, L"Userinit starts something besides userinit.exe");
        out.push_back(e);
    }
}

static void CollectIfeo(std::vector<PersistenceEntry>& out)
{
    const std::wstring base = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    for (REGSAM view : { static_cast<REGSAM>(KEY_WOW64_64KEY), static_cast<REGSAM>(KEY_WOW64_32KEY) }) {
        for (const std::wstring& exe : RegEnumSubKeys(HKEY_LOCAL_MACHINE, base, view)) {
            std::wstring debugger = RegReadString(HKEY_LOCAL_MACHINE, base + L"\\" + exe, L"Debugger", true, view);
            if (TrimW(debugger).empty()) continue;
            PersistenceEntry e;
            e.source = L"Image File Execution Options";
            e.location = L"HKLM\\" + base + L"\\" + exe;
            e.name = exe;
            e.command = debugger;
            Inspect(e);
            Flag(e, Level::High, L"starting " + exe + L" runs this program instead");
            out.push_back(e);
        }
    }
    const std::wstring silent = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";
    for (const std::wstring& exe : RegEnumSubKeys(HKEY_LOCAL_MACHINE, silent)) {
        std::wstring monitor = RegReadString(HKEY_LOCAL_MACHINE, silent + L"\\" + exe, L"MonitorProcess");
        if (TrimW(monitor).empty()) continue;
        PersistenceEntry e;
        e.source = L"Silent Process Exit";
        e.location = L"HKLM\\" + silent + L"\\" + exe;
        e.name = exe;
        e.command = monitor;
        Inspect(e);
        Flag(e, Level::High, L"runs this program whenever " + exe + L" exits");
        out.push_back(e);
    }
}

static void CollectAppInit(std::vector<PersistenceEntry>& out)
{
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    for (REGSAM view : { static_cast<REGSAM>(KEY_WOW64_64KEY), static_cast<REGSAM>(KEY_WOW64_32KEY) }) {
        std::wstring dlls = TrimW(RegReadString(HKEY_LOCAL_MACHINE, key, L"AppInit_DLLs", true, view));
        if (dlls.empty()) continue;
        DWORD load = 0;
        RegReadDword(HKEY_LOCAL_MACHINE, key, L"LoadAppInit_DLLs", load, view);
        for (const std::wstring& dll : SplitAppInitList(dlls)) {
            PersistenceEntry e;
            e.source = view == KEY_WOW64_32KEY ? L"AppInit DLLs (32-bit)" : L"AppInit DLLs";
            e.location = std::wstring(L"HKLM\\") + key;
            e.name = L"AppInit_DLLs";
            e.program = dll;
            e.command = dll;
            Inspect(e);
            Flag(e, load == 1 ? Level::High : Level::Review,
                 load == 1 ? L"loaded into every program that uses user32.dll" : L"listed, but LoadAppInit_DLLs is off");
            out.push_back(e);
        }
    }
}

static void CollectWmi(std::vector<PersistenceEntry>& out)
{
    WmiResult cmd = WmiQuery(L"ROOT\\subscription", L"SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer",
        { L"Name", L"CommandLineTemplate", L"ExecutablePath" });
    for (const WmiRow& row : cmd.rows) {
        PersistenceEntry e;
        e.source = L"WMI event consumer (command line)";
        e.location = L"ROOT\\subscription";
        e.name = row.count(L"Name") ? row.at(L"Name") : L"";
        e.command = row.count(L"CommandLineTemplate") ? row.at(L"CommandLineTemplate") : L"";
        if (row.count(L"ExecutablePath")) e.program = row.at(L"ExecutablePath");
        Inspect(e);
        Flag(e, Level::High, L"WMI runs this command when an event fires");
        out.push_back(e);
    }
    WmiResult script = WmiQuery(L"ROOT\\subscription", L"SELECT Name, ScriptingEngine, ScriptFileName, ScriptText FROM ActiveScriptEventConsumer",
        { L"Name", L"ScriptingEngine", L"ScriptFileName", L"ScriptText" });
    for (const WmiRow& row : script.rows) {
        PersistenceEntry e;
        e.source = L"WMI event consumer (script)";
        e.location = L"ROOT\\subscription";
        e.name = row.count(L"Name") ? row.at(L"Name") : L"";
        std::wstring text = row.count(L"ScriptText") ? row.at(L"ScriptText") : L"";
        e.command = row.count(L"ScriptFileName") && !row.at(L"ScriptFileName").empty() ? row.at(L"ScriptFileName")
                                                                                         : text.substr(0, 200);
        Flag(e, Level::High, L"WMI runs this script when an event fires");
        out.push_back(e);
    }
}

static void CollectLsa(std::vector<PersistenceEntry>& out)
{
    const wchar_t* lsa = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
    std::wstring system32 = ExpandEnvironment(L"%SystemRoot%\\System32\\");
    struct Source { const wchar_t* key; const wchar_t* value; };
    const Source sources[] = {
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages" },
        { L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", L"Security Packages" },
    };
    (void)lsa;
    for (const Source& s : sources) {
        for (const std::wstring& name : RegReadMultiString(HKEY_LOCAL_MACHINE, s.key, s.value)) {
            if (IsExpectedLsaPackage(s.value, name)) continue;
            PersistenceEntry e;
            e.source = std::wstring(L"LSA ") + s.value;
            e.location = std::wstring(L"HKLM\\") + s.key;
            e.name = name;
            std::wstring dll = name;
            if (ExtensionOf(dll) != L".dll") dll += L".dll";
            e.program = system32 + dll;
            e.command = e.program;
            Inspect(e);
            Flag(e, e.microsoft ? Level::Review : Level::High, L"not a standard Windows LSA package; it would see every password typed");
            out.push_back(e);
        }
    }
}

static void CollectPrintMonitors(std::vector<PersistenceEntry>& out)
{
    const std::wstring base = L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors";
    std::wstring system32 = ExpandEnvironment(L"%SystemRoot%\\System32\\");
    for (const std::wstring& monitor : RegEnumSubKeys(HKEY_LOCAL_MACHINE, base)) {
        std::wstring driver = RegReadString(HKEY_LOCAL_MACHINE, base + L"\\" + monitor, L"Driver");
        if (driver.empty()) continue;
        PersistenceEntry e;
        e.source = L"Print monitor";
        e.location = L"HKLM\\" + base + L"\\" + monitor;
        e.name = monitor;
        e.program = driver.find(L'\\') == std::wstring::npos ? system32 + driver : driver;
        e.command = e.program;
        Inspect(e);
        if (!e.microsoft) {
            // Printer vendors often ship unsigned port monitors. Worth a look, not an alarm.
            if (e.level == Level::High && e.reasons.size() == 1 && e.reasons[0].rfind(L"not validly signed", 0) == 0) {
                e.level = Level::Review;
            }
            Flag(e, Level::Review, L"third-party print monitor DLL loaded by the spooler (SYSTEM)");
        }
        out.push_back(e);
    }
}

static std::wstring ComServerPath(HKEY root, const std::wstring& clsidKeyBase, const std::wstring& clsid)
{
    std::wstring dll = RegReadString(root, clsidKeyBase + L"\\" + clsid + L"\\InprocServer32", L"");
    if (dll.empty()) dll = RegReadString(root, clsidKeyBase + L"\\" + clsid + L"\\LocalServer32", L"");
    return TrimW(dll);
}

static void CollectShellExtensions(std::vector<PersistenceEntry>& out)
{
    const wchar_t* approved = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved";
    for (const RegValue& v : RegEnumValues(HKEY_LOCAL_MACHINE, approved)) {
        if (v.name.empty() || v.name[0] != L'{') continue;
        std::wstring dll = ComServerPath(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", v.name);
        if (dll.empty()) continue;
        PersistenceEntry e;
        e.source = L"Explorer shell extension";
        e.location = std::wstring(L"HKLM\\") + approved;
        e.name = v.text.empty() ? v.name : v.text + L" " + v.name;
        e.command = dll;
        e.program = ProgramFromCommandLine(dll);
        Inspect(e);
        out.push_back(e);
    }
}

static void CollectComHijacks(std::vector<PersistenceEntry>& out)
{
    const std::wstring userBase = L"Software\\Classes\\CLSID";
    for (const std::wstring& clsid : RegEnumSubKeys(HKEY_CURRENT_USER, userBase)) {
        std::wstring server = ComServerPath(HKEY_CURRENT_USER, userBase, clsid);
        bool hasServerKey = RegKeyExists(HKEY_CURRENT_USER, userBase + L"\\" + clsid + L"\\InprocServer32") ||
                            RegKeyExists(HKEY_CURRENT_USER, userBase + L"\\" + clsid + L"\\LocalServer32");
        if (!hasServerKey) continue;
        bool overridesMachine = RegKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\InprocServer32") ||
                                RegKeyExists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\LocalServer32");
        if (server.empty() || server == L"-") {
            // A blank per-user override switches a system component off for this
            // user. The best-known case is the Windows 11 "classic right-click menu"
            // tweak. It runs nothing, so it is listed, not alarmed.
            if (overridesMachine) {
                PersistenceEntry e;
                e.source = L"Blank COM override";
                e.location = L"HKCU\\" + userBase + L"\\" + clsid;
                e.name = clsid;
                Flag(e, Level::Review, L"turns off the system's " +
                     ComServerPath(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", clsid) +
                     L" for this user (often the Windows 11 classic context menu tweak)");
                out.push_back(e);
            }
            continue;
        }
        PersistenceEntry e;
        e.source = overridesMachine ? L"COM registration overriding the system" : L"Per-user COM registration";
        e.location = L"HKCU\\" + userBase + L"\\" + clsid;
        e.name = clsid;
        e.command = server;
        e.program = ProgramFromCommandLine(server);
        Inspect(e);
        if (overridesMachine) {
            std::wstring machineServer = ComServerPath(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", clsid);
            if (!EqualsI(ExpandEnvironment(machineServer), ExpandEnvironment(server))) {
                Flag(e, Level::High, L"replaces the system's " + machineServer + L" for this user (COM hijack pattern)");
            }
        }
        out.push_back(e);
    }
}

static void CollectOfficeAddins(std::vector<PersistenceEntry>& out)
{
    const wchar_t* apps[] = { L"Word", L"Excel", L"PowerPoint", L"Outlook" };
    struct Hive { HKEY root; REGSAM view; const wchar_t* label; };
    const Hive hives[] = { { HKEY_CURRENT_USER, 0, L"HKCU" }, { HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, L"HKLM" },
                           { HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, L"HKLM 32-bit" } };
    for (const wchar_t* app : apps) {
        for (const Hive& h : hives) {
            std::wstring base = std::wstring(L"Software\\Microsoft\\Office\\") + app + L"\\Addins";
            for (const std::wstring& progId : RegEnumSubKeys(h.root, base, h.view)) {
                DWORD load = 0;
                RegReadDword(h.root, base + L"\\" + progId, L"LoadBehavior", load, h.view);
                if ((load & 1) == 0 && load != 0) continue;   // not set to load
                std::wstring manifest = RegReadString(h.root, base + L"\\" + progId, L"Manifest", true, h.view);
                std::wstring friendly = RegReadString(h.root, base + L"\\" + progId, L"FriendlyName", true, h.view);
                PersistenceEntry e;
                e.source = std::wstring(L"Office add-in (") + app + L")";
                e.location = std::wstring(h.label) + L"\\" + base;
                e.name = friendly.empty() ? progId : friendly + L" (" + progId + L")";
                if (!manifest.empty()) {
                    std::wstring path = manifest;
                    size_t bar = path.find(L'|');
                    if (bar != std::wstring::npos) path = path.substr(0, bar);
                    if (StartsWithI(path, L"file:///")) path = ReplaceAllW(path.substr(8), L"/", L"\\");
                    e.program = path;
                    e.command = manifest;
                }
                else {
                    std::wstring clsid = RegReadString(HKEY_CLASSES_ROOT, progId + L"\\CLSID", L"");
                    if (!clsid.empty()) e.command = ComServerPath(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID", clsid);
                    if (e.command.empty() && !clsid.empty()) e.command = ComServerPath(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", clsid);
                    e.program = ProgramFromCommandLine(e.command);
                }
                Inspect(e);
                out.push_back(e);
            }
        }
    }
    // Startup folders that Office loads templates and add-ins from automatically
    std::wstring appdata = ExpandEnvironment(L"%APPDATA%");
    const std::wstring folders[] = { appdata + L"\\Microsoft\\Word\\STARTUP", appdata + L"\\Microsoft\\Excel\\XLSTART" };
    for (const std::wstring& dir : folders) {
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(JoinPath(dir, L"*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            PersistenceEntry e;
            e.source = L"Office startup folder";
            e.location = dir;
            e.name = fd.cFileName;
            e.command = JoinPath(dir, fd.cFileName);
            Flag(e, Level::Review, L"Office opens this file every time it starts (template macros)");
            out.push_back(e);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}

static std::wstring JsonStringValue(const std::wstring& json, const std::wstring& key, size_t from = 0)
{
    std::wstring needle = L"\"" + key + L"\"";
    size_t k = json.find(needle, from);
    if (k == std::wstring::npos) return L"";
    size_t colon = json.find(L':', k + needle.size());
    if (colon == std::wstring::npos) return L"";
    size_t q1 = json.find(L'"', colon + 1);
    if (q1 == std::wstring::npos) return L"";
    std::wstring value;
    for (size_t i = q1 + 1; i < json.size(); ++i) {
        if (json[i] == L'\\' && i + 1 < json.size()) { value += json[++i]; continue; }
        if (json[i] == L'"') break;
        value += json[i];
    }
    return value;
}

static void CollectChromiumExtensions(const std::wstring& browser, const std::wstring& userData, std::vector<PersistenceEntry>& out)
{
    if (!DirectoryExists(userData)) return;
    WIN32_FIND_DATAW pd = {};
    HANDLE hp = FindFirstFileW(JoinPath(userData, L"*").c_str(), &pd);
    if (hp == INVALID_HANDLE_VALUE) return;
    do {
        if (!(pd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        std::wstring profile = pd.cFileName;
        if (profile != L"Default" && profile.rfind(L"Profile ", 0) != 0) continue;
        std::wstring extDir = JoinPath(JoinPath(userData, profile), L"Extensions");
        WIN32_FIND_DATAW ed = {};
        HANDLE he = FindFirstFileW(JoinPath(extDir, L"*").c_str(), &ed);
        if (he == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(ed.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || ed.cFileName[0] == L'.') continue;
            std::wstring id = ed.cFileName;
            std::wstring idDir = JoinPath(extDir, id);
            WIN32_FIND_DATAW vd = {};
            HANDLE hv = FindFirstFileW(JoinPath(idDir, L"*").c_str(), &vd);
            if (hv == INVALID_HANDLE_VALUE) continue;
            std::wstring versionDir;
            do {
                if ((vd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && vd.cFileName[0] != L'.') versionDir = JoinPath(idDir, vd.cFileName);
            } while (FindNextFileW(hv, &vd));
            FindClose(hv);
            if (versionDir.empty()) continue;
            std::wstring manifest;
            if (!ReadTextFile(JoinPath(versionDir, L"manifest.json"), manifest, 512 * 1024)) continue;
            std::wstring name = JsonStringValue(manifest, L"name");
            if (name.rfind(L"__MSG_", 0) == 0) {
                std::wstring key = name.substr(6);
                if (!key.empty() && key.back() == L'_') {
                    key.pop_back();
                    key.pop_back();
                }
                std::wstring messages;
                if (ReadTextFile(JoinPath(versionDir, L"_locales\\en\\messages.json"), messages, 512 * 1024) ||
                    ReadTextFile(JoinPath(versionDir, L"_locales\\en_US\\messages.json"), messages, 512 * 1024)) {
                    size_t k = ToLowerW(messages).find(L"\"" + ToLowerW(key) + L"\"");
                    if (k != std::wstring::npos) name = JsonStringValue(messages, L"message", k);
                }
            }
            PersistenceEntry e;
            e.source = browser + L" extension";
            e.location = extDir;
            e.name = (name.empty() ? id : name) + L" [" + id + L"] (" + profile + L")";
            out.push_back(e);
        } while (FindNextFileW(he, &ed));
        FindClose(he);
    } while (FindNextFileW(hp, &pd));
    FindClose(hp);
}

static void CollectBrowserExtensions(std::vector<PersistenceEntry>& out)
{
    std::wstring local = ExpandEnvironment(L"%LOCALAPPDATA%");
    CollectChromiumExtensions(L"Chrome", local + L"\\Google\\Chrome\\User Data", out);
    CollectChromiumExtensions(L"Edge", local + L"\\Microsoft\\Edge\\User Data", out);
    CollectChromiumExtensions(L"Brave", local + L"\\BraveSoftware\\Brave-Browser\\User Data", out);

    std::wstring profiles = ExpandEnvironment(L"%APPDATA%\\Mozilla\\Firefox\\Profiles");
    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW(JoinPath(profiles, L"*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == L'.') continue;
            std::wstring json;
            if (!ReadTextFile(JoinPath(JoinPath(profiles, fd.cFileName), L"extensions.json"), json, 8 * 1024 * 1024)) continue;
            size_t pos = 0;
            while ((pos = json.find(L"\"defaultLocale\"", pos)) != std::wstring::npos) {
                std::wstring name = JsonStringValue(json, L"name", pos);
                pos += 15;
                if (name.empty()) continue;
                PersistenceEntry e;
                e.source = L"Firefox extension";
                e.location = JoinPath(profiles, fd.cFileName);
                e.name = name;
                out.push_back(e);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }

    // Extensions forced in by policy. Companies do this on purpose; adware does it too.
    bool domainJoined = !GetJoinedDomainName().empty();
    struct Policy { HKEY root; const wchar_t* key; const wchar_t* browser; };
    const Policy policies[] = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist", L"Chrome" },
        { HKEY_CURRENT_USER,  L"Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist", L"Chrome" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist", L"Edge" },
        { HKEY_CURRENT_USER,  L"Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist", L"Edge" },
    };
    for (const Policy& p : policies) {
        for (const RegValue& v : RegEnumValues(p.root, p.key)) {
            PersistenceEntry e;
            e.source = std::wstring(p.browser) + L" forced extension (policy)";
            e.location = RegRootName(p.root) + L"\\" + p.key;
            e.name = v.text;
            Flag(e, domainJoined ? Level::Review : Level::High,
                 domainJoined ? L"installed by policy (normal for company PCs)" : L"forced in by policy on a PC no company manages");
            out.push_back(e);
        }
    }
}

static void CollectServices(std::vector<PersistenceEntry>& out)
{
    std::wstring error;
    for (const ServiceInfo& s : EnumerateServices(&error)) {
        if (s.startType == SERVICE_DISABLED || s.exePath.empty()) continue;
        if (!(s.serviceType & SERVICE_WIN32_OWN_PROCESS)) continue;   // shared svchost services are Windows'
        if (IsUnderWindowsDirectory(s.exePath)) continue;
        PersistenceEntry e;
        e.source = L"Service";
        e.location = L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\" + s.name;
        e.name = s.name + (s.displayName.empty() ? L"" : L" (" + s.displayName + L")");
        e.command = s.binaryPathRaw;
        e.program = s.exePath;
        Inspect(e);
        out.push_back(e);
    }
}

// ---------------------------------------------------------------------------
// Snapshot of entries between audits
// ---------------------------------------------------------------------------
static std::wstring SnapshotKey(const PersistenceEntry& e)
{
    return ToLowerW(e.source + L"|" + e.name + L"|" + e.command);
}

static std::set<std::wstring> LoadSnapshot(const std::wstring& path, bool& existed)
{
    std::set<std::wstring> keys;
    std::wstring text;
    existed = ReadTextFile(path, text);
    if (!existed) return keys;
    for (const std::wstring& line : SplitW(text, L'\n')) {
        if (!line.empty() && line[0] != L'#') keys.insert(line);
    }
    return keys;
}

static void SaveSnapshot(const std::wstring& path, const std::vector<PersistenceEntry>& entries)
{
    std::wstring text = L"# Phantom Recon autostart snapshot. One entry per line.\n";
    for (const PersistenceEntry& e : entries) text += SnapshotKey(e) + L"\n";
    WriteUtf8File(path, text);
}

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------
SecurityCheckResult CheckPersistence(const AuditContext& context)
{
    SecurityCheckResult result = MakeCheckResult(L"persist.sweep");
    ComScope com;

    std::vector<PersistenceEntry> entries;
    DebugLog(L"CollectRunKeys");
    CollectRunKeys(entries);
    DebugLog(L"CollectStartupFolders");
    CollectStartupFolders(entries);
    DebugLog(L"CollectWinlogon");
    CollectWinlogon(entries);
    DebugLog(L"CollectIfeo");
    CollectIfeo(entries);
    DebugLog(L"CollectAppInit");
    CollectAppInit(entries);
    DebugLog(L"CollectWmi");
    CollectWmi(entries);
    DebugLog(L"CollectLsa");
    CollectLsa(entries);
    DebugLog(L"CollectPrintMonitors");
    CollectPrintMonitors(entries);
    DebugLog(L"CollectShellExtensions");
    CollectShellExtensions(entries);
    DebugLog(L"CollectComHijacks");
    CollectComHijacks(entries);
    DebugLog(L"CollectOfficeAddins");
    CollectOfficeAddins(entries);
    DebugLog(L"CollectBrowserExtensions");
    CollectBrowserExtensions(entries);
    DebugLog(L"CollectServices");
    CollectServices(entries);
    DebugLog(L"Collected " + std::to_wstring(entries.size()) + L" autostart entries");

    std::wstring snapshotPath = context.snapshotPath.empty() ? AppFilePath(L"phantom_recon_persistence.snapshot") : context.snapshotPath;
    bool hadSnapshot = false;
    std::set<std::wstring> previous = LoadSnapshot(snapshotPath, hadSnapshot);
    int newCount = 0;
    for (PersistenceEntry& e : entries) {
        if (hadSnapshot && previous.count(SnapshotKey(e)) == 0) {
            e.isNew = true;
            newCount++;
            Flag(e, Level::Review, L"NEW since the last audit");
        }
        if (context.baseline && !e.program.empty() && FileExists(e.program)) {
            const BaselineEntry* b = context.baseline->FindEntry(e.program);
            if (!b) {
                if (!e.microsoft) Flag(e, Level::Review, L"program is not in the baseline");
            }
            else {
                std::wstring sha = ComputeFileSHA256(ToExtendedPath(e.program));
                if (!sha.empty() && !b->sha256.empty() && !EqualsI(sha, b->sha256)) {
                    Flag(e, e.microsoft ? Level::Review : Level::High, L"program changed since the baseline");
                }
            }
        }
    }
    SaveSnapshot(snapshotPath, entries);

    // Report
    std::map<std::wstring, int> perSource;
    std::wstringstream flagged;
    std::wstringstream inventory;
    int high = 0, review = 0;
    for (const PersistenceEntry& e : entries) {
        perSource[e.source]++;
        std::wstring line = L"  " + e.source + L": " + e.name + (e.command.empty() ? L"" : L"\n      " + e.command);
        if (e.level == Level::High) {
            high++;
            flagged << L"  [HIGH] " << line.substr(2) << L"\n      why: " << JoinW(e.reasons, L"; ") << L"\n";
        }
        else if (e.level == Level::Review) {
            review++;
            flagged << L"  [REVIEW] " << line.substr(2) << L"\n      why: " << JoinW(e.reasons, L"; ") << L"\n";
        }
        else if (!e.microsoft) {
            inventory << line << L"\n";
        }
    }

    std::wstringstream detail;
    detail << entries.size() << L" autostart entries in " << perSource.size() << L" kinds of location";
    if (hadSnapshot) detail << L"; " << newCount << L" new since the last audit";
    else detail << L"; first audit, so nothing is marked new yet";
    if (context.baseline) detail << L"; programs cross-checked against the baseline";
    detail << L".\n";
    if (high + review > 0) detail << L"Flagged:\n" << flagged.str();
    detail << L"Counts:\n";
    for (const auto& pair : perSource) detail << L"  " << pair.first << L": " << pair.second << L"\n";
    std::wstring inv = inventory.str();
    if (!inv.empty()) detail << L"Other entries (not signed by Microsoft):\n" << inv;

    result.status = high > 0 ? CHECK_FAIL : (review > 0 ? CHECK_WARNING : CHECK_PASS);
    result.detail = detail.str();
    return result;
}
