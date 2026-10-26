#include "pch.h"
#include "SecurityCheckModules.h"

#include "AppPaths.h"
#include "CheckHelpers.h"
#include "FileAnalysis.h"
#include "FileIO.h"
#include "RegUtil.h"
#include "TextUtils.h"
#include "WmiQuery.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netfw.h>
#include <algorithm>
#include <map>
#include <set>
#include <sstream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ---------------------------------------------------------------------------
// Listening programs
// ---------------------------------------------------------------------------
struct Listener {
    std::wstring protocol;   // TCP, TCPv6, UDP, UDPv6
    std::wstring address;
    unsigned     port = 0;
    DWORD        pid = 0;
};

static std::wstring ImageOfPid(DWORD pid)
{
    if (pid == 0) return L"System Idle";
    if (pid == 4) return L"System";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";
    wchar_t path[MAX_PATH * 2] = {};
    DWORD size = MAX_PATH * 2;
    std::wstring out;
    if (QueryFullProcessImageNameW(h, 0, path, &size)) out = path;
    CloseHandle(h);
    return out;
}

static std::wstring AddressText(int family, const void* addr)
{
    wchar_t buf[64] = {};
    InetNtopW(family, addr, buf, 64);
    return buf;
}

static std::vector<Listener> ReadListeners()
{
    std::vector<Listener> out;
    auto tcp = [&](ULONG family) {
        DWORD size = 0;
        GetExtendedTcpTable(NULL, &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
        std::vector<BYTE> buffer(size + 1024);
        size = static_cast<DWORD>(buffer.size());
        if (GetExtendedTcpTable(buffer.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR) return;
        if (family == AF_INET) {
            MIB_TCPTABLE_OWNER_PID* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                Listener l;
                l.protocol = L"TCP";
                IN_ADDR a;
                a.S_un.S_addr = t->table[i].dwLocalAddr;
                l.address = AddressText(AF_INET, &a);
                l.port = ntohs(static_cast<u_short>(t->table[i].dwLocalPort));
                l.pid = t->table[i].dwOwningPid;
                out.push_back(l);
            }
        }
        else {
            MIB_TCP6TABLE_OWNER_PID* t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                Listener l;
                l.protocol = L"TCPv6";
                l.address = AddressText(AF_INET6, t->table[i].ucLocalAddr);
                l.port = ntohs(static_cast<u_short>(t->table[i].dwLocalPort));
                l.pid = t->table[i].dwOwningPid;
                out.push_back(l);
            }
        }
    };
    auto udp = [&](ULONG family) {
        DWORD size = 0;
        GetExtendedUdpTable(NULL, &size, FALSE, family, UDP_TABLE_OWNER_PID, 0);
        std::vector<BYTE> buffer(size + 1024);
        size = static_cast<DWORD>(buffer.size());
        if (GetExtendedUdpTable(buffer.data(), &size, FALSE, family, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) return;
        if (family == AF_INET) {
            MIB_UDPTABLE_OWNER_PID* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                Listener l;
                l.protocol = L"UDP";
                IN_ADDR a;
                a.S_un.S_addr = t->table[i].dwLocalAddr;
                l.address = AddressText(AF_INET, &a);
                l.port = ntohs(static_cast<u_short>(t->table[i].dwLocalPort));
                l.pid = t->table[i].dwOwningPid;
                out.push_back(l);
            }
        }
        else {
            MIB_UDP6TABLE_OWNER_PID* t = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                Listener l;
                l.protocol = L"UDPv6";
                l.address = AddressText(AF_INET6, t->table[i].ucLocalAddr);
                l.port = ntohs(static_cast<u_short>(t->table[i].dwLocalPort));
                l.pid = t->table[i].dwOwningPid;
                out.push_back(l);
            }
        }
    };
    tcp(AF_INET);
    tcp(AF_INET6);
    udp(AF_INET);
    udp(AF_INET6);
    return out;
}

static bool IsLoopbackListener(const std::wstring& address)
{
    return address.rfind(L"127.", 0) == 0 || address == L"::1";
}

// Inbound allow rules: program paths (lowercase, expanded) and port specs.
struct InboundRules {
    std::set<std::wstring> programs;
    std::vector<std::wstring> ports;   // "*" or "80,443" or "5000-5100"
    bool loaded = false;
};

static InboundRules ReadInboundAllowRules()
{
    InboundRules out;
    ComScope com;
    INetFwPolicy2* policy = NULL;
    if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(&policy))) || !policy) return out;
    INetFwRules* rules = NULL;
    if (SUCCEEDED(policy->get_Rules(&rules)) && rules) {
        IUnknown* enumUnknown = NULL;
        if (SUCCEEDED(rules->get__NewEnum(&enumUnknown)) && enumUnknown) {
            IEnumVARIANT* e = NULL;
            if (SUCCEEDED(enumUnknown->QueryInterface(__uuidof(IEnumVARIANT), reinterpret_cast<void**>(&e))) && e) {
                VARIANT v;
                VariantInit(&v);
                ULONG fetched = 0;
                while (e->Next(1, &v, &fetched) == S_OK && fetched == 1) {
                    INetFwRule* rule = NULL;
                    if (v.vt == VT_DISPATCH && v.pdispVal &&
                        SUCCEEDED(v.pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&rule))) && rule) {
                        VARIANT_BOOL enabled = VARIANT_FALSE;
                        NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_OUT;
                        NET_FW_ACTION act = NET_FW_ACTION_BLOCK;
                        rule->get_Enabled(&enabled);
                        rule->get_Direction(&dir);
                        rule->get_Action(&act);
                        if (enabled == VARIANT_TRUE && dir == NET_FW_RULE_DIR_IN && act == NET_FW_ACTION_ALLOW) {
                            BSTR app = NULL;
                            if (SUCCEEDED(rule->get_ApplicationName(&app)) && app) {
                                out.programs.insert(ToLowerW(ExpandEnvironment(std::wstring(app, SysStringLen(app)))));
                                SysFreeString(app);
                            }
                            BSTR ports = NULL;
                            if (SUCCEEDED(rule->get_LocalPorts(&ports)) && ports) {
                                out.ports.push_back(std::wstring(ports, SysStringLen(ports)));
                                SysFreeString(ports);
                            }
                        }
                        rule->Release();
                    }
                    VariantClear(&v);
                }
                e->Release();
            }
            enumUnknown->Release();
        }
        rules->Release();
    }
    policy->Release();
    out.loaded = true;
    return out;
}

static bool PortAllowed(const InboundRules& rules, unsigned port)
{
    for (const std::wstring& spec : rules.ports) {
        for (const std::wstring& part : SplitW(spec, L',')) {
            if (part == L"*") continue;   // "any port" rules are tied to a program, handled separately
            size_t dash = part.find(L'-');
            if (dash != std::wstring::npos) {
                unsigned lo = static_cast<unsigned>(_wtoi(part.substr(0, dash).c_str()));
                unsigned hi = static_cast<unsigned>(_wtoi(part.substr(dash + 1).c_str()));
                if (port >= lo && port <= hi) return true;
            }
            else if (static_cast<unsigned>(_wtoi(part.c_str())) == port && !part.empty() && iswdigit(part[0])) {
                return true;
            }
        }
    }
    return false;
}

SecurityCheckResult CheckListeningPorts()
{
    SecurityCheckResult result = MakeCheckResult(L"net.listening");
    std::vector<Listener> listeners = ReadListeners();
    InboundRules rules = ReadInboundAllowRules();

    // Group by program
    struct Group {
        std::wstring image;
        std::set<std::wstring> endpoints;
        bool external = false;
        std::set<DWORD> pids;
    };
    std::map<std::wstring, Group> groups;
    int unknownOwner = 0;
    for (const Listener& l : listeners) {
        std::wstring image = ImageOfPid(l.pid);
        if (image.empty()) {
            unknownOwner++;
            image = L"(pid " + std::to_wstring(l.pid) + L", not accessible)";
        }
        Group& g = groups[ToLowerW(image)];
        g.image = image;
        g.pids.insert(l.pid);
        g.endpoints.insert(l.protocol + L" " + l.address + L":" + std::to_wstring(l.port));
        if (!IsLoopbackListener(l.address)) g.external = true;
    }

    std::wstringstream flagged;
    std::wstringstream inventory;
    int fail = 0, warn = 0;
    for (auto& pair : groups) {
        Group& g = pair.second;
        if (!g.external) continue;
        bool hasPath = g.image.find(L'\\') != std::wstring::npos;
        bool windowsBinary = hasPath && IsProtectedWindowsPath(g.image);
        SignatureSummary sig;
        if (hasPath) sig = GetSignatureSummary(g.image);
        bool appRule = hasPath && rules.programs.count(ToLowerW(g.image)) > 0;
        bool portRule = false;
        for (const std::wstring& ep : g.endpoints) {
            size_t colon = ep.find_last_of(L':');
            unsigned port = static_cast<unsigned>(_wtoi(ep.substr(colon + 1).c_str()));
            if (PortAllowed(rules, port)) portRule = true;
        }

        std::wstring line = L"  " + g.image + L"\n      " + JoinW(std::vector<std::wstring>(g.endpoints.begin(), g.endpoints.end()), L", ");
        if (hasPath) line += L"\n      signature: " + sig.status + (sig.signer.empty() ? L"" : L" (" + sig.signer + L")");
        if (rules.loaded) line += std::wstring(L"\n      firewall: ") + (appRule ? L"inbound allowed for this program" :
            portRule ? L"inbound allowed for its port" : L"no inbound allow rule");
        line += L"\n";

        if (hasPath && (IsUserDropLocation(g.image) || (!sig.valid && !windowsBinary))) {
            fail++;
            flagged << L"  [HIGH] " << line.substr(2);
        }
        else if (hasPath && !windowsBinary && (appRule || portRule)) {
            warn++;
            flagged << L"  [REVIEW] " << line.substr(2);
        }
        else {
            inventory << line;
        }
    }

    std::wstringstream detail;
    detail << listeners.size() << L" listening socket(s) in " << groups.size() << L" program(s)";
    if (unknownOwner > 0) detail << L"; " << unknownOwner << L" belong to processes only an administrator can see";
    detail << L".\n";
    if (fail + warn > 0) detail << L"Flagged:\n" << flagged.str();
    std::wstring inv = inventory.str();
    if (!inv.empty()) detail << L"Other programs reachable from the network:\n" << inv;

    result.status = fail > 0 ? CHECK_FAIL : (warn > 0 ? CHECK_WARNING : CHECK_PASS);
    result.detail = detail.str();
    return result;
}

// ---------------------------------------------------------------------------
// Hosts file
// ---------------------------------------------------------------------------
SecurityCheckResult CheckHostsFile()
{
    SecurityCheckResult result = MakeCheckResult(L"net.hosts");
    // Windows reads the hosts file from the folder in Tcpip\Parameters\DataBasePath.
    // Pointing that value at another folder swaps the hosts file without touching the
    // usual one, so the value is read and a changed folder is reported.
    std::wstring defaultFolder = ExpandEnvironment(L"%SystemRoot%\\System32\\drivers\\etc");
    std::wstring dataBasePath = TrimW(RegReadString(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"DataBasePath"));
    std::wstring path = HostsFilePath(dataBasePath, defaultFolder);
    std::wstring configured = dataBasePath;
    while (configured.size() > 3 && (configured.back() == L'\\' || configured.back() == L'/')) configured.pop_back();
    bool movedFolder = !configured.empty() && !EqualsI(configured, defaultFolder);
    std::wstring folderNote = movedFolder
        ? L"Windows reads the hosts file from a non-standard folder: DataBasePath = " + dataBasePath +
          L" (the default is " + defaultFolder + L"). Check who changed it.\n"
        : L"";
    OutputDebugStringW((L"[Network] hosts file: " + path + (movedFolder ? L" (DataBasePath changed)" : L"") + L"\n").c_str());

    std::wstring text;
    if (!ReadTextFile(path, text)) {
        result.status = movedFolder ? CHECK_WARNING : CHECK_PASS;
        result.detail = folderNote + L"There is no hosts file at " + path + L".";
        return result;
    }
    std::vector<HostsEntry> entries = ParseHostsFile(text);
    std::wstringstream watched;
    std::wstringstream other;
    int watchedCount = 0;
    for (const HostsEntry& e : entries) {
        std::wstring line = L"  line " + std::to_wstring(e.line) + L": " + e.address + L" " + e.host + L"\n";
        if (IsWatchedDomain(e.host)) {
            watchedCount++;
            watched << line;
        }
        else {
            other << line;
        }
    }
    if (watchedCount > 0) {
        result.status = CHECK_FAIL;
        result.detail = std::to_wstring(watchedCount) + L" entry or entries redirect security, update or banking sites:\n" + watched.str();
        if (!other.str().empty()) result.detail += L"Other entries:\n" + other.str();
    }
    else if (!entries.empty()) {
        result.status = movedFolder ? CHECK_WARNING : CHECK_INFO;
        result.detail = std::to_wstring(entries.size()) + L" custom entry or entries, none for well-known sites:\n" + other.str();
    }
    else {
        result.status = movedFolder ? CHECK_WARNING : CHECK_PASS;
        result.detail = L"The hosts file has no active entries.";
    }
    result.detail = folderNote + result.detail;
    if (!movedFolder) {
        if (!result.detail.empty() && result.detail.back() != L'\n') result.detail += L"\n";
        result.detail += L"File: " + path + L"\n";
    }
    return result;
}

// ---------------------------------------------------------------------------
// DNS servers
// ---------------------------------------------------------------------------
SecurityCheckResult CheckDnsSettings()
{
    SecurityCheckResult result = MakeCheckResult(L"net.dns");
    ULONG size = 16 * 1024;
    std::vector<BYTE> buffer(size);
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (rc != NO_ERROR) {
        result.status = CHECK_ERROR;
        result.detail = L"Network adapters could not be read (error " + std::to_wstring(rc) + L").";
        return result;
    }

    // Hand-set servers are in the NameServer value of the adapter, under Tcpip for IPv4
    // and Tcpip6 for IPv6. Each server is matched against the list for its own family,
    // so a hand-set IPv6 server is checked even when IPv4 comes from DHCP.
    std::wstringstream details;
    int suspicious = 0;
    for (IP_ADAPTER_ADDRESSES* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        std::wstring name = a->FriendlyName ? a->FriendlyName : L"";
        std::string guid = a->AdapterName ? a->AdapterName : "";
        std::wstring guidW(guid.begin(), guid.end());
        std::set<std::wstring> staticV4, staticV6;
        for (const std::wstring& s : ParseNameServerList(RegReadString(HKEY_LOCAL_MACHINE,
                 L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + guidW, L"NameServer"))) {
            staticV4.insert(CanonicalAddress(s));
        }
        for (const std::wstring& s : ParseNameServerList(RegReadString(HKEY_LOCAL_MACHINE,
                 L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\" + guidW, L"NameServer"))) {
            staticV6.insert(CanonicalAddress(s));
        }

        std::vector<std::wstring> servers;
        std::vector<std::wstring> handSet;
        for (IP_ADAPTER_DNS_SERVER_ADDRESS* d = a->FirstDnsServerAddress; d; d = d->Next) {
            const SOCKADDR* sa = d->Address.lpSockaddr;
            if (!sa) continue;
            std::wstring text;
            bool v6 = false;
            // InetNtopW needs no Winsock start-up, unlike WSAAddressToStringW, and leaves
            // out the IPv6 zone id ("%12"), which only names a local interface.
            if (sa->sa_family == AF_INET && d->Address.iSockaddrLength >= static_cast<INT>(sizeof(sockaddr_in))) {
                text = AddressText(AF_INET, &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr);
            }
            else if (sa->sa_family == AF_INET6 && d->Address.iSockaddrLength >= static_cast<INT>(sizeof(sockaddr_in6))) {
                text = AddressText(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr);
                v6 = true;
            }
            text = StripAddressZone(text);
            if (text.empty()) continue;
            bool isStatic = (v6 ? staticV6 : staticV4).count(CanonicalAddress(text)) > 0;
            servers.push_back(text + (isStatic ? L" (set by hand)" : L""));
            if (isStatic) handSet.push_back(text);
        }
        if (servers.empty()) continue;
        details << L"  " << name << L": " << JoinW(servers, L", ") << L"\n";
        for (const std::wstring& s : handSet) {
            if (!IsPrivateOrLocalAddress(s) && !IsWellKnownPublicResolver(s)) {
                suspicious++;
                details << L"      " << s << L" is a public address that is not a well-known resolver\n";
            }
        }
    }
    OutputDebugStringW((L"[Network] DNS: " + std::to_wstring(suspicious) + L" unusual hand-set server(s)\n").c_str());
    if (details.str().empty()) details << L"No DNS servers are set on any connected adapter.\n";

    DWORD autoDoh = 0;
    RegReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", L"EnableAutoDoh", autoDoh);
    DWORD dohPolicy = 0;
    bool dohPolicySet = RegReadDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"DoHPolicy", dohPolicy);
    details << L"DNS over HTTPS: " << (dohPolicySet ? (dohPolicy == 3 ? L"required by policy" : dohPolicy == 2 ? L"allowed by policy" : L"blocked by policy")
                                                     : (autoDoh == 2 ? L"automatic" : L"not configured")) << L"\n";

    if (suspicious > 0) {
        result.status = CHECK_WARNING;
        result.detail = std::to_wstring(suspicious) + L" hand-set DNS server(s) are not well-known resolvers. Check you set them.\n" + details.str();
    }
    else {
        result.status = CHECK_INFO;
        result.detail = details.str();
    }
    return result;
}
