#include "pch.h"
#include "SecurityChecksWireless.h"

#include "CheckHelpers.h"
#include "PlatformRules.h"
#include "ServiceUtil.h"
#include "TextUtils.h"

#include <windows.h>
#include <wlanapi.h>
#include <set>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[SecurityChecksWireless] " + msg + L"\n").c_str());
}

// ---------------------------------------------------------------------------
// The Native Wifi API, loaded at run time. Windows Server without the Wireless LAN
// feature has no wlanapi.dll; a static import would stop every program that links
// the engine from starting there.
// ---------------------------------------------------------------------------
namespace {

typedef DWORD (WINAPI* WlanOpenHandleFn)(DWORD, PVOID, PDWORD, PHANDLE);
typedef DWORD (WINAPI* WlanCloseHandleFn)(HANDLE, PVOID);
typedef DWORD (WINAPI* WlanEnumInterfacesFn)(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST*);
typedef DWORD (WINAPI* WlanGetProfileListFn)(HANDLE, const GUID*, PVOID, PWLAN_PROFILE_INFO_LIST*);
typedef DWORD (WINAPI* WlanGetProfileFn)(HANDLE, const GUID*, LPCWSTR, PVOID, LPWSTR*, DWORD*, DWORD*);
typedef VOID (WINAPI* WlanFreeMemoryFn)(PVOID);

class WlanApi {
public:
    WlanApi()
    {
        m_module = LoadLibraryExW(L"wlanapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!m_module) return;
        open = reinterpret_cast<WlanOpenHandleFn>(GetProcAddress(m_module, "WlanOpenHandle"));
        close = reinterpret_cast<WlanCloseHandleFn>(GetProcAddress(m_module, "WlanCloseHandle"));
        enumInterfaces = reinterpret_cast<WlanEnumInterfacesFn>(GetProcAddress(m_module, "WlanEnumInterfaces"));
        getProfileList = reinterpret_cast<WlanGetProfileListFn>(GetProcAddress(m_module, "WlanGetProfileList"));
        getProfile = reinterpret_cast<WlanGetProfileFn>(GetProcAddress(m_module, "WlanGetProfile"));
        freeMemory = reinterpret_cast<WlanFreeMemoryFn>(GetProcAddress(m_module, "WlanFreeMemory"));
    }
    ~WlanApi()
    {
        if (m_module) FreeLibrary(m_module);
    }
    WlanApi(const WlanApi&) = delete;
    WlanApi& operator=(const WlanApi&) = delete;

    bool Ok() const
    {
        return m_module && open && close && enumInterfaces && getProfileList && getProfile && freeMemory;
    }

    WlanOpenHandleFn     open = nullptr;
    WlanCloseHandleFn    close = nullptr;
    WlanEnumInterfacesFn enumInterfaces = nullptr;
    WlanGetProfileListFn getProfileList = nullptr;
    WlanGetProfileFn     getProfile = nullptr;
    WlanFreeMemoryFn     freeMemory = nullptr;

private:
    HMODULE m_module = NULL;
};

} // namespace

// One profile's XML, reduced to the three fields this check uses. The XML is
// requested without WLAN_PROFILE_GET_PLAINTEXT_KEY, so a secured profile holds at
// most an encrypted key; the copy is wiped and both buffers are freed straight away.
static bool ReadProfileSummary(const WlanApi& api, HANDLE client, const GUID& iface, const wchar_t* name,
                               WlanProfileSummary& out)
{
    LPWSTR xml = NULL;
    DWORD flags = 0;   // input: no WLAN_PROFILE_GET_PLAINTEXT_KEY
    DWORD rc = api.getProfile(client, &iface, name, NULL, &xml, &flags, NULL);
    if (rc != ERROR_SUCCESS || !xml) {
        DebugLog(L"WlanGetProfile failed with " + std::to_wstring(rc));
        if (xml) api.freeMemory(xml);
        return false;
    }
    std::wstring copy(xml);
    SecureZeroMemory(xml, (wcslen(xml) + 1) * sizeof(wchar_t));
    api.freeMemory(xml);
    out = ParseWlanProfileXml(copy);
    if (!copy.empty()) SecureZeroMemory(&copy[0], copy.size() * sizeof(wchar_t));
    return out.parsed;
}

SecurityCheckResult CheckOpenWifi()
{
    SecurityCheckResult result = MakeCheckResult(L"net.wifiopen");
    WifiFacts facts;
    ServiceInfo service;
    facts.serviceInstalled = QueryServiceByName(L"WlanSvc", service);
    std::wstring note;

    WlanApi api;
    facts.apiAvailable = api.Ok();
    HANDLE client = NULL;
    if (facts.serviceInstalled && facts.apiAvailable && service.state == SERVICE_RUNNING) {
        DWORD negotiated = 0;
        DWORD rc = api.open(2, NULL, &negotiated, &client);
        if (rc == ERROR_SUCCESS) {
            facts.serviceRunning = true;
        }
        else {
            client = NULL;
            note = L"WlanOpenHandle answered " + std::to_wstring(rc) + L".";
            DebugLog(L"WlanOpenHandle failed with " + std::to_wstring(rc));
        }
    }

    CappedList listed(50);
    if (client) {
        PWLAN_INTERFACE_INFO_LIST interfaces = NULL;
        if (api.enumInterfaces(client, NULL, &interfaces) == ERROR_SUCCESS && interfaces) {
            facts.interfaces = static_cast<int>(interfaces->dwNumberOfItems);
            std::set<std::wstring> seen;   // a profile shared by several adapters is listed once
            for (DWORD i = 0; i < interfaces->dwNumberOfItems; ++i) {
                const GUID& iface = interfaces->InterfaceInfo[i].InterfaceGuid;
                PWLAN_PROFILE_INFO_LIST profiles = NULL;
                DWORD rc = api.getProfileList(client, &iface, NULL, &profiles);
                if (rc != ERROR_SUCCESS || !profiles) {
                    DebugLog(L"WlanGetProfileList failed with " + std::to_wstring(rc));
                    continue;
                }
                for (DWORD p = 0; p < profiles->dwNumberOfItems; ++p) {
                    std::wstring name = profiles->ProfileInfo[p].strProfileName;
                    if (!seen.insert(ToLowerW(name)).second) continue;
                    WlanProfileSummary summary;
                    if (!ReadProfileSummary(api, client, iface, profiles->ProfileInfo[p].strProfileName, summary)) {
                        facts.profilesUnreadable++;
                        continue;
                    }
                    facts.profilesRead++;
                    if (IsOpenAutoConnectProfile(summary)) {
                        facts.openAutoProfiles.push_back(name);
                        listed.Add(L"  \"" + name + L"\" (open, connects automatically" +
                                   (summary.connectionModeMissing ? L", no connection mode saved" : L"") + L")\n");
                    }
                }
                api.freeMemory(profiles);
            }
            api.freeMemory(interfaces);
        }
        api.close(client, NULL);
    }

    std::wstring text;
    result.status = OpenWifiStatus(facts, &text);
    result.detail = text;
    if (!listed.Empty()) result.detail += L"\n" + listed.Text();
    // The exact names, for the fix plan's one command per network (not capped like the
    // evidence: each one is a network the plan should offer to fix).
    if (result.status == CHECK_FAIL || result.status == CHECK_WARNING) result.targets = facts.openAutoProfiles;
    if (!note.empty() && result.status == CHECK_NA) result.detail += L" " + note;
    DebugLog(L"Open Wi-Fi -> " + result.status);
    return result;
}
