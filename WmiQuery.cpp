#include "pch.h"
#include "WmiQuery.h"

#include <windows.h>
#include <comdef.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[WmiQuery] " + msg + L"\n").c_str());
}

ComScope::ComScope()
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        m_ok = true;
        m_uninit = true;
    }
    else if (hr == RPC_E_CHANGED_MODE) {
        m_ok = true;      // thread already has an STA; COM is usable
        m_uninit = false;
    }
}

ComScope::~ComScope()
{
    if (m_uninit) CoUninitialize();
}

static std::wstring VariantToText(const VARIANT& v)
{
    if (v.vt == VT_NULL || v.vt == VT_EMPTY) return L"";

    if (v.vt & VT_ARRAY) {
        SAFEARRAY* sa = v.parray;
        if (!sa) return L"";
        LONG lower = 0;
        LONG upper = -1;
        SafeArrayGetLBound(sa, 1, &lower);
        SafeArrayGetUBound(sa, 1, &upper);
        VARTYPE elementType = static_cast<VARTYPE>(v.vt & ~VT_ARRAY);
        std::wstring out;
        for (LONG i = lower; i <= upper; ++i) {
            VARIANT element;
            VariantInit(&element);
            if (elementType == VT_VARIANT) {
                SafeArrayGetElement(sa, &i, &element);
            }
            else if (elementType == VT_BSTR) {
                BSTR b = NULL;
                if (SUCCEEDED(SafeArrayGetElement(sa, &i, &b))) {
                    element.vt = VT_BSTR;
                    element.bstrVal = b;
                }
            }
            else {
                // Numeric element: read raw into the matching VARIANT slot
                element.vt = elementType;
                SafeArrayGetElement(sa, &i, &element.llVal);
            }
            if (!out.empty()) out += L"\n";
            out += VariantToText(element);
            VariantClear(&element);
        }
        return out;
    }

    VARIANT converted;
    VariantInit(&converted);
    if (v.vt == VT_BOOL) {
        return v.boolVal ? L"True" : L"False";
    }
    if (SUCCEEDED(VariantChangeType(&converted, &v, VARIANT_ALPHABOOL, VT_BSTR)) && converted.bstrVal) {
        std::wstring out(converted.bstrVal, SysStringLen(converted.bstrVal));
        VariantClear(&converted);
        return out;
    }
    VariantClear(&converted);
    return L"";
}

static std::wstring HrText(HRESULT hr)
{
    wchar_t buf[32];
    swprintf_s(buf, L"0x%08X", static_cast<unsigned int>(hr));
    return buf;
}

WmiResult WmiQuery(const std::wstring& wmiNamespace, const std::wstring& wql,
                   const std::vector<std::wstring>& properties)
{
    WmiResult result;
    ComScope com;
    if (!com.Ok()) {
        result.error = L"COM could not be initialised";
        return result;
    }

    IWbemLocator* locator = NULL;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
        reinterpret_cast<LPVOID*>(&locator));
    if (FAILED(hr)) {
        result.hresult = hr;
        result.error = L"WbemLocator unavailable (" + HrText(hr) + L")";
        return result;
    }

    IWbemServices* services = NULL;
    BSTR ns = SysAllocString(wmiNamespace.c_str());
    hr = locator->ConnectServer(ns, NULL, NULL, NULL, 0, NULL, NULL, &services);
    SysFreeString(ns);
    if (FAILED(hr)) {
        locator->Release();
        result.hresult = hr;
        result.error = L"Cannot connect to " + wmiNamespace + L" (" + HrText(hr) + L")";
        return result;
    }

    CoSetProxyBlanket(services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    IEnumWbemClassObject* enumerator = NULL;
    BSTR language = SysAllocString(L"WQL");
    BSTR query = SysAllocString(wql.c_str());
    hr = services->ExecQuery(language, query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &enumerator);
    SysFreeString(language);
    SysFreeString(query);
    if (FAILED(hr)) {
        services->Release();
        locator->Release();
        result.hresult = hr;
        result.error = L"Query failed: " + wql + L" (" + HrText(hr) + L")";
        DebugLog(result.error);
        return result;
    }

    CoSetProxyBlanket(enumerator, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    result.ok = true;
    while (true) {
        IWbemClassObject* obj = NULL;
        ULONG returned = 0;
        hr = enumerator->Next(15000, 1, &obj, &returned);
        if (FAILED(hr)) {
            result.ok = result.rows.size() > 0;
            result.hresult = hr;
            result.error = L"Enumeration failed (" + HrText(hr) + L")";
            break;
        }
        if (returned == 0) break;

        WmiRow row;
        for (const std::wstring& prop : properties) {
            VARIANT v;
            VariantInit(&v);
            if (SUCCEEDED(obj->Get(prop.c_str(), 0, &v, NULL, NULL))) {
                if (v.vt != VT_NULL && v.vt != VT_EMPTY) {
                    row[prop] = VariantToText(v);
                }
            }
            VariantClear(&v);
        }
        result.rows.push_back(row);
        obj->Release();
    }

    enumerator->Release();
    services->Release();
    locator->Release();
    return result;
}
