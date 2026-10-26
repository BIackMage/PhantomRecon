#include "pch.h"
#include "RegUtil.h"

#include "AppPaths.h"

#pragma comment(lib, "advapi32.lib")

static HKEY OpenKey(HKEY root, const std::wstring& subKey, REGSAM view)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | view, &hKey) != ERROR_SUCCESS) {
        return NULL;
    }
    return hKey;
}

bool RegKeyExists(HKEY root, const std::wstring& subKey, REGSAM view)
{
    HKEY hKey = OpenKey(root, subKey, view);
    if (!hKey) return false;
    RegCloseKey(hKey);
    return true;
}

LONG RegOpenStatus(HKEY root, const std::wstring& subKey, REGSAM view)
{
    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | view, &hKey);
    if (rc == ERROR_SUCCESS) RegCloseKey(hKey);
    else if (rc != ERROR_FILE_NOT_FOUND) {
        OutputDebugStringW((L"[RegUtil] Cannot open " + RegRootName(root) + L"\\" + subKey + L": error " +
                            std::to_wstring(rc) + L"\n").c_str());
    }
    return rc;
}

bool RegReadDword(HKEY root, const std::wstring& subKey, const std::wstring& valueName, DWORD& out, REGSAM view)
{
    HKEY hKey = OpenKey(root, subKey, view);
    if (!hKey) return false;
    DWORD type = 0;
    // Room for a REG_QWORD: with a 4-byte buffer RegQueryValueExW answers
    // ERROR_MORE_DATA for one, so the QWORD branch below could never run.
    ULONGLONG value = 0;
    DWORD size = sizeof(value);
    LONG rc = RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, reinterpret_cast<BYTE*>(&value), &size);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) return false;
    if (type == REG_DWORD && size == sizeof(DWORD)) {
        out = static_cast<DWORD>(value);
        return true;
    }
    if (type == REG_QWORD && size == sizeof(ULONGLONG)) {
        out = static_cast<DWORD>(value & 0xFFFFFFFFull);   // low 32 bits are enough for the flags we read
        if ((value >> 32) != 0) {
            OutputDebugStringW((L"[RegUtil] QWORD " + valueName + L" has high bits set; using the low 32 bits\n").c_str());
        }
        return true;
    }
    return false;
}

static bool QueryRaw(HKEY root, const std::wstring& subKey, const std::wstring& valueName, REGSAM view,
                     DWORD& type, std::vector<BYTE>& data)
{
    HKEY hKey = OpenKey(root, subKey, view);
    if (!hKey) return false;
    DWORD size = 0;
    LONG rc = RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, NULL, &size);
    if (rc != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    data.assign(static_cast<size_t>(size) + sizeof(wchar_t) * 2, 0);
    DWORD size2 = size;
    rc = RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, data.data(), &size2);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) return false;
    data.resize(static_cast<size_t>(size2) + sizeof(wchar_t) * 2);
    return true;
}

std::wstring RegReadString(HKEY root, const std::wstring& subKey, const std::wstring& valueName, bool expand, REGSAM view)
{
    DWORD type = 0;
    std::vector<BYTE> data;
    if (!QueryRaw(root, subKey, valueName, view, type, data)) return L"";
    if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ) return L"";
    std::wstring value(reinterpret_cast<const wchar_t*>(data.data()));
    if (expand && type == REG_EXPAND_SZ) value = ExpandEnvironment(value);
    return value;
}

bool RegValueExists(HKEY root, const std::wstring& subKey, const std::wstring& valueName, REGSAM view)
{
    HKEY hKey = OpenKey(root, subKey, view);
    if (!hKey) return false;
    LONG rc = RegQueryValueExW(hKey, valueName.c_str(), NULL, NULL, NULL, NULL);
    RegCloseKey(hKey);
    return rc == ERROR_SUCCESS;
}

static std::vector<std::wstring> ParseMultiSz(const BYTE* data, size_t bytes)
{
    std::vector<std::wstring> out;
    const wchar_t* p = reinterpret_cast<const wchar_t*>(data);
    size_t chars = bytes / sizeof(wchar_t);
    size_t i = 0;
    while (i < chars) {
        size_t start = i;
        while (i < chars && p[i] != L'\0') ++i;
        if (i > start) out.emplace_back(p + start, i - start);
        ++i;
        if (i < chars && p[i] == L'\0') break;
    }
    return out;
}

std::vector<std::wstring> RegReadMultiString(HKEY root, const std::wstring& subKey, const std::wstring& valueName, REGSAM view)
{
    DWORD type = 0;
    std::vector<BYTE> data;
    if (!QueryRaw(root, subKey, valueName, view, type, data)) return {};
    if (type == REG_MULTI_SZ) return ParseMultiSz(data.data(), data.size());
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        std::wstring v(reinterpret_cast<const wchar_t*>(data.data()));
        if (v.empty()) return {};
        return { v };
    }
    return {};
}

bool RegReadBinary(HKEY root, const std::wstring& subKey, const std::wstring& valueName, std::vector<BYTE>& out, REGSAM view)
{
    HKEY hKey = OpenKey(root, subKey, view);
    if (!hKey) return false;
    DWORD type = 0;
    DWORD size = 0;
    LONG rc = RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, NULL, &size);
    if (rc != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    out.resize(size);
    rc = RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, out.data(), &size);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) return false;
    out.resize(size);
    return true;
}

std::vector<std::wstring> RegEnumSubKeys(HKEY root, const std::wstring& subKey, REGSAM view)
{
    std::vector<std::wstring> out;
    HKEY hKey = OpenKey(root, subKey, view);
    if (!hKey) return out;

    DWORD count = 0;
    DWORD maxLen = 0;
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &count, &maxLen, NULL, NULL, NULL, NULL, NULL, NULL);
    std::vector<wchar_t> name(static_cast<size_t>(maxLen) + 2);
    for (DWORD i = 0; i < count; ++i) {
        DWORD len = static_cast<DWORD>(name.size());
        if (RegEnumKeyExW(hKey, i, name.data(), &len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            out.emplace_back(name.data(), len);
        }
    }
    RegCloseKey(hKey);
    return out;
}

std::vector<RegValue> RegEnumValues(HKEY root, const std::wstring& subKey, REGSAM view)
{
    std::vector<RegValue> out;
    HKEY hKey = OpenKey(root, subKey, view);
    if (!hKey) return out;

    DWORD count = 0;
    DWORD maxNameLen = 0;
    DWORD maxDataLen = 0;
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &count, &maxNameLen, &maxDataLen, NULL, NULL);

    std::vector<wchar_t> name(static_cast<size_t>(maxNameLen) + 2);
    std::vector<BYTE> data(static_cast<size_t>(maxDataLen) + 8);

    for (DWORD i = 0; i < count; ++i) {
        DWORD nameLen = static_cast<DWORD>(name.size());
        DWORD dataLen = static_cast<DWORD>(data.size() - 4);
        DWORD type = 0;
        std::fill(data.begin(), data.end(), static_cast<BYTE>(0));
        if (RegEnumValueW(hKey, i, name.data(), &nameLen, NULL, &type, data.data(), &dataLen) != ERROR_SUCCESS) {
            continue;
        }
        RegValue v;
        v.name.assign(name.data(), nameLen);
        v.type = type;
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            v.text = reinterpret_cast<const wchar_t*>(data.data());
        }
        else if (type == REG_MULTI_SZ) {
            std::vector<std::wstring> parts = ParseMultiSz(data.data(), dataLen);
            for (size_t k = 0; k < parts.size(); ++k) {
                if (k > 0) v.text += L"; ";
                v.text += parts[k];
            }
        }
        else if (type == REG_DWORD && dataLen >= sizeof(DWORD)) {
            v.dword = *reinterpret_cast<const DWORD*>(data.data());
            v.text = std::to_wstring(v.dword);
        }
        out.push_back(v);
    }
    RegCloseKey(hKey);
    return out;
}

bool RegKeyLastWrite(HKEY root, const std::wstring& subKey, FILETIME& out, REGSAM view)
{
    HKEY hKey = OpenKey(root, subKey, view);
    if (!hKey) return false;
    LONG rc = RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &out);
    RegCloseKey(hKey);
    return rc == ERROR_SUCCESS;
}

std::wstring RegRootName(HKEY root)
{
    if (root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (root == HKEY_CURRENT_USER) return L"HKCU";
    if (root == HKEY_CLASSES_ROOT) return L"HKCR";
    if (root == HKEY_USERS) return L"HKU";
    return L"HK?";
}
