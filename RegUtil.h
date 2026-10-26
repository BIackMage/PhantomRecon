#pragma once

#include <windows.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// RegUtil: registry reads used by every check module.
//
// view selects the 64-bit or 32-bit registry view (KEY_WOW64_64KEY or
// KEY_WOW64_32KEY). 0 means "the process default", which for this x64 build
// is the 64-bit view.
// ---------------------------------------------------------------------------

bool RegKeyExists(HKEY root, const std::wstring& subKey, REGSAM view = 0);

bool RegReadDword(HKEY root, const std::wstring& subKey, const std::wstring& valueName,
                  DWORD& out, REGSAM view = 0);

// REG_SZ / REG_EXPAND_SZ (expanded when expand is true). Empty string when missing.
std::wstring RegReadString(HKEY root, const std::wstring& subKey, const std::wstring& valueName,
                           bool expand = true, REGSAM view = 0);

// True when the value exists (any type).
bool RegValueExists(HKEY root, const std::wstring& subKey, const std::wstring& valueName, REGSAM view = 0);

// REG_MULTI_SZ as a list. A REG_SZ value is returned as a one-element list.
std::vector<std::wstring> RegReadMultiString(HKEY root, const std::wstring& subKey,
                                             const std::wstring& valueName, REGSAM view = 0);

// Raw value bytes. False when missing.
bool RegReadBinary(HKEY root, const std::wstring& subKey, const std::wstring& valueName,
                   std::vector<BYTE>& out, REGSAM view = 0);

std::vector<std::wstring> RegEnumSubKeys(HKEY root, const std::wstring& subKey, REGSAM view = 0);

struct RegValue {
    std::wstring name;
    DWORD        type = 0;
    std::wstring text;    // REG_SZ, REG_EXPAND_SZ (unexpanded), REG_MULTI_SZ joined with "; ", DWORD as decimal
    DWORD        dword = 0;
};
std::vector<RegValue> RegEnumValues(HKEY root, const std::wstring& subKey, REGSAM view = 0);

// Last write time of a key. False when the key cannot be opened.
bool RegKeyLastWrite(HKEY root, const std::wstring& subKey, FILETIME& out, REGSAM view = 0);

// "HKLM", "HKCU" etc. for reports.
std::wstring RegRootName(HKEY root);
