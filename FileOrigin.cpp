#include "pch.h"
#include "FileOrigin.h"

#include "AppPaths.h"
#include "FileIO.h"
#include "TextUtils.h"

#include <windows.h>

std::wstring ZoneName(int zoneId)
{
    switch (zoneId) {
    case 0:  return L"Local machine";
    case 1:  return L"Local intranet";
    case 2:  return L"Trusted sites";
    case 3:  return L"Internet";
    case 4:  return L"Restricted sites";
    default: return L"None";
    }
}

void ParseZoneIdentifier(const std::wstring& text, int& zoneId, std::wstring& hostUrl, std::wstring& referrerUrl)
{
    zoneId = -1;
    for (const std::wstring& rawLine : SplitAnyW(text, L"\r\n")) {
        std::wstring line = TrimW(rawLine);
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring key = ToLowerW(TrimW(line.substr(0, eq)));
        std::wstring value = TrimW(line.substr(eq + 1));
        if (key == L"zoneid") zoneId = _wtoi(value.c_str());
        else if (key == L"hosturl") hostUrl = value;
        else if (key == L"referrerurl") referrerUrl = value;
    }
}

static bool LooksExecutable(const uint8_t* p, size_t n)
{
    if (n >= 2 && p[0] == 'M' && p[1] == 'Z') return true;
    if (n >= 2 && p[0] == '#' && p[1] == '!') return true;
    std::wstring text = ToLowerW(DecodeTextBytes(p, n));
    const wchar_t* markers[] = { L"powershell", L"cmd /c", L"cmd.exe", L"wscript", L"cscript",
                                 L"createobject(", L"<script", L"@echo off", L"invoke-expression", L"iex " };
    for (const wchar_t* m : markers) {
        if (text.find(m) != std::wstring::npos) return true;
    }
    return false;
}

// Streams that Windows, browsers and sync clients attach routinely.
static bool IsRoutineStreamName(const std::wstring& name)
{
    const wchar_t* routine[] = {
        L"SmartScreen", L"com.dropbox.attrs", L"com.dropbox.attributes", L"Afp_AfpInfo", L"AFP_AfpInfo",
        L"encryptable", L"OECustomProperty", L"ms-properties", L"Win32App_1", L"{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",
        L"\x05SummaryInformation", L"\x05" L"DocumentSummaryInformation", L"KAVICHS", L"OneDriveStream",
    };
    for (const wchar_t* r : routine) {
        if (EqualsI(name, r)) return true;
    }
    return false;
}

static bool ReadStreamHead(const std::wstring& path, const std::wstring& stream, std::vector<uint8_t>& out, size_t maxBytes)
{
    return ReadBinaryFile(path + L":" + stream, out, maxBytes);
}

static bool CreatedWithinDays(const std::wstring& path, int days)
{
    WIN32_FILE_ATTRIBUTE_DATA info = {};
    if (!GetFileAttributesExW(ToExtendedPath(path).c_str(), GetFileExInfoStandard, &info)) return false;
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER a, b;
    a.LowPart = info.ftCreationTime.dwLowDateTime;
    a.HighPart = info.ftCreationTime.dwHighDateTime;
    b.LowPart = now.dwLowDateTime;
    b.HighPart = now.dwHighDateTime;
    if (b.QuadPart < a.QuadPart) return true;
    ULONGLONG ageDays = (b.QuadPart - a.QuadPart) / (864000000000ULL);
    return ageDays <= static_cast<ULONGLONG>(days);
}

FileOriginInfo AnalyzeFileOrigin(const std::wstring& path, bool isExecutable)
{
    FileOriginInfo info;
    std::wstring ioPath = ToExtendedPath(path);

    WIN32_FIND_STREAM_DATA data = {};
    HANDLE hFind = FindFirstStreamW(ioPath.c_str(), FindStreamInfoStandard, &data, 0);
    bool hasZone = false;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring name = data.cStreamName;   // "::$DATA" or ":name:$DATA"
            if (name == L"::$DATA") continue;
            if (name.size() > 1 && name[0] == L':') name = name.substr(1);
            size_t suffix = name.rfind(L":$DATA");
            if (suffix != std::wstring::npos) name = name.substr(0, suffix);

            if (EqualsI(name, L"Zone.Identifier")) {
                hasZone = true;
                std::vector<uint8_t> bytes;
                if (ReadStreamHead(ioPath, name, bytes, 8192)) {
                    std::wstring text = DecodeTextBytes(bytes.data(), bytes.size());
                    ParseZoneIdentifier(text, info.zoneId, info.hostUrl, info.referrerUrl);
                }
                continue;
            }

            AltStream s;
            s.name = name;
            s.size = data.StreamSize.QuadPart;
            std::vector<uint8_t> head;
            if (s.size > 0 && ReadStreamHead(ioPath, name, head, 4096)) {
                s.executable = LooksExecutable(head.data(), head.size());
            }
            info.streams.push_back(s);
        } while (FindNextStreamW(hFind, &data));
        FindClose(hFind);
    }

    if (!isExecutable) {
        for (const AltStream& s : info.streams) {
            if (s.executable) {
                info.warnings.push_back(L"ADS_EXECUTABLE: Stream \"" + s.name + L"\" (" + std::to_wstring(s.size) + L" bytes) holds a program or script");
            }
        }
        return info;
    }

    if (info.zoneId == 3) {
        info.warnings.push_back(L"MOTW_INTERNET: Downloaded from the internet" +
            (info.hostUrl.empty() ? std::wstring() : L" (" + info.hostUrl + L")"));
    }
    else if (info.zoneId == 4) {
        info.warnings.push_back(L"MOTW_RESTRICTED: Came from a Restricted-zone site" +
            (info.hostUrl.empty() ? std::wstring() : L" (" + info.hostUrl + L")"));
    }

    if (!hasZone) {
        std::wstring lower = ToLowerW(path);
        bool dropFolder = lower.find(L"\\downloads\\") != std::wstring::npos || lower.find(L"\\desktop\\") != std::wstring::npos;
        if (dropFolder && CreatedWithinDays(path, 30)) {
            info.warnings.push_back(L"MOTW_MISSING: Recent executable in Downloads or Desktop has no download mark");
        }
    }

    for (const AltStream& s : info.streams) {
        if (s.executable) {
            info.warnings.push_back(L"ADS_EXECUTABLE: Stream \"" + s.name + L"\" (" + std::to_wstring(s.size) + L" bytes) holds a program or script");
        }
        else if (!IsRoutineStreamName(s.name)) {
            info.warnings.push_back(L"ADS_PRESENT: Stream \"" + s.name + L"\" (" + std::to_wstring(s.size) + L" bytes)");
        }
    }
    return info;
}
