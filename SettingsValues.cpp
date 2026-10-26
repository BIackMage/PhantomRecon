#include "pch.h"
#include "SettingsValues.h"

#include "DebugTrace.h"
#include "FileIO.h"
#include "TextUtils.h"

#include <windows.h>
#include <cmath>
#include <cstdlib>
#include <vector>

double SanitizeTemperature(double value, double fallback)
{
    double safeFallback = std::isfinite(fallback) ? fallback : 0.3;
    if (safeFallback < 0.0) safeFallback = 0.0;
    if (safeFallback > 2.0) safeFallback = 2.0;
    if (!std::isfinite(value)) {
        Trace(L"SettingsValues", L"SanitizeTemperature: not a finite number, using the fallback");
        return safeFallback;
    }
    if (value < 0.0) return 0.0;
    if (value > 2.0) return 2.0;
    return value;
}

double ParseTemperatureText(const std::wstring& text, double fallback)
{
    std::wstring trimmed = TrimW(text);
    const wchar_t* start = trimmed.c_str();
    wchar_t* end = nullptr;
    double value = std::wcstod(start, &end);
    if (trimmed.empty() || end == start) {
        Trace(L"SettingsValues", L"ParseTemperatureText: \"" + text + L"\" is not a number, using the fallback");
        return SanitizeTemperature(fallback, fallback);
    }
    double result = SanitizeTemperature(value, fallback);
    Trace(L"SettingsValues", L"ParseTemperatureText: \"" + text + L"\" -> " + std::to_wstring(result));
    return result;
}

static bool HasUtf16LeBom(const std::vector<uint8_t>& bytes)
{
    return bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE;
}

static bool WriteUtf16LeWithBom(const std::wstring& path, const std::wstring& text)
{
    std::vector<uint8_t> bytes;
    bytes.reserve(2 + text.size() * sizeof(wchar_t));
    bytes.push_back(0xFF);
    bytes.push_back(0xFE);
    for (wchar_t c : text) {
        bytes.push_back(static_cast<uint8_t>(c & 0xFF));
        bytes.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
    // Write next to the file, then swap it in, so a failed write never leaves half a file.
    std::wstring temp = path + L".tmp";
    if (!WriteBinaryFile(temp, bytes.data(), bytes.size())) return false;
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temp.c_str());
        return false;
    }
    return true;
}

bool EnsureUnicodeIniFile(const std::wstring& path)
{
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        bool created = WriteUtf16LeWithBom(path, L"");
        Trace(L"SettingsValues", (created ? L"EnsureUnicodeIniFile: created UTF-16 file " : L"EnsureUnicodeIniFile: could not create ") + path);
        return created;
    }

    std::vector<uint8_t> bytes;
    if (!ReadBinaryFile(path, bytes, 16 * 1024 * 1024)) {
        Trace(L"SettingsValues", L"EnsureUnicodeIniFile: could not read " + path);
        return false;
    }
    if (HasUtf16LeBom(bytes)) return true;

    // ANSI (what Windows wrote before) or UTF-8 typed by hand: decode, then store as UTF-16.
    std::wstring text = bytes.empty() ? std::wstring() : DecodeTextBytes(bytes.data(), bytes.size());
    bool converted = WriteUtf16LeWithBom(path, text);
    Trace(L"SettingsValues", (converted ? L"EnsureUnicodeIniFile: converted to UTF-16 " : L"EnsureUnicodeIniFile: could not convert ") + path);
    return converted;
}
