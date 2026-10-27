#pragma once

#include <windows.h>
#include <climits>
#include <cstdio>
#include <string>

// ---------------------------------------------------------------------------
// StringConv: the one place UTF-8 <-> UTF-16 conversion is written.
// Header-only so every module shares the same functions.
//
// Both directions convert the whole string, including any embedded NUL.
//
// NTFS allows file names with an unpaired UTF-16 surrogate, which UTF-8 cannot
// carry. WideToUtf8 writes each one as the visible ASCII marker "[U+D8xx]" instead
// of the lossy U+FFFD, so a report still shows which code unit the name held and
// two such names stay distinct. (The JSON writer escapes them as \udxxx instead,
// which keeps the exact name.)
// ---------------------------------------------------------------------------

inline bool IsHighSurrogate(wchar_t c) { return c >= 0xD800 && c <= 0xDBFF; }
inline bool IsLowSurrogate(wchar_t c)  { return c >= 0xDC00 && c <= 0xDFFF; }

// The text with every unpaired surrogate replaced by "[U+XXXX]". Unchanged when
// there is none.
inline std::wstring MarkLoneSurrogates(const std::wstring& wide)
{
    std::wstring out;
    bool changed = false;
    for (size_t i = 0; i < wide.size(); ++i) {
        wchar_t c = wide[i];
        bool lone = false;
        if (IsHighSurrogate(c)) {
            if (i + 1 < wide.size() && IsLowSurrogate(wide[i + 1])) {
                if (changed) {
                    out += c;
                    out += wide[i + 1];
                }
                ++i;
                continue;
            }
            lone = true;
        }
        else if (IsLowSurrogate(c)) {
            lone = true;
        }
        if (lone && !changed) {
            out.assign(wide, 0, i);
            changed = true;
        }
        if (!changed) continue;
        if (lone) {
            wchar_t buf[16];
            swprintf_s(buf, L"[U+%04X]", static_cast<unsigned int>(c));
            out += buf;
        }
        else {
            out += c;
        }
    }
    return changed ? out : wide;
}

inline std::wstring Utf8ToWide(const std::string& utf8)
{
    if (utf8.empty() || utf8.size() > static_cast<size_t>(INT_MAX)) return L"";
    int length = static_cast<int>(utf8.size());
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), length, NULL, 0);
    if (size <= 0) return L"";
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), length, &result[0], size);
    return result;
}

inline std::string WideToUtf8(const std::wstring& input)
{
    if (input.empty()) return "";
    const std::wstring wide = MarkLoneSurrogates(input);
    if (wide.size() > static_cast<size_t>(INT_MAX)) return "";
    int length = static_cast<int>(wide.size());
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), length, NULL, 0, NULL, NULL);
    if (size <= 0) return "";
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), length, &result[0], size, NULL, NULL);
    return result;
}
