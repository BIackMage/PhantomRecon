#pragma once

#include <windows.h>
#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// TextUtils: small, pure string helpers shared by every module.
// Header-only and side-effect free so tests can call them directly.
// ---------------------------------------------------------------------------

// Lowercase for comparisons. ASCII text takes a fast path; anything else goes
// through Windows' invariant casing, so accented and non-Latin letters in paths
// compare equal the way the file system treats them. (towlower in the C locale
// only knows A to Z.)
inline std::wstring ToLowerW(std::wstring s)
{
    bool ascii = true;
    for (wchar_t& c : s) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + (L'a' - L'A'));
        else if (c >= 0x80) ascii = false;
    }
    if (ascii || s.empty()) return s;
    int size = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.c_str(), static_cast<int>(s.size()),
        NULL, 0, NULL, NULL, 0);
    if (size <= 0) return s;
    std::wstring out(static_cast<size_t>(size), L'\0');
    LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.c_str(), static_cast<int>(s.size()),
        &out[0], size, NULL, NULL, 0);
    return out;
}

inline std::string ToLowerA(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](char c) { return static_cast<char>(::tolower(static_cast<unsigned char>(c))); });
    return s;
}

inline bool ContainsI(const std::wstring& haystack, const std::wstring& needle)
{
    if (needle.empty()) return true;
    return ToLowerW(haystack).find(ToLowerW(needle)) != std::wstring::npos;
}

inline bool StartsWithI(const std::wstring& s, const std::wstring& prefix)
{
    if (prefix.size() > s.size()) return false;
    return _wcsnicmp(s.c_str(), prefix.c_str(), prefix.size()) == 0;
}

inline bool EndsWithI(const std::wstring& s, const std::wstring& suffix)
{
    if (suffix.size() > s.size()) return false;
    return _wcsicmp(s.c_str() + (s.size() - suffix.size()), suffix.c_str()) == 0;
}

inline bool EqualsI(const std::wstring& a, const std::wstring& b)
{
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
}

inline std::wstring TrimW(const std::wstring& s)
{
    const wchar_t* ws = L" \t\r\n\v\f";
    size_t start = s.find_first_not_of(ws);
    if (start == std::wstring::npos) return L"";
    size_t end = s.find_last_not_of(ws);
    return s.substr(start, end - start + 1);
}

inline std::vector<std::wstring> SplitW(const std::wstring& s, wchar_t delimiter, bool skipEmpty = true)
{
    std::vector<std::wstring> parts;
    std::wstring current;
    for (wchar_t c : s) {
        if (c == delimiter) {
            std::wstring t = TrimW(current);
            if (!skipEmpty || !t.empty()) parts.push_back(t);
            current.clear();
        }
        else {
            current += c;
        }
    }
    std::wstring t = TrimW(current);
    if (!skipEmpty || !t.empty()) parts.push_back(t);
    return parts;
}

// Split on any of several delimiters (used for "; " or newline separated lists).
inline std::vector<std::wstring> SplitAnyW(const std::wstring& s, const std::wstring& delimiters)
{
    std::vector<std::wstring> parts;
    std::wstring current;
    for (wchar_t c : s) {
        if (delimiters.find(c) != std::wstring::npos) {
            std::wstring t = TrimW(current);
            if (!t.empty()) parts.push_back(t);
            current.clear();
        }
        else {
            current += c;
        }
    }
    std::wstring t = TrimW(current);
    if (!t.empty()) parts.push_back(t);
    return parts;
}

inline std::wstring JoinW(const std::vector<std::wstring>& parts, const std::wstring& separator)
{
    std::wstring out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) out += separator;
        out += parts[i];
    }
    return out;
}

inline std::wstring ReplaceAllW(std::wstring s, const std::wstring& from, const std::wstring& to)
{
    if (from.empty()) return s;
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::wstring::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

// Case-insensitive replace of every occurrence.
inline std::wstring ReplaceAllI(const std::wstring& s, const std::wstring& from, const std::wstring& to)
{
    if (from.empty()) return s;
    std::wstring lower = ToLowerW(s);
    std::wstring lowerFrom = ToLowerW(from);
    std::wstring out;
    size_t pos = 0;
    while (true) {
        size_t hit = lower.find(lowerFrom, pos);
        if (hit == std::wstring::npos) {
            out += s.substr(pos);
            break;
        }
        out += s.substr(pos, hit - pos);
        out += to;
        pos = hit + from.size();
    }
    return out;
}

// Compare dotted numeric versions ("24.09", "3.0.21", "8.8.2"). Non-numeric parts
// compare as 0. Returns -1 if a < b, 0 if equal, 1 if a > b.
inline int CompareVersions(const std::wstring& a, const std::wstring& b)
{
    auto parse = [](const std::wstring& v) {
        std::vector<long long> parts;
        long long current = 0;
        bool inNumber = false;
        for (wchar_t c : v) {
            if (c >= L'0' && c <= L'9') {
                current = current * 10 + (c - L'0');
                inNumber = true;
            }
            else if (c == L'.' || c == L',' || c == L'-' || c == L'_' || c == L' ') {
                parts.push_back(inNumber ? current : 0);
                current = 0;
                inNumber = false;
            }
            else {
                // letters end the numeric part of a component ("8u401" -> 8, then 401)
                if (inNumber) {
                    parts.push_back(current);
                    current = 0;
                    inNumber = false;
                }
            }
        }
        if (inNumber) parts.push_back(current);
        while (!parts.empty() && parts.back() == 0) parts.pop_back();
        return parts;
    };

    std::vector<long long> pa = parse(a);
    std::vector<long long> pb = parse(b);
    size_t n = (std::max)(pa.size(), pb.size());
    for (size_t i = 0; i < n; ++i) {
        long long x = i < pa.size() ? pa[i] : 0;
        long long y = i < pb.size() ? pb[i] : 0;
        if (x < y) return -1;
        if (x > y) return 1;
    }
    return 0;
}

// True when s is not empty and every character is a hex digit. A hash column holds
// either a digest or an error text ("MD5 Checksum Error"); only a digest is comparable.
inline bool IsHexText(const std::wstring& s)
{
    if (s.empty()) return false;
    for (wchar_t c : s) {
        bool hex = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
        if (!hex) return false;
    }
    return true;
}

// Quote a CSV field when it contains a comma, quote or line break (RFC 4180).
inline std::wstring CsvEscape(const std::wstring& field)
{
    bool needsQuotes = field.find_first_of(L",\"\r\n") != std::wstring::npos;
    if (!needsQuotes) return field;
    std::wstring out = L"\"";
    for (wchar_t c : field) {
        if (c == L'"') out += L"\"\"";
        else out += c;
    }
    out += L"\"";
    return out;
}

inline std::wstring HtmlEscape(const std::wstring& s)
{
    std::wstring out;
    out.reserve(s.size() + 16);
    for (wchar_t c : s) {
        switch (c) {
        case L'&':  out += L"&amp;";  break;
        case L'<':  out += L"&lt;";   break;
        case L'>':  out += L"&gt;";   break;
        case L'"':  out += L"&quot;"; break;
        case L'\'': out += L"&#39;";  break;
        default:    out += c;         break;
        }
    }
    return out;
}

// Format a double with a fixed number of decimals, no locale surprises.
inline std::wstring FormatFixed(double value, int decimals)
{
    wchar_t buf[64];
    swprintf_s(buf, L"%.*f", decimals, value);
    return buf;
}

// Replace typographic dashes and quotes with ASCII. Used on any text that comes from
// Windows (display names, error strings) before it is written to a report.
inline std::wstring AsciiPunctuation(std::wstring s)
{
    for (wchar_t& c : s) {
        if (c == 0x2013 || c == 0x2014 || c == 0x2212) c = L'-';
        else if (c == 0x2018 || c == 0x2019) c = L'\'';
        else if (c == 0x201C || c == 0x201D) c = L'"';
        else if (c == 0x00A0) c = L' ';
    }
    return s;
}
