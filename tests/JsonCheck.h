#pragma once

// A strict JSON syntax checker (RFC 8259) for the report tests. It answers one
// question: would a standard parser accept this text? It also counts keys so a
// test can look for a field by name.

#include <cwctype>
#include <string>

class JsonCheck {
public:
    explicit JsonCheck(const std::wstring& text) : s(text) {}

    bool Valid()
    {
        pos = 0;
        Ws();
        if (!Value(0)) return false;
        Ws();
        return pos == s.size();
    }

    std::wstring error;

private:
    const std::wstring& s;
    size_t pos = 0;

    bool Fail(const wchar_t* what)
    {
        if (error.empty()) error = std::wstring(what) + L" at " + std::to_wstring(pos);
        return false;
    }
    void Ws()
    {
        while (pos < s.size() && (s[pos] == L' ' || s[pos] == L'\t' || s[pos] == L'\r' || s[pos] == L'\n')) ++pos;
    }
    bool Lit(const wchar_t* word)
    {
        size_t n = wcslen(word);
        if (s.compare(pos, n, word) != 0) return Fail(L"bad literal");
        pos += n;
        return true;
    }
    bool String()
    {
        if (pos >= s.size() || s[pos] != L'"') return Fail(L"expected string");
        ++pos;
        while (pos < s.size()) {
            wchar_t c = s[pos++];
            if (c == L'"') return true;
            if (c < 0x20) return Fail(L"control character in string");
            if (c == L'\\') {
                if (pos >= s.size()) return Fail(L"bad escape");
                wchar_t e = s[pos++];
                if (e == L'u') {
                    for (int i = 0; i < 4; ++i) {
                        if (pos >= s.size() || !iswxdigit(s[pos])) return Fail(L"bad \\u escape");
                        ++pos;
                    }
                }
                else if (wcschr(L"\"\\/bfnrt", e) == nullptr) {
                    return Fail(L"bad escape");
                }
            }
        }
        return Fail(L"unterminated string");
    }
    bool Number()
    {
        size_t start = pos;
        if (pos < s.size() && s[pos] == L'-') ++pos;
        if (pos >= s.size() || !iswdigit(s[pos])) return Fail(L"bad number");
        if (s[pos] == L'0') ++pos;
        else while (pos < s.size() && iswdigit(s[pos])) ++pos;
        if (pos < s.size() && s[pos] == L'.') {
            ++pos;
            if (pos >= s.size() || !iswdigit(s[pos])) return Fail(L"bad fraction");
            while (pos < s.size() && iswdigit(s[pos])) ++pos;
        }
        if (pos < s.size() && (s[pos] == L'e' || s[pos] == L'E')) {
            ++pos;
            if (pos < s.size() && (s[pos] == L'+' || s[pos] == L'-')) ++pos;
            if (pos >= s.size() || !iswdigit(s[pos])) return Fail(L"bad exponent");
            while (pos < s.size() && iswdigit(s[pos])) ++pos;
        }
        return pos > start;
    }
    bool Value(int depth)
    {
        if (depth > 200) return Fail(L"too deep");
        if (pos >= s.size()) return Fail(L"unexpected end");
        wchar_t c = s[pos];
        if (c == L'{') {
            ++pos;
            Ws();
            if (pos < s.size() && s[pos] == L'}') { ++pos; return true; }
            while (true) {
                Ws();
                if (!String()) return false;
                Ws();
                if (pos >= s.size() || s[pos] != L':') return Fail(L"expected colon");
                ++pos;
                Ws();
                if (!Value(depth + 1)) return false;
                Ws();
                if (pos < s.size() && s[pos] == L',') { ++pos; continue; }
                if (pos < s.size() && s[pos] == L'}') { ++pos; return true; }
                return Fail(L"expected , or }");
            }
        }
        if (c == L'[') {
            ++pos;
            Ws();
            if (pos < s.size() && s[pos] == L']') { ++pos; return true; }
            while (true) {
                Ws();
                if (!Value(depth + 1)) return false;
                Ws();
                if (pos < s.size() && s[pos] == L',') { ++pos; continue; }
                if (pos < s.size() && s[pos] == L']') { ++pos; return true; }
                return Fail(L"expected , or ]");
            }
        }
        if (c == L'"') return String();
        if (c == L't') return Lit(L"true");
        if (c == L'f') return Lit(L"false");
        if (c == L'n') return Lit(L"null");
        return Number();
    }
};
