#pragma once

// A strict JSON syntax checker (RFC 8259) for the report tests. It answers one
// question: would a standard parser accept this text? While checking it also
// counts object keys (escapes decoded), so a test can ask whether a field is
// there and how often.
//
// The checker keeps its own copy of the text, so JsonCheck(BuildJsonReport(d))
// is safe. Digits and hex digits are ASCII only, as the RFC says; a Unicode
// digit such as U+0661 is not a JSON number.

#include <cwchar>
#include <map>
#include <string>
#include <utility>

class JsonCheck {
public:
    explicit JsonCheck(std::wstring text) : s(std::move(text)) {}

    bool Valid()
    {
        pos = 0;
        error.clear();
        keys.clear();
        Ws();
        if (!Value(0)) return false;
        Ws();
        if (pos != s.size()) return Fail(L"text after the value");
        return true;
    }

    // How many times an object key appeared anywhere in the document (after Valid()).
    int KeyCount(const std::wstring& key) const
    {
        auto it = keys.find(key);
        return it == keys.end() ? 0 : it->second;
    }
    bool HasKey(const std::wstring& key) const { return KeyCount(key) > 0; }

    std::wstring error;

private:
    std::wstring s;
    size_t pos = 0;
    std::map<std::wstring, int> keys;

    static bool Digit(wchar_t c) { return c >= L'0' && c <= L'9'; }
    static int HexValue(wchar_t c)
    {
        if (c >= L'0' && c <= L'9') return c - L'0';
        if (c >= L'a' && c <= L'f') return c - L'a' + 10;
        if (c >= L'A' && c <= L'F') return c - L'A' + 10;
        return -1;
    }

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
    // Checks one string and returns its decoded text in out.
    bool String(std::wstring& out)
    {
        out.clear();
        if (pos >= s.size() || s[pos] != L'"') return Fail(L"expected string");
        ++pos;
        while (pos < s.size()) {
            wchar_t c = s[pos++];
            if (c == L'"') return true;
            if (c < 0x20) return Fail(L"control character in string");
            if (c != L'\\') {
                out.push_back(c);
                continue;
            }
            if (pos >= s.size()) return Fail(L"bad escape");
            wchar_t e = s[pos++];
            switch (e) {
            case L'"':  out.push_back(L'"'); break;
            case L'\\': out.push_back(L'\\'); break;
            case L'/':  out.push_back(L'/'); break;
            case L'b':  out.push_back(L'\b'); break;
            case L'f':  out.push_back(L'\f'); break;
            case L'n':  out.push_back(L'\n'); break;
            case L'r':  out.push_back(L'\r'); break;
            case L't':  out.push_back(L'\t'); break;
            case L'u': {
                unsigned value = 0;
                for (int i = 0; i < 4; ++i) {
                    int h = pos < s.size() ? HexValue(s[pos]) : -1;
                    if (h < 0) return Fail(L"bad \\u escape");
                    value = value * 16 + static_cast<unsigned>(h);
                    ++pos;
                }
                out.push_back(static_cast<wchar_t>(value));
                break;
            }
            default:
                return Fail(L"bad escape");
            }
        }
        return Fail(L"unterminated string");
    }
    bool Number()
    {
        if (pos < s.size() && s[pos] == L'-') ++pos;
        if (pos >= s.size() || !Digit(s[pos])) return Fail(L"bad number");
        if (s[pos] == L'0') ++pos;
        else while (pos < s.size() && Digit(s[pos])) ++pos;
        if (pos < s.size() && s[pos] == L'.') {
            ++pos;
            if (pos >= s.size() || !Digit(s[pos])) return Fail(L"bad fraction");
            while (pos < s.size() && Digit(s[pos])) ++pos;
        }
        if (pos < s.size() && (s[pos] == L'e' || s[pos] == L'E')) {
            ++pos;
            if (pos < s.size() && (s[pos] == L'+' || s[pos] == L'-')) ++pos;
            if (pos >= s.size() || !Digit(s[pos])) return Fail(L"bad exponent");
            while (pos < s.size() && Digit(s[pos])) ++pos;
        }
        return true;
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
                std::wstring key;
                if (!String(key)) return false;
                ++keys[key];
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
        std::wstring ignored;
        if (c == L'"') return String(ignored);
        if (c == L't') return Lit(L"true");
        if (c == L'f') return Lit(L"false");
        if (c == L'n') return Lit(L"null");
        return Number();
    }
};
