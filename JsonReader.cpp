#include "pch.h"
#include "JsonReader.h"

#include <charconv>
#include <cstring>
#include <system_error>

static void DebugLog(const std::string& msg)
{
    OutputDebugStringA(("[JsonReader] " + msg + "\n").c_str());
}

const JsonValue* JsonValue::Find(const std::string& key) const
{
    if (type != Type::Object) return nullptr;
    for (const auto& m : members) {
        if (m.first == key) return &m.second;
    }
    return nullptr;
}

const JsonValue* JsonValue::At(size_t index) const
{
    if (type != Type::Array || index >= items.size()) return nullptr;
    return &items[index];
}

namespace {

class Parser {
public:
    explicit Parser(const std::string& s) : m_s(s) {}

    bool ParseDocument(JsonValue& out)
    {
        SkipSpace();
        if (!ParseValue(out, 0)) return false;
        SkipSpace();
        if (m_pos != m_s.size()) return Fail("text after the JSON value");
        return true;
    }

    const std::string& Error() const { return m_error; }

private:
    const std::string& m_s;
    size_t m_pos = 0;
    std::string m_error;

    bool Fail(const std::string& why)
    {
        if (m_error.empty()) m_error = why + " at byte " + std::to_string(m_pos);
        return false;
    }

    void SkipSpace()
    {
        while (m_pos < m_s.size()) {
            char c = m_s[m_pos];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
            ++m_pos;
        }
    }

    bool Literal(const char* word)
    {
        size_t n = strlen(word);
        if (m_s.compare(m_pos, n, word) != 0) return Fail("unknown word");
        m_pos += n;
        return true;
    }

    bool ParseValue(JsonValue& out, int depth)
    {
        if (m_pos >= m_s.size()) return Fail("unexpected end");
        char c = m_s[m_pos];
        switch (c) {
        case '{': return ParseObject(out, depth + 1);
        case '[': return ParseArray(out, depth + 1);
        case '"': out.type = JsonValue::Type::String; return ParseString(out.text);
        case 't': out.type = JsonValue::Type::Bool; out.boolean = true; return Literal("true");
        case 'f': out.type = JsonValue::Type::Bool; out.boolean = false; return Literal("false");
        case 'n': out.type = JsonValue::Type::Null; return Literal("null");
        default:
            if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber(out);
            return Fail("unexpected character");
        }
    }

    bool ParseObject(JsonValue& out, int depth)
    {
        if (depth > kJsonMaxDepth) return Fail("nested too deeply");
        out.type = JsonValue::Type::Object;
        ++m_pos;   // {
        SkipSpace();
        if (m_pos < m_s.size() && m_s[m_pos] == '}') {
            ++m_pos;
            return true;
        }
        while (true) {
            SkipSpace();
            if (m_pos >= m_s.size() || m_s[m_pos] != '"') return Fail("expected a member name");
            std::string key;
            if (!ParseString(key)) return false;
            SkipSpace();
            if (m_pos >= m_s.size() || m_s[m_pos] != ':') return Fail("expected ':'");
            ++m_pos;
            SkipSpace();
            out.members.emplace_back(std::move(key), JsonValue());
            if (!ParseValue(out.members.back().second, depth)) return false;
            SkipSpace();
            if (m_pos >= m_s.size()) return Fail("unexpected end in object");
            if (m_s[m_pos] == ',') {
                ++m_pos;
                continue;
            }
            if (m_s[m_pos] == '}') {
                ++m_pos;
                return true;
            }
            return Fail("expected ',' or '}'");
        }
    }

    bool ParseArray(JsonValue& out, int depth)
    {
        if (depth > kJsonMaxDepth) return Fail("nested too deeply");
        out.type = JsonValue::Type::Array;
        ++m_pos;   // [
        SkipSpace();
        if (m_pos < m_s.size() && m_s[m_pos] == ']') {
            ++m_pos;
            return true;
        }
        while (true) {
            SkipSpace();
            out.items.emplace_back();
            if (!ParseValue(out.items.back(), depth)) return false;
            SkipSpace();
            if (m_pos >= m_s.size()) return Fail("unexpected end in array");
            if (m_s[m_pos] == ',') {
                ++m_pos;
                continue;
            }
            if (m_s[m_pos] == ']') {
                ++m_pos;
                return true;
            }
            return Fail("expected ',' or ']'");
        }
    }

    static void AppendUtf8(std::string& out, unsigned long cp)
    {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        }
        else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
        else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
        else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    bool Hex4(unsigned long& value)
    {
        if (m_pos + 4 > m_s.size()) return Fail("short \\u escape");
        value = 0;
        for (int i = 0; i < 4; ++i) {
            char h = m_s[m_pos + i];
            value <<= 4;
            if (h >= '0' && h <= '9') value |= static_cast<unsigned long>(h - '0');
            else if (h >= 'a' && h <= 'f') value |= static_cast<unsigned long>(h - 'a' + 10);
            else if (h >= 'A' && h <= 'F') value |= static_cast<unsigned long>(h - 'A' + 10);
            else return Fail("bad \\u escape");
        }
        m_pos += 4;
        return true;
    }

    bool ParseString(std::string& out)
    {
        ++m_pos;   // opening quote
        out.clear();
        while (true) {
            if (m_pos >= m_s.size()) return Fail("unterminated string");
            unsigned char c = static_cast<unsigned char>(m_s[m_pos]);
            if (c == '"') {
                ++m_pos;
                return true;
            }
            if (c < 0x20) return Fail("control character in string");
            if (c != '\\') {
                out += static_cast<char>(c);
                ++m_pos;
                continue;
            }
            ++m_pos;
            if (m_pos >= m_s.size()) return Fail("unterminated escape");
            char e = m_s[m_pos++];
            switch (e) {
            case '"':  out += '"';  break;
            case '\\': out += '\\'; break;
            case '/':  out += '/';  break;
            case 'b':  out += '\b'; break;
            case 'f':  out += '\f'; break;
            case 'n':  out += '\n'; break;
            case 'r':  out += '\r'; break;
            case 't':  out += '\t'; break;
            case 'u': {
                unsigned long cp = 0;
                if (!Hex4(cp)) return false;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    // A high surrogate needs a following \uDC00-\uDFFF to make one character.
                    unsigned long low = 0;
                    if (m_pos + 6 <= m_s.size() && m_s[m_pos] == '\\' && m_s[m_pos + 1] == 'u') {
                        size_t save = m_pos;
                        m_pos += 2;
                        if (!Hex4(low)) return false;
                        if (low >= 0xDC00 && low <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                        }
                        else {
                            m_pos = save;   // the next escape is its own character
                            cp = 0xFFFD;
                        }
                    }
                    else {
                        cp = 0xFFFD;
                    }
                }
                else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    cp = 0xFFFD;
                }
                AppendUtf8(out, cp);
                break;
            }
            default:
                return Fail("unknown escape");
            }
        }
    }

    bool ParseNumber(JsonValue& out)
    {
        size_t start = m_pos;
        if (m_s[m_pos] == '-') ++m_pos;
        if (m_pos >= m_s.size()) return Fail("bad number");
        if (m_s[m_pos] == '0') {
            ++m_pos;
        }
        else if (m_s[m_pos] >= '1' && m_s[m_pos] <= '9') {
            while (m_pos < m_s.size() && m_s[m_pos] >= '0' && m_s[m_pos] <= '9') ++m_pos;
        }
        else {
            return Fail("bad number");
        }
        if (m_pos < m_s.size() && m_s[m_pos] == '.') {
            ++m_pos;
            size_t digits = m_pos;
            while (m_pos < m_s.size() && m_s[m_pos] >= '0' && m_s[m_pos] <= '9') ++m_pos;
            if (m_pos == digits) return Fail("bad fraction");
        }
        if (m_pos < m_s.size() && (m_s[m_pos] == 'e' || m_s[m_pos] == 'E')) {
            ++m_pos;
            if (m_pos < m_s.size() && (m_s[m_pos] == '+' || m_s[m_pos] == '-')) ++m_pos;
            size_t digits = m_pos;
            while (m_pos < m_s.size() && m_s[m_pos] >= '0' && m_s[m_pos] <= '9') ++m_pos;
            if (m_pos == digits) return Fail("bad exponent");
        }
        out.type = JsonValue::Type::Number;
        double value = 0.0;
        auto result = std::from_chars(m_s.data() + start, m_s.data() + m_pos, value);
        // A number too large or too small for a double still is valid JSON; keep 0.
        out.number = result.ec == std::errc() ? value : 0.0;
        return true;
    }
};

}   // namespace

bool ParseJson(const std::string& utf8, JsonValue& out, std::string& error)
{
    out = JsonValue();
    error.clear();
    Parser parser(utf8);
    if (parser.ParseDocument(out)) return true;
    error = parser.Error();
    out = JsonValue();
    DebugLog("ParseJson failed: " + error);
    return false;
}
