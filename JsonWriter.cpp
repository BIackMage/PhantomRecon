#include "pch.h"
#include "JsonWriter.h"

#include <cmath>
#include <cwchar>

std::wstring JsonWriter::Escape(const std::wstring& value)
{
    std::wstring out;
    out.reserve(value.size() + 8);
    for (size_t i = 0; i < value.size(); ++i) {
        wchar_t c = value[i];
        // A surrogate pair is copied as it is. An unpaired surrogate (legal in an NTFS
        // file name, impossible in UTF-8) is written as a \u escape, which JSON allows,
        // so the exact name survives the UTF-8 file.
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < value.size() && value[i + 1] >= 0xDC00 && value[i + 1] <= 0xDFFF) {
            out += c;
            out += value[++i];
            continue;
        }
        if (c >= 0xD800 && c <= 0xDFFF) {
            wchar_t buf[8];
            swprintf_s(buf, L"\\u%04x", static_cast<unsigned int>(c));
            out += buf;
            continue;
        }
        switch (c) {
        case L'"':  out += L"\\\""; break;
        case L'\\': out += L"\\\\"; break;
        case L'\n': out += L"\\n";  break;
        case L'\r': out += L"\\r";  break;
        case L'\t': out += L"\\t";  break;
        case L'\b': out += L"\\b";  break;
        case L'\f': out += L"\\f";  break;
        default:
            if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                wchar_t buf[8];
                swprintf_s(buf, L"\\u%04x", static_cast<unsigned int>(c));
                out += buf;
            }
            else {
                out += c;
            }
        }
    }
    return out;
}

void JsonWriter::Newline()
{
    m_out += L"\n";
    m_out.append(m_stack.size() * 2, L' ');
}

void JsonWriter::BeforeValue()
{
    if (m_afterKey) {
        m_afterKey = false;
        return;
    }
    if (!m_stack.empty()) {
        Level& level = m_stack.back();
        if (level.count > 0) m_out += L",";
        Newline();
        level.count++;
    }
}

void JsonWriter::BeginObject()
{
    BeforeValue();
    m_out += L"{";
    m_stack.push_back(Level{ false, 0 });
}

void JsonWriter::EndObject()
{
    bool hadMembers = !m_stack.empty() && m_stack.back().count > 0;
    m_stack.pop_back();
    if (hadMembers) Newline();
    m_out += L"}";
}

void JsonWriter::BeginArray()
{
    BeforeValue();
    m_out += L"[";
    m_stack.push_back(Level{ true, 0 });
}

void JsonWriter::EndArray()
{
    bool hadItems = !m_stack.empty() && m_stack.back().count > 0;
    m_stack.pop_back();
    if (hadItems) Newline();
    m_out += L"]";
}

void JsonWriter::Key(const std::wstring& name)
{
    Level& level = m_stack.back();
    if (level.count > 0) m_out += L",";
    Newline();
    level.count++;
    m_out += L"\"" + Escape(name) + L"\": ";
    m_afterKey = true;
}

void JsonWriter::String(const std::wstring& value)
{
    BeforeValue();
    m_out += L"\"" + Escape(value) + L"\"";
}

void JsonWriter::Number(double value)
{
    BeforeValue();
    if (!std::isfinite(value)) {
        m_out += L"null";
        return;
    }
    wchar_t buf[64];
    swprintf_s(buf, L"%.6g", value);
    m_out += buf;
}

void JsonWriter::Number(long long value)
{
    BeforeValue();
    m_out += std::to_wstring(value);
}

void JsonWriter::Bool(bool value)
{
    BeforeValue();
    m_out += value ? L"true" : L"false";
}

void JsonWriter::Null()
{
    BeforeValue();
    m_out += L"null";
}

void JsonWriter::StringArray(const std::vector<std::wstring>& values)
{
    BeginArray();
    for (const std::wstring& v : values) String(v);
    EndArray();
}
