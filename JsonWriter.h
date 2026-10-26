#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// JsonWriter: a small streaming JSON writer with correct string escaping.
// Produces pretty-printed UTF-16 text; convert with WideToUtf8 to save.
// ---------------------------------------------------------------------------

class JsonWriter {
public:
    void BeginObject();
    void EndObject();
    void BeginArray();
    void EndArray();

    // Object member name. Must be followed by exactly one value.
    void Key(const std::wstring& name);

    void String(const std::wstring& value);
    void Number(double value);
    void Number(long long value);
    void Number(int value) { Number(static_cast<long long>(value)); }
    void Number(size_t value) { Number(static_cast<long long>(value)); }
    void Bool(bool value);
    void Null();

    // Convenience: array of strings.
    void StringArray(const std::vector<std::wstring>& values);

    const std::wstring& Text() const { return m_out; }

    static std::wstring Escape(const std::wstring& value);

private:
    struct Level {
        bool isArray = false;
        int  count = 0;
    };
    std::vector<Level> m_stack;
    std::wstring       m_out;
    bool               m_afterKey = false;

    void BeforeValue();
    void Newline();
};
