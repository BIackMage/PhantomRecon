#pragma once

#include <string>
#include <utility>
#include <vector>

// ---------------------------------------------------------------------------
// JsonReader: a small, strict JSON parser for UTF-8 text (RFC 8259).
//
// Used for answers from the optional AI server, so it treats its input as
// hostile: nesting is limited, numbers are parsed without the C locale, and
// \uXXXX escapes (surrogate pairs included) are decoded to UTF-8. An unpaired
// surrogate escape becomes U+FFFD. No exceptions are thrown.
// ---------------------------------------------------------------------------

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type        type = Type::Null;
    bool        boolean = false;
    double      number = 0.0;
    std::string text;                                        // UTF-8, for String
    std::vector<JsonValue> items;                            // for Array
    std::vector<std::pair<std::string, JsonValue>> members;  // for Object, in file order

    bool IsNull() const   { return type == Type::Null; }
    bool IsString() const { return type == Type::String; }
    bool IsArray() const  { return type == Type::Array; }
    bool IsObject() const { return type == Type::Object; }

    // Member of an object by name (first match), or nullptr.
    const JsonValue* Find(const std::string& key) const;
    // Item of an array, or nullptr.
    const JsonValue* At(size_t index) const;
};

// Deepest nesting of arrays and objects accepted.
const int kJsonMaxDepth = 64;

// Parse the whole text (surrounding white space allowed). False with a short reason
// in error when the text is not one valid JSON value.
bool ParseJson(const std::string& utf8, JsonValue& out, std::string& error);
