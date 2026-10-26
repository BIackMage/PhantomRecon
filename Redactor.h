#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Redactor: hide personal details before text leaves the machine or goes into
// a report someone else will read.
//
// Replaces the user profile folder, the user name, the computer name and the
// joined domain with <user>, <host> and <domain>. Matching is case-insensitive
// and the name replacements only hit whole words.
// ---------------------------------------------------------------------------

struct RedactionTerms {
    std::wstring userName;
    std::wstring profileDirectory;   // C:\Users\name
    std::wstring computerName;
    std::wstring domain;
};

// Terms for the current user and machine.
RedactionTerms CurrentRedactionTerms();

std::wstring RedactText(const std::wstring& text, const RedactionTerms& terms);
std::wstring RedactText(const std::wstring& text);

// Replace whole-word, case-insensitive occurrences of word.
std::wstring ReplaceWholeWordI(const std::wstring& text, const std::wstring& word, const std::wstring& replacement);

// Split text into parts of at most maxChars, breaking at line ends where possible.
std::vector<std::wstring> SplitIntoParts(const std::wstring& text, size_t maxChars);
