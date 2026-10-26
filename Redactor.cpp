#include "pch.h"
#include "Redactor.h"

#include "SystemInfo.h"
#include "TextUtils.h"

#include <cwctype>

RedactionTerms CurrentRedactionTerms()
{
    RedactionTerms t;
    t.userName = GetCurrentUserNameString();
    t.profileDirectory = GetUserProfileFolder();
    t.computerName = GetComputerNameString();
    t.domain = GetJoinedDomainName();
    return t;
}

static bool IsWordChar(wchar_t c)
{
    return iswalnum(c) || c == L'_' || c == L'-';
}

std::wstring ReplaceWholeWordI(const std::wstring& text, const std::wstring& word, const std::wstring& replacement)
{
    if (word.empty()) return text;
    std::wstring lower = ToLowerW(text);
    std::wstring lowerWord = ToLowerW(word);
    std::wstring out;
    size_t pos = 0;
    while (true) {
        size_t hit = lower.find(lowerWord, pos);
        if (hit == std::wstring::npos) {
            out += text.substr(pos);
            break;
        }
        bool startOk = hit == 0 || !IsWordChar(text[hit - 1]);
        size_t end = hit + word.size();
        bool endOk = end >= text.size() || !IsWordChar(text[end]);
        out += text.substr(pos, hit - pos);
        out += (startOk && endOk) ? replacement : text.substr(hit, word.size());
        pos = end;
    }
    return out;
}

std::wstring RedactText(const std::wstring& text, const RedactionTerms& terms)
{
    std::wstring out = text;
    if (terms.profileDirectory.size() > 3) {
        std::wstring parent = terms.profileDirectory.substr(0, terms.profileDirectory.find_last_of(L'\\') + 1);
        out = ReplaceAllI(out, terms.profileDirectory, parent + L"<user>");
    }
    if (terms.userName.size() >= 3) out = ReplaceWholeWordI(out, terms.userName, L"<user>");
    if (terms.computerName.size() >= 3) out = ReplaceWholeWordI(out, terms.computerName, L"<host>");
    if (terms.domain.size() >= 3) out = ReplaceAllI(out, terms.domain, L"<domain>");
    return out;
}

std::wstring RedactText(const std::wstring& text)
{
    static const RedactionTerms terms = CurrentRedactionTerms();
    return RedactText(text, terms);
}

std::vector<std::wstring> SplitIntoParts(const std::wstring& text, size_t maxChars)
{
    std::vector<std::wstring> parts;
    if (maxChars < 200) maxChars = 200;
    size_t pos = 0;
    while (pos < text.size()) {
        if (text.size() - pos <= maxChars) {
            parts.push_back(text.substr(pos));
            break;
        }
        size_t cut = text.rfind(L'\n', pos + maxChars);
        if (cut == std::wstring::npos || cut <= pos) cut = pos + maxChars;
        else cut += 1;
        parts.push_back(text.substr(pos, cut - pos));
        pos = cut;
    }
    return parts;
}
