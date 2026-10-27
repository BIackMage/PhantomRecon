#include "pch.h"
#include "Redactor.h"

#include "SystemInfo.h"
#include "TextUtils.h"

#include <algorithm>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[Redactor] " + msg + L"\n").c_str());
}

// Placeholders are swapped for private-use characters while the names are replaced,
// so a user called "user" or a host called "host" cannot hit the placeholder text.
static const wchar_t kUserMark = 0xE000;
static const wchar_t kHostMark = 0xE001;
static const wchar_t kDomainMark = 0xE002;
static const wchar_t* kUserToken = L"<user>";
static const wchar_t* kHostToken = L"<host>";
static const wchar_t* kDomainToken = L"<domain>";

// Sign-in names Windows gives its built-in accounts (RID 500, 501, 503, 504) in common
// languages. They name no person, and redacting them would blank out audit text
// such as "Administrator account renamed".
static bool IsDefaultBuiltInName(const std::wstring& name)
{
    static const wchar_t* kDefaults[] = {
        L"administrator", L"administrateur", L"administrador", L"amministratore", L"administrat\x00f6r",
        L"rendszergazda", L"j\x00e4rjestelm\x00e4nvalvoja",
        L"guest", L"invit\x00e9", L"gast", L"invitado", L"convidado", L"ospite", L"vieras",
        L"defaultaccount", L"wdagutilityaccount",
    };
    std::wstring lower = ToLowerW(name);
    for (const wchar_t* d : kDefaults) {
        if (lower == d) return true;
    }
    return false;
}

static bool IsBuiltInRid(DWORD rid)
{
    return rid == 500 || rid == 501 || rid == 503 || rid == 504;
}

static void AddUnique(std::vector<std::wstring>& list, const std::wstring& value, const std::wstring& except = L"")
{
    std::wstring v = TrimW(value);
    if (v.empty() || (!except.empty() && EqualsI(v, except))) return;
    for (const std::wstring& existing : list) {
        if (EqualsI(existing, v)) return;
    }
    list.push_back(v);
}

RedactionTerms CurrentRedactionTerms()
{
    RedactionTerms t;
    t.userName = GetCurrentUserNameString();
    t.profileDirectory = GetUserProfileFolder();
    t.computerName = GetComputerNameString();
    if (t.computerName == L"Unknown") t.computerName.clear();   // GetComputerNameString's failure text
    t.domain = GetJoinedDomainName();

    std::wstring shortProfile = GetShortPathString(t.profileDirectory);
    AddUnique(t.otherProfileDirectories, shortProfile, t.profileDirectory);

    AddUnique(t.otherHostNames, GetDnsHostNameString(), t.computerName);

    bool isDomain = false;
    std::wstring netbios = GetJoinedNetbiosName(&isDomain);
    if (isDomain || !EqualsI(netbios, L"WORKGROUP")) AddUnique(t.otherDomains, netbios, t.domain);

    std::wstring logonDomain, logonUser;
    if (GetLogonDomainAndUser(logonDomain, logonUser)) {
        bool authority = EqualsI(logonDomain, L"NT AUTHORITY") || EqualsI(logonDomain, L"BUILTIN") ||
                         EqualsI(logonDomain, L"NT SERVICE") || EqualsI(logonDomain, L"WORKGROUP");
        if (!authority && !EqualsI(logonDomain, t.computerName)) AddUnique(t.otherDomains, logonDomain, t.domain);
        AddUnique(t.otherUserNames, logonUser, t.userName);
    }
    AddUnique(t.otherUserNames, GetUserDisplayName(), t.userName);

    for (const LocalAccountName& a : GetLocalAccountNames()) {
        if (!(IsBuiltInRid(a.rid) && IsDefaultBuiltInName(a.name))) AddUnique(t.otherUserNames, a.name, t.userName);
        if (!IsDefaultBuiltInName(a.fullName)) AddUnique(t.otherUserNames, a.fullName, t.userName);
    }
    for (const std::wstring& folder : GetProfileFolderNames()) {
        if (!IsDefaultBuiltInName(folder)) AddUnique(t.otherUserNames, folder, t.userName);
    }

    DebugLog(L"Terms: " + std::to_wstring(1 + t.otherUserNames.size()) + L" user name(s), " +
             std::to_wstring(1 + t.otherHostNames.size()) + L" host name(s), " +
             std::to_wstring((t.domain.empty() ? 0 : 1) + t.otherDomains.size()) + L" domain(s), " +
             std::to_wstring(1 + t.otherProfileDirectories.size()) + L" profile path(s)");
    return t;
}

const RedactionTerms& CachedRedactionTerms()
{
    static const RedactionTerms terms = CurrentRedactionTerms();
    return terms;
}

// Letters and digits are word characters; '-', '_', '.', '\' and spaces end a word.
static bool IsWordChar(wchar_t c)
{
    if (c < 0x80) return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z');
    if (c >= 0xD800 && c <= 0xDFFF) return true;     // half of a letter outside the BMP
    if (c >= 0xE000 && c <= 0xF8FF) return false;    // private use, includes the placeholders
    WORD type = 0;
    if (!GetStringTypeW(CT_CTYPE1, &c, 1, &type)) return false;
    return (type & (C1_ALPHA | C1_DIGIT)) != 0;
}

// lowerText must be ToLowerW(text); lowerWord must be lowercase and not empty.
static std::wstring ReplaceWholeWordLower(const std::wstring& text, const std::wstring& lowerText,
                                          const std::wstring& lowerWord, const std::wstring& replacement)
{
    std::wstring out;
    size_t pos = 0;
    while (true) {
        size_t hit = lowerText.find(lowerWord, pos);
        if (hit == std::wstring::npos) {
            out.append(text, pos, std::wstring::npos);
            break;
        }
        size_t end = hit + lowerWord.size();
        bool startOk = hit == 0 || !IsWordChar(text[hit - 1]) || !IsWordChar(text[hit]);
        bool endOk = end >= text.size() || !IsWordChar(text[end]) || !IsWordChar(text[end - 1]);
        out.append(text, pos, hit - pos);
        if (startOk && endOk) {
            out += replacement;
            pos = end;
        }
        else {
            // Not a whole word here; a match may still start inside it.
            out += text[hit];
            pos = hit + 1;
        }
    }
    return out;
}

std::wstring ReplaceWholeWordI(const std::wstring& text, const std::wstring& word, const std::wstring& replacement)
{
    if (word.empty() || text.empty()) return text;
    std::wstring lowerText = ToLowerW(text);
    std::wstring lowerWord = ToLowerW(word);
    if (lowerText.size() != text.size() || lowerText.find(lowerWord) == std::wstring::npos) {
        if (lowerText.size() != text.size()) DebugLog(L"Lowercase changed the text length; whole-word match skipped");
        return text;
    }
    return ReplaceWholeWordLower(text, lowerText, lowerWord, replacement);
}

namespace {
struct CompiledTerm {
    std::wstring lowerText;
    std::wstring replacement;
};
}

static std::vector<CompiledTerm> CompileTerms(const RedactionTerms& terms)
{
    std::vector<CompiledTerm> list;
    std::vector<std::wstring> seen;
    auto add = [&](const std::wstring& raw, const std::wstring& replacement) {
        std::wstring text = TrimW(raw);
        if (text.empty()) return;
        std::wstring lower = ToLowerW(text);
        if (lower.size() != text.size()) return;
        for (const std::wstring& s : seen) {
            if (s == lower) return;
        }
        seen.push_back(lower);
        list.push_back({ lower, replacement });
    };
    auto addProfile = [&](const std::wstring& dir) {
        std::wstring d = dir;
        while (d.size() > 3 && d.back() == L'\\') d.pop_back();
        size_t slash = d.find_last_of(L'\\');
        // Needs a real folder below a parent ("C:\Users\name"), never a drive root.
        if (d.size() <= 3 || slash == std::wstring::npos || slash + 1 >= d.size() || slash < 2) return;
        add(d, d.substr(0, slash + 1) + std::wstring(1, kUserMark));
    };

    addProfile(terms.profileDirectory);
    for (const std::wstring& p : terms.otherProfileDirectories) addProfile(p);
    add(terms.userName, std::wstring(1, kUserMark));
    for (const std::wstring& u : terms.otherUserNames) add(u, std::wstring(1, kUserMark));
    add(terms.computerName, std::wstring(1, kHostMark));
    for (const std::wstring& h : terms.otherHostNames) add(h, std::wstring(1, kHostMark));
    add(terms.domain, std::wstring(1, kDomainMark));
    for (const std::wstring& d : terms.otherDomains) add(d, std::wstring(1, kDomainMark));

    // Longest first, so "Alice Example" goes before "Alice" and a full path before a name in it.
    std::stable_sort(list.begin(), list.end(), [](const CompiledTerm& a, const CompiledTerm& b) {
        return a.lowerText.size() > b.lowerText.size();
    });
    return list;
}

static std::wstring ApplyTerms(const std::wstring& text, const std::vector<CompiledTerm>& terms)
{
    if (text.empty() || terms.empty()) return text;
    std::wstring out = text;
    bool marked = false;
    if (out.find(L'<') != std::wstring::npos) {
        std::wstring before = out;
        out = ReplaceAllW(out, kUserToken, std::wstring(1, kUserMark));
        out = ReplaceAllW(out, kHostToken, std::wstring(1, kHostMark));
        out = ReplaceAllW(out, kDomainToken, std::wstring(1, kDomainMark));
        marked = out != before;
    }
    std::wstring lower = ToLowerW(out);
    if (lower.size() != out.size()) {
        // Invariant lowercase keeps the length for UTF-16 text; if it ever does not,
        // fall back to an exact-case pass rather than mis-aligned positions.
        DebugLog(L"Lowercase changed the text length; exact-case redaction used");
        lower = out;
    }
    for (const CompiledTerm& t : terms) {
        if (lower.find(t.lowerText) == std::wstring::npos) continue;
        std::wstring replaced = ReplaceWholeWordLower(out, lower, t.lowerText, t.replacement);
        if (replaced == out) continue;
        out = replaced;
        marked = true;
        lower = ToLowerW(out);
        if (lower.size() != out.size()) lower = out;
    }
    if (!marked) return text;
    out = ReplaceAllW(out, std::wstring(1, kUserMark), kUserToken);
    out = ReplaceAllW(out, std::wstring(1, kHostMark), kHostToken);
    out = ReplaceAllW(out, std::wstring(1, kDomainMark), kDomainToken);
    return out;
}

std::wstring RedactText(const std::wstring& text, const RedactionTerms& terms)
{
    return ApplyTerms(text, CompileTerms(terms));
}

static const std::vector<CompiledTerm>& CachedCompiledTerms()
{
    static const std::vector<CompiledTerm> compiled = CompileTerms(CachedRedactionTerms());
    return compiled;
}

std::wstring RedactText(const std::wstring& text)
{
    return ApplyTerms(text, CachedCompiledTerms());
}

static ScanRow RedactRowWith(const ScanRow& row, const std::vector<CompiledTerm>& terms)
{
    ScanRow r = row;
    BaselineEntry& e = r.entry;
    // Every free-text field. md5, sha256, imphash, ssdeep and thumbprint are hashes and
    // cannot hold a name; attackIds, readOnly and hidden are fixed vocabularies.
    for (std::wstring* field : { &e.path, &e.signature, &e.signatureType, &e.issuer, &e.rootCA, &e.version,
                                 &e.developer, &e.permissions, &e.packingStatus, &e.sigWarnings, &e.packIndicators,
                                 &e.catalogSigner, &e.revocation, &e.zoneHostUrl, &e.zoneReferrerUrl, &e.altStreams,
                                 &e.originWarnings, &e.peAnomalies, &e.pdbPath, &e.scriptIndicators }) {
        *field = ApplyTerms(*field, terms);
    }
    r.changeDetails = ApplyTerms(r.changeDetails, terms);
    return r;
}

ScanRow RedactScanRow(const ScanRow& row, const RedactionTerms& terms)
{
    return RedactRowWith(row, CompileTerms(terms));
}

ScanRow RedactScanRow(const ScanRow& row)
{
    return RedactRowWith(row, CachedCompiledTerms());
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
        // The last character a part may hold is at pos + maxChars - 1, so the newline
        // searched for (kept at the end of the part) must be at or before it.
        size_t cut = text.rfind(L'\n', pos + maxChars - 1);
        if (cut == std::wstring::npos || cut < pos) {
            cut = pos + maxChars;
            // Do not leave half of a surrogate pair at the end of a part.
            if (cut > pos + 1 && text[cut - 1] >= 0xD800 && text[cut - 1] <= 0xDBFF) --cut;
        }
        else {
            cut += 1;
        }
        parts.push_back(text.substr(pos, cut - pos));
        pos = cut;
    }
    return parts;
}
