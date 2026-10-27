#pragma once

#include <string>
#include <vector>

#include "ScanTypes.h"

// ---------------------------------------------------------------------------
// Redactor: hide personal details before text leaves the machine or goes into
// a report someone else will read.
//
// Replaces the user profile folder (long and 8.3 form) with <parent>\<user>,
// every user name (the signed-in user, every local account, every profile folder
// name, full names) with <user>, every name of this computer (NetBIOS and DNS)
// with <host>, and every domain (DNS domain, NetBIOS domain, logon domain, a
// workgroup that is not the default "WORKGROUP") with <domain>.
//
// Matching is case-insensitive and hits whole words only: letters and digits
// count as word characters, so "PCNAME-backup" and "PCNAME_old" are redacted
// while "malice" keeps the "alice" inside it. Names of any length are hidden; a
// one- or two-letter name also hides that word elsewhere in the text, which is
// the safe side. Running the redaction twice gives the same text as once.
// ---------------------------------------------------------------------------

struct RedactionTerms {
    std::wstring userName;
    std::wstring profileDirectory;   // C:\Users\name
    std::wstring computerName;
    std::wstring domain;

    // Extra names of the same kinds (B6): other local accounts and profile folders,
    // full names, the 8.3 profile path, the DNS host name, NetBIOS and logon domains.
    std::vector<std::wstring> otherUserNames;
    std::vector<std::wstring> otherProfileDirectories;
    std::vector<std::wstring> otherHostNames;
    std::vector<std::wstring> otherDomains;
};

// Terms for the current user and machine (reads Windows every call).
RedactionTerms CurrentRedactionTerms();

// The same terms, read once per process and kept.
const RedactionTerms& CachedRedactionTerms();

std::wstring RedactText(const std::wstring& text, const RedactionTerms& terms);
std::wstring RedactText(const std::wstring& text);

// Every text field of a scan row (paths, signer names, version text, origin URLs,
// indicators, change details). Hashes, scores and ATT&CK ids are left as they are.
ScanRow RedactScanRow(const ScanRow& row, const RedactionTerms& terms);
ScanRow RedactScanRow(const ScanRow& row);

// Replace whole-word, case-insensitive occurrences of word.
std::wstring ReplaceWholeWordI(const std::wstring& text, const std::wstring& word, const std::wstring& replacement);

// Split text into parts of at most maxChars, breaking at line ends where possible.
// A surrogate pair is never split.
std::vector<std::wstring> SplitIntoParts(const std::wstring& text, size_t maxChars);
