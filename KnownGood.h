#pragma once

#include <string>

// ---------------------------------------------------------------------------
// KnownGood: an optional local list of SHA-256 hashes you trust.
//
// File: known_good_sha256.txt next to the exe. One hash per line, optionally
// followed by a comma and a name. Lines starting with # are comments. You can
// build it from a trusted machine, from vendor-published hashes, or from a
// subset of the NIST NSRL. New files whose hash is in the list are reported as
// KNOWN instead of NEW.
// ---------------------------------------------------------------------------

// True when the hash (any case) is in the list. Loads the file on first use.
bool IsKnownGoodHash(const std::wstring& sha256);

// Name recorded next to the hash, or "".
std::wstring KnownGoodName(const std::wstring& sha256);

// Number of hashes loaded.
size_t KnownGoodCount();

// Replace the list with the contents of another file (tests, CLI). Returns the count loaded.
size_t LoadKnownGoodList(const std::wstring& path);

std::wstring DefaultKnownGoodPath();
