#pragma once

#include <cstdint>
#include <string>

// ---------------------------------------------------------------------------
// FuzzyHash: context-triggered piecewise hashing (the spamsum algorithm that
// ssdeep is built on). Two files that differ by a small edit produce similar
// hashes; CompareFuzzyHashes scores the similarity from 0 to 100.
//
// Output format matches ssdeep: "blocksize:hash1:hash2". Files under a few
// bytes or unreadable files produce an empty string.
// ---------------------------------------------------------------------------

std::wstring ComputeFuzzyHashBuffer(const uint8_t* data, size_t size);
std::wstring ComputeFuzzyHashFile(const std::wstring& path, size_t maxBytes = 256 * 1024 * 1024);

// 0 = unrelated, 100 = identical. Returns 0 when either hash is empty or the
// block sizes are not comparable.
int CompareFuzzyHashes(const std::wstring& a, const std::wstring& b);
