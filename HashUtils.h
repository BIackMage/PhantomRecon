#pragma once

#include <string>
#include <windows.h>

// ---------------------------------------------------------------------------
// HashUtils: file hashing.
//   SHA-256 via BCrypt (CNG). The hash to use for lookups and reporting.
//   MD5 via CryptoAPI. Kept for baseline format compatibility only.
// Both read the file in 64 KB blocks and are safe to call from any thread.
// ---------------------------------------------------------------------------

// Lowercase hex SHA-256 of a file. Empty string on failure.
std::wstring ComputeFileSHA256(const std::wstring& filePath);

// Lowercase hex MD5 of a file. Empty string on failure.
std::wstring ComputeFileMD5Hex(const std::wstring& filePath);
