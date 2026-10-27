#pragma once

#include <string>
#include <windows.h>

// ---------------------------------------------------------------------------
// HashUtils: file and buffer hashing.
//   SHA-256 via BCrypt (CNG). The hash to use for lookups and reporting.
//   MD5 via BCrypt (CNG). Kept for baseline compatibility and the import hash.
// All functions read in 64 KB blocks and are safe to call from any thread.
// File paths may be plain or \\?\ prefixed; long paths get the prefix here.
// ---------------------------------------------------------------------------

// Lowercase hex SHA-256 of a file. Empty string on failure, including a read
// error part way through the file (never a digest of a partial read).
std::wstring ComputeFileSHA256(const std::wstring& filePath);

// Lowercase hex MD5 of a file. Empty string on failure, as above.
std::wstring ComputeFileMD5Hex(const std::wstring& filePath);

// Lowercase hex digests of a memory buffer.
std::wstring ComputeBufferMD5Hex(const void* data, size_t size);
std::wstring ComputeBufferSHA256Hex(const void* data, size_t size);
