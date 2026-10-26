#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// FileIO: UTF-8 text files and raw byte files.
//
// std::wofstream writes through the C locale and silently fails on the first
// non-ASCII character, which broke CSV output for paths with accented names.
// Everything that writes text now goes through these helpers instead.
// ---------------------------------------------------------------------------

// Replace the file with UTF-8 text. Writes a BOM when withBom is true (Excel needs it for CSV).
bool WriteUtf8File(const std::wstring& path, const std::wstring& text, bool withBom = false);

// Append UTF-8 text. If the file is new or empty, writes the BOM (when asked) and the header first.
bool AppendUtf8File(const std::wstring& path, const std::wstring& text,
                    const std::wstring& headerIfNew = L"", bool withBom = false);

// Read a whole text file, detecting UTF-16 LE/BE and UTF-8 BOMs. Bytes without a BOM are
// decoded as UTF-8 when valid, else as the system ANSI code page. maxBytes caps the read.
bool ReadTextFile(const std::wstring& path, std::wstring& out, size_t maxBytes = 64 * 1024 * 1024);

// Raw bytes, capped at maxBytes.
bool ReadBinaryFile(const std::wstring& path, std::vector<uint8_t>& out, size_t maxBytes = 512 * 1024 * 1024);
bool WriteBinaryFile(const std::wstring& path, const void* data, size_t size);

// Decode a byte buffer that may hold text in any of the encodings above.
std::wstring DecodeTextBytes(const uint8_t* data, size_t size);
