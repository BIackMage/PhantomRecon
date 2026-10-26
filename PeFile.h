#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// PeFile: one bounds-checked pass over a Windows executable (PE32 or PE32+).
//
// The file is memory-mapped read-only. Every read is range-checked against the
// mapping, and the parse runs under structured exception handling, so a
// truncated or hostile file yields valid == false instead of a crash.
// ---------------------------------------------------------------------------

struct PeImport {
    std::string dll;          // as written in the import table, e.g. "KERNEL32.dll"
    std::string function;     // empty for ordinal imports
    uint16_t    ordinal = 0;
    bool        byOrdinal = false;
};

struct PeSection {
    std::string name;             // up to 8 chars, NUL-trimmed
    uint32_t    virtualAddress = 0;
    uint32_t    virtualSize = 0;
    uint32_t    rawPointer = 0;
    uint32_t    rawSize = 0;
    uint32_t    characteristics = 0;
    double      entropySample = 0.0;   // entropy of the first 4 KB of raw data
    bool        nameHasOddChars = false;
};

struct PeInfo {
    bool        valid = false;
    std::wstring error;

    bool        is64 = false;
    bool        isDll = false;
    bool        isDriver = false;       // subsystem native or IMAGE_FILE_SYSTEM
    bool        isDotNet = false;
    bool        isReproducible = false; // IMAGE_DEBUG_TYPE_REPRO present: timestamp is a hash, not a date
    uint16_t    machine = 0;
    uint16_t    subsystem = 0;
    uint32_t    timestamp = 0;
    uint64_t    imageBase = 0;
    uint32_t    entryPointRva = 0;
    uint32_t    sizeOfHeaders = 0;

    uint32_t    checksumHeader = 0;
    uint32_t    checksumComputed = 0;
    bool        checksumComputedOk = false;

    std::vector<PeSection> sections;
    std::vector<PeImport>  imports;
    std::vector<uint8_t>   entryBytes;  // first 16 bytes at the entry point

    uint32_t    tlsCallbackCount = 0;
    std::string pdbPath;

    int64_t     fileSize = 0;
    int64_t     overlayOffset = 0;      // end of the last section's raw data
    int64_t     overlaySize = 0;        // bytes after overlayOffset, excluding the Authenticode blob
    double      overlayEntropy = 0.0;
    bool        overlayHasPe = false;   // overlay starts with, or contains early, an MZ/PE header
    uint32_t    securityDirOffset = 0;
    uint32_t    securityDirSize = 0;
};

// Parse a file. Returns valid == false (with error) when it is not a PE.
PeInfo ParsePeFile(const std::wstring& path);

// Parse a buffer already in memory (used by tests and the sample generator).
PeInfo ParsePeBuffer(const uint8_t* data, size_t size);

// Import hash in the pefile / VirusTotal format: lowercase "dll.function" items,
// dll extension (.dll/.ocx/.sys) removed, ordinals as "ord<N>", comma joined, MD5.
// Empty when there are no imports.
std::wstring ComputeImphash(const PeInfo& pe);

// The string the imphash is computed over (exposed for tests).
std::string ImphashInput(const PeInfo& pe);

// Header anomalies, as "CODE: detail" strings. filePathLower is used for the
// driver checks (".sys"). nowUnixSeconds lets tests pin the clock.
std::vector<std::wstring> FindPeAnomalies(const PeInfo& pe, const std::wstring& filePathLower,
                                          int64_t nowUnixSeconds);
