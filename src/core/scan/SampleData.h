#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// ---------------------------------------------------------------------------
// SampleData: harmless demo files for the video, the README walkthrough and
// the tests.
//
// The demo programs are tiny 64-bit executables whose only code is "return".
// They exist so a first-time user can see each kind of finding (unsigned file,
// odd headers, a download mark, an extra data stream, a script line worth a
// look) and each comparison status (NEW, CHANGED, MISSING, MATCH) without
// touching anything real. Nothing here is packed, obfuscated or imitates
// malware.
// ---------------------------------------------------------------------------

struct SamplePeSpec {
    // Function names; "#<n>" imports ordinal n instead of a name.
    std::vector<std::pair<std::string, std::vector<std::string>>> imports = {
        { "KERNEL32.dll", { "ExitProcess", "GetStdHandle", "WriteFile" } },
    };
    bool        reproducible = false;     // add an IMAGE_DEBUG_TYPE_REPRO debug entry
    uint32_t    timestamp = 0x65000000;   // a date in 2023
    int         checksumMode = 0;         // 0 correct, 1 wrong, 2 zero
    int         tlsCallbacks = 0;
    bool        writableCode = false;     // code section also writable (RWX)
    size_t      overlayBytes = 0;         // pseudo-random bytes appended after the last section
    std::string pdbPath = "C:\\build\\sample\\sample.pdb";
};

// Build a PE32+ image in memory.
std::vector<uint8_t> BuildSamplePe(const SamplePeSpec& spec);

struct SamplePackResult {
    bool                      ok = false;
    std::wstring              error;
    std::wstring              folder;
    std::wstring              baselinePath;
    std::vector<std::wstring> files;
};

// Create the pack in folder (created if missing; must be empty if it exists).
SamplePackResult CreateSamplePack(const std::wstring& folder);
