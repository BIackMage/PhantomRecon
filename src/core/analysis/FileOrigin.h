#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// FileOrigin: where a file came from, according to NTFS.
//
//   - Mark of the Web: the Zone.Identifier stream that browsers and mail
//     clients attach to downloads (zone, host URL, referrer URL).
//   - Other alternate data streams, and whether any of them holds a program
//     or script.
//   - An executable in Downloads or on the Desktop with no download mark,
//     which is what stripping the mark looks like.
// ---------------------------------------------------------------------------

struct AltStream {
    std::wstring name;        // without the leading ':' and trailing ':$DATA'
    int64_t      size = 0;
    bool         executable = false;   // starts with MZ, #!, or common script text
};

// Streams inspected per file. Any user can attach thousands of streams to a
// file; past this many they are only counted.
const size_t kMaxOriginStreamsInspected = 256;

// Per-stream findings (ADS_EXECUTABLE, ADS_PRESENT) listed per file before the
// rest are summed up in one line, so the warning text stays bounded.
const size_t kMaxOriginStreamWarnings = 32;

struct FileOriginInfo {
    int          zoneId = -1;          // -1 when there is no Zone.Identifier
    std::wstring hostUrl;
    std::wstring referrerUrl;
    std::vector<AltStream>    streams;   // excluding Zone.Identifier; the first kMaxOriginStreamsInspected
    int64_t      streamCount = 0;        // every stream excluding Zone.Identifier, inspected or not
    std::vector<std::wstring> warnings;  // "CODE: detail"
};

// isExecutable: the file itself is a program or script (drives the MOTW findings).
FileOriginInfo AnalyzeFileOrigin(const std::wstring& path, bool isExecutable);

// Parse the text of a Zone.Identifier stream (exposed for tests).
void ParseZoneIdentifier(const std::wstring& text, int& zoneId, std::wstring& hostUrl, std::wstring& referrerUrl);

std::wstring ZoneName(int zoneId);
