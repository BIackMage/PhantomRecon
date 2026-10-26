#pragma once

#include "ScanTypes.h"
#include <windows.h>
#include <string>
#include <unordered_map>
#include <vector>

// ---------------------------------------------------------------------------
// Baseline: stores and retrieves a ground-truth snapshot of scanned files.
//
// Binary file format ("PRBL"):
//   [4 bytes]  magic  "PRBL"
//   [4 bytes]  version (uint32)        1, 2 or 3; this build writes 3
//   [8 bytes]  entry count (uint64)
//   [8 bytes]  creation timestamp (FILETIME as uint64)
//   [N entries] each entry is length-prefixed wstrings + fixed fields
//   [16 bytes] MD5 checksum of everything above (integrity check)
//
// v2 added SHA-256. v3 appends a block per entry with catalog signer,
// revocation, imphash, fuzzy hash, Mark of the Web, streams, PE header facts,
// script indicators, ATT&CK ids and the known-good flag.
// ---------------------------------------------------------------------------

class Baseline {
public:
    Baseline();

    void AddEntry(const BaselineEntry& entry);
    const BaselineEntry* FindEntry(const std::wstring& path) const;

    void MarkSeen(const std::wstring& path);
    std::vector<const BaselineEntry*> GetUnseenEntries() const;
    void ResetSeenFlags();

    // Every entry, in no particular order.
    std::vector<const BaselineEntry*> AllEntries() const;

    bool SaveToFile(const std::wstring& filePath) const;
    // Write an older format version (tests use this to prove upgrades work).
    bool SaveToFile(const std::wstring& filePath, uint32_t version) const;
    bool LoadFromFile(const std::wstring& filePath);

    size_t Count() const;
    void Clear();

    // Compare a current file's entry against the baseline.
    ComparisonResult CompareEntry(const BaselineEntry& current) const;

    std::wstring GetCreationTimeString() const;
    uint64_t GetCreationTime() const { return m_creationTime; }
    void SetCreationTime(uint64_t fileTime) { m_creationTime = fileTime; }
    int GetAgeDays() const;
    bool IsOlderThan(int days) const;

    // Format version of the last file loaded (0 when built in memory).
    uint32_t LoadedVersion() const { return m_loadedVersion; }

    static void WriteString(std::vector<BYTE>& buffer, const std::wstring& str);
    static bool ReadString(const std::vector<BYTE>& buffer, size_t& offset, std::wstring& out);

    static std::wstring NormalizePath(const std::wstring& path);

    static const uint32_t BASELINE_VERSION = 3;

private:
    struct InternalEntry {
        BaselineEntry data;
        bool          seen = false;
    };

    std::unordered_map<std::wstring, InternalEntry> m_entries;
    uint64_t m_creationTime;
    uint32_t m_loadedVersion = 0;

    static const char BASELINE_MAGIC[4];
};

// True when the entry is validly signed by Microsoft (embedded or catalog).
bool IsMicrosoftSignedEntry(const BaselineEntry& entry);

std::wstring BaselineStatusName(BaselineStatus status);

// Compare two baselines. Every path in either one produces a row: NEW (only in
// newer), MISSING (only in older), CHANGED / UPDATED (in both, different), or
// MATCH. includeMatches controls whether MATCH rows are returned.
std::vector<ScanRow> DiffBaselines(const Baseline& older, const Baseline& newer, bool includeMatches);
