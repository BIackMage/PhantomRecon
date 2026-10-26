#pragma once

#include "ScanTypes.h"
#include <string>
#include <unordered_map>
#include <vector>

// ---------------------------------------------------------------------------
// Baseline — stores and retrieves a ground-truth snapshot of scanned files.
//
// Binary file format ("PRBL"):
//   [4 bytes]  magic  "PRBL"
//   [4 bytes]  version (uint32)
//   [8 bytes]  entry count (uint64)
//   [8 bytes]  creation timestamp (FILETIME as uint64)
//   [N entries] each entry is length-prefixed wstrings + fixed fields
//   [16 bytes] MD5 checksum of everything above (integrity check)
// ---------------------------------------------------------------------------

class Baseline {
public:
    Baseline();

    // Add or update an entry (path is normalized internally)
    void AddEntry(const BaselineEntry& entry);

    // Lookup by file path (normalized). Returns nullptr if not found.
    const BaselineEntry* FindEntry(const std::wstring& path) const;

    // Mark an entry as "seen" during a comparison scan
    void MarkSeen(const std::wstring& path);

    // Get all entries that were NOT marked as seen (i.e. missing from disk)
    std::vector<const BaselineEntry*> GetUnseenEntries() const;

    // Reset all seen flags (call before starting a comparison scan)
    void ResetSeenFlags();

    // Serialize all entries to a binary file. Returns true on success.
    bool SaveToFile(const std::wstring& filePath) const;

    // Deserialize from a binary file. Returns true on success.
    bool LoadFromFile(const std::wstring& filePath);

    // Number of entries currently stored
    size_t Count() const;

    // Compare a current file's entry against the baseline.
    // Returns a ComparisonResult describing what changed (or if it's new).
    ComparisonResult CompareEntry(const BaselineEntry& current) const;

    // Get the creation timestamp as a readable string
    std::wstring GetCreationTimeString() const;

    // Get the age of the baseline in days. Returns -1 if no timestamp.
    int GetAgeDays() const;

    // Check if baseline is older than the given number of days.
    bool IsOlderThan(int days) const;

    // Write a length-prefixed wstring to a buffer (public for serialization helpers)
    static void WriteString(std::vector<BYTE>& buffer, const std::wstring& str);

    // Read a length-prefixed wstring from a buffer at the given offset.
    // Advances offset past the string. Returns false on underflow.
    static bool ReadString(const std::vector<BYTE>& buffer, size_t& offset, std::wstring& out);

private:
    // Normalize a path for consistent lookup (lowercase, single backslashes)
    static std::wstring NormalizePath(const std::wstring& path);

    struct InternalEntry {
        BaselineEntry data;
        bool          seen;   // used during comparison scans
    };

    std::unordered_map<std::wstring, InternalEntry> m_entries;
    uint64_t m_creationTime;

    static const uint32_t BASELINE_VERSION = 2;  // v2 adds SHA-256 field
    static const char     BASELINE_MAGIC[4];
};
