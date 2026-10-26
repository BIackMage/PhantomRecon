#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Scan mode: determines behaviour of the scan engine
// ---------------------------------------------------------------------------
enum class ScanMode {
    Baseline,   // Full recursive scan, saves results as ground truth
    FullScan,   // Full recursive scan, compares against saved baseline
    FastScan    // Registry-enumerated installed programs only, compares against baseline
};

// ---------------------------------------------------------------------------
// BaselineEntry: everything known about one scanned file.
// Field order mirrors the CSV columns. Fields marked v3 were added in baseline
// format version 3; older baselines load them with the defaults shown here.
// ---------------------------------------------------------------------------
struct BaselineEntry {
    std::wstring path;
    int64_t      fileSize = 0;
    std::wstring md5;
    std::wstring sha256;
    std::wstring signature;
    std::wstring signatureType;
    std::wstring thumbprint;
    std::wstring issuer;
    std::wstring rootCA;
    std::wstring version;
    std::wstring developer;
    std::wstring readOnly;
    std::wstring hidden;
    std::wstring permissions;
    double       entropy = 0.0;
    double       malwareScore = 0.0;
    int          totalImports = 0;
    int          suspiciousImports = 0;
    std::wstring packingStatus;
    int          rwxSections = 0;
    std::wstring sigWarnings;
    std::wstring packIndicators;

    // --- v3 ---
    std::wstring catalogSigner;          // signer of the security catalog covering the file
    std::wstring revocation;             // Not checked / Good / REVOKED / Unknown (offline)
    std::wstring imphash;                // MD5 of the ordered import list (pefile format)
    std::wstring ssdeep;                 // context-triggered piecewise hash
    int          zoneId = -1;            // Mark of the Web zone, -1 when absent
    std::wstring zoneHostUrl;
    std::wstring zoneReferrerUrl;
    std::wstring altStreams;             // other named NTFS streams: "name (bytes)"; "; " joined
    std::wstring originWarnings;         // MOTW / stream findings, "; " joined codes
    uint32_t     peTimestamp = 0;
    std::wstring peAnomalies;            // header anomaly findings, "; " joined codes
    int64_t      overlaySize = 0;
    double       overlayEntropy = 0.0;
    int          tlsCallbacks = 0;
    std::wstring pdbPath;
    double       scriptScore = 0.0;
    std::wstring scriptIndicators;       // "; " joined codes
    std::wstring attackIds;              // MITRE ATT&CK technique ids, ", " joined
    bool         knownGood = false;      // SHA-256 is in the local known-good list
};

// ---------------------------------------------------------------------------
// Comparison status when checking a file against the baseline
// ---------------------------------------------------------------------------
enum class BaselineStatus {
    Match,      // identical key fields
    New,        // not in the baseline
    Changed,    // in the baseline, key fields differ
    Missing,    // in the baseline, gone from disk
    Updated,    // changed, and the new file is a valid Microsoft-signed update
    Known       // not in the baseline, but Microsoft-signed or on the known-good list
};

// ---------------------------------------------------------------------------
// ComparisonResult: outcome of comparing one file to the baseline
// ---------------------------------------------------------------------------
struct ComparisonResult {
    BaselineStatus status = BaselineStatus::Match;
    std::wstring   changeDetails;   // human-readable list of what changed
    double         riskDelta = 0.0; // malwareScore(now) - malwareScore(baseline)
};

// ---------------------------------------------------------------------------
// ScanRow: one result row as shown in the list, the CSV and the reports.
// ---------------------------------------------------------------------------
struct ScanRow {
    BaselineEntry entry;
    std::wstring  status;          // BASELINE, MATCH, NEW, CHANGED, MISSING, UPDATED, KNOWN, LOADED
    std::wstring  changeDetails;
    double        riskDelta = 0.0;
};
