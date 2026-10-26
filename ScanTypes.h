#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Scan mode — determines behavior of the scan engine
// ---------------------------------------------------------------------------
enum class ScanMode {
    Baseline,   // Full recursive scan, saves results as ground truth
    FullScan,   // Full recursive scan, compares against saved baseline
    FastScan    // Registry-enumerated installed programs only, compares against baseline
};

// ---------------------------------------------------------------------------
// BaselineEntry — one row of data for a scanned file (mirrors CSV columns)
// ---------------------------------------------------------------------------
struct BaselineEntry {
    std::wstring path;
    int64_t      fileSize;
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
    double       entropy;
    double       malwareScore;
    int          totalImports;
    int          suspiciousImports;
    std::wstring packingStatus;
    int          rwxSections;
    std::wstring sigWarnings;
    std::wstring packIndicators;
};

// ---------------------------------------------------------------------------
// Comparison status when checking a file against the baseline
// ---------------------------------------------------------------------------
enum class BaselineStatus {
    Match,      // File exists in baseline with identical key fields
    New,        // File not found in baseline
    Changed,    // File exists in baseline but key fields differ
    Missing     // File was in baseline but not found on disk
};

// ---------------------------------------------------------------------------
// ComparisonResult — the outcome of comparing one file to the baseline
// ---------------------------------------------------------------------------
struct ComparisonResult {
    BaselineStatus status;
    std::wstring   changeDetails;   // human-readable list of what changed
    double         riskDelta;       // malwareScore(now) - malwareScore(baseline)
};
