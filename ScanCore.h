#pragma once

#include <functional>
#include <string>
#include <vector>

#include "Baseline.h"
#include "FileAnalysis.h"
#include "ScanTypes.h"

// ---------------------------------------------------------------------------
// ScanCore: the scan engine with no user interface.
//
// The GUI (ScanEngine.cpp) and the command line (CliRunner.cpp) both call
// RunScan. It walks the files, analyses each one, compares against the
// baseline, writes the CSV and reports through callbacks. It never touches a
// window. All callbacks run on the calling thread.
// ---------------------------------------------------------------------------

struct ScanOptions {
    RevocationMode revocation = RevocationMode::CacheOnly;
    std::vector<std::wstring> excludePathPrefixes;   // lowercase absolute prefixes ("c:\\dev\\")
    std::vector<std::wstring> excludeFolderNames;    // lowercase folder names anywhere ("node_modules")
    std::vector<std::wstring> excludeExtensions;     // lowercase with dot (".log")
    bool computeFuzzyHash = true;
    bool precount = true;                            // walk once first so progress can show a percentage
    int  fastScanDepth = 3;
};

// Parse an exclusion list (one entry per line or ';' separated):
//   "*.ext" or ".ext"  -> extension
//   "C:\path" or "\\server\share" -> that folder (and everything in it) or that one file
//   anything else      -> a folder or file with that exact name, anywhere in the path
void ParseExclusions(const std::wstring& text, ScanOptions& options);

// True when the path is excluded. isDirectory skips the extension rule.
bool IsExcluded(const std::wstring& path, bool isDirectory, const ScanOptions& options);

struct ScanCallbacks {
    std::function<bool()> isCancelled;
    std::function<void(const std::wstring& fileName, const std::wstring& fullPath, bool isExecutable)> onFile;
    std::function<void(const ScanRow& row)> onRow;
    std::function<void(int totalFiles)> onTotal;          // after the pre-count
    std::function<void(const std::wstring& phase)> onPhase;
};

struct ScanSummary {
    ScanMode     mode = ScanMode::FullScan;
    std::wstring root;
    std::wstring csvPath;
    std::wstring baselinePath;
    std::wstring startedAt;            // ISO 8601 local time
    double       seconds = 0.0;
    bool         cancelled = false;
    bool         baselineSaved = false;
    bool         baselineSaveFailed = false;
    bool         csvFailed = false;
    size_t       baselineEntries = 0;
    int          totalFiles = 0;       // from the pre-count, 0 when not counted
    int          filesProcessed = 0;
    int          executables = 0;
    int          match = 0, added = 0, changed = 0, missing = 0, updated = 0, known = 0;
    int          highRisk = 0;         // score >= 7
    std::wstring finalState;
};

// Every analysis pass on one file. Thread-safe, no UI.
BaselineEntry AnalyzeFile(const std::wstring& fullPath, const ScanOptions& options);
BaselineEntry AnalyzeFile(const std::wstring& fullPath);

// True for the 28 extensions that can carry or execute code on Windows.
bool IsExecutableExtension(const std::wstring& fileName);

// Count files under root (respecting exclusions). Stops early when cancelled.
int CountFilesUnder(const std::wstring& root, const ScanOptions& options, const std::function<bool()>& isCancelled);

// Run one scan.
//   Every root is normalized first (NormalizeScanRoot) and repeats are dropped. When one
//   root lies inside another, the inner one is walked once, from its own root.
//   Baseline:  walks every root, saves the new baseline to baselineSavePath (not on cancel).
//   FullScan:  walks every root, compares with *comparison, then reports as MISSING the
//              baseline entries under those roots that were not found.
//   FastScan:  scans installed programs from the registry (roots ignored), compares
//              with *comparison.
// csvPath may be empty (no CSV).
ScanSummary RunScan(ScanMode mode, const std::vector<std::wstring>& roots, const std::wstring& csvPath,
                    Baseline* comparison, const std::wstring& baselineSavePath,
                    const ScanOptions& options, const ScanCallbacks& callbacks);

// One root ("" for Fast Scan).
ScanSummary RunScan(ScanMode mode, const std::wstring& root, const std::wstring& csvPath,
                    Baseline* comparison, const std::wstring& baselineSavePath,
                    const ScanOptions& options, const ScanCallbacks& callbacks);

// "C:\A; D:\B\; E:" -> { "C:\A", "D:\B", "E:\" }: trimmed, trailing backslashes dropped,
// a bare drive letter made the drive root, no duplicates.
std::vector<std::wstring> SplitScanRoots(const std::wstring& text);

// One scan root as RunScan uses it: trimmed, "/" as "\", "D:" as "D:\" (the drive, not
// D:'s current folder), absolute, 8.3 short names expanded when the folder exists, and
// no trailing backslash except on a drive root.
std::wstring NormalizeScanRoot(const std::wstring& root);

std::wstring ScanModeName(ScanMode mode);

// Re-read phantom_recon_scoring.ini so edits apply to the next scan without a restart.
void ReloadScoringConfig();
