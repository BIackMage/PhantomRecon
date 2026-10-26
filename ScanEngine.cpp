#include "pch.h"
#include "ScanEngine.h"

#include "FileAnalysis.h"
#include "GuiComponents.h"
#include "HashUtils.h"
#include "MalwareScoring.h"
#include "RegistryEnumerator.h"
#include "ScoringConfig.h"
#include "StringConv.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[ScanEngine] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
static std::wstring JoinPath(const std::wstring& directory, const wchar_t* fileName)
{
    if (directory.empty()) return fileName;
    if (directory.back() == L'\\') return directory + fileName;
    return directory + L"\\" + fileName;
}

static std::wstring GetScanStateLabel(ScanMode mode)
{
    switch (mode) {
    case ScanMode::Baseline: return L"Baseline Scan Running...";
    case ScanMode::FullScan: return L"Full Scan Running...";
    case ScanMode::FastScan: return L"Fast Scan Running...";
    default:                 return L"Scanning...";
    }
}

std::wstring BaselineStatusToString(BaselineStatus status)
{
    switch (status) {
    case BaselineStatus::Match:   return L"MATCH";
    case BaselineStatus::New:     return L"NEW";
    case BaselineStatus::Changed: return L"CHANGED";
    case BaselineStatus::Missing: return L"MISSING";
    default:                      return L"UNKNOWN";
    }
}

bool IsExecutableExtension(const std::wstring& fileName)
{
    size_t dotPos = fileName.find_last_of(L'.');
    if (dotPos == std::wstring::npos || dotPos == fileName.length() - 1) {
        return false;
    }

    std::wstring ext = fileName.substr(dotPos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

    static const wchar_t* const kExtensions[] = {
        // PE binaries
        L".exe", L".dll", L".com", L".scr", L".sys", L".drv", L".cpl", L".ocx",
        // Installers / packages
        L".msi", L".msp", L".mst",
        // Windows shell scripts
        L".bat", L".cmd", L".ps1", L".psm1", L".psd1",
        // VBScript / JScript (Windows Script Host)
        L".vbs", L".vbe", L".js", L".jse", L".wsf", L".wsh", L".wsc",
        // HTML Application (full trust execution)
        L".hta",
        // Legacy / shortcut-based execution
        L".pif", L".lnk", L".inf", L".reg",
    };

    for (const wchar_t* candidate : kExtensions) {
        if (ext == candidate) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Progress plumbing: scan thread -> UI thread, never the other way
// ---------------------------------------------------------------------------
static void SetCurrentFile(AppState& app, const std::wstring& fileName, const std::wstring& fullPath)
{
    std::lock_guard<std::mutex> lock(app.progress.textMutex);
    app.progress.currentFileName = fileName;
    app.progress.currentFilePath = fullPath;
}

static void SetScanState(AppState& app, const std::wstring& state)
{
    std::lock_guard<std::mutex> lock(app.progress.textMutex);
    app.progress.state = state;
}

// Ask the UI to repaint the operation label. Coalesced: one message in flight.
static void NotifyProgress(AppState& app)
{
    if (!app.progress.progressPosted.exchange(true)) {
        if (!PostMessageW(app.hMainWindow, WM_APP_SCAN_PROGRESS, 0, 0)) {
            app.progress.progressPosted = false;
        }
    }
}

// Queue a finished row for the list view. Coalesced: one message in flight.
static void QueueRow(AppState& app, const BaselineEntry& entry, const std::wstring& status)
{
    {
        std::lock_guard<std::mutex> lock(app.progress.rowsMutex);
        app.progress.pendingRows.push_back(ScanRow{ entry, status });
    }
    if (!app.progress.rowsPosted.exchange(true)) {
        if (!PostMessageW(app.hMainWindow, WM_APP_SCAN_ROWS, 0, 0)) {
            app.progress.rowsPosted = false;
        }
    }
}

static void FinishScan(AppState& app, ScanFinishedPayload* payload)
{
    SetScanState(app, payload->finalState);
    PostPayload(app.hMainWindow, WM_APP_SCAN_FINISHED, payload);
}

static ScanFinishedPayload* MakeFinished(const std::wstring& finalState)
{
    ScanFinishedPayload* p = new ScanFinishedPayload();
    p->finalState = finalState;
    return p;
}

static ScanFinishedPayload* MakeFinishedWithDialog(const std::wstring& finalState,
    const std::wstring& title, const std::wstring& text, UINT icon)
{
    ScanFinishedPayload* p = MakeFinished(finalState);
    p->showDialog = true;
    p->dialogTitle = title;
    p->dialogText = text;
    p->dialogIcon = icon;
    return p;
}

// ---------------------------------------------------------------------------
// CSV output
// ---------------------------------------------------------------------------
static const wchar_t* const kCsvCommonHeader =
    L"Path,File Size,MD5,SHA-256,Signature,Signature Type,Cert Thumbprint,Issuer,Root CA,"
    L"Version,Developer,Read Only,Hidden,Permissions,Entropy,Malware Score,"
    L"Total Imports,Suspicious Imports,Packing Status,RWX Sections,"
    L"Signature Warnings,Packing Indicators";

static std::wstring FormatCsvCommonColumns(const BaselineEntry& entry)
{
    std::wstringstream msStream;
    msStream << entry.malwareScore << L"/10";
    if (entry.suspiciousImports > 0) {
        msStream << L" (" << entry.suspiciousImports << L" suspicious imports)";
    }

    std::wstringstream out;
    out << entry.path << L"," << entry.fileSize << L"," << entry.md5 << L","
        << entry.sha256 << L","
        << entry.signature << L"," << entry.signatureType << L","
        << entry.thumbprint << L"," << entry.issuer << L"," << entry.rootCA << L","
        << entry.version << L"," << entry.developer << L","
        << entry.readOnly << L"," << entry.hidden << L"," << entry.permissions << L","
        << entry.entropy << L"," << msStream.str() << L","
        << entry.totalImports << L"," << entry.suspiciousImports << L","
        << entry.packingStatus << L"," << entry.rwxSections << L","
        << L"\"" << entry.sigWarnings << L"\","
        << L"\"" << entry.packIndicators << L"\"";
    return out.str();
}

// Open the CSV for append and write the header if the file is empty.
// Returns false if the file could not be opened.
static bool OpenCsvForAppend(const std::wstring& outputPath, std::wofstream& out, const wchar_t* header)
{
    out.open(outputPath, std::ios_base::app);
    if (!out.is_open()) {
        DebugLog(L"failed to open CSV for append: " + outputPath);
        return false;
    }
    out.seekp(0, std::ios::end);
    if (out.tellp() == std::streampos(0)) {
        out << header << std::endl;
    }
    return true;
}

void WriteCsvRow(const std::wstring& outputPath, const BaselineEntry& entry)
{
    std::wofstream out;
    if (!OpenCsvForAppend(outputPath, out, kCsvCommonHeader)) return;
    out << FormatCsvCommonColumns(entry) << std::endl;
}

void WriteCsvRowWithComparison(const std::wstring& outputPath, const BaselineEntry& entry,
                               const ComparisonResult& comparison)
{
    static const std::wstring header =
        std::wstring(kCsvCommonHeader) + L",Baseline Status,Change Details,Risk Delta";

    std::wofstream out;
    if (!OpenCsvForAppend(outputPath, out, header.c_str())) return;

    std::wstringstream rdStream;
    if (comparison.riskDelta >= 0) rdStream << L"+";
    rdStream << std::fixed << std::setprecision(1) << comparison.riskDelta;

    out << FormatCsvCommonColumns(entry) << L","
        << BaselineStatusToString(comparison.status) << L","
        << L"\"" << comparison.changeDetails << L"\","
        << rdStream.str()
        << std::endl;
}

// ---------------------------------------------------------------------------
// AnalyzeFile: every analysis pass on one file
// ---------------------------------------------------------------------------
BaselineEntry AnalyzeFile(const std::wstring& fullPath)
{
    DebugLog(L"AnalyzeFile: " + fullPath);

    BaselineEntry entry;
    entry.path = fullPath;
    entry.fileSize = GetFileSizeBytes(fullPath);

    entry.md5 = ComputeFileMD5Hex(fullPath);
    if (entry.md5.empty()) {
        entry.md5 = L"MD5 Checksum Error";
    }

    entry.sha256 = ComputeFileSHA256(fullPath);
    if (entry.sha256.empty()) {
        entry.sha256 = L"SHA256 Checksum Error";
    }

    // Full signature analysis: status, signer, chain, warnings in one pass
    SignatureInfo sigInfo = AnalyzeFileSignature(fullPath);

    entry.signature = sigInfo.status;
    if (sigInfo.signerName != L"N/A") {
        entry.signature += L" (" + sigInfo.signerName + L")";
    }
    entry.signatureType = sigInfo.signatureType;
    entry.thumbprint = sigInfo.thumbprint;
    entry.issuer = sigInfo.issuerName;
    entry.rootCA = sigInfo.rootCA;

    for (size_t w = 0; w < sigInfo.warnings.size(); w++) {
        if (w > 0) entry.sigWarnings += L"; ";
        entry.sigWarnings += sigInfo.warnings[w];
    }

    entry.version = GetFileVersion(fullPath);
    entry.developer = GetFileDeveloper(fullPath);
    entry.readOnly = GetFileReadOnly(fullPath);
    entry.hidden = GetFileHidden(fullPath);
    entry.permissions = GetFilePermissions(fullPath);
    entry.entropy = CalculateFileEntropy(fullPath);

    // Static analysis: imports and composite malware score
    bool isSigned = sigInfo.hashValid && sigInfo.chainTrusted;
    bool isHidden = (entry.hidden == L"Yes");
    std::wstring lowerPath = fullPath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    bool isInTempDir = (lowerPath.find(L"\\temp\\") != std::wstring::npos
        || lowerPath.find(L"\\tmp\\") != std::wstring::npos
        || lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos
        || lowerPath.find(L"\\downloads\\") != std::wstring::npos);

    ImportScanResult importResult = ScanPEImports(fullPath);
    entry.totalImports = importResult.totalImports;
    entry.suspiciousImports = importResult.suspiciousImportCount;

    PackingAnalysisResult packResult = AnalyzePEPacking(fullPath, entry.entropy, importResult.totalImports);

    double malwareScoreValue = CalculateMalwareScore(entry.entropy, isSigned, isHidden, isInTempDir, importResult);

    const ScoringConfig& cfg = GetScoringConfig();
    if (!sigInfo.hashValid && sigInfo.status != L"Unsigned") {
        malwareScoreValue += cfg.anomalies.hash_mismatch;
    }
    if (!sigInfo.chainTrusted && sigInfo.status != L"Unsigned") {
        malwareScoreValue += cfg.anomalies.untrusted_chain;
    }
    if (packResult.isPacked) {
        malwareScoreValue += cfg.anomalies.packing;
    }
    if (packResult.writableExecSections > 0) {
        malwareScoreValue += cfg.anomalies.rwx_sections;
    }
    if (malwareScoreValue > cfg.weights.score_cap) malwareScoreValue = cfg.weights.score_cap;

    entry.malwareScore = malwareScoreValue;
    entry.rwxSections = packResult.writableExecSections;

    if (packResult.isPacked) {
        std::wstringstream ps;
        ps << L"PACKED (" << static_cast<int>(packResult.packingConfidence * 100) << L"% confidence)";
        if (!packResult.detectedPacker.empty()) {
            ps << L" [" << Utf8ToWide(packResult.detectedPacker) << L"]";
        }
        entry.packingStatus = ps.str();
    }
    else {
        entry.packingStatus = L"Not packed";
    }

    for (size_t pi = 0; pi < packResult.indicators.size(); pi++) {
        if (pi > 0) entry.packIndicators += L"; ";
        entry.packIndicators += Utf8ToWide(packResult.indicators[pi]);
    }

    return entry;
}

// ---------------------------------------------------------------------------
// Per-file handling shared by the directory walker and the file-list walker
// ---------------------------------------------------------------------------
static void ProcessExecutable(AppState& app, const std::wstring& fullPath, ScanMode mode,
                              Baseline* baseline, const std::wstring& outputPath)
{
    app.progress.executablesFound++;

    BaselineEntry entry = AnalyzeFile(fullPath);

    if (mode == ScanMode::Baseline) {
        if (baseline) {
            baseline->AddEntry(entry);
        }
        WriteCsvRow(outputPath, entry);
        QueueRow(app, entry, L"BASELINE");
        return;
    }

    if (baseline) {
        ComparisonResult comparison = baseline->CompareEntry(entry);
        baseline->MarkSeen(entry.path);
        WriteCsvRowWithComparison(outputPath, entry, comparison);
        QueueRow(app, entry, BaselineStatusToString(comparison.status));
    }
}

// Recursive directory walk used by Baseline Scan and Full Scan.
static void ScanDirectory(AppState& app, const std::wstring& directory, ScanMode mode,
                          Baseline* baseline, const std::wstring& outputPath)
{
    WIN32_FIND_DATAW findData = {};
    HANDLE hFind = FindFirstFileW(JoinPath(directory, L"*").c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (app.progress.cancelRequested) break;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(findData.cFileName, L".") != 0 && wcscmp(findData.cFileName, L"..") != 0) {
                ScanDirectory(app, JoinPath(directory, findData.cFileName), mode, baseline, outputPath);
            }
            continue;
        }

        app.progress.filesProcessed++;
        std::wstring fullPath = JoinPath(directory, findData.cFileName);
        SetCurrentFile(app, findData.cFileName, fullPath);

        if (IsExecutableExtension(findData.cFileName)) {
            ProcessExecutable(app, fullPath, mode, baseline, outputPath);
        }
        NotifyProgress(app);
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

// Flat file-list walk used by Fast Scan.
static void ScanFileList(AppState& app, const std::vector<std::wstring>& filePaths, ScanMode mode,
                         Baseline* baseline, const std::wstring& outputPath)
{
    DebugLog(L"ScanFileList: scanning " + std::to_wstring(filePaths.size()) + L" files");

    for (const std::wstring& filePath : filePaths) {
        if (app.progress.cancelRequested) break;

        app.progress.filesProcessed++;

        size_t lastSlash = filePath.find_last_of(L'\\');
        std::wstring fileName = (lastSlash != std::wstring::npos) ? filePath.substr(lastSlash + 1) : filePath;
        SetCurrentFile(app, fileName, filePath);

        DWORD attrs = GetFileAttributesW(filePath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            NotifyProgress(app);
            continue;
        }

        if (IsExecutableExtension(filePath)) {
            ProcessExecutable(app, filePath, mode, baseline, outputPath);
        }
        NotifyProgress(app);
    }
}

// Write a MISSING row for every baseline entry the scan never reached.
static size_t ReportMissingEntries(AppState& app, const std::wstring& outputPath)
{
    std::lock_guard<std::mutex> lock(app.baselineMutex);
    std::vector<const BaselineEntry*> missing = app.currentBaseline.GetUnseenEntries();
    for (const BaselineEntry* entry : missing) {
        ComparisonResult missingResult;
        missingResult.status = BaselineStatus::Missing;
        missingResult.changeDetails = L"File missing from disk (was in baseline)";
        missingResult.riskDelta = 0.0;
        WriteCsvRowWithComparison(outputPath, *entry, missingResult);
        QueueRow(app, *entry, L"MISSING");
    }
    return missing.size();
}

// ---------------------------------------------------------------------------
// Scan thread bodies
// ---------------------------------------------------------------------------
static void RunFastScan(AppState& app, const std::wstring& outputPath)
{
    DebugLog(L"Fast Scan thread started");

    std::vector<InstalledProgram> programs = RegistryEnumerator::EnumerateInstalledPrograms();
    DebugLog(L"Fast Scan: found " + std::to_wstring(programs.size()) + L" installed programs");

    std::vector<std::wstring> exePaths = RegistryEnumerator::GetExecutablePathsFromPrograms(programs);
    DebugLog(L"Fast Scan: resolved " + std::to_wstring(exePaths.size()) + L" executable paths");

    // The UI thread loaded currentBaseline before starting us and will not swap it
    // while progress.running is set, so a plain pointer is safe here.
    Baseline* baseline = &app.currentBaseline;
    ScanFileList(app, exePaths, ScanMode::FastScan, baseline, outputPath);

    // A cancelled Fast Scan leaves most baseline entries unseen. The sweep below
    // would then report them all as MISSING. Skip it and label results as partial.
    if (app.progress.cancelRequested) {
        DebugLog(L"Fast Scan cancelled, MISSING sweep skipped (results are partial)");
        FinishScan(app, MakeFinished(L"Fast Scan Cancelled (partial results)"));
        return;
    }

    size_t missing = ReportMissingEntries(app, outputPath);
    DebugLog(L"Fast Scan: " + std::to_wstring(missing) + L" missing entries reported");
    FinishScan(app, MakeFinished(L"Fast Scan Completed!"));
}

static void RunDirectoryScan(AppState& app, ScanMode mode, const std::wstring& directory,
                             const std::wstring& outputPath, const std::wstring& baselineFilePath)
{
    DebugLog(std::wstring(mode == ScanMode::Baseline ? L"Baseline" : L"Full") + L" Scan thread started");

    Baseline scanBaseline;
    Baseline* baselinePtr = nullptr;
    if (mode == ScanMode::Baseline) {
        baselinePtr = &scanBaseline;       // building a new baseline from scratch
    }
    else if (mode == ScanMode::FullScan) {
        baselinePtr = &app.currentBaseline; // comparing against the loaded baseline
    }

    ScanDirectory(app, directory, mode, baselinePtr, outputPath);

    if (mode == ScanMode::Baseline) {
        // A cancelled scan has only walked part of the disk. Writing it would replace
        // the ground truth with a truncated snapshot, and every file that was never
        // reached would be reported as NEW on the next Full Scan. Keep the old file.
        if (app.progress.cancelRequested) {
            DebugLog(L"Baseline Scan cancelled, baseline NOT saved, existing file left untouched");
            FinishScan(app, MakeFinishedWithDialog(L"Baseline Scan Cancelled",
                L"Baseline Scan Cancelled",
                L"Baseline Scan cancelled.\n\nNo baseline was written. Any existing baseline file is unchanged.",
                MB_ICONINFORMATION));
            return;
        }

        if (scanBaseline.SaveToFile(baselineFilePath)) {
            std::wstringstream ss;
            ss << L"Baseline saved: " << scanBaseline.Count() << L" entries\n"
               << L"File: " << baselineFilePath;
            FinishScan(app, MakeFinishedWithDialog(L"Baseline Scan Completed!",
                L"Baseline Scan Complete", ss.str(), MB_ICONINFORMATION));
        }
        else {
            FinishScan(app, MakeFinishedWithDialog(L"Baseline Scan Completed (save failed)",
                L"Error", L"Failed to save baseline file!", MB_ICONERROR));
        }
        return;
    }

    // Full Scan. Same trap as the baseline save: if cancelled, every baseline entry we
    // never reached is still unseen and the sweep would report it as MISSING.
    if (app.progress.cancelRequested) {
        DebugLog(L"Full Scan cancelled, MISSING sweep skipped (results are partial)");
        FinishScan(app, MakeFinished(L"Full Scan Cancelled (partial results)"));
        return;
    }

    size_t missing = ReportMissingEntries(app, outputPath);
    DebugLog(L"Full Scan: " + std::to_wstring(missing) + L" missing entries reported");
    FinishScan(app, MakeFinished(L"Full Scan Completed!"));
}

// ---------------------------------------------------------------------------
// StartScanInBackground: UI thread entry point
// ---------------------------------------------------------------------------
void StartScanInBackground(AppState& app, ScanMode mode, const std::wstring& directory)
{
    ScanProgress& progress = app.progress;
    if (progress.running.exchange(true)) {
        DebugLog(L"StartScanInBackground ignored: a scan is already running");
        return;
    }

    progress.cancelRequested = false;
    progress.filesProcessed = 0;
    progress.executablesFound = 0;
    progress.progressPosted = false;
    progress.rowsPosted = false;
    {
        std::lock_guard<std::mutex> lock(progress.textMutex);
        progress.state = GetScanStateLabel(mode);
        progress.currentFileName.clear();
        progress.currentFilePath.clear();
    }
    {
        std::lock_guard<std::mutex> lock(progress.rowsMutex);
        progress.pendingRows.clear();
    }

    ClearResultRows(app.controls.resultsListView);
    SetProgressMarquee(app.controls.progressBar, true);
    NotifyProgress(app);

    DebugLog(L"StartScanInBackground: launching scan thread");

    // Copy everything the thread needs. It must not read these fields from app later,
    // because the UI thread may change them for the next scan.
    AppState* appPtr = &app;
    std::wstring outputPath = app.outputCsvPath;
    std::wstring baselineFilePath = app.baselineFilePath;

    if (mode == ScanMode::FastScan) {
        app.worker.Run([appPtr, outputPath]() {
            RunFastScan(*appPtr, outputPath);
        });
    }
    else {
        app.worker.Run([appPtr, mode, directory, outputPath, baselineFilePath]() {
            RunDirectoryScan(*appPtr, mode, directory, outputPath, baselineFilePath);
        });
    }
}
