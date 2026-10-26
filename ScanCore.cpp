#include "pch.h"
#include "ScanCore.h"

#include "AppPaths.h"
#include "AttackMapping.h"
#include "FileOrigin.h"
#include "FuzzyHash.h"
#include "HashUtils.h"
#include "KnownGood.h"
#include "MalwareScoring.h"
#include "PeFile.h"
#include "RegistryEnumerator.h"
#include "ScanCsv.h"
#include "ScoringConfig.h"
#include "ScriptAnalysis.h"
#include "StringConv.h"
#include "TextUtils.h"

#include <windows.h>
#include <algorithm>
#include <ctime>
#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[ScanCore] " + msg + L"\n").c_str());
}

std::wstring ScanModeName(ScanMode mode)
{
    switch (mode) {
    case ScanMode::Baseline: return L"Baseline Scan";
    case ScanMode::FullScan: return L"Full Scan";
    case ScanMode::FastScan: return L"Fast Scan";
    default:                 return L"Scan";
    }
}

void ReloadScoringConfig()
{
    std::wstring path = AppFilePath(L"phantom_recon_scoring.ini");
    ScoringConfig& cfg = GetScoringConfig();
    if (FileExists(path)) {
        cfg.ResetToDefaults();
        cfg.LoadFromFile(path);
    }
}

// ---------------------------------------------------------------------------
// Exclusions
// ---------------------------------------------------------------------------
void ParseExclusions(const std::wstring& text, ScanOptions& options)
{
    for (const std::wstring& raw : SplitAnyW(text, L";\r\n")) {
        std::wstring item = ToLowerW(TrimW(raw));
        if (item.empty()) continue;
        if (item.rfind(L"*.", 0) == 0) {
            options.excludeExtensions.push_back(item.substr(1));
        }
        else if (item[0] == L'.') {
            options.excludeExtensions.push_back(item);
        }
        else if ((item.size() >= 3 && item[1] == L':' && item[2] == L'\\') || item.rfind(L"\\\\", 0) == 0) {
            std::wstring prefix = item;
            if (prefix.back() != L'\\') prefix += L'\\';
            options.excludePathPrefixes.push_back(prefix);
        }
        else {
            std::wstring name = item;
            while (!name.empty() && (name.front() == L'\\' || name.front() == L'*')) name.erase(name.begin());
            while (!name.empty() && (name.back() == L'\\' || name.back() == L'*')) name.pop_back();
            if (!name.empty()) options.excludeFolderNames.push_back(name);
        }
    }
}

bool IsExcluded(const std::wstring& path, bool isDirectory, const ScanOptions& options)
{
    if (options.excludePathPrefixes.empty() && options.excludeFolderNames.empty() && options.excludeExtensions.empty()) {
        return false;
    }
    std::wstring lower = ToLowerW(path);
    std::wstring withSlash = lower;
    if (isDirectory && !withSlash.empty() && withSlash.back() != L'\\') withSlash += L'\\';

    for (const std::wstring& prefix : options.excludePathPrefixes) {
        if (withSlash.rfind(prefix, 0) == 0) return true;
    }
    for (const std::wstring& name : options.excludeFolderNames) {
        std::wstring needle = L"\\" + name + L"\\";
        if (withSlash.find(needle) != std::wstring::npos) return true;
    }
    if (!isDirectory) {
        std::wstring ext = ExtensionOf(lower);
        for (const std::wstring& e : options.excludeExtensions) {
            if (ext == e) return true;
        }
    }
    return false;
}

bool IsExecutableExtension(const std::wstring& fileName)
{
    static const wchar_t* const kExtensions[] = {
        L".exe", L".dll", L".com", L".scr", L".sys", L".drv", L".cpl", L".ocx",
        L".msi", L".msp", L".mst",
        L".bat", L".cmd", L".ps1", L".psm1", L".psd1",
        L".vbs", L".vbe", L".js", L".jse", L".wsf", L".wsh", L".wsc",
        L".hta",
        L".pif", L".lnk", L".inf", L".reg",
    };
    std::wstring ext = ExtensionOf(fileName);
    if (ext.empty()) return false;
    for (const wchar_t* candidate : kExtensions) {
        if (ext == candidate) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// AnalyzeFile
// ---------------------------------------------------------------------------
static std::wstring JoinCodes(const std::vector<std::wstring>& items)
{
    return JoinW(items, L"; ");
}

static bool HasCode(const std::vector<std::wstring>& items, const std::wstring& code)
{
    for (const std::wstring& item : items) {
        if (IndicatorCode(item) == code) return true;
    }
    return false;
}

static bool HasRightToLeftOverride(const std::wstring& path)
{
    return path.find(static_cast<wchar_t>(0x202E)) != std::wstring::npos;
}

BaselineEntry AnalyzeFile(const std::wstring& fullPath)
{
    ScanOptions defaults;
    defaults.revocation = RevocationMode::Off;
    return AnalyzeFile(fullPath, defaults);
}

BaselineEntry AnalyzeFile(const std::wstring& fullPath, const ScanOptions& options)
{
    DebugLog(L"AnalyzeFile: " + fullPath);

    const std::wstring ioPath = ToExtendedPath(fullPath);
    const std::wstring ext = ExtensionOf(fullPath);
    const ScoringConfig& cfg = GetScoringConfig();

    BaselineEntry entry;
    entry.path = fullPath;
    entry.fileSize = GetFileSizeBytes(ioPath);

    entry.md5 = ComputeFileMD5Hex(ioPath);
    if (entry.md5.empty()) entry.md5 = L"MD5 Checksum Error";
    entry.sha256 = ComputeFileSHA256(ioPath);
    if (entry.sha256.empty()) entry.sha256 = L"SHA256 Checksum Error";
    entry.knownGood = IsKnownGoodHash(entry.sha256);

    // Signature
    SignatureInfo sigInfo = AnalyzeFileSignature(ioPath, options.revocation);
    entry.signature = sigInfo.status;
    if (sigInfo.signerName != L"N/A") entry.signature += L" (" + sigInfo.signerName + L")";
    entry.signatureType = sigInfo.signatureType;
    entry.thumbprint = sigInfo.thumbprint;
    entry.issuer = sigInfo.issuerName;
    entry.rootCA = sigInfo.rootCA;
    entry.catalogSigner = sigInfo.catalogSigner;
    entry.revocation = sigInfo.revocation;

    std::vector<std::wstring> sigWarnings = sigInfo.warnings;
    if (HasRightToLeftOverride(fullPath)) {
        sigWarnings.push_back(L"RLO_FILENAME: File name contains a right-to-left override character");
    }
    entry.sigWarnings = JoinCodes(sigWarnings);

    // Version, attributes, entropy
    entry.version = GetFileVersion(ioPath);
    entry.developer = GetFileDeveloper(ioPath);
    entry.readOnly = GetFileReadOnly(ioPath);
    entry.hidden = GetFileHidden(ioPath);
    entry.permissions = GetFilePermissions(ioPath);
    entry.entropy = CalculateFileEntropy(ioPath);

    // PE structure (one mapping for imports, packing, anomalies, imphash)
    PeInfo pe = ParsePeFile(fullPath);
    ImportScanResult importResult = ScanPEImports(pe);
    entry.totalImports = importResult.totalImports;
    entry.suspiciousImports = importResult.suspiciousImportCount;

    PackingAnalysisResult packResult = AnalyzePEPacking(pe, entry.entropy, importResult.totalImports);
    entry.rwxSections = packResult.writableExecSections;
    if (packResult.isPacked) {
        std::wstringstream ps;
        ps << L"PACKED (" << static_cast<int>(packResult.packingConfidence * 100) << L"% confidence)";
        if (!packResult.detectedPacker.empty()) ps << L" [" << Utf8ToWide(packResult.detectedPacker) << L"]";
        entry.packingStatus = ps.str();
    }
    else {
        entry.packingStatus = pe.valid ? L"Not packed" : L"Not a PE file";
    }
    std::vector<std::wstring> packIndicators;
    for (const std::string& s : packResult.indicators) packIndicators.push_back(Utf8ToWide(s));
    entry.packIndicators = JoinCodes(packIndicators);

    std::vector<std::wstring> peAnomalies;
    if (pe.valid) {
        entry.imphash = ComputeImphash(pe);
        entry.peTimestamp = pe.timestamp;
        entry.overlaySize = pe.overlaySize;
        entry.overlayEntropy = pe.overlayEntropy;
        entry.tlsCallbacks = static_cast<int>(pe.tlsCallbackCount);
        entry.pdbPath = Utf8ToWide(pe.pdbPath);
        peAnomalies = FindPeAnomalies(pe, ToLowerW(fullPath), static_cast<int64_t>(time(nullptr)));
        if (pe.isDotNet) peAnomalies.push_back(L"DOTNET: .NET assembly");
    }
    entry.peAnomalies = JoinCodes(peAnomalies);

    if (options.computeFuzzyHash) {
        entry.ssdeep = ComputeFuzzyHashFile(ioPath);
    }

    // Origin
    FileOriginInfo origin = AnalyzeFileOrigin(fullPath, IsExecutableExtension(fullPath));
    entry.zoneId = origin.zoneId;
    entry.zoneHostUrl = origin.hostUrl;
    entry.zoneReferrerUrl = origin.referrerUrl;
    {
        std::vector<std::wstring> streams;
        for (const AltStream& s : origin.streams) streams.push_back(s.name + L" (" + std::to_wstring(s.size) + L")");
        entry.altStreams = JoinW(streams, L"; ");
    }
    entry.originWarnings = JoinCodes(origin.warnings);

    // Scripts
    ScriptAnalysisResult script;
    if (IsScriptExtension(ext)) {
        script = AnalyzeScriptFile(ioPath);
        entry.scriptScore = script.score;
        entry.scriptIndicators = JoinCodes(script.indicators);
    }

    // --- Composite score ---
    bool isSigned = sigInfo.hashValid && sigInfo.chainTrusted;
    bool isHidden = (entry.hidden == L"Yes");
    std::wstring lowerPath = ToLowerW(fullPath);
    bool isInTempDir = (lowerPath.find(L"\\temp\\") != std::wstring::npos
        || lowerPath.find(L"\\tmp\\") != std::wstring::npos
        || lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos
        || lowerPath.find(L"\\downloads\\") != std::wstring::npos);

    double score = CalculateMalwareScore(entry.entropy, isSigned, isHidden, isInTempDir, importResult);

    if (!sigInfo.hashValid && sigInfo.status != L"Unsigned") score += cfg.anomalies.hash_mismatch;
    if (!sigInfo.chainTrusted && sigInfo.status != L"Unsigned") score += cfg.anomalies.untrusted_chain;
    if (packResult.isPacked) score += cfg.anomalies.packing;
    if (packResult.writableExecSections > 0) score += cfg.anomalies.rwx_sections;
    if (sigInfo.revocation == L"REVOKED") score += cfg.revocation.revoked;
    if (HasRightToLeftOverride(fullPath)) score += cfg.peAnomalies.rlo_filename;

    // Origin bumps
    if (origin.zoneId == 3 && !isSigned) score += cfg.origin.internet_unsigned;
    if (origin.zoneId == 4) score += cfg.origin.restricted_zone;
    if (HasCode(origin.warnings, L"ADS_EXECUTABLE")) score += cfg.origin.executable_stream;
    if (HasCode(origin.warnings, L"MOTW_MISSING")) score += cfg.origin.motw_missing;

    // Header anomalies count only when the file is not validly signed: signed
    // builds routinely use TLS callbacks and overlays (installers).
    if (!isSigned) {
        if (HasCode(peAnomalies, L"TIMESTAMP_FUTURE") || HasCode(peAnomalies, L"TIMESTAMP_ZERO") ||
            HasCode(peAnomalies, L"TIMESTAMP_ANCIENT")) score += cfg.peAnomalies.timestamp;
        if (HasCode(peAnomalies, L"CHECKSUM_MISMATCH")) score += cfg.peAnomalies.checksum_mismatch;
        if (HasCode(peAnomalies, L"TLS_CALLBACKS")) score += cfg.peAnomalies.tls_callbacks;
        if (HasCode(peAnomalies, L"OVERLAY_HIGH_ENTROPY")) score += cfg.peAnomalies.overlay_high_entropy;
        if (HasCode(peAnomalies, L"OVERLAY_EMBEDDED_PE")) score += cfg.peAnomalies.overlay_embedded_pe;
        if (HasCode(peAnomalies, L"PDB_SUSPICIOUS_WORDS")) score += cfg.peAnomalies.pdb_suspicious;
        if (HasCode(peAnomalies, L"SECTION_COUNT_HIGH") || HasCode(peAnomalies, L"SECTION_NAME_ODD")) {
            score += cfg.peAnomalies.section_oddities;
        }
    }

    if (script.analyzed && script.score > 0) {
        score += (std::min)(script.score * cfg.script.weight_multiplier, cfg.script.score_cap);
    }

    if (score < 0.0) score = 0.0;
    if (score > cfg.weights.score_cap) score = cfg.weights.score_cap;
    entry.malwareScore = score;

    // --- ATT&CK techniques ---
    std::vector<std::wstring> techniques;
    AddUniqueTechniques(techniques, importResult.techniques);
    if (packResult.isPacked) AddUniqueTechniques(techniques, { L"T1027.002" });
    if (packResult.writableExecSections > 0) AddUniqueTechniques(techniques, { L"T1055" });
    auto addFromCodes = [&techniques](const std::vector<std::wstring>& items) {
        for (const std::wstring& item : items) {
            std::wstring t = AttackTechniqueForCode(IndicatorCode(item));
            if (!t.empty()) AddUniqueTechniques(techniques, { t });
        }
    };
    addFromCodes(sigWarnings);
    if (!isSigned) addFromCodes(peAnomalies);
    addFromCodes(origin.warnings);
    AddUniqueTechniques(techniques, script.techniques);
    if (isHidden) AddUniqueTechniques(techniques, { L"T1564.001" });
    entry.attackIds = JoinW(techniques, L", ");

    return entry;
}

// ---------------------------------------------------------------------------
// Walkers
// ---------------------------------------------------------------------------
int CountFilesUnder(const std::wstring& root, const ScanOptions& options, const std::function<bool()>& isCancelled)
{
    int count = 0;
    std::vector<std::wstring> stack = { root };
    while (!stack.empty()) {
        if (isCancelled && isCancelled()) return count;
        std::wstring dir = stack.back();
        stack.pop_back();

        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileExW(ToExtendedPath(JoinPath(dir, L"*")).c_str(), FindExInfoBasic, &fd,
            FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
        if (hFind == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;   // junctions loop
                std::wstring sub = JoinPath(dir, fd.cFileName);
                if (!IsExcluded(sub, true, options)) stack.push_back(sub);
            }
            else if (!IsExcluded(JoinPath(dir, fd.cFileName), false, options)) {
                count++;
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    return count;
}

struct ScanContext {
    ScanMode            mode;
    Baseline*           comparison;
    Baseline*           building;
    CsvWriter*          csv;
    const ScanOptions*  options;
    const ScanCallbacks* callbacks;
    ScanSummary*        summary;
};

static bool Cancelled(const ScanContext& ctx)
{
    return ctx.callbacks->isCancelled && ctx.callbacks->isCancelled();
}

static void Emit(ScanContext& ctx, const ScanRow& row)
{
    if (ctx.csv && ctx.csv->IsOpen()) ctx.csv->Write(row);
    ScanSummary& s = *ctx.summary;
    if (row.status == L"MATCH") s.match++;
    else if (row.status == L"NEW") s.added++;
    else if (row.status == L"CHANGED") s.changed++;
    else if (row.status == L"MISSING") s.missing++;
    else if (row.status == L"UPDATED") s.updated++;
    else if (row.status == L"KNOWN") s.known++;
    if (row.entry.malwareScore >= 7.0 && row.status != L"MISSING") s.highRisk++;
    if (ctx.callbacks->onRow) ctx.callbacks->onRow(row);
}

static void ProcessFile(ScanContext& ctx, const std::wstring& fileName, const std::wstring& fullPath)
{
    bool executable = IsExecutableExtension(fileName);
    ctx.summary->filesProcessed++;
    if (ctx.callbacks->onFile) ctx.callbacks->onFile(fileName, fullPath, executable);
    if (!executable) return;

    ctx.summary->executables++;
    BaselineEntry entry = AnalyzeFile(fullPath, *ctx.options);

    ScanRow row;
    row.entry = entry;
    if (ctx.mode == ScanMode::Baseline) {
        if (ctx.building) ctx.building->AddEntry(entry);
        row.status = L"BASELINE";
    }
    else if (ctx.comparison) {
        ComparisonResult cmp = ctx.comparison->CompareEntry(entry);
        ctx.comparison->MarkSeen(entry.path);
        row.status = BaselineStatusName(cmp.status);
        row.changeDetails = cmp.changeDetails;
        row.riskDelta = cmp.riskDelta;
    }
    else {
        row.status = L"NEW";
    }
    Emit(ctx, row);
}

static void WalkDirectory(ScanContext& ctx, const std::wstring& root)
{
    std::vector<std::wstring> stack = { root };
    while (!stack.empty()) {
        if (Cancelled(ctx)) return;
        std::wstring dir = stack.back();
        stack.pop_back();

        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileExW(ToExtendedPath(JoinPath(dir, L"*")).c_str(), FindExInfoBasic, &fd,
            FindExSearchNameMatch, NULL, FIND_FIRST_EX_LARGE_FETCH);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        std::vector<std::wstring> subdirs;
        do {
            if (Cancelled(ctx)) break;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
                std::wstring sub = JoinPath(dir, fd.cFileName);
                if (!IsExcluded(sub, true, *ctx.options)) subdirs.push_back(sub);
            }
            else {
                std::wstring full = JoinPath(dir, fd.cFileName);
                if (IsExcluded(full, false, *ctx.options)) continue;
                ProcessFile(ctx, fd.cFileName, full);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);

        // Push in reverse so folders are visited in directory order.
        for (auto it = subdirs.rbegin(); it != subdirs.rend(); ++it) stack.push_back(*it);
    }
}

// limitToDirs: when not empty, only baseline entries whose folder is in this set
// (lowercase, no trailing slash) are considered. Fast Scan uses it so that files
// outside the program folders it looked at are not reported as missing.
static void ReportMissing(ScanContext& ctx, const std::vector<std::wstring>& limitToDirs)
{
    if (!ctx.comparison) return;
    for (const BaselineEntry* entry : ctx.comparison->GetUnseenEntries()) {
        if (IsExcluded(entry->path, false, *ctx.options)) continue;
        if (!limitToDirs.empty()) {
            std::wstring dir = ToLowerW(DirectoryOf(entry->path));
            if (!std::binary_search(limitToDirs.begin(), limitToDirs.end(), dir)) continue;
        }
        ScanRow row;
        row.entry = *entry;
        row.status = L"MISSING";
        row.changeDetails = L"File missing from disk (was in baseline)";
        row.riskDelta = 0.0;
        Emit(ctx, row);
    }
}

static std::wstring NowIso()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[40];
    swprintf_s(buf, L"%04u-%02u-%02uT%02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

ScanSummary RunScan(ScanMode mode, const std::wstring& root, const std::wstring& csvPath,
                    Baseline* comparison, const std::wstring& baselineSavePath,
                    const ScanOptions& options, const ScanCallbacks& callbacks)
{
    ScanSummary summary;
    summary.mode = mode;
    summary.root = root;
    summary.csvPath = csvPath;
    summary.baselinePath = baselineSavePath;
    summary.startedAt = NowIso();
    ULONGLONG started = GetTickCount64();

    ReloadScoringConfig();

    CsvWriter csv;
    if (!csvPath.empty() && !csv.Open(csvPath)) {
        summary.csvFailed = true;
    }

    Baseline building;
    ScanContext ctx{ mode, comparison, mode == ScanMode::Baseline ? &building : nullptr, &csv, &options, &callbacks, &summary };
    if (comparison) comparison->ResetSeenFlags();

    std::vector<std::wstring> fastScanDirs;
    if (mode == ScanMode::FastScan) {
        if (callbacks.onPhase) callbacks.onPhase(L"Finding installed programs...");
        std::vector<InstalledProgram> programs = RegistryEnumerator::EnumerateInstalledPrograms();
        std::vector<std::wstring> paths = RegistryEnumerator::GetExecutablePathsFromPrograms(programs, options.fastScanDepth);
        for (const std::wstring& p : paths) fastScanDirs.push_back(ToLowerW(DirectoryOf(p)));
        std::sort(fastScanDirs.begin(), fastScanDirs.end());
        fastScanDirs.erase(std::unique(fastScanDirs.begin(), fastScanDirs.end()), fastScanDirs.end());
        summary.totalFiles = static_cast<int>(paths.size());
        if (callbacks.onTotal) callbacks.onTotal(summary.totalFiles);
        if (callbacks.onPhase) callbacks.onPhase(ScanModeName(mode) + L" Running...");
        for (const std::wstring& path : paths) {
            if (Cancelled(ctx)) break;
            if (IsExcluded(path, false, options)) continue;
            DWORD attrs = GetFileAttributesW(ToExtendedPath(path).c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                summary.filesProcessed++;
                if (callbacks.onFile) callbacks.onFile(FileNameOf(path), path, false);
                continue;
            }
            ProcessFile(ctx, FileNameOf(path), path);
        }
    }
    else {
        if (options.precount) {
            if (callbacks.onPhase) callbacks.onPhase(L"Counting files...");
            summary.totalFiles = CountFilesUnder(root, options, callbacks.isCancelled);
            if (callbacks.onTotal) callbacks.onTotal(summary.totalFiles);
        }
        if (callbacks.onPhase) callbacks.onPhase(ScanModeName(mode) + L" Running...");
        WalkDirectory(ctx, root);
    }

    summary.cancelled = Cancelled(ctx);

    if (mode == ScanMode::Baseline) {
        // A cancelled scan has only walked part of the disk. Writing it would replace
        // the ground truth with a truncated snapshot. Keep the old file.
        if (!summary.cancelled) {
            if (building.SaveToFile(baselineSavePath)) {
                summary.baselineSaved = true;
                summary.baselineEntries = building.Count();
            }
            else {
                summary.baselineSaveFailed = true;
            }
        }
    }
    else if (!summary.cancelled) {
        // A cancelled comparison never reached most entries; reporting them as MISSING
        // would be false, so only a complete scan runs the sweep. Fast Scan sweeps only
        // the program folders it scanned, because the baseline usually covers far more.
        if (mode == ScanMode::FullScan) {
            ReportMissing(ctx, {});
        }
        else if (!fastScanDirs.empty()) {
            ReportMissing(ctx, fastScanDirs);
        }
    }

    csv.Close();
    SaveRevocationCache();

    summary.seconds = static_cast<double>(GetTickCount64() - started) / 1000.0;
    if (summary.cancelled) {
        summary.finalState = ScanModeName(mode) + (mode == ScanMode::Baseline ? L" Cancelled" : L" Cancelled (partial results)");
    }
    else if (summary.baselineSaveFailed) {
        summary.finalState = ScanModeName(mode) + L" Completed (save failed)";
    }
    else {
        summary.finalState = ScanModeName(mode) + L" Completed!";
    }
    DebugLog(summary.finalState + L" in " + FormatFixed(summary.seconds, 1) + L" s, " +
        std::to_wstring(summary.executables) + L" executables");
    return summary;
}
