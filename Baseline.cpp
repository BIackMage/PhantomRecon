#include "pch.h"
#include "Baseline.h"

#include "FileAnalysis.h"
#include "FuzzyHash.h"
#include "TextUtils.h"

#include <fstream>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <wincrypt.h>
#include <ctime>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "advapi32.lib")

// Static member initialization
const char Baseline::BASELINE_MAGIC[4] = { 'P', 'R', 'B', 'L' };

// ---------------------------------------------------------------------------
// Debug logging helper
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[Baseline] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

static void DebugLog(const std::wstring& msg)
{
    DebugLog(msg.c_str());
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
Baseline::Baseline()
    : m_creationTime(0)
{
}

// ---------------------------------------------------------------------------
// NormalizePath — lowercase + collapse double backslashes
// ---------------------------------------------------------------------------
std::wstring Baseline::NormalizePath(const std::wstring& path)
{
    std::wstring norm = path;

    // Lowercase
    std::transform(norm.begin(), norm.end(), norm.begin(), ::towlower);

    // Collapse double backslashes
    size_t pos = norm.find(L"\\\\");
    while (pos != std::wstring::npos) {
        norm.replace(pos, 2, L"\\");
        pos = norm.find(L"\\\\", pos);
    }

    // Remove trailing backslash unless it's a root like "C:\"
    if (norm.size() > 3 && norm.back() == L'\\') {
        norm.pop_back();
    }

    return norm;
}

// ---------------------------------------------------------------------------
// WriteString — length-prefixed wstring into byte buffer
// Format: [uint32 charCount][charCount * wchar_t]
// ---------------------------------------------------------------------------
void Baseline::WriteString(std::vector<BYTE>& buffer, const std::wstring& str)
{
    uint32_t charCount = static_cast<uint32_t>(str.size());
    const BYTE* countBytes = reinterpret_cast<const BYTE*>(&charCount);
    buffer.insert(buffer.end(), countBytes, countBytes + sizeof(uint32_t));

    if (charCount > 0) {
        const BYTE* strBytes = reinterpret_cast<const BYTE*>(str.data());
        buffer.insert(buffer.end(), strBytes, strBytes + charCount * sizeof(wchar_t));
    }
}

// ---------------------------------------------------------------------------
// ReadString — read length-prefixed wstring from byte buffer at offset
// ---------------------------------------------------------------------------
bool Baseline::ReadString(const std::vector<BYTE>& buffer, size_t& offset, std::wstring& out)
{
    if (offset + sizeof(uint32_t) > buffer.size()) {
        DebugLog(L"ReadString: buffer underflow reading char count");
        return false;
    }

    uint32_t charCount = 0;
    std::memcpy(&charCount, buffer.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    // Sanity check — no single string should be > 64KB chars
    if (charCount > 65536) {
        DebugLog(L"ReadString: implausible char count, possible corruption");
        return false;
    }

    size_t byteLen = charCount * sizeof(wchar_t);
    if (offset + byteLen > buffer.size()) {
        DebugLog(L"ReadString: buffer underflow reading string data");
        return false;
    }

    if (charCount > 0) {
        out.resize(charCount);
        std::memcpy(&out[0], buffer.data() + offset, byteLen);
    }
    else {
        out.clear();
    }
    offset += byteLen;
    return true;
}

// ---------------------------------------------------------------------------
// AddEntry
// ---------------------------------------------------------------------------
void Baseline::AddEntry(const BaselineEntry& entry)
{
    std::wstring key = NormalizePath(entry.path);
    InternalEntry ie;
    ie.data = entry;
    ie.seen = false;
    m_entries[key] = std::move(ie);

    DebugLog(L"AddEntry: " + key);
}

// ---------------------------------------------------------------------------
// FindEntry
// ---------------------------------------------------------------------------
const BaselineEntry* Baseline::FindEntry(const std::wstring& path) const
{
    std::wstring key = NormalizePath(path);
    auto it = m_entries.find(key);
    if (it != m_entries.end()) {
        return &it->second.data;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// MarkSeen
// ---------------------------------------------------------------------------
void Baseline::MarkSeen(const std::wstring& path)
{
    std::wstring key = NormalizePath(path);
    auto it = m_entries.find(key);
    if (it != m_entries.end()) {
        it->second.seen = true;
    }
}

// ---------------------------------------------------------------------------
// GetUnseenEntries — files in baseline but not found on disk
// ---------------------------------------------------------------------------
std::vector<const BaselineEntry*> Baseline::GetUnseenEntries() const
{
    std::vector<const BaselineEntry*> unseen;
    for (const auto& pair : m_entries) {
        if (!pair.second.seen) {
            unseen.push_back(&pair.second.data);
        }
    }
    return unseen;
}

// ---------------------------------------------------------------------------
// ResetSeenFlags
// ---------------------------------------------------------------------------
void Baseline::ResetSeenFlags()
{
    for (auto& pair : m_entries) {
        pair.second.seen = false;
    }
    DebugLog(L"ResetSeenFlags: all entries reset");
}

// ---------------------------------------------------------------------------
// Count / Clear / AllEntries
// ---------------------------------------------------------------------------
size_t Baseline::Count() const
{
    return m_entries.size();
}

void Baseline::Clear()
{
    m_entries.clear();
    m_creationTime = 0;
    m_loadedVersion = 0;
}

std::vector<const BaselineEntry*> Baseline::AllEntries() const
{
    std::vector<const BaselineEntry*> out;
    out.reserve(m_entries.size());
    for (const auto& pair : m_entries) out.push_back(&pair.second.data);
    return out;
}

bool IsMicrosoftSignedEntry(const BaselineEntry& entry)
{
    if (entry.signature.rfind(L"Signed (Valid)", 0) != 0) return false;
    // signature column is "Signed (Valid) (Signer Name)" for embedded signatures
    size_t open = entry.signature.find(L"(", 14);
    if (open != std::wstring::npos) {
        std::wstring signer = entry.signature.substr(open + 1);
        if (!signer.empty() && signer.back() == L')') signer.pop_back();
        if (IsMicrosoftSignerName(signer)) return true;
    }
    return IsMicrosoftSignerName(entry.catalogSigner);
}

std::wstring BaselineStatusName(BaselineStatus status)
{
    switch (status) {
    case BaselineStatus::Match:   return L"MATCH";
    case BaselineStatus::New:     return L"NEW";
    case BaselineStatus::Changed: return L"CHANGED";
    case BaselineStatus::Missing: return L"MISSING";
    case BaselineStatus::Updated: return L"UPDATED";
    case BaselineStatus::Known:   return L"KNOWN";
    default:                      return L"UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// CompareEntry: compare a current scan result against the baseline
// ---------------------------------------------------------------------------
ComparisonResult Baseline::CompareEntry(const BaselineEntry& current) const
{
    ComparisonResult result;
    result.riskDelta = 0.0;

    const BaselineEntry* baseline = FindEntry(current.path);
    if (!baseline) {
        result.riskDelta = current.malwareScore;
        if (current.knownGood) {
            result.status = BaselineStatus::Known;
            result.changeDetails = L"New file; hash is on the local known-good list";
        }
        else if (IsMicrosoftSignedEntry(current)) {
            result.status = BaselineStatus::Known;
            result.changeDetails = L"New file; validly signed by Microsoft";
        }
        else {
            result.status = BaselineStatus::New;
            result.changeDetails = L"New file (not in baseline)";
        }
        return result;
    }

    // Compare key fields
    std::wstring changes;

    if (current.md5 != baseline->md5) {
        if (!changes.empty()) changes += L"; ";
        changes += L"MD5 changed";
    }

    if (!current.sha256.empty() && !baseline->sha256.empty() && current.sha256 != baseline->sha256) {
        if (!changes.empty()) changes += L"; ";
        changes += L"SHA-256 changed";
    }

    if (current.fileSize != baseline->fileSize) {
        if (!changes.empty()) changes += L"; ";
        std::wstringstream ss;
        ss << L"Size changed (" << baseline->fileSize << L" -> " << current.fileSize << L")";
        changes += ss.str();
    }

    // Baselines written before v3 recorded catalog-signed Windows files as
    // "Unsigned" because the catalog lookup did not exist yet. If the content is
    // identical and only that label moved to a catalog signature, it is not a change.
    bool sameContent = current.md5 == baseline->md5 &&
        (current.sha256.empty() || baseline->sha256.empty() || current.sha256 == baseline->sha256);
    bool legacyCatalogRelabel = sameContent && baseline->signature == L"Unsigned" &&
        current.signatureType == L"Catalog" && baseline->imphash.empty() && baseline->revocation.empty();
    if (current.signature != baseline->signature && !legacyCatalogRelabel) {
        if (!changes.empty()) changes += L"; ";
        changes += L"Signature changed";
    }

    if (current.version != baseline->version) {
        if (!changes.empty()) changes += L"; ";
        changes += L"Version changed (" + baseline->version + L" -> " + current.version + L")";
    }

    if (current.packingStatus != baseline->packingStatus) {
        if (!changes.empty()) changes += L"; ";
        changes += L"Packing status changed";
    }

    if (current.hidden != baseline->hidden) {
        if (!changes.empty()) changes += L"; ";
        changes += L"Hidden attribute changed";
    }

    if (current.permissions != baseline->permissions) {
        if (!changes.empty()) changes += L"; ";
        changes += L"Permissions changed";
    }

    // Entropy change > 0.5 is noteworthy
    double entropyDelta = current.entropy - baseline->entropy;
    if (std::abs(entropyDelta) > 0.5) {
        if (!changes.empty()) changes += L"; ";
        std::wstringstream ss;
        ss << std::fixed << std::setprecision(2)
           << L"Entropy changed (" << baseline->entropy << L" -> " << current.entropy << L")";
        changes += ss.str();
    }

    // v3 fields: only compared when both sides recorded them, so a v2 baseline
    // does not report every file as changed after an upgrade.
    bool baselineHasV3 = !baseline->imphash.empty() || !baseline->ssdeep.empty() || !baseline->revocation.empty();
    if (baselineHasV3) {
        if (baseline->zoneId >= 0 && current.zoneId < 0) {
            if (!changes.empty()) changes += L"; ";
            changes += L"Mark of the Web removed (was zone " + std::to_wstring(baseline->zoneId) + L")";
        }
        if (baseline->altStreams != current.altStreams && !current.altStreams.empty()) {
            if (!changes.empty()) changes += L"; ";
            changes += L"Alternate data streams changed";
        }
        if (!baseline->imphash.empty() && !current.imphash.empty() && baseline->imphash != current.imphash) {
            if (!changes.empty()) changes += L"; ";
            changes += L"Import table changed";
        }
        if (current.revocation == L"REVOKED" && baseline->revocation != L"REVOKED") {
            if (!changes.empty()) changes += L"; ";
            changes += L"Signing certificate now revoked";
        }
    }

    bool contentChanged = (current.md5 != baseline->md5) ||
        (!current.sha256.empty() && !baseline->sha256.empty() && current.sha256 != baseline->sha256);
    if (contentChanged && !baseline->ssdeep.empty() && !current.ssdeep.empty()) {
        int similarity = CompareFuzzyHashes(baseline->ssdeep, current.ssdeep);
        if (!changes.empty()) changes += L"; ";
        if (similarity >= 50) changes += L"Content " + std::to_wstring(similarity) + L"% similar (small edit or patch)";
        else if (similarity > 0) changes += L"Content " + std::to_wstring(similarity) + L"% similar";
        else changes += L"Content replaced entirely (fuzzy hashes unrelated)";
    }

    if (changes.empty()) {
        result.status = BaselineStatus::Match;
        result.changeDetails = L"No changes";
    }
    else if (contentChanged && IsMicrosoftSignedEntry(current) && IsMicrosoftSignedEntry(*baseline)) {
        // Both the old and new file are validly Microsoft-signed: a Windows update.
        result.status = BaselineStatus::Updated;
        result.changeDetails = L"Updated by a Microsoft-signed file; " + changes;
    }
    else {
        result.status = BaselineStatus::Changed;
        result.changeDetails = changes;
    }

    result.riskDelta = current.malwareScore - baseline->malwareScore;
    return result;
}

// ---------------------------------------------------------------------------
// DiffBaselines
// ---------------------------------------------------------------------------
std::vector<ScanRow> DiffBaselines(const Baseline& older, const Baseline& newer, bool includeMatches)
{
    std::vector<ScanRow> rows;
    for (const BaselineEntry* entry : newer.AllEntries()) {
        ComparisonResult cmp = older.CompareEntry(*entry);
        if (cmp.status == BaselineStatus::Match && !includeMatches) continue;
        ScanRow row;
        row.entry = *entry;
        row.status = BaselineStatusName(cmp.status);
        row.changeDetails = cmp.changeDetails;
        row.riskDelta = cmp.riskDelta;
        rows.push_back(row);
    }
    for (const BaselineEntry* entry : older.AllEntries()) {
        if (newer.FindEntry(entry->path)) continue;
        ScanRow row;
        row.entry = *entry;
        row.status = L"MISSING";
        row.changeDetails = L"In the older baseline only";
        row.riskDelta = -entry->malwareScore;
        rows.push_back(row);
    }
    std::sort(rows.begin(), rows.end(), [](const ScanRow& a, const ScanRow& b) {
        if (a.status != b.status) return a.status < b.status;
        return ToLowerW(a.entry.path) < ToLowerW(b.entry.path);
    });
    return rows;
}

// ---------------------------------------------------------------------------
// GetCreationTimeString
// ---------------------------------------------------------------------------
std::wstring Baseline::GetCreationTimeString() const
{
    if (m_creationTime == 0) {
        return L"Unknown";
    }

    FILETIME ft;
    ft.dwLowDateTime = static_cast<DWORD>(m_creationTime & 0xFFFFFFFF);
    ft.dwHighDateTime = static_cast<DWORD>((m_creationTime >> 32) & 0xFFFFFFFF);

    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    wchar_t buf[64];
    swprintf_s(buf, 64, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::wstring(buf);
}

// ---------------------------------------------------------------------------
// GetAgeDays
// ---------------------------------------------------------------------------
int Baseline::GetAgeDays() const
{
    if (m_creationTime == 0) return -1;

    FILETIME nowFT;
    GetSystemTimeAsFileTime(&nowFT);
    ULARGE_INTEGER now;
    now.LowPart = nowFT.dwLowDateTime;
    now.HighPart = nowFT.dwHighDateTime;

    // FILETIME units are 100-nanosecond intervals
    // 1 day = 24 * 60 * 60 * 10,000,000 = 864,000,000,000
    const uint64_t ticksPerDay = 864000000000ULL;

    if (now.QuadPart <= m_creationTime) return 0;
    return static_cast<int>((now.QuadPart - m_creationTime) / ticksPerDay);
}

// ---------------------------------------------------------------------------
// IsOlderThan
// ---------------------------------------------------------------------------
bool Baseline::IsOlderThan(int days) const
{
    int age = GetAgeDays();
    if (age < 0) return false; // unknown age, don't warn
    return age > days;
}

// ---------------------------------------------------------------------------
// Helper: compute MD5 of a byte buffer using CryptoAPI
// ---------------------------------------------------------------------------
static bool ComputeBufferMD5(const BYTE* data, size_t dataLen, BYTE outHash[16])
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    bool success = false;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        DebugLog(L"ComputeBufferMD5: CryptAcquireContext failed");
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        DebugLog(L"ComputeBufferMD5: CryptCreateHash failed");
        CryptReleaseContext(hProv, 0);
        return false;
    }

    // Hash in chunks to avoid DWORD overflow for very large buffers
    size_t remaining = dataLen;
    const BYTE* ptr = data;
    while (remaining > 0) {
        DWORD chunk = (remaining > 0x7FFFFFFF) ? 0x7FFFFFFF : static_cast<DWORD>(remaining);
        if (!CryptHashData(hHash, ptr, chunk, 0)) {
            DebugLog(L"ComputeBufferMD5: CryptHashData failed");
            goto cleanup;
        }
        ptr += chunk;
        remaining -= chunk;
    }

    {
        DWORD hashSize = 16;
        if (CryptGetHashParam(hHash, HP_HASHVAL, outHash, &hashSize, 0)) {
            success = true;
        }
        else {
            DebugLog(L"ComputeBufferMD5: CryptGetHashParam failed");
        }
    }

cleanup:
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return success;
}

// ---------------------------------------------------------------------------
// Helper: serialize one BaselineEntry into the byte buffer
// ---------------------------------------------------------------------------
static void SerializeEntry(std::vector<BYTE>& buffer, const BaselineEntry& e)
{
    Baseline::WriteString(buffer, e.path);

    // fileSize as int64
    const BYTE* sizeBytes = reinterpret_cast<const BYTE*>(&e.fileSize);
    buffer.insert(buffer.end(), sizeBytes, sizeBytes + sizeof(int64_t));

    Baseline::WriteString(buffer, e.md5);
    Baseline::WriteString(buffer, e.sha256);  // v2: SHA-256 hash
    Baseline::WriteString(buffer, e.signature);
    Baseline::WriteString(buffer, e.signatureType);
    Baseline::WriteString(buffer, e.thumbprint);
    Baseline::WriteString(buffer, e.issuer);
    Baseline::WriteString(buffer, e.rootCA);
    Baseline::WriteString(buffer, e.version);
    Baseline::WriteString(buffer, e.developer);
    Baseline::WriteString(buffer, e.readOnly);
    Baseline::WriteString(buffer, e.hidden);
    Baseline::WriteString(buffer, e.permissions);

    // entropy as double
    const BYTE* entropyBytes = reinterpret_cast<const BYTE*>(&e.entropy);
    buffer.insert(buffer.end(), entropyBytes, entropyBytes + sizeof(double));

    // malwareScore as double
    const BYTE* scoreBytes = reinterpret_cast<const BYTE*>(&e.malwareScore);
    buffer.insert(buffer.end(), scoreBytes, scoreBytes + sizeof(double));

    // totalImports as int32
    const BYTE* impBytes = reinterpret_cast<const BYTE*>(&e.totalImports);
    buffer.insert(buffer.end(), impBytes, impBytes + sizeof(int));

    // suspiciousImports as int32
    const BYTE* susBytes = reinterpret_cast<const BYTE*>(&e.suspiciousImports);
    buffer.insert(buffer.end(), susBytes, susBytes + sizeof(int));

    Baseline::WriteString(buffer, e.packingStatus);

    // rwxSections as int32
    const BYTE* rwxBytes = reinterpret_cast<const BYTE*>(&e.rwxSections);
    buffer.insert(buffer.end(), rwxBytes, rwxBytes + sizeof(int));

    Baseline::WriteString(buffer, e.sigWarnings);
    Baseline::WriteString(buffer, e.packIndicators);
}

template <typename T>
static void WritePod(std::vector<BYTE>& buffer, const T& value)
{
    const BYTE* p = reinterpret_cast<const BYTE*>(&value);
    buffer.insert(buffer.end(), p, p + sizeof(T));
}

template <typename T>
static bool ReadPod(const std::vector<BYTE>& buffer, size_t& offset, T& value)
{
    if (offset + sizeof(T) > buffer.size()) return false;
    std::memcpy(&value, buffer.data() + offset, sizeof(T));
    offset += sizeof(T);
    return true;
}

// v3 block, appended after the v2 fields of each entry.
static void SerializeEntryV3(std::vector<BYTE>& buffer, const BaselineEntry& e)
{
    Baseline::WriteString(buffer, e.catalogSigner);
    Baseline::WriteString(buffer, e.revocation);
    Baseline::WriteString(buffer, e.imphash);
    Baseline::WriteString(buffer, e.ssdeep);
    WritePod(buffer, static_cast<int32_t>(e.zoneId));
    Baseline::WriteString(buffer, e.zoneHostUrl);
    Baseline::WriteString(buffer, e.zoneReferrerUrl);
    Baseline::WriteString(buffer, e.altStreams);
    Baseline::WriteString(buffer, e.originWarnings);
    WritePod(buffer, e.peTimestamp);
    Baseline::WriteString(buffer, e.peAnomalies);
    WritePod(buffer, e.overlaySize);
    WritePod(buffer, e.overlayEntropy);
    WritePod(buffer, static_cast<int32_t>(e.tlsCallbacks));
    Baseline::WriteString(buffer, e.pdbPath);
    WritePod(buffer, e.scriptScore);
    Baseline::WriteString(buffer, e.scriptIndicators);
    Baseline::WriteString(buffer, e.attackIds);
    WritePod(buffer, static_cast<uint8_t>(e.knownGood ? 1 : 0));
}

static bool DeserializeEntryV3(const std::vector<BYTE>& buffer, size_t& offset, BaselineEntry& e)
{
    int32_t zone = -1;
    int32_t tls = 0;
    uint8_t known = 0;
    if (!Baseline::ReadString(buffer, offset, e.catalogSigner)) return false;
    if (!Baseline::ReadString(buffer, offset, e.revocation)) return false;
    if (!Baseline::ReadString(buffer, offset, e.imphash)) return false;
    if (!Baseline::ReadString(buffer, offset, e.ssdeep)) return false;
    if (!ReadPod(buffer, offset, zone)) return false;
    if (!Baseline::ReadString(buffer, offset, e.zoneHostUrl)) return false;
    if (!Baseline::ReadString(buffer, offset, e.zoneReferrerUrl)) return false;
    if (!Baseline::ReadString(buffer, offset, e.altStreams)) return false;
    if (!Baseline::ReadString(buffer, offset, e.originWarnings)) return false;
    if (!ReadPod(buffer, offset, e.peTimestamp)) return false;
    if (!Baseline::ReadString(buffer, offset, e.peAnomalies)) return false;
    if (!ReadPod(buffer, offset, e.overlaySize)) return false;
    if (!ReadPod(buffer, offset, e.overlayEntropy)) return false;
    if (!ReadPod(buffer, offset, tls)) return false;
    if (!Baseline::ReadString(buffer, offset, e.pdbPath)) return false;
    if (!ReadPod(buffer, offset, e.scriptScore)) return false;
    if (!Baseline::ReadString(buffer, offset, e.scriptIndicators)) return false;
    if (!Baseline::ReadString(buffer, offset, e.attackIds)) return false;
    if (!ReadPod(buffer, offset, known)) return false;
    e.zoneId = zone;
    e.tlsCallbacks = tls;
    e.knownGood = known != 0;
    return true;
}

// ---------------------------------------------------------------------------
// Helper: deserialize one BaselineEntry from buffer at offset
// ---------------------------------------------------------------------------
static bool DeserializeEntry(const std::vector<BYTE>& buffer, size_t& offset, BaselineEntry& e, uint32_t version)
{
    if (!Baseline::ReadString(buffer, offset, e.path)) return false;

    // fileSize
    if (offset + sizeof(int64_t) > buffer.size()) return false;
    std::memcpy(&e.fileSize, buffer.data() + offset, sizeof(int64_t));
    offset += sizeof(int64_t);

    if (!Baseline::ReadString(buffer, offset, e.md5)) return false;

    // v2+: SHA-256 field
    if (version >= 2) {
        if (!Baseline::ReadString(buffer, offset, e.sha256)) return false;
    }
    else {
        e.sha256 = L"";  // v1 baselines don't have SHA-256
    }

    if (!Baseline::ReadString(buffer, offset, e.signature)) return false;
    if (!Baseline::ReadString(buffer, offset, e.signatureType)) return false;
    if (!Baseline::ReadString(buffer, offset, e.thumbprint)) return false;
    if (!Baseline::ReadString(buffer, offset, e.issuer)) return false;
    if (!Baseline::ReadString(buffer, offset, e.rootCA)) return false;
    if (!Baseline::ReadString(buffer, offset, e.version)) return false;
    if (!Baseline::ReadString(buffer, offset, e.developer)) return false;
    if (!Baseline::ReadString(buffer, offset, e.readOnly)) return false;
    if (!Baseline::ReadString(buffer, offset, e.hidden)) return false;
    if (!Baseline::ReadString(buffer, offset, e.permissions)) return false;

    // entropy
    if (offset + sizeof(double) > buffer.size()) return false;
    std::memcpy(&e.entropy, buffer.data() + offset, sizeof(double));
    offset += sizeof(double);

    // malwareScore
    if (offset + sizeof(double) > buffer.size()) return false;
    std::memcpy(&e.malwareScore, buffer.data() + offset, sizeof(double));
    offset += sizeof(double);

    // totalImports
    if (offset + sizeof(int) > buffer.size()) return false;
    std::memcpy(&e.totalImports, buffer.data() + offset, sizeof(int));
    offset += sizeof(int);

    // suspiciousImports
    if (offset + sizeof(int) > buffer.size()) return false;
    std::memcpy(&e.suspiciousImports, buffer.data() + offset, sizeof(int));
    offset += sizeof(int);

    if (!Baseline::ReadString(buffer, offset, e.packingStatus)) return false;

    // rwxSections
    if (offset + sizeof(int) > buffer.size()) return false;
    std::memcpy(&e.rwxSections, buffer.data() + offset, sizeof(int));
    offset += sizeof(int);

    if (!Baseline::ReadString(buffer, offset, e.sigWarnings)) return false;
    if (!Baseline::ReadString(buffer, offset, e.packIndicators)) return false;

    if (version >= 3) {
        if (!DeserializeEntryV3(buffer, offset, e)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// SaveToFile — binary format with PRBL magic + MD5 integrity footer
// ---------------------------------------------------------------------------
bool Baseline::SaveToFile(const std::wstring& filePath) const
{
    return SaveToFile(filePath, BASELINE_VERSION);
}

bool Baseline::SaveToFile(const std::wstring& filePath, uint32_t version) const
{
    DebugLog(L"SaveToFile: writing v" + std::to_wstring(version) + L" to " + filePath);
    if (version < 1 || version > BASELINE_VERSION) return false;

    std::vector<BYTE> buffer;
    buffer.reserve(1024 * 1024); // pre-allocate 1MB

    // Magic header "PRBL"
    buffer.insert(buffer.end(), BASELINE_MAGIC, BASELINE_MAGIC + 4);

    // Version (uint32)
    const BYTE* verBytes = reinterpret_cast<const BYTE*>(&version);
    buffer.insert(buffer.end(), verBytes, verBytes + sizeof(uint32_t));

    // Entry count (uint64)
    uint64_t entryCount = static_cast<uint64_t>(m_entries.size());
    const BYTE* countBytes = reinterpret_cast<const BYTE*>(&entryCount);
    buffer.insert(buffer.end(), countBytes, countBytes + sizeof(uint64_t));

    // Creation timestamp (uint64 FILETIME)
    uint64_t timestamp = m_creationTime;
    if (timestamp == 0) {
        // Set to current time
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER li;
        li.LowPart = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        timestamp = li.QuadPart;
    }
    const BYTE* tsBytes = reinterpret_cast<const BYTE*>(&timestamp);
    buffer.insert(buffer.end(), tsBytes, tsBytes + sizeof(uint64_t));

    // Serialize all entries
    for (const auto& pair : m_entries) {
        if (version >= 2) {
            SerializeEntry(buffer, pair.second.data);
        }
        else {
            // v1 had no SHA-256 field: write v2 layout then cut the SHA-256 string back out.
            std::vector<BYTE> one;
            BaselineEntry copy = pair.second.data;
            copy.sha256.clear();
            SerializeEntry(one, copy);
            // path, int64 size, md5, then an empty sha256 (4 zero bytes) to drop
            size_t offset = 0;
            std::wstring skip;
            Baseline::ReadString(one, offset, skip);
            offset += sizeof(int64_t);
            Baseline::ReadString(one, offset, skip);
            one.erase(one.begin() + static_cast<std::ptrdiff_t>(offset), one.begin() + static_cast<std::ptrdiff_t>(offset + sizeof(uint32_t)));
            buffer.insert(buffer.end(), one.begin(), one.end());
        }
        if (version >= 3) {
            SerializeEntryV3(buffer, pair.second.data);
        }
    }

    // Compute MD5 of everything so far
    BYTE md5Hash[16] = { 0 };
    if (!ComputeBufferMD5(buffer.data(), buffer.size(), md5Hash)) {
        DebugLog(L"SaveToFile: failed to compute MD5 integrity hash");
        return false;
    }

    // Append MD5 footer
    buffer.insert(buffer.end(), md5Hash, md5Hash + 16);

    // Write to file
    // Write to a temporary file, then move it over the target, so a crash or a
    // full disk never leaves a half-written baseline behind.
    std::wstring tempPath = filePath + L".tmp";
    {
        std::ofstream file(tempPath, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            DebugLog(L"SaveToFile: failed to open file for writing");
            return false;
        }
        file.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        file.close();
        if (file.fail()) {
            DebugLog(L"SaveToFile: write failed");
            DeleteFileW(tempPath.c_str());
            return false;
        }
    }
    if (!MoveFileExW(tempPath.c_str(), filePath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DebugLog(L"SaveToFile: could not replace target (error " + std::to_wstring(GetLastError()) + L")");
        DeleteFileW(tempPath.c_str());
        return false;
    }

    std::wstringstream ss;
    ss << L"SaveToFile: wrote " << entryCount << L" entries, "
       << buffer.size() << L" bytes";
    DebugLog(ss.str());

    return true;
}

// ---------------------------------------------------------------------------
// LoadFromFile — read binary PRBL file, verify MD5 integrity
// ---------------------------------------------------------------------------
bool Baseline::LoadFromFile(const std::wstring& filePath)
{
    DebugLog(L"LoadFromFile: reading from " + filePath);

    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        DebugLog(L"LoadFromFile: failed to open file");
        return false;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Minimum size: magic(4) + version(4) + count(8) + timestamp(8) + md5(16) = 40
    if (fileSize < 40) {
        DebugLog(L"LoadFromFile: file too small to be a valid baseline");
        return false;
    }

    std::vector<BYTE> buffer(static_cast<size_t>(fileSize));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        DebugLog(L"LoadFromFile: failed to read file contents");
        return false;
    }
    file.close();

    // Verify MD5 integrity: hash everything except the last 16 bytes
    size_t dataLen = buffer.size() - 16;
    BYTE computedMD5[16] = { 0 };
    if (!ComputeBufferMD5(buffer.data(), dataLen, computedMD5)) {
        DebugLog(L"LoadFromFile: failed to compute verification MD5");
        return false;
    }

    if (std::memcmp(computedMD5, buffer.data() + dataLen, 16) != 0) {
        DebugLog(L"LoadFromFile: MD5 integrity check FAILED — file is corrupted or tampered");
        return false;
    }
    DebugLog(L"LoadFromFile: MD5 integrity check passed");

    // Parse header
    size_t offset = 0;

    // Check magic
    if (std::memcmp(buffer.data(), BASELINE_MAGIC, 4) != 0) {
        DebugLog(L"LoadFromFile: invalid magic header (not PRBL)");
        return false;
    }
    offset += 4;

    // Version
    uint32_t version = 0;
    std::memcpy(&version, buffer.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    if (version < 1 || version > BASELINE_VERSION) {
        std::wstringstream ss;
        ss << L"LoadFromFile: unsupported version " << version
           << L" (supported: 1-" << BASELINE_VERSION << L")";
        DebugLog(ss.str());
        return false;
    }
    if (version < BASELINE_VERSION) {
        std::wstringstream ss;
        ss << L"LoadFromFile: upgrading from v" << version << L" to v" << BASELINE_VERSION;
        DebugLog(ss.str());
    }

    // Entry count
    uint64_t entryCount = 0;
    std::memcpy(&entryCount, buffer.data() + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    // Timestamp
    std::memcpy(&m_creationTime, buffer.data() + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    // Deserialize entries
    m_entries.clear();
    m_loadedVersion = version;
    if (entryCount > 50000000ULL) {
        DebugLog(L"LoadFromFile: implausible entry count");
        return false;
    }
    m_entries.reserve(static_cast<size_t>(entryCount));

    for (uint64_t i = 0; i < entryCount; i++) {
        BaselineEntry entry;
        if (!DeserializeEntry(buffer, offset, entry, version)) {
            std::wstringstream ss;
            ss << L"LoadFromFile: failed to deserialize entry " << i << L" of " << entryCount;
            DebugLog(ss.str());
            m_entries.clear();
            return false;
        }

        std::wstring key = NormalizePath(entry.path);
        InternalEntry ie;
        ie.data = std::move(entry);
        ie.seen = false;
        m_entries[key] = std::move(ie);
    }

    std::wstringstream ss;
    ss << L"LoadFromFile: loaded " << m_entries.size() << L" entries, created "
       << GetCreationTimeString();
    DebugLog(ss.str());

    return true;
}
