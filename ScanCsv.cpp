#include "pch.h"
#include "ScanCsv.h"

#include "AppPaths.h"
#include "FileIO.h"
#include "StringConv.h"
#include "TextUtils.h"

#include <map>
#include <sstream>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW((L"[ScanCsv] " + msg + L"\n").c_str());
}

// Column order. Keep the first 22 names identical to older versions so old
// CSVs still load.
static const wchar_t* const kColumns[] = {
    L"Path", L"File Size", L"MD5", L"SHA-256", L"Signature", L"Signature Type", L"Cert Thumbprint",
    L"Issuer", L"Root CA", L"Version", L"Developer", L"Read Only", L"Hidden", L"Permissions",
    L"Entropy", L"Malware Score", L"Total Imports", L"Suspicious Imports", L"Packing Status",
    L"RWX Sections", L"Signature Warnings", L"Packing Indicators",
    L"Catalog Signer", L"Revocation", L"Imphash", L"Ssdeep", L"Zone", L"Host URL", L"Referrer URL",
    L"Alt Streams", L"Origin Warnings", L"PE Timestamp", L"PE Anomalies", L"Overlay Size",
    L"Overlay Entropy", L"TLS Callbacks", L"PDB Path", L"Script Score", L"Script Indicators",
    L"ATT&CK", L"Known Good",
    L"Baseline Status", L"Change Details", L"Risk Delta",
};

std::wstring CsvHeaderLine()
{
    std::wstring line;
    for (const wchar_t* c : kColumns) {
        if (!line.empty()) line += L",";
        line += CsvEscape(c);
    }
    return line;
}

// Fields never contain raw line breaks: they would split the row.
static std::wstring Field(const std::wstring& s)
{
    std::wstring clean = s;
    for (wchar_t& c : clean) {
        if (c == L'\r' || c == L'\n') c = L' ';
    }
    return CsvEscape(clean);
}

static std::wstring FormatScore(const BaselineEntry& e)
{
    std::wstring s = FormatFixed(e.malwareScore, 2) + L"/10";
    if (e.suspiciousImports > 0) s += L" (" + std::to_wstring(e.suspiciousImports) + L" suspicious imports)";
    return s;
}

static std::wstring FormatDelta(double delta)
{
    std::wstring s = FormatFixed(delta, 1);
    if (delta >= 0) s = L"+" + s;
    return s;
}

std::wstring CsvRowLine(const ScanRow& row)
{
    const BaselineEntry& e = row.entry;
    std::vector<std::wstring> f = {
        e.path, std::to_wstring(e.fileSize), e.md5, e.sha256, e.signature, e.signatureType, e.thumbprint,
        e.issuer, e.rootCA, e.version, e.developer, e.readOnly, e.hidden, e.permissions,
        FormatFixed(e.entropy, 5), FormatScore(e), std::to_wstring(e.totalImports), std::to_wstring(e.suspiciousImports),
        e.packingStatus, std::to_wstring(e.rwxSections), e.sigWarnings, e.packIndicators,
        e.catalogSigner, e.revocation, e.imphash, e.ssdeep, std::to_wstring(e.zoneId), e.zoneHostUrl, e.zoneReferrerUrl,
        e.altStreams, e.originWarnings, std::to_wstring(e.peTimestamp), e.peAnomalies, std::to_wstring(e.overlaySize),
        FormatFixed(e.overlayEntropy, 3), std::to_wstring(e.tlsCallbacks), e.pdbPath, FormatFixed(e.scriptScore, 2),
        e.scriptIndicators, e.attackIds, e.knownGood ? L"Yes" : L"No",
        row.status, row.changeDetails, FormatDelta(row.riskDelta),
    };
    std::wstring line;
    for (size_t i = 0; i < f.size(); ++i) {
        if (i > 0) line += L",";
        line += Field(f[i]);
    }
    return line;
}

// ---------------------------------------------------------------------------
// CsvWriter
// ---------------------------------------------------------------------------
CsvWriter::~CsvWriter()
{
    Close();
}

bool CsvWriter::Open(const std::wstring& path)
{
    Close();
    m_file = CreateFileW(ToExtendedPath(path).c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_file == INVALID_HANDLE_VALUE) {
        DebugLog(L"Open failed: " + path + L" (error " + std::to_wstring(GetLastError()) + L")");
        return false;
    }
    m_buffer = "\xEF\xBB\xBF";
    m_buffer += WideToUtf8(CsvHeaderLine() + L"\r\n");
    Flush();
    return true;
}

void CsvWriter::Write(const ScanRow& row)
{
    if (m_file == INVALID_HANDLE_VALUE) return;
    m_buffer += WideToUtf8(CsvRowLine(row) + L"\r\n");
    if (m_buffer.size() > 64 * 1024) Flush();
}

void CsvWriter::Flush()
{
    if (m_file == INVALID_HANDLE_VALUE || m_buffer.empty()) return;
    const char* p = m_buffer.data();
    size_t left = m_buffer.size();
    while (left > 0) {
        DWORD written = 0;
        DWORD chunk = left > 0x100000 ? 0x100000 : static_cast<DWORD>(left);
        if (!WriteFile(m_file, p, chunk, &written, NULL) || written == 0) {
            DebugLog(L"Write failed (error " + std::to_wstring(GetLastError()) + L")");
            break;
        }
        p += written;
        left -= written;
    }
    m_buffer.clear();
}

void CsvWriter::Close()
{
    if (m_file == INVALID_HANDLE_VALUE) return;
    Flush();
    CloseHandle(m_file);
    m_file = INVALID_HANDLE_VALUE;
}

bool ExportRowsToCsv(const std::wstring& path, const std::vector<ScanRow>& rows)
{
    CsvWriter writer;
    if (!writer.Open(path)) return false;
    for (const ScanRow& row : rows) writer.Write(row);
    writer.Close();
    return true;
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------
std::vector<std::wstring> ParseCsvLine(const std::wstring& line)
{
    std::vector<std::wstring> fields;
    std::wstring current;
    bool inQuotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        wchar_t c = line[i];
        if (inQuotes) {
            if (c == L'"') {
                if (i + 1 < line.size() && line[i + 1] == L'"') {
                    current += L'"';
                    ++i;
                }
                else {
                    inQuotes = false;
                }
            }
            else {
                current += c;
            }
        }
        else if (c == L'"') {
            inQuotes = true;
        }
        else if (c == L',') {
            fields.push_back(current);
            current.clear();
        }
        else {
            current += c;
        }
    }
    fields.push_back(current);
    return fields;
}

bool LoadRowsFromCsv(const std::wstring& path, std::vector<ScanRow>& rows)
{
    std::wstring text;
    if (!ReadTextFile(path, text)) {
        DebugLog(L"Cannot read " + path);
        return false;
    }

    std::vector<std::wstring> lines;
    {
        std::wstring current;
        for (wchar_t c : text) {
            if (c == L'\n') {
                if (!current.empty() && current.back() == L'\r') current.pop_back();
                lines.push_back(current);
                current.clear();
            }
            else {
                current += c;
            }
        }
        if (!current.empty()) lines.push_back(current);
    }
    if (lines.empty()) return false;

    std::vector<std::wstring> headers = ParseCsvLine(lines[0]);
    std::map<std::wstring, int> col;
    for (int i = 0; i < static_cast<int>(headers.size()); ++i) col[TrimW(headers[i])] = i;
    if (col.find(L"Path") == col.end()) {
        DebugLog(L"CSV has no Path column");
        return false;
    }

    for (size_t li = 1; li < lines.size(); ++li) {
        if (TrimW(lines[li]).empty()) continue;
        std::vector<std::wstring> fields = ParseCsvLine(lines[li]);
        auto get = [&](const wchar_t* name) -> std::wstring {
            auto it = col.find(name);
            if (it == col.end() || it->second >= static_cast<int>(fields.size())) return L"";
            return fields[it->second];
        };

        ScanRow row;
        BaselineEntry& e = row.entry;
        e.path = get(L"Path");
        if (e.path.empty()) continue;
        e.fileSize = _wtoi64(get(L"File Size").c_str());
        e.md5 = get(L"MD5");
        e.sha256 = get(L"SHA-256");
        e.signature = get(L"Signature");
        e.signatureType = get(L"Signature Type");
        e.thumbprint = get(L"Cert Thumbprint");
        e.issuer = get(L"Issuer");
        e.rootCA = get(L"Root CA");
        e.version = get(L"Version");
        e.developer = get(L"Developer");
        e.readOnly = get(L"Read Only");
        e.hidden = get(L"Hidden");
        e.permissions = get(L"Permissions");
        e.entropy = _wtof(get(L"Entropy").c_str());
        e.malwareScore = _wtof(get(L"Malware Score").c_str());
        e.totalImports = _wtoi(get(L"Total Imports").c_str());
        e.suspiciousImports = _wtoi(get(L"Suspicious Imports").c_str());
        e.packingStatus = get(L"Packing Status");
        e.rwxSections = _wtoi(get(L"RWX Sections").c_str());
        e.sigWarnings = get(L"Signature Warnings");
        e.packIndicators = get(L"Packing Indicators");
        e.catalogSigner = get(L"Catalog Signer");
        e.revocation = get(L"Revocation");
        e.imphash = get(L"Imphash");
        e.ssdeep = get(L"Ssdeep");
        std::wstring zone = get(L"Zone");
        e.zoneId = zone.empty() ? -1 : _wtoi(zone.c_str());
        e.zoneHostUrl = get(L"Host URL");
        e.zoneReferrerUrl = get(L"Referrer URL");
        e.altStreams = get(L"Alt Streams");
        e.originWarnings = get(L"Origin Warnings");
        e.peTimestamp = static_cast<uint32_t>(_wtoi64(get(L"PE Timestamp").c_str()));
        e.peAnomalies = get(L"PE Anomalies");
        e.overlaySize = _wtoi64(get(L"Overlay Size").c_str());
        e.overlayEntropy = _wtof(get(L"Overlay Entropy").c_str());
        e.tlsCallbacks = _wtoi(get(L"TLS Callbacks").c_str());
        e.pdbPath = get(L"PDB Path");
        e.scriptScore = _wtof(get(L"Script Score").c_str());
        e.scriptIndicators = get(L"Script Indicators");
        e.attackIds = get(L"ATT&CK");
        e.knownGood = EqualsI(get(L"Known Good"), L"Yes");

        row.status = get(L"Baseline Status");
        if (row.status.empty()) row.status = L"LOADED";
        row.changeDetails = get(L"Change Details");
        row.riskDelta = _wtof(get(L"Risk Delta").c_str());
        rows.push_back(row);
    }

    DebugLog(L"Loaded " + std::to_wstring(rows.size()) + L" rows from " + path);
    return true;
}
