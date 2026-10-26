#include "pch.h"
#include "ScanCsv.h"

#include "AppPaths.h"
#include "FileIO.h"
#include "StringConv.h"
#include "TextUtils.h"

#include <iterator>
#include <map>
#include <new>
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

// Characters that make Excel, LibreOffice and Google Sheets read a cell as a formula.
static bool IsFormulaTrigger(wchar_t c)
{
    return c == L'=' || c == L'+' || c == L'-' || c == L'@' || c == L'\t' || c == L'\r' ||
           c == 0xFF1D /* fullwidth = */ || c == 0xFF0B /* fullwidth + */ || c == 0xFF0D /* fullwidth - */ ||
           c == 0xFF20 /* fullwidth @ */;
}

// True when s is zero or more apostrophes followed by a formula trigger.
static bool NeedsFormulaGuard(const std::wstring& s)
{
    size_t i = 0;
    while (i < s.size() && s[i] == L'\'') ++i;
    return i < s.size() && IsFormulaTrigger(s[i]);
}

std::wstring CsvGuardFormula(const std::wstring& text)
{
    // Text from the scanned file (company name, version, PDB path, URLs) is attacker
    // controlled. "=HYPERLINK(...)" would run as a formula when the CSV is opened in a
    // spreadsheet, so such text gets a leading apostrophe, which spreadsheets show as
    // plain text. Text that already starts with apostrophes before a trigger gets one
    // more, so CsvUnguardFormula restores every value exactly.
    if (!NeedsFormulaGuard(text)) return text;
    DebugLog(L"CsvGuardFormula: cell starting with a formula character written as text");
    return L"'" + text;
}

std::wstring CsvUnguardFormula(const std::wstring& field)
{
    if (field.size() >= 2 && field[0] == L'\'' && NeedsFormulaGuard(field.substr(1))) return field.substr(1);
    return field;
}

// A text field: never contains raw line breaks (they would split the row) and never
// starts like a formula.
static std::wstring Field(const std::wstring& s)
{
    std::wstring clean = s;
    for (wchar_t& c : clean) {
        if (c == L'\r' || c == L'\n') c = L' ';
    }
    return CsvEscape(CsvGuardFormula(clean));
}

// A number this program formatted itself ("-1", "+0.5"). Spreadsheets read a sign
// followed by a digit as a number, not a formula, so that is written as is. Anything
// else with a leading sign ("-nan(ind)", "-inf") is guarded like text.
static std::wstring NumberField(const std::wstring& s)
{
    bool signedNumber = s.size() >= 2 && (s[0] == L'-' || s[0] == L'+') && s[1] >= L'0' && s[1] <= L'9';
    return CsvEscape(signedNumber ? s : CsvGuardFormula(s));
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
    struct Cell {
        std::wstring text;
        bool         number;   // formatted here from a numeric field, not text from the file
    };
    const bool T = false;
    const bool N = true;
    std::vector<Cell> f = {
        { e.path, T }, { std::to_wstring(e.fileSize), N }, { e.md5, T }, { e.sha256, T }, { e.signature, T },
        { e.signatureType, T }, { e.thumbprint, T },
        { e.issuer, T }, { e.rootCA, T }, { e.version, T }, { e.developer, T }, { e.readOnly, T }, { e.hidden, T },
        { e.permissions, T },
        { FormatFixed(e.entropy, 5), N }, { FormatScore(e), N }, { std::to_wstring(e.totalImports), N },
        { std::to_wstring(e.suspiciousImports), N },
        { e.packingStatus, T }, { std::to_wstring(e.rwxSections), N }, { e.sigWarnings, T }, { e.packIndicators, T },
        { e.catalogSigner, T }, { e.revocation, T }, { e.imphash, T }, { e.ssdeep, T }, { std::to_wstring(e.zoneId), N },
        { e.zoneHostUrl, T }, { e.zoneReferrerUrl, T },
        { e.altStreams, T }, { e.originWarnings, T }, { std::to_wstring(e.peTimestamp), N }, { e.peAnomalies, T },
        { std::to_wstring(e.overlaySize), N },
        { FormatFixed(e.overlayEntropy, 3), N }, { std::to_wstring(e.tlsCallbacks), N }, { e.pdbPath, T },
        { FormatFixed(e.scriptScore, 2), N },
        { e.scriptIndicators, T }, { e.attackIds, T }, { e.knownGood ? L"Yes" : L"No", T },
        { row.status, T }, { row.changeDetails, T }, { FormatDelta(row.riskDelta), N },
    };
    std::wstring line;
    for (size_t i = 0; i < f.size(); ++i) {
        if (i > 0) line += L",";
        line += f[i].number ? NumberField(f[i].text) : Field(f[i].text);
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
    m_failed = false;
    m_path = path;
    m_file = CreateFileW(ToExtendedPath(path).c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (m_file == INVALID_HANDLE_VALUE) {
        DebugLog(L"Open failed: " + path + L" (error " + std::to_wstring(GetLastError()) + L")");
        m_failed = true;
        return false;
    }
    m_buffer = "\xEF\xBB\xBF";
    m_buffer += WideToUtf8(CsvHeaderLine() + L"\r\n");
    Flush();
    return !m_failed;
}

void CsvWriter::Write(const ScanRow& row)
{
    if (m_file == INVALID_HANDLE_VALUE || m_failed) return;
    m_buffer += WideToUtf8(CsvRowLine(row) + L"\r\n");
    if (m_buffer.size() > 64 * 1024) Flush();
}

bool CsvWriter::WriteBytes(const char* data, size_t size)
{
    const char* p = data;
    size_t left = size;
    while (left > 0) {
        DWORD written = 0;
        DWORD chunk = left > 0x100000 ? 0x100000 : static_cast<DWORD>(left);
        if (!WriteFile(m_file, p, chunk, &written, NULL) || written == 0) {
            DebugLog(L"Write failed (error " + std::to_wstring(GetLastError()) + L"): " + m_path);
            return false;
        }
        p += written;
        left -= written;
    }
    return true;
}

void CsvWriter::Flush()
{
    if (m_file == INVALID_HANDLE_VALUE || m_buffer.empty()) return;
    if (!m_failed && !WriteBytes(m_buffer.data(), m_buffer.size())) {
        // Disk full or a removed drive. Every later row is dropped and Close reports it,
        // so a cut-off file is never presented as a complete export.
        m_failed = true;
    }
    m_buffer.clear();
}

bool CsvWriter::Close()
{
    if (m_file == INVALID_HANDLE_VALUE) return !m_failed;
    Flush();
    if (!m_failed && !FlushFileBuffers(m_file)) {
        DebugLog(L"FlushFileBuffers failed (error " + std::to_wstring(GetLastError()) + L"): " + m_path);
        m_failed = true;
    }
    if (!CloseHandle(m_file)) {
        DebugLog(L"CloseHandle failed (error " + std::to_wstring(GetLastError()) + L"): " + m_path);
        m_failed = true;
    }
    m_file = INVALID_HANDLE_VALUE;
    if (m_failed) {
        // A partial CSV loads later as if it were the whole scan. Remove it.
        if (DeleteFileW(ToExtendedPath(m_path).c_str())) DebugLog(L"Removed incomplete CSV: " + m_path);
        else DebugLog(L"Could not remove incomplete CSV (error " + std::to_wstring(GetLastError()) + L"): " + m_path);
    }
    return !m_failed;
}

bool ExportRowsToCsv(const std::wstring& path, const std::vector<ScanRow>& rows)
{
    CsvWriter writer;
    if (!writer.Open(path)) {
        writer.Close();
        return false;
    }
    for (const ScanRow& row : rows) writer.Write(row);
    bool ok = writer.Close();
    if (!ok) DebugLog(L"ExportRowsToCsv failed: " + path);
    return ok;
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

// Next line of text starting at pos (no line break, CR of a CRLF removed). False at the end.
static bool NextLine(const std::wstring& text, size_t& pos, std::wstring& line)
{
    if (pos >= text.size()) return false;
    size_t nl = text.find(L'\n', pos);
    size_t end = nl == std::wstring::npos ? text.size() : nl;
    line.assign(text, pos, end - pos);
    if (!line.empty() && line.back() == L'\r') line.pop_back();
    pos = nl == std::wstring::npos ? text.size() : nl + 1;
    return true;
}

static bool LoadRowsFromCsvText(const std::wstring& text, std::vector<ScanRow>& rows);

bool LoadRowsFromCsv(const std::wstring& path, std::vector<ScanRow>& rows)
{
    // A CSV larger than this is refused rather than loaded in part: reading only the
    // first bytes used to give a partial result plus one cut-off row, shown as complete.
    const size_t kMaxCsvBytes = 512u * 1024u * 1024u;
    WIN32_FILE_ATTRIBUTE_DATA info = {};
    if (GetFileAttributesExW(ToExtendedPath(path).c_str(), GetFileExInfoStandard, &info)) {
        uint64_t size = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
        if (size > kMaxCsvBytes) {
            DebugLog(L"CSV of " + std::to_wstring(size) + L" bytes is over the " +
                std::to_wstring(kMaxCsvBytes / (1024 * 1024)) + L" MB limit, not loaded: " + path);
            return false;
        }
    }
    try {
        std::wstring text;
        bool truncated = false;
        if (!ReadTextFile(path, text, kMaxCsvBytes, &truncated)) {
            DebugLog(L"Cannot read " + path);
            return false;
        }
        if (truncated) {
            DebugLog(L"CSV larger than " + std::to_wstring(kMaxCsvBytes / (1024 * 1024)) + L" MB, not loaded: " + path);
            return false;
        }
        std::vector<ScanRow> loaded;
        if (!LoadRowsFromCsvText(text, loaded)) return false;
        rows.insert(rows.end(), std::make_move_iterator(loaded.begin()), std::make_move_iterator(loaded.end()));
        DebugLog(L"Loaded " + std::to_wstring(loaded.size()) + L" rows from " + path);
        return true;
    }
    catch (const std::bad_alloc&) {
        DebugLog(L"Out of memory loading " + path);
        return false;
    }
}

static bool LoadRowsFromCsvText(const std::wstring& text, std::vector<ScanRow>& rows)
{
    size_t pos = 0;
    std::wstring line;
    if (!NextLine(text, pos, line)) return false;

    std::vector<std::wstring> headers = ParseCsvLine(line);
    std::map<std::wstring, int> col;
    for (int i = 0; i < static_cast<int>(headers.size()); ++i) col[TrimW(headers[i])] = i;
    if (col.find(L"Path") == col.end()) {
        DebugLog(L"CSV has no Path column");
        return false;
    }

    while (NextLine(text, pos, line)) {
        if (TrimW(line).empty()) continue;
        std::vector<std::wstring> fields = ParseCsvLine(line);
        auto get = [&](const wchar_t* name) -> std::wstring {
            auto it = col.find(name);
            if (it == col.end() || it->second >= static_cast<int>(fields.size())) return L"";
            return CsvUnguardFormula(fields[it->second]);
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
        rows.push_back(std::move(row));
    }
    return true;
}
