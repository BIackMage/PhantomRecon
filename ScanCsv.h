#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "ScanTypes.h"

// ---------------------------------------------------------------------------
// ScanCsv: the CSV format for scan results.
//
// UTF-8 with a BOM (so Excel shows non-English paths correctly), RFC 4180
// quoting, one header line. Every row carries the baseline status columns;
// a Baseline Scan writes BASELINE there.
// ---------------------------------------------------------------------------

// The header line (no line break).
std::wstring CsvHeaderLine();

// One row (no line break).
std::wstring CsvRowLine(const ScanRow& row);

// Buffered writer that keeps the file open for the whole scan.
class CsvWriter {
public:
    CsvWriter() = default;
    ~CsvWriter();
    CsvWriter(const CsvWriter&) = delete;
    CsvWriter& operator=(const CsvWriter&) = delete;

    // Create or truncate the file and write BOM + header. False on failure.
    bool Open(const std::wstring& path);
    bool IsOpen() const { return m_file != INVALID_HANDLE_VALUE; }
    void Write(const ScanRow& row);
    void Flush();
    // Flush and close. False when any write failed (disk full, drive removed); the
    // incomplete file is then deleted so it cannot be loaded as a whole scan later.
    bool Close();
    // True once a write has failed. Later rows are dropped.
    bool Failed() const { return m_failed; }

private:
    bool WriteBytes(const char* data, size_t size);

    HANDLE       m_file = INVALID_HANDLE_VALUE;
    std::string  m_buffer;
    std::wstring m_path;
    bool         m_failed = false;
};

// Write all rows to a new file. False on failure, including a failed write part way.
bool ExportRowsToCsv(const std::wstring& path, const std::vector<ScanRow>& rows);

// Read a CSV written by any version of Phantom Recon. Unknown columns are ignored,
// missing ones keep defaults. Status defaults to LOADED when the file has none.
// Files over 512 MB are refused (false), never loaded in part. Rows are appended to
// rows only when the whole file loaded.
bool LoadRowsFromCsv(const std::wstring& path, std::vector<ScanRow>& rows);

// Formula injection guard for text cells. Text from scanned files (company names,
// versions, URLs) that starts like a spreadsheet formula ("=", "+", "-", "@", tab)
// gets a leading apostrophe; CsvUnguardFormula reverses it exactly when loading.
std::wstring CsvGuardFormula(const std::wstring& text);
std::wstring CsvUnguardFormula(const std::wstring& field);

// Split one CSV line into fields (exposed for tests).
std::vector<std::wstring> ParseCsvLine(const std::wstring& line);
