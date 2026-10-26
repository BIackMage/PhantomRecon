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
    void Close();

private:
    HANDLE      m_file = INVALID_HANDLE_VALUE;
    std::string m_buffer;
};

// Write all rows to a new file. False on failure.
bool ExportRowsToCsv(const std::wstring& path, const std::vector<ScanRow>& rows);

// Read a CSV written by any version of Phantom Recon. Unknown columns are ignored,
// missing ones keep defaults. Status defaults to LOADED when the file has none.
bool LoadRowsFromCsv(const std::wstring& path, std::vector<ScanRow>& rows);

// Split one CSV line into fields (exposed for tests).
std::vector<std::wstring> ParseCsvLine(const std::wstring& line);
