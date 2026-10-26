#include "pch.h"
#include "GuiComponents.h"
#include "resource.h"

#include <commctrl.h>
#include <ShlObj.h>
#include <commdlg.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <string>

#pragma comment(lib, "comctl32.lib")

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const wchar_t* msg)
{
    OutputDebugStringW(L"[GuiComponents] ");
    OutputDebugStringW(msg);
    OutputDebugStringW(L"\n");
}

// ---------------------------------------------------------------------------
// InitGuiCommonControls
// ---------------------------------------------------------------------------
void InitGuiCommonControls()
{
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);
    DebugLog(L"Common controls initialized");
}

// ---------------------------------------------------------------------------
// Progress Bar
// ---------------------------------------------------------------------------
HWND CreateScanProgressBar(HWND hParent, HINSTANCE hInst, int x, int y, int width, int height)
{
    HWND hProgress = CreateWindowExW(
        0, PROGRESS_CLASSW, NULL,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        x, y, width, height,
        hParent, (HMENU)ID_PROGRESS_BAR, hInst, NULL);

    if (!hProgress) {
        DebugLog(L"Failed to create progress bar");
    }
    else {
        DebugLog(L"Progress bar created");
    }
    return hProgress;
}

void SetProgressRange(HWND hProgressBar, int maxValue)
{
    if (hProgressBar) {
        SendMessage(hProgressBar, PBM_SETRANGE32, 0, maxValue);
    }
}

void SetProgressPosition(HWND hProgressBar, int position)
{
    if (hProgressBar) {
        SendMessage(hProgressBar, PBM_SETPOS, position, 0);
    }
}

void SetProgressMarquee(HWND hProgressBar, bool enable)
{
    if (!hProgressBar) return;

    LONG_PTR style = GetWindowLongPtr(hProgressBar, GWL_STYLE);
    if (enable) {
        SetWindowLongPtr(hProgressBar, GWL_STYLE, style | PBS_MARQUEE);
        SendMessage(hProgressBar, PBM_SETMARQUEE, TRUE, 30);
    }
    else {
        SendMessage(hProgressBar, PBM_SETMARQUEE, FALSE, 0);
        SetWindowLongPtr(hProgressBar, GWL_STYLE, style & ~PBS_MARQUEE);
    }
}

// ---------------------------------------------------------------------------
// Results ListView
// ---------------------------------------------------------------------------

// Column definitions for the results list
struct ColumnDef {
    const wchar_t* name;
    int width;
};

static const ColumnDef g_ResultColumns[] = {
    { L"File Path",         250 },
    { L"Status",             70 },
    { L"Score",              60 },
    { L"SHA-256",           120 },
    { L"Signature",         150 },
    { L"Packing",           100 },
    { L"Size",               70 },
    { L"Developer",         120 },
};
static const int g_ResultColumnCount = sizeof(g_ResultColumns) / sizeof(g_ResultColumns[0]);

HWND CreateResultsListView(HWND hParent, HINSTANCE hInst, int x, int y, int width, int height)
{
    HWND hListView = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_VSCROLL | WS_HSCROLL,
        x, y, width, height,
        hParent, (HMENU)ID_RESULTS_LISTVIEW, hInst, NULL);

    if (!hListView) {
        DebugLog(L"Failed to create results ListView");
        return NULL;
    }

    // Enable full row select and grid lines
    ListView_SetExtendedListViewStyle(hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    // Add columns
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;

    for (int i = 0; i < g_ResultColumnCount; i++) {
        lvc.iSubItem = i;
        lvc.pszText = const_cast<LPWSTR>(g_ResultColumns[i].name);
        lvc.cx = g_ResultColumns[i].width;
        ListView_InsertColumn(hListView, i, &lvc);
    }

    DebugLog(L"Results ListView created with columns");
    return hListView;
}

int AddResultRow(HWND hListView, const BaselineEntry& entry, const std::wstring& status)
{
    if (!hListView) return -1;

    int rowIndex = ListView_GetItemCount(hListView);

    // Extract just the filename for the path column (full path in tooltip)
    std::wstring displayPath = entry.path;
    size_t lastSlash = displayPath.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        displayPath = displayPath.substr(lastSlash + 1);
    }

    LVITEMW lvi = {};
    lvi.mask = LVIF_TEXT;
    lvi.iItem = rowIndex;
    lvi.iSubItem = 0;
    lvi.pszText = const_cast<LPWSTR>(displayPath.c_str());
    int idx = ListView_InsertItem(hListView, &lvi);
    if (idx < 0) return -1;

    // Status
    ListView_SetItemText(hListView, idx, 1, const_cast<LPWSTR>(status.c_str()));

    // Score
    std::wstringstream scoreStr;
    scoreStr << std::fixed << std::setprecision(1) << entry.malwareScore << L"/10";
    std::wstring scoreText = scoreStr.str();
    ListView_SetItemText(hListView, idx, 2, const_cast<LPWSTR>(scoreText.c_str()));

    // SHA-256 (truncated for display)
    std::wstring sha256Display = entry.sha256.length() > 16
        ? entry.sha256.substr(0, 16) + L"..."
        : entry.sha256;
    ListView_SetItemText(hListView, idx, 3, const_cast<LPWSTR>(sha256Display.c_str()));

    // Signature
    ListView_SetItemText(hListView, idx, 4, const_cast<LPWSTR>(entry.signature.c_str()));

    // Packing
    ListView_SetItemText(hListView, idx, 5, const_cast<LPWSTR>(entry.packingStatus.c_str()));

    // Size
    std::wstring sizeStr = std::to_wstring(entry.fileSize / 1024) + L" KB";
    ListView_SetItemText(hListView, idx, 6, const_cast<LPWSTR>(sizeStr.c_str()));

    // Developer
    ListView_SetItemText(hListView, idx, 7, const_cast<LPWSTR>(entry.developer.c_str()));

    return idx;
}

void ClearResultRows(HWND hListView)
{
    if (hListView) {
        ListView_DeleteAllItems(hListView);
    }
}

// ---------------------------------------------------------------------------
// Custom draw handler — color rows by malware score
// ---------------------------------------------------------------------------
LRESULT HandleResultsCustomDraw(LPARAM lParam)
{
    LPNMLVCUSTOMDRAW pCD = reinterpret_cast<LPNMLVCUSTOMDRAW>(lParam);

    switch (pCD->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;

    case CDDS_ITEMPREPAINT:
    {
        // Read the score text from column 2
        wchar_t scoreBuf[32] = {};
        ListView_GetItemText(pCD->nmcd.hdr.hwndFrom,
            static_cast<int>(pCD->nmcd.dwItemSpec), 2, scoreBuf, 32);

        double score = _wtof(scoreBuf);

        // Color coding: red > 7.0, yellow > 4.0, green < 2.0
        if (score >= 7.0) {
            pCD->clrTextBk = RGB(255, 200, 200);  // light red
        }
        else if (score >= 4.0) {
            pCD->clrTextBk = RGB(255, 255, 180);  // light yellow
        }
        else if (score < 2.0) {
            pCD->clrTextBk = RGB(200, 255, 200);  // light green
        }
        else {
            pCD->clrTextBk = RGB(255, 255, 255);  // white (2.0 - 3.9)
        }

        return CDRF_NEWFONT;
    }

    default:
        return CDRF_DODEFAULT;
    }
}

// ---------------------------------------------------------------------------
// Directory Picker
// ---------------------------------------------------------------------------
std::wstring BrowseForScanDirectory(HWND hParent)
{
    DebugLog(L"Opening directory picker");

    wchar_t path[MAX_PATH] = {};

    BROWSEINFOW bi = {};
    bi.hwndOwner = hParent;
    bi.pszDisplayName = path;
    bi.lpszTitle = L"Select a directory to scan:";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_NONEWFOLDERBUTTON;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        if (SHGetPathFromIDListW(pidl, path)) {
            CoTaskMemFree(pidl);
            std::wstring result = path;
            DebugLog((L"Directory selected: " + result).c_str());
            return result;
        }
        CoTaskMemFree(pidl);
    }

    DebugLog(L"Directory selection cancelled");
    return L"";
}

// ---------------------------------------------------------------------------
// BrowseForScanFile — open dialog for CSV scan results
// ---------------------------------------------------------------------------
std::wstring BrowseForScanFile(HWND hParent)
{
    DebugLog(L"Opening scan file dialog");

    wchar_t filePath[MAX_PATH] = {};

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hParent;
    ofn.lpstrFilter = L"CSV Scan Results (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Open Previous Scan Results";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        DebugLog((L"Scan file selected: " + std::wstring(filePath)).c_str());
        return filePath;
    }

    DebugLog(L"Scan file selection cancelled");
    return L"";
}

// ---------------------------------------------------------------------------
// BrowseForBaselineFile — open dialog for .prbl baseline files
// ---------------------------------------------------------------------------
std::wstring BrowseForBaselineFile(HWND hParent)
{
    DebugLog(L"Opening baseline file dialog");

    wchar_t filePath[MAX_PATH] = {};

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hParent;
    ofn.lpstrFilter = L"Phantom Recon Baseline (*.prbl)\0*.prbl\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Open Baseline File";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        DebugLog((L"Baseline file selected: " + std::wstring(filePath)).c_str());
        return filePath;
    }

    DebugLog(L"Baseline file selection cancelled");
    return L"";
}

// ---------------------------------------------------------------------------
// SaveBaselineFileDialog — save dialog for exporting .prbl
// ---------------------------------------------------------------------------
std::wstring SaveBaselineFileDialog(HWND hParent)
{
    DebugLog(L"Opening baseline export dialog");

    wchar_t filePath[MAX_PATH] = {};
    wcscpy_s(filePath, L"phantom_recon_baseline.prbl");

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hParent;
    ofn.lpstrFilter = L"Phantom Recon Baseline (*.prbl)\0*.prbl\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Export Baseline";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"prbl";

    if (GetSaveFileNameW(&ofn)) {
        DebugLog((L"Baseline export path: " + std::wstring(filePath)).c_str());
        return filePath;
    }

    DebugLog(L"Baseline export cancelled");
    return L"";
}

// ---------------------------------------------------------------------------
// CSV Parser helpers
// ---------------------------------------------------------------------------

// Parse one field from a CSV line, handling quoted fields with embedded commas.
// Advances pos past the consumed field + delimiter.
static std::wstring ParseCSVField(const std::wstring& line, size_t& pos)
{
    if (pos >= line.size()) return L"";

    std::wstring result;

    if (line[pos] == L'"') {
        // Quoted field — read until closing quote
        pos++;  // skip opening quote
        while (pos < line.size()) {
            if (line[pos] == L'"') {
                if (pos + 1 < line.size() && line[pos + 1] == L'"') {
                    // Escaped quote
                    result += L'"';
                    pos += 2;
                }
                else {
                    // End of quoted field
                    pos++;  // skip closing quote
                    break;
                }
            }
            else {
                result += line[pos];
                pos++;
            }
        }
        // Skip comma after closing quote
        if (pos < line.size() && line[pos] == L',') pos++;
    }
    else {
        // Unquoted field — read until comma or end
        size_t start = pos;
        while (pos < line.size() && line[pos] != L',') {
            pos++;
        }
        result = line.substr(start, pos - start);
        if (pos < line.size()) pos++;  // skip comma
    }

    return result;
}

// Parse all fields from a CSV line
static std::vector<std::wstring> ParseCSVLine(const std::wstring& line)
{
    std::vector<std::wstring> fields;
    size_t pos = 0;
    while (pos <= line.size()) {
        fields.push_back(ParseCSVField(line, pos));
        if (pos == 0) break;  // safety
    }
    return fields;
}

// ---------------------------------------------------------------------------
// ParseScanResultCSV
// ---------------------------------------------------------------------------
bool ParseScanResultCSV(const std::wstring& filePath,
    std::vector<BaselineEntry>& outEntries,
    std::vector<std::wstring>& outStatuses)
{
    DebugLog((L"Parsing CSV: " + filePath).c_str());

    std::wifstream file(filePath);
    if (!file.is_open()) {
        DebugLog(L"Failed to open CSV file");
        return false;
    }

    // Read header line to determine column layout
    std::wstring headerLine;
    if (!std::getline(file, headerLine)) {
        DebugLog(L"CSV file is empty");
        return false;
    }

    std::vector<std::wstring> headers = ParseCSVLine(headerLine);

    // Build column index map
    int colPath = -1, colSize = -1, colMD5 = -1, colSHA256 = -1;
    int colSignature = -1, colSigType = -1, colThumbprint = -1;
    int colIssuer = -1, colRootCA = -1, colVersion = -1, colDeveloper = -1;
    int colReadOnly = -1, colHidden = -1, colPermissions = -1;
    int colEntropy = -1, colMalwareScore = -1;
    int colTotalImports = -1, colSuspiciousImports = -1;
    int colPackingStatus = -1, colRWXSections = -1;
    int colSigWarnings = -1, colPackIndicators = -1;
    int colBaselineStatus = -1;

    for (int i = 0; i < (int)headers.size(); i++) {
        const std::wstring& h = headers[i];
        if (h == L"Path")                  colPath = i;
        else if (h == L"File Size")        colSize = i;
        else if (h == L"MD5")              colMD5 = i;
        else if (h == L"SHA-256")          colSHA256 = i;
        else if (h == L"Signature")        colSignature = i;
        else if (h == L"Signature Type")   colSigType = i;
        else if (h == L"Cert Thumbprint")  colThumbprint = i;
        else if (h == L"Issuer")           colIssuer = i;
        else if (h == L"Root CA")          colRootCA = i;
        else if (h == L"Version")          colVersion = i;
        else if (h == L"Developer")        colDeveloper = i;
        else if (h == L"Read Only")        colReadOnly = i;
        else if (h == L"Hidden")           colHidden = i;
        else if (h == L"Permissions")      colPermissions = i;
        else if (h == L"Entropy")          colEntropy = i;
        else if (h == L"Malware Score")    colMalwareScore = i;
        else if (h == L"Total Imports")    colTotalImports = i;
        else if (h == L"Suspicious Imports") colSuspiciousImports = i;
        else if (h == L"Packing Status")   colPackingStatus = i;
        else if (h == L"RWX Sections")     colRWXSections = i;
        else if (h == L"Signature Warnings") colSigWarnings = i;
        else if (h == L"Packing Indicators") colPackIndicators = i;
        else if (h == L"Baseline Status")  colBaselineStatus = i;
    }

    if (colPath < 0) {
        DebugLog(L"CSV missing required 'Path' column");
        return false;
    }

    // Parse data rows
    std::wstring line;
    int rowCount = 0;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::vector<std::wstring> fields = ParseCSVLine(line);
        if (fields.empty()) continue;

        auto getField = [&](int col) -> std::wstring {
            if (col < 0 || col >= (int)fields.size()) return L"";
            return fields[col];
        };

        BaselineEntry entry = {};
        entry.path = getField(colPath);
        if (entry.path.empty()) continue;

        if (colSize >= 0) entry.fileSize = _wtoi64(getField(colSize).c_str());
        entry.md5 = getField(colMD5);
        entry.sha256 = getField(colSHA256);
        entry.signature = getField(colSignature);
        entry.signatureType = getField(colSigType);
        entry.thumbprint = getField(colThumbprint);
        entry.issuer = getField(colIssuer);
        entry.rootCA = getField(colRootCA);
        entry.version = getField(colVersion);
        entry.developer = getField(colDeveloper);
        entry.readOnly = getField(colReadOnly);
        entry.hidden = getField(colHidden);
        entry.permissions = getField(colPermissions);

        if (colEntropy >= 0) entry.entropy = _wtof(getField(colEntropy).c_str());

        // Malware score: "7.2/10" or "7.2/10 (3 suspicious imports)"
        if (colMalwareScore >= 0) {
            std::wstring scoreStr = getField(colMalwareScore);
            entry.malwareScore = _wtof(scoreStr.c_str());  // parses up to "/"
        }

        if (colTotalImports >= 0) entry.totalImports = _wtoi(getField(colTotalImports).c_str());
        if (colSuspiciousImports >= 0) entry.suspiciousImports = _wtoi(getField(colSuspiciousImports).c_str());
        entry.packingStatus = getField(colPackingStatus);
        if (colRWXSections >= 0) entry.rwxSections = _wtoi(getField(colRWXSections).c_str());
        entry.sigWarnings = getField(colSigWarnings);
        entry.packIndicators = getField(colPackIndicators);

        outEntries.push_back(entry);

        // Status column (only in comparison CSVs)
        std::wstring status = getField(colBaselineStatus);
        if (status.empty()) status = L"LOADED";
        outStatuses.push_back(status);

        rowCount++;
    }

    file.close();

    DebugLog((L"CSV parsed: " + std::to_wstring(rowCount) + L" rows").c_str());
    return true;
}
