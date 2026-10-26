#include "pch.h"
#include "GuiComponents.h"
#include "resource.h"

#include "AppPaths.h"

#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")

// ---------------------------------------------------------------------------
// Debug logging
// ---------------------------------------------------------------------------
static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[GuiComponents] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

const wchar_t kFilterCsv[]      = L"CSV files (*.csv)\0*.csv\0All files (*.*)\0*.*\0";
const wchar_t kFilterBaseline[] = L"Phantom Recon baseline (*.prbl)\0*.prbl\0All files (*.*)\0*.*\0";
const wchar_t kFilterHtml[]     = L"Web page (*.html)\0*.html\0All files (*.*)\0*.*\0";
const wchar_t kFilterJson[]     = L"JSON (*.json)\0*.json\0All files (*.*)\0*.*\0";
const wchar_t kFilterText[]     = L"Text (*.txt)\0*.txt\0All files (*.*)\0*.*\0";

// ---------------------------------------------------------------------------
// Startup and fonts
// ---------------------------------------------------------------------------
void InitGuiCommonControls()
{
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);
    DebugLog(L"Common controls initialized");
}

HFONT CreateUiFont(HWND hWnd, int pointSizeDelta, bool bold)
{
    NONCLIENTMETRICSW ncm = {};
    ncm.cbSize = sizeof(ncm);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    LOGFONTW lf = ncm.lfMessageFont;

    UINT dpi = 96;
    HDC hdc = GetDC(hWnd);
    if (hdc) {
        dpi = static_cast<UINT>(GetDeviceCaps(hdc, LOGPIXELSY));
        ReleaseDC(hWnd, hdc);
    }
    if (pointSizeDelta != 0) {
        // lfHeight is negative character height in pixels.
        int deltaPixels = MulDiv(pointSizeDelta, static_cast<int>(dpi), 72);
        lf.lfHeight -= deltaPixels;
    }
    if (bold) lf.lfWeight = FW_SEMIBOLD;
    return CreateFontIndirectW(&lf);
}

void SetControlFont(HWND hControl, HFONT font)
{
    if (hControl && font) SendMessageW(hControl, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

// ---------------------------------------------------------------------------
// Progress bar
// ---------------------------------------------------------------------------
HWND CreateScanProgressBar(HWND hParent, HINSTANCE hInst, int x, int y, int width, int height)
{
    HWND hProgress = CreateWindowExW(0, PROGRESS_CLASSW, NULL, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        x, y, width, height, hParent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_PROGRESS_BAR)), hInst, NULL);
    DebugLog(hProgress ? L"Progress bar created" : L"Failed to create progress bar");
    return hProgress;
}

void SetProgressRange(HWND hProgressBar, int maxValue)
{
    if (hProgressBar) SendMessageW(hProgressBar, PBM_SETRANGE32, 0, maxValue > 0 ? maxValue : 1);
}

void SetProgressPosition(HWND hProgressBar, int position)
{
    if (hProgressBar) SendMessageW(hProgressBar, PBM_SETPOS, static_cast<WPARAM>(position), 0);
}

void SetProgressMarquee(HWND hProgressBar, bool enable)
{
    if (!hProgressBar) return;
    LONG_PTR style = GetWindowLongPtrW(hProgressBar, GWL_STYLE);
    bool isMarquee = (style & PBS_MARQUEE) != 0;
    if (enable == isMarquee) return;
    if (enable) {
        SetWindowLongPtrW(hProgressBar, GWL_STYLE, style | PBS_MARQUEE);
        SendMessageW(hProgressBar, PBM_SETMARQUEE, TRUE, 30);
    }
    else {
        SendMessageW(hProgressBar, PBM_SETMARQUEE, FALSE, 0);
        SetWindowLongPtrW(hProgressBar, GWL_STYLE, style & ~static_cast<LONG_PTR>(PBS_MARQUEE));
    }
}

// ---------------------------------------------------------------------------
// Results list
// ---------------------------------------------------------------------------
HWND CreateResultsListView(HWND hParent, HINSTANCE hInst, int x, int y, int width, int height)
{
    HWND hListView = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA | LVS_SINGLESEL,
        x, y, width, height, hParent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_RESULTS_LISTVIEW)), hInst, NULL);
    if (!hListView) {
        DebugLog(L"Failed to create results ListView");
        return NULL;
    }

    // No grid lines: they draw white in dark mode, and the row colours already separate rows.
    ListView_SetExtendedListViewStyle(hListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP | LVS_EX_LABELTIP);

    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    for (int i = 0; i < static_cast<int>(ResultColumn::Count); ++i) {
        ResultColumn column = static_cast<ResultColumn>(i);
        lvc.fmt = (column == ResultColumn::Score || column == ResultColumn::Size) ? LVCFMT_RIGHT : LVCFMT_LEFT;
        if (i == 0) lvc.fmt = LVCFMT_LEFT;   // the first column is always left aligned
        lvc.iSubItem = i;
        lvc.pszText = const_cast<LPWSTR>(ResultsModel::ColumnName(column));
        lvc.cx = ResultsModel::ColumnWidth(column);
        ListView_InsertColumn(hListView, i, &lvc);
    }
    DebugLog(L"Results ListView created (owner data, " + std::to_wstring(static_cast<int>(ResultColumn::Count)) + L" columns)");
    return hListView;
}

void RefreshResultsList(HWND hListView, const ResultsModel& model)
{
    if (!hListView) return;
    // LVSICF_NOSCROLL keeps the scroll position while rows stream in.
    ListView_SetItemCountEx(hListView, static_cast<int>(model.ViewCount()), LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    InvalidateRect(hListView, NULL, FALSE);
}

void FillResultsDispInfo(LPARAM lParam, const ResultsModel& model)
{
    NMLVDISPINFOW* info = reinterpret_cast<NMLVDISPINFOW*>(lParam);
    LVITEMW& item = info->item;
    if (!(item.mask & LVIF_TEXT) || !item.pszText || item.cchTextMax <= 0) return;
    if (item.iItem < 0 || static_cast<size_t>(item.iItem) >= model.ViewCount() ||
        item.iSubItem < 0 || item.iSubItem >= static_cast<int>(ResultColumn::Count)) {
        item.pszText[0] = L'\0';
        return;
    }
    std::wstring text = model.CellText(static_cast<size_t>(item.iItem), static_cast<ResultColumn>(item.iSubItem));
    wcsncpy_s(item.pszText, static_cast<size_t>(item.cchTextMax), text.c_str(), _TRUNCATE);
}

void UpdateSortArrow(HWND hListView, const ResultsModel& model)
{
    HWND header = ListView_GetHeader(hListView);
    if (!header) return;
    int count = Header_GetItemCount(header);
    for (int i = 0; i < count; ++i) {
        HDITEMW hd = {};
        hd.mask = HDI_FORMAT;
        Header_GetItem(header, i, &hd);
        hd.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (model.HasSort() && static_cast<int>(model.SortColumn()) == i) {
            hd.fmt |= model.SortAscending() ? HDF_SORTUP : HDF_SORTDOWN;
        }
        Header_SetItem(header, i, &hd);
    }
}

int SelectedResultIndex(HWND hListView)
{
    if (!hListView) return -1;
    return ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
}

const wchar_t* StatusFilterName(StatusFilter filter)
{
    switch (filter) {
    case StatusFilter::All:         return L"All rows";
    case StatusFilter::NeedsReview: return L"Needs review (new, changed, missing or score 7+)";
    case StatusFilter::NewOnly:     return L"New only";
    case StatusFilter::ChangedOnly: return L"Changed only";
    case StatusFilter::MissingOnly: return L"Missing only";
    case StatusFilter::HighScore:   return L"Score 7 or more";
    case StatusFilter::MediumScore: return L"Score 4 or more";
    default:                        return L"";
    }
}

void FillFilterCombo(HWND hCombo)
{
    if (!hCombo) return;
    SendMessageW(hCombo, CB_RESETCONTENT, 0, 0);
    const StatusFilter filters[] = {
        StatusFilter::All, StatusFilter::NeedsReview, StatusFilter::NewOnly, StatusFilter::ChangedOnly,
        StatusFilter::MissingOnly, StatusFilter::HighScore, StatusFilter::MediumScore,
    };
    for (StatusFilter f : filters) {
        SendMessageW(hCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(StatusFilterName(f)));
    }
    SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
}

// ---------------------------------------------------------------------------
// Dialogs
// ---------------------------------------------------------------------------
// Shared folder picker. multiple adds Ctrl and Shift selection.
static std::vector<std::wstring> PickFolders(HWND hParent, const wchar_t* title, const std::wstring& startFolder, bool multiple)
{
    std::vector<std::wstring> result;
    IFileOpenDialog* dialog = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog));
    if (FAILED(hr) || !dialog) {
        DebugLog(L"PickFolders: could not create the folder dialog, hr=" + std::to_wstring(hr));
        return result;
    }
    DWORD options = 0;
    dialog->GetOptions(&options);
    options |= FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST;
    if (multiple) options |= FOS_ALLOWMULTISELECT;
    dialog->SetOptions(options);
    if (title) dialog->SetTitle(title);
    if (!startFolder.empty() && DirectoryExists(startFolder)) {
        IShellItem* start = nullptr;
        if (SUCCEEDED(SHCreateItemFromParsingName(startFolder.c_str(), NULL, IID_PPV_ARGS(&start))) && start) {
            dialog->SetFolder(start);
            start->Release();
        }
    }
    if (SUCCEEDED(dialog->Show(hParent))) {
        IShellItemArray* items = nullptr;
        if (SUCCEEDED(dialog->GetResults(&items)) && items) {
            DWORD count = 0;
            items->GetCount(&count);
            for (DWORD i = 0; i < count; ++i) {
                IShellItem* item = nullptr;
                if (SUCCEEDED(items->GetItemAt(i, &item)) && item) {
                    PWSTR path = nullptr;
                    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path) {
                        result.push_back(path);
                        CoTaskMemFree(path);
                    }
                    item->Release();
                }
            }
            items->Release();
        }
    }
    dialog->Release();
    DebugLog(result.empty() ? L"Folder selection cancelled"
                            : L"Folder(s) selected: " + std::to_wstring(result.size()) + L", first " + result[0]);
    return result;
}

std::wstring BrowseForFolder(HWND hParent, const wchar_t* title, const std::wstring& startFolder)
{
    std::vector<std::wstring> picked = PickFolders(hParent, title, startFolder, false);
    return picked.empty() ? L"" : picked[0];
}

std::vector<std::wstring> BrowseForFolders(HWND hParent, const wchar_t* title, const std::wstring& startFolder)
{
    return PickFolders(hParent, title, startFolder, true);
}

std::wstring BrowseForOpenFile(HWND hParent, const wchar_t* title, const wchar_t* filter)
{
    wchar_t filePath[32768] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hParent;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = static_cast<DWORD>(sizeof(filePath) / sizeof(filePath[0]));
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn)) {
        DebugLog(L"Open file selected: " + std::wstring(filePath));
        return filePath;
    }
    DebugLog(L"Open file cancelled");
    return L"";
}

std::wstring BrowseForSaveFile(HWND hParent, const wchar_t* title, const wchar_t* filter,
                               const wchar_t* defaultExtension, const std::wstring& suggestedPath)
{
    wchar_t filePath[32768] = {};
    std::wstring initialDir;
    if (!suggestedPath.empty()) {
        wcsncpy_s(filePath, FileNameOf(suggestedPath).c_str(), _TRUNCATE);
        initialDir = DirectoryOf(suggestedPath);
    }
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hParent;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = static_cast<DWORD>(sizeof(filePath) / sizeof(filePath[0]));
    ofn.lpstrTitle = title;
    ofn.lpstrDefExt = defaultExtension;
    ofn.lpstrInitialDir = initialDir.empty() ? NULL : initialDir.c_str();
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;
    if (GetSaveFileNameW(&ofn)) {
        DebugLog(L"Save file selected: " + std::wstring(filePath));
        return filePath;
    }
    DebugLog(L"Save file cancelled");
    return L"";
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
bool CopyTextToClipboard(HWND hOwner, const std::wstring& text)
{
    if (!OpenClipboard(hOwner)) {
        DebugLog(L"Clipboard busy");
        return false;
    }
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    bool ok = false;
    if (mem) {
        void* dst = GlobalLock(mem);
        if (dst) {
            memcpy(dst, text.c_str(), bytes);
            GlobalUnlock(mem);
            ok = SetClipboardData(CF_UNICODETEXT, mem) != NULL;
        }
        if (!ok) GlobalFree(mem);   // on success the clipboard owns the memory
    }
    CloseClipboard();
    return ok;
}

std::wstring GetWindowTextString(HWND hWnd)
{
    if (!hWnd) return L"";
    int len = GetWindowTextLengthW(hWnd);
    if (len <= 0) return L"";
    std::wstring text(static_cast<size_t>(len) + 1, L'\0');
    int copied = GetWindowTextW(hWnd, &text[0], len + 1);
    text.resize(static_cast<size_t>(copied > 0 ? copied : 0));
    return text;
}

void ShowFileInExplorer(const std::wstring& path)
{
    if (FileExists(path)) {
        std::wstring args = L"/select,\"" + path + L"\"";
        ShellExecuteW(NULL, L"open", L"explorer.exe", args.c_str(), NULL, SW_SHOWNORMAL);
        return;
    }
    std::wstring folder = DirectoryOf(path);
    if (DirectoryExists(folder)) OpenWithShell(folder);
}

void OpenWithShell(const std::wstring& path)
{
    HINSTANCE r = ShellExecuteW(NULL, L"open", path.c_str(), NULL, NULL, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(r) <= 32) {
        DebugLog(L"ShellExecute failed for " + path + L", code " + std::to_wstring(reinterpret_cast<INT_PTR>(r)));
    }
}

std::wstring FileTimeStamp()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[32];
    swprintf_s(buf, L"%04u-%02u-%02u-%02u%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buf;
}
