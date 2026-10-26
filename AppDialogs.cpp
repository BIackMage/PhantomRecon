#include "pch.h"
#include "AppDialogs.h"

#include "Theme.h"
#include "Version.h"
#include "resource.h"

#include <string>

static void DebugLog(const std::wstring& msg)
{
    OutputDebugStringW(L"[AppDialogs] ");
    OutputDebugStringW(msg.c_str());
    OutputDebugStringW(L"\n");
}

static const wchar_t kGettingStartedText[] =
    L"Phantom Recon looks at this PC in two ways.\r\n"
    L"\r\n"
    L"1. Security audit. About fifty checks of Windows settings, scored from 0 to 100. "
    L"It runs when the program starts. Press F6 to see each problem with the exact fix "
    L"and how to undo it.\r\n"
    L"\r\n"
    L"2. File watch. Scans > Take Baseline records every program in a folder while you "
    L"trust the PC. Later, Scans > Full Scan or Fast Scan shows what is NEW, CHANGED or "
    L"MISSING since then. Double-click a row to read what each finding means.\r\n"
    L"\r\n"
    L"Want to see it work first? Create Sample Pack writes a few harmless demo files and a "
    L"demo baseline, then runs a scan on them.\r\n"
    L"\r\n"
    L"Nothing leaves this PC. The AI panel on the right edge stays idle until you use it.";

// Shared colour handling for both dialogs.
static INT_PTR ThemeDialogMessage(HWND hDlg, UINT message, WPARAM wParam)
{
    switch (message) {
    case WM_CTLCOLORDLG:
        return reinterpret_cast<INT_PTR>(ThemeBackgroundBrush());
    case WM_CTLCOLORSTATIC:
        return reinterpret_cast<INT_PTR>(ThemeCtlColorStatic(reinterpret_cast<HDC>(wParam)));
    case WM_CTLCOLORBTN:
        return reinterpret_cast<INT_PTR>(ThemeCtlColorButton(reinterpret_cast<HDC>(wParam)));
    default:
        UNREFERENCED_PARAMETER(hDlg);
        return 0;
    }
}

static INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG: {
        std::wstring version = std::wstring(PHANTOMRECON_NAME_W) + L", version " + PHANTOMRECON_VERSION_W;
        SetDlgItemTextW(hDlg, IDC_ABOUT_VERSION, version.c_str());
        ApplyThemeToWindowTree(hDlg);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        }
        break;
    default:
        return ThemeDialogMessage(hDlg, message, wParam);
    }
    return FALSE;
}

void ShowAboutDialog(HWND hParent, HINSTANCE hInst)
{
    DialogBoxW(hInst, MAKEINTRESOURCEW(IDD_ABOUTBOX), hParent, AboutDlgProc);
}

static INT_PTR CALLBACK GettingStartedDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
    case WM_INITDIALOG: {
        GettingStartedResult* result = reinterpret_cast<GettingStartedResult*>(lParam);
        SetWindowLongPtrW(hDlg, DWLP_USER, reinterpret_cast<LONG_PTR>(result));
        SetDlgItemTextW(hDlg, IDC_GS_TEXT, kGettingStartedText);
        CheckDlgButton(hDlg, IDC_GS_SHOW, result && result->showAtStartup ? BST_CHECKED : BST_UNCHECKED);
        ApplyThemeToWindowTree(hDlg);
        return TRUE;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDOK || id == IDCANCEL || id == IDC_GS_SAMPLES) {
            GettingStartedResult* result = reinterpret_cast<GettingStartedResult*>(GetWindowLongPtrW(hDlg, DWLP_USER));
            if (result) {
                result->showAtStartup = IsDlgButtonChecked(hDlg, IDC_GS_SHOW) == BST_CHECKED;
                result->createSamples = id == IDC_GS_SAMPLES;
            }
            EndDialog(hDlg, id);
            return TRUE;
        }
        break;
    }
    default:
        return ThemeDialogMessage(hDlg, message, wParam);
    }
    return FALSE;
}

GettingStartedResult ShowGettingStarted(HWND hParent, HINSTANCE hInst, bool showAtStartup)
{
    GettingStartedResult result;
    result.showAtStartup = showAtStartup;
    DialogBoxParamW(hInst, MAKEINTRESOURCEW(IDD_GETTING_STARTED), hParent, GettingStartedDlgProc,
        reinterpret_cast<LPARAM>(&result));
    DebugLog(std::wstring(L"Getting Started closed, show at startup=") + (result.showAtStartup ? L"yes" : L"no") +
             L", samples=" + (result.createSamples ? L"yes" : L"no"));
    return result;
}
