#pragma once

#include "framework.h"
#include "resource.h"
#include <windows.h>
#include <string>

#include "AppState.h"

// ---------------------------------------------------------------------------
// PhantomRecon.h: the main window.
//
// This header declares only functions. All state lives in AppState (AppState.h),
// which wWinMain owns and the window reaches through GetAppState(hWnd).
// ---------------------------------------------------------------------------

// Register the main window class. Uses app.windowClass as the class name.
ATOM RegisterMainWindowClass(AppState& app);

// Create and show the main window. Stores &app on the window for MainWndProc.
BOOL CreateMainWindow(AppState& app, int nCmdShow);

// Dispatcher: one case per message, each calling a handler.
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

// Help > About box.
INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

// Build the two info panels, the progress bar, the Cancel button and the results list.
void CreateMainControls(AppState& app, HWND hWnd);

// Repaint the "Current Operation Information" label from AppState::progress.
void RefreshOperationLabel(AppState& app);

// Run the host posture audit on the worker. Posts WM_APP_AUDIT_FINISHED when done.
void RunSecurityAuditInBackground(AppState& app);
