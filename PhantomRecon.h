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
// Controls and layout live in MainLayout.cpp, commands in MainCommands.cpp,
// ReportCommands.cpp and ResultsCommands.cpp.
// ---------------------------------------------------------------------------

// Register the main window class. Uses app.windowClass as the class name.
ATOM RegisterMainWindowClass(AppState& app);

// Create and show the main window. Stores &app on the window for MainWndProc.
BOOL CreateMainWindow(AppState& app, int nCmdShow);

// Dispatcher: one case per message, each calling a handler.
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
