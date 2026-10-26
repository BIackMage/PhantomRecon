#pragma once

#include <windows.h>
#include "AppState.h"

// ---------------------------------------------------------------------------
// MainCommands: one function per WM_COMMAND id from the menus, the Cancel
// button and the AI sidebar buttons. All run on the UI thread.
// ---------------------------------------------------------------------------

// Route a command id to its handler. Returns false if the id is not ours.
// ID_SETTINGS comes from SettingsDialog.h; the AI ids from AiSidebar.h; the rest from resource.h.
bool DispatchCommand(AppState& app, HWND hWnd, int commandId);
