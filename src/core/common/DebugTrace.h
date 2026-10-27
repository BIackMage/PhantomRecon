#pragma once

#include <string>

// ---------------------------------------------------------------------------
// DebugTrace: debug logging that can also reach the console.
//
// Always goes to OutputDebugString (DebugView, Visual Studio). When the
// environment variable PHANTOMRECON_TRACE is set to 1, every line is also
// written to stderr and flushed at once, so a crash in the console program
// shows the last step it reached.
// ---------------------------------------------------------------------------

void Trace(const wchar_t* module, const std::wstring& message);
