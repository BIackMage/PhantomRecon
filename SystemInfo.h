#pragma once

#include <string>

// ---------------------------------------------------------------------------
// SystemInfo: read-only facts about the host for the left-hand panel.
// Safe to call from any thread; none of these touch a window.
// ---------------------------------------------------------------------------

std::wstring GetComputerNameString();
std::wstring GetProcessorInfo();
std::wstring GetRamInfo();
std::wstring GetDiskSpaceInfo();

// The four lines above joined with newlines, ending in a newline.
std::wstring BuildSystemInfoText();
