#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// StartupRequest: the window program's command line, split into what to do.
// Pure (no UI), so the tests check it; StartupArgs.cpp acts on it.
//
//   results.csv          open saved scan results
//   baseline.prbl        use that baseline for this session
//   --samples <folder>   write the sample pack there and scan it
//   --portable           see AppPaths.h (accepted and otherwise ignored here)
// ---------------------------------------------------------------------------

struct StartupRequest {
    std::wstring              samplesFolder;   // --samples <folder>
    std::vector<std::wstring> files;           // .csv and .prbl files, in order
    std::vector<std::wstring> unknown;         // anything else, reported to the user
};

// Split the arguments (without the program name).
StartupRequest ParseStartupArguments(const std::vector<std::wstring>& args);
