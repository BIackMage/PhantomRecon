#pragma once

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// ScriptAnalysis: static indicators in PowerShell, batch, VBScript, JScript,
// HTA and WSF files. Nothing is executed. The text is decoded (UTF-8, UTF-16
// or ANSI), lowercased, and matched against patterns that show up in
// malicious scripts: encoded commands, download cradles, living-off-the-land
// binaries, obfuscation and embedded payloads.
// ---------------------------------------------------------------------------

struct ScriptAnalysisResult {
    bool   analyzed = false;               // false when the extension is not a script type
    double score = 0.0;                    // 0 - 10
    std::vector<std::wstring> indicators;  // "CODE: detail"
    std::vector<std::wstring> techniques;  // ATT&CK ids
};

// True for .ps1 .psm1 .psd1 .bat .cmd .vbs .vbe .js .jse .wsf .wsh .wsc .hta
bool IsScriptExtension(const std::wstring& extensionLower);

// Analyse a file on disk (reads at most 4 MB).
ScriptAnalysisResult AnalyzeScriptFile(const std::wstring& path);

// Analyse text already in memory. extensionLower selects the language-specific rules.
ScriptAnalysisResult AnalyzeScriptText(const std::wstring& text, const std::wstring& extensionLower);
