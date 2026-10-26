#pragma once

#include <windows.h>
#include <string>
#include "BackgroundWorker.h"
#include "LLMClient.h"
#include "ScanCore.h"

class PayloadTracker;   // AppMessages.h

// ---------------------------------------------------------------------------
// SettingsDialog: modal window with three tabs.
//   Scanning    exclusions, default folder, baseline file, reports folder,
//               certificate revocation, Fast Scan depth, fuzzy hashing
//   Appearance  theme, getting-started window, audit at startup
//   AI          endpoint, model, tokens, temperature, redaction, prompt size,
//               Test Connection
// Settings persist to phantom_recon_settings.ini next to the exe.
//
// The connection test runs on the shared BackgroundWorker and posts
// WM_APP_STATUS_TEXT back to the dialog. The dialog never blocks the UI.
// ---------------------------------------------------------------------------

struct AppSettings {
    // AI. Defaults come from LLMConfig so the two cannot drift.
    std::wstring llmEndpoint = LLMConfig{}.endpoint;
    std::string  llmModel = LLMConfig{}.model;
    int          llmMaxTokens = LLMConfig{}.maxTokens;
    double       llmTemperature = LLMConfig{}.temperature;
    bool         llmRedact = LLMConfig{}.redact;
    int          llmMaxPromptChars = LLMConfig{}.maxPromptChars;

    // Scanning. Defaults come from ScanOptions.
    std::wstring scanExclusions;                 // ';' separated, see ParseExclusions
    std::wstring defaultScanFolder;              // empty: ask every time
    std::wstring baselinePath;                   // empty: phantom_recon_baseline.prbl next to the exe
    std::wstring reportsDirectory;               // empty: DefaultReportsDirectory()
    int          revocationMode = static_cast<int>(ScanOptions{}.revocation);   // 0 off, 1 cache, 2 online
    int          fastScanDepth = ScanOptions{}.fastScanDepth;
    bool         fuzzyHashing = ScanOptions{}.computeFuzzyHash;

    // Appearance and startup.
    int          theme = 0;                      // 0 follow Windows, 1 dark, 2 light
    bool         showGettingStarted = true;
    bool         auditOnStartup = true;
    bool         redactReports = false;          // hide user, computer and domain names in saved reports
};

// Show the settings dialog (modal). Returns true if the user saved changes;
// settings then holds the saved values. payloads tracks the connection test's
// reply (AppMessages.h), so a reply that arrives as the dialog closes is freed.
bool ShowSettingsDialog(HWND hParent, HINSTANCE hInst, BackgroundWorker& worker, PayloadTracker& payloads,
                        AppSettings& settings);

// Load settings from the INI file. Returns defaults if the file does not exist.
AppSettings LoadAppSettings();

// Save settings to the INI file. False when the file could not be written.
bool SaveAppSettings(const AppSettings& settings);

// Apply loaded settings to the LLM client singleton.
void ApplySettingsToLLMClient(const AppSettings& settings);

// Build scan options (exclusions, revocation, depth, fuzzy hashing) from settings.
ScanOptions ScanOptionsFromSettings(const AppSettings& settings);

// Resolved paths: the setting when set, else the default next to the exe.
std::wstring EffectiveBaselinePath(const AppSettings& settings);
std::wstring EffectiveReportsDirectory(const AppSettings& settings);

// Settings menu ID (File menu)
#define ID_SETTINGS 32780
